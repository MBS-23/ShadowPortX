"""HTTP intelligence: headers, security headers, redirects, and technology fingerprinting.

Technology detection is evidence-based — each detected technology records *why* it was
detected (which header, cookie, or body marker), never a bare claim.
"""

from __future__ import annotations

import re

import httpx

from shadowportx.core import enums
from shadowportx.core.config import settings
from shadowportx.engines.results import HttpInfo, TechInfo

SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# (technology, category, where, pattern) — `where` ∈ {header:<name>, cookie, body, generator}
_TECH_SIGNATURES: list[tuple[str, str, str, re.Pattern[str]]] = [
    ("nginx", "web-server", "header:server", re.compile(r"nginx", re.I)),
    ("Apache", "web-server", "header:server", re.compile(r"apache", re.I)),
    ("Microsoft IIS", "web-server", "header:server", re.compile(r"iis", re.I)),
    ("Cloudflare", "cdn", "header:server", re.compile(r"cloudflare", re.I)),
    ("PHP", "runtime", "header:x-powered-by", re.compile(r"php/?([\d.]+)?", re.I)),
    ("ASP.NET", "runtime", "header:x-powered-by", re.compile(r"asp\.net", re.I)),
    ("Express", "framework", "header:x-powered-by", re.compile(r"express", re.I)),
    ("PHP", "runtime", "cookie", re.compile(r"PHPSESSID", re.I)),
    ("Java", "runtime", "cookie", re.compile(r"JSESSIONID", re.I)),
    ("Laravel", "framework", "cookie", re.compile(r"laravel_session", re.I)),
    ("Django", "framework", "cookie", re.compile(r"csrftoken|sessionid", re.I)),
    ("Ruby on Rails", "framework", "cookie", re.compile(r"_rails|_session_id", re.I)),
    ("WordPress", "cms", "body", re.compile(r"wp-content|wp-includes", re.I)),
    ("Drupal", "cms", "body", re.compile(r"Drupal.settings|/sites/default/files", re.I)),
    ("Joomla", "cms", "body", re.compile(r"/media/jui/|Joomla", re.I)),
    ("React", "framework", "body", re.compile(r"data-reactroot|__REACT_DEVTOOLS", re.I)),
    ("Next.js", "framework", "body", re.compile(r"/_next/|__NEXT_DATA__", re.I)),
    ("Vue.js", "framework", "body", re.compile(r"data-v-[0-9a-f]{8}|__vue__", re.I)),
    ("Angular", "framework", "body", re.compile(r"ng-version|ng-app", re.I)),
]


def _detect_technologies(headers: dict[str, str], cookies: list[str], body: str) -> list[TechInfo]:
    found: dict[str, TechInfo] = {}
    for name, category, where, pattern in _TECH_SIGNATURES:
        haystack, evidence_src = "", where
        if where.startswith("header:"):
            haystack = headers.get(where.split(":", 1)[1], "")
        elif where == "cookie":
            haystack = "; ".join(cookies)
        elif where in ("body", "generator"):
            haystack = body
        if not haystack:
            continue
        m = pattern.search(haystack)
        if not m:
            continue
        version = None
        if m.groups() and m.lastindex:
            version = m.group(1)
        ev = f"{evidence_src}: {m.group(0)[:80]}"
        if name in found:
            if ev not in found[name].evidence:
                found[name].evidence.append(ev)
            found[name].version = found[name].version or version
        else:
            found[name] = TechInfo(
                name=name,
                category=category,
                version=version,
                confidence=enums.Confidence.HIGH if version else enums.Confidence.MEDIUM,
                evidence=[ev],
            )
    return list(found.values())


async def probe(url: str) -> HttpInfo | None:
    """Fetch ``url`` and extract HTTP intelligence. ``url`` should include scheme."""
    headers = {"User-Agent": settings.recon_user_agent}
    try:
        async with httpx.AsyncClient(
            timeout=settings.recon_http_timeout,
            follow_redirects=True,
            # Assessment intent: inspect endpoints regardless of cert validity.
            verify=False,  # nosec B501
            headers=headers,
        ) as client:
            resp = await client.get(url)
    except Exception:
        return None

    hdrs = {k.lower(): v for k, v in resp.headers.items()}
    redirect_chain = [str(r.url) for r in resp.history] + [str(resp.url)]
    cookies = [f"{k}={v}" for k, v in resp.cookies.items()]
    # Also capture Set-Cookie names from raw headers (httpx consumes some).
    set_cookie_names = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
    cookies += set_cookie_names

    body = resp.text[:20000] if resp.headers.get("content-type", "").startswith(("text", "application/json", "application/xml")) else ""
    title_m = _TITLE_RE.search(body)

    sec = {h: (h in hdrs) for h in SECURITY_HEADERS}

    return HttpInfo(
        url=url,
        status_code=resp.status_code,
        final_url=str(resp.url),
        redirect_chain=redirect_chain,
        server=hdrs.get("server"),
        title=title_m.group(1).strip()[:200] if title_m else None,
        headers=hdrs,
        security_headers=sec,
        technologies=_detect_technologies(hdrs, cookies, body),
        cookies=cookies[:20],
    )
