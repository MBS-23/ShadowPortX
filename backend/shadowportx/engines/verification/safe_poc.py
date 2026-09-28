"""Safe proof-of-concept checks (Level 3 — SAFE).

Confirms that a suspected *web* exposure is real without weaponized or state-changing
payloads. Every probe is a read-only ``GET`` with benign values, a single attempt, and a
short timeout. This layer NEVER sends exploit payloads, writes/deletes data, brute-forces
credentials, or performs anything destructive — it only observes a response signal that
proves the issue exists (e.g. a `.git/HEAD` that returns a real ref). Each result carries
report-ready evidence (the exact probe + the observed response) so a finding can move to
``confirmed``.

Weaponized / automated exploitation (Level 4) is intentionally NOT implemented here.
"""

from __future__ import annotations

import re
from urllib.parse import quote

import httpx

from shadowportx.core import enums
from shadowportx.engines.results import VerificationResult

# Web ports the safe PoC knows how to talk to.
WEB_PORTS = {80, 81, 443, 591, 2082, 2480, 3000, 5000, 5601, 7474, 8000, 8008, 8080,
             8081, 8086, 8088, 8090, 8161, 8443, 8888, 9000, 9090, 9200, 9443, 9999,
             15672, 10000}
_TLS_PORTS = {443, 8443, 9443, 4848}

_UA = "ShadowPortX/3.1 (+authorized-security-assessment; safe-poc)"
_BENIGN_ORIGIN = "https://poc.example.com"          # IANA example domain — safe
_BENIGN_REDIRECT = "https://example.com/spx-poc"    # benign external redirect target
_METHOD = "safe proof-of-concept (L3, read-only)"

_ENV_HINT = re.compile(r"(?m)^\s*(APP_KEY|SECRET|SECRET_KEY|DB_PASSWORD|DATABASE_URL|AWS_|API_KEY|TOKEN)\w*\s*=")
_REDIRECT_PARAMS = ("next", "url", "redirect", "return", "dest", "continue")


def _snip(text: str, n: int = 160) -> str:
    return (text or "")[:n].replace("\n", "\\n").strip()


async def _check_exposed_git(client: httpx.AsyncClient, base: str):
    r = await client.get(base + "/.git/HEAD")
    if r.status_code == 200 and r.text.strip().startswith("ref:"):
        return VerificationResult(
            service="http", verified=True, condition="exposed-git-repository",
            severity=enums.Severity.HIGH, confidence=enums.Confidence.HIGH,
            evidence={"probe": "GET /.git/HEAD", "status": 200,
                      "response_snippet": _snip(r.text, 80), "method": _METHOD, "safe": True},
            recommendation="Deny web access to the .git directory and rotate any secrets it exposed.",
        )
    return None


async def _check_exposed_env(client: httpx.AsyncClient, base: str):
    r = await client.get(base + "/.env")
    ctype = r.headers.get("content-type", "")
    if r.status_code == 200 and "html" not in ctype.lower() and _ENV_HINT.search(r.text or ""):
        keys = re.findall(r"(?m)^\s*([A-Z][A-Z0-9_]+)=", r.text)[:8]
        return VerificationResult(
            service="http", verified=True, condition="exposed-dotenv-file",
            severity=enums.Severity.HIGH, confidence=enums.Confidence.HIGH,
            evidence={"probe": "GET /.env", "status": 200, "leaked_keys": keys,
                      "method": _METHOD, "safe": True},
            recommendation="Remove the .env file from the web root and rotate the exposed credentials.",
        )
    return None


async def _check_dir_listing(client: httpx.AsyncClient, base: str):
    r = await client.get(base + "/")
    body = r.text or ""
    if r.status_code == 200 and ("<title>Index of /" in body or ">Index of /" in body):
        return VerificationResult(
            service="http", verified=True, condition="directory-listing-enabled",
            severity=enums.Severity.MEDIUM, confidence=enums.Confidence.HIGH,
            evidence={"probe": "GET /", "status": 200, "observed": "Autoindex 'Index of /' page",
                      "method": _METHOD, "safe": True},
            recommendation="Disable directory autoindexing (e.g. `autoindex off` / `Options -Indexes`).",
        )
    return None


async def _check_cors(client: httpx.AsyncClient, base: str):
    r = await client.get(base + "/", headers={"Origin": _BENIGN_ORIGIN})
    acao = r.headers.get("access-control-allow-origin", "")
    acac = (r.headers.get("access-control-allow-credentials", "") or "").lower()
    if acao == _BENIGN_ORIGIN and acac == "true":
        return VerificationResult(
            service="http", verified=True, condition="cors-reflects-arbitrary-origin-with-credentials",
            severity=enums.Severity.HIGH, confidence=enums.Confidence.HIGH,
            evidence={"probe": f"GET / (Origin: {_BENIGN_ORIGIN})",
                      "access_control_allow_origin": acao,
                      "access_control_allow_credentials": True, "method": _METHOD, "safe": True},
            recommendation="Do not reflect arbitrary Origins with credentials; use an allow-list of trusted origins.",
        )
    return None


async def _check_open_redirect(client: httpx.AsyncClient, base: str):
    for param in _REDIRECT_PARAMS:
        r = await client.get(base + f"/?{param}={quote(_BENIGN_REDIRECT, safe='')}",
                             follow_redirects=False)
        loc = r.headers.get("location", "")
        if r.status_code in (301, 302, 303, 307, 308) and loc.startswith(_BENIGN_REDIRECT):
            return VerificationResult(
                service="http", verified=True, condition="open-redirect",
                severity=enums.Severity.MEDIUM, confidence=enums.Confidence.HIGH,
                evidence={"probe": f"GET /?{param}={_BENIGN_REDIRECT}", "status": r.status_code,
                          "location": _snip(loc, 120), "parameter": param,
                          "method": _METHOD, "safe": True},
                recommendation="Validate redirect targets against an allow-list; never redirect to attacker-supplied URLs.",
            )
    return None


async def _check_spring_actuator(client: httpx.AsyncClient, base: str):
    r = await client.get(base + "/actuator/env")
    if r.status_code == 200 and "propertySources" in (r.text or ""):
        return VerificationResult(
            service="http", verified=True, condition="spring-actuator-env-exposed",
            severity=enums.Severity.HIGH, confidence=enums.Confidence.HIGH,
            evidence={"probe": "GET /actuator/env", "status": 200,
                      "observed": "Spring Boot Actuator /env exposed (may leak config/secrets)",
                      "method": _METHOD, "safe": True},
            recommendation="Restrict Actuator endpoints (management.endpoints) and require authentication.",
        )
    return None


_CHECKS = (
    _check_exposed_git, _check_exposed_env, _check_dir_listing,
    _check_cors, _check_open_redirect, _check_spring_actuator,
)


async def probe(client: httpx.AsyncClient, base: str) -> list[VerificationResult]:
    """Run every safe check against ``base`` and return the confirmed results.

    Pure and injectable (tests pass their own client + base). Each check is isolated so one
    failing probe never aborts the others.
    """
    results: list[VerificationResult] = []
    for check in _CHECKS:
        try:
            res = await check(client, base)
        except (httpx.HTTPError, OSError):
            res = None
        if res is not None:
            results.append(res)
    return results


async def run_safe_poc(host: str, port: int, *, timeout: float = 5.0) -> list[VerificationResult]:
    """Reach the host over HTTP(S) and run the safe PoC probes. Returns confirmed results
    (possibly empty). Only ever issues read-only GET requests."""
    schemes = ("https", "http") if port in _TLS_PORTS else ("http", "https")
    async with httpx.AsyncClient(
        timeout=timeout, verify=False, headers={"User-Agent": _UA},  # nosec B501
        follow_redirects=True,
    ) as client:
        for scheme in schemes:
            base = f"{scheme}://{host}:{port}"
            try:
                await client.get(base + "/")   # reachability probe
            except (httpx.HTTPError, OSError):
                continue
            return await probe(client, base)
    return []


__all__ = ["run_safe_poc", "probe", "WEB_PORTS"]
