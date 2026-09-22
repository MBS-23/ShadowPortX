"""Web application admin-exposure verification (Grafana / Jenkins / Kibana).

Read-only checks against public identity/health endpoints to see whether an admin
interface is reachable and, where determinable, whether it permits anonymous access.
"""

from __future__ import annotations

import httpx

from shadowportx.core import enums
from shadowportx.engines.results import VerificationResult


async def _get(host: str, port: int, path: str, timeout: float):
    for scheme in ("http", "https"):
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as c:  # nosec B501
                return await c.get(f"{scheme}://{host}:{port}{path}")
        except (httpx.HTTPError, OSError):
            continue
    return None


async def verify_grafana(host: str, port: int, timeout: float = 6.0) -> VerificationResult | None:
    resp = await _get(host, port, "/api/health", timeout)
    if resp is None or resp.status_code != 200:
        return None
    version = None
    try:
        version = resp.json().get("version")
    except Exception:
        pass
    # Probe whether the org endpoint is reachable anonymously.
    org = await _get(host, port, "/api/org", timeout)
    anon = bool(org is not None and org.status_code == 200)
    return VerificationResult(
        service="grafana",
        verified=True,
        condition="anonymous-access" if anon else "reachable",
        severity=enums.Severity.HIGH if anon else enums.Severity.MEDIUM,
        confidence=enums.Confidence.HIGH if anon else enums.Confidence.MEDIUM,
        evidence={
            "probe": "GET /api/health, GET /api/org (read-only)",
            "version": version,
            "anonymous_org_readable": anon,
        },
        recommendation=(
            "Disable anonymous access, enforce strong admin credentials, and place Grafana "
            "behind authenticated ingress." if anon else
            "Confirm authentication is enforced and restrict exposure."
        ),
    )


async def verify_jenkins(host: str, port: int, timeout: float = 6.0) -> VerificationResult | None:
    resp = await _get(host, port, "/api/json", timeout)
    if resp is None:
        return None
    header_ver = resp.headers.get("x-jenkins")
    if resp.status_code == 200 and (header_ver or "jobs" in resp.text.lower()):
        return VerificationResult(
            service="jenkins",
            verified=True,
            condition="anonymous-read-access",
            severity=enums.Severity.HIGH,
            confidence=enums.Confidence.HIGH,
            evidence={"probe": "GET /api/json (read-only)", "x_jenkins": header_ver,
                      "observed": "Jenkins API readable anonymously."},
            recommendation="Enable security realm + matrix authorization; deny anonymous read.",
        )
    if header_ver or resp.status_code in (401, 403):
        return VerificationResult(
            service="jenkins", verified=True, condition="reachable",
            severity=enums.Severity.MEDIUM, confidence=enums.Confidence.MEDIUM,
            evidence={"probe": "GET /api/json", "x_jenkins": header_ver, "status": resp.status_code},
            recommendation="Restrict Jenkins exposure to trusted networks/VPN.",
        )
    return None


async def verify_kibana(host: str, port: int, timeout: float = 6.0) -> VerificationResult | None:
    resp = await _get(host, port, "/api/status", timeout)
    if resp is None or resp.status_code not in (200, 401, 403):
        return None
    if resp.status_code == 200 and "version" in resp.text.lower():
        return VerificationResult(
            service="kibana", verified=True, condition="no-authentication-required",
            severity=enums.Severity.HIGH, confidence=enums.Confidence.HIGH,
            evidence={"probe": "GET /api/status (read-only)",
                      "observed": "Kibana status readable without authentication."},
            recommendation="Enable Elastic Stack security and require authentication for Kibana.",
        )
    return VerificationResult(
        service="kibana", verified=True, condition="authentication-required",
        severity=enums.Severity.INFO, confidence=enums.Confidence.MEDIUM,
        evidence={"probe": "GET /api/status", "status": resp.status_code},
        recommendation="Authentication appears enforced. Keep exposure minimal.",
    )
