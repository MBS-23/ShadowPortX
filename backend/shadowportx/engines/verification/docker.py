"""Docker Engine API verification — read-only ``/version`` probe (non-destructive).

An exposed, unauthenticated Docker API is effectively remote root, so this is CRITICAL.
"""

from __future__ import annotations

import httpx

from shadowportx.core import enums
from shadowportx.engines.results import VerificationResult


async def verify(host: str, port: int, timeout: float = 6.0) -> VerificationResult | None:
    for scheme in ("http", "https"):
        url = f"{scheme}://{host}:{port}/version"
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:  # nosec B501
                resp = await client.get(url)
        except (httpx.HTTPError, OSError):
            continue
        if resp.status_code != 200:
            continue
        try:
            data = resp.json()
        except Exception:
            continue
        if "ApiVersion" in data or "Version" in data:
            return VerificationResult(
                service="docker",
                verified=True,
                condition="unauthenticated-docker-api",
                severity=enums.Severity.CRITICAL,
                confidence=enums.Confidence.HIGH,
                evidence={
                    "probe": "GET /version (read-only)",
                    "observed": "Docker Engine API responded without authentication.",
                    "docker_version": data.get("Version"),
                    "api_version": data.get("ApiVersion"),
                },
                recommendation=(
                    "Never expose the Docker API on the network unauthenticated. Bind to a "
                    "local socket, or require mutual TLS, and firewall the port immediately."
                ),
            )
    return None
