"""Service verification engine.

Performs *non-destructive*, read-only checks to observe whether a service exposes a
security-relevant condition (e.g. "reachable without authentication"). This is the layer
that turns "Redis is running" into "Redis is reachable and required no authentication for
a read-only INFO probe" — evidence, not assumption.

Every verifier is safe by design: it only issues read-only/identity commands, never writes,
deletes, or state-changing operations.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from shadowportx.engines.results import VerificationResult
from shadowportx.engines.verification import (
    docker,
    elasticsearch,
    ftp,
    memcached,
    mongodb,
    redis,
    smtp,
    web_admin,
)

Verifier = Callable[[str, int, float], Awaitable[VerificationResult | None]]

# Map a detected service name -> verifier. Web apps are keyed by their app fingerprint.
_REGISTRY: dict[str, Verifier] = {
    "redis": redis.verify,
    "elasticsearch": elasticsearch.verify,
    "mongodb": mongodb.verify,
    "docker": docker.verify,
    "ftp": ftp.verify,
    "smtp": smtp.verify,
    "memcached": memcached.verify,
}

# HTTP application verifiers, tried when a web app fingerprint is present.
_WEB_APPS: dict[str, Verifier] = {
    "grafana": web_admin.verify_grafana,
    "jenkins": web_admin.verify_jenkins,
    "kibana": web_admin.verify_kibana,
}


def supported_services() -> list[str]:
    return sorted(set(_REGISTRY) | set(_WEB_APPS))


async def run_verification(
    service_name: str | None,
    host: str,
    port: int,
    *,
    application: str | None = None,
    timeout: float = 4.0,
) -> VerificationResult | None:
    """Run the appropriate verifier for a detected service, if one exists."""
    if application:
        app_verifier = _WEB_APPS.get(application.strip().lower())
        if app_verifier:
            return await app_verifier(host, port, timeout)

    if not service_name:
        return None
    verifier = _REGISTRY.get(service_name.strip().lower())
    if not verifier:
        return None
    return await verifier(host, port, timeout)


__all__ = ["run_verification", "supported_services", "VerificationResult"]
