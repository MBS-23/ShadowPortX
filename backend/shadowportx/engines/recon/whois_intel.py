"""WHOIS/registration intelligence (wraps python-whois, run off the event loop)."""

from __future__ import annotations

import asyncio


def _stringify(value):
    if isinstance(value, list):
        return [str(v) for v in value]
    return str(value) if value is not None else None


def _blocking_whois(domain: str) -> dict:
    import whois  # imported lazily; slow to import

    try:
        data = whois.whois(domain)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"WHOIS lookup failed: {exc}"}
    if not data:
        return {"error": "WHOIS returned no data"}
    return {
        "domain_name": _stringify(getattr(data, "domain_name", None)),
        "registrar": _stringify(getattr(data, "registrar", None)),
        "creation_date": _stringify(getattr(data, "creation_date", None)),
        "expiration_date": _stringify(getattr(data, "expiration_date", None)),
        "updated_date": _stringify(getattr(data, "updated_date", None)),
        "name_servers": _stringify(getattr(data, "name_servers", None)),
        "status": _stringify(getattr(data, "status", None)),
        "org": _stringify(getattr(data, "org", None)),
        "country": _stringify(getattr(data, "country", None)),
        "emails": _stringify(getattr(data, "emails", None)) or "hidden",
    }


async def lookup(domain: str) -> dict:
    try:
        return await asyncio.wait_for(asyncio.to_thread(_blocking_whois, domain), timeout=15)
    except (TimeoutError, Exception) as exc:  # noqa: BLE001
        return {"error": f"WHOIS lookup timed out or failed: {exc}"}
