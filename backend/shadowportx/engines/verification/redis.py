"""Redis verification — read-only ``INFO server`` probe (non-destructive)."""

from __future__ import annotations

import asyncio
import re

from shadowportx.core import enums
from shadowportx.engines.results import VerificationResult


async def verify(host: str, port: int, timeout: float = 4.0) -> VerificationResult | None:
    writer = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        writer.write(b"INFO server\r\n")  # read-only
        await writer.drain()
        data = await asyncio.wait_for(reader.read(8192), timeout)
        text = data.decode("utf-8", "ignore")
    except (TimeoutError, ConnectionRefusedError, OSError):
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    if not text:
        return None
    low = text.lower()

    if "redis_version" in low:
        m = re.search(r"redis_version:([\d.]+)", text)
        return VerificationResult(
            service="redis",
            verified=True,
            condition="no-authentication-required",
            severity=enums.Severity.HIGH,
            confidence=enums.Confidence.HIGH,
            evidence={
                "probe": "INFO server (read-only)",
                "observed": "Redis returned server INFO without requiring authentication.",
                "redis_version": m.group(1) if m else None,
            },
            recommendation=(
                "Require authentication (requirepass or ACLs), enable protected-mode, and "
                "restrict network exposure to trusted hosts only."
            ),
        )

    if any(tok in low for tok in ("-noauth", "-denied", "authentication required", "-err")):
        return VerificationResult(
            service="redis",
            verified=True,
            condition="authentication-required",
            severity=enums.Severity.INFO,
            confidence=enums.Confidence.HIGH,
            evidence={"probe": "INFO server (read-only)", "observed": "Authentication is enforced."},
            recommendation="Authentication is enforced. Keep network exposure minimal.",
        )
    return None
