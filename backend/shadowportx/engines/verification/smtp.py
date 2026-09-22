"""SMTP verification — banner + EHLO capability inspection (read-only, no relay test)."""

from __future__ import annotations

import asyncio

from shadowportx.core import enums
from shadowportx.engines.results import VerificationResult


async def verify(host: str, port: int, timeout: float = 4.0) -> VerificationResult | None:
    writer = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        banner = await asyncio.wait_for(reader.readline(), timeout)
        if not banner.startswith(b"220"):
            return None
        writer.write(b"EHLO shadowportx.local\r\n")
        await writer.drain()
        caps = b""
        for _ in range(15):
            line = await asyncio.wait_for(reader.readline(), timeout)
            caps += line
            if not line.startswith(b"250-"):
                break
        writer.write(b"QUIT\r\n")
        await writer.drain()
    except (TimeoutError, ConnectionRefusedError, OSError):
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    text = caps.upper()
    has_starttls = b"STARTTLS" in text
    if not has_starttls:
        return VerificationResult(
            service="smtp", verified=True, condition="no-starttls",
            severity=enums.Severity.LOW, confidence=enums.Confidence.HIGH,
            evidence={"probe": "EHLO (read-only)", "observed": "Server does not advertise STARTTLS.",
                      "banner": banner.decode("utf-8", "ignore").strip()[:120]},
            recommendation="Enable STARTTLS so mail submission can be encrypted in transit.",
        )
    return VerificationResult(
        service="smtp", verified=True, condition="starttls-available",
        severity=enums.Severity.INFO, confidence=enums.Confidence.HIGH,
        evidence={"probe": "EHLO", "observed": "STARTTLS advertised."},
        recommendation="STARTTLS is available. Ensure it is required for submission.",
    )
