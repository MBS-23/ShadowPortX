"""Memcached verification — read-only ``stats`` probe (no auth by default; DDoS amplifier)."""

from __future__ import annotations

import asyncio

from shadowportx.core import enums
from shadowportx.engines.results import VerificationResult


async def verify(host: str, port: int, timeout: float = 4.0) -> VerificationResult | None:
    writer = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        writer.write(b"stats\r\n")  # read-only
        await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), timeout)
    except (TimeoutError, ConnectionRefusedError, OSError):
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    if b"STAT " in data:
        version = None
        for line in data.decode("utf-8", "ignore").splitlines():
            if line.startswith("STAT version"):
                version = line.split()[-1]
                break
        return VerificationResult(
            service="memcached", verified=True, condition="no-authentication-required",
            severity=enums.Severity.HIGH, confidence=enums.Confidence.HIGH,
            evidence={"probe": "stats (read-only)",
                      "observed": "Memcached returned stats without authentication.",
                      "version": version},
            recommendation=("Bind memcached to localhost, enable SASL auth, and firewall UDP/TCP "
                            "11211 (also a UDP reflection/amplification vector)."),
        )
    return None
