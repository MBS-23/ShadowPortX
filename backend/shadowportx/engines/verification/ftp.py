"""FTP verification — checks for anonymous login (read-only auth attempt, then QUIT)."""

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
        writer.write(b"USER anonymous\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.readline(), timeout)
        writer.write(b"PASS shadowportx@example.com\r\n")
        await writer.drain()
        resp = await asyncio.wait_for(reader.readline(), timeout)
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

    if resp.startswith(b"230"):
        return VerificationResult(
            service="ftp", verified=True, condition="anonymous-login-allowed",
            severity=enums.Severity.HIGH, confidence=enums.Confidence.HIGH,
            evidence={"probe": "USER anonymous (read-only)", "observed": "Anonymous FTP login accepted.",
                      "banner": banner.decode("utf-8", "ignore").strip()[:120]},
            recommendation="Disable anonymous FTP or migrate to SFTP/FTPS with authentication.",
        )
    return VerificationResult(
        service="ftp", verified=True, condition="authentication-required",
        severity=enums.Severity.INFO, confidence=enums.Confidence.MEDIUM,
        evidence={"probe": "USER anonymous", "observed": "Anonymous login rejected."},
        recommendation="Prefer SFTP/FTPS; restrict exposure.",
    )
