"""Asynchronous TCP connect scanner.

A full 3-way handshake per port. Reliable and needs no special privileges (unlike SYN),
at the cost of being more visible. Concurrency/rate limiting live in the orchestrator;
this module just probes one port.
"""

from __future__ import annotations

import asyncio
import time

from shadowportx.core import enums
from shadowportx.engines.results import PortResult


async def probe(host: str, port: int, timeout: float) -> PortResult | None:
    """Return a :class:`PortResult` if the port is OPEN, else ``None``."""
    start = time.perf_counter()
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        latency = (time.perf_counter() - start) * 1000
        return PortResult(
            host=host,
            port=port,
            protocol=enums.Protocol.TCP,
            state=enums.PortState.OPEN,
            latency_ms=round(latency, 2),
        )
    except (TimeoutError, ConnectionRefusedError, OSError):
        # Closed or filtered — connect scan only reports open ports.
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, asyncio.CancelledError):
                pass
