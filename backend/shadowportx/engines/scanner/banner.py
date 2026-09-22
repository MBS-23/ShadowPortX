"""Protocol-aware banner grabbing.

Sends a minimal, service-appropriate probe (an HTTP request to web ports, a ``PING`` to
Redis, nothing to banner-first services like SSH/SMTP/FTP that greet on connect) and
reads the response. Non-destructive and read-only.
"""

from __future__ import annotations

import asyncio

# Ports that speak HTTP in cleartext (TLS ports are handled by the recon TLS/HTTP engine).
_HTTP_PORTS = {80, 81, 591, 2082, 2480, 3000, 5000, 8000, 8008, 8080, 8081, 8088,
               8090, 8161, 8888, 9000, 9090, 9200, 9999, 15672, 5601, 8086}
_HTTP_PROBE = "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ShadowPortX/2.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"

# A few text protocols where a tiny probe yields a useful, harmless banner.
_LINE_PROBES = {
    6379: b"PING\r\n",          # Redis -> +PONG / -NOAUTH
    11211: b"version\r\n",      # Memcached -> VERSION x.y.z
    9092: b"",                  # Kafka (no cleartext banner; left for verification)
}


async def _read(reader: asyncio.StreamReader, timeout: float) -> bytes:
    try:
        return await asyncio.wait_for(reader.read(4096), timeout=timeout)
    except (TimeoutError, OSError):
        return b""


async def grab_banner(host: str, port: int, timeout: float) -> str | None:
    """Return a decoded banner for ``host:port`` or ``None``.

    Strategy: HTTP ports get an HTTP request; a few text protocols get a tiny probe;
    everything else is read banner-first (SSH/FTP/SMTP greet on connect) and, if silent,
    retried with an HTTP request — HTTP is the most common service on arbitrary ports.
    """
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )

        if port in _HTTP_PORTS:
            writer.write(_HTTP_PROBE.format(host=host).encode())
            await writer.drain()
            data = await _read(reader, timeout)
        elif port in _LINE_PROBES and _LINE_PROBES[port]:
            writer.write(_LINE_PROBES[port])
            await writer.drain()
            data = await _read(reader, timeout)
        else:
            # 1) Listen briefly for a greeting. Banner-first services (SSH/FTP/SMTP)
            #    greet within milliseconds, so a short window keeps the HTTP fallback fast.
            data = await _read(reader, min(timeout, 0.5))
            # 2) Silent? Try an HTTP request (catches HTTP on non-standard ports).
            if not data:
                try:
                    writer.write(_HTTP_PROBE.format(host=host).encode())
                    await writer.drain()
                    data = await _read(reader, timeout)
                except (OSError, asyncio.CancelledError):
                    data = b""

        text = data.decode("utf-8", "ignore").strip()
        return text or None
    except (TimeoutError, ConnectionRefusedError, OSError, asyncio.CancelledError):
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, asyncio.CancelledError):
                pass
