"""Asynchronous UDP scanner.

UDP is connectionless, so state is inferred:
* a reply           => OPEN
* ICMP port-unreach => CLOSED (surfaced as ``ConnectionRefusedError`` on many OSes)
* silence           => OPEN|FILTERED

Protocol-specific payloads are sent for common UDP services (DNS/SNMP/NTP/NetBIOS) to
elicit a reply; otherwise an empty datagram is used. The blocking socket work runs in a
worker thread so the event loop stays responsive.
"""

from __future__ import annotations

import asyncio
import socket
import time

from shadowportx.core import enums
from shadowportx.engines.results import PortResult

# Minimal, well-formed payloads that provoke a response from common UDP services.
_PAYLOADS: dict[int, bytes] = {
    53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
    123: b"\x1b" + 47 * b"\x00",  # NTP client request
    161: bytes.fromhex(  # SNMPv1 get-request public sysDescr
        "302902010004067075626c6963a01c0204"
        "00000000020100020100300e300c06082b060102010101000500"
    ),
    137: b"\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00!\x00\x01",
}


def _blocking_probe(host: str, port: int, timeout: float) -> tuple[enums.PortState, bool]:
    payload = _PAYLOADS.get(port, b"\x00")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (host, port))
        try:
            sock.recvfrom(2048)
            return enums.PortState.OPEN, True
        except TimeoutError:
            return enums.PortState.OPEN_FILTERED, False
        except ConnectionResetError:
            return enums.PortState.CLOSED, False
    except OSError:
        return enums.PortState.CLOSED, False
    finally:
        sock.close()


async def probe(host: str, port: int, timeout: float) -> PortResult | None:
    """Return a PortResult for OPEN / OPEN|FILTERED UDP ports; ``None`` if closed."""
    start = time.perf_counter()
    try:
        state, responded = await asyncio.to_thread(_blocking_probe, host, port, timeout)
    except Exception:
        return None
    if state == enums.PortState.CLOSED:
        return None
    return PortResult(
        host=host,
        port=port,
        protocol=enums.Protocol.UDP,
        state=state,
        latency_ms=round((time.perf_counter() - start) * 1000, 2),
    )
