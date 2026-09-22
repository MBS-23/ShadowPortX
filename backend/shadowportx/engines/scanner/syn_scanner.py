"""TCP SYN (half-open) scanner using scapy.

Sends a SYN, treats SYN/ACK as OPEN (then sends a RST to tear down politely), and RST as
CLOSED. Requires raw-socket privileges (root on Linux, Npcap on Windows). If scapy is
missing or privileges are unavailable, raises :class:`SynScanUnavailable` so the
orchestrator can fall back to a TCP connect scan with a clear message.
"""

from __future__ import annotations

import asyncio

from shadowportx.core import enums
from shadowportx.engines.results import PortResult

try:  # scapy is an optional extra ("scan"); import lazily and degrade gracefully.
    from scapy.all import IP, TCP, RandShort, conf, sr1  # type: ignore

    conf.verb = 0
    _SCAPY_AVAILABLE = True
    _SCAPY_ERROR: str | None = None
except Exception as exc:  # noqa: BLE001 - any import/runtime failure disables SYN
    _SCAPY_AVAILABLE = False
    _SCAPY_ERROR = str(exc)


class SynScanUnavailable(RuntimeError):
    """Raised when a SYN scan cannot run (no scapy or insufficient privileges)."""


def is_available() -> tuple[bool, str | None]:
    return _SCAPY_AVAILABLE, _SCAPY_ERROR


def _syn_probe_blocking(host: str, port: int, timeout: float) -> bool | None:
    pkt = IP(dst=host) / TCP(sport=RandShort(), dport=port, flags="S")
    resp = sr1(pkt, timeout=timeout, verbose=0)
    if resp is None or not resp.haslayer(TCP):
        return None  # no response => filtered
    flags = int(resp[TCP].flags)
    if flags & 0x12 == 0x12:  # SYN+ACK => open; RST to close half-open connection
        sr1(IP(dst=host) / TCP(sport=pkt[TCP].sport, dport=port, flags="R"),
            timeout=0.5, verbose=0)
        return True
    return False  # RST/other => closed


async def probe(host: str, port: int, timeout: float) -> PortResult | None:
    if not _SCAPY_AVAILABLE:
        raise SynScanUnavailable(f"scapy unavailable: {_SCAPY_ERROR}")
    try:
        state = await asyncio.to_thread(_syn_probe_blocking, host, port, timeout)
    except PermissionError as exc:
        raise SynScanUnavailable("raw-socket permission denied (need root / Npcap)") from exc
    except OSError as exc:
        raise SynScanUnavailable(f"raw socket error: {exc}") from exc
    if state:
        return PortResult(host=host, port=port, protocol=enums.Protocol.TCP,
                          state=enums.PortState.OPEN)
    return None
