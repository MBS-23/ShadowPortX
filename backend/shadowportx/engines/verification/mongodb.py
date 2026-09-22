"""MongoDB verification — legacy ``isMaster`` OP_QUERY (read-only, non-destructive).

Sends the standard identity command every MongoDB driver issues on connect. If the server
answers without requiring authentication, unauthenticated network access is confirmed.
"""

from __future__ import annotations

import asyncio
import struct

_OP_QUERY = 2004


def _bson_ismaster() -> bytes:
    # BSON document { "isMaster": 1 } (int32 field).
    field = b"\x10" + b"isMaster\x00" + struct.pack("<i", 1)
    doc_len = 4 + len(field) + 1
    return struct.pack("<i", doc_len) + field + b"\x00"


def _build_query() -> bytes:
    full_collection = b"admin.$cmd\x00"
    body = (
        struct.pack("<i", 0)        # flags
        + full_collection
        + struct.pack("<i", 0)      # numberToSkip
        + struct.pack("<i", 1)      # numberToReturn
        + _bson_ismaster()
    )
    header = struct.pack("<iiii", 16 + len(body), 1, 0, _OP_QUERY)
    return header + body


async def verify(host: str, port: int, timeout: float = 4.0):
    from shadowportx.core import enums
    from shadowportx.engines.results import VerificationResult

    writer = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        writer.write(_build_query())
        await writer.drain()
        header = await asyncio.wait_for(reader.readexactly(16), timeout)
        msg_len = struct.unpack("<i", header[:4])[0]
        if not (16 < msg_len < 48 * 1024):
            return None
        payload = await asyncio.wait_for(reader.readexactly(msg_len - 16), timeout)
    except (TimeoutError, ConnectionRefusedError, OSError, asyncio.IncompleteReadError):
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    low = payload.lower()
    if b"ismaster" in low or b"maxwireversion" in low or b"ok" in low:
        return VerificationResult(
            service="mongodb",
            verified=True,
            condition="no-authentication-required",
            severity=enums.Severity.HIGH,
            confidence=enums.Confidence.HIGH,
            evidence={
                "probe": "isMaster OP_QUERY (read-only)",
                "observed": "MongoDB answered the identity command without authentication.",
            },
            recommendation=(
                "Enable authorization (authnz), create administrative users, bind to trusted "
                "interfaces, and firewall the MongoDB port."
            ),
        )
    return None
