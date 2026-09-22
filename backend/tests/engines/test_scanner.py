import asyncio

from shadowportx.core import enums
from shadowportx.engines.scanner import ScanConfig, ScanOrchestrator


async def test_orchestrator_detects_open_port_and_service():
    async def ssh(reader, writer):
        writer.write(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n")
        await writer.drain()
        try:
            await asyncio.wait_for(reader.read(16), timeout=1)
        except Exception:
            pass
        writer.close()

    server = await asyncio.start_server(ssh, "127.0.0.1", 8911)
    try:
        cfg = ScanConfig(ports=[8911, 8912], technique=enums.ScanType.TCP_CONNECT, concurrency=10)
        results = await ScanOrchestrator(cfg).run("127.0.0.1")
    finally:
        server.close()

    assert len(results) == 1
    r = results[0]
    assert r.port == 8911 and r.state == enums.PortState.OPEN
    assert r.service and r.service.product == "OpenSSH" and r.service.version == "9.6p1"


async def test_closed_ports_not_reported():
    cfg = ScanConfig(ports=[8913], technique=enums.ScanType.TCP_CONNECT, concurrency=5)
    results = await ScanOrchestrator(cfg).run("127.0.0.1")
    assert results == []
