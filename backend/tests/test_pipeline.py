"""Integration test: full scan pipeline against a local fake service (authorized: 127.0.0.1)."""

import asyncio

from sqlalchemy import select

from shadowportx.core import enums
from shadowportx.db import models
from shadowportx.db.base import session_scope
from shadowportx.services.pipeline import ScanPipeline


async def test_full_pipeline_generates_scored_findings(seeded):
    async def redis(reader, writer):
        try:
            await asyncio.wait_for(reader.read(64), timeout=1)
        except Exception:
            pass
        writer.write(b"# Server\r\nredis_version:6.0.9\r\nredis_mode:standalone\r\n+PONG\r\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(redis, "127.0.0.1", 8931)
    try:
        async with session_scope() as session:
            scan = models.Scan(
                organization_id=seeded["org_id"], target="127.0.0.1",
                scan_type=enums.ScanType.FULL, status=enums.ScanStatus.QUEUED,
                config={"ports": "8931", "subdomains": False}, stats={})
            session.add(scan)
            await session.flush()
            await ScanPipeline(session).run(scan)

            assert scan.status == enums.ScanStatus.COMPLETED
            assert scan.stats["open_ports"] >= 1
            assert scan.stats["services"] >= 1

            findings = (await session.execute(
                select(models.Finding).where(models.Finding.organization_id == seeded["org_id"])
            )).scalars().all()
            # Expect at least: exposed-service + verification (no-auth) + CVE correlation.
            assert len(findings) >= 2
            titles = " ".join(f.title.lower() for f in findings)
            assert "redis" in titles
            # Evidence-based: at least one confirmed (verification) finding.
            assert any(f.state == enums.FindingState.CONFIRMED for f in findings)
            # And at least one potentially-affected (CVE correlation) finding.
            assert any(f.state == enums.FindingState.POTENTIALLY_AFFECTED for f in findings)
    finally:
        server.close()


async def test_out_of_scope_is_blocked(seeded):
    async with session_scope() as session:
        scan = models.Scan(
            organization_id=seeded["org_id"], target="8.8.8.8",
            scan_type=enums.ScanType.FULL, status=enums.ScanStatus.QUEUED,
            config={"ports": "80"}, stats={})
        session.add(scan)
        await session.flush()
        await ScanPipeline(session).run(scan)
        assert scan.status == enums.ScanStatus.BLOCKED
        assert "scope" in (scan.error or "").lower()
