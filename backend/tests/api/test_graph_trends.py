"""Graph, blast-radius, and trends tests (2.5 intelligence layer)."""

import asyncio

import httpx
from sqlalchemy import select

from shadowportx.core import enums
from shadowportx.db import models
from shadowportx.db.base import session_scope
from shadowportx.services.pipeline import ScanPipeline


async def _client():
    from shadowportx.main import app
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def _run_scan(org_id: int, port: int):
    async def redis(reader, writer):
        try:
            await asyncio.wait_for(reader.read(64), timeout=1)
        except Exception:
            pass
        writer.write(b"# Server\r\nredis_version:6.0.9\r\n+PONG\r\n")
        await writer.drain()
        writer.close()

    srv = await asyncio.start_server(redis, "127.0.0.1", port)
    try:
        async with session_scope() as session:
            scan = models.Scan(organization_id=org_id, target="127.0.0.1",
                               scan_type=enums.ScanType.FULL, status=enums.ScanStatus.QUEUED,
                               config={"ports": str(port), "subdomains": False}, stats={})
            session.add(scan)
            await session.flush()
            await ScanPipeline(session).run(scan)
    finally:
        srv.close()


async def test_asset_graph_and_blast_radius(seeded):
    await _run_scan(seeded["org_id"], 8951)
    async with session_scope() as session:
        asset = (await session.execute(
            select(models.Asset).where(models.Asset.value == "127.0.0.1"))).scalar_one()
        asset_id = asset.id

    async with await _client() as c:
        g = await c.get(f"/api/v1/graph/assets/{asset_id}")
        assert g.status_code == 200
        data = g.json()
        types = {n["type"] for n in data["nodes"]}
        assert "asset" in types and "service" in types and "finding" in types
        # A finding node must carry a finding_id for navigation.
        assert any(n["type"] == "finding" and n["ref"].get("finding_id") for n in data["nodes"])

        br = await c.get("/api/v1/graph/blast-radius", params={"cve": "CVE-2022-0543"})
        assert br.status_code == 200
        assert br.json()["affected"] >= 1


async def test_trends_snapshot(seeded):
    await _run_scan(seeded["org_id"], 8952)
    async with await _client() as c:
        t = await c.get("/api/v1/trends")
        assert t.status_code == 200
        body = t.json()
        assert len(body["series"]) >= 1
        assert "org_risk" in body["current"]
