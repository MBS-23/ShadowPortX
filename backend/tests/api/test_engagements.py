"""Engagement workspace + safe validation tests (3.0)."""

import asyncio

import httpx

from shadowportx.core import enums
from shadowportx.db import models
from shadowportx.db.base import session_scope
from shadowportx.services.pipeline import ScanPipeline


async def _client():
    from shadowportx.main import app
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def test_engagement_workspace_and_validation(seeded):
    org_id = seeded["org_id"]

    async def redis(reader, writer):
        try:
            await asyncio.wait_for(reader.read(64), timeout=1)
        except Exception:
            pass
        writer.write(b"# Server\r\nredis_version:6.0.9\r\n+PONG\r\n")
        await writer.drain()
        writer.close()

    srv = await asyncio.start_server(redis, "127.0.0.1", 8961)
    try:
        async with await _client() as c:
            e = await c.post("/api/v1/engagements",
                             json={"name": "Acme Pentest", "client": "Acme", "tester": "Sunil"})
            assert e.status_code == 201
            eng_id = e.json()["id"]

        # Scan linked to the engagement.
        async with session_scope() as session:
            scan = models.Scan(organization_id=org_id, target="127.0.0.1", engagement_id=eng_id,
                               scan_type=enums.ScanType.FULL, status=enums.ScanStatus.QUEUED,
                               config={"ports": "8961", "subdomains": False}, stats={})
            session.add(scan)
            await session.flush()
            await ScanPipeline(session).run(scan)

        async with await _client() as c:
            d = await c.get(f"/api/v1/engagements/{eng_id}")
            assert d.status_code == 200
            body = d.json()
            assert body["stats"]["scans"] >= 1
            assert len(body["findings"]) >= 1

            rep = await c.get(f"/api/v1/engagements/{eng_id}/report")
            assert rep.status_code == 200 and len(rep.json()["findings"]) >= 1

            # Validate a verification-based finding (redis no-auth).
            fid = next(f["id"] for f in body["findings"]
                       if f["category"] == "service_misconfiguration")
            v = await c.post(f"/api/v1/findings/{fid}/validate")
            assert v.status_code == 200
            assert v.json()["state"] in ("confirmed", "needs_verification")
            assert "message" in v.json()
    finally:
        srv.close()


async def test_engagement_crud(seeded):
    async with await _client() as c:
        created = await c.post("/api/v1/engagements", json={"name": "Bug Bounty", "kind": "bug_bounty"})
        assert created.status_code == 201
        eid = created.json()["id"]
        listed = await c.get("/api/v1/engagements")
        assert any(e["id"] == eid for e in listed.json())
        patched = await c.patch(f"/api/v1/engagements/{eid}", json={"name": "Bug Bounty", "status": "completed"})
        assert patched.status_code == 200 and patched.json()["status"] == "completed"
