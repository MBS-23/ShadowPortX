"""Populate the database with realistic demo data.

Spins up non-destructive *fake* vulnerable services on localhost (authorized scope) and
runs a real ShadowPortX scan against them, so the dashboard shows genuine, engine-produced
findings rather than hardcoded numbers. Safe: everything binds to 127.0.0.1.

    cd backend && ./.venv/Scripts/python.exe scripts/seed_demo.py
"""

from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select  # noqa: E402

from shadowportx.core import enums  # noqa: E402
from shadowportx.db import models  # noqa: E402
from shadowportx.db.base import init_db, session_scope  # noqa: E402
from shadowportx.services.pipeline import ScanPipeline  # noqa: E402
from shadowportx.services.seed import seed  # noqa: E402


def _http_response(server: str, body: bytes, ctype: str = "application/json") -> bytes:
    return (
        b"HTTP/1.1 200 OK\r\nServer: %b\r\nContent-Type: %b\r\n"
        b"Content-Length: %d\r\nConnection: close\r\n\r\n%b"
        % (server.encode(), ctype.encode(), len(body), body)
    )


async def _read_request(reader) -> str:
    try:
        data = await asyncio.wait_for(reader.read(2048), timeout=3)
        return data.decode("latin1", "ignore")
    except Exception:
        return ""


def make_http_fake(server: str, routes: dict[str, bytes], default: bytes):
    async def handler(reader, writer):
        req = await _read_request(reader)
        path = req.split(" ")[1] if " " in req else "/"
        body = default
        for prefix, payload in routes.items():
            if path.startswith(prefix):
                body = payload
                break
        writer.write(_http_response(server, body))
        try:
            await writer.drain()
        except Exception:
            pass
        writer.close()
    return handler


async def redis_handler(reader, writer):
    try:
        await asyncio.wait_for(reader.read(128), timeout=3)
    except Exception:
        pass
    writer.write(b"# Server\r\nredis_version:6.0.9\r\nredis_mode:standalone\r\nos:Linux\r\n+PONG\r\n")
    try:
        await writer.drain()
    except Exception:
        pass
    writer.close()


async def ssh_handler(reader, writer):
    writer.write(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n")
    try:
        await writer.drain()
        await asyncio.wait_for(reader.read(64), timeout=3)
    except Exception:
        pass
    writer.close()


async def start_baseline() -> list:
    """Initial exposure: redis, ssh, nginx."""
    return [
        await asyncio.start_server(redis_handler, "127.0.0.1", 6379),
        await asyncio.start_server(ssh_handler, "127.0.0.1", 8022),
        await asyncio.start_server(
            make_http_fake("nginx/1.18.0",
                           {"/": b"<html><head><title>Acme Staging</title></head><body>ok</body></html>"},
                           b"<html><title>Acme Staging</title></html>"),
            "127.0.0.1", 8090),
    ]


async def start_expansion() -> list:
    """New exposures appearing later: elasticsearch, docker API, grafana."""
    es_body = b'{"name":"es01","cluster_name":"prod-logs","version":{"number":"7.10.0","lucene_version":"8.7.0"}}'
    docker_body = b'{"Version":"24.0.5","ApiVersion":"1.43","Os":"linux","Arch":"amd64"}'
    grafana_health = b'{"commit":"abc","database":"ok","version":"9.0.0"}'
    grafana_org = b'{"id":1,"name":"Main Org."}'
    return [
        await asyncio.start_server(
            make_http_fake("Elasticsearch",
                           {"/_cat/indices": b'[{"index":"users"},{"index":"orders"}]', "/": es_body},
                           es_body),
            "127.0.0.1", 9200),
        await asyncio.start_server(
            make_http_fake("Docker/24.0.5", {"/version": docker_body}, docker_body),
            "127.0.0.1", 2375),
        await asyncio.start_server(
            make_http_fake("nginx",
                           {"/api/health": grafana_health, "/api/org": grafana_org,
                            "/": b"<html><title>Grafana</title>grafana</html>"},
                           grafana_health),
            "127.0.0.1", 3000),
    ]


def _prog(pct, msg):
    sys.stdout.write(f"\r[{pct:5.1f}%] {msg:<45}")
    sys.stdout.flush()


async def _scan(org_id: int, ports: str, engagement_id: int | None = None) -> dict:
    async with session_scope() as session:
        scan = models.Scan(organization_id=org_id, target="127.0.0.1", engagement_id=engagement_id,
                           scan_type=enums.ScanType.FULL, status=enums.ScanStatus.QUEUED,
                           config={"ports": ports, "subdomains": False}, stats={})
        session.add(scan)
        await session.flush()
        await ScanPipeline(session).run(scan, progress=_prog)
        print()
        return dict(scan.stats)


async def main() -> None:
    await init_db()
    info = await seed()
    org_id = info["org_id"]

    # Demo engagement so the 3.0 workspace is populated.
    async with session_scope() as session:
        eng = models.Engagement(organization_id=org_id, name="Acme External Assessment",
                                client="Acme Corp", kind="pentest", tester="Demo Analyst",
                                scope_note="127.0.0.0/8 (local lab)", status="active")
        session.add(eng)
        await session.flush()
        eng_id = eng.id

    # --- Scan 1: baseline exposure ---
    base = await start_baseline()
    print("Phase 1 — baseline services up (redis, ssh, nginx). Scanning…")
    s1 = await _scan(org_id, "22,443,6379,8022,8090", engagement_id=eng_id)
    print("Baseline scan:", s1)

    # Tag the asset with business context so risk contextualization is meaningful.
    async with session_scope() as session:
        asset = (await session.execute(
            select(models.Asset).where(models.Asset.value == "127.0.0.1"))).scalar_one()
        asset.criticality = enums.Criticality.HIGH
        asset.environment = enums.Environment.PRODUCTION
        asset.owner = "Platform Engineering"
        asset.business_unit = "Infrastructure"
        asset.application = "Demo Lab"

    # --- Scan 2: new exposures appear (elasticsearch, docker, grafana) ---
    expansion = await start_expansion()
    print("\nPhase 2 — new services exposed (elasticsearch, docker, grafana). Re-scanning…")
    s2 = await _scan(org_id, "22,443,2375,3000,6379,8022,8090,9200", engagement_id=eng_id)
    print("Expanded scan:", s2)

    for srv in base + expansion:
        srv.close()

    async with session_scope() as session:
        findings = (await session.execute(select(models.Finding))).scalars().all()
        snaps = (await session.execute(select(models.MetricSnapshot))).scalars().all()
        changes = (await session.execute(select(models.AssetChange))).scalars().all()
        print(f"\nSeeded {len(findings)} findings, {len(snaps)} trend snapshots, "
              f"{len(changes)} change events. Start the API to view the dashboard.")


if __name__ == "__main__":
    asyncio.run(main())
