"""Asset relationship graph + blast-radius analysis (intelligence over existing data).

The graph is a navigation interface for security data: every node carries a ``ref`` so the
UI can deep-link (a finding node opens its finding page). Blast radius answers "how many
assets does this technology/CVE touch?".
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from shadowportx import schemas
from shadowportx.api.deps import Context, get_context
from shadowportx.core import enums
from shadowportx.db import models
from shadowportx.db.base import get_session

router = APIRouter(prefix="/graph", tags=["graph"])


@router.get("/assets/{asset_id}", response_model=schemas.GraphResponse)
async def asset_graph(
    asset_id: int,
    ctx: Context = Depends(get_context),
    session: AsyncSession = Depends(get_session),
):
    asset = (await session.execute(
        select(models.Asset)
        .where(models.Asset.id == asset_id, models.Asset.organization_id == ctx.org_id)
        .options(
            selectinload(models.Asset.ports).selectinload(models.Port.services),
            selectinload(models.Asset.technologies),
        )
    )).scalar_one_or_none()
    if not asset:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")

    findings = (await session.execute(
        select(models.Finding).where(models.Finding.asset_id == asset_id)
    )).scalars().all()
    vuln_ids = {f.vulnerability_id for f in findings if f.vulnerability_id}
    vulns = {}
    if vuln_ids:
        for v in (await session.execute(
            select(models.Vulnerability).where(models.Vulnerability.id.in_(vuln_ids))
        )).scalars().all():
            vulns[v.id] = v

    nodes: list[schemas.GraphNode] = []
    edges: list[schemas.GraphEdge] = []
    seen: set[str] = set()

    def add_node(nid, ntype, label, ref=None):
        if nid not in seen:
            seen.add(nid)
            nodes.append(schemas.GraphNode(id=nid, type=ntype, label=label, ref=ref or {}))

    def add_edge(src, dst, rel):
        edges.append(schemas.GraphEdge(source=src, target=dst, rel=rel))

    root = f"asset:{asset.id}"
    add_node(root, "asset", asset.value, {"asset_id": asset.id, "risk": asset.risk_score,
                                          "exposure": asset.exposure.value})
    anchor = root
    if asset.ip_address:
        ip_id = f"ip:{asset.ip_address}"
        add_node(ip_id, "ip", asset.ip_address, {"ip": asset.ip_address})
        add_edge(root, ip_id, "RESOLVES_TO")
        anchor = ip_id

    svc_node_by_id: dict[int, str] = {}
    for port in asset.ports:
        if port.state != enums.PortState.OPEN:
            continue
        pid = f"port:{port.id}"
        add_node(pid, "port", f"{port.number}/{port.protocol.value}", {"port": port.number})
        add_edge(anchor, pid, "EXPOSES")
        for svc in port.services:
            sid = f"svc:{svc.id}"
            label = svc.product or svc.name or "service"
            add_node(sid, "service", f"{label}{(' ' + svc.version) if svc.version else ''}",
                     {"verified": svc.verified, "port": port.number})
            add_edge(pid, sid, "RUNS")
            svc_node_by_id[svc.id] = sid

    for tech in asset.technologies:
        tid = f"tech:{tech.id}"
        add_node(tid, "technology", f"{tech.name}{(' ' + tech.version) if tech.version else ''}",
                 {"category": tech.category})
        add_edge(root, tid, "USES")

    for f in findings:
        fid = f"finding:{f.id}"
        add_node(fid, "finding", f.spx_id,
                 {"finding_id": f.id, "severity": f.severity.value, "risk": f.risk_score,
                  "title": f.title, "state": f.state.value})
        src = svc_node_by_id.get(f.service_id, root)
        if f.vulnerability_id and f.vulnerability_id in vulns:
            v = vulns[f.vulnerability_id]
            vid = f"vuln:{v.cve_id}"
            add_node(vid, "vulnerability", v.cve_id,
                     {"cvss": v.cvss_score, "severity": v.severity.value, "exploit_known": v.exploit_known})
            add_edge(src, vid, "AFFECTED_BY")
            add_edge(vid, fid, "HAS_FINDING")
        else:
            add_edge(src, fid, "HAS_FINDING")

    return schemas.GraphResponse(asset_id=asset.id, root=root, nodes=nodes, edges=edges)


@router.get("/blast-radius", response_model=schemas.BlastRadius)
async def blast_radius(
    technology: str | None = None,
    cve: str | None = None,
    ctx: Context = Depends(get_context),
    session: AsyncSession = Depends(get_session),
):
    if not technology and not cve:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Provide ?technology= or ?cve=")

    A = models.Asset
    if technology:
        key, kind = technology, "technology"
        asset_ids = [row[0] for row in (await session.execute(
            select(func.distinct(models.Technology.asset_id))
            .join(A, models.Technology.asset_id == A.id)
            .where(A.organization_id == ctx.org_id, func.lower(models.Technology.name) == technology.lower())
        )).all()]
    else:
        key, kind = cve, "cve"
        asset_ids = [row[0] for row in (await session.execute(
            select(func.distinct(models.Finding.asset_id))
            .join(models.Vulnerability, models.Finding.vulnerability_id == models.Vulnerability.id)
            .where(models.Finding.organization_id == ctx.org_id, models.Vulnerability.cve_id == cve)
        )).all()]

    assets = []
    if asset_ids:
        assets = (await session.execute(
            select(A).where(A.id.in_(asset_ids)).order_by(A.risk_score.desc())
        )).scalars().all()

    return schemas.BlastRadius(
        key=key, kind=kind, affected=len(assets),
        internet_facing=sum(1 for a in assets if a.exposure == enums.Exposure.INTERNET_FACING),
        production=sum(1 for a in assets if a.environment == enums.Environment.PRODUCTION),
        critical_assets=sum(1 for a in assets if a.criticality == enums.Criticality.CRITICAL),
        assets=[schemas.BlastAsset(id=a.id, value=a.value, exposure=a.exposure.value,
                                   criticality=a.criticality.value, risk_score=a.risk_score)
                for a in assets],
    )
