"""Inventory endpoints: services, technologies, and the vulnerability catalog."""

from __future__ import annotations

from collections import defaultdict

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shadowportx import schemas
from shadowportx.api.deps import Context, get_context
from shadowportx.db import models
from shadowportx.db.base import get_session

router = APIRouter(tags=["inventory"])


@router.get("/services", response_model=list[schemas.ServiceRow])
async def list_services(
    ctx: Context = Depends(get_context),
    session: AsyncSession = Depends(get_session),
    limit: int = 500,
):
    rows = (await session.execute(
        select(models.Service, models.Port, models.Asset)
        .join(models.Port, models.Service.port_id == models.Port.id)
        .join(models.Asset, models.Port.asset_id == models.Asset.id)
        .where(models.Asset.organization_id == ctx.org_id)
        .order_by(models.Asset.value, models.Port.number)
        .limit(limit)
    )).all()
    return [
        schemas.ServiceRow(
            id=s.id, asset_id=a.id, asset=a.value, port=p.number, protocol=p.protocol.value,
            name=s.name, product=s.product, version=s.version,
            confidence=s.confidence.value, verified=s.verified,
            detection_method=s.detection_method.value,
        )
        for s, p, a in rows
    ]


@router.get("/technologies", response_model=list[schemas.TechnologyRow])
async def list_technologies(
    ctx: Context = Depends(get_context),
    session: AsyncSession = Depends(get_session),
):
    rows = (await session.execute(
        select(models.Technology, models.Asset.id)
        .join(models.Asset, models.Technology.asset_id == models.Asset.id)
        .where(models.Asset.organization_id == ctx.org_id)
    )).all()
    grouped: dict[str, dict] = defaultdict(lambda: {"category": None, "versions": set(), "assets": set()})
    for tech, asset_id in rows:
        g = grouped[tech.name]
        g["category"] = g["category"] or tech.category
        if tech.version:
            g["versions"].add(tech.version)
        g["assets"].add(asset_id)
    return [
        schemas.TechnologyRow(
            name=name, category=g["category"],
            versions=sorted(g["versions"]), asset_count=len(g["assets"]),
        )
        for name, g in sorted(grouped.items(), key=lambda kv: -len(kv[1]["assets"]))
    ]


@router.get("/vulnerabilities", response_model=list[schemas.VulnerabilityRow])
async def list_vulnerabilities(
    ctx: Context = Depends(get_context),
    session: AsyncSession = Depends(get_session),
):
    # Count findings per vulnerability within this org.
    counts = dict((await session.execute(
        select(models.Finding.vulnerability_id, func.count(models.Finding.id))
        .where(models.Finding.organization_id == ctx.org_id,
               models.Finding.vulnerability_id.isnot(None))
        .group_by(models.Finding.vulnerability_id)
    )).all())
    if not counts:
        return []
    vulns = (await session.execute(
        select(models.Vulnerability).where(models.Vulnerability.id.in_(counts.keys()))
        .order_by(models.Vulnerability.cvss_score.desc())
    )).scalars().all()
    return [
        schemas.VulnerabilityRow(
            id=v.id, cve_id=v.cve_id, title=v.title, cvss_score=v.cvss_score,
            severity=v.severity, exploit_known=v.exploit_known,
            affected_findings=counts.get(v.id, 0), references=v.references or [],
        )
        for v in vulns
    ]
