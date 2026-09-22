"""Dashboard / overview aggregation endpoint."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shadowportx import schemas
from shadowportx.api.deps import Context, get_context
from shadowportx.core import enums
from shadowportx.db import models
from shadowportx.db.base import get_session, utcnow

router = APIRouter(tags=["dashboard"])


async def _count(session: AsyncSession, stmt) -> int:
    return int((await session.execute(stmt)).scalar_one() or 0)


@router.get("/overview", response_model=schemas.Overview)
async def overview(
    ctx: Context = Depends(get_context),
    session: AsyncSession = Depends(get_session),
):
    org = ctx.org_id
    A, F, S, P_, T, C = (models.Asset, models.Finding, models.Service, models.Port,
                         models.Technology, models.AssetChange)

    assets = await _count(session, select(func.count(A.id)).where(A.organization_id == org))
    internet_facing = await _count(session, select(func.count(A.id)).where(
        A.organization_id == org, A.exposure == enums.Exposure.INTERNET_FACING))
    unknown_assets = await _count(session, select(func.count(A.id)).where(
        A.organization_id == org, A.is_known.is_(False)))
    technologies = await _count(session, select(func.count(func.distinct(T.name)))
                                .join(A, T.asset_id == A.id).where(A.organization_id == org))
    services = await _count(session, select(func.count(S.id)).join(P_, S.port_id == P_.id)
                            .join(A, P_.asset_id == A.id).where(A.organization_id == org))

    findings = await _count(session, select(func.count(F.id)).where(F.organization_id == org))
    resolved = await _count(session, select(func.count(F.id)).where(
        F.organization_id == org, F.status == enums.FindingStatus.RESOLVED))
    open_findings = findings - resolved

    # Severity counts over open findings.
    sev_rows = (await session.execute(
        select(F.severity, func.count(F.id)).where(
            F.organization_id == org, F.status != enums.FindingStatus.RESOLVED
        ).group_by(F.severity)
    )).all()
    sev = schemas.SeverityCounts()
    for severity, count in sev_rows:
        setattr(sev, severity.value, count)

    org_risk = (await session.execute(
        select(func.avg(A.risk_score)).where(A.organization_id == org, A.risk_score > 0)
    )).scalar_one_or_none() or 0.0

    since = utcnow() - timedelta(days=7)
    recent_changes = await _count(session, select(func.count(C.id)).where(
        C.organization_id == org, C.detected_at >= since))
    scans = await _count(session, select(func.count(models.Scan.id)).where(
        models.Scan.organization_id == org))

    top = (await session.execute(
        select(F).where(F.organization_id == org, F.status != enums.FindingStatus.RESOLVED)
        .order_by(desc(F.risk_score)).limit(8)
    )).scalars().all()
    changes = (await session.execute(
        select(C).where(C.organization_id == org).order_by(desc(C.detected_at)).limit(10)
    )).scalars().all()

    return schemas.Overview(
        org_risk=round(float(org_risk), 1),
        assets=assets, internet_facing=internet_facing, unknown_assets=unknown_assets,
        services=services, technologies=technologies,
        findings=findings, open_findings=open_findings, resolved_findings=resolved,
        severity=sev, recent_changes=recent_changes, scans=scans,
        top_findings=list(top), recent_changes_list=list(changes),
    )
