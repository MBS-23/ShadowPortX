"""Risk endpoint: distribution, top assets, and trend."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shadowportx import schemas
from shadowportx.api.deps import Context, get_context
from shadowportx.core import enums
from shadowportx.db import models
from shadowportx.db.base import get_session

router = APIRouter(tags=["risk"])


@router.get("/risk", response_model=schemas.RiskSummary)
async def risk_summary(
    ctx: Context = Depends(get_context),
    session: AsyncSession = Depends(get_session),
):
    org = ctx.org_id
    F, A = models.Finding, models.Asset
    open_filter = (F.organization_id == org, F.status != enums.FindingStatus.RESOLVED)

    org_risk = (await session.execute(
        select(func.avg(A.risk_score)).where(A.organization_id == org, A.risk_score > 0)
    )).scalar_one_or_none() or 0.0

    sev = schemas.SeverityCounts()
    for s, c in (await session.execute(
        select(F.severity, func.count(F.id)).where(*open_filter).group_by(F.severity)
    )).all():
        setattr(sev, s.value, c)

    by_category = {
        cat.value: c for cat, c in (await session.execute(
            select(F.category, func.count(F.id)).where(*open_filter).group_by(F.category)
        )).all()
    }
    by_exposure = {
        exp.value: c for exp, c in (await session.execute(
            select(F.exposure, func.count(F.id)).where(*open_filter).group_by(F.exposure)
        )).all()
    }

    top_assets = [
        schemas.RiskAsset(id=a.id, value=a.value, risk_score=a.risk_score,
                          exposure=a.exposure.value, criticality=a.criticality.value)
        for a in (await session.execute(
            select(A).where(A.organization_id == org, A.risk_score > 0)
            .order_by(desc(A.risk_score)).limit(10)
        )).scalars().all()
    ]

    # Trend from completed scans (chronological): open findings + asset risk over time.
    trend = []
    scans = (await session.execute(
        select(models.Scan).where(models.Scan.organization_id == org,
                                  models.Scan.status == enums.ScanStatus.COMPLETED)
        .order_by(models.Scan.finished_at).limit(30)
    )).scalars().all()
    for sc in scans:
        stats = sc.stats or {}
        trend.append({
            "date": (sc.finished_at or sc.created_at).strftime("%Y-%m-%d %H:%M"),
            "findings": stats.get("findings", 0),
            "avg_risk": stats.get("asset_risk", 0),
        })

    return schemas.RiskSummary(
        org_risk=round(float(org_risk), 1), severity=sev, by_category=by_category,
        by_exposure=by_exposure, top_assets=top_assets, trend=trend,
    )
