"""Security trends & executive posture — turns metric snapshots into intelligence."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shadowportx import schemas
from shadowportx.api.deps import Context, get_context
from shadowportx.core import enums
from shadowportx.db import models
from shadowportx.db.base import get_session

router = APIRouter(tags=["trends"])


async def _count(session, stmt) -> int:
    return int((await session.execute(stmt)).scalar_one() or 0)


@router.get("/trends", response_model=schemas.Trends)
async def trends(
    ctx: Context = Depends(get_context),
    session: AsyncSession = Depends(get_session),
    limit: int = 60,
):
    snaps = (await session.execute(
        select(models.MetricSnapshot).where(models.MetricSnapshot.organization_id == ctx.org_id)
        .order_by(models.MetricSnapshot.ts).limit(limit)
    )).scalars().all()

    series = [schemas.TrendPoint(ts=s.ts.isoformat(), org_risk=s.org_risk, metrics=s.metrics) for s in snaps]
    if not snaps:
        return schemas.Trends()

    cur = snaps[-1]
    prev = snaps[-2] if len(snaps) > 1 else None
    current = {"org_risk": cur.org_risk, **cur.metrics}
    previous = {"org_risk": prev.org_risk, **prev.metrics} if prev else {}

    change = {}
    if prev:
        for k in ("org_risk", "assets", "internet_facing", "unknown_assets", "services",
                  "open_findings", "critical", "high", "resolved"):
            change[k] = round(current.get(k, 0) - previous.get(k, 0), 1)

    # Contributors — what happened between the previous and current snapshot.
    contributors = {}
    if prev:
        F, C = models.Finding, models.AssetChange
        window = (C.organization_id == ctx.org_id, C.detected_at > prev.ts, C.detected_at <= cur.ts)
        contributors = {
            "findings_resolved": await _count(session, select(func.count(F.id)).where(
                F.organization_id == ctx.org_id, F.resolved_at.isnot(None),
                F.resolved_at > prev.ts, F.resolved_at <= cur.ts)),
            "new_findings": await _count(session, select(func.count(F.id)).where(
                F.organization_id == ctx.org_id, F.first_seen > prev.ts, F.first_seen <= cur.ts)),
            "new_assets": await _count(session, select(func.count(C.id)).where(
                *window, C.change_type == enums.ChangeType.NEW_ASSET)),
            "new_services": await _count(session, select(func.count(C.id)).where(
                *window, C.change_type.in_([enums.ChangeType.NEW_PORT, enums.ChangeType.NEW_SERVICE]))),
            "services_removed": await _count(session, select(func.count(C.id)).where(
                *window, C.change_type.in_([enums.ChangeType.PORT_CLOSED, enums.ChangeType.SERVICE_REMOVED]))),
            "technology_changes": await _count(session, select(func.count(C.id)).where(
                *window, C.change_type.in_([enums.ChangeType.TECHNOLOGY_CHANGED, enums.ChangeType.VERSION_CHANGED]))),
            "certificate_changes": await _count(session, select(func.count(C.id)).where(
                *window, C.change_type == enums.ChangeType.CERTIFICATE_CHANGED)),
        }

    executive = {
        "current_exposure": cur.org_risk,
        "previous_exposure": prev.org_risk if prev else cur.org_risk,
        "change": round(cur.org_risk - (prev.org_risk if prev else cur.org_risk), 1),
        "critical_findings": current.get("critical", 0),
        "high_findings": current.get("high", 0),
        "resolved_this_period": contributors.get("findings_resolved", 0),
        "unknown_assets": current.get("unknown_assets", 0),
        "new_exposures": current.get("new_exposures", 0),
        "internet_facing": current.get("internet_facing", 0),
        "assets": current.get("assets", 0),
    }

    return schemas.Trends(series=series, current=current, previous=previous,
                          change=change, contributors=contributors, executive=executive)
