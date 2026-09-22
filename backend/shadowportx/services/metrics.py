"""Security-metrics snapshots — the data behind trends and posture deltas."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shadowportx.core import enums
from shadowportx.db import models


async def _count(session: AsyncSession, stmt) -> int:
    return int((await session.execute(stmt)).scalar_one() or 0)


async def compute_metrics(session: AsyncSession, org_id: int) -> tuple[float, dict]:
    A, F, S, P_, T = (models.Asset, models.Finding, models.Service, models.Port, models.Technology)

    assets = await _count(session, select(func.count(A.id)).where(A.organization_id == org_id))
    internet_facing = await _count(session, select(func.count(A.id)).where(
        A.organization_id == org_id, A.exposure == enums.Exposure.INTERNET_FACING))
    unknown_assets = await _count(session, select(func.count(A.id)).where(
        A.organization_id == org_id, A.is_known.is_(False)))
    services = await _count(session, select(func.count(S.id)).join(P_, S.port_id == P_.id)
                            .join(A, P_.asset_id == A.id).where(A.organization_id == org_id))
    technologies = await _count(session, select(func.count(func.distinct(T.name)))
                                .join(A, T.asset_id == A.id).where(A.organization_id == org_id))

    open_filter = (F.organization_id == org_id, F.status != enums.FindingStatus.RESOLVED)
    open_findings = await _count(session, select(func.count(F.id)).where(*open_filter))
    resolved = await _count(session, select(func.count(F.id)).where(
        F.organization_id == org_id, F.status == enums.FindingStatus.RESOLVED))

    sev = {s.value: 0 for s in enums.Severity}
    for s, c in (await session.execute(
        select(F.severity, func.count(F.id)).where(*open_filter).group_by(F.severity)
    )).all():
        sev[s.value] = c

    org_risk = (await session.execute(
        select(func.avg(A.risk_score)).where(A.organization_id == org_id, A.risk_score > 0)
    )).scalar_one_or_none() or 0.0

    metrics = {
        "assets": assets, "internet_facing": internet_facing, "unknown_assets": unknown_assets,
        "services": services, "technologies": technologies,
        "open_findings": open_findings, "resolved": resolved,
        "critical": sev["critical"], "high": sev["high"], "medium": sev["medium"],
        "low": sev["low"], "info": sev["info"],
    }
    return round(float(org_risk), 1), metrics


async def capture_snapshot(session: AsyncSession, org_id: int, scan_id: int | None = None,
                           scan_stats: dict | None = None) -> models.MetricSnapshot:
    org_risk, metrics = await compute_metrics(session, org_id)
    stats = scan_stats or {}
    metrics["new_exposures"] = int(stats.get("new_ports", 0)) + int(stats.get("new_subdomains", 0))
    metrics["new_services"] = int(stats.get("new_ports", 0))
    metrics["new_findings"] = int(stats.get("new_findings", 0))
    snap = models.MetricSnapshot(organization_id=org_id, scan_id=scan_id, org_risk=org_risk, metrics=metrics)
    session.add(snap)
    await session.flush()
    return snap
