"""Engagement workspace — authorized pentest / bug-bounty assessments (3.0)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from shadowportx import schemas
from shadowportx.api.deps import Context, get_context, require_scan
from shadowportx.core import enums
from shadowportx.db import models
from shadowportx.db.base import get_session, utcnow
from shadowportx.services import persistence as P

router = APIRouter(prefix="/engagements", tags=["engagements"])


async def _get(session, org_id, eng_id) -> models.Engagement:
    eng = (await session.execute(
        select(models.Engagement).where(
            models.Engagement.id == eng_id, models.Engagement.organization_id == org_id)
    )).scalar_one_or_none()
    if not eng:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Engagement not found")
    return eng


async def _collect(session, org_id, eng_id):
    scans = (await session.execute(
        select(models.Scan).where(models.Scan.engagement_id == eng_id).order_by(desc(models.Scan.id))
    )).scalars().all()
    targets = {s.target for s in scans}
    findings, assets = [], []
    if targets:
        assets = (await session.execute(
            select(models.Asset).where(models.Asset.organization_id == org_id, models.Asset.value.in_(targets))
        )).scalars().all()
        asset_ids = [a.id for a in assets]
        if asset_ids:
            findings = (await session.execute(
                select(models.Finding).where(models.Finding.asset_id.in_(asset_ids))
                .order_by(desc(models.Finding.risk_score))
            )).scalars().all()
    return scans, assets, findings


@router.get("", response_model=list[schemas.EngagementOut])
async def list_engagements(ctx: Context = Depends(get_context), session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(
        select(models.Engagement).where(models.Engagement.organization_id == ctx.org_id)
        .order_by(desc(models.Engagement.id))
    )).scalars().all()
    return list(rows)


@router.post("", response_model=schemas.EngagementOut, status_code=status.HTTP_201_CREATED)
async def create_engagement(
    body: schemas.EngagementIn,
    ctx: Context = Depends(require_scan),
    session: AsyncSession = Depends(get_session),
):
    eng = models.Engagement(
        organization_id=ctx.org_id, name=body.name, client=body.client, kind=body.kind,
        status=body.status, scope_note=body.scope_note, tester=body.tester, notes=body.notes,
        starts_at=utcnow(),
    )
    session.add(eng)
    await session.flush()
    await P.audit(session, ctx.org_id, "engagement.created", body.name, actor=ctx.email)
    return eng


@router.get("/{eng_id}", response_model=schemas.EngagementDetail)
async def get_engagement(eng_id: int, ctx: Context = Depends(get_context), session: AsyncSession = Depends(get_session)):
    eng = await _get(session, ctx.org_id, eng_id)
    scans, assets, findings = await _collect(session, ctx.org_id, eng_id)
    sev = {s.value: 0 for s in enums.Severity}
    for f in findings:
        if f.status != enums.FindingStatus.RESOLVED:
            sev[f.severity.value] += 1
    detail = schemas.EngagementDetail.model_validate(eng)
    detail.stats = {"scans": len(scans), "assets": len(assets), "findings": len(findings), "severity": sev}
    detail.scans = [schemas.ScanOut.model_validate(s) for s in scans]
    detail.findings = [schemas.FindingOut.model_validate(f) for f in findings]
    return detail


@router.patch("/{eng_id}", response_model=schemas.EngagementOut)
async def update_engagement(
    eng_id: int, body: schemas.EngagementIn,
    ctx: Context = Depends(require_scan), session: AsyncSession = Depends(get_session),
):
    eng = await _get(session, ctx.org_id, eng_id)
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(eng, field, value)
    if body.status == "completed" and eng.ends_at is None:
        eng.ends_at = utcnow()
    return eng


@router.delete("/{eng_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_engagement(eng_id: int, ctx: Context = Depends(require_scan), session: AsyncSession = Depends(get_session)):
    eng = await _get(session, ctx.org_id, eng_id)
    await session.delete(eng)


@router.get("/{eng_id}/report")
async def engagement_report(eng_id: int, ctx: Context = Depends(get_context), session: AsyncSession = Depends(get_session)):
    """Evidence package: engagement metadata + findings with evidence & recommendations."""
    eng = await _get(session, ctx.org_id, eng_id)
    scans, assets, findings = await _collect(session, ctx.org_id, eng_id)
    return {
        "engagement": {"name": eng.name, "client": eng.client, "kind": eng.kind,
                       "tester": eng.tester, "scope": eng.scope_note, "status": eng.status,
                       "starts_at": eng.starts_at.isoformat() if eng.starts_at else None,
                       "generated_at": utcnow().isoformat()},
        "summary": {"scans": len(scans), "assets": len(assets), "findings": len(findings)},
        "assets": [a.value for a in assets],
        "findings": [
            {"spx_id": f.spx_id, "title": f.title, "severity": f.severity.value,
             "state": f.state.value, "status": f.status.value, "risk_score": f.risk_score,
             "detection_method": f.detection_method.value, "evidence": f.evidence,
             "recommendation": f.recommendation, "references": f.references, "notes": f.notes}
            for f in findings
        ],
    }
