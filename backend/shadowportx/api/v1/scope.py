"""Authorization scope management endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shadowportx import schemas
from shadowportx.api.deps import Context, get_context, require_manage
from shadowportx.db import models
from shadowportx.db.base import get_session
from shadowportx.services import persistence as P

router = APIRouter(prefix="/scope", tags=["scope"])


@router.get("", response_model=list[schemas.ScopeRuleOut])
async def list_scope(
    ctx: Context = Depends(get_context),
    session: AsyncSession = Depends(get_session),
):
    rows = (await session.execute(
        select(models.ScopeRule).where(models.ScopeRule.organization_id == ctx.org_id)
    )).scalars().all()
    return list(rows)


@router.post("", response_model=schemas.ScopeRuleOut, status_code=status.HTTP_201_CREATED)
async def add_scope(
    body: schemas.ScopeRuleIn,
    ctx: Context = Depends(require_manage),
    session: AsyncSession = Depends(get_session),
):
    rule = models.ScopeRule(
        organization_id=ctx.org_id, kind=body.kind, target_type=body.target_type,
        value=body.value.strip().lower(), note=body.note,
    )
    session.add(rule)
    await session.flush()
    await P.audit(session, ctx.org_id, "scope.added", rule.value,
                  kind=rule.kind, target_type=rule.target_type, actor=ctx.email)
    return rule


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scope(
    rule_id: int,
    ctx: Context = Depends(require_manage),
    session: AsyncSession = Depends(get_session),
):
    rule = (await session.execute(
        select(models.ScopeRule).where(
            models.ScopeRule.id == rule_id, models.ScopeRule.organization_id == ctx.org_id)
    )).scalar_one_or_none()
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scope rule not found")
    await session.delete(rule)
    await P.audit(session, ctx.org_id, "scope.deleted", rule.value, actor=ctx.email)
