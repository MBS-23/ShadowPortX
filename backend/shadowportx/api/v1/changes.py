"""Attack-surface change endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from shadowportx import schemas
from shadowportx.api.deps import Context, get_context
from shadowportx.core import enums
from shadowportx.db import models
from shadowportx.db.base import get_session

router = APIRouter(prefix="/changes", tags=["changes"])


@router.get("", response_model=list[schemas.ChangeOut])
async def list_changes(
    ctx: Context = Depends(get_context),
    session: AsyncSession = Depends(get_session),
    change_type: enums.ChangeType | None = None,
    asset_id: int | None = None,
    limit: int = 200,
):
    stmt = select(models.AssetChange).where(models.AssetChange.organization_id == ctx.org_id)
    if change_type:
        stmt = stmt.where(models.AssetChange.change_type == change_type)
    if asset_id:
        stmt = stmt.where(models.AssetChange.asset_id == asset_id)
    stmt = stmt.order_by(desc(models.AssetChange.detected_at)).limit(limit)
    return list((await session.execute(stmt)).scalars().all())
