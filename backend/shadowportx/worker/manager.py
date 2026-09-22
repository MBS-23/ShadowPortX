"""In-process asyncio job manager for running scans off the request path."""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select

from shadowportx.core import enums
from shadowportx.db import models
from shadowportx.db.base import session_scope, utcnow
from shadowportx.services.pipeline import ScanPipeline

logger = logging.getLogger("shadowportx.worker")


class JobManager:
    def __init__(self) -> None:
        self._tasks: dict[int, asyncio.Task] = {}

    def submit(self, scan_id: int) -> None:
        if scan_id in self._tasks and not self._tasks[scan_id].done():
            return
        task = asyncio.create_task(self._run(scan_id), name=f"scan-{scan_id}")
        self._tasks[scan_id] = task
        task.add_done_callback(lambda t: self._tasks.pop(scan_id, None))

    def is_running(self, scan_id: int) -> bool:
        t = self._tasks.get(scan_id)
        return bool(t and not t.done())

    async def _run(self, scan_id: int) -> None:
        try:
            async with session_scope() as session:
                scan = (await session.execute(
                    select(models.Scan).where(models.Scan.id == scan_id)
                )).scalar_one_or_none()
                if scan is None:
                    logger.warning("scan %s not found", scan_id)
                    return
                await ScanPipeline(session).run(scan)
        except asyncio.CancelledError:
            await self._mark_failed(scan_id, "cancelled")
            raise
        except Exception as exc:  # noqa: BLE001 - a worker must never crash the process
            logger.exception("scan %s failed: %s", scan_id, exc)
            await self._mark_failed(scan_id, str(exc))

    async def _mark_failed(self, scan_id: int, reason: str) -> None:
        try:
            async with session_scope() as session:
                scan = (await session.execute(
                    select(models.Scan).where(models.Scan.id == scan_id)
                )).scalar_one_or_none()
                if scan and scan.status in (enums.ScanStatus.RUNNING, enums.ScanStatus.QUEUED):
                    scan.status = enums.ScanStatus.FAILED
                    scan.error = reason
                    scan.finished_at = utcnow()
        except Exception:  # noqa: BLE001
            logger.exception("failed to mark scan %s failed", scan_id)


job_manager = JobManager()
