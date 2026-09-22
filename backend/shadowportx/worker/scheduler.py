"""Continuous-monitoring scheduler.

Periodically enqueues scans for due :class:`Schedule` rows, powering ongoing
attack-surface monitoring and change detection. In-process asyncio (matches the MVP worker
model); swappable for Celery beat / a cron sidecar later.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

from sqlalchemy import select

from shadowportx.core import enums
from shadowportx.db import models
from shadowportx.db.base import session_scope, utcnow
from shadowportx.worker.manager import job_manager

logger = logging.getLogger("shadowportx.scheduler")


class Scheduler:
    def __init__(self, poll_seconds: int = 30):
        self.poll_seconds = poll_seconds
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._loop(), name="spx-scheduler")
            logger.info("Scheduler started (poll=%ss)", self.poll_seconds)

    async def stop(self) -> None:
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _loop(self) -> None:
        while True:
            try:
                await self._tick()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - scheduler must not die
                logger.exception("scheduler tick failed: %s", exc)
            await asyncio.sleep(self.poll_seconds)

    async def _tick(self) -> None:
        created: list[int] = []
        async with session_scope() as session:
            now = utcnow()
            due = (await session.execute(
                select(models.Schedule).where(
                    models.Schedule.enabled.is_(True),
                    models.Schedule.next_run_at.isnot(None),
                    models.Schedule.next_run_at <= now,
                )
            )).scalars().all()
            for sched in due:
                scan = models.Scan(
                    organization_id=sched.organization_id, target=sched.target,
                    scan_type=enums.ScanType.FULL, status=enums.ScanStatus.QUEUED,
                    config={"ports": sched.ports or "top1000", "subdomains": sched.subdomains},
                    stats={},
                )
                session.add(scan)
                await session.flush()
                created.append(scan.id)
                sched.last_run_at = now
                sched.next_run_at = now + timedelta(minutes=sched.interval_minutes)
        # Submit outside the transaction so the scan rows are visible to the worker.
        for scan_id in created:
            job_manager.submit(scan_id)
        if created:
            logger.info("Scheduler enqueued %d scan(s)", len(created))


scheduler = Scheduler()
