"""Background job execution.

MVP uses an in-process asyncio job manager (matches the brief's "asyncio worker
architecture for your initial implementation"). The interface is intentionally small so a
Celery/Redis or RQ backend can replace it later without touching the API layer.
"""

from shadowportx.worker.manager import JobManager, job_manager

__all__ = ["JobManager", "job_manager"]
