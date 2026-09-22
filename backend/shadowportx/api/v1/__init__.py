"""API v1 router aggregation."""

from fastapi import APIRouter

from shadowportx.api.v1 import (
    assets,
    auth,
    changes,
    dashboard,
    engagements,
    findings,
    graph,
    inventory,
    notifications,
    reports,
    risk,
    scans,
    schedules,
    scope,
    trends,
)

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(auth.router)
api_router.include_router(dashboard.router)
api_router.include_router(risk.router)
api_router.include_router(trends.router)
api_router.include_router(graph.router)
api_router.include_router(scans.router)
api_router.include_router(engagements.router)
api_router.include_router(assets.router)
api_router.include_router(inventory.router)
api_router.include_router(findings.router)
api_router.include_router(changes.router)
api_router.include_router(schedules.router)
api_router.include_router(notifications.router)
api_router.include_router(scope.router)
api_router.include_router(reports.router)

__all__ = ["api_router"]
