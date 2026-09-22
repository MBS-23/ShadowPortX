"""ShadowPortX 2.0 FastAPI application entry point."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from shadowportx import __version__
from shadowportx.api.middleware import RateLimitMiddleware, SecurityHeadersMiddleware
from shadowportx.api.v1 import api_router
from shadowportx.core.config import settings
from shadowportx.db.base import init_db
from shadowportx.services.seed import seed
from shadowportx.worker.scheduler import scheduler

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("shadowportx")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting ShadowPortX %s (env=%s, db=%s)", __version__, settings.environment,
                "sqlite" if settings.is_sqlite else "postgres")
    await init_db()
    info = await seed()
    logger.info("Seeded default org id=%s (scope enforcement=%s)", info["org_id"], settings.enforce_scope)
    if settings.scheduler_enabled:
        scheduler.poll_seconds = settings.scheduler_poll_seconds
        scheduler.start()
    yield
    await scheduler.stop()
    logger.info("ShadowPortX shutting down")


app = FastAPI(
    title="ShadowPortX",
    version=__version__,
    description=(
        "Attack Surface Intelligence & Security Exposure Management Platform. "
        "Authorized assessment only — non-destructive verification, vulnerability "
        "intelligence *correlation* (not exploitation), contextual risk prioritization."
    ),
    lifespan=lifespan,
)

# CORS for the React dashboard (Vite dev + previews). Credentials allowed for JWT.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173", "http://127.0.0.1:5173",
        "http://localhost:4173", "http://127.0.0.1:4173",
        "http://localhost:3000", "http://127.0.0.1:3000",
    ],
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware, limit_per_min=settings.api_rate_limit_per_min)

app.include_router(api_router)


@app.get("/health", tags=["meta"])
async def health():
    return {"status": "ok", "service": "shadowportx", "version": __version__,
            "scope_enforcement": settings.enforce_scope}


@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/docs")
