"""ShadowPortX 2.0 FastAPI application entry point."""

from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from shadowportx import __version__
from shadowportx.api.middleware import RateLimitMiddleware, SecurityHeadersMiddleware
from shadowportx.api.v1 import api_router
from shadowportx.core.config import settings
from shadowportx.db.base import init_db
from shadowportx.services.seed import seed
from shadowportx.worker.scheduler import scheduler

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("shadowportx")


# The insecure default we refuse to run with in production (checked in lifespan below).
_DEV_SECRET = "dev-insecure-change-me-in-production"  # nosec B105


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting ShadowPortX %s (env=%s, db=%s)", __version__, settings.environment,
                "sqlite" if settings.is_sqlite else "postgres")
    # Hardening: never run production with the insecure default signing key or the dev auth bypass.
    if settings.is_production:
        if settings.secret_key == _DEV_SECRET or len(settings.secret_key) < 32:
            raise RuntimeError(
                "Refusing to start in production with a weak/default SPX_SECRET_KEY. "
                "Set a strong random value (>= 32 chars)."
            )
        if settings.debug:
            logger.warning("SPX_DEBUG is true in production; the auth fallback is active. Set SPX_DEBUG=false.")
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

# CORS for the React dashboard (Vite dev + previews) plus any configured production origins.
_cors_origins = [
    "http://localhost:5173", "http://127.0.0.1:5173",
    "http://localhost:4173", "http://127.0.0.1:4173",
    "http://localhost:3000", "http://127.0.0.1:3000",
]
_cors_origins += [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
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
            "database": "sqlite" if settings.is_sqlite else "postgres",
            "scope_enforcement": settings.enforce_scope}


# Optionally serve the built dashboard from this same process (single-artifact / desktop /
# self-host). Enabled when a `webui/` build is present next to the package or in the PyInstaller
# bundle. When absent (dev/tests), "/" simply redirects to the API docs.
_WEBUI = next(
    (p for p in (
        Path(getattr(sys, "_MEIPASS", "")) / "webui" if getattr(sys, "_MEIPASS", "") else None,
        Path(__file__).resolve().parents[1] / "webui",
    ) if p and p.exists()),
    None,
)

if _WEBUI is not None:
    if (_WEBUI / "assets").exists():
        app.mount("/assets", StaticFiles(directory=_WEBUI / "assets"), name="assets")

    @app.get("/", include_in_schema=False)
    async def spa_root():
        return FileResponse(_WEBUI / "index.html")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_catch_all(full_path: str):
        candidate = _WEBUI / full_path
        if full_path and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(_WEBUI / "index.html")  # SPA client-side routing fallback
else:
    @app.get("/", include_in_schema=False)
    async def root():
        return RedirectResponse(url="/docs")
