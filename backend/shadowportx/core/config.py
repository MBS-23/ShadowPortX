"""Central configuration for ShadowPortX 2.0.

All tunables live here (no magic numbers scattered across the engines). Values can be
overridden via environment variables or a `.env` file, following 12-factor practice.
Secrets (JWT signing key, DB URL) are read from the environment and never hardcoded.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Repo layout anchors ---------------------------------------------------------
BACKEND_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BACKEND_DIR / "shadowportx" / "data"
REPORTS_DIR = BACKEND_DIR / "var" / "reports"
LOG_DIR = BACKEND_DIR / "var" / "logs"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SPX_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- app ---
    app_name: str = "ShadowPortX"
    app_version: str = "2.5.0"
    environment: str = Field(default="development")  # development | production
    debug: bool = True

    # --- security / auth ---
    # In production this MUST be provided via env. The default is dev-only.
    secret_key: str = Field(default="dev-insecure-change-me-in-production")
    access_token_expire_minutes: int = 60 * 12
    jwt_algorithm: str = "HS256"
    # When True (default), the platform refuses to scan targets outside the
    # configured authorization scope. Disabling requires an explicit override.
    enforce_scope: bool = True
    # Platform self-protection: max API requests per client IP per minute (0 = unlimited).
    api_rate_limit_per_min: int = 600
    scheduler_enabled: bool = True
    scheduler_poll_seconds: int = 30

    # --- database ---
    # Async SQLAlchemy URL. Defaults to a local SQLite file so the platform runs
    # with zero external services; point at Postgres (asyncpg) in Docker/prod.
    database_url: str = Field(default=f"sqlite+aiosqlite:///{BACKEND_DIR / 'var' / 'shadowportx.db'}")

    # --- scanner engine defaults ---
    scan_default_ports: str = "top1000"  # "top100" | "top1000" | "1-1024" | "all"
    scan_max_concurrency: int = 200
    scan_connect_timeout: float = 1.5
    scan_banner_timeout: float = 2.5
    scan_rate_limit_per_sec: int = 500  # 0 = unlimited
    scan_retries: int = 1

    # --- recon engine ---
    recon_dns_timeout: float = 5.0
    recon_http_timeout: float = 8.0
    recon_max_subdomains: int = 2000
    recon_user_agent: str = "ShadowPortX/2.0 (+authorized-security-assessment)"

    # --- intel engine ---
    # Local seed CVE dataset ships with the repo so correlation works offline.
    # Set an NVD API key to enable live enrichment (optional, never required).
    nvd_api_key: str | None = None
    nvd_api_base: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    intel_offline_only: bool = True  # default offline for privacy & determinism

    # --- risk engine (SPX Exposure Score) ---
    # Documented weightings for the ShadowPortX Exposure Score (SPX-ES).
    # See engines/risk/scoring.py for the methodology.
    risk_weight_severity: float = 0.35
    risk_weight_exposure: float = 0.20
    risk_weight_criticality: float = 0.15
    risk_weight_confidence: float = 0.10
    risk_weight_exploit_intel: float = 0.10
    risk_weight_verification: float = 0.10

    @field_validator("environment")
    @classmethod
    def _normalize_env(cls, v: str) -> str:
        return v.strip().lower()

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    # Ensure runtime dirs exist.
    for d in (DATA_DIR, REPORTS_DIR, LOG_DIR, BACKEND_DIR / "var"):
        d.mkdir(parents=True, exist_ok=True)
    return settings


settings = get_settings()
