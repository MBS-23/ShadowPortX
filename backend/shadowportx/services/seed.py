"""Seed the default organization, authorization scope, and an admin user.

Idempotent: safe to call on every startup.
"""

from __future__ import annotations

import logging
import os

from sqlalchemy import select

from shadowportx.core import enums
from shadowportx.core.config import settings
from shadowportx.core.security import hash_password
from shadowportx.db import models
from shadowportx.db.base import session_scope
from shadowportx.services import persistence as P

logger = logging.getLogger("shadowportx.seed")

DEFAULT_ORG_NAME = "ShadowPortX Demo Org"
DEFAULT_ORG_SLUG = "default"
DEFAULT_ADMIN_EMAIL = os.environ.get("SPX_ADMIN_EMAIL", "admin@shadowportx.local")
# Dev default; override with SPX_ADMIN_PASSWORD. A warning is logged if the default is
# used in production.
_DEFAULT_ADMIN_PASSWORD = "shadowportx"  # nosec B105

# Authorized-by-default demo scope: localhost + the RFC-safe example domains + the local lab.
_DEFAULT_SCOPE = [
    ("allow", "ip", "127.0.0.1", "localhost IPv4"),
    ("allow", "domain", "localhost", "localhost name"),
    ("allow", "cidr", "127.0.0.0/8", "loopback range"),
    ("allow", "wildcard", "*.example.com", "IANA example domain (safe for demos)"),
    ("allow", "domain", "example.com", "IANA example domain"),
    ("allow", "domain", "scanme.nmap.org", "Nmap's explicitly authorized scan target"),
    ("allow", "cidr", "172.16.0.0/12", "local Docker lab range"),
]


async def seed() -> dict:
    async with session_scope() as session:
        org = await P.get_or_create_org(session, DEFAULT_ORG_NAME, DEFAULT_ORG_SLUG)

        # Scope
        existing = {
            (r.kind, r.target_type, r.value)
            for r in (await session.execute(
                select(models.ScopeRule).where(models.ScopeRule.organization_id == org.id)
            )).scalars().all()
        }
        for kind, ttype, value, note in _DEFAULT_SCOPE:
            if (kind, ttype, value) not in existing:
                session.add(models.ScopeRule(
                    organization_id=org.id, kind=kind, target_type=ttype, value=value, note=note))

        # Admin user
        admin = (await session.execute(
            select(models.User).where(models.User.organization_id == org.id,
                                      models.User.email == DEFAULT_ADMIN_EMAIL)
        )).scalar_one_or_none()
        if admin is None:
            password = os.environ.get("SPX_ADMIN_PASSWORD", _DEFAULT_ADMIN_PASSWORD)
            if settings.is_production and password == _DEFAULT_ADMIN_PASSWORD:
                logger.warning(
                    "Seeding admin with the DEFAULT password in production. "
                    "Set SPX_ADMIN_PASSWORD and rotate this credential immediately."
                )
            session.add(models.User(
                organization_id=org.id, email=DEFAULT_ADMIN_EMAIL, full_name="Demo Admin",
                hashed_password=hash_password(password), role=enums.UserRole.ADMIN))

        await session.flush()
        return {"org_id": org.id, "org_slug": org.slug}
