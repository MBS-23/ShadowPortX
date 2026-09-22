"""Authentication primitives: password hashing (bcrypt) and JWT issue/verify.

Kept dependency-light (bcrypt + PyJWT directly) to avoid passlib's compatibility
drift on newer Python. Never logs or returns plaintext secrets.
"""

from __future__ import annotations

from datetime import timedelta

import bcrypt
import jwt

from shadowportx.core.config import settings
from shadowportx.db.base import utcnow

_BCRYPT_MAX_BYTES = 72  # bcrypt truncates beyond 72 bytes; guard explicitly.


def hash_password(password: str) -> str:
    pw = password.encode("utf-8")[:_BCRYPT_MAX_BYTES]
    return bcrypt.hashpw(pw, bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8")[:_BCRYPT_MAX_BYTES], hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def create_access_token(subject: str, *, role: str, org_id: int, extra: dict | None = None) -> str:
    now = utcnow()
    payload = {
        "sub": subject,
        "role": role,
        "org": org_id,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
        "iss": "shadowportx",
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict:
    """Decode & verify a JWT. Raises ``jwt.PyJWTError`` on any problem."""
    return jwt.decode(
        token,
        settings.secret_key,
        algorithms=[settings.jwt_algorithm],
        issuer="shadowportx",
        options={"require": ["exp", "iat", "sub"]},
    )
