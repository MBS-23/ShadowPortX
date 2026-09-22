"""Platform self-protection middleware: security headers + API rate limiting."""

from __future__ import annotations

import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from shadowportx.core.config import settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds baseline security headers to every response (the platform hardening itself)."""

    async def dispatch(self, request: Request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        # SAMEORIGIN (not DENY) so the dashboard can preview its own HTML report in an
        # iframe while still blocking cross-origin clickjacking.
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("X-XSS-Protection", "0")
        if settings.is_production:
            resp.headers.setdefault(
                "Strict-Transport-Security", "max-age=63072000; includeSubDomains"
            )
        return resp


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Fixed-window per-IP rate limit for /api/ routes (in-memory; MVP scale)."""

    def __init__(self, app, limit_per_min: int):
        super().__init__(app)
        self.limit = limit_per_min
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next):
        if self.limit <= 0 or not request.url.path.startswith("/api/"):
            return await call_next(request)
        ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        dq = self._hits[ip]
        while dq and now - dq[0] > 60:
            dq.popleft()
        if len(dq) >= self.limit:
            return JSONResponse(
                {"detail": "Rate limit exceeded. Try again shortly."},
                status_code=429, headers={"Retry-After": "60"},
            )
        dq.append(now)
        return await call_next(request)
