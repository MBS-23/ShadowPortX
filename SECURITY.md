# Security Policy

## Authorized use

ShadowPortX is a defensive/authorized-assessment platform. It must only be pointed at
systems you own or are explicitly authorized to test. Every scan passes a **default-deny
scope guardrail** before any packet is sent, and service checks are **non-destructive**.
Vulnerability handling is **intelligence correlation** — the platform never runs automated
exploitation.

## Product security model

- **Scope enforcement** — allow/deny rules; deny wins; unknown targets are refused.
- **AuthN/AuthZ** — JWT auth with role-based access control (owner/admin/analyst/developer/viewer).
- **Non-destructive verification** — read-only protocol checks only; controlled PoC (L3) and
  exploitation (L4) are intentionally **not** implemented.
- **Platform hardening** — security headers, per-IP API rate limiting, input validation
  (Pydantic), ORM-parameterized queries (no string SQL), audit logging.
- **Secrets** — read from the environment; `.env` is git-ignored. The server **refuses to start
  in production** with a weak/default `SPX_SECRET_KEY`.
- **Supply chain** — CI runs `ruff`, `bandit` (SAST), and `pip-audit` (dependency audit) on every push.

## Reporting a vulnerability

Please open a private security advisory on the repository, or contact the maintainer directly.
Do not open a public issue for undisclosed vulnerabilities. We aim to acknowledge reports within
72 hours.

## Hardening checklist for deployments

- Set a strong `SPX_SECRET_KEY` (>= 32 random chars) and `SPX_DEBUG=false`.
- Use PostgreSQL (`SPX_DATABASE_URL`) and restrict database network access.
- Front the API with TLS and set `SPX_CORS_ORIGINS` to your dashboard origin only.
- Keep `SPX_ENFORCE_SCOPE=true` and review scope rules regularly.
- Rotate the seeded admin credential (`SPX_ADMIN_PASSWORD`) immediately.
