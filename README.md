# ShadowPortX 3.0

**Attack Surface Intelligence, Exposure Management & Offensive Security Validation Platform**

ShadowPortX 2.0 is an authorized attack-surface assessment platform that discovers assets,
identifies exposed services, fingerprints technologies, performs **non-destructive
service verification**, correlates findings with **public vulnerability intelligence**,
tracks attack-surface **changes**, and prioritizes remediation with a documented,
contextual **ShadowPortX Exposure Score (SPX-ES)**.

> **Authorized assessment only.** Every scan passes a scope guardrail (default-deny).
> Verification is read-only and non-destructive. Vulnerability handling is *intelligence
> correlation* — never automated exploitation.

It evolves the original **ShadowPortX 1.0** desktop scanner (preserved in
[`legacy/v1.0-desktop/`](legacy/v1.0-desktop/)) into a full platform:

```
DISCOVER → IDENTIFY → VERIFY → CORRELATE → PRIORITIZE → MONITOR → REMEDIATE → VALIDATE
```

---

## Architecture

```
                         React dashboard (Vite + Tailwind + Recharts)
                                        │  /api/v1
                                        ▼
                              FastAPI  (async, JWT/RBAC)
                                        │
        ┌───────────────┬──────────────┼───────────────┬────────────────┐
        ▼               ▼              ▼               ▼                ▼
   Recon Engine    Scanner Engine  Verification    Intel Engine    Risk Engine
   DNS/subdomain   TCP/UDP/SYN     Redis/Mongo     CPE→CVE→CVSS    SPX-ES
   WHOIS/TLS/HTTP  banner/service  Docker/ES/...   (offline seed)  (contextual)
        └───────────────┴──────────────┼───────────────┴────────────────┘
                                        ▼
                              Correlation Engine → Findings (evidence-based)
                                        ▼
              Change detection · Continuous monitoring · Reporting · Notifications
                                        ▼
                     SQLAlchemy (async)  →  SQLite (dev) / PostgreSQL (prod)
```

Backend package lives in [`backend/shadowportx/`](backend/shadowportx/); engines are
independent and unit-tested (`engines/{scanner,recon,verification,intel,correlation,risk,reporting}`).

---

## Quickstart

### Backend (API)
```bash
cd backend
python -m venv .venv
./.venv/Scripts/pip install -e ".[dev]"      # Windows  (Linux/macOS: .venv/bin/pip)
./.venv/Scripts/python -m uvicorn shadowportx.main:app --reload
# API + docs: http://localhost:8000/docs
```

### Frontend (dashboard)
```bash
cd frontend
npm install
npm run dev
# Dashboard: http://localhost:5173  (proxies /api → :8000)
```
Dev login: `admin@shadowportx.local` / `shadowportx` (in debug mode the dashboard also
works without login). Override with `SPX_ADMIN_PASSWORD`.

### Demo data (real, engine-produced)
```bash
cd backend && ./.venv/Scripts/python scripts/seed_demo.py
```
Spins up local fake services and runs a real scan → populates assets, services, findings.

### CLI
```bash
python -m shadowportx.cli scan 127.0.0.1 --ports top1000 --json report.json
```

### Full stack (Docker)
```bash
cd deploy && docker compose up --build
# Dashboard: http://localhost:8080   API: http://localhost:8000
```

### Validation lab
```bash
cd lab && docker compose up -d   # vulnerable + hardened services on 127.0.0.1
```
See [`lab/README.md`](lab/README.md) for the detection → remediation → re-scan walkthrough.

---

## Features

| Capability | Detail |
|---|---|
| **Asset discovery** | Domains, subdomains (wordlist + optional CT), IPs, DNS (A/AAAA/CNAME/MX/NS/TXT/SOA/CAA/DNSSEC), WHOIS |
| **Network discovery** | Async TCP connect / SYN (scapy) / UDP, controlled concurrency, rate limiting, timeouts, retries |
| **Service detection** | Protocol-first fingerprinting with evidence + confidence + CPE (works on non-standard ports) |
| **Service verification** | Non-destructive checks: Redis, MongoDB, Elasticsearch, Docker API, memcached, FTP (anon), SMTP, Grafana, Jenkins, Kibana |
| **Web/TLS intelligence** | Security headers, redirects, cookies, technology fingerprinting; TLS versions, cert validity/expiry, SANs |
| **Vulnerability intelligence** | Offline CVE seed dataset → version-aware CPE/CVE/CVSS correlation (correlation, not exploitation) |
| **Risk engine** | SPX-ES: severity + exposure + criticality + confidence + exploit intel + verification, with transparent breakdown |
| **Findings** | Evidence-based, states (detected / potentially-affected / confirmed), lifecycle, dedupe, auto-resolve |
| **Change detection** | New/removed assets, ports, services; risk increased/decreased |
| **Continuous monitoring** | Scheduled recurring scans (in-process asyncio scheduler) |
| **Remediation loop** | "Verify fix" re-scan → findings auto-resolve, risk drops |
| **Asset graph** | Clickable relationship map (asset→ip→port→service→technology→vulnerability→finding) used as a navigation surface |
| **Blast radius** | "How many assets does this technology/CVE touch?" — affected / internet-facing / production / critical counts |
| **Security trends** | Metric snapshot per scan → executive posture, multi-metric trend, and *why did risk change* contributors |
| **Engagement workspace** | Authorized pentest / bug-bounty workspaces grouping scope, scans, findings, evidence + evidence-package export |
| **Safe validation** | Non-destructive confirmation of findings (L0–L2 via read-only verification). **L3 PoC / L4 exploitation are not enabled** — no fake confirmations |
| **Reporting** | Executive + technical in JSON / CSV / HTML / PDF |
| **Notifications** | Outbound webhooks (Slack/Teams/Discord/generic) on new high/critical findings |
| **Platform** | JWT auth + RBAC (owner/admin/analyst/developer/viewer), scope guardrail, audit log, security headers, API rate limiting |

---

## SPX Exposure Score (SPX-ES)

Not CVSS. CVSS measures a vulnerability's intrinsic severity; **SPX-ES answers "what should
this organization fix first?"**

```
SPX-ES = 100 · Σ (weightᵢ · factorᵢ) + modifiers        (clamped 0–100)

factor         weight   source
severity        0.35    CVSS/10 or qualitative rank
exposure        0.20    internet-facing > limited > internal
criticality     0.15    business criticality of the asset
confidence      0.10    detection confidence
exploit_intel   0.10    public exploit / KEV known
verification    0.10    was a security condition actually observed
```

The full per-factor breakdown is shown on every finding (methodology in
[`engines/risk/scoring.py`](backend/shadowportx/engines/risk/scoring.py)). Weights are
configurable via `SPX_RISK_WEIGHT_*`.

---

## API (`/api/v1`)

`auth` · `overview` · `risk` · `trends` · `graph` (+ `blast-radius`) · `assets` · `services` ·
`technologies` · `vulnerabilities` · `findings` (+ `{id}/verify`, `{id}/validate`) · `changes` · `scans` (+ `{a}/compare/{b}`) ·
`engagements` (+ `{id}/report`) · `schedules` · `notifications` · `scope` · `reports`. Docs at `/docs`.

## Data model

`organizations · users · scope_rules · assets · ports · services · technologies ·
certificates · scans · asset_changes · vulnerabilities · findings · reports · audit_log ·
schedules · notification_channels · metric_snapshots · engagements` (async SQLAlchemy;
SQLite dev / PostgreSQL prod).

---

## Testing & CI

```bash
cd backend && pytest -q          # 50 tests: scope, scanner, detector, intel, risk, recon,
                                 # verification, reporting, pipeline, graph, trends, engagements, API
ruff check . && bandit -c pyproject.toml -r shadowportx
```
GitHub Actions ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs lint (ruff),
security (bandit + pip-audit), tests (pytest + coverage), frontend build, and Docker builds
on every push/PR.

## Security posture

Scope enforcement (default-deny), non-destructive verification, correlation-not-exploitation,
JWT/RBAC, audit logging, security headers, API rate limiting, secrets via env (never in
source), bandit + pip-audit in CI. The platform can assess itself in the lab.

## Configuration

Copy [`backend/.env.example`](backend/.env.example) → `.env`. Key vars: `SPX_DATABASE_URL`,
`SPX_SECRET_KEY`, `SPX_ENFORCE_SCOPE`, `SPX_DEBUG`, `SPX_ADMIN_PASSWORD`,
`SPX_INTEL_OFFLINE_ONLY`, `SPX_NVD_API_KEY`, `SPX_API_RATE_LIMIT_PER_MIN`.

## Version story

- **1.0** ([`legacy/`](legacy/v1.0-desktop/)) — PyQt6 desktop scanner (TCP/UDP/stealth/version, DNS/WHOIS, PDF/JSON).
- **2.0** — attack-surface intelligence platform (asset inventory, service verification, CVE intel, SPX-ES, findings, change detection, monitoring, RBAC, reporting).
- **2.5** — asset relationship graph, blast-radius analysis, security-trend intelligence + executive posture.
- **3.0** (this repo) — **engagement workspaces (pentest / bug-bounty), evidence packages, and
  safe non-destructive validation** (L0–L2; L3/L4 exploitation deliberately not enabled).
- **Enterprise roadmap** — SSO/SAML/OIDC + MFA, hardened multi-tenant isolation + teams,
  vendor connectors (Jira/ServiceNow/Splunk/Sentinel) on the notification interface,
  Celery/Redis workers, Kubernetes deployment.

## License

MIT.

---
🤖 Generated with [Claude Code](https://claude.com/claude-code)
