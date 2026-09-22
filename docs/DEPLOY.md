# Deployment guide

ShadowPortX has a Python backend (FastAPI) that performs scanning and a React dashboard.
Pick the model that fits your environment.

| Model | Best for | Backend | Dashboard |
|---|---|---|---|
| Local dev | development | uvicorn `:8000` | Vite `:5173` |
| Single process | demos, small self-host | uvicorn serves both at `:8000` | bundled `webui/` |
| Docker Compose | full self-host | container | container (nginx) |
| Vercel + host | public showcase | container host | Vercel (static) |

---

## 1. Local development
```bash
# backend
cd backend && python -m venv .venv
./.venv/Scripts/pip install -e ".[dev]"          # Linux/macOS: .venv/bin/pip
./.venv/Scripts/python -m uvicorn shadowportx.main:app --reload
# dashboard (new terminal)
cd frontend && npm install && npm run dev
```

## 2. Single process (one artifact serves API + dashboard)
```bash
cd frontend && npm run build && cp -r dist ../backend/webui
cd ../backend && ./.venv/Scripts/python -m uvicorn shadowportx.main:app
# open http://localhost:8000  (dashboard). API stays under /api/v1
```
When `backend/webui/` exists the API serves the SPA at `/` (with client-side-routing
fallback); otherwise `/` redirects to `/docs`.

## 3. Docker Compose (recommended self-host)
```bash
cd deploy && docker compose up --build
# dashboard http://localhost:8080 · API http://localhost:8000
```
Brings up PostgreSQL + backend + dashboard. Set real values for `SPX_SECRET_KEY` and
`SPX_ADMIN_PASSWORD` in `deploy/docker-compose.yml` before any non-local use.

## 4. Vercel (dashboard) + hosted backend
The dashboard is a static SPA — ideal for Vercel. The backend needs raw sockets and
long-running jobs, so host it on a container platform (Render, Railway, Fly.io, a VPS, or the
Docker image), **not** on serverless.

**Dashboard on Vercel**
1. New Project → import the repo → set **Root Directory** to `frontend`.
2. Framework preset **Vite** (build `npm run build`, output `dist`) — see `frontend/vercel.json`.
3. Add env var `VITE_API_BASE = https://<your-backend-host>/api/v1`.
4. Deploy.

**Backend on a container host**
```bash
docker build -t shadowportx-backend ./backend
docker run -p 8000:8000 \
  -e SPX_ENVIRONMENT=production -e SPX_DEBUG=false \
  -e SPX_SECRET_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')" \
  -e SPX_DATABASE_URL="postgresql+asyncpg://user:pass@host:5432/shadowportx" \
  -e SPX_CORS_ORIGINS="https://<your-vercel-app>.vercel.app" \
  -e SPX_ADMIN_PASSWORD="<strong-password>" \
  shadowportx-backend
```
The backend refuses to start in production with a weak/default `SPX_SECRET_KEY`.

## 5. Desktop executable (optional)
For an offline single-file desktop build, package the single-process launcher with
PyInstaller after building the frontend into `backend/webui/`:
```bash
cd backend && ./.venv/Scripts/pip install pyinstaller
./.venv/Scripts/pyinstaller --noconfirm --name ShadowPortX --onefile \
  --add-data "webui;webui" --add-data "shadowportx/data;shadowportx/data" \
  --collect-all shadowportx desktop/launch.py
```
This is an advanced/optional path; Docker Compose and Vercel are the recommended,
fully-supported deployment options.

## Environment variables
See [`backend/.env.example`](../backend/.env.example). Key: `SPX_DATABASE_URL`,
`SPX_SECRET_KEY`, `SPX_DEBUG`, `SPX_ENVIRONMENT`, `SPX_ENFORCE_SCOPE`, `SPX_CORS_ORIGINS`,
`SPX_ADMIN_PASSWORD`, `SPX_INTEL_OFFLINE_ONLY`, `SPX_NVD_API_KEY`, `SPX_API_RATE_LIMIT_PER_MIN`.
