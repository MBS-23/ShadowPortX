# ShadowPortX — single-service image (one container serves the API and the dashboard).
# Ideal for free hosting (Render / Fly / Railway): build the React SPA, then let the
# FastAPI backend serve it from /app/backend/webui at the same origin (no CORS needed).
#
#   docker build -t shadowportx .
#   docker run -p 8000:8000 -e SPX_SECRET_KEY=$(openssl rand -hex 32) shadowportx
#   open http://localhost:8000

# --- Stage 1: build the dashboard ---
FROM node:20-slim AS frontend
WORKDIR /fe
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build          # -> /fe/dist

# --- Stage 2: backend runtime that also serves the built SPA ---
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# libpcap for optional scapy SYN scanning; curl for the health check.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 curl \
    && rm -rf /var/lib/apt/lists/*

# Install the backend (editable, so the package stays in the source tree and main.py can
# locate ./webui next to it via parents[1]).
COPY backend/pyproject.toml backend/README.md /app/backend/
COPY backend/shadowportx /app/backend/shadowportx
RUN pip install --upgrade pip && pip install -e /app/backend

# Drop the built dashboard where the backend serves it (backend/webui).
COPY --from=frontend /fe/dist /app/backend/webui

# Runtime dirs + non-root user.
RUN mkdir -p /app/backend/var && useradd -m -u 10001 spx && chown -R spx:spx /app
USER spx

WORKDIR /app/backend
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT:-8000}/health" || exit 1

# Bind to the platform-provided $PORT when present (Render/Fly set it), else 8000.
CMD ["sh", "-c", "uvicorn shadowportx.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
