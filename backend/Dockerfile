# ShadowPortX 2.0 backend image
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps: libpcap for optional scapy SYN scanning; curl for healthcheck.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps first (better layer caching).
COPY pyproject.toml README.md ./
COPY shadowportx ./shadowportx
RUN pip install --upgrade pip && pip install .

# Runtime dirs + non-root user.
RUN mkdir -p /app/var && useradd -m -u 10001 spx && chown -R spx:spx /app
USER spx

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/health || exit 1

CMD ["uvicorn", "shadowportx.main:app", "--host", "0.0.0.0", "--port", "8000"]
