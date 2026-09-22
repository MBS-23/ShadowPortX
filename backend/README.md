# ShadowPortX 2.0 — Backend

FastAPI + async SQLAlchemy backend for the ShadowPortX Attack Surface Intelligence platform.

```bash
python -m venv .venv && ./.venv/Scripts/pip install -e ".[dev]"   # Windows
uvicorn shadowportx.main:app --reload                              # run API at :8000
pytest -q                                                          # run tests
python -m shadowportx.cli scan 127.0.0.1 --ports top1000          # CLI scan
```

See the repository root `README.md` for full documentation and architecture.
