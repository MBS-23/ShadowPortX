"""Desktop launcher — run the ShadowPortX platform locally and open the dashboard.

Serves the API and the bundled dashboard (``webui/``) from a single process, then opens the
browser. Package with PyInstaller for an offline desktop build (see docs/DEPLOY.md).
"""

from __future__ import annotations

import threading
import time
import webbrowser

import uvicorn

HOST, PORT = "127.0.0.1", 8000


def _open_browser() -> None:
    time.sleep(2.0)
    try:
        webbrowser.open(f"http://{HOST}:{PORT}")
    except Exception:
        pass


def main() -> None:
    threading.Thread(target=_open_browser, daemon=True).start()
    uvicorn.run("shadowportx.main:app", host=HOST, port=PORT, log_level="info")


if __name__ == "__main__":
    main()
