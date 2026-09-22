"""ShadowPortX command-line interface — run an authorized scan from the terminal.

Useful for offensive-security recon workflows and CI, sharing the exact same engine and
scope enforcement as the API/dashboard.

    python -m shadowportx.cli scan 127.0.0.1 --ports top1000
    python -m shadowportx.cli scan example.com --json report.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from shadowportx.core import enums
from shadowportx.db import models
from shadowportx.db.base import init_db, session_scope
from shadowportx.engines.reporting import gather_report_data
from shadowportx.services.pipeline import ScanPipeline
from shadowportx.services.seed import seed


async def _scan(target: str, ports: str, technique: str, subs: bool, json_path: str | None) -> int:
    await init_db()
    info = await seed()
    async with session_scope() as session:
        scan = models.Scan(
            organization_id=info["org_id"], target=target,
            scan_type=enums.ScanType.FULL, status=enums.ScanStatus.QUEUED,
            config={"ports": ports, "technique": technique, "subdomains": subs}, stats={},
        )
        session.add(scan)
        await session.flush()

        def on_progress(pct, msg):
            sys.stderr.write(f"\r[{pct:5.1f}%] {msg:<40}")
            sys.stderr.flush()

        await ScanPipeline(session).run(scan, progress=on_progress)
        sys.stderr.write("\n")

        if scan.status == enums.ScanStatus.BLOCKED:
            print(f"BLOCKED: {scan.error}", file=sys.stderr)
            print("Add an allow rule to scope for this target first.", file=sys.stderr)
            return 2

        print(f"\nScan #{scan.id} {scan.status.value} — {target}")
        for k, v in scan.stats.items():
            print(f"  {k}: {v}")

        if json_path:
            data = await gather_report_data(session, info["org_id"])
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            print(f"\nReport written to {json_path}")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="shadowportx", description="ShadowPortX 2.0 CLI")
    sub = parser.add_subparsers(dest="command", required=True)
    sc = sub.add_parser("scan", help="Run an authorized scan")
    sc.add_argument("target")
    sc.add_argument("--ports", default="top1000")
    sc.add_argument("--technique", default="tcp_connect", choices=["tcp_connect", "tcp_syn", "udp"])
    sc.add_argument("--no-subdomains", action="store_true")
    sc.add_argument("--json", dest="json_path", default=None, help="Write a JSON report")
    args = parser.parse_args()

    if args.command == "scan":
        code = asyncio.run(_scan(args.target, args.ports, args.technique,
                                 not args.no_subdomains, args.json_path))
        sys.exit(code)


if __name__ == "__main__":
    main()
