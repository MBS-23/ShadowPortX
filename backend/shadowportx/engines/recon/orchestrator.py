"""Recon orchestrator — domain-level discovery (DNS, subdomains, WHOIS).

Per-host TLS and HTTP intelligence live in :mod:`tls_intel` / :mod:`http_intel` and are
invoked by the scan pipeline once open web/TLS ports are known.
"""

from __future__ import annotations

import asyncio
import ipaddress

from shadowportx.engines.recon import dns_intel, subdomain, whois_intel
from shadowportx.engines.results import ReconResult


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


class ReconEngine:
    async def run(self, target: str, *, do_subdomains: bool = True, do_whois: bool = True) -> ReconResult:
        target = target.strip().lower().rstrip(".")
        result = ReconResult(target=target)

        if _is_ip(target):
            result.resolved_ips = [target]
            return result

        # Run domain-level lookups concurrently.
        tasks = {
            "dns": dns_intel.resolve_records(target),
            "ips": dns_intel.resolve_ips(target),
        }
        if do_subdomains:
            tasks["subs"] = subdomain.discover(target)
        if do_whois:
            tasks["whois"] = whois_intel.lookup(target)

        gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
        out = dict(zip(tasks.keys(), gathered, strict=True))

        result.dns_records = out["dns"] if isinstance(out["dns"], dict) else {}
        result.resolved_ips = out["ips"] if isinstance(out["ips"], list) else []
        if "subs" in out and isinstance(out["subs"], list):
            result.subdomains = out["subs"]
        if "whois" in out and isinstance(out["whois"], dict):
            result.whois = out["whois"]
        return result
