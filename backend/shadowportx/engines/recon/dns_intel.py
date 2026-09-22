"""DNS intelligence — resolves the full set of record types the ASM view needs."""

from __future__ import annotations

import asyncio

import dns.asyncresolver
import dns.resolver

from shadowportx.core.config import settings

_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]


async def _query(resolver: dns.asyncresolver.Resolver, domain: str, rtype: str) -> list[str]:
    try:
        answers = await resolver.resolve(domain, rtype)
        return [r.to_text() for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout, Exception):
        return []


async def resolve_records(domain: str) -> dict[str, list[str]]:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = settings.recon_dns_timeout
    resolver.timeout = settings.recon_dns_timeout
    results = await asyncio.gather(*(_query(resolver, domain, rt) for rt in _RECORD_TYPES))
    records = {rt: res for rt, res in zip(_RECORD_TYPES, results, strict=True) if res}
    # DNSSEC presence indicator (best-effort).
    try:
        await resolver.resolve(domain, "DNSKEY")
        records["DNSSEC"] = ["present"]
    except Exception:
        pass
    return records


async def resolve_ips(domain: str) -> list[str]:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = settings.recon_dns_timeout
    ips: list[str] = []
    for rt in ("A", "AAAA"):
        ips.extend(await _query(resolver, domain, rt))
    return ips
