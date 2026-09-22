"""Subdomain discovery.

Default method is DNS resolution over a built-in wordlist of common subdomains — fully
offline, no third-party data sharing. Certificate-transparency enrichment (crt.sh) is
available but opt-in (``intel_offline_only=False``) since it discloses the target to a
third party.
"""

from __future__ import annotations

import asyncio

import dns.asyncresolver
import dns.resolver
import httpx

from shadowportx.core.config import settings

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "api", "dev", "staging",
    "test", "portal", "admin", "vpn", "ns1", "ns2", "blog", "shop", "store", "app",
    "apps", "mobile", "m", "cdn", "static", "assets", "img", "images", "media",
    "docs", "support", "help", "status", "monitor", "monitoring", "grafana", "kibana",
    "jenkins", "gitlab", "git", "jira", "confluence", "dashboard", "beta", "demo",
    "secure", "login", "auth", "sso", "id", "account", "accounts", "billing", "pay",
    "payment", "payments", "internal", "intranet", "corp", "cloud", "db", "database",
    "redis", "cache", "queue", "mq", "kafka", "elastic", "search", "analytics",
    "metrics", "logs", "log", "backup", "old", "new", "v1", "v2", "v3", "stage",
    "uat", "qa", "sandbox", "preview", "gateway", "proxy", "edge", "origin", "ws",
    "socket", "chat", "email", "ns", "mx", "autodiscover", "remote", "citrix", "owa",
]


async def _resolves(resolver: dns.asyncresolver.Resolver, fqdn: str) -> str | None:
    try:
        await resolver.resolve(fqdn, "A")
        return fqdn
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout, Exception):
        return None


async def _crtsh(domain: str) -> set[str]:
    """Certificate-transparency lookup (opt-in). Returns discovered names."""
    found: set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=settings.recon_http_timeout) as client:
            resp = await client.get(f"https://crt.sh/?q=%25.{domain}&output=json")
            if resp.status_code == 200:
                for entry in resp.json():
                    for name in str(entry.get("name_value", "")).splitlines():
                        name = name.strip().lstrip("*.").lower()
                        if name.endswith(domain):
                            found.add(name)
    except Exception:
        pass
    return found


async def discover(domain: str, *, include_ct: bool | None = None) -> list[str]:
    domain = domain.lower().strip().rstrip(".")
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = settings.recon_dns_timeout

    candidates = {f"{sub}.{domain}" for sub in COMMON_SUBDOMAINS}

    use_ct = (not settings.intel_offline_only) if include_ct is None else include_ct
    if use_ct:
        candidates |= await _crtsh(domain)

    # Resolve concurrently (bounded).
    sem = asyncio.Semaphore(100)

    async def bounded(fqdn: str) -> str | None:
        async with sem:
            return await _resolves(resolver, fqdn)

    limited = list(candidates)[: settings.recon_max_subdomains]
    results = await asyncio.gather(*(bounded(f) for f in limited))
    return sorted({r for r in results if r})
