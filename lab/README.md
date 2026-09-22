# ShadowPortX Validation Lab

Intentionally-vulnerable services plus hardened counterparts, for validating detection,
verification, CVE correlation, risk scoring, and the remediation → re-scan loop.

> ⚠️ **Local testing only.** Everything binds to `127.0.0.1`. Never expose the `*-vuln` /
> `*-open` / `*-anon` services on a reachable network.

## Run

```bash
cd lab
docker compose up -d
```

| Service | Port | What ShadowPortX should report |
|---|---|---|
| redis-vuln | 6379 | Exposed Redis, **no-auth verified**, CVE-2022-0543 (via version) |
| mongo-vuln | 27017 | Exposed MongoDB, **no-auth verified** |
| memcached-vuln | 11211 | Exposed memcached |
| nginx-old | 8080 | nginx 1.18.0 → CVE-2021-23017, missing security headers |
| grafana-anon | 3000 | Grafana **anonymous access verified** |
| elasticsearch-open | 9200 | Elasticsearch **no-auth verified** |
| redis-hardened | 6380 | Auth enforced (informational only) |
| nginx-hardened | 8081 | No missing-header findings |

## Demonstrate the lifecycle

```bash
# From backend/ (venv active):
python -m shadowportx.cli scan 127.0.0.1 --ports 3000,6379,8080,9200,11211,27017 --no-subdomains
# ... review findings, then re-scan the hardened ports to see the surface shrink:
python -m shadowportx.cli scan 127.0.0.1 --ports 6380,8081 --no-subdomains
```

Detection → Verification → Finding → Risk → Remediation → Re-scan → Resolved.
