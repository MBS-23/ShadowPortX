"""Authorization scope control — the platform's primary safety guardrail.

ShadowPortX only assesses targets the operator is authorized to assess. Every scan
passes through :func:`evaluate` before any packet is sent. The model is deliberately
conservative:

* **Deny always wins.** A matching deny rule blocks the target outright.
* **Allow is required.** With enforcement on, a target with no matching allow rule is
  blocked (default-deny), not scanned.
* Rules match by exact domain, wildcard domain (``*.example.com``), exact IP, or CIDR.

This is pure/functional (operates on plain dataclasses) so it is trivially unit-testable
without a database.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass


@dataclass(frozen=True)
class ScopeRuleData:
    kind: str          # "allow" | "deny"
    target_type: str   # "domain" | "wildcard" | "ip" | "cidr"
    value: str


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    matched_rule: ScopeRuleData | None = None


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _domain_matches(rule: ScopeRuleData, target: str) -> bool:
    t = target.lower().rstrip(".")
    v = rule.value.lower().rstrip(".")
    if rule.target_type == "domain":
        return t == v
    if rule.target_type == "wildcard":
        # "*.example.com" matches any subdomain AND the apex example.com.
        base = v[2:] if v.startswith("*.") else v
        return t == base or t.endswith("." + base)
    return False


def _ip_matches(rule: ScopeRuleData, target: str) -> bool:
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        return False
    if rule.target_type == "ip":
        try:
            return ip == ipaddress.ip_address(rule.value)
        except ValueError:
            return False
    if rule.target_type == "cidr":
        try:
            return ip in ipaddress.ip_network(rule.value, strict=False)
        except ValueError:
            return False
    return False


def _matches(rule: ScopeRuleData, target: str) -> bool:
    if _is_ip(target):
        return _ip_matches(rule, target)
    return _domain_matches(rule, target)


def evaluate(target: str, rules: list[ScopeRuleData], *, enforce: bool = True) -> ScopeDecision:
    """Decide whether ``target`` may be scanned given ``rules``."""
    target = (target or "").strip()
    if not target:
        return ScopeDecision(False, "Empty target.")

    # 1) Deny wins.
    for rule in rules:
        if rule.kind == "deny" and _matches(rule, target):
            return ScopeDecision(False, f"Target matches deny rule '{rule.value}'.", rule)

    # 2) Allow required (unless enforcement disabled).
    for rule in rules:
        if rule.kind == "allow" and _matches(rule, target):
            return ScopeDecision(True, f"Target authorized by allow rule '{rule.value}'.", rule)

    if not enforce:
        return ScopeDecision(True, "Scope enforcement disabled (explicit override).")

    return ScopeDecision(
        False,
        "Target is outside the authorized scope. Add an allow rule for it before scanning.",
    )
