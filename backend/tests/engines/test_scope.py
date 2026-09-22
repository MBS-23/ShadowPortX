from shadowportx.core import scope


def _rules():
    return [
        scope.ScopeRuleData("allow", "wildcard", "*.example.com"),
        scope.ScopeRuleData("allow", "cidr", "10.0.0.0/24"),
        scope.ScopeRuleData("allow", "domain", "scanme.nmap.org"),
        scope.ScopeRuleData("deny", "domain", "secret.example.com"),
    ]


def test_wildcard_allows_subdomain():
    assert scope.evaluate("api.example.com", _rules()).allowed


def test_wildcard_allows_apex():
    assert scope.evaluate("example.com", _rules()).allowed


def test_deny_wins_over_allow():
    d = scope.evaluate("secret.example.com", _rules())
    assert not d.allowed and "deny" in d.reason.lower()


def test_out_of_scope_blocked():
    assert not scope.evaluate("evil.com", _rules()).allowed


def test_cidr_allows_ip_inside():
    assert scope.evaluate("10.0.0.5", _rules()).allowed


def test_cidr_excludes_ip_outside():
    assert not scope.evaluate("10.0.1.5", _rules()).allowed


def test_exact_domain():
    assert scope.evaluate("scanme.nmap.org", _rules()).allowed


def test_enforcement_off_allows_anything():
    assert scope.evaluate("anything.com", [], enforce=False).allowed


def test_empty_target_blocked():
    assert not scope.evaluate("", _rules()).allowed
