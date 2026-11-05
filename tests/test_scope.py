"""Scope-lock unit tests. No live tools, no network — only loopback-safe DNS-ish checks
(IP literals resolve instantly; the one hostname case uses a name guaranteed not to exist)."""

from dogpark.scope import Scope


def make_scope():
    return Scope(
        allowed_cidrs=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"],
        lab_subnet="192.168.1.0/24",
    )


def test_in_range_allow():
    scope = make_scope()
    result = scope.check("192.168.1.50")
    assert result.ok is True
    assert result.ip == "192.168.1.50"


def test_public_ip_rejected():
    scope = make_scope()
    result = scope.check("8.8.8.8")
    assert result.ok is False
    assert "public" in result.reason.lower() or "out of scope" in result.reason.lower()


def test_metadata_address_rejected():
    scope = make_scope()
    result = scope.check("169.254.169.254")
    assert result.ok is False
    assert "metadata" in result.reason.lower()


def test_out_of_subnet_rejected():
    # 192.168.2.0/24 is outside the allowed 192.168.0.0/16? No — it's INSIDE 192.168.0.0/16.
    # Use a target outside every allowed CIDR to test the out-of-range path.
    scope = make_scope()
    result = scope.check("203.0.113.5")  # TEST-NET-3, public, not in any allowed CIDR
    assert result.ok is False


def test_out_of_lab_subnet_but_in_rfc1918_still_allowed():
    # 10.x.x.x is allowed via the broader RFC1918 CIDR even though it's outside lab_subnet.
    scope = make_scope()
    result = scope.check("10.1.2.3")
    assert result.ok is True


def test_strict_subnet_only_scope_rejects_outside_lab_subnet():
    # A scope configured with ONLY the lab subnet (no broad RFC1918) should reject a 10.x host.
    scope = Scope(allowed_cidrs=["192.168.1.0/24"], lab_subnet=None)
    result = scope.check("10.1.2.3")
    assert result.ok is False


def test_bad_hostname_not_ok():
    scope = make_scope()
    result = scope.check("this-host-does-not-exist.invalid")
    assert result.ok is False
    assert "resolve" in result.reason.lower()


def test_link_local_apipa_rejected():
    scope = make_scope()
    result = scope.check("169.254.1.1")
    assert result.ok is False


def test_empty_target_not_ok():
    scope = make_scope()
    result = scope.check("")
    assert result.ok is False
