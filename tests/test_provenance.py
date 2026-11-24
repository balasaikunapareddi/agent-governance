"""Tests for control 1 (provenance) and the fictional dataset."""

from agent_governance.provenance import Classification, TrustLevel
from agent_governance.store import build_registry


def test_trusted_order_retrieves_with_provenance():
    reg = build_registry()
    ret = reg.retrieve("CM-1042")
    assert ret.allowed and ret.record is not None
    assert ret.provenance.source == "orders_db"
    assert ret.provenance.owner == "support-ops"
    assert ret.provenance.trust == TrustLevel.TRUSTED


def test_restricted_record_blocked_by_default():
    reg = build_registry()
    ret = reg.retrieve("CUST-VIP-001")
    assert not ret.allowed
    assert ret.reason == "restricted_record_blocked"
    assert ret.record is None  # contents never returned
    assert ret.provenance.classification == Classification.RESTRICTED


def test_restricted_record_allowed_only_with_explicit_scope():
    reg = build_registry()
    ret = reg.retrieve("CUST-VIP-001", allow_restricted=True)
    assert ret.allowed and ret.record is not None


def test_untrusted_ticket_flagged_not_silently_used():
    reg = build_registry()
    ret = reg.retrieve("TKT-77")
    assert ret.allowed
    assert ret.flagged_untrusted is True
    assert ret.provenance.trust == TrustLevel.UNTRUSTED
    assert ret.provenance.source == "vendor_ticket_feed"


def test_trusted_ticket_not_flagged():
    reg = build_registry()
    ret = reg.retrieve("TKT-78")
    assert ret.allowed and ret.flagged_untrusted is False


def test_unknown_record_not_found():
    reg = build_registry()
    ret = reg.retrieve("NOPE-1")
    assert not ret.allowed and ret.reason == "record_not_found"


def test_restricted_record_never_leaks_salary_or_ssn():
    reg = build_registry()
    ret = reg.retrieve("CUST-VIP-001")
    assert ret.record is None
    assert "412000" not in str(ret)
    assert "078-05-1120" not in str(ret)
