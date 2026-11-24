"""Tests for controls 4 (approval gate) and 5 (audit log)."""

from agent_governance.approval import ApprovalGate
from agent_governance.audit import AuditLog


def test_approval_starts_pending_and_blocks_execution():
    gate = ApprovalGate()
    a = gate.request("issue_refund", {"order_id": "CM-1042", "amount_usd": 150},
                     requested_by="support-agent", reason="test")
    assert a.status == "pending"
    assert a.approval_id == "APR-0001"
    assert len(gate.open_requests()) == 1


def test_approval_ids_are_unique_and_sequential():
    gate = ApprovalGate()
    ids = [gate.request("issue_refund", {}, "agent", "x").approval_id for _ in range(3)]
    assert ids == ["APR-0001", "APR-0002", "APR-0003"]


def test_reject_leaves_nothing_pending():
    gate = ApprovalGate()
    a = gate.request("issue_refund", {}, "agent", "x")
    decided = gate.decide(a.approval_id, approve=False)
    assert decided.status == "rejected"
    assert gate.open_requests() == []


def test_decide_unknown_approval_returns_none():
    assert ApprovalGate().decide("APR-9999", approve=True) is None


def test_decide_twice_returns_none_second_time():
    gate = ApprovalGate()
    a = gate.request("issue_refund", {}, "agent", "x")
    assert gate.decide(a.approval_id, approve=True) is not None
    assert gate.decide(a.approval_id, approve=True) is None


def test_audit_records_events_in_order():
    log = AuditLog()
    log.record("intake", "hello", control="runtime")
    log.record("tool_blocked", "export", reason="x", control="firewall")
    assert [e.seq for e in log.events] == [1, 2]
    assert log.of_kind("tool_blocked")[0].control == "firewall"


def test_audit_summary_counts_by_kind():
    log = AuditLog()
    log.record("intake", "a")
    log.record("intake", "b")
    log.record("tool_blocked", "c")
    summary = log.summary()
    assert summary["total_events"] == 3
    assert summary["by_kind"] == {"intake": 2, "tool_blocked": 1}


def test_audit_blocked_helper_finds_blocks():
    log = AuditLog()
    log.record("intake", "a")
    log.record("tool_blocked", "export_all_customers")
    assert len(log.blocked()) == 1
