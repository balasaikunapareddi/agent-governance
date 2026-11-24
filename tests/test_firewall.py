"""Tests for control 2 (least-privilege firewall)."""

from agent_governance.firewall import HIGH_IMPACT, NEVER_ALLOWED, ToolFirewall


def test_support_task_can_read_orders_policies_tickets():
    fw = ToolFirewall(task="support")
    for tool in ("lookup_order", "lookup_customer", "get_policy", "search_tickets"):
        assert fw.check(tool).allowed, tool


def test_never_allowed_tools_blocked_for_every_task():
    for task in ("support", "read_only"):
        fw = ToolFirewall(task=task)
        for tool in NEVER_ALLOWED:
            d = fw.check(tool)
            assert not d.allowed and d.reason.startswith("tool_never_allowed")


def test_export_and_delete_blocked_even_if_model_asks():
    fw = ToolFirewall(task="support")
    assert not fw.check("export_all_customers").allowed
    assert not fw.check("delete_record").allowed
    assert not fw.check("admin_override").allowed


def test_read_only_task_cannot_request_refunds():
    fw = ToolFirewall(task="read_only")
    assert not fw.check("issue_refund").allowed
    assert fw.check("issue_refund").reason.startswith("tool_out_of_scope")


def test_unknown_tool_blocked():
    fw = ToolFirewall(task="support")
    assert not fw.check("wipe_database").allowed


def test_high_impact_tools_are_marked_not_executed_by_firewall():
    fw = ToolFirewall(task="support")
    for tool in ("issue_refund", "update_order_status", "apply_resolution"):
        assert fw.is_high_impact(tool)
        assert fw.check(tool).allowed  # allowed *to request*; execution is gated
    assert not fw.is_high_impact("lookup_order")


def test_non_string_tool_name_denied_not_crash():
    # Malformed model JSON can produce a list/dict/None tool name.
    # `name in <frozenset>` raises TypeError on an unhashable value —
    # the firewall must deny it, not crash the runtime loop.
    fw = ToolFirewall(task="support")
    for bad in (["issue_refund"], {"tool": "issue_refund"}, None, 42):
        d = fw.check(bad)
        assert not d.allowed and d.reason == "tool_name_invalid", bad
