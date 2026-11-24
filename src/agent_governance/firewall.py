"""Control 2 — access controls that actually work: least-privilege firewall.

Every tool call passes through the firewall before it runs. The firewall
holds a per-task allowlist: a support task may read orders, policies and
tickets, and may *request* (never execute) refunds and record changes. It
may not export customer data, delete records, or touch admin tools — those
tools exist in the catalogue but are in no task's allowlist, so calling
them is blocked and logged, not "not implemented".

The firewall checks the tool name only. Whether the *record* may be seen
is the provenance registry's job (control 1); whether the *effect* may
happen now is the approval gate's job (control 4). Three separate checks,
three separate logs — so a failure names the control that stopped it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Tools that exist in the catalogue but no task is ever allowed to call.
NEVER_ALLOWED = {"export_all_customers", "delete_record", "admin_override"}

# High-impact tools: callable, but their effect is held for human approval
# (control 4) — the firewall lets the call through to the approval gate.
HIGH_IMPACT = {"issue_refund", "update_order_status", "apply_resolution"}

# Per-task allowlists. A task gets exactly the tools its job needs.
TASK_SCOPES: dict[str, frozenset[str]] = {
    "support": frozenset({
        "lookup_order", "lookup_customer", "get_policy", "search_tickets",
        "issue_refund", "update_order_status", "apply_resolution",
    }),
    "read_only": frozenset({
        "lookup_order", "lookup_customer", "get_policy", "search_tickets",
    }),
}


@dataclass
class FirewallDecision:
    allowed: bool
    reason: str


@dataclass
class ToolFirewall:
    task: str = "support"
    extra_denied: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        self._allowed = TASK_SCOPES.get(self.task, frozenset())

    @property
    def allowed_tools(self) -> frozenset[str]:
        return self._allowed

    def check(self, tool_name: str) -> FirewallDecision:
        if tool_name in NEVER_ALLOWED:
            return FirewallDecision(False, f"tool_never_allowed:{tool_name}")
        if tool_name in self.extra_denied:
            return FirewallDecision(False, f"tool_denied_for_task:{tool_name}")
        if tool_name not in self._allowed:
            return FirewallDecision(False, f"tool_out_of_scope:{tool_name}")
        return FirewallDecision(True, "ok")

    def is_high_impact(self, tool_name: str) -> bool:
        return tool_name in HIGH_IMPACT
