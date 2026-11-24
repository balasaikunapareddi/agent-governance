"""Control 4 — human approval for high-impact decisions.

A high-impact action (refund, record change, commitment) is NEVER executed
by the agent. The runtime creates a ``PendingApproval`` holding the exact
action, its arguments, and why it was requested, and stops there. A human
approves or rejects it out of band; only an approval executes the action,
through ``execute_approved`` — and the decision is audited either way.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PendingApproval:
    approval_id: str
    action: str
    args: dict
    requested_by: str
    reason: str
    status: str = "pending"  # pending | approved | rejected | executed


class ApprovalGate:
    def __init__(self) -> None:
        self.pending: dict[str, PendingApproval] = {}
        self._counter = 0

    def request(self, action: str, args: dict, requested_by: str, reason: str) -> PendingApproval:
        self._counter += 1
        approval = PendingApproval(
            approval_id=f"APR-{self._counter:04d}",
            action=action, args=dict(args), requested_by=requested_by, reason=reason)
        self.pending[approval.approval_id] = approval
        return approval

    def decide(self, approval_id: str, approve: bool) -> PendingApproval | None:
        approval = self.pending.get(approval_id)
        if approval is None or approval.status != "pending":
            return None
        approval.status = "approved" if approve else "rejected"
        return approval

    def open_requests(self) -> list[PendingApproval]:
        return [a for a in self.pending.values() if a.status == "pending"]
