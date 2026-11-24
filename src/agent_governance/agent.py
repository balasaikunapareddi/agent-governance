"""The governed agent: a thin wrapper over the runtime graph.

``GovernedAgent`` owns a conversation history and one ``GovernedRuntime``
(the five controls + the LangGraph loop). The LLM only ever *proposes*;
every proposal is checked by the graph before anything happens. The
agent also exposes the human-approval workflow: list pending approvals,
approve/reject one, and execute an approved action.
"""

from __future__ import annotations

from .approval import PendingApproval
from .audit import AuditLog
from .llm import LiteLLMClient
from .mock_llm import StubLLM
from .runtime import GovernedRuntime
from .store import build_registry


class GovernedAgent:
    def __init__(self, live: bool = False, task: str = "support",
                 audit_path=None) -> None:
        self.registry = build_registry()
        self.llm = LiteLLMClient() if live else StubLLM()
        self.runtime = GovernedRuntime(self.registry, self.llm, task=task,
                                       audit_path=audit_path)
        self.history: list[dict] = []

    # -- conversation --------------------------------------------------
    def run(self, user_message: str) -> str:
        reply = self.runtime.run(user_message, history=self.history)
        self.history.append({"role": "user", "content": user_message})
        self.history.append({"role": "assistant", "content": reply})
        return reply

    # -- inspection ----------------------------------------------------
    @property
    def audit(self) -> AuditLog:
        return self.runtime.audit

    @property
    def approvals(self):
        return self.runtime.approvals

    @property
    def ledger(self):
        return self.runtime.ledger

    def pending_approvals(self) -> list[PendingApproval]:
        return self.approvals.open_requests()

    # -- human approval workflow ---------------------------------------
    def approve(self, approval_id: str) -> str:
        """Human approves a held action; the action is then executed."""
        approval = self.approvals.decide(approval_id, approve=True)
        if approval is None:
            return f"No pending approval {approval_id}."
        self.audit.record("approval_decision", f"{approval_id} approved by human",
                          reason="human_approved", control="approval")
        return self.runtime.executor.execute_approved(approval_id)

    def reject(self, approval_id: str) -> str:
        approval = self.approvals.decide(approval_id, approve=False)
        if approval is None:
            return f"No pending approval {approval_id}."
        self.audit.record("approval_decision", f"{approval_id} rejected by human",
                          reason="human_rejected", control="approval")
        return f"Approval {approval_id} rejected; nothing was executed."
