"""Runtime governance loop — LangGraph StateGraph.

Why LangGraph: the governance loop is a state machine with branches
(policy check -> decide -> tool gate -> execute -> guardrail, with
escalation and rollback exits). LangGraph makes those nodes and edges
explicit and inspectable instead of buried in nested ifs, and every node
runs its control before the next step — the loop IS the runtime
governance. The controls themselves are plain code (firewall,
provenance, guardrails, approval gate, audit); the graph only orders
them, so a control cannot be skipped by taking a different path.

Nodes:
  intake     — scan the user message for injection; on a hit, escalate.
  decide     — the LLM proposes one tool call or a final reply (JSON).
  tool_gate  — firewall: out-of-scope tools are blocked, never executed.
  execute    — run the tool (provenance + approval + rollback inside).
  guardrail  — scan the reply (PII/secrets/forbidden claims) before sending.
  escalate   — violation path: log, refuse safely, stop.

Policy checks run on every step: intake scans input, the gate checks
every tool call, execute enforces provenance/approval, guardrail scans
every reply. A violation escalates (blocked + audited + safe reply) and
a partially applied action is rolled back in the tool layer.
"""

from __future__ import annotations

import json
import re
from typing import TypedDict

from langgraph.graph import END, StateGraph

from .approval import ApprovalGate
from .audit import AuditLog
from .firewall import ToolFirewall
from .guardrails import scan_input_for_injection, scan_output
from .prompts import AGENT_SYSTEM_PROMPT, TOOL_RESULT_REMINDER
from .tools import Ledger, ToolExecutor

MAX_STEPS = 8


class GovState(TypedDict, total=False):
    user_message: str
    messages: list[dict]
    pending_tool: dict
    pending_reply: str
    observation: str
    refusal: str
    steps: int


class GovernedRuntime:
    """Holds the five controls and the graph that runs them in order."""

    def __init__(self, registry, llm, task: str = "support",
                 audit_path=None) -> None:
        self.registry = registry
        self.llm = llm
        self.audit = AuditLog(audit_path)
        self.firewall = ToolFirewall(task=task)
        self.approvals = ApprovalGate()
        self.ledger = Ledger()
        self.executor = ToolExecutor(registry, self.ledger, self.approvals, self.audit)
        self.graph = self._build_graph()

    # -- graph construction -------------------------------------------
    def _build_graph(self):
        graph = StateGraph(GovState)
        graph.add_node("intake", self._intake)
        graph.add_node("decide", self._decide)
        graph.add_node("tool_gate", self._tool_gate)
        graph.add_node("execute", self._execute)
        graph.add_node("guardrail", self._guardrail)
        graph.add_node("escalate", self._escalate)
        graph.set_entry_point("intake")
        graph.add_conditional_edges("intake", self._route_after_intake,
                                    {"decide": "decide", "escalate": "escalate"})
        graph.add_conditional_edges("decide", self._route_after_decide,
                                    {"tool_gate": "tool_gate",
                                     "guardrail": "guardrail", "escalate": "escalate"})
        graph.add_conditional_edges("tool_gate", self._route_after_gate,
                                    {"execute": "execute", "decide": "decide"})
        graph.add_edge("execute", "decide")
        graph.add_edge("guardrail", END)
        graph.add_edge("escalate", END)
        return graph.compile()

    # -- nodes ---------------------------------------------------------
    def _intake(self, state: GovState) -> GovState:
        text = state["user_message"]
        self.audit.record("intake", f"user message received ({len(text)} chars)",
                          control="runtime")
        scan = scan_input_for_injection(text)
        if not scan.clean:
            self.audit.record("injection_detected",
                              f"user input matched injection patterns: {scan.hits}",
                              reason="prompt_injection_in_user_input", control="guardrails")
            state["refusal"] = (
                "I can't follow that instruction — it tries to override how I work. "
                "I can still help with your order: tell me the order id and what happened.")
            return state
        return state

    def _decide(self, state: GovState) -> GovState:
        state["steps"] = state.get("steps", 0) + 1
        messages = [{"role": "system", "content": AGENT_SYSTEM_PROMPT}]
        # state["messages"] already holds every prior tool result, each
        # with its TOOL_RESULT_REMINDER attached by _execute — append
        # nothing here, or the latest result is sent to the model twice.
        messages.extend(state["messages"])
        try:
            raw = self.llm.complete(messages)
        except Exception as exc:
            # A backend failure (503, timeout, transport error) must fail
            # loudly AND safely: no tool runs, no action is taken, the
            # failure is audited, and the customer gets a safe reply —
            # never an unhandled exception out of run().
            self.audit.record("llm_error", f"model call failed: {exc!r}"[:200],
                              reason="llm_backend_failure", control="runtime")
            state["pending_reply"] = (
                "Sorry — I couldn't reach my help system just now, so I "
                "haven't looked anything up or changed anything. "
                "Please try again in a moment.")
            state["pending_tool"] = {}
            return state
        self.audit.record("llm_decision", f"model output: {raw[:200]}", control="runtime")
        action = _parse_action(raw)
        if action is None:
            # Unparseable model output is treated as a reply, never as a tool call.
            state["pending_reply"] = raw.strip() or "Sorry — I could not understand that."
            state["pending_tool"] = {}
            return state
        if "reply" in action:
            state["pending_reply"] = str(action["reply"])
            state["pending_tool"] = {}
        else:
            state["pending_tool"] = {"tool": action.get("tool", ""),
                                     "args": action.get("args", {}) or {}}
            state["pending_reply"] = ""
        return state

    def _tool_gate(self, state: GovState) -> GovState:
        tool = state["pending_tool"]
        decision = self.firewall.check(tool["tool"])
        self.audit.record(
            "policy_check" if decision.allowed else "tool_blocked",
            f"{tool['tool']} {tool['args']}", reason=decision.reason, control="firewall")
        if not decision.allowed:
            state["observation"] = (
                f"BLOCKED BY FIREWALL: {decision.reason}. This tool is not "
                f"available for this task. Do not retry it; reply to the customer instead.")
            # The block notice must reach the model as a tool message, or
            # the next decide sees the same history as before and retries
            # the blocked tool until MAX_STEPS. (_decide no longer appends
            # state["observation"] — see _execute — so each producer of an
            # observation appends its own message, exactly once.)
            state["messages"].append({"role": "tool", "content": state["observation"]})
            state["pending_tool"] = {}
        return state

    def _execute(self, state: GovState) -> GovState:
        tool = state["pending_tool"]
        observation = self.executor.execute(tool["tool"], tool["args"])
        # Scan tool results: an injection inside untrusted data is flagged
        # and audited even though the text is passed on (labelled) to the model.
        scan = scan_input_for_injection(observation)
        if not scan.clean:
            self.audit.record("injection_detected",
                              f"tool result for {tool['tool']} matched injection "
                              f"patterns: {scan.hits}",
                              reason="prompt_injection_in_tool_result", control="guardrails")
            self.audit.record("provenance_flag",
                              f"tool result for {tool['tool']} came from untrusted data",
                              reason="untrusted_source", control="provenance")
        state["observation"] = observation
        state["pending_tool"] = {}
        # The observation goes into the message history exactly once, with
        # the TOOL_RESULT_REMINDER attached — so the model sees every tool
        # result labelled as data, and _decide must not append it a second
        # time (it used to, which sent the latest result twice: once raw,
        # without the reminder, and once labelled).
        state["messages"].append({"role": "tool",
                                  "content": observation + "\n" + TOOL_RESULT_REMINDER})
        return state

    def _guardrail(self, state: GovState) -> GovState:
        reply = state.get("pending_reply", "")
        scan = scan_output(reply)
        if not scan.clean:
            if any(h.startswith("forbidden_claim") for h in scan.hits):
                self.audit.record("guardrail_block",
                                  f"reply blocked: {scan.hits}",
                                  reason="forbidden_claim_in_reply", control="guardrails")
                reply = ("I can't confirm that — refunds and shipments are only "
                         "completed after a human approves them. Your request is "
                         "held for review.")
            else:
                self.audit.record("guardrail_redaction",
                                  f"reply redacted: {scan.hits}",
                                  reason="pii_or_secret_in_reply", control="guardrails")
                reply = scan.redacted_text
        else:
            # Cross-turn assembly: a secret split across two replies
            # ("078-05-" now, "1120" next turn) is clean in each reply
            # alone. Prior replies were already scanned and sent, so any
            # PII pattern that matches the concatenation must span the
            # boundary between a sent reply and this one — block it.
            prior = "".join(
                m.get("content", "") for m in state.get("messages", [])
                if m.get("role") == "assistant")
            if prior:
                combined = scan_output(prior + reply)
                if not combined.clean and any(
                        h.startswith("pii:") for h in combined.hits):
                    self.audit.record(
                        "guardrail_block",
                        f"reply blocked: PII assembled across replies: {combined.hits}",
                        reason="pii_assembled_across_replies", control="guardrails")
                    reply = ("I can't share that detail here — it looks like "
                             "sensitive information split across messages. "
                             "Nothing was sent.")
        self.audit.record("reply_sent", reply[:200], reason="ok", control="guardrails")
        state["pending_reply"] = reply
        return state

    def _escalate(self, state: GovState) -> GovState:
        self.audit.record("escalation",
                          "violation escalated: request refused safely, no action taken",
                          reason="policy_violation", control="runtime")
        state["pending_reply"] = state.get("refusal") or (
            "That request was blocked by governance policy. No action was taken.")
        self.audit.record("reply_sent", state["pending_reply"][:200],
                          reason="escalation_refusal", control="runtime")
        return state

    # -- routing -------------------------------------------------------
    @staticmethod
    def _route_after_intake(state: GovState) -> str:
        return "escalate" if state.get("refusal") else "decide"

    @staticmethod
    def _route_after_decide(state: GovState) -> str:
        if state.get("steps", 0) >= MAX_STEPS:
            return "escalate"
        if state.get("pending_reply"):
            return "guardrail"
        if state.get("pending_tool"):
            return "tool_gate"
        return "escalate"

    @staticmethod
    def _route_after_gate(state: GovState) -> str:
        return "decide" if not state.get("pending_tool") else "execute"

    # -- public --------------------------------------------------------
    def run(self, user_message: str, history: list[dict] | None = None) -> str:
        state: GovState = {
            "user_message": user_message,
            "messages": list(history or []) + [{"role": "user", "content": user_message}],
            "steps": 0,
        }
        result = self.graph.invoke(state)
        return result.get("pending_reply", "")


def _parse_action(raw: str) -> dict | None:
    """Parse the model's JSON action. Returns None if unparseable.

    The shape is validated, not just the JSON: a tool must be a string
    and args a dict, a reply must be a string. A malformed shape (tool
    as a list, args as a list, reply null) is treated as an unparseable
    reply, never as a tool call — and it must never reach the firewall
    as an unhashable value, which used to crash the graph.
    """
    match = re.search(r"\{.*\}", raw, re.S)
    if not match:
        return None
    try:
        action = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    if not isinstance(action, dict):
        return None
    if "reply" in action:
        return action if isinstance(action["reply"], str) else None
    if "tool" in action:
        if not isinstance(action["tool"], str):
            return None
        args = action.get("args", {})
        if not isinstance(args, dict):
            return None
        return action
    return None
