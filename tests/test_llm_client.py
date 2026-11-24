"""Tests for the live-LLM boundary: tool-role messages must never reach
Gemini, which rejects a ``role: "tool"`` message unless it follows an
assistant ``tool_calls`` entry. The agent parses the model's JSON action
itself, so ``LiteLLMClient.complete`` translates tool results into
labelled user messages at the boundary. Uses a fake ``litellm`` module —
no network.
"""

from __future__ import annotations

import sys
import types

import pytest

from agent_governance.llm import LiteLLMClient


class _Choice:
    def __init__(self, content: str) -> None:
        self.message = types.SimpleNamespace(content=content)


class _Resp:
    def __init__(self, content: str) -> None:
        self.choices = [_Choice(content)]


@pytest.fixture
def fake_litellm(monkeypatch):
    seen = {}

    def completion(model, messages):
        seen["model"] = model
        seen["messages"] = messages
        return _Resp('{"reply": "ok"}')

    mod = types.ModuleType("litellm")
    mod.completion = completion
    monkeypatch.setitem(sys.modules, "litellm", mod)
    return seen


def test_tool_role_messages_translated_before_live_call(fake_litellm):
    client = LiteLLMClient(model="gemini/gemini-3.5-flash-lite")
    client.complete([
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "My order CM-1042 arrived damaged."},
        {"role": "tool", "content": "Order CM-1042: Ceramic vase, status=delivered"},
    ])
    roles = [m["role"] for m in fake_litellm["messages"]]
    assert "tool" not in roles
    assert roles == ["system", "user", "user"]
    tool_as_user = fake_litellm["messages"][2]
    assert "Order CM-1042" in tool_as_user["content"]
    assert "Tool result" in tool_as_user["content"]


def test_non_tool_messages_pass_through_unchanged(fake_litellm):
    client = LiteLLMClient(model="gemini/gemini-3.5-flash-lite")
    client.complete([
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "hello"},
        {"role": "assistant", "content": "hi"},
    ])
    assert fake_litellm["messages"] == [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "hello"},
        {"role": "assistant", "content": "hi"},
    ]
