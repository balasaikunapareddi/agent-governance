"""LLM access via LiteLLM. Model from LLM_MODEL, default
gemini/gemini-3.5-flash-lite. No API key is ever printed or logged here;
the key arrives via environment (run_live.py injects GEMINI_API_KEY).
"""

from __future__ import annotations

import os

MODEL = os.environ.get("LLM_MODEL", "gemini/gemini-3.5-flash-lite")


class LiteLLMClient:
    """Live LLM. ``complete`` takes chat messages, returns raw text."""

    def __init__(self, model: str | None = None) -> None:
        self.model = model or MODEL

    def complete(self, messages: list[dict]) -> str:
        import litellm

        resp = litellm.completion(model=self.model, messages=messages)
        return resp.choices[0].message.content or ""
