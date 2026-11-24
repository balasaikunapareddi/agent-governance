"""CLI: `python -m agent_governance demo` or `python -m agent_governance chat`."""

from __future__ import annotations

import sys

from .agent import GovernedAgent
from .demo import main as demo_main


def chat_main() -> int:
    agent = GovernedAgent(live=False)
    print("Governed support agent (stub LLM). Type 'quit' to exit.")
    print("Try: 'my order CM-1042 arrived damaged' — or paste an injection.")
    while True:
        try:
            text = input("you: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if text.lower() in {"quit", "exit"}:
            return 0
        if not text:
            continue
        print(f"agent: {agent.run(text)}")


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] == "demo":
        return demo_main()
    if args[0] == "chat":
        return chat_main()
    print("usage: python -m agent_governance [demo|chat]")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
