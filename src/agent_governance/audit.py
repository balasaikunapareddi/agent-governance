"""Control 5 — continuous monitoring + auditability: the audit log.

Every access, tool call, decision, and *why* goes in here, in order, with
a sequence number. The log is append-only in memory and mirrored to a
JSONL file when a path is given, so a run can be reconstructed after the
fact: what the agent saw, which control allowed or blocked each step, and
what the human decided. If a step is not in the log, it did not happen —
that is the audit standard the runtime holds itself to.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AuditEvent:
    seq: int
    ts: float
    kind: str
    detail: str
    reason: str = ""
    control: str = ""  # which control produced this event, e.g. "firewall"

    def to_dict(self) -> dict:
        return {"seq": self.seq, "ts": round(self.ts, 3), "kind": self.kind,
                "detail": self.detail, "reason": self.reason, "control": self.control}


class AuditLog:
    def __init__(self, path: str | Path | None = None) -> None:
        self.events: list[AuditEvent] = []
        self.path = Path(path) if path else None
        # Resume sequence numbers from an existing file — never truncate
        # it. Wiping the file on construction destroyed the history the
        # log exists to preserve.
        self._next_seq = 1
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.exists():
                try:
                    text = self.path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    text = ""
                for line in text.splitlines():
                    try:
                        self._next_seq = max(
                            self._next_seq, int(json.loads(line).get("seq", 0)) + 1)
                    except (ValueError, TypeError, AttributeError):
                        continue
            else:
                self.path.touch()

    def record(self, kind: str, detail: str, reason: str = "", control: str = "") -> AuditEvent:
        event = AuditEvent(seq=self._next_seq, ts=time.time(), kind=kind,
                           detail=detail, reason=reason, control=control)
        self._next_seq += 1
        self.events.append(event)
        if self.path:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event.to_dict()) + "\n")
        return event

    def of_kind(self, kind: str) -> list[AuditEvent]:
        return [e for e in self.events if e.kind == kind]

    def blocked(self) -> list[AuditEvent]:
        return [e for e in self.events if "blocked" in e.kind or "denied" in e.kind]

    def summary(self) -> dict:
        kinds: dict[str, int] = {}
        for e in self.events:
            kinds[e.kind] = kinds.get(e.kind, 0) + 1
        return {"total_events": len(self.events), "by_kind": kinds}
