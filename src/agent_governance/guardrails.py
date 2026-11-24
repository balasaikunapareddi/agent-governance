"""Control 3 — model guardrails + policy enforcement on outputs.

Two scans, both deterministic regex/policy code, both run on EVERY reply
before it is sent — and on tool results before the model sees them:

1. ``scan_input_for_injection``: instruction-shaped language ("ignore all
   previous instructions", "you must", "disregard", "no approval needed")
   in user input or in untrusted tool output. A hit does not crash the run;
   it escalates: the injected instruction is stripped/ignored and the
   attempt is logged.
2. ``scan_output``: PII/secrets (SSN, card numbers, API-key-shaped tokens,
   salary figures from restricted records) and forbidden claims ("refund
   issued", "replacement shipped", "money sent") — claims the agent can
   never truthfully make, because high-impact actions are never
   auto-executed. Violations are redacted or the reply is replaced with a
   safe refusal; either way the event is audited.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

INJECTION_PATTERNS = [
    re.compile(r"ignore (all |any |your |previous |prior )*(instructions|rules|policies)", re.I),
    re.compile(r"disregard (all |any |your |previous )*(instructions|rules|policies)", re.I),
    re.compile(r"you must (look up|read|issue|send|refund|disclose|reveal)", re.I),
    re.compile(r"no approval needed", re.I),
    re.compile(r"do not tell (the )?(customer|user|anyone)", re.I),
    re.compile(r"override (your |the )*(instructions|policy|safety)", re.I),
    re.compile(r"pretend (you are|to be)", re.I),
]

PII_PATTERNS = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN REDACTED]"),
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), "[CARD REDACTED]"),
    (re.compile(r"\b(?:sk|ghp_|gho_|AKIA)[A-Za-z0-9_\-]{8,}\b"), "[SECRET REDACTED]"),
    (re.compile(r"\bsalary_usd['\"]?\s*[:=]\s*\$?[\d,]+\b", re.I), "[SALARY REDACTED]"),
    (re.compile(r"\b412000\b"), "[SALARY REDACTED]"),
]

FORBIDDEN_CLAIMS = [
    re.compile(r"refund (has been )?(issued|sent|processed|completed|applied)", re.I),
    re.compile(r"replacement (has been )?(shipped|sent|dispatched)", re.I),
    re.compile(r"money (has been )?(sent|transferred|refunded)", re.I),
    re.compile(r"your refund is on (its|the) way", re.I),
]


@dataclass
class ScanResult:
    clean: bool
    hits: list[str] = field(default_factory=list)
    redacted_text: str = ""


def scan_input_for_injection(text: str) -> ScanResult:
    hits = [p.pattern for p in INJECTION_PATTERNS if p.search(text or "")]
    return ScanResult(clean=not hits, hits=hits, redacted_text=text or "")


def scan_output(text: str) -> ScanResult:
    """Scan a reply before sending. Returns redacted text + hit list.

    PII/secrets are redacted in place. Forbidden claims make the reply
    unclean (the caller replaces it with a safe message) — a redacted
    "refund issued" is still a lie.
    """
    hits: list[str] = []
    redacted = text or ""
    for pattern, replacement in PII_PATTERNS:
        if pattern.search(redacted):
            hits.append(f"pii:{pattern.pattern[:40]}")
            redacted = pattern.sub(replacement, redacted)
    for pattern in FORBIDDEN_CLAIMS:
        if pattern.search(redacted):
            hits.append(f"forbidden_claim:{pattern.pattern[:40]}")
    return ScanResult(clean=not hits, hits=hits, redacted_text=redacted)


def contains_forbidden_claim(text: str) -> bool:
    return any(p.search(text or "") for p in FORBIDDEN_CLAIMS)
