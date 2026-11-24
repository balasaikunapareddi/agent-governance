"""Control 3 — model guardrails + policy enforcement on outputs.

Two scans, both deterministic regex/policy code, both run on EVERY reply
before it is sent — and on tool results before the model sees them:

1. ``scan_input_for_injection``: instruction-shaped language ("ignore all
   previous instructions", "you must", "disregard", "no approval needed")
   in user input or in untrusted tool output. A hit does not crash the run;
   it escalates: the injected instruction is stripped/ignored and the
   attempt is logged.
2. ``scan_output``: PII/secrets (SSN, cards, API keys, salary figures from
   restricted records) and forbidden claims ("refund issued", "replacement
   shipped", "money sent") — claims the agent can never truthfully make,
   because high-impact actions are never auto-executed. Violations are
   redacted or the reply is replaced with a safe refusal; either way the
   event is audited.

Evasion hardening (added in review): the scans normalise away zero-width
characters and accept dash/space/dot SSN separators, so "078-05-1120"
cannot be smuggled past as "078 05 1120" or with invisible characters
inserted. Base64-looking tokens are decoded and the decoded text is
scanned too, so an SSN or an injected instruction cannot hide behind
encoding. The runtime additionally checks PII assembled across replies
(see ``runtime._guardrail``), because a single-turn scan cannot see a
secret split over two turns.
"""

from __future__ import annotations

import base64
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
    # SSN with any of dash/space/dot separators (078-05-1120, 078 05 1120, 078.05.1120).
    (re.compile(r"\b\d{3}[ .-]\d{2}[ .-]\d{4}\b"), "[SSN REDACTED]"),
    (re.compile(r"\b(?:\d[ .-]?){13,19}\b"), "[CARD REDACTED]"),
    (re.compile(r"\b(?:sk|ghp_|gho_|AKIA)[A-Za-z0-9_\-]{8,}\b"), "[SECRET REDACTED]"),
    (re.compile(r"\bsalary_usd['\"]?\s*[:=]\s*\$?[\d,]+\b", re.I), "[SALARY REDACTED]"),
    (re.compile(r"\b412000\b"), "[SALARY REDACTED]"),
]

FORBIDDEN_CLAIMS = [
    re.compile(r"refund (has been )?(issued|sent|processed|completed|applied)", re.I),
    re.compile(r"replacement (has been )?(shipped|sent|dispatched)", re.I),
    re.compile(r"money (has been )?(sent|transferred|refunded)", re.I),
    re.compile(r"your refund is on (its|the) way", re.I),
    # Paraphrases of the same false claims — a reworded lie is still a lie.
    re.compile(r"(refund|money|payment) (is )?(already )?(on (its|the) way)", re.I),
    re.compile(r"replacement (is )?(already )?(on (its|the) way)", re.I),
    re.compile(r"refund (is )?(complete|completed|done|finished)\b", re.I),
    re.compile(r"refund (has )?(gone through|went through)", re.I),
]

# Invisible characters used to break up a pattern without changing how
# the text looks ("078-<ZWSP>05-<ZWSP>1120" reads as an SSN).
# Written as escapes on purpose: the characters themselves are invisible
# in source and must never be typed literally here.
_ZERO_WIDTH = ("\u200b", "\u200c", "\u200d", "\ufeff")

# Long base64-alphabet runs worth decoding and re-scanning.
_B64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")


def _normalize(text: str) -> str:
    """Strip invisible characters so a pattern cannot be split by them."""
    for ch in _ZERO_WIDTH:
        text = text.replace(ch, "")
    return text


def _base64_decoded_variants(text: str) -> list[tuple[str, str]]:
    """Decode base64-looking tokens; return (token, decoded text) pairs.

    Only tokens that decode to printable UTF-8 are returned, so random
    hex/ids do not produce garbage candidates.
    """
    variants: list[tuple[str, str]] = []
    for token in set(_B64_TOKEN.findall(text or "")):
        padded = token + "=" * (-len(token) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
            decoded = raw.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if len(decoded) < 4:
            continue
        if not all(c.isprintable() or c in " \t\n\r" for c in decoded):
            continue
        variants.append((token, decoded))
    return variants


@dataclass
class ScanResult:
    clean: bool
    hits: list[str] = field(default_factory=list)
    redacted_text: str = ""


def scan_input_for_injection(text: str) -> ScanResult:
    clean_text = _normalize(text or "")
    hits = [p.pattern for p in INJECTION_PATTERNS if p.search(clean_text)]
    for _token, decoded in _base64_decoded_variants(clean_text):
        if any(p.search(decoded) for p in INJECTION_PATTERNS):
            hits.append("injection:base64_encoded")
            break
    return ScanResult(clean=not hits, hits=hits, redacted_text=clean_text)


def scan_output(text: str) -> ScanResult:
    """Scan a reply before sending. Returns redacted text + hit list.

    PII/secrets are redacted in place. Forbidden claims make the reply
    unclean (the caller replaces it with a safe message) — a redacted
    "refund issued" is still a lie.
    """
    hits: list[str] = []
    redacted = _normalize(text or "")
    for pattern, replacement in PII_PATTERNS:
        if pattern.search(redacted):
            hits.append(f"pii:{pattern.pattern[:40]}")
            redacted = pattern.sub(replacement, redacted)
    # Encoded PII / claims: decode base64-looking tokens and scan the
    # decoded text; a secret that only exists encoded still may not leave.
    for token, decoded in _base64_decoded_variants(redacted):
        if any(p.search(decoded) for p, _ in PII_PATTERNS):
            hits.append("pii:base64_encoded")
            redacted = redacted.replace(token, "[ENCODED PII REDACTED]")
        elif any(p.search(decoded) for p in FORBIDDEN_CLAIMS):
            hits.append("forbidden_claim:base64_encoded")
            redacted = redacted.replace(token, "[ENCODED CLAIM REDACTED]")
    for pattern in FORBIDDEN_CLAIMS:
        if pattern.search(redacted):
            hits.append(f"forbidden_claim:{pattern.pattern[:40]}")
    return ScanResult(clean=not hits, hits=hits, redacted_text=redacted)


def contains_forbidden_claim(text: str) -> bool:
    return any(p.search(_normalize(text or "")) for p in FORBIDDEN_CLAIMS)
