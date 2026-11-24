"""Control 1 — trusted data pipelines: provenance registry.

Every record the agent can touch carries provenance: where it came from
(source), who owns it (owner), whether it is trusted, and its
classification. Nothing is retrieved "bare": a lookup returns the record
PLUS its provenance, and the runtime decides what may be used.

- ``trusted``: from a system we own (orders DB, policy KB). Usable.
- ``untrusted``: from outside our control (vendor ticket notes, pasted
  customer text). Readable, but flagged — and any instruction-shaped text
  inside it is treated as an injection attempt, never as an instruction.
- ``restricted`` classification: the record exists, but this agent's task
  is not allowed to see its contents (e.g. an executive/HR record). The
  lookup is blocked and logged; the contents are never returned.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class TrustLevel:
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class Classification:
    PUBLIC = "public"
    INTERNAL = "internal"
    RESTRICTED = "restricted"


@dataclass(frozen=True)
class Provenance:
    source: str          # e.g. "orders_db", "vendor_ticket_feed"
    owner: str           # e.g. "support-ops", "hr", "external-vendor"
    trust: str           # TrustLevel.TRUSTED / UNTRUSTED
    classification: str  # Classification.*


@dataclass
class Record:
    record_id: str
    kind: str
    fields: dict
    provenance: Provenance

    def is_restricted(self) -> bool:
        return self.provenance.classification == Classification.RESTRICTED

    def is_untrusted(self) -> bool:
        return self.provenance.trust == TrustLevel.UNTRUSTED


@dataclass
class Retrieval:
    """What a lookup returns: the record (or None) plus what the runtime
    decided about it, so every use is traceable to a provenance decision."""

    record: Record | None
    allowed: bool
    reason: str
    provenance: Provenance | None = None
    flagged_untrusted: bool = False


class ProvenanceRegistry:
    """The single place records are registered and retrieved through."""

    def __init__(self) -> None:
        self._records: dict[str, Record] = {}

    def register(self, record: Record) -> None:
        self._records[record.record_id] = record

    def get(self, record_id: str) -> Record | None:
        return self._records.get(record_id)

    def retrieve(self, record_id: str, *, allow_restricted: bool = False) -> Retrieval:
        """Retrieve a record with its provenance decision attached.

        Restricted records are blocked unless the caller explicitly holds
        the ``restricted_read`` scope — this agent's support task never does.
        Untrusted records are returned but flagged; the caller must not treat
        their contents as instructions.
        """
        record = self._records.get(record_id)
        if record is None:
            return Retrieval(record=None, allowed=False, reason="record_not_found")
        if record.is_restricted() and not allow_restricted:
            return Retrieval(
                record=None,
                allowed=False,
                reason="restricted_record_blocked",
                provenance=record.provenance,
            )
        return Retrieval(
            record=record,
            allowed=True,
            reason="ok",
            provenance=record.provenance,
            flagged_untrusted=record.is_untrusted(),
        )

    def all_ids(self) -> list[str]:
        return sorted(self._records)
