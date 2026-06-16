"""AnalysisLedger port — protocol + record dataclass for AI verdict persistence.

ADR-0044: every schema-validated AI analysis is persisted as one row in the
ai_analyses table.  This module defines the port (AnalysisLedger Protocol) and
the record carrier (AnalysisRecord dataclass).

Design notes
------------
- AnalysisRecord is a plain dataclass (not Pydantic) because it is an internal
  pipeline carrier, not an API model.  It is created at write time by the pipeline
  and consumed only by the adapter.
- ``kind`` is a Literal string rather than an enum so that JSON serialisation is
  trivial and the value remains legible in SQL queries.
- ``validated_json`` stores the closed-schema projection already computed by the
  OpenAI adapter (dict).  The adapter serialises it to TEXT/JSON for storage.
- Nullable token usage fields (prompt_tokens / completion_tokens) are None when
  the endpoint's ``usage`` block is absent — never fabricated (ADR-0044 §2).
- ``endpoint_host`` must carry host:port only — no scheme, no credentials
  (security: ADR-0044 §Security).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal, Protocol, runtime_checkable

# Closed verdict set re-exported for use by the API layer.
VerdictLiteral = Literal["agree", "disagree"]

# The two analysis kinds the pipeline produces (matching pipeline call names).
AnalysisKind = Literal["concise", "detailed"]

# Closed schema version sentinel.  Increment when the validated_json schema changes.
SCHEMA_VERSION: int = 1


@dataclass
class AnalysisRecord:
    """Carrier for one AI analysis record persisted to the ledger.

    Fields match ADR-0044 §2 column list verbatim.  Optional fields default to
    ``None`` to signal "not available" (never fabricated).

    Security note: ``prompt_text`` and ``response_text`` are attacker-influenced
    strings (the prompt contains sentinel-wrapped attacker-controlled payloads;
    the response is from the local model).  They MUST be size-capped before
    this record is passed to the adapter (caps.apply_field_caps).  The record
    itself does not enforce caps — that is the pipeline's responsibility so
    caps are applied exactly once before the save() call.
    """

    # Identity
    ip: str
    kind: AnalysisKind

    # Model metadata
    model: str
    endpoint_host: str  # host:port only — never credentials (ADR-0044 §Security)

    # Prompt / response (attacker-influenced; capped before storage)
    prompt_text: str
    response_text: str

    # Validated output
    validated_json: dict[str, Any]
    ai_status: str
    threat_level: str
    confidence: float

    # Score state at analysis time (ADR-0035/0036)
    score: int
    score_derivation: str

    # Timing / token stats
    latency_ms: float
    prompt_tokens: int | None = None
    completion_tokens: int | None = None

    # Schema bookkeeping
    schema_version: int = SCHEMA_VERSION

    # Timestamp — UTC at the moment the analysis completed
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    # Truncation flags set by caps.apply_field_caps when fields were capped.
    # These are NOT persisted as separate columns — they are embedded in a
    # flags JSON blob column in the DB (future-proof for additional flags).
    prompt_truncated: bool = False
    response_truncated: bool = False


@runtime_checkable
class AnalysisLedger(Protocol):
    """Port for the AI verdict ledger (ADR-0044).

    The adapter (SqliteAnalysisLedger) provides the concrete implementation.
    The pipeline depends on this protocol — never on the concrete adapter.

    All methods are async (aiosqlite-backed storage).
    """

    async def save(self, record: AnalysisRecord) -> None:
        """Persist one analysis record.

        Applies per-IP and global caps inline (prune-on-write, ADR-0044 §6).
        Field caps (64 KiB) must be applied by the caller before save().

        Raises on hard storage errors — callers wrap in try/except (fail-safe
        policy is enforced at the pipeline call site, not here).
        """
        ...

    async def list_page(
        self,
        limit: int = 50,
        cursor: str | None = None,
        ip_filter: str | None = None,
    ) -> dict[str, Any]:
        """Return a cursor-paginated summary page (ADR-0029).

        The page dict matches the ADR-0029 envelope::

            {
                "items": [ /* summary rows — NO prompt_text/response_text */ ],
                "next_cursor": "<opaque>|<id>" | None,
                "has_more": bool,
            }

        Summary rows contain: id, ip, kind, model, endpoint_host, ai_status,
        threat_level, confidence, score, score_derivation, latency_ms,
        prompt_tokens, completion_tokens, schema_version, created_at.

        ``prompt_text`` and ``response_text`` are intentionally excluded from
        the list projection (ADR-0029 D3 / OWASP LLM05 / ADR-0044 §Security).
        """
        ...

    async def get_by_id(self, row_id: int) -> dict[str, Any] | None:
        """Return the full record for *row_id*, or None if not found.

        Includes ``prompt_text`` and ``response_text`` (detail endpoint only).
        """
        ...

    async def upsert_feedback(
        self,
        analysis_id: int,
        verdict: VerdictLiteral,
        reason: str | None,
    ) -> dict[str, Any]:
        """Upsert analyst feedback for an analysis record (ADR-0045 D1).

        Raises ``LookupError`` on unknown analysis_id; ``ValueError`` on invalid
        verdict or oversized reason (> 1 000 chars).
        """
        ...

    async def get_feedback_for_analysis(
        self,
        analysis_id: int,
    ) -> dict[str, Any] | None:
        """Return the current feedback row for *analysis_id*, or None if absent.

        Used to populate the ``feedback`` field on list items (ADR-0045 D2).
        """
        ...

    async def get_feedback_summary(self) -> dict[str, Any]:
        """Return the agreement rollup: {graded, agreed, agreement_pct} (ADR-0045 D4).

        Computed at read time — no denormalized counters.
        """
        ...
