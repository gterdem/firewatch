"""DecisionStore port — protocol for the ``triage_decisions`` adapter (ADR-0072 D2/D8).

``firewatch_core.adapters.decisions.sqlite_decisions.SqliteDecisionStore`` is
the concrete implementation. Route handlers and the annotator depend on this
protocol shape (structurally, via ``Any`` + duck typing at the call site —
same convention as ``get_event_store``/``get_pipeline`` in
``firewatch_api.deps``); this module exists so the shape is documented and
type-checkable in one place.
"""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class DecisionStore(Protocol):
    """Port for the append-only triage-decisions store (ADR-0072 D2)."""

    async def init(self) -> None:
        """Create schema and configure the connection (idempotent)."""
        ...

    async def close(self) -> None:
        """Release the store's connections."""
        ...

    async def create_decision(
        self,
        *,
        actor_ip: str,
        verb: str,
        rule_name: str | None,
        decided_tier: int | None,
        decided_score: int,
        author: str = "local operator",
        note: str | None = None,
    ) -> dict[str, Any]:
        """Insert a new decision row; return the full record incl. server snapshot.

        Raises ``ValueError`` on an invalid verb, a verb/rule_name pairing
        mismatch, or an oversized field.
        """
        ...

    async def revoke_decision(self, decision_id: int) -> None:
        """Soft-revoke (set ``revoked_at``); idempotent; ``LookupError`` if absent."""
        ...

    async def list_decisions(
        self,
        limit: int = 50,
        cursor: str | None = None,
        actor: str | None = None,
    ) -> dict[str, Any]:
        """Return a cursor-paginated page (ADR-0029 D2 envelope), newest-first."""
        ...

    async def get_active_for_actor(self, actor_ip: str) -> list[dict[str, Any]]:
        """Return this actor's active (non-revoked) decision rows."""
        ...
