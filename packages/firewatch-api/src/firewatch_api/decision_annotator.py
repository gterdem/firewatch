"""Pure annotation/exclusion helper — GET /threats & GET /banner/summary consume
the SAME evaluator through this module (ADR-0072 D8, "one evaluator, every
surface" — finding 2).

Style mirrors ``banner_assembler.py``: aggregates ALREADY-COMPUTED facts (a
``triage_decisions`` row set + an ``EscalationVerdict``) into a wire-agnostic
dataclass; never re-derives suppression math — that lives in the single pure
evaluator, ``firewatch_core.triage.suppression.evaluate``.

No I/O; no store access. Callers (``routes/threats.py``, ``routes/banner.py``)
fetch each actor's active decision rows (``DecisionStore.get_active_for_actor``)
and pass them in here alongside that actor's current verdict.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from firewatch_sdk.models import EscalationVerdict

from firewatch_core.triage.models import TriageDecision
from firewatch_core.triage.suppression import evaluate


@dataclass(frozen=True)
class AnnotatedDecision:
    """Wire-agnostic shape for the additive ``triage_decision`` annotation.

    The route layer converts this to ``firewatch_api.schemas.
    TriageDecisionAnnotation`` (same split ``banner_assembler``'s dataclasses
    keep from ``schemas.BannerAttemptSummary``).
    """

    verb: str
    decided_at: str
    decided_tier: int | None
    decided_score: int
    suppressed: bool
    reentry: None = None  # #56 seam — always None until #56 implements re-entry.


def _rows_to_decisions(rows: list[dict[str, Any]]) -> list[TriageDecision]:
    """Map raw store rows (dicts) to the pure ``TriageDecision`` domain type."""
    return [
        TriageDecision(
            id=int(row["id"]),
            actor_ip=str(row["actor_ip"]),
            verb=row["verb"],
            rule_name=row.get("rule_name"),
            decided_tier=row.get("decided_tier"),
            decided_score=int(row["decided_score"]),
            decided_at=str(row["decided_at"]),
            revoked_at=row.get("revoked_at"),
            author=str(row.get("author") or "local operator"),
            note=row.get("note"),
        )
        for row in rows
    ]


def annotate(
    rows: list[dict[str, Any]],
    verdict: EscalationVerdict | None,
) -> AnnotatedDecision | None:
    """Build the ``triage_decision`` annotation for one actor (ADR-0072 D3/D8).

    Returns ``None`` when the actor carries no active actor-identity decision
    (D4's ``A``) — ``false_positive``-only rows are rule-scoped and are not
    rendered in this slot; they still contribute to ``suppressed`` via
    ``suppressed_by_fp``, which is why ``evaluate()`` (not a re-derivation) is
    always run over the FULL row set, not just the actor-scoped rows.
    """
    evaluation = evaluate(_rows_to_decisions(rows), verdict)
    actor_decision = evaluation.active_actor_decision
    if actor_decision is None:
        return None
    return AnnotatedDecision(
        verb=actor_decision.verb,
        decided_at=actor_decision.decided_at,
        decided_tier=actor_decision.decided_tier,
        decided_score=actor_decision.decided_score,
        suppressed=evaluation.suppressed,
    )


def is_suppressed(
    rows: list[dict[str, Any]],
    verdict: EscalationVerdict | None,
) -> bool:
    """Return whether the actor's CURRENT verdict is suppressed (ADR-0072 D4).

    The single source of truth ``GET /banner/summary``'s ``queue_size``
    exclusion calls — the SAME evaluator ``annotate()`` uses (ADR-0072 finding
    2: one evaluator, every surface). Never removes the actor from any store
    or list — this is a read-time predicate only (ADR-0072 finding 1).
    """
    return evaluate(_rows_to_decisions(rows), verdict).suppressed
