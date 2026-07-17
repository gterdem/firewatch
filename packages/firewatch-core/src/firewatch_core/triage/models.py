"""Frozen, pure data carriers for the triage-decision domain (ADR-0072 D2/D8).

``TriageDecision`` is the read-shaped mirror of one ``triage_decisions`` row
(``firewatch_core.adapters.decisions.sqlite_decisions`` is the only writer).
``DecisionEvaluation`` is the output of the pure evaluator in
``suppression.py`` — what a given actor's decision history means for its
CURRENT verdict, recomputed at read time (ADR-0041 precedent: never
persisted).

No I/O, no pydantic — plain ``dataclass(frozen=True)``, matching the style of
``firewatch_core.escalation.qualify.QualifyResult``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

#: The three verbs (ADR-0070 D6 / ADR-0072 D2) — kept as a plain Literal
#: (not an enum) so JSON round-tripping through the sqlite TEXT column and
#: the API layer stays trivial (mirrors ``AnalysisKind`` in
#: ``firewatch_core.ports.analysis_ledger``).
TriageVerbLiteral = Literal["expected", "dismissed", "false_positive"]


@dataclass(frozen=True)
class TriageDecision:
    """One ``triage_decisions`` row, read-shaped (ADR-0072 D2).

    Mirrors the DB row exactly — no reinterpretation. ``rule_name`` is
    ``None`` for actor-scoped verbs (``expected``/``dismissed``) and a
    non-empty string for ``false_positive`` (the DB ``CHECK`` constraint
    enforces this at write time; this type does not re-validate it).
    ``revoked_at`` is ``None`` for an active (non-revoked) row.
    """

    id: int
    actor_ip: str
    verb: TriageVerbLiteral
    rule_name: str | None
    decided_tier: int | None
    decided_score: int
    decided_at: str
    revoked_at: str | None
    author: str
    note: str | None


@dataclass(frozen=True)
class ReentryInfo:
    """Re-entry payload (ADR-0072 D4) — engine integers, RULE-tagged (ADR-0035).

    Deferred seam: issue #56 is the only producer of a non-``None`` value.
    ``suppression.evaluate`` in THIS package (#47) never constructs one — see
    the seam comment there.
    """

    decided_tier: int | None
    decided_score: int
    current_tier: int | None
    current_score: int
    decided_at: str


@dataclass(frozen=True)
class DecisionEvaluation:
    """The D4 evaluator's output for one actor against its current verdict.

    ``active_actor_decision`` is D4's ``A`` — the latest active row with
    ``verb in {expected, dismissed}`` — exposed so callers can render
    verb/decided_at/decided_tier/decided_score without a second query.
    ``false_positive`` decisions are rule-scoped and are intentionally NOT
    surfaced here (ADR-0072 D6: FP targets a detection, not the actor
    identity); they only affect ``suppressed_by_fp`` below.
    """

    suppressed: bool
    suppressed_by_actor: bool
    suppressed_by_fp: bool
    active_actor_decision: TriageDecision | None
    reentry: ReentryInfo | None = None
