"""Severity ordering and verdict types for the escalation axis (ADR-0058 D1/D2).

This module owns the C-foundation data shapes consumed by policy.py (this issue)
and decider.py (issue #648).

Re-exports ``EscalationVerdict`` from ``firewatch_sdk.models`` so that imports
via ``firewatch_core.escalation.model`` continue to work after the type was moved
to the SDK (dependency rule: core may import SDK, but SDK must not import core).

Standard anchor:
- Sigma ``level`` vocabulary (informational/low/medium/high/critical) —
  https://sigmahq.io/docs/basics/rules.html
- Elastic Detection Rules ``risk_score`` (0-100 ordinal) —
  https://www.elastic.co/guide/en/security/current/rules-ui-create.html

``SeverityLiteral`` already mirrors Sigma's five levels in the SDK (models.py:21).
We reuse it here and do NOT introduce a new enum (ADR-0058 §D3).
"""
from __future__ import annotations

from functools import total_ordering

from firewatch_sdk.models import EscalationVerdict, SeverityLiteral

__all__ = ["SEVERITY_RANKS", "SeverityOrder", "EscalationVerdict"]

# Sigma-anchored rank table (integer ordinals for comparison).
# Elastic risk_score analog: info≈1-21, low≈22-47, medium≈48-73, high≈74-90, critical≈91-100.
# Ref: Elastic Detection Rules risk_score
# https://www.elastic.co/guide/en/security/current/rules-ui-create.html
SEVERITY_RANKS: dict[str, int] = {
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


@total_ordering
class SeverityOrder:
    """Comparable wrapper around ``SeverityLiteral`` implementing Sigma total ordering.

    Allows ``sorted()``, ``<``, ``>``, ``==`` across severity levels without
    constructing an enum.  Uses ``SEVERITY_RANKS`` for the integer comparison so
    the ordering is explicit and testable.

    Example::

        assert SeverityOrder("high") > SeverityOrder("medium")
        levels = sorted(SeverityOrder(lv) for lv in ["critical", "info", "high"])
        # → [info, high, critical]
    """

    def __init__(self, level: SeverityLiteral) -> None:
        # N-3 (issue #648): annotation narrowed to SeverityLiteral so Pyright flags
        # bad call sites statically. The runtime guard stays as defense-in-depth for
        # untyped/dynamic callers (e.g. values widened to str elsewhere).
        if level not in SEVERITY_RANKS:
            raise ValueError(
                f"Unknown severity level {level!r}. "
                f"Must be one of: {sorted(SEVERITY_RANKS)}"
            )
        self.level = level

    def _rank(self) -> int:
        return SEVERITY_RANKS[self.level]

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SeverityOrder):
            return self._rank() == other._rank()
        return NotImplemented

    def __lt__(self, other: object) -> bool:
        if isinstance(other, SeverityOrder):
            return self._rank() < other._rank()
        return NotImplemented

    def __repr__(self) -> str:
        return f"SeverityOrder({self.level!r})"

    def __hash__(self) -> int:
        return hash(self.level)
