"""Tests for ``firewatch_api.decision_annotator`` (ADR-0072 D8).

EARS → test mapping
─────────────────────
- annotate() returns None when the actor has no active actor-scoped decision.
  -> test_annotate_returns_none_when_undecided

- annotate() surfaces verb/decided_at/decided_tier/decided_score/suppressed
  from the latest active actor-scoped row.
  -> test_annotate_surfaces_active_actor_decision

- annotate() returns None for an FP-only actor (rule-scoped, not rendered in
  this slot) even though suppressed may be True via is_suppressed().
  -> test_annotate_returns_none_for_fp_only_actor

- is_suppressed() is the SAME evaluator annotate() uses — ADR-0072 finding 2
  ("one evaluator, every surface"): calling both on the same input agrees.
  -> test_is_suppressed_agrees_with_annotate_suppressed_field

- verdict=None (no escalation available) degrades safely — no crash, no
  false suppression claim beyond actor-identity.
  -> test_none_verdict_does_not_crash

All IPs are RFC 5737 documentation IPs (198.51.100.0/24).
"""
from __future__ import annotations

from firewatch_sdk.models import EscalationVerdict

from firewatch_api.decision_annotator import annotate, is_suppressed

_IP = "198.51.100.80"


def _row(
    *,
    id: int = 1,
    verb: str = "expected",
    rule_name: str | None = None,
    decided_tier: int | None = 2,
    decided_score: int = 40,
    decided_at: str = "2026-07-01T00:00:00+00:00",
    revoked_at: str | None = None,
) -> dict:  # type: ignore[type-arg]
    return {
        "id": id,
        "actor_ip": _IP,
        "verb": verb,
        "rule_name": rule_name,
        "decided_tier": decided_tier,
        "decided_score": decided_score,
        "decided_at": decided_at,
        "revoked_at": revoked_at,
        "author": "local operator",
        "note": None,
    }


def _verdict(*, tier: int | None = 2, qualifying_rules: list[str] | None = None) -> EscalationVerdict:
    return EscalationVerdict(
        tier=tier,
        disposition="observed" if tier is None else "block_status_unknown",
        justification="[RULE] test",
        block_status="unknown",
        qualifying_rules=qualifying_rules or [],
    )


def test_annotate_returns_none_when_undecided() -> None:
    assert annotate([], _verdict()) is None


def test_annotate_surfaces_active_actor_decision() -> None:
    result = annotate([_row(verb="dismissed", decided_tier=1, decided_score=55)], _verdict())
    assert result is not None
    assert result.verb == "dismissed"
    assert result.decided_tier == 1
    assert result.decided_score == 55
    assert result.suppressed is True
    assert result.reentry is None


def test_annotate_ignores_revoked_rows() -> None:
    row = _row(verb="expected", revoked_at="2026-07-02T00:00:00+00:00")
    assert annotate([row], _verdict()) is None


def test_annotate_returns_none_for_fp_only_actor() -> None:
    """FP rows are rule-scoped — not rendered in the actor-level slot, even
    when they fully suppress the current verdict."""
    fp_row = _row(id=1, verb="false_positive", rule_name="waf_sqli")
    verdict = _verdict(tier=2, qualifying_rules=["waf_sqli"])
    assert annotate([fp_row], verdict) is None
    assert is_suppressed([fp_row], verdict) is True  # still excluded from the queue


def test_is_suppressed_agrees_with_annotate_suppressed_field() -> None:
    rows = [_row(verb="expected")]
    verdict = _verdict()
    annotated = annotate(rows, verdict)
    assert annotated is not None
    assert is_suppressed(rows, verdict) == annotated.suppressed


def test_none_verdict_does_not_crash() -> None:
    rows = [_row(verb="expected")]
    assert is_suppressed(rows, None) is True  # actor-identity suppression unaffected
    annotated = annotate(rows, None)
    assert annotated is not None
    assert annotated.suppressed is True
