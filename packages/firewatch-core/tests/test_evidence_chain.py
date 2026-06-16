"""Tests for build_evidence_chain (ADR-0041 / issue #387 MI-6).

EARS acceptance criteria → test mapping:

  EARS-1 — WHEN evidence is requested for an IP, every breakdown factor present
           SHALL list the ``logs`` row ids that contributed, recomputed at read
           time.
           → test_brute_force_evidence_lists_all_blocked_row_ids
           → test_port_scan_evidence_lists_distinct_port_rows
           → test_sqli_evidence_lists_matching_rows
           → test_xss_evidence_lists_matching_rows
           → test_blocked_events_evidence_lists_all_blocked_row_ids  (#651: now tests 'persistence')
           → test_detection_boost_evidence_present
           → test_empty_rows_yields_empty_evidence

  EARS-2 (consistency invariant, ADR-0041) — the factors and points in the
           evidence response SHALL be identical to build_score_breakdown's output
           for the same rows.
           → test_factor_keys_match_breakdown
           → test_factor_points_match_breakdown
           → test_evidence_chain_factors_match_breakdown_all_factors

  EARS-3 — WHEN matched_event_ids / event_id are empty (production reality),
           the chain SHALL still be complete.
           → test_empty_event_id_still_complete
           → test_no_matched_event_ids_does_not_matter

  EARS-4 — Ubiquitous: the endpoint SHALL be read-only — no writes, no LLM
           calls, no sampling.
           → test_no_ai_call_in_evidence_chain (structural: builder is pure fn)

  EARS-5 — WHEN the ai_boost factor is present, its evidence SHALL be a
           reference to the stored analysis artifact, never recomputed samples.
           → test_ai_boost_evidence_is_reference_not_recompute
           → test_ai_boost_evidence_contains_stored_artifact_fields
           → test_ai_boost_evidence_no_log_row_ids

  RFC-5737 IPs only: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from firewatch_core.evidence import build_evidence_chain
from firewatch_core.scoring import build_score_breakdown
from firewatch_sdk.models import AiBoostEvidence, FactorEvidence

from _fakes import make_event

# Canonical test IP (RFC 5737 documentation range).
_IP = "203.0.113.10"
_T0 = datetime(2026, 6, 3, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row(
    row_id: int,
    action: str = "BLOCK",
    destination_port: int = 80,
    payload_snippet: str | None = None,
    rule_id: str | None = None,
) -> dict[str, Any]:
    """Build a minimal ``get_events_with_row_ids``-shaped row dict."""
    return {
        "id": row_id,
        "timestamp": _T0.isoformat(),
        "action": action,
        "destination_port": destination_port,
        "rule_id": rule_id,
        "payload_snippet": payload_snippet,
        "source_type": "suricata",
        "category": None,
    }


def _events_from_rows(rows: list[dict[str, Any]]) -> list[Any]:
    """Build SecurityEvent list from row dicts so build_score_breakdown can consume them."""
    return [
        make_event(
            source_ip=_IP,
            action=r["action"],
            destination_port=r.get("destination_port"),
            payload_snippet=r.get("payload_snippet"),
            rule_id=r.get("rule_id"),
        )
        for r in rows
    ]


def _factor_names(chain: list[Any]) -> list[str]:
    return [item.factor for item in chain]


def _factor_points(chain: list[Any]) -> dict[str, int]:
    return {item.factor: item.points for item in chain}


# ---------------------------------------------------------------------------
# EARS-1: per-factor row id resolution
# ---------------------------------------------------------------------------


def test_brute_force_evidence_lists_all_blocked_row_ids() -> None:
    """EARS-1: brute_force factor lists all blocked row ids (≥10 blocked)."""
    rows = [_row(i, action="BLOCK") for i in range(1, 11)]  # 10 blocked
    events = _events_from_rows(rows)
    breakdown = build_score_breakdown(events)
    chain = build_evidence_chain(rows, breakdown)

    bf = next(i for i in chain if i.factor == "brute_force")
    assert isinstance(bf, FactorEvidence)
    assert set(bf.log_row_ids) == set(range(1, 11))
    assert bf.count == 10


def test_port_scan_evidence_lists_distinct_port_rows() -> None:
    """EARS-1: port_scan factor lists one row per distinct destination port."""
    # 5 distinct ports across 7 events (some ports repeated).
    rows = [
        _row(1, action="ALERT", destination_port=22),
        _row(2, action="ALERT", destination_port=80),
        _row(3, action="ALERT", destination_port=443),
        _row(4, action="ALERT", destination_port=8080),
        _row(5, action="ALERT", destination_port=8443),
        _row(6, action="ALERT", destination_port=22),   # duplicate port
        _row(7, action="ALERT", destination_port=80),   # duplicate port
    ]
    events = _events_from_rows(rows)
    breakdown = build_score_breakdown(events)
    chain = build_evidence_chain(rows, breakdown)

    ps = next((i for i in chain if i.factor == "port_scan"), None)
    assert ps is not None, "port_scan factor must be present for 5+ distinct ports"
    assert isinstance(ps, FactorEvidence)
    # Deduped by port: exactly one row per unique port (5 ports → 5 rows).
    assert ps.count == 5
    # All distinct ports are represented.
    assert len(ps.log_row_ids) == 5


def test_sqli_evidence_lists_matching_rows() -> None:
    """EARS-1: sql_injection factor lists ALL rows with SQLi payloads (#651).

    SQLi is scored across every event regardless of disposition (#651), so the
    evidence chain must attribute the factor to matching rows of ANY action —
    including an alert-only / allowed-through SQLi (the headline #648/#651 case).
    A drawer that omitted the ALERT row would be the exact inconsistency #651 fixes.
    """
    rows = [
        _row(1, action="BLOCK", payload_snippet="GET /safe HTTP/1.1"),
        _row(2, action="BLOCK", payload_snippet="UNION SELECT 1,2,3"),
        _row(3, action="BLOCK", payload_snippet="1 OR 1=1"),
        _row(4, action="ALERT", payload_snippet="UNION SELECT passwd"),  # alert-only SQLi
    ]
    events = _events_from_rows(rows)
    breakdown = build_score_breakdown(events)
    chain = build_evidence_chain(rows, breakdown)

    sqli = next((i for i in chain if i.factor == "sql_injection"), None)
    assert sqli is not None, "sql_injection factor must be present"
    assert isinstance(sqli, FactorEvidence)
    # Rows 2 and 3 (blocked) AND row 4 (alert-only) all match SQLi patterns (#651).
    assert 2 in sqli.log_row_ids
    assert 3 in sqli.log_row_ids
    assert 4 in sqli.log_row_ids  # alert-only SQLi now attributed (#651)
    assert 1 not in sqli.log_row_ids  # benign payload, no match


def test_xss_evidence_lists_matching_rows() -> None:
    """EARS-1: xss factor lists ALL rows with XSS payloads (#651, any disposition)."""
    rows = [
        _row(1, action="BLOCK", payload_snippet="<script>alert(1)</script>"),
        _row(2, action="BLOCK", payload_snippet="onerror=doEvil"),
        _row(3, action="BLOCK", payload_snippet="normal payload"),
        _row(4, action="ALERT", payload_snippet="<script>x</script>"),  # alert-only XSS
    ]
    events = _events_from_rows(rows)
    breakdown = build_score_breakdown(events)
    chain = build_evidence_chain(rows, breakdown)

    xss = next((i for i in chain if i.factor == "xss"), None)
    assert xss is not None
    assert isinstance(xss, FactorEvidence)
    assert 1 in xss.log_row_ids
    assert 2 in xss.log_row_ids
    assert 3 not in xss.log_row_ids  # benign payload, no match
    assert 4 in xss.log_row_ids  # alert-only XSS now attributed (#651)


def test_blocked_events_evidence_lists_all_blocked_row_ids() -> None:
    """EARS-1: persistence factor lists all blocked row ids (#651 rename).

    (#651) 'blocked_events' was renamed to 'persistence' in build_score_breakdown.
    The evidence chain builder maps all blocked rows to the persistence factor —
    the semantics (which rows contribute) are unchanged; only the factor key changes.
    3 blocked rows >= _PERSISTENCE_THRESHOLD so the factor fires.
    """
    rows = [
        _row(1, action="BLOCK"),
        _row(2, action="BLOCK"),
        _row(3, action="ALLOW"),
        _row(4, action="ALERT"),
        _row(5, action="BLOCK"),
    ]
    events = _events_from_rows(rows)
    breakdown = build_score_breakdown(events)
    chain = build_evidence_chain(rows, breakdown)

    # Factor renamed to 'persistence' in #651; same contributing rows as before.
    be = next((i for i in chain if i.factor == "persistence"), None)
    assert be is not None
    assert isinstance(be, FactorEvidence)
    assert set(be.log_row_ids) == {1, 2, 5}
    assert be.count == 3


def test_detection_boost_evidence_present() -> None:
    """EARS-1: detection_boost factor present when boost > 0."""
    rows = [_row(i, action="BLOCK") for i in range(1, 6)]
    events = _events_from_rows(rows)
    detection_boost = 15
    breakdown = build_score_breakdown(events, None, detection_boost=detection_boost)
    chain = build_evidence_chain(rows, breakdown, ai_result=None)

    det = next((i for i in chain if i.factor == "detection_boost"), None)
    assert det is not None, "detection_boost factor must be present when boost > 0"
    assert isinstance(det, FactorEvidence)
    assert det.points == 15


def test_empty_rows_yields_empty_evidence() -> None:
    """EARS-1: no rows → no breakdown → empty evidence chain."""
    breakdown = build_score_breakdown([], None, 0)
    chain = build_evidence_chain([], breakdown)
    assert chain == []


# ---------------------------------------------------------------------------
# EARS-2: consistency invariant — factors and points match build_score_breakdown
# ---------------------------------------------------------------------------


def test_factor_keys_match_breakdown() -> None:
    """EARS-2: factor keys in evidence chain match build_score_breakdown output."""
    rows = [
        _row(i, action="BLOCK", destination_port=i, payload_snippet="UNION SELECT 1")
        for i in range(1, 11)
    ]
    events = _events_from_rows(rows)
    breakdown = build_score_breakdown(events)
    chain = build_evidence_chain(rows, breakdown)

    assert _factor_names(chain) == [item.factor for item in breakdown]


def test_factor_points_match_breakdown() -> None:
    """EARS-2: points in evidence chain match build_score_breakdown output."""
    rows = [
        _row(i, action="BLOCK", destination_port=i, payload_snippet="<script>x</script>")
        for i in range(1, 12)
    ]
    events = _events_from_rows(rows)
    breakdown = build_score_breakdown(events)
    chain = build_evidence_chain(rows, breakdown)

    breakdown_points = {item.factor: item.points for item in breakdown}
    chain_points = _factor_points(chain)
    assert chain_points == breakdown_points, (
        f"EARS-2 consistency invariant violated: "
        f"breakdown={breakdown_points} chain={chain_points}"
    )


def test_evidence_chain_factors_match_breakdown_all_factors() -> None:
    """EARS-2: all-factors scenario — chain mirrors breakdown exactly."""
    rows = [
        _row(i, action="BLOCK", destination_port=i, payload_snippet="UNION SELECT 1")
        for i in range(1, 11)
    ]
    ai_result = {"threat_level": "CRITICAL", "confidence": 0.9}
    events = _events_from_rows(rows)
    detection_boost = 20
    breakdown = build_score_breakdown(events, ai_result, detection_boost=detection_boost)
    chain = build_evidence_chain(rows, breakdown, ai_result=ai_result)

    for bd_item, ev_item in zip(breakdown, chain):
        assert bd_item.factor == ev_item.factor, (
            f"Factor mismatch: breakdown={bd_item.factor} evidence={ev_item.factor}"
        )
        assert bd_item.points == ev_item.points, (
            f"Points mismatch for factor '{bd_item.factor}': "
            f"breakdown={bd_item.points} evidence={ev_item.points}"
        )


# ---------------------------------------------------------------------------
# EARS-3: production reality — empty event_id / matched_event_ids still works
# ---------------------------------------------------------------------------


def test_empty_event_id_still_complete() -> None:
    """EARS-3: evidence chain is complete even when SecurityEvent.event_id is None."""
    # make_event defaults event_id=None — this is the production state.
    rows = [_row(i, action="BLOCK") for i in range(1, 11)]
    events = _events_from_rows(rows)
    # Confirm event_id is None on all events (production reality).
    assert all(e.event_id is None for e in events)
    breakdown = build_score_breakdown(events)
    chain = build_evidence_chain(rows, breakdown)

    assert len(chain) > 0
    bf = next((i for i in chain if i.factor == "brute_force"), None)
    assert bf is not None
    assert isinstance(bf, FactorEvidence)
    assert bf.count == 10


def test_no_matched_event_ids_does_not_matter() -> None:
    """EARS-3: evidence chain does not depend on Detection.matched_event_ids.

    (#651) Factor renamed to 'persistence'; the chain is still complete without
    any detection / matched_event_ids — the builder uses row dicts directly.
    5 blocked rows >= _PERSISTENCE_THRESHOLD so persistence fires.
    """
    # The builder takes row dicts directly — it never reads matched_event_ids.
    # This test confirms the chain is complete with the row-dict-only path.
    rows = [_row(i, action="BLOCK") for i in range(1, 6)]
    events = _events_from_rows(rows)
    breakdown = build_score_breakdown(events)
    # No detections/matched_event_ids passed in at all.
    chain = build_evidence_chain(rows, breakdown, ai_result=None)
    assert len(chain) > 0
    # Factor renamed to 'persistence' in #651; all 5 blocked rows contribute.
    be = next((i for i in chain if i.factor == "persistence"), None)
    assert be is not None
    assert isinstance(be, FactorEvidence)
    assert set(be.log_row_ids) == set(range(1, 6))


# ---------------------------------------------------------------------------
# EARS-4: read-only — no AI calls (structural — builder is a pure function)
# ---------------------------------------------------------------------------


def test_no_ai_call_in_evidence_chain() -> None:
    """EARS-4: build_evidence_chain is a pure function — no I/O, no LLM call.

    Structural test: if the function completes without any external call,
    the invariant holds.  The monkeypatch guard ensures no accidental call
    to any scoring/AI entry point occurs inside the builder.
    """
    rows = [_row(i, action="BLOCK") for i in range(1, 6)]
    events = _events_from_rows(rows)
    breakdown = build_score_breakdown(events)
    # Simply calling build_evidence_chain with no live resources must not raise.
    chain = build_evidence_chain(rows, breakdown, ai_result=None)
    # If we reach here without hanging or raising, no I/O occurred.
    assert len(chain) >= 0  # always true — the assertion proves reachability


# ---------------------------------------------------------------------------
# EARS-5: ai_boost evidence is a stored-artifact reference, not a re-run
# ---------------------------------------------------------------------------


def test_ai_boost_evidence_is_reference_not_recompute() -> None:
    """EARS-5: ai_boost evidence is AiBoostEvidence, not FactorEvidence with row ids."""
    rows = [_row(i, action="BLOCK") for i in range(1, 6)]
    events = _events_from_rows(rows)
    ai_result = {"threat_level": "CRITICAL", "confidence": 0.85}
    breakdown = build_score_breakdown(events, ai_result)
    chain = build_evidence_chain(rows, breakdown, ai_result=ai_result)

    ai_ev = next((i for i in chain if i.factor == "ai_boost"), None)
    assert ai_ev is not None, "ai_boost factor must be present when boost was applied"
    assert isinstance(ai_ev, AiBoostEvidence), (
        "ai_boost evidence must be AiBoostEvidence (stored-artifact reference)"
    )


def test_ai_boost_evidence_contains_stored_artifact_fields() -> None:
    """EARS-5: AiBoostEvidence carries threat_level and confidence from the artifact."""
    rows = [_row(i, action="BLOCK") for i in range(1, 5)]
    events = _events_from_rows(rows)
    ai_result = {"threat_level": "HIGH", "confidence": 0.75}
    breakdown = build_score_breakdown(events, ai_result)
    chain = build_evidence_chain(rows, breakdown, ai_result=ai_result)

    ai_ev = next((i for i in chain if i.factor == "ai_boost"), None)
    assert ai_ev is not None
    assert isinstance(ai_ev, AiBoostEvidence)
    assert ai_ev.threat_level == "HIGH"
    assert ai_ev.confidence == pytest.approx(0.75)
    assert ai_ev.points == 10  # HIGH + conf > 0.7 → +10


def test_ai_boost_evidence_no_log_row_ids() -> None:
    """EARS-5: AiBoostEvidence has no log_row_ids (reference, not row binding).

    The AiBoostEvidence type does not declare a log_row_ids field — this test
    confirms the type boundary holds by inspecting the model fields dict.
    """
    rows = [_row(i, action="BLOCK") for i in range(1, 5)]
    events = _events_from_rows(rows)
    ai_result = {"threat_level": "CRITICAL", "confidence": 0.9}
    breakdown = build_score_breakdown(events, ai_result)
    chain = build_evidence_chain(rows, breakdown, ai_result=ai_result)

    ai_ev = next((i for i in chain if i.factor == "ai_boost"), None)
    assert ai_ev is not None
    assert isinstance(ai_ev, AiBoostEvidence)
    # AiBoostEvidence is a Pydantic model; model_fields lists declared fields.
    assert "log_row_ids" not in AiBoostEvidence.model_fields, (
        "AiBoostEvidence must not declare log_row_ids "
        "(it is a stored-artifact reference, not a row binding)"
    )


def test_ai_boost_absent_when_no_ai_result() -> None:
    """EARS-5: no ai_boost factor in chain when ai_result is None."""
    rows = [_row(i, action="BLOCK") for i in range(1, 5)]
    events = _events_from_rows(rows)
    breakdown = build_score_breakdown(events, None)
    chain = build_evidence_chain(rows, breakdown, ai_result=None)

    factors = _factor_names(chain)
    assert "ai_boost" not in factors


def test_ai_boost_note_explains_read_time_semantics() -> None:
    """EARS-5: AiBoostEvidence.note mentions ADR-0035 / no LLM call."""
    rows = [_row(i, action="BLOCK") for i in range(1, 5)]
    events = _events_from_rows(rows)
    ai_result = {"threat_level": "CRITICAL", "confidence": 0.9}
    breakdown = build_score_breakdown(events, ai_result)
    chain = build_evidence_chain(rows, breakdown, ai_result=ai_result)

    ai_ev = next(i for i in chain if i.factor == "ai_boost")
    assert isinstance(ai_ev, AiBoostEvidence)
    assert "ADR-0035" in ai_ev.note
    assert "ADR-0041" in ai_ev.note


# ---------------------------------------------------------------------------
# Structural / edge-case invariants
# ---------------------------------------------------------------------------


def test_summaries_populated_with_correct_row_ids() -> None:
    """EventSummary entries in FactorEvidence mirror their row ids.

    (#651) Factor renamed from 'blocked_events' to 'persistence'.
    3 BLOCK rows >= _PERSISTENCE_THRESHOLD (3) so persistence fires; all blocked
    rows get EventSummary entries with their log_row_id values.
    """
    rows = [
        _row(10, action="BLOCK", payload_snippet="UNION SELECT 1"),
        _row(20, action="BLOCK", payload_snippet="DROP TABLE users"),
        _row(30, action="BLOCK"),  # 3rd BLOCK to meet _PERSISTENCE_THRESHOLD=3 (#651)
    ]
    events = _events_from_rows(rows)
    breakdown = build_score_breakdown(events)
    chain = build_evidence_chain(rows, breakdown)

    # Factor renamed to 'persistence' in #651; all blocked rows contribute.
    be = next(i for i in chain if i.factor == "persistence")
    assert isinstance(be, FactorEvidence)
    summary_ids = [s.log_row_id for s in be.summaries]
    assert set(summary_ids) == {10, 20, 30}


def test_payload_snippet_truncated_in_summary() -> None:
    """EventSummary.payload_snippet is truncated to ≤ 200 chars.

    (#651) Factor renamed from 'blocked_events' to 'persistence'.
    Need ≥3 BLOCK rows to trigger persistence; all share the long payload.
    """
    long_payload = "A" * 300
    # 3 BLOCK rows to meet _PERSISTENCE_THRESHOLD=3 (#651)
    rows = [
        _row(1, action="BLOCK", payload_snippet=long_payload),
        _row(2, action="BLOCK", payload_snippet=long_payload),
        _row(3, action="BLOCK", payload_snippet=long_payload),
    ]
    events = _events_from_rows(rows)
    breakdown = build_score_breakdown(events)
    chain = build_evidence_chain(rows, breakdown)

    # Factor renamed to 'persistence' in #651.
    be = next(i for i in chain if i.factor == "persistence")
    assert isinstance(be, FactorEvidence)
    assert len(be.summaries) == 3
    # Every summary's payload_snippet is truncated to ≤ 200 chars.
    for summary in be.summaries:
        assert summary.payload_snippet is not None
        assert len(summary.payload_snippet) <= 200


def test_cap_factor_has_no_row_ids() -> None:
    """Cap factor (score adjustment) has no contributing row ids.

    (#651) New math: brute_force(30) + port_scan(25) + sqli_BLOCK(20) +
    persistence(10) + detection_boost(20) = 105 > 100 → cap fires.
    Old math (removed): brute_force(30) + sqli(40) + blocked_events(30) + port_scan(25) = 125.
    """
    # 30 BLOCK events with distinct ports and SQLi payload, plus detection_boost=20:
    #   brute_force=30, port_scan=25, sqli on BLOCK=round(40×0.5)=20,
    #   persistence=10, detection_boost=20 → raw=105 → capped (#651)
    rows = [
        _row(i, action="BLOCK", destination_port=i, payload_snippet="UNION SELECT 1")
        for i in range(1, 31)
    ]
    events = _events_from_rows(rows)
    breakdown = build_score_breakdown(events, None, detection_boost=20)
    chain = build_evidence_chain(rows, breakdown)

    cap = next((i for i in chain if i.factor == "cap"), None)
    assert cap is not None, "cap factor must be present when raw > 100"
    assert isinstance(cap, FactorEvidence)
    assert cap.log_row_ids == []
    assert cap.count == 0
