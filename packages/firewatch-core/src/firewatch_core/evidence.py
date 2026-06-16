"""Evidence-chain builder — factor → contributing ``logs`` row ids (ADR-0041).

Pure function, no I/O, no side-effects.  Operates on the IP's stored events
**with their ``logs`` row ids** (as returned by
``SQLiteEventStore.get_events_with_row_ids``), the score-breakdown items from
``build_score_breakdown``, and an optional AI result dict.

Design:
  - Imports patterns/constants directly from ``scoring.py`` — never duplicates them.
  - For rule factors (brute_force, port_scan, sql_injection, xss, persistence,
    detection_boost): re-applies each factor's predicate read-only to identify the
    contributing row ids.  ("blocked_events" is the pre-#651 name for persistence;
    both are handled for forward-compat.)
  - For ai_boost: returns an ``AiBoostEvidence`` referencing the stored AI analysis
    artifact (ADR-0035 provenance) — NO LLM call, NO sample rebuild.

ai-engine-invariants boundary (hard out-of-scope per ADR-0041):
  - This module does NOT call run_rules, merge_score, or build_score_breakdown.
  - It does NOT build AI samples, call the AI engine, or modify any prompt.
  - It does NOT write to the store.  Read-time-only.

Consistency invariant (ADR-0041): the factor keys and points in the evidence
response are identical to build_score_breakdown's output for the same rows.  This
is enforced by a test that feeds the same SecurityEvent list to both functions and
asserts the factor/points sets match.
"""
from __future__ import annotations

import re
from typing import Any, Union

from firewatch_sdk import ScoreBreakdownItem
from firewatch_sdk.models import AiBoostEvidence, EventSummary, FactorEvidence

# Import scoring patterns/constants directly — NEVER duplicate them (ADR-0041).
from firewatch_core.scoring import SQL_PATTERNS, XSS_PATTERNS

# Maximum payload characters to include in an EventSummary (cosmetic bound only;
# never truncate the original row).
_SUMMARY_PAYLOAD_MAX = 200

# Type alias for a row dict returned by get_events_with_row_ids.
_RowDict = dict[str, Any]

# Union type for the evidence list items (rule factors + ai_boost variant).
EvidenceItem = Union[FactorEvidence, AiBoostEvidence]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _to_summary(row: _RowDict) -> EventSummary:
    """Build an ``EventSummary`` from a ``get_events_with_row_ids`` row dict."""
    payload = row.get("payload_snippet")
    if payload and len(payload) > _SUMMARY_PAYLOAD_MAX:
        payload = payload[:_SUMMARY_PAYLOAD_MAX]
    return EventSummary(
        log_row_id=int(row["id"]),
        timestamp=str(row.get("timestamp", "")),
        action=str(row.get("action", "")),
        rule_id=row.get("rule_id") or None,
        payload_snippet=payload or None,
    )


def _factor_evidence(
    item: ScoreBreakdownItem,
    contributing_rows: list[_RowDict],
) -> FactorEvidence:
    """Build a ``FactorEvidence`` from a breakdown item and its contributing rows."""
    row_ids = [int(r["id"]) for r in contributing_rows]
    summaries = [_to_summary(r) for r in contributing_rows]
    return FactorEvidence(
        factor=item.factor,
        label=item.label,
        points=item.points,
        log_row_ids=row_ids,
        count=len(row_ids),
        summaries=summaries,
    )


# ---------------------------------------------------------------------------
# Per-factor predicate helpers
# ---------------------------------------------------------------------------


def _blocked_rows(rows: list[_RowDict]) -> list[_RowDict]:
    """Return rows whose action is BLOCK or DROP."""
    return [r for r in rows if r.get("action") in ("BLOCK", "DROP")]


def _port_scan_rows(rows: list[_RowDict]) -> list[_RowDict]:
    """Return the minimal row set that establishes ≥ 5 distinct destination ports.

    The port_scan factor fires on the full event set (all actions), using all
    distinct destination ports.  We return the deduplicated first-seen row per
    distinct port so the analyst can see exactly which events established the scan.
    """
    seen: set[int | None] = set()
    result: list[_RowDict] = []
    for r in rows:
        port = r.get("destination_port")
        if port not in seen:
            seen.add(port)
            result.append(r)
    return result


def _sqli_rows(rows: list[_RowDict]) -> list[_RowDict]:
    """Return rows whose payload matches any SQL injection pattern.

    Scans ALL rows, not just blocked ones (issue #651): run_rules now scores
    SQLi across every event regardless of disposition, so the evidence chain
    must attribute the factor to the same rows (e.g. an allowed-through/alert-only
    SQLi must list its contributing row, not show an empty drawer).
    """
    result: list[_RowDict] = []
    for r in rows:
        payload = r.get("payload_snippet") or ""
        if any(re.search(p, payload, re.IGNORECASE) for p in SQL_PATTERNS):
            result.append(r)
    return result


def _xss_rows(rows: list[_RowDict]) -> list[_RowDict]:
    """Return rows whose payload matches any XSS pattern (all rows — see _sqli_rows / #651)."""
    result: list[_RowDict] = []
    for r in rows:
        payload = r.get("payload_snippet") or ""
        if any(re.search(p, payload, re.IGNORECASE) for p in XSS_PATTERNS):
            result.append(r)
    return result


# ---------------------------------------------------------------------------
# Public builder
# ---------------------------------------------------------------------------


def build_evidence_chain(
    rows: list[_RowDict],
    breakdown: list[ScoreBreakdownItem],
    ai_result: dict[str, Any] | None = None,
) -> list[EvidenceItem]:
    """Build the evidence chain for one IP's stored events (ADR-0041).

    Parameters
    ----------
    rows:
        Row dicts from ``store.get_events_with_row_ids(ip)`` — must include at
        least ``id``, ``timestamp``, ``action``, ``destination_port``,
        ``rule_id``, ``payload_snippet``.
    breakdown:
        Score-breakdown items from ``build_score_breakdown(events, ai_result,
        detection_boost)``.  The factor keys and points in the returned evidence
        chain will mirror this list exactly (consistency invariant, ADR-0041).
    ai_result:
        The AI analysis result dict (as stored by the pipeline), or ``None`` when
        no AI analysis was performed.  Used ONLY to populate the ``AiBoostEvidence``
        reference fields — no AI call is made.

    Returns
    -------
    list[EvidenceItem]
        One item per breakdown factor (same order as *breakdown*).  For the
        ``ai_boost`` factor the item is an ``AiBoostEvidence``; all others are
        ``FactorEvidence``.

    Notes
    -----
    - Read-time semantics: events arriving after scoring may shift the contributing
      row sets (this is a recompute, not a snapshot — ADR-0041).
    - No writes, no LLM calls, no sample building (ai-engine-invariants boundary).
    """
    if not breakdown:
        return []

    # Pre-compute commonly reused row subsets.
    blocked = _blocked_rows(rows)

    # Lazily computed per-factor to avoid unnecessary work when a factor is absent.
    _port_rows: list[_RowDict] | None = None
    _sql_rows: list[_RowDict] | None = None
    _xss_matching: list[_RowDict] | None = None

    evidence: list[EvidenceItem] = []

    for item in breakdown:
        factor = item.factor

        if factor == "brute_force":
            # brute_force fires when ≥ 10 blocked rows; all blocked rows contribute.
            evidence.append(_factor_evidence(item, blocked))

        elif factor == "port_scan":
            # port_scan fires on all events (not just blocked); deduplicated by port.
            if _port_rows is None:
                _port_rows = _port_scan_rows(rows)
            evidence.append(_factor_evidence(item, _port_rows))

        elif factor == "sql_injection":
            # SQLi is scored across ALL events (#651), not just blocked — scan all rows.
            if _sql_rows is None:
                _sql_rows = _sqli_rows(rows)
            evidence.append(_factor_evidence(item, _sql_rows))

        elif factor == "xss":
            if _xss_matching is None:
                _xss_matching = _xss_rows(rows)
            evidence.append(_factor_evidence(item, _xss_matching))

        elif factor in ("persistence", "blocked_events"):
            # persistence (renamed from blocked_events in #651): all blocked rows
            # contribute to the persistence floor.  The old name is kept as a
            # fallback for forward-compat with any stored breakdowns pre-#651.
            evidence.append(_factor_evidence(item, blocked))

        elif factor == "detection_boost":
            # detection_boost arises from correlation detections (detector.py).
            # At read time we cannot re-match correlation rules to specific rows
            # without re-running the full detector — the row set for this factor
            # is therefore the full blocked-event set (the events the detector
            # operated on).  The ``note`` in the label explains this.
            evidence.append(_factor_evidence(item, blocked))

        elif factor == "ai_boost":
            # ai-engine-invariants boundary: no LLM call, no sample rebuild.
            # Return a reference to the stored AI artifact (ADR-0035 provenance).
            ai_level = str(ai_result.get("threat_level", "")) if ai_result else None
            ai_conf_raw = ai_result.get("confidence") if ai_result else None
            ai_conf = float(ai_conf_raw) if ai_conf_raw is not None else None
            evidence.append(AiBoostEvidence(
                factor="ai_boost",
                label=item.label,
                points=item.points,
                provenance="ai+rule",
                threat_level=ai_level or None,
                confidence=ai_conf,
            ))

        elif factor == "cap":
            # The cap item is a score adjustment, not tied to specific rows.
            evidence.append(FactorEvidence(
                factor="cap",
                label=item.label,
                points=item.points,
                log_row_ids=[],
                count=0,
                summaries=[],
            ))

        else:
            # Unknown future factor — emit with empty rows for forward-compat.
            evidence.append(FactorEvidence(
                factor=factor,
                label=item.label,
                points=item.points,
                log_row_ids=[],
                count=0,
                summaries=[],
            ))

    return evidence
