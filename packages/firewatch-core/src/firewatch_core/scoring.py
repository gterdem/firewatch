"""Rule-based scoring + sample building + score merging.

Pure functions, no I/O. Operates on ``SecurityEvent``.

Score formulas and sample-dict shapes are byte-compatible with the v1 oracle so the
#5 golden/prompt-regression baseline keeps passing.

NOTE (issue #199, ADR-0024): SQL_PATTERNS was ported verbatim from legacy/core/scoring.py
where it contained r"\\s*OR" — \\s* matches ZERO whitespace, so any URI containing the
bare substring "or" (e.g. /.env.orig, /authorized_keys) matched, causing false-positive
sql_injection labels.  The patterns are now anchored to real SQL context:

  boolean OR — two-alternative pattern (OWASP TGv4.2 §4.7.5):
    alt-1: OR preceded by digit/quote — covers numeric-context (1 OR 1=1,
           ) OR (1=1) and string-delimiter context (' OR '1'='1).
    alt-2: OR not preceded by letter/underscore AND followed by whitespace
           + digit/quote/paren — catches sqlmap-default `1 OR 1=1`.
    Previous r"'\\s*OR\\b" only covered 3/10 OWASP §4.7.5 payloads;
    two-alternative form covers 10/10.
  r"\\bUNION\\s+SELECT\\b"  — word boundaries prevent matching concatenated strings.
  r"\\bDROP\\s+TABLE\\b"    — word boundaries; same rationale.
"""
import re
from collections import defaultdict
from typing import Any

from firewatch_sdk import ScoreBreakdownItem, SecurityEvent

from firewatch_core.normalize_helpers import categorize_rule

# Anchored SQL injection patterns (issue #199, security-review follow-up).
# r"\s*OR" was the broken v1 pattern (\s* matched zero chars, hitting any "or" URI).
# r"'\s*OR\b" was the first fix (false-negative: only quote-led payloads, 3/10 OWASP).
# Two-alternative boolean-OR pattern below covers 10/10 OWASP TGv4.2 §4.7.5 payloads
# and is clean on false-positive inputs (/.env.orig, ORACLE, /corridor, color=red).
# Ref: OWASP Testing Guide v4.2 §4.7.5 (boolean-based SQLi), §4.7.6 (UNION-based).
_BOOL_OR = r"(?:(?<=[\d'])\s*OR\b|(?<![A-Za-z_])OR(?=\s+[\d'(]))"
SQL_PATTERNS = [_BOOL_OR, r"\bUNION\s+SELECT\b", r"\bDROP\s+TABLE\b"]
XSS_PATTERNS = [r"<script", r"onerror\s*=", r"javascript:"]

MAX_SAMPLES = 15
MAX_PAYLOAD_LEN = 100
MAX_DETAILED_PAYLOAD_LEN = 300

# Minimum confidence the AI must exceed for a HIGH/CRITICAL verdict to raise the merged score.
# Mirrors frontend CONFIDENCE_HIGH_THRESHOLD (frontend/src/lib/provenance.ts) — keep both in sync.
CONFIDENCE_BOOST_THRESHOLD = 0.7
# F1 (DoS-via-legitimate-input hardening): the detailed path caps event load to this
# many most-recent events before building samples or running rules.  Fetching the
# most-recent N events still surfaces every rule that appears in that window; the
# accepted trade-off is that a rule appearing ONLY in events older than the most-recent
# N could be missed on a pathologically high-volume IP.  10 000 is generous enough for
# all realistic deployments while bounding the per-coroutine memory footprint.
MAX_DETAILED_EVENTS = 10_000

# Signature base points (OWASP-derived; issues #199 / #651).
_SQLI_BASE = 40
_XSS_BASE = 35

# Disposition weights for signature scoring (ADR-0058 §D5a / issue #651). A SQLi/XSS
# signature scores its base × the LOUDEST disposition among the events it matched on:
# an allowed-through exploit (possible success) outweighs a blocked one (the control
# fired). The 1.0/0.75/0.5 ladder maps one-to-one to the escalation decider's
# Tier 1 / Tier 2 / Tier 3-4 ordering (escalation/decider.py). Anchors: Sigma `level`,
# Elastic risk_score, OCSF disposition_id — see ADR-0058.
_DISPOSITION_WEIGHT: dict[str, float] = {
    "ALLOW": 1.0,
    "ALERT": 0.75,
    "LOG": 0.75,
    "BLOCK": 0.5,
    "DROP": 0.5,
}

# Persistence floor (ADR-0058 §D5a / issue #651): ≥3 blocked events = Tier-3
# "adversary persisting" — kept in lockstep with escalation/decider.py's
# _PERSISTENCE_THRESHOLD so the score axis and the escalation axis agree. A single
# flat floor, NOT a per-event +1: blocked volume must not be the loudest signal
# (the exact inversion ADR-0058 names).
_PERSISTENCE_THRESHOLD = 3
_PERSISTENCE_FLOOR = 10


def _matches_any(text: str, patterns: list[str]) -> bool:
    """True if *text* matches any of *patterns* (case-insensitive)."""
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


def _loudest_weight(events: list[SecurityEvent]) -> float:
    """Loudest disposition weight among *events* (issue #651 R2).

    Unknown/unmapped actions default to the conservative BLOCK weight (0.5).
    """
    return max((_DISPOSITION_WEIGHT.get(e.action, 0.5) for e in events), default=0.5)


def run_rules(events: list[SecurityEvent]) -> tuple[int, list[str]]:
    """Apply deterministic rule-based scoring (ADR-0058 §D5a disposition-weighted)."""
    blocked = [e for e in events if e.action in ("BLOCK", "DROP")]
    attack_types: list[str] = []
    score = 0

    if len(blocked) >= 10:
        score += 30
        attack_types.append("brute_force")

    dest_ports = {e.destination_port for e in events}
    if len(dest_ports) >= 5:
        score += 25
        attack_types.append("port_scan")

    # R1: SQLi/XSS scanned across ALL events (was blocked-only — the ADR-0058 blind
    # spot). R2: each signature scores its base × the loudest matching disposition.
    sqli_events = [
        e for e in events if e.payload_snippet and _matches_any(e.payload_snippet, SQL_PATTERNS)
    ]
    if sqli_events:
        score += round(_SQLI_BASE * _loudest_weight(sqli_events))
        attack_types.append("sql_injection")

    xss_events = [
        e for e in events if e.payload_snippet and _matches_any(e.payload_snippet, XSS_PATTERNS)
    ]
    if xss_events:
        score += round(_XSS_BASE * _loudest_weight(xss_events))
        attack_types.append("xss")

    # R3: persistence floor instead of a flat +1 per blocked event.
    if len(blocked) >= _PERSISTENCE_THRESHOLD:
        score += _PERSISTENCE_FLOOR

    return score, attack_types


def build_samples(events: list[SecurityEvent]) -> list[dict[str, Any]]:
    """Group blocked events by rule_id and pick one sample payload per rule.

    Returns top MAX_SAMPLES dicts sorted by frequency:
    ``{rule_id, category, payload, count}``.
    """
    groups: dict[str, list[SecurityEvent]] = defaultdict(list)
    for e in events:
        if e.action in ("BLOCK", "DROP") and e.rule_id:
            groups[e.rule_id].append(e)

    samples = []
    for rule_id, entries in groups.items():
        best = max(entries, key=lambda e: len(e.payload_snippet or ""))
        payload = (best.payload_snippet or "(no payload)")[:MAX_PAYLOAD_LEN]
        samples.append({
            "rule_id": rule_id,
            "category": categorize_rule(rule_id),
            "payload": payload,
            "count": len(entries),
        })

    samples.sort(key=lambda s: s["count"], reverse=True)
    return samples[:MAX_SAMPLES]


def build_detailed_samples(
    events: list[SecurityEvent],
    rule_descs: dict[str, str],
) -> list[dict[str, Any]]:
    """Group blocked events by rule_id for the detailed analysis path.

    Unlike ``build_samples``, this function:
    - Includes ALL triggered rules (no MAX_SAMPLES cap).
    - Truncates payloads at MAX_DETAILED_PAYLOAD_LEN (300 chars).
    - Adds per-rule ``first_triggered`` / ``last_triggered`` timestamps.
    - Adds ``description`` from *rule_descs* (blank string if absent — graceful).

    Returns dicts sorted by frequency descending:
    ``{rule_id, category, description, payload, count, first_triggered, last_triggered}``.

    Ported from ``legacy/app/analyzer.py:116-140`` (REFERENCE-ONLY — do not import legacy/).
    """
    groups: dict[str, list[SecurityEvent]] = defaultdict(list)
    for e in events:
        if e.action in ("BLOCK", "DROP") and e.rule_id:
            groups[e.rule_id].append(e)

    samples = []
    for rule_id, entries in groups.items():
        best = max(entries, key=lambda e: len(e.payload_snippet or ""))
        timestamps = [e.timestamp for e in entries]
        payload = (best.payload_snippet or "(no payload)")[:MAX_DETAILED_PAYLOAD_LEN]
        samples.append({
            "rule_id": rule_id,
            "category": categorize_rule(rule_id),
            "description": rule_descs.get(rule_id, ""),
            "payload": payload,
            "count": len(entries),
            "first_triggered": str(min(timestamps)),
            "last_triggered": str(max(timestamps)),
        })

    samples.sort(key=lambda s: s["count"], reverse=True)
    return samples  # no cap — ALL rules


def _ai_boost(ai_result: dict[str, Any] | None) -> int:
    """Return the AI score boost for *ai_result* (additive-only, ADR-0003).

    Pure function: no side-effects, no I/O.

    Boost rules (ai-engine-invariants skill):
      CRITICAL + confidence > CONFIDENCE_BOOST_THRESHOLD  -> +20
      HIGH     + confidence > CONFIDENCE_BOOST_THRESHOLD  -> +10
      anything else                                       -> 0

    Returns 0 when *ai_result* is ``None``, malformed, or the threshold is not met.
    This is the single source of truth for the AI boost decision (ADR-0035 contract
    point 1: derivation is determined at the point of authorship, never inferred
    downstream).
    """
    if ai_result is None:
        return 0
    ai_level = str(ai_result.get("threat_level", "")).upper()
    ai_conf = float(ai_result.get("confidence", 0.0))
    if ai_level == "CRITICAL" and ai_conf > CONFIDENCE_BOOST_THRESHOLD:
        return 20
    if ai_level == "HIGH" and ai_conf > CONFIDENCE_BOOST_THRESHOLD:
        return 10
    return 0


def merge_score(
    rule_score: int,
    ai_result: dict[str, Any] | None = None,
    detection_boost: int = 0,
) -> tuple[int, str, str]:
    """Combine the rule score with optional AI + detection boosts.

    Returns ``(final_score, threat_level, score_derivation)`` where
    ``score_derivation`` is ``"ai+rule"`` when the AI boost was actually applied
    (CRITICAL/HIGH + confidence > CONFIDENCE_BOOST_THRESHOLD) and ``"rule"`` otherwise.

    The ``detection_boost`` is the sum of correlation ``Detection.score_delta``
    values, capped at +30 to prevent runaway escalation from rule cascades.
    AI is additive-only (ARCHITECTURE invariant 3 / ADR-0003).

    ``score_derivation`` is computed here — at the point of authorship — never
    inferred downstream from ``ai_status`` or other heuristics (ADR-0035 §1).
    """
    score = rule_score + min(max(detection_boost, 0), 30)
    boost = _ai_boost(ai_result)
    score += boost
    score = min(score, 100)

    # Derivation: "ai+rule" only when a non-zero boost was actually applied.
    score_derivation = "ai+rule" if boost > 0 else "rule"

    if score >= 76:
        level = "CRITICAL"
    elif score >= 51:
        level = "HIGH"
    elif score >= 26:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level, score_derivation


def build_score_breakdown(
    events: list[SecurityEvent],
    ai_result: dict[str, Any] | None = None,
    detection_boost: int = 0,
) -> list[ScoreBreakdownItem]:
    """Compute the additive score breakdown for *events* (ADR-0036 D4, issue #209).

    Returns a list of ``ScoreBreakdownItem`` whose ``points`` values sum to the
    final score produced by ``merge_score(run_rules(events)[0], ai_result,
    detection_boost)``.  All scoring constants come from this module — no literals
    are duplicated.

    Factors (in order):
      brute_force      +30  when ≥ 10 blocked events
      port_scan        +25  when ≥ 5 distinct destination ports
      sql_injection    +40×w  when any payload matches SQL patterns (w = loudest
                              disposition weight: ALLOW 1.0 / ALERT·LOG 0.75 / BLOCK 0.5)
      xss              +35×w  when any payload matches XSS patterns (same weighting)
      persistence      +10   when ≥ 3 blocked/dropped events (Tier-3 floor, not per-event)
      detection_boost  +B   capped correlation boost (cap +30)
      ai_boost         +20/+10  when CRITICAL/HIGH AI result with conf > CONFIDENCE_BOOST_THRESHOLD
      cap              negative adjustment when raw sum exceeded 100

    The function is pure (no I/O, no side-effects).  It intentionally mirrors
    the logic in ``run_rules`` and ``merge_score`` rather than calling them so
    that it can inspect each intermediate value for the breakdown without
    altering any existing return contract.
    """
    blocked = [e for e in events if e.action in ("BLOCK", "DROP")]
    items: list[ScoreBreakdownItem] = []
    raw = 0

    # ── Rule factors ──────────────────────────────────────────────────────────

    if len(blocked) >= 10:
        items.append(ScoreBreakdownItem(
            factor="brute_force",
            label=f"Brute force — {len(blocked)} blocked events",
            points=30,
        ))
        raw += 30

    dest_ports = {e.destination_port for e in events}
    if len(dest_ports) >= 5:
        items.append(ScoreBreakdownItem(
            factor="port_scan",
            label=f"Port scan — {len(dest_ports)} distinct destination ports",
            points=25,
        ))
        raw += 25

    # SQLi/XSS scanned across ALL events, disposition-weighted (issue #651 R1/R2) —
    # mirrors run_rules so the breakdown still sums to the final score.
    sqli_events = [
        e for e in events if e.payload_snippet and _matches_any(e.payload_snippet, SQL_PATTERNS)
    ]
    if sqli_events:
        weight = _loudest_weight(sqli_events)
        pts = round(_SQLI_BASE * weight)
        items.append(ScoreBreakdownItem(
            factor="sql_injection",
            label=f"SQL injection payload detected (disposition weight ×{weight:g})",
            points=pts,
        ))
        raw += pts

    xss_events = [
        e for e in events if e.payload_snippet and _matches_any(e.payload_snippet, XSS_PATTERNS)
    ]
    if xss_events:
        weight = _loudest_weight(xss_events)
        pts = round(_XSS_BASE * weight)
        items.append(ScoreBreakdownItem(
            factor="xss",
            label=f"XSS payload detected (disposition weight ×{weight:g})",
            points=pts,
        ))
        raw += pts

    # Persistence floor (issue #651 R3) — replaces the flat +1 per blocked event.
    n_blocked = len(blocked)
    if n_blocked >= _PERSISTENCE_THRESHOLD:
        items.append(ScoreBreakdownItem(
            factor="persistence",
            label=f"Persistent blocked traffic — {n_blocked} blocked events",
            points=_PERSISTENCE_FLOOR,
        ))
        raw += _PERSISTENCE_FLOOR

    # ── Detection (correlation) boost — capped at +30 ────────────────────────

    effective_detection = min(max(detection_boost, 0), 30)
    if effective_detection > 0:
        items.append(ScoreBreakdownItem(
            factor="detection_boost",
            label=f"Correlation detection boost (+{effective_detection})",
            points=effective_detection,
        ))
        raw += effective_detection

    # ── AI boost ──────────────────────────────────────────────────────────────

    boost = _ai_boost(ai_result)
    if boost > 0 and ai_result is not None:
        ai_level_str = str(ai_result.get("threat_level", "")).upper()
        items.append(ScoreBreakdownItem(
            factor="ai_boost",
            label=f"AI boost — high-confidence {ai_level_str} threat (+{boost})",
            points=boost,
        ))
        raw += boost

    # ── Cap ───────────────────────────────────────────────────────────────────

    if raw > 100:
        reduction = raw - 100
        items.append(ScoreBreakdownItem(
            factor="cap",
            label=f"Score capped at 100 (raw {raw}, reduced by {reduction})",
            points=-(reduction),
        ))

    return items
