"""IP narration builder — ML-7 (issue #435).

Builds a SHORT, grounded narrative prompt from a REAL detail payload.
Anti-fabrication: every clause is gated on the actual presence of the field
in the payload.  Fields that are NULL / absent / empty are NOT mentioned —
the model cannot fabricate dimensions that were not collected.

Design principles (EARS-3 / ADR-0035):
- Each sentence in the prompt lists ONLY the fields that are non-null.
- The model is instructed to derive narration ONLY from the listed fields.
- A ``collected_fields`` list is injected so the model knows what it was
  actually given — if a field is not in that list, it MUST NOT mention it.
- Dimensions never collected by FireWatch (bytes_in, bytes_out, DNS queries,
  JA4 fingerprint when null) are withheld entirely from the prompt.

Security (NB-1, OWASP LLM01 / ADR-0015):
- Attacker-controlled strings (rule IDs, geo city/country, AS name, attack
  type labels) are wrapped in <untrusted_data> sentinels.
- Score factors are trusted numeric outputs from the rule engine — no sentinel.
- The model's output must be SHORT (≤ 120 words) and advisory (ADR-0015 §Tier-0).

ai-engine-invariants boundary:
- This module builds a PROMPT string only.
- No LLM call, no scoring, no threshold logic.
- The caller (pipeline.narrate_ip) passes the prompt to the existing
  AI engine via ``analyze_concise`` / the narration adapter.
- We re-use the existing ``/threats/{ip}/detailed`` + ``score_breakdown``
  data; no new scoring path is created.
"""
from __future__ import annotations

from typing import Any

from firewatch_core.ai.prompts import SENTINEL_CLOSE, SENTINEL_OPEN, _escape_sentinels

# ---------------------------------------------------------------------------
# Sentinel helper
# ---------------------------------------------------------------------------

_MAX_FIELD_LEN = 80  # hard cap for attacker-controlled string fields


def _wrap(text: str, max_len: int = _MAX_FIELD_LEN) -> str:
    """Truncate *text* to *max_len*, escape sentinels, wrap in delimiters."""
    truncated = str(text)[:max_len]
    escaped = _escape_sentinels(truncated)
    return f"{SENTINEL_OPEN}{escaped}{SENTINEL_CLOSE}"


# ---------------------------------------------------------------------------
# Field extraction helpers
# ---------------------------------------------------------------------------


def _extract_geo(detail: dict[str, Any]) -> str | None:
    """Return geo string only when non-empty (e.g. ``'Chicago, United States'``)."""
    loc = detail.get("location") or None
    return str(loc).strip() if loc else None


def _extract_asn(detail: dict[str, Any]) -> str | None:
    """Return AS descriptor only when at least one ASN field is non-null."""
    asn = detail.get("asn")
    as_name = detail.get("as_name") or None
    if asn is not None or as_name:
        parts = []
        if asn is not None:
            parts.append(f"AS{asn}")
        if as_name:
            parts.append(str(as_name).strip())
        return " ".join(parts) if parts else None
    return None


def _extract_score_factors(detail: dict[str, Any]) -> list[str]:
    """Return human-readable rule-factor labels from score_breakdown.

    score_breakdown is engine output (trusted), not attacker-controlled.
    We emit the label strings without sentinel wrapping.
    """
    breakdown = detail.get("score_breakdown") or []
    labels: list[str] = []
    for item in breakdown:
        if isinstance(item, dict):
            label = item.get("label") or ""
            factor = item.get("factor") or ""
            points = item.get("points", 0)
            # Skip the 'cap' pseudo-factor (negative adjustment, not a signal)
            if factor == "cap" or points == 0:
                continue
            if label:
                labels.append(f"{label} (+{points})")
    return labels


def _extract_attack_types(detail: dict[str, Any]) -> list[str]:
    """Return attack type strings — attacker-influenced labels wrapped in sentinels."""
    types_ = detail.get("attack_types") or []
    return [_wrap(t) for t in types_ if t]


def _extract_mitre(detail: dict[str, Any]) -> list[str]:
    """Return MITRE ATT&CK technique IDs when present."""
    # MITRE technique IDs are structured (T1234) and rule-engine derived.
    # They may also come from AI fields — wrap as sentinel for safety.
    mitre_raw = detail.get("mitre_techniques") or []
    return [_wrap(m) for m in mitre_raw if m]


def _build_collected_list(
    has_geo: bool,
    has_asn: bool,
    has_attack_types: bool,
    has_score_factors: bool,
    has_mitre: bool,
    has_ai_fields: bool,
) -> list[str]:
    """Enumerate what was actually collected so the model knows its scope."""
    fields: list[str] = [
        "source_ip",
        "threat_level",
        "score (0-100)",
        "total_events",
        "blocked_events",
        "first_seen",
        "last_seen",
        "action (per event)",
    ]
    if has_geo:
        fields.append("geo location")
    if has_asn:
        fields.append("ASN / AS name")
    if has_attack_types:
        fields.append("attack_types (rule-detected categories)")
    if has_score_factors:
        fields.append("score_breakdown (rule factors)")
    if has_mitre:
        fields.append("MITRE ATT&CK technique IDs")
    if has_ai_fields:
        fields.append("AI intent / executive_summary (from prior deep analysis)")
    return fields


# ---------------------------------------------------------------------------
# Prompt constants
# ---------------------------------------------------------------------------

_NARRATION_PREAMBLE = """\
You are a concise SOC analyst assistant. Write a SHORT narrative (≤ 120 words) that
explains what this IP is doing and what the analyst should consider next.

CRITICAL RULES:
1. Ground EVERY claim in the "Collected data" list below. Do NOT invent or infer fields
   not listed (no bytes, no DNS queries, no JA4 fingerprints unless explicitly listed).
2. Be honest about missing context: if a field is absent, say nothing about it.
3. End with ONE advisory "What to check next" sentence (no execution, no SOAR actions).
4. Output ONLY the narrative text — no JSON, no headers, no bullet lists.
5. Maximum 120 words. Shorter is better.
"""

_NARRATION_SCHEMA_INSTRUCTION = """
Return the narrative as a plain paragraph (≤ 120 words), then on a NEW LINE output:
PROVENANCE: <comma-separated list of actual field names you used, from the Collected data list>

Example:
The IP 192.0.2.1 triggered brute-force rules (+30 pts) with 95 of 120 events blocked...
What to check next: Review the triggered rules in the Evidence section.
PROVENANCE: source_ip, score_breakdown, blocked_events, threat_level
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_narration_prompt(ip: str, detail: dict[str, Any]) -> str:
    """Build the narration prompt for *ip* from the *detail* payload.

    Parameters
    ----------
    ip:
        The source IP address (display value, also present in *detail* as source_ip).
    detail:
        The dict returned by ``pipeline.analyze_ip_detailed`` — must contain at
        minimum ``score``, ``threat_level``, ``score_breakdown``, ``total_events``,
        ``blocked_events``.  All other fields are optional; absent fields are
        silently omitted (anti-fabrication).

    Returns
    -------
    str
        A ready-to-send prompt string.  No network call; caller passes to LLM.

    Anti-fabrication (EARS-3):
        - Each field is gated: only included when non-null/non-empty.
        - ``collected_fields`` is written into the prompt so the model knows
          exactly what was provided.
        - Attacker-controlled strings (geo, ASN name, attack types) are wrapped
          in <untrusted_data> sentinels (NB-1 / OWASP LLM01).
    """
    score = detail.get("score", 0)
    threat_level = detail.get("threat_level", "UNKNOWN")
    total_events = detail.get("total_events", 0)
    blocked_events = detail.get("blocked_events", 0)
    first_seen = detail.get("first_seen") or "unknown"
    last_seen = detail.get("last_seen") or "unknown"
    score_derivation = detail.get("score_derivation", "rule")

    # Optional enriched fields — anti-fabrication: gated on non-null.
    geo = _extract_geo(detail)
    asn_str = _extract_asn(detail)
    attack_types = _extract_attack_types(detail)
    score_factors = _extract_score_factors(detail)
    mitre_techniques = _extract_mitre(detail)

    # AI-derived fields from a prior deep analysis (if present in detail).
    # Only included when the AI actually ran (ai_status not unavailable/skipped).
    ai_status = detail.get("ai_status", "unavailable")
    ai_ran = ai_status not in ("unavailable", "skipped", "disabled")
    executive_summary = detail.get("executive_summary") if ai_ran else None
    ai_intent = detail.get("intent") if ai_ran else None
    has_ai_fields = bool(executive_summary or ai_intent)

    # Build the collected-fields list for the model.
    collected = _build_collected_list(
        has_geo=bool(geo),
        has_asn=bool(asn_str),
        has_attack_types=bool(attack_types),
        has_score_factors=bool(score_factors),
        has_mitre=bool(mitre_techniques),
        has_ai_fields=has_ai_fields,
    )

    # ── Assemble the data section ────────────────────────────────────────────

    lines: list[str] = [
        _NARRATION_PREAMBLE,
        "",
        "## Collected data",
        f"(Fields available: {', '.join(collected)})",
        "",
        f"- Source IP: {ip}",
        f"- Threat level: {threat_level}  |  Score: {score}/100  |  Derivation: {score_derivation}",
        f"- Events: {total_events} total, {blocked_events} blocked",
        f"- Active window: {first_seen} → {last_seen}",
    ]

    if geo:
        lines.append(f"- Geo location: {_wrap(geo)}")

    if asn_str:
        lines.append(f"- Network: {_wrap(asn_str)}")

    if score_factors:
        lines.append("- Rule factors (why the score is what it is):")
        for factor in score_factors:
            lines.append(f"    • {factor}")

    if attack_types:
        lines.append("- Attack categories (rule-detected):")
        for atype in attack_types:
            lines.append(f"    • {atype}")

    if mitre_techniques:
        lines.append("- MITRE ATT&CK techniques (if rule-mapped):")
        for t in mitre_techniques:
            lines.append(f"    • {t}")

    if has_ai_fields:
        lines.append("- AI analysis (from prior deep analysis run):")
        if executive_summary:
            lines.append(f"    Executive summary: {_wrap(str(executive_summary), 300)}")
        if ai_intent:
            lines.append(f"    Inferred intent: {_wrap(str(ai_intent), 200)}")

    lines.append("")
    lines.append(_NARRATION_SCHEMA_INSTRUCTION)

    return "\n".join(lines)


def build_rule_only_narration(ip: str, detail: dict[str, Any]) -> dict[str, Any]:
    """Build a rule-only fallback narration when the AI engine is unavailable.

    Returns the same shape as the narration API response but with
    ``provenance="rule"`` and text derived deterministically from the
    score_breakdown + real fields.

    This is the EARS-4 degrade path (AI unavailable → rule-only summary).
    No LLM is called; the function is synchronous and pure.

    Parameters
    ----------
    ip:
        Source IP address.
    detail:
        Dict from ``pipeline.analyze_ip_detailed``.

    Returns
    -------
    dict with keys:
        narrative      — rule-only advisory text (no AI).
        provenance     — always "rule".
        collected_fields — list of field names used.
        ai_status      — "unavailable" (or the actual status from detail).
    """
    score = detail.get("score", 0)
    threat_level = detail.get("threat_level", "UNKNOWN")
    total_events = detail.get("total_events", 0)
    blocked_events = detail.get("blocked_events", 0)
    first_seen = detail.get("first_seen") or "unknown"
    last_seen = detail.get("last_seen") or "unknown"

    geo = _extract_geo(detail)
    asn_str = _extract_asn(detail)
    score_factors = _extract_score_factors(detail)
    attack_types_raw = detail.get("attack_types") or []

    # Build collected fields (non-NULL only).
    collected: list[str] = ["source_ip", "threat_level", "score", "total_events",
                             "blocked_events", "first_seen", "last_seen"]
    if geo:
        collected.append("geo location")
    if asn_str:
        collected.append("ASN / AS name")
    if score_factors:
        collected.append("score_breakdown")
    if attack_types_raw:
        collected.append("attack_types")

    # Build the rule-only narrative text.
    parts: list[str] = [
        f"IP {ip} received threat level {threat_level} (score {score}/100).",
        f"{total_events} events observed ({blocked_events} blocked)"
        + (f" from {first_seen} to {last_seen}." if first_seen != "unknown" else "."),
    ]

    if score_factors:
        factor_text = "; ".join(
            f.split(" (+")[0]  # label only, no points suffix
            for f in score_factors[:3]
        )
        parts.append(f"Rule signals: {factor_text}.")

    if attack_types_raw:
        cats = ", ".join(str(a) for a in attack_types_raw[:3])
        parts.append(f"Detected categories: {cats}.")

    if geo:
        parts.append(f"Origin: {geo}.")

    parts.append(
        "What to check next: Review the score breakdown and evidence chain "
        "in the panel for rule-by-rule detail."
    )

    return {
        "narrative": " ".join(parts),
        "provenance": "rule",
        "collected_fields": collected,
        "ai_status": detail.get("ai_status", "unavailable"),
    }


# ---------------------------------------------------------------------------
# ASN narration (issue #533, A2 — EARS-5)
# ---------------------------------------------------------------------------

_ASN_NARRATION_PREAMBLE = """\
You are a concise SOC analyst assistant. Write a SHORT narrative (≤ 120 words) that
explains what this Autonomous System is doing in the analyst's network and what to
consider operationally.

CRITICAL RULES:
1. Ground EVERY claim in the "Collected data" list below. Do NOT invent or infer fields
   not listed (no actor attribution, no threat-intel lookups).
2. Be honest about missing context: if a field is absent, say nothing about it.
3. End with ONE advisory "What to check next" sentence (no SOAR/block actions).
4. Output ONLY the narrative text — no JSON, no headers, no bullet lists.
5. Maximum 120 words. Shorter is better.
"""

_ASN_NARRATION_SCHEMA_INSTRUCTION = """
Return the narrative as a plain paragraph (≤ 120 words), then on a NEW LINE output:
PROVENANCE: <comma-separated list of actual field names you used, from the Collected data list>

Example:
AS4837 (China Unicom) contributed 412 events across 18 IPs, with 60% blocked...
What to check next: Review the individual IPs in the Network Logs ASN filter.
PROVENANCE: asn, as_name, total_events, distinct_ips, blocked_pct
"""


def build_asn_narration_prompt(asn_row: dict[str, Any]) -> str:
    """Build a narration prompt for an ASN from its aggregated analytics row.

    Parameters
    ----------
    asn_row:
        A dict with keys: ``asn``, ``as_name``, ``total_events``, ``distinct_ips``,
        ``blocked``, ``blocked_pct``.  Matches the shape returned by
        ``get_analytics_asn()``.

    Returns
    -------
    str
        Ready-to-send prompt string.  No network call; caller passes to LLM.

    Anti-fabrication (EARS-5 / ADR-0035):
        Only collected fields are injected.  ``as_name`` is attacker-influenced
        (an ASN org name could be crafted) — wrapped in <untrusted_data> sentinels
        (NB-1 / OWASP LLM01).
    """
    asn: int | None = asn_row.get("asn")
    as_name_raw: str | None = asn_row.get("as_name") or None
    total_events: int = int(asn_row.get("total_events", 0))
    distinct_ips: int = int(asn_row.get("distinct_ips", 0))
    blocked: int = int(asn_row.get("blocked", 0))
    blocked_pct: float = float(asn_row.get("blocked_pct", 0.0))

    asn_label = f"AS{asn}" if asn is not None else "Unknown ASN"
    as_name_wrapped = _wrap(as_name_raw) if as_name_raw else None

    collected: list[str] = ["asn", "total_events", "distinct_ips", "blocked", "blocked_pct"]
    if as_name_raw:
        collected.append("as_name")

    lines: list[str] = [
        _ASN_NARRATION_PREAMBLE,
        "",
        "## Collected data",
        f"(Fields available: {', '.join(collected)})",
        "",
        f"- Autonomous System: {asn_label}"
        + (f" ({as_name_wrapped})" if as_name_wrapped else ""),
        f"- Total events: {total_events}",
        f"- Distinct source IPs: {distinct_ips}",
        f"- Blocked events: {blocked} ({blocked_pct}%)",
        "",
        _ASN_NARRATION_SCHEMA_INSTRUCTION,
    ]
    return "\n".join(lines)


def build_rule_only_asn_narration(asn_row: dict[str, Any]) -> dict[str, Any]:
    """Build a deterministic rule-only ASN narration (EARS-5 degrade, ADR-0015).

    Called when the LLM is unavailable.  No AI involved; pure Python.

    Returns
    -------
    dict with keys:
        narrative        — deterministic rule-based text
        provenance       — always "rule"
        collected_fields — fields used
        ai_status        — "unavailable"
    """
    asn: int | None = asn_row.get("asn")
    as_name_raw: str | None = asn_row.get("as_name") or None
    total_events: int = int(asn_row.get("total_events", 0))
    distinct_ips: int = int(asn_row.get("distinct_ips", 0))
    blocked: int = int(asn_row.get("blocked", 0))
    blocked_pct: float = float(asn_row.get("blocked_pct", 0.0))

    asn_label = f"AS{asn}" if asn is not None else "Unknown ASN"
    name_part = f" ({as_name_raw})" if as_name_raw else ""

    collected: list[str] = ["asn", "total_events", "distinct_ips", "blocked", "blocked_pct"]
    if as_name_raw:
        collected.append("as_name")

    parts: list[str] = [
        f"{asn_label}{name_part} generated {total_events} event{'' if total_events == 1 else 's'}"
        f" from {distinct_ips} distinct IP{'' if distinct_ips == 1 else 's'}.",
        f"{blocked} event{'' if blocked == 1 else 's'} ({blocked_pct}%) were blocked.",
        "What to check next: Filter Network Logs by this ASN to review individual IPs.",
    ]

    return {
        "narrative": " ".join(parts),
        "provenance": "rule",
        "collected_fields": collected,
        "ai_status": "unavailable",
    }
