"""AI prompt templates — concise and detailed per-IP analysis.

Ported from ``legacy/adapters/ai/prompts/{concise,detailed}.py`` with NB-1
hardening: every attacker-supplied sample payload is wrapped in an unambiguous
untrusted-data sentinel so the LLM cannot be confused by embedded prompt text.

NB-1 (OWASP LLM01 / ADR-0015)
------------------------------
Each sampled ``payload`` is attacker-controlled.  The v1 implementation
interpolated it directly into the prompt string (concise.py:108), allowing an
adversary to embed the closing sentinel and inject arbitrary instructions.

This module wraps each payload in::

    <untrusted_data>…payload…</untrusted_data>

Rules:

* The delimiter wraps the payload string ONLY (concise) or BOTH the payload
  AND the ``description`` field (detailed).
* **Issue #642 — sensor-observed strings are untrusted (security hardening):**
  ``rule_id``, ``category`` (both concise and detailed), and the correlation
  fields ``rule_name`` and ``reason`` are sensor-observed values that can be
  attacker-influenced (e.g. CEF SignatureID / CategoryName).  As of #642 these
  are wrapped via ``_wrap_payload`` with ``_RULE_FIELD_MAX`` / ``_REASON_MAX``
  limits.  Only ``count``, ``score_delta``, ``first_triggered``, and
  ``last_triggered`` remain bare — they are trusted engine numerics/timestamps.
* For the detailed path, the ``description`` field (populated from the rule
  descriptions store, which is derived from vendor rule-sets) is also treated
  as potentially attacker-influenced and is wrapped identically to payloads.
  This is the parked #16 NB-1 security requirement, landed with issue #19.
* Before wrapping, both ``SENTINEL_OPEN`` and ``SENTINEL_CLOSE`` occurrences
  inside the raw string are replaced with a visually distinct but structurally
  inert escape (the sentinel tag name with a leading ``!``).  This prevents a
  crafted value from opening or closing a spurious delimiter boundary.
* Truncation (100 chars concise / 300 chars detailed) is applied BEFORE
  wrapping so the sentinel boundaries always have well-defined content.

Closed output JSON contract (used by #7's validator)
----------------------------------------------------
Both prompts instruct the model to return a JSON object with these fields:

Concise::

    {
      "threat_level": "CRITICAL|HIGH|MEDIUM|LOW",
      "confidence": 0.0–1.0,
      "intent": str,
      "attack_stage": "reconnaissance|exploitation|brute_force|data_exfiltration|automated_scanning",
      "insights": [str, ...],
      "recommended_action": "block|investigate|monitor|ignore"
    }

Detailed adds::

    {
      "executive_summary": str,
      "attack_progression": [str, ...],
      "insights": {"patterns": [...], "risks": [...], "mitigations": [...]},
      "ioc_indicators": [str, ...],
      "false_positive_likelihood": 0.0–1.0
    }
"""
from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# NB-1 sentinel constants
# ---------------------------------------------------------------------------

SENTINEL_OPEN: str = "<untrusted_data>"
SENTINEL_CLOSE: str = "</untrusted_data>"

# Escape substitutes — replace sentinel tags found inside a payload with these
# inert variants so they cannot close or open delimiter boundaries.
_ESCAPE_OPEN: str = "<!untrusted_data>"
_ESCAPE_CLOSE: str = "</!untrusted_data>"

# Truncation limits (ai-engine-invariants skill)
_CONCISE_MAX_PAYLOAD: int = 100
_DETAILED_MAX_PAYLOAD: int = 300

# Issue #642: per-field limits for sensor-observed strings.
# rule_id / category / correlation rule_name — matches CEF plugin's _RULE_ID_MAX.
_RULE_FIELD_MAX: int = 64
# correlation reason — free-text, generous but bounded.
_REASON_MAX: int = 200


# ---------------------------------------------------------------------------
# Prompt templates (byte-compatible with v1 for security_mode=False + no correlations)
# ---------------------------------------------------------------------------

IP_SUMMARY_PROMPT = """You are a SOC (Security Operations Center) analyst AI assistant.
Analyze this threat actor based on WAF (Web Application Firewall) log data.
Be concise. Keep each insight under 30 words.

## Threat Actor Profile
- **IP Address:** {ip}
- **Total Events:** {total_events}
- **Blocked Events:** {blocked_events}
- **Block Rate:** {block_rate}%
- **Unique Rules Triggered:** {rules_triggered}
- **Activity Window:** {first_seen} to {last_seen}

## Attack Samples (top rules by frequency)
{samples}

## Your Task
Provide a threat assessment in JSON format only, no other text:
{{
  "threat_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": 0.0-1.0,
  "intent": "brief description of attacker's likely goal",
  "attack_stage": "reconnaissance|exploitation|brute_force|data_exfiltration|automated_scanning",
  "insights": [
    "pattern: <what attack pattern you observe>",
    "risk: <what is the real risk to the system>",
    "action: <specific next step for SOC analyst>"
  ],
  "recommended_action": "block|investigate|monitor|ignore"
}}"""

IP_SUMMARY_PROMPT_SECURITY = """You are a SOC (Security Operations Center) analyst AI assistant.
Analyze this threat actor based on security log data (WAF, IDS, and other sources).
Be concise. Keep each insight under 30 words.

## Threat Actor Profile
- **IP Address:** {ip}
- **Total Events:** {total_events}
- **Blocked Events:** {blocked_events}
- **Block Rate:** {block_rate}%
- **Unique Rules Triggered:** {rules_triggered}
- **Activity Window:** {first_seen} to {last_seen}

## Attack Samples (top rules by frequency)
{samples}

## Your Task
Provide a threat assessment in JSON format only, no other text:
{{
  "threat_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": 0.0-1.0,
  "intent": "brief description of attacker's likely goal",
  "attack_stage": "reconnaissance|exploitation|brute_force|data_exfiltration|automated_scanning",
  "insights": [
    "pattern: <what attack pattern you observe>",
    "risk: <what is the real risk to the system>",
    "action: <specific next step for SOC analyst>"
  ],
  "recommended_action": "block|investigate|monitor|ignore"
}}"""

IP_DETAILED_PROMPT = """You are a senior SOC (Security Operations Center) analyst.
Provide a thorough, detailed threat assessment based on WAF log data.

## Threat Actor Profile
- **IP Address:** {ip}
- **Total Events:** {total_events}
- **Blocked Events:** {blocked_events}
- **Block Rate:** {block_rate}%
- **Unique Rules Triggered:** {rules_triggered}
- **Activity Window:** {first_seen} to {last_seen}

## All Triggered Rules (with timestamps and descriptions)
{samples}

## Your Task
Provide a comprehensive threat assessment in JSON format only, no other text:
{{
  "threat_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": 0.0-1.0,
  "executive_summary": "2-3 sentence overview of the threat actor and their activity",
  "intent": "description of attacker's likely goal and motivation",
  "attack_stage": "reconnaissance|exploitation|brute_force|data_exfiltration|automated_scanning",
  "attack_progression": [
    "Step 1: description of initial activity",
    "Step 2: description of escalation",
    "Step 3: description of final activity"
  ],
  "insights": {{
    "patterns": [
      "detailed observation about attack patterns"
    ],
    "risks": [
      "specific risk to the system or data"
    ],
    "mitigations": [
      "specific remediation step or WAF rule recommendation"
    ]
  }},
  "ioc_indicators": [
    "indicator of compromise observed in the data"
  ],
  "recommended_action": "block|investigate|monitor|ignore",
  "false_positive_likelihood": 0.0-1.0
}}"""

IP_DETAILED_PROMPT_SECURITY = """You are a senior SOC (Security Operations Center) analyst.
Provide a thorough, detailed threat assessment based on security log data (WAF, IDS, and other sources).

## Threat Actor Profile
- **IP Address:** {ip}
- **Total Events:** {total_events}
- **Blocked Events:** {blocked_events}
- **Block Rate:** {block_rate}%
- **Unique Rules Triggered:** {rules_triggered}
- **Activity Window:** {first_seen} to {last_seen}

## All Triggered Rules (with timestamps and descriptions)
{samples}

## Your Task
Provide a comprehensive threat assessment in JSON format only, no other text:
{{
  "threat_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": 0.0-1.0,
  "executive_summary": "2-3 sentence overview of the threat actor and their activity",
  "intent": "description of attacker's likely goal and motivation",
  "attack_stage": "reconnaissance|exploitation|brute_force|data_exfiltration|automated_scanning",
  "attack_progression": [
    "Step 1: description of initial activity",
    "Step 2: description of escalation",
    "Step 3: description of final activity"
  ],
  "insights": {{
    "patterns": [
      "detailed observation about attack patterns"
    ],
    "risks": [
      "specific risk to the system or data"
    ],
    "mitigations": [
      "specific remediation step or WAF rule recommendation"
    ]
  }},
  "ioc_indicators": [
    "indicator of compromise observed in the data"
  ],
  "recommended_action": "block|investigate|monitor|ignore",
  "false_positive_likelihood": 0.0-1.0
}}"""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _escape_sentinels(text: str) -> str:
    """Replace any literal sentinel tags inside *text* with inert escapes.

    This prevents an attacker-controlled payload from opening or closing a
    spurious ``<untrusted_data>`` boundary.  The replacements are ordered
    carefully: close is replaced before open so that a payload containing both
    ``SENTINEL_OPEN + SENTINEL_CLOSE`` cannot reconstruct a valid sentinel pair
    after replacement.
    """
    text = text.replace(SENTINEL_CLOSE, _ESCAPE_CLOSE)
    text = text.replace(SENTINEL_OPEN, _ESCAPE_OPEN)
    return text


def _wrap_payload(raw: str, max_len: int) -> str:
    """Truncate *raw* to *max_len*, escape sentinels, then wrap in delimiters.

    Truncation happens before escaping so the escaping characters do not
    inadvertently push content past the limit.
    """
    truncated = raw[:max_len]
    escaped = _escape_sentinels(truncated)
    return f"{SENTINEL_OPEN}{escaped}{SENTINEL_CLOSE}"


# ---------------------------------------------------------------------------
# Public API — signatures match AIEngine protocol (ports.py:157-181)
# ---------------------------------------------------------------------------


def format_concise(
    ip: str,
    total_events: int,
    blocked_events: int,
    rules_triggered: int,
    first_seen: str,
    last_seen: str,
    samples: list[dict[str, Any]],
    security_mode: bool = False,
    correlations: list[Any] | None = None,
    dga_flags: list[dict[str, Any]] | None = None,
    tls_fingerprints: list[str] | None = None,
) -> str:
    """Build the concise per-IP prompt string.

    With ``security_mode=False`` and ``correlations`` empty/None this produces
    output byte-compatible with v1 AIClassifier.analyze_ip_summary for pure-Azure
    WAF data (M1 prompt parity), except that each sample payload is now wrapped
    in an untrusted-data sentinel (NB-1 hardening — no parity break because the
    legacy prompts were never pinned by the oracle harness before this issue).

    Parameters
    ----------
    ip:
        Source IP address being assessed.
    total_events:
        Total event count for the IP across the analysis window.
    blocked_events:
        Count of events where the WAF/IDS blocked the request.
    rules_triggered:
        Number of distinct rules that fired for this IP.
    first_seen:
        ISO-8601 timestamp of the earliest event.
    last_seen:
        ISO-8601 timestamp of the most recent event.
    samples:
        List of sample dicts, each with keys: ``rule_id``, ``category``,
        ``count``, ``payload``.  Built by ``scoring.build_samples``.
    security_mode:
        ``False`` (default) → WAF-worded template (pure-Azure parity).
        ``True`` → generalized "security log" template for mixed-source IPs.
    correlations:
        Optional list of Detection-like objects with attributes ``rule_name``,
        ``score_delta``, ``reason``.  Non-empty → appends Cross-source
        Correlations block.  Empty / None → block omitted.
    dga_flags:
        Optional list of DGA-suspect dicts from ``analytics.dga.score_domain``.
        Each has keys: ``dns_query`` (str, attacker-controlled),
        ``dga_score`` (float 0-1).  Non-empty → appends a
        "## Possible DGA Domains (heuristic, RULE provenance)" section.
        Provenance note is included so the LLM does not overstate confidence
        (glass-box honesty, ML-12 issue #440).
        ``dns_query`` values are wrapped in <untrusted_data> sentinel (NB-1).
        Empty / None → block omitted.
    tls_fingerprints:
        Optional list of unique JA4 TLS fingerprints observed for this IP
        (ML-13, issue #441 EARS-3). Consume-only — sourced directly from the
        sensor; never fabricated. Non-empty → appends a TLS Fingerprints block
        so the LLM can reason about tool/malware family identification.
        Each fingerprint is wrapped in the untrusted-data sentinel (NB-1).

    Returns
    -------
    str
        Ready-to-send prompt string (no network call; caller passes to LLM).
    """
    block_rate = round(blocked_events / total_events * 100, 1) if total_events > 0 else 0

    samples_text = ""
    for i, s in enumerate(samples, 1):
        # Issue #642: rule_id and category are sensor-observed and attacker-influenceable
        # (e.g. CEF SignatureID / CategoryName).  Wrap via _wrap_payload so no current or
        # future source can inject through them regardless of per-plugin sanitization.
        # count is a trusted engine numeric — left bare.
        wrapped_rule_id = _wrap_payload(str(s["rule_id"]), _RULE_FIELD_MAX)
        wrapped_category = _wrap_payload(str(s["category"]), _RULE_FIELD_MAX)
        wrapped = _wrap_payload(str(s["payload"]), _CONCISE_MAX_PAYLOAD)
        samples_text += (
            f"  {i}. Rule: {wrapped_rule_id} ({wrapped_category}) — "
            f"triggered {s['count']}x\n"
            f"     Sample payload: {wrapped}\n"
        )
    if not samples_text:
        samples_text = "  No payload samples available.\n"

    if correlations:
        samples_text += "\n## Cross-source Correlations\n"
        for d in correlations:
            # Issue #642: rule_name and reason are sensor-observed free-text — wrap them.
            # score_delta is a trusted engine numeric — left bare.
            wrapped_rule_name = _wrap_payload(str(d.rule_name), _RULE_FIELD_MAX)
            wrapped_reason = _wrap_payload(str(d.reason), _REASON_MAX)
            samples_text += (
                f"- {wrapped_rule_name} (boost +{d.score_delta}): {wrapped_reason}\n"
            )

    if dga_flags:
        samples_text += "\n## Possible DGA Domains (heuristic signal — RULE provenance, not AI)\n"
        samples_text += "These domains were flagged by local entropy/lexical analysis.\n"
        for flag in dga_flags:
            wrapped_domain = _wrap_payload(str(flag["dns_query"]), _CONCISE_MAX_PAYLOAD)
            samples_text += (
                f"- {wrapped_domain} "
                f"(dga_score={flag['dga_score']:.2f})\n"
            )

    # ML-13 (issue #441 EARS-3): append JA4 fingerprint context when the sensor
    # populated the field. Each fingerprint is sentinel-wrapped (NB-1 / OWASP LLM01)
    # because a crafted fingerprint string could embed prompt-injection text.
    if tls_fingerprints:
        samples_text += "\n## TLS Fingerprints (JA4+)\n"
        for fp in tls_fingerprints:
            wrapped_fp = _wrap_payload(fp, _CONCISE_MAX_PAYLOAD)
            samples_text += f"- {wrapped_fp}\n"

    template = IP_SUMMARY_PROMPT_SECURITY if security_mode else IP_SUMMARY_PROMPT
    return template.format(
        ip=ip,
        total_events=total_events,
        blocked_events=blocked_events,
        block_rate=block_rate,
        rules_triggered=rules_triggered,
        first_seen=first_seen,
        last_seen=last_seen,
        samples=samples_text,
    )


def format_detailed(
    ip: str,
    total_events: int,
    blocked_events: int,
    rules_triggered: int,
    first_seen: str,
    last_seen: str,
    samples: list[dict[str, Any]],
    security_mode: bool = False,
    correlations: list[Any] | None = None,
    dga_flags: list[dict[str, Any]] | None = None,
    tls_fingerprints: list[str] | None = None,
) -> str:
    """Build the detailed per-IP prompt string.

    With ``security_mode=False`` (default) this mirrors v1 behavior for
    pure-Azure IPs (M1 parity), with NB-1 hardening applied to payloads.
    With ``security_mode=True`` it uses the generalized security-log template
    for mixed-source IPs.

    Parameters
    ----------
    ip:
        Source IP address being assessed.
    total_events:
        Total event count for the IP across the analysis window.
    blocked_events:
        Count of events where the request was blocked.
    rules_triggered:
        Number of distinct rules that fired.
    first_seen:
        ISO-8601 timestamp of the earliest event.
    last_seen:
        ISO-8601 timestamp of the most recent event.
    samples:
        List of sample dicts, each with keys: ``rule_id``, ``category``,
        ``count``, ``payload``, and optionally ``description``,
        ``first_triggered``, ``last_triggered``.
    security_mode:
        ``False`` (default) → WAF-worded template.
        ``True`` → generalized "security log" template.
    correlations:
        Optional Detection-like objects.  Non-empty → appends Cross-source
        Correlations block.
    dga_flags:
        Optional list of DGA-suspect dicts (ML-12, issue #440).
        Non-empty → appends a DGA section with score and glass-box note.
        ``dns_query`` values are NB-1 sentinel-wrapped (attacker-controlled).
    tls_fingerprints:
        Optional list of unique JA4 TLS fingerprints observed for this IP
        (ML-13, issue #441 EARS-3). Consume-only — sourced from the sensor.
        Each fingerprint is sentinel-wrapped (NB-1 / OWASP LLM01).

    Returns
    -------
    str
        Ready-to-send prompt string (no network call).
    """
    block_rate = round(blocked_events / total_events * 100, 1) if total_events > 0 else 0

    samples_text = ""
    for i, s in enumerate(samples, 1):
        # Issue #642: rule_id and category are sensor-observed and attacker-influenceable.
        # count is a trusted engine numeric — left bare.
        wrapped_rule_id = _wrap_payload(str(s["rule_id"]), _RULE_FIELD_MAX)
        wrapped_category = _wrap_payload(str(s["category"]), _RULE_FIELD_MAX)
        samples_text += (
            f"  {i}. Rule: {wrapped_rule_id} ({wrapped_category}) — "
            f"triggered {s['count']}x\n"
        )
        if s.get("description"):
            # NB-1 (parked #16 security req, landed #19): description is treated as
            # attacker-influenced data and wrapped in the untrusted-data sentinel,
            # identically to how payloads are delimited.
            wrapped_desc = _wrap_payload(str(s["description"]), _DETAILED_MAX_PAYLOAD)
            samples_text += f"     Description: {wrapped_desc}\n"
        if s.get("first_triggered") and s.get("last_triggered"):
            # first_triggered / last_triggered are trusted engine timestamps — left bare.
            samples_text += (
                f"     Timeline: {s['first_triggered']} to {s['last_triggered']}\n"
            )
        wrapped = _wrap_payload(str(s["payload"]), _DETAILED_MAX_PAYLOAD)
        samples_text += f"     Sample payload: {wrapped}\n"

    if not samples_text:
        samples_text = "  No payload samples available.\n"

    if correlations:
        samples_text += "\n## Cross-source Correlations\n"
        for d in correlations:
            # Issue #642: rule_name and reason are sensor-observed free-text — wrap them.
            # score_delta is a trusted engine numeric — left bare.
            wrapped_rule_name = _wrap_payload(str(d.rule_name), _RULE_FIELD_MAX)
            wrapped_reason = _wrap_payload(str(d.reason), _REASON_MAX)
            samples_text += (
                f"- {wrapped_rule_name} (boost +{d.score_delta}): {wrapped_reason}\n"
            )

    if dga_flags:
        samples_text += "\n## Possible DGA Domains (heuristic signal — RULE provenance, not AI)\n"
        samples_text += "These domains were flagged by local entropy/lexical analysis.\n"
        for flag in dga_flags:
            wrapped_domain = _wrap_payload(str(flag["dns_query"]), _DETAILED_MAX_PAYLOAD)
            samples_text += (
                f"- {wrapped_domain} "
                f"(dga_score={flag['dga_score']:.2f})\n"
            )

    # ML-13 (issue #441 EARS-3): append JA4 fingerprint context when the sensor
    # populated the field. Each fingerprint is sentinel-wrapped (NB-1 / OWASP LLM01).
    if tls_fingerprints:
        samples_text += "\n## TLS Fingerprints (JA4+)\n"
        for fp in tls_fingerprints:
            wrapped_fp = _wrap_payload(fp, _DETAILED_MAX_PAYLOAD)
            samples_text += f"- {wrapped_fp}\n"

    template = IP_DETAILED_PROMPT_SECURITY if security_mode else IP_DETAILED_PROMPT
    return template.format(
        ip=ip,
        total_events=total_events,
        blocked_events=blocked_events,
        block_rate=block_rate,
        rules_triggered=rules_triggered,
        first_seen=first_seen,
        last_seen=last_seen,
        samples=samples_text,
    )
