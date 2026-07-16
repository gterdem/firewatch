---
name: canonical-schema
description: Rules for normalizing any telemetry source into the FireWatch SecurityEvent. Use whenever mapping vendor logs (Azure WAF, Suricata, Syslog, AWS, …) to the internal schema, or touching normalization logic.
---
# Canonical event normalization

`SecurityEvent` (in firewatch-sdk) is the single internal model. Its authoritative field
list lives in firewatch-sdk — confirm against it. This skill is the mapping *discipline*,
not the source of truth.

## Required fields every normalize() must set
- `source_ip`, `destination_port`, `protocol`
- `action` ∈ {BLOCK, ALLOW, DROP, ALERT, LOG} — IDS detection → ALERT, WAF/IPS block → BLOCK (ADR-0012); LOG = non-blocking informational (e.g. Syslog SSH-Login)
- `rule_id`, `rule_name`, `payload_snippet`
- `timestamp` (UTC ISO-8601), `severity` ∈ {info, low, medium, high, critical} (see Severity below), `category`
- `source_type` AND `source_id` (the named instance, e.g. "pi-home") (ADR-0016)
- `attack_technique` (T####), `attack_tactic` (TA####), `kill_chain_phase`, `capec_id` — where derivable (ADR-0014)

## Discipline
- Map vendor → SecurityEvent, never the reverse.
- Unmapped vendor fields stay in `RawEvent.data` — never add new top-level fields.
- `categorize_rule(rule_id)` maps rule-id prefixes → category (942→SQLi, 941→XSS, …); shared, lives in core/sdk. It is a **normalize-time (write-path) mapping helper only**.
- **`category` is assigned once at normalize-time and is the single source of truth.** API/UI category facets (e.g. `/logs/categories`, a `?category=` filter) MUST derive from the stored `SecurityEvent.category` value — never re-derive category from `rule_id` at read time. Read-time re-classification creates a parallel, divergent vocabulary (the #322/#325 bug class) and breaks OCSF alignment (ADR-0020: classification is assigned at producer mapping time; consumers query the stored attribute).

## Severity (ADR-0069 — semantics live in PLUGIN_CONTRACT.md "Severity semantics")
- Five levels, Sigma `level` vocabulary (FireWatch `info` = Sigma `informational`):
  **info · low · medium · high · critical**. `high`+ on an ALERT asserts the event belongs in
  the triage queue on its own (ADR-0067 D1(b)).
- **Distribution rule:** any event class that is ambient at volume on a healthy deployment maps
  to at most `medium` — by definition, not by tuning. Escalation of ambient classes belongs to
  the correlation rules and the band axis, never to the per-event map.
- **Translate the vendor's published scale; never re-score events.** Missing/unparseable vendor
  severity → `low` (fail quiet — never a gate-qualifying level).
- **Worked example — the Suricata/AWS NFW priority map (ADR-0069 D4(a), normative for both):**
  priority 1 → `high` · 2 → `medium` · 3 → `low` · 4 → `info` · missing/unparseable → `low`.
  Priority 2 is the ET SCAN / reputation-drop ambient mass — the distribution rule is why it
  caps at `medium`.

## MITRE/CAPEC sources (ADR-0014) — extract at normalize-time, no new deps
- Suricata ET Open: alert metadata carries `mitre_technique_id` / `mitre_technique_name`.
- Azure WAF (OWASP CRS): rules carry CAPEC tags.
- Terminology: ATT&CK v18 (Oct 2025) renamed "Data Sources" → "Log Sources"; use the current term.

## OCSF alignment (ADR-0020) — lightweight, at normalize-time
- Formalize the existing `ocsf_class`/`ocsf_category` as OCSF `class_uid`/`category_uid`.
- Map at normalize-time where it lines up: `action` → OCSF `disposition_id`/`activity_id`,
  `severity` → `severity_id`, `category` → OCSF class.
- Lightweight alignment only — do NOT restructure `SecurityEvent` into nested OCSF objects.
  Full conformance is deferred; an OCSF view lives at the API/export boundary, not the internal model.
- ECS framing for source identity (`source_type`≈`event.module`, `source_id`≈`observer.name`)
  stays — it's complementary to OCSF, not in conflict.

## Examples
- **Azure WAF**: AzureDiagnostics / AGWFirewallLogs rows → SecurityEvent.
- **Suricata EVE**: `alert.signature`→rule_name, `alert.signature_id`→rule_id, `alert.severity` (priority 1..4) → severity per the ADR-0069 D4(a) map above, `alert.action`→ALERT/BLOCK, `http.url`+`hostname`→payload_snippet.
- **Syslog**: RFC 3164 / 5424 → SecurityEvent.
