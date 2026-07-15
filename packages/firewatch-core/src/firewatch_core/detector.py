"""Cross-source correlation engine.

Pure functions, no I/O. Each rule operates on a per-IP event list and returns zero or
more ``Detection`` records. ``detect()`` is called from ``Pipeline.analyze_ip`` after rule
scoring and before AI analysis. Detections boost the threat score and provide cross-source
context to the AI prompt; they are computed on-demand and not persisted (M4 scope).

Ported from ``legacy/core/detector.py`` with the ECS rename ``source_module`` →
``source_type`` (ADR-0016 / Flag B): cross-source correlation keys on the telemetry type.
Thresholds are verbatim.

ADR-0058 §D1 (issue #647) — each rule registers its declared severity and ``auto_escalate``
policy in ``ESCALATION_POLICY`` at module import time.  The registry is populated here (rule
author declares alongside the rule) and consumed by ``detect()`` when it attaches metadata
to each ``Detection`` it emits.  Score math is unchanged — this is additive metadata only.

Severity anchoring (Sigma ``level`` vocabulary):
- ``brute_force_then_login`` — ``critical`` / auto_escalate=True: credential compromise,
  confirmed successful login after brute-force (Sigma T1110/TA0006; Elastic risk_score≈91).
- ``ids_then_brute_force``  — ``high``     / auto_escalate=True: IDS-corroborated SSH
  attack; cross-source correlation raises signal fidelity (Sigma T1110; risk_score≈74).
- ``multi_source_attack``   — ``medium``   / auto_escalate=False: multi-source diversity
  increases suspicion but lacks a confirmed outcome (risk_score≈48).
- ``sustained_attack``      — ``medium``   / auto_escalate=False: persistence is notable
  but the defence held; not yet a confirmed breach (risk_score≈48).
- ``ssh_login_failure_burst`` — ``high`` / auto_escalate=False (issue #3, ADR-0069 D4(e) /
  ADR-0067 D1a): a pure burst of ``action=ALERT``, ``severity=low`` "SSH Login Failure" auth
  telemetry from one IP, with no successful login and no cross-source corroboration. `low`
  never qualifies the ADR-0067 D1(b) severity gate at ANY volume (ADR-0069 D1's ambient-mass
  corollary + issue #3's Must-NOT criterion); none of the four rules above fire on this shape
  either (``brute_force_then_login`` additionally requires a subsequent success;
  ``ids_then_brute_force`` additionally requires a Suricata IDS event; ``sustained_attack``
  counts BLOCK/DROP only) — so a pure host-level SSH brute force needs this rule to become a
  qualifying assertion at all (Sigma T1110; risk_score≈65, below the confirmed-compromise
  ``brute_force_then_login`` case).

Skill gate: ai-engine-invariants loaded before editing this file.
"""
import logging
from collections.abc import Callable
from datetime import timedelta

from firewatch_sdk import Detection, SecurityEvent
from firewatch_core.escalation.policy import ESCALATION_POLICY

CorrelationRule = Callable[[list[SecurityEvent]], list[Detection]]

logger = logging.getLogger("firewatch.detector")

# ── Per-rule severity declarations (ADR-0058 §D1) ────────────────────────────
# Registered once at module import; consumed by _emit() below.
# Anchored to Sigma `level` vocabulary (informational/low/medium/high/critical):
#   https://sigmahq.io/docs/basics/rules.html
# Elastic risk_score analogues:
#   https://www.elastic.co/guide/en/security/current/rules-ui-create.html

ESCALATION_POLICY.register(
    "brute_force_then_login",
    severity="critical",
    auto_escalate=True,
)
ESCALATION_POLICY.register(
    "ids_then_brute_force",
    severity="high",
    auto_escalate=True,
)
ESCALATION_POLICY.register(
    "multi_source_attack",
    severity="medium",
    auto_escalate=False,
)
ESCALATION_POLICY.register(
    "sustained_attack",
    severity="medium",
    auto_escalate=False,
)
ESCALATION_POLICY.register(
    "ssh_login_failure_burst",
    severity="high",
    auto_escalate=False,
)
# N-2 (issue #648): lock the registry once module-import-time registrations are
# done. Any later register() (e.g. a stray plugin import) now raises, so a rule's
# declared severity / auto_escalate cannot be silently downgraded post-startup.
ESCALATION_POLICY.finalize()


def _emit(
    source_ip: str,
    rule_name: str,
    score_delta: int,
    reason: str,
    matched_event_ids: list[str],
) -> Detection:
    """Construct a Detection with declared severity metadata from the policy registry.

    Looks up the registered ``RulePolicy`` for ``rule_name`` in ``ESCALATION_POLICY``
    and attaches its ``severity`` and ``auto_escalate`` fields to the emitted
    ``Detection``.  Unregistered rules default to ``severity=None, auto_escalate=False``
    (EARS-2 — zero behaviour change for any future rule that omits registration).

    Score math is NOT touched here: ``score_delta`` is passed through verbatim.
    """
    policy = ESCALATION_POLICY.get_or_default(rule_name)
    return Detection(
        source_ip=source_ip,
        rule_name=rule_name,
        score_delta=score_delta,
        reason=reason,
        matched_event_ids=matched_event_ids,
        severity=policy.severity,
        auto_escalate=policy.auto_escalate,
    )


# ── Rule helpers ─────────────────────────────────────────────────────


def _ids_then_brute_force(events: list[SecurityEvent]) -> list[Detection]:
    """≥1 Suricata IDS event coincides with ≥3 syslog SSH brute-force
    events from the same IP within a 10-minute window.
    """
    if not events:
        return []
    suricata = [e for e in events if e.source_type == "suricata"]
    ssh_bf = [
        e for e in events
        if e.source_type == "syslog" and e.category == "SSH Brute Force"
    ]
    if not suricata or len(ssh_bf) < 3:
        return []

    window = timedelta(minutes=10)
    for s in suricata:
        nearby = [e for e in ssh_bf if abs(e.timestamp - s.timestamp) <= window]
        if len(nearby) >= 3:
            ids = [e.event_id for e in (nearby + [s]) if e.event_id]
            return [_emit(
                source_ip=events[0].source_ip,
                rule_name="ids_then_brute_force",
                score_delta=20,
                reason=(
                    f"{len(suricata)} Suricata IDS alert(s) coincided with "
                    f"{len(nearby)} syslog SSH brute-force events within 10 min"
                ),
                matched_event_ids=ids,
            )]
    return []


def _brute_force_then_login(events: list[SecurityEvent]) -> list[Detection]:
    """≥3 SSH brute-force events followed by ≥1 successful SSH login
    from the same IP within 30 minutes — possible credential compromise.
    """
    bf = sorted(
        [e for e in events if e.category == "SSH Brute Force"],
        key=lambda e: e.timestamp,
    )
    logins = sorted(
        [e for e in events if e.category == "SSH Login"],
        key=lambda e: e.timestamp,
    )
    if len(bf) < 3 or not logins:
        return []

    window_secs = timedelta(minutes=30).total_seconds()
    last_bf = bf[-1].timestamp
    successful = [
        login for login in logins
        if 0 < (login.timestamp - last_bf).total_seconds() <= window_secs
    ]
    if not successful:
        return []

    ids = [e.event_id for e in (bf + successful) if e.event_id]
    return [_emit(
        source_ip=events[0].source_ip,
        rule_name="brute_force_then_login",
        score_delta=30,
        reason=(
            f"{len(bf)} SSH brute-force attempts followed by "
            f"{len(successful)} successful login(s) within 30 min — "
            "possible credential compromise"
        ),
        matched_event_ids=ids,
    )]


def _multi_source_attack(events: list[SecurityEvent]) -> list[Detection]:
    """Events from ≥2 distinct source_types from the same IP within 1 hour."""
    if len(events) < 2:
        return []
    sources = sorted({e.source_type for e in events})
    if len(sources) < 2:
        return []
    timestamps = sorted(e.timestamp for e in events)
    span = timestamps[-1] - timestamps[0]
    if span > timedelta(hours=1):
        return []
    return [_emit(
        source_ip=events[0].source_ip,
        rule_name="multi_source_attack",
        score_delta=10,
        reason=(
            f"Events from {len(sources)} sources ({', '.join(sources)}) "
            f"within {int(span.total_seconds() / 60)} min"
        ),
        matched_event_ids=[e.event_id for e in events if e.event_id][:20],
    )]


def _sustained_attack(events: list[SecurityEvent]) -> list[Detection]:
    """≥10 BLOCK/DROP events spanning ≥30 min from the same IP."""
    blocked = [e for e in events if e.action in ("BLOCK", "DROP")]
    if len(blocked) < 10:
        return []
    timestamps = sorted(e.timestamp for e in blocked)
    span = timestamps[-1] - timestamps[0]
    if span < timedelta(minutes=30):
        return []
    return [_emit(
        source_ip=events[0].source_ip,
        rule_name="sustained_attack",
        score_delta=15,
        reason=(
            f"{len(blocked)} blocked events sustained over "
            f"{int(span.total_seconds() / 60)} min"
        ),
        matched_event_ids=[e.event_id for e in blocked if e.event_id][:20],
    )]


def _ssh_login_failure_burst(events: list[SecurityEvent]) -> list[Detection]:
    """>=5 "SSH Login Failure" ALERT events from one IP within 10 minutes.

    issue #3 / ADR-0069 D4(e) / ADR-0067 D1(a): a single failed SSH login is
    ``action=ALERT``, ``severity=low`` (Sigma `low` — "notable event but
    rarely an incident... relevant in high numbers or combination with
    others", a lone failed attempt letter for letter; see
    ``firewatch_linux_auth.normalize``'s severity table). `low` never
    qualifies the ADR-0067 D1(b) severity gate at ANY volume (issue #3's own
    Must-NOT criterion: queue entry for auth failures belongs to the
    correlation rules alone) — so without this dedicated rule, a pure SSH
    brute-force burst against this host (repeated failures, no successful
    login, no other source's corroboration) would never leave the observed
    stratum, no matter how large the burst. This rule is the "high numbers...
    combination" escalation path the severity table explicitly defers to.
    Source-agnostic by design: keyed on ``category``+``action``, not
    ``source_type`` — any future source reusing the "SSH Login Failure"
    category joins this rule for free, matching the existing rules' own
    category-keyed (not source_type-keyed) convention.

    Threshold: 5 events within a 10-minute overall span — a conventional
    brute-force detection threshold (e.g. fail2ban's default
    maxretry=5/findtime=600s) consistent with the 10-minute window
    ``_ids_then_brute_force`` already uses. Span check mirrors
    ``_sustained_attack``'s style (first-to-last span, not a sliding window).
    """
    failures = sorted(
        (
            e for e in events
            if e.category == "SSH Login Failure" and e.action == "ALERT"
        ),
        key=lambda e: e.timestamp,
    )
    if len(failures) < 5:
        return []
    span = failures[-1].timestamp - failures[0].timestamp
    if span > timedelta(minutes=10):
        return []
    return [_emit(
        source_ip=events[0].source_ip,
        rule_name="ssh_login_failure_burst",
        score_delta=20,
        reason=(
            f"{len(failures)} failed SSH login attempts within "
            f"{int(span.total_seconds() / 60)} min — brute-force pattern"
        ),
        matched_event_ids=[e.event_id for e in failures if e.event_id][:20],
    )]


# ── Rule registry ────────────────────────────────────────────────────


BUILTIN_RULES: list[CorrelationRule] = [
    _ids_then_brute_force,
    _brute_force_then_login,
    _multi_source_attack,
    _sustained_attack,
    _ssh_login_failure_burst,
]


def detect(events: list[SecurityEvent]) -> list[Detection]:
    """Run all built-in correlation rules against a per-IP event list.

    Failed rules are logged and skipped — they never abort the pipeline. Returns a flat
    list of all detections produced.
    """
    out: list[Detection] = []
    for rule in BUILTIN_RULES:
        try:
            out.extend(rule(events))
        except Exception:
            logger.exception("correlation rule %s failed", rule.__name__)
    return out
