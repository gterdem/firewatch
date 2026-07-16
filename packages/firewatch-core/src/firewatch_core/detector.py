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
- ``attempt_pressure``      — ``medium``   / auto_escalate=False (issue #53, ADR-0070
  Revision 1 D2): an actor's peak decayed attempt intensity (``firewatch_core.attempts``)
  within the trailing state window reaches ``θ_press``. Retires ``_sustained_attack`` (the
  span/count proxy) and ``_ssh_login_failure_burst`` (the ambient-cadence proxy) — R1
  subsumes both under a single rate measure. Pressure alone never queues (``medium`` does
  not satisfy the ADR-0067 D1(a) Tier-2 gate); it contributes score/band visibility and the
  pressure-strip signal, same "on the record, keep watching" posture the two retired rules
  had.
- ``ssh_login_failure_intense`` — ``high`` / auto_escalate=True (issue #3 — **INTERIM**, see the
  function's own docstring): ≥45 events within the same 10-minute window — a genuinely active,
  high-intensity SSH brute force, not ambient noise. Declaring a qualifying severity here routes
  it to Tier-2 through ADR-0067 D1(a)'s existing mechanism (unchanged: a Detection with
  ``severity∈{high,critical}`` or ``auto_escalate=True`` reaches Tier 2). This rule is a stopgap
  pending the redrafted campaign (#54) work, which will supersede and retire it; 45 is chosen
  to *agree* with that end-state model's queue bar (ADR-0070 Rev-1 / issue #54, ``θ_high=40``),
  not as an independently-tuned constant — see the function's own docstring for the derivation.

Skill gate: ai-engine-invariants loaded before editing this file.
"""
import logging
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from firewatch_sdk import Detection, SecurityEvent
from firewatch_core.attempts import HALF_LIFE, PRESSURE_THRESHOLD, is_attempt, peak_intensity
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
    "attempt_pressure",
    severity="medium",
    auto_escalate=False,
)
ESCALATION_POLICY.register(
    "ssh_login_failure_intense",
    severity="high",
    auto_escalate=True,
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

# INTERIM (issue #3 / PR #73 held batch, 2026-07-15): Tier-1 and IDS-corroboration
# reachability, keyed on ``category`` string equality. PLUGIN_CONTRACT.md's
# `category` field currently has NO enumerated vocabulary — each source plugin
# invents its own strings — so a rule that matches on ONE source's spelling
# (syslog's "SSH Brute Force"/"SSH Login") is unreachable from any other source
# that expresses the same real-world event differently (linux_auth's "SSH Login
# Failure"/"SSH Login Success"). These frozensets union the known spellings so
# both rules below are reachable from every SSH-capable source, not just syslog.
# The durable fix is ADR-0071 (an auth-outcome contract vocabulary), which
# should retire this file-local synonym list entirely; this deliberately grows
# the magic-string set in ONE core file so that ADR retires it in one place.
_SSH_BRUTE_FORCE_CATEGORIES = frozenset({"SSH Brute Force", "SSH Login Failure"})
_SSH_LOGIN_SUCCESS_CATEGORIES = frozenset({"SSH Login", "SSH Login Success"})


def _ids_then_brute_force(events: list[SecurityEvent]) -> list[Detection]:
    """≥1 Suricata IDS event coincides with ≥3 SSH brute-force events from
    the same IP within a 10-minute window.

    The SSH leg keys on ``category`` alone (no ``source_type`` restriction):
    "SSH Brute Force" (syslog/syslog_cef) and "SSH Login Failure" (linux_auth)
    are each emitted by exactly one plugin family — verified no other source
    emits either string — so dropping the source_type check does not widen
    which events can match, only which *source* they may arrive from.
    """
    if not events:
        return []
    suricata = [e for e in events if e.source_type == "suricata"]
    ssh_bf = [e for e in events if e.category in _SSH_BRUTE_FORCE_CATEGORIES]
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
                    f"{len(nearby)} SSH brute-force events within 10 min"
                ),
                matched_event_ids=ids,
            )]
    return []


def _brute_force_then_login(events: list[SecurityEvent]) -> list[Detection]:
    """≥3 SSH brute-force events followed by ≥1 successful SSH login
    from the same IP within 30 minutes — possible credential compromise.

    Both legs union the known category spellings across source families (see
    ``_SSH_BRUTE_FORCE_CATEGORIES`` / ``_SSH_LOGIN_SUCCESS_CATEGORIES`` above)
    so this — the product's flagship "you are already breached" Tier-1 path —
    is reachable from linux_auth, not only syslog/syslog_cef.
    """
    bf = sorted(
        [e for e in events if e.category in _SSH_BRUTE_FORCE_CATEGORIES],
        key=lambda e: e.timestamp,
    )
    logins = sorted(
        [e for e in events if e.category in _SSH_LOGIN_SUCCESS_CATEGORIES],
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


_PRESSURE_WINDOW = timedelta(hours=24)
"""R1's peak-check window ("the trailing W_STATE", ADR-0070 D2). MUST equal
``pipeline.W_STATE`` (24h) — duplicated here, not imported, solely to avoid a
detector<->pipeline circular import (``pipeline.py`` imports ``detect`` from
this module at module load time). Pinned equal by
``test_detector.py::test_pressure_window_matches_pipeline_w_state`` so any
future drift between the two fails CI immediately rather than silently."""


def _attempt_pressure(events: list[SecurityEvent], now: datetime) -> list[Detection]:
    """R1 ``attempt_pressure`` (ADR-0070 Revision 1 D2): fires iff the actor's
    peak decayed attempt intensity within the trailing state window
    (``_PRESSURE_WINDOW``) reaches ``PRESSURE_THRESHOLD`` (θ_press).

    Retires ``_sustained_attack`` (the ≥10-blocked/≥30-min span+count proxy)
    and ``_ssh_login_failure_burst`` (the ≥5-in-10-min ambient-cadence proxy):
    both were crude proxies for the same underlying quantity — rate — that
    ``firewatch_core.attempts`` now measures directly. The reason string
    carries engine integers only (ADR-0035) — the qualifying attempt count and
    the window's own span in hours — never the raw λ̂ value (D2).
    """
    if not events:
        return []
    peak = peak_intensity(events, _PRESSURE_WINDOW, now, half_life=HALF_LIFE)
    if peak < PRESSURE_THRESHOLD:
        return []
    attempt_count = sum(
        1 for e in events
        if is_attempt(e) and now - _PRESSURE_WINDOW <= e.timestamp <= now
    )
    hours = int(_PRESSURE_WINDOW.total_seconds() // 3600)
    return [_emit(
        source_ip=events[0].source_ip,
        rule_name="attempt_pressure",
        score_delta=15,
        reason=(
            f"{attempt_count} hostile attempts within the trailing {hours}h "
            "— pressure threshold reached"
        ),
        matched_event_ids=[
            e.event_id for e in events
            if e.event_id and is_attempt(e) and now - _PRESSURE_WINDOW <= e.timestamp <= now
        ][:20],
    )]


def _ssh_login_failure_events(events: list[SecurityEvent]) -> list[SecurityEvent]:
    """Sorted "SSH Login Failure" ALERT events from one actor's event list.

    Shared helper — stands until #54 (ADR-0070 Revision-1 retire list); used
    below by ``_ssh_login_failure_intense`` only (its ``_burst`` sibling
    retired in #53/ADR-0070 Revision 1, R1 subsumes it).
    """
    return sorted(
        (
            e for e in events
            if e.category == "SSH Login Failure" and e.action == "ALERT"
        ),
        key=lambda e: e.timestamp,
    )


def _ssh_login_failure_intense(events: list[SecurityEvent]) -> list[Detection]:
    """**INTERIM rule — see below before touching this.**

    >=45 "SSH Login Failure" ALERT events from one IP within a 10-minute
    window — a genuinely active, high-intensity brute force, not ambient
    scanner background (the ambient case is R1 ``attempt_pressure``'s job
    now — ADR-0070 Revision 1; its own sibling ``_ssh_login_failure_burst``
    was retired in #53). Registered at ``severity="high"``/
    ``auto_escalate=True``, so a Detection from this rule satisfies the
    ADR-0067 D1(a) Tier-2 gate — that gate mechanism (a Detection with a
    qualifying severity reaches Tier 2) is Accepted and unchanged; only this
    rule's OWN existence is new.

    **This is a stopgap, not settled design.** It exists only because the
    real owner of "distinguish ambient volume from an active attack" — the
    rewritten campaign (#54) correlation work — has not landed yet. Once it
    does, it supersedes and retires this function; do not extend or
    generalize this rule in the meantime.

    **Why 45, not a round number:** the end-state model (ADR-0070 Rev-1 /
    issue #54) scores an actor by a decaying intensity λ̂ with a 30-minute
    half-life and queues once λ̂ reaches θ_high=40. A uniform 30-events/
    10-minutes burst peaks at λ̂ ≈ 26.8 — below θ_high — so a ≥30 interim rule
    would queue actors the end state deliberately excludes, and they would
    un-queue the moment #53/#54 land (a regression manufactured by this very
    stopgap). At ≥45 the worst case (all 45 events packed into the 10-minute
    window) peaks at λ̂ ≈ 40.2 ≥ 40, so interim and end-state agree at the
    boundary. 45 is picked to match θ_high under that model, not as an
    independently-tuned constant — the live capture that #53/#54 are built
    against still sets the real end-state numbers.
    """
    failures = _ssh_login_failure_events(events)
    if len(failures) < 45:
        return []
    span = failures[-1].timestamp - failures[0].timestamp
    if span > timedelta(minutes=10):
        return []
    return [_emit(
        source_ip=events[0].source_ip,
        rule_name="ssh_login_failure_intense",
        score_delta=20,
        reason=(
            f"{len(failures)} failed SSH login attempts within "
            f"{int(span.total_seconds() / 60)} min — active high-intensity brute force"
        ),
        matched_event_ids=[e.event_id for e in failures if e.event_id][:20],
    )]


# ── Rule registry ────────────────────────────────────────────────────


BUILTIN_RULES: list[CorrelationRule] = [
    _ids_then_brute_force,
    _brute_force_then_login,
    _multi_source_attack,
    _ssh_login_failure_intense,
]


def detect(events: list[SecurityEvent], now: datetime | None = None) -> list[Detection]:
    """Run all built-in correlation rules against a per-IP event list.

    ``now`` (ADR-0070 Revision 1 D2/"Module shape") is the pipeline's anchored
    evaluation instant, consumed by R1 ``attempt_pressure`` to compute peak
    decayed intensity. Optional, defaulting to the real wall clock, mirroring
    ``Pipeline.__init__``'s own ``clock`` parameter (issue #52) — this keeps
    every existing ``detect(events)`` call site (golden/e2e tests included)
    working unchanged, since none of their fixture timestamps are recent
    enough for R1 to fire under a real-wall-clock default; the pipeline always
    passes its own anchored ``now`` explicitly in production.

    Failed rules are logged and skipped — they never abort the pipeline. Returns a flat
    list of all detections produced.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    out: list[Detection] = []
    for rule in BUILTIN_RULES:
        try:
            out.extend(rule(events))
        except Exception:
            logger.exception("correlation rule %s failed", rule.__name__)
    try:
        out.extend(_attempt_pressure(events, now))
    except Exception:
        logger.exception("correlation rule %s failed", "_attempt_pressure")
    return out
