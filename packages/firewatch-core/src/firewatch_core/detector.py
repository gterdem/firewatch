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
- ``attack_in_progress``    — ``high``     / auto_escalate=True (issue #54, ADR-0070
  Revision 1 D3): the actor's CURRENT decayed intensity ``lambda_hat(now)`` reaches
  ``θ_high`` — a high-rate attack is happening right now (the Maintainer's 50/min case
  queues in under a minute). Retires ``_ssh_login_failure_intense`` (issue #3's INTERIM
  stopgap, whose ≥45-in-10-min threshold was derived to agree with ``θ_high`` — the
  handover is value-preserving, not a behavior loss). Fades by decay alone: no manual
  expiry, nothing persisted.
- ``campaign``              — ``high``     / auto_escalate=True (issue #54, ADR-0070
  Revision 1 D3): fires when the actor's pressure episodes within the campaign horizon show
  recidivism (≥2 episodes — rose, collapsed to quiet, rose again — "collapsed to quiet"
  meaning λ̂ fell below θ_quiet = θ_press/2, ADR-0070 Amendment 1), endurance (one episode
  spanning ≥ ``D_endure`` — the moderate-rate grinder that never spikes but never stops), or
  breadth (≥1 episode **and** ≥2 attack categories or ≥5 destination ports — pressure that is
  also exploring). Below ``attack_in_progress``'s ``score_delta`` so the decider's headline
  names the *current* attack over the historical pattern when both fire.

Skill gate: ai-engine-invariants loaded before editing this file.
"""
import logging
from collections.abc import Callable
from datetime import datetime, timedelta

from firewatch_sdk import Detection, SecurityEvent
from firewatch_core.attempts import (
    HALF_LIFE,
    PRESSURE_THRESHOLD,
    episodes,
    intensity_at,
    is_attempt,
    peak_intensity,
)
from firewatch_core.escalation.policy import ESCALATION_POLICY

CorrelationRule = Callable[[list[SecurityEvent]], list[Detection]]
TimeAnchoredRule = Callable[[list[SecurityEvent], datetime], list[Detection]]
"""A correlation rule that additionally needs the pipeline's anchored ``now``
(ADR-0070 D2/D3) — R1/R2/R3, all built on `firewatch_core.attempts`. Kept
distinct from ``CorrelationRule`` (``BUILTIN_RULES``) rather than widening that
type, so a rule with no time dependency cannot accidentally acquire a second,
un-anchored wall-clock read."""

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
    "attack_in_progress",
    severity="high",
    auto_escalate=True,
)
ESCALATION_POLICY.register(
    "campaign",
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


THETA_HIGH = 40
"""theta_high — the R2 ``attack_in_progress`` firing threshold (ADR-0070 D5):
``lambda_hat(now) >= THETA_HIGH`` means a high-rate attack is happening right
now. Crossed in <1 min at 50 attempts/min (the Maintainer's case); unreachable
below ~55 attempts/hour sustained."""

D_ENDURE = timedelta(hours=24)
"""D_endure — the R3 ``campaign`` endurance-clause span (ADR-0070 D5): a
single pressure episode spanning >= D_ENDURE queues the moderate-rate grinder
that never spikes to THETA_HIGH but never stops."""

CAMPAIGN_MIN_EPISODES = 2
"""Recidivism clause (ADR-0070 D3/D5): >=2 pressure episodes within the
campaign horizon — the actor's intensity rose, collapsed to quiet, and rose
again (fail2ban's ``recidive`` shape). "Collapsed to quiet" is defined by the
theta_quiet crossing (theta_press/2, ADR-0070 Amendment 1) — episodes() merges
two excursions unless lambda_hat fell that far between them."""

CAMPAIGN_MIN_CATEGORIES = 2
"""Breadth clause (ADR-0070 D5): >=1 pressure episode AND >=2 distinct attack
categories — pressure that is also exploring is not commodity spray."""

CAMPAIGN_MIN_PORTS = 5
"""Breadth clause (ADR-0070 D5): >=1 pressure episode AND >=5 distinct
destination ports — matches ``port_scan``'s own breadth bar."""

_CAMPAIGN_WINDOW = timedelta(days=7)
"""R3's reporting horizon ("the trailing W_CAMPAIGN", ADR-0070 D4). MUST equal
``pipeline.W_CAMPAIGN`` (7d) — duplicated here (not imported) for the same
detector<->pipeline circular-import reason as ``_PRESSURE_WINDOW`` above; used
only to phrase R3's reason string in engine integers (ADR-0035), never to
filter events (the pipeline's fetch/slice seam already bounds what ``detect()``
sees — ADR-0070 D4). Pinned equal by
``test_issue_54_attack_in_progress_campaign.py::test_campaign_window_matches_pipeline_w_campaign``."""


def _attack_in_progress(events: list[SecurityEvent], now: datetime) -> list[Detection]:
    """R2 ``attack_in_progress`` (ADR-0070 Revision 1 D3): fires iff the
    actor's CURRENT decayed attempt intensity ``lambda_hat(now)`` reaches
    ``THETA_HIGH`` — a high-rate attack is happening right now, not merely
    accumulating (contrast R1, which checks the *peak* over a trailing
    window; R2 checks the instant).

    Retires ``_ssh_login_failure_intense`` (issue #3's INTERIM stopgap,
    ≥45-in-10-min — chosen to agree with ``THETA_HIGH`` so the handover is
    value-preserving). Fades by decay alone: as the actor's attempts stop,
    ``lambda_hat(now)`` on the next analysis falls below ``THETA_HIGH`` and
    this rule simply stops firing — no persisted state, no manual expiry.
    The reason string carries engine integers only (ADR-0035) — the
    qualifying attempt count in the trailing window, never the raw λ̂ value.
    """
    if not events:
        return []
    current = intensity_at(events, now, half_life=HALF_LIFE)
    if current < THETA_HIGH:
        return []
    attempt_count = sum(
        1 for e in events
        if is_attempt(e) and now - _PRESSURE_WINDOW <= e.timestamp <= now
    )
    hours = int(_PRESSURE_WINDOW.total_seconds() // 3600)
    return [_emit(
        source_ip=events[0].source_ip,
        rule_name="attack_in_progress",
        score_delta=25,
        reason=(
            f"{attempt_count} hostile attempts within the trailing {hours}h "
            "— high-intensity attack in progress"
        ),
        matched_event_ids=[
            e.event_id for e in events
            if e.event_id and is_attempt(e) and now - _PRESSURE_WINDOW <= e.timestamp <= now
        ][:20],
    )]


def _campaign(events: list[SecurityEvent], now: datetime) -> list[Detection]:
    """R3 ``campaign`` (ADR-0070 Revision 1 D3): fires when the actor's
    pressure episodes within the campaign horizon satisfy any of three
    clauses — recidivism (>=``CAMPAIGN_MIN_EPISODES`` episodes), endurance
    (one episode spanning >=``D_ENDURE``), or breadth (>=1 episode AND
    >=``CAMPAIGN_MIN_CATEGORIES`` attack categories or
    >=``CAMPAIGN_MIN_PORTS`` distinct destination ports).

    ``now`` bounds nothing here directly — ``episodes()`` is itself
    time-agnostic (closed-form crossings over whatever attempts are in
    ``events``); the campaign horizon is applied at the pipeline's fetch/slice
    seam (ADR-0070 D4), so a campaign stops deriving on its own once the
    qualifying episodes age out of that slice — no manual expiry. ``now`` is
    accepted for signature symmetry with the other time-anchored rules
    (``TimeAnchoredRule``) and is unused by design.

    The clause-seam boundary (ADR-0070 D3, hysteresis per Amendment 1):
    filling the quiet gap between two episodes merges them (recidivism stops
    deriving), but the filler must prevent a θ_quiet collapse — hold
    λ̂ >= θ_quiet in the gaps — which merges everything into one span that
    fires endurance at ``D_ENDURE`` — no addition of events can move an actor
    to calm.
    """
    del now  # unused by design — see docstring
    eps = episodes(events, PRESSURE_THRESHOLD, half_life=HALF_LIFE)
    if not eps:
        return []

    recidivism = len(eps) >= CAMPAIGN_MIN_EPISODES
    longest_span = max((ep.end - ep.start for ep in eps), default=timedelta(0))
    endurance = longest_span >= D_ENDURE

    attempts = [e for e in events if is_attempt(e)]
    categories = {e.category for e in attempts if e.category}
    ports = {e.destination_port for e in attempts if e.destination_port is not None}
    breadth = len(categories) >= CAMPAIGN_MIN_CATEGORIES or len(ports) >= CAMPAIGN_MIN_PORTS

    if not (recidivism or endurance or breadth):
        return []

    clauses: list[str] = []
    if recidivism:
        clauses.append(f"{len(eps)} pressure episodes")
    if endurance:
        span_hours = int(longest_span.total_seconds() // 3600)
        clauses.append(f"one episode spanning {span_hours}h")
    if breadth:
        clauses.append(f"{len(categories)} categories, {len(ports)} distinct ports")

    days = int(_CAMPAIGN_WINDOW.total_seconds() // 86400)
    reason = (
        ", ".join(clauses)
        + f" within the trailing {days}d — sustained campaign"
    )
    return [_emit(
        source_ip=events[0].source_ip,
        rule_name="campaign",
        score_delta=20,
        reason=reason,
        matched_event_ids=[e.event_id for e in attempts if e.event_id][:20],
    )]


# ── Rule registry ────────────────────────────────────────────────────


BUILTIN_RULES: list[CorrelationRule] = [
    _ids_then_brute_force,
    _brute_force_then_login,
    _multi_source_attack,
]

TIME_ANCHORED_RULES: list[TimeAnchoredRule] = [
    _attempt_pressure,
    _attack_in_progress,
    _campaign,
]
"""R1/R2/R3 (ADR-0070) — the rules built on ``firewatch_core.attempts`` that
need the pipeline's anchored ``now``. Run separately from ``BUILTIN_RULES``
(different call signature); ``detect()`` loops both, one try/except per rule
so a single misbehaving rule never aborts the others."""


def detect(events: list[SecurityEvent], *, now: datetime) -> list[Detection]:
    """Run all built-in correlation rules against a per-IP event list.

    ``now`` (ADR-0070 Revision 1 D2/D3, "Module shape") is the pipeline's
    anchored evaluation instant, consumed by ``TIME_ANCHORED_RULES``
    (R1 ``attempt_pressure``, R2 ``attack_in_progress``, R3 ``campaign``) to
    compute decayed intensity. Required and keyword-only (issue #82): an
    optional wall-clock-fallback ``now`` is a footgun by construction — any
    caller that forgets ``now=`` would silently degrade into non-deterministic,
    wall-clock-dependent scoring with no signal from pyright, exactly how the
    ``GET /escalation/policy`` determinism defect shipped (issue #53 / PR #81,
    fixed in commit ``4afa29c``). Making ``now`` required closes that class:
    a forgotten call site now fails at type-check, not silently at runtime.
    The pipeline computes its own anchored ``now`` once and threads it through
    (``Pipeline.analyze_ip`` → this function), and no rule below ever reads
    the wall clock a second time on its own.

    Failed rules are logged and skipped — they never abort the pipeline. Returns a flat
    list of all detections produced.
    """
    out: list[Detection] = []
    for rule in BUILTIN_RULES:
        try:
            out.extend(rule(events))
        except Exception:
            logger.exception("correlation rule %s failed", rule.__name__)
    for time_rule in TIME_ANCHORED_RULES:
        try:
            out.extend(time_rule(events, now))
        except Exception:
            logger.exception("correlation rule %s failed", time_rule.__name__)
    return out
