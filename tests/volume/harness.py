"""RawEvents -> real normalizers -> per-actor ThreatScore + EscalationVerdict
(ADR-0068 D4). No DB, no API server, no AI — the decision path is pure, so
the whole night scores in well under a second.

This module deliberately MIRRORS ``firewatch_core.pipeline.Pipeline.analyze_ip``'s
decision slice (windowing -> run_rules -> detect -> merge_score -> decide)
rather than reimplementing it, so the oracle can never silently drift from
what the real pipeline computes. It skips only the I/O-bound concerns the
ADR excludes: the event store fetch (the manifest/generator supply events
directly), the AI sample call (ADR-0068 D4 — additive and never
de-escalating, so its absence cannot hide a flood), and geo/ASN enrichment
(presentation-only, no bearing on queue membership).
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from firewatch_sdk import RawEvent, SecurityEvent, ThreatScore

from firewatch_core.escalation.decider import decide
from firewatch_core.pipeline import W_CAMPAIGN, W_STATE, _window_slice
from firewatch_core.detector import detect
from firewatch_core.scoring import merge_score, run_rules

from generator import SOURCE_ID_SURICATA, SOURCE_ID_SYSLOG, SOURCE_ID_SYSLOG_CEF

# Real normalizers only (ADR-0068 D4 / the issue's acceptance criteria) — no
# hand-built SecurityEvents anywhere in the scenario path.
from firewatch_suricata.normalize import normalize as _normalize_suricata
from firewatch_syslog.normalize import normalize as _normalize_syslog
from firewatch_syslog_cef.normalize import normalize as _normalize_syslog_cef

_NORMALIZERS = {
    "suricata": (_normalize_suricata, SOURCE_ID_SURICATA),
    "syslog": (_normalize_syslog, SOURCE_ID_SYSLOG),
    "syslog_cef": (_normalize_syslog_cef, SOURCE_ID_SYSLOG_CEF),
}


def normalize_all(raw_events: list[RawEvent]) -> list[SecurityEvent]:
    """Dispatch each RawEvent to its owning plugin's real ``normalize()``."""
    out: list[SecurityEvent] = []
    for raw in raw_events:
        normalize_fn, source_id = _NORMALIZERS[raw.source_type]
        out.append(normalize_fn(raw, source_id))
    return out


def group_by_ip(events: list[SecurityEvent]) -> dict[str, list[SecurityEvent]]:
    by_ip: dict[str, list[SecurityEvent]] = defaultdict(list)
    for e in events:
        by_ip[e.source_ip].append(e)
    return dict(by_ip)


def score_actor(events: list[SecurityEvent], now: datetime) -> ThreatScore:
    """One actor's full ``analyze_ip`` decision slice, without I/O or AI.

    Mirrors ``Pipeline.analyze_ip`` field-for-field for the fields that drive
    queue membership (``threat_level``, ``score``, ``escalation``) and for
    the conservation/provenance fields (`total_events`, `source_types`,
    `first_seen`/`last_seen`).
    """
    ip = events[0].source_ip
    blocked = [e for e in events if e.action in ("BLOCK", "DROP")]
    timestamps = [e.timestamp for e in events]

    state_events = _window_slice(events, now, W_STATE)
    campaign_events = _window_slice(events, now, W_CAMPAIGN)

    rule_score, attack_types = run_rules(state_events)
    detections = detect(campaign_events, now=now)
    detection_boost = sum(d.score_delta for d in detections)

    score, level, score_derivation = merge_score(
        rule_score, None, detection_boost=detection_boost
    )
    escalation_verdict = decide(state_events, detections)

    return ThreatScore(
        source_ip=ip,
        threat_level=level,  # type: ignore[arg-type]
        score=score,
        total_events=len(events),
        blocked_events=len(blocked),
        attack_types=attack_types,
        first_seen=min(timestamps),
        last_seen=max(timestamps),
        source_types=sorted({e.source_type for e in events}),
        detections=detections,
        score_derivation=score_derivation,  # type: ignore[arg-type]
        escalation=escalation_verdict,
    )


def score_all(raw_events: list[RawEvent], now: datetime) -> list[ThreatScore]:
    """RawEvents -> real normalizers -> one ThreatScore per distinct actor IP.

    Sorted by ``source_ip`` — determinism for the regeneration-drift test
    (ADR-0068 D2-6), independent of dict/set iteration order.
    """
    events = normalize_all(raw_events)
    by_ip = group_by_ip(events)
    return sorted(
        (score_actor(actor_events, now) for actor_events in by_ip.values()),
        key=lambda t: t.source_ip,
    )
