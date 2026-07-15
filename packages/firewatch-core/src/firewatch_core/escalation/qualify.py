"""The assertion gate — ADR-0067 D1. Pure; the single home of Tier-2 entry rules.

``qualify(events, detections) -> QualifyResult`` decides whether an actor's
ALERT/LOG population contains a *qualifying assertion* — something that actually
claims the actor is hostile — as opposed to bare, non-asserting telemetry. This
is the flood-control valve RC1 identified as designed (ADR-0058 D1's registry)
but never wired into routing; this module is where it is finally consumed.

D1 gate — either signal opens it:

- **(a)** any ``Detection`` with ``auto_escalate=True`` **or** declared
  ``severity in {"high", "critical"}`` — the ADR-0058 D1 registry. ``detector.py``
  already populates ``Detection.severity``/``auto_escalate`` from
  ``ESCALATION_POLICY`` at detection time (ADR-0058 D1), so this module reads
  those fields directly rather than re-querying the registry.
- **(b)** any ``ALERT`` event carrying source-declared
  ``SecurityEvent.severity in {"high", "critical"}`` (Sigma-anchored; every
  in-tree normalizer populates it).

``LOG`` events **never** self-qualify under (b): ECS ``event.kind: event`` is
telemetry, not an assertion (ADR-0067 D1 / RC4) — they escalate only via (a).

**Fail-quiet (D3):** a ``Detection``/``ALERT`` with ``severity=None`` and no
``auto_escalate`` does NOT qualify. This is the one place the "zero-tuning,
can't-miss" property is deliberately relaxed; Tier 1 (unconditional), the
correlation rules themselves, and the band axis (ADR-0067 D5) remain the nets
that catch anything this gate lets through as "observed."

Security note: ``qualifying_event_severity`` is a validated ``SeverityLiteral``
(Pydantic-enforced 5-value vocabulary) — safe to render in a justification,
unlike free-text vendor fields such as ``SecurityEvent.rule_name``/``category``
(ADR-0035 / #642 / #648 discipline, unaffected by this module).
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from firewatch_sdk.models import Detection, SecurityEvent, SeverityLiteral

# Sigma/D1-anchored qualifying severities (ADR-0067 D1a/D1b).
_QUALIFYING_SEVERITIES: frozenset[str] = frozenset({"high", "critical"})

# Rank used only to pick the single highest qualifying event severity for
# evidence (critical > high); both are equally "qualifying" for the gate itself.
_SEVERITY_RANK: dict[str, int] = {"high": 1, "critical": 2}


@dataclass(frozen=True)
class QualifyResult:
    """Whether the D1 assertion gate opens for this actor, and the evidence.

    ``qualified``                 — True when either D1(a) or D1(b) is satisfied.
    ``qualifying_detections``     — the subset of the input ``detections`` that
                                     satisfy D1(a). Used by the decider to build
                                     an honest, engine-authored justification
                                     (``Detection.rule_name`` — never
                                     ``SecurityEvent.rule_name``/``category``).
    ``qualifying_event_severity`` — the highest source-declared severity among
                                     qualifying ``ALERT`` events (D1(b)), or
                                     ``None`` when qualification came only via
                                     (a), or not at all.
    """

    qualified: bool
    qualifying_detections: tuple[Detection, ...] = field(default_factory=tuple)
    qualifying_event_severity: SeverityLiteral | None = None


def _detection_qualifies(detection: Detection) -> bool:
    """D1(a): ``auto_escalate=True`` or declared severity in {high, critical}."""
    if detection.auto_escalate:
        return True
    return detection.severity is not None and detection.severity in _QUALIFYING_SEVERITIES


def _qualifying_event_severity(events: Iterable[SecurityEvent]) -> SeverityLiteral | None:
    """D1(b): highest source-declared severity among qualifying ``ALERT`` events.

    ``LOG`` events are never considered here — ECS ``kind:event`` is telemetry,
    not an assertion (D1 / RC4); only ``ALERT`` (ECS ``kind:alert``) qualifies.
    """
    best: SeverityLiteral | None = None
    best_rank = 0
    for event in events:
        if event.action != "ALERT":
            continue
        severity = event.severity
        if severity is None or severity not in _QUALIFYING_SEVERITIES:
            continue
        rank = _SEVERITY_RANK[severity]
        if rank > best_rank:
            best_rank = rank
            best = severity
    return best


def qualify(
    events: list[SecurityEvent],
    detections: list[Detection],
) -> QualifyResult:
    """Return whether the D1 assertion gate opens for this actor, and why.

    Pure function — no I/O, never raises. Called once per actor by
    ``decider.decide()`` before Tier-2 routing.
    """
    qualifying_detections = tuple(d for d in detections if _detection_qualifies(d))
    qualifying_severity = _qualifying_event_severity(events)
    qualified = bool(qualifying_detections) or qualifying_severity is not None
    return QualifyResult(
        qualified=qualified,
        qualifying_detections=qualifying_detections,
        qualifying_event_severity=qualifying_severity,
    )
