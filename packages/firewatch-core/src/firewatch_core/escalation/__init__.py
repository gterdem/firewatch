"""Escalation package — ADR-0058 C/B foundation + D2 decider + ADR-0059 D2 worthiness.

Public surface for the ``escalation`` concern:

- ``model.py``      — ``SeverityOrder`` + ``SEVERITY_RANKS`` (C metadata shapes);
                      re-exports ``EscalationVerdict`` from the SDK.
- ``policy.py``     — ``EscalationPolicyRegistry`` + ``ESCALATION_POLICY`` singleton
                      + ``RulePolicy`` (per-rule declared metadata registry).
- ``decider.py``    — pure ``decide(events, detections) → EscalationVerdict``
                      (issue #648, ADR-0058 D2, 4-tier action model).
- ``worthiness.py`` — shared alert-worthiness predicate ``is_alert_worthy`` + ``band_meets``
                      (issue #661, ADR-0059 D2); consumed by the notifier and banner feed.
- ``posture.py``    — ``resolve_posture_map`` + ``qualified_tier2_disposition``
                      (issue #75, ADR-0067 D6 + Amendment 1 — enforcement-posture axis).
- ``transition.py`` — ``NotifyTransitionTracker`` (issue #74, ADR-0059 Amendment 1): the
                      per-actor notification-cadence gate ("fire on transition, not on
                      every re-evaluation of an unchanged state").
"""

from firewatch_core.escalation.decider import decide
from firewatch_core.escalation.model import SEVERITY_RANKS, SeverityOrder
from firewatch_core.escalation.policy import (
    ESCALATION_POLICY,
    EscalationPolicyRegistry,
    RulePolicy,
)
from firewatch_core.escalation.posture import (
    InstanceKey,
    qualified_tier2_disposition,
    resolve_posture_map,
)
from firewatch_core.escalation.transition import NotifyTransitionTracker
from firewatch_core.escalation.worthiness import band_meets, is_alert_worthy
from firewatch_sdk.models import EscalationVerdict

__all__ = [
    "ESCALATION_POLICY",
    "EscalationPolicyRegistry",
    "EscalationVerdict",
    "InstanceKey",
    "NotifyTransitionTracker",
    "RulePolicy",
    "SEVERITY_RANKS",
    "SeverityOrder",
    "band_meets",
    "decide",
    "is_alert_worthy",
    "qualified_tier2_disposition",
    "resolve_posture_map",
]
