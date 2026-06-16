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
"""

from firewatch_core.escalation.decider import decide
from firewatch_core.escalation.model import SEVERITY_RANKS, SeverityOrder
from firewatch_core.escalation.policy import (
    ESCALATION_POLICY,
    EscalationPolicyRegistry,
    RulePolicy,
)
from firewatch_core.escalation.worthiness import band_meets, is_alert_worthy
from firewatch_sdk.models import EscalationVerdict

__all__ = [
    "ESCALATION_POLICY",
    "EscalationPolicyRegistry",
    "EscalationVerdict",
    "RulePolicy",
    "SEVERITY_RANKS",
    "SeverityOrder",
    "band_meets",
    "decide",
    "is_alert_worthy",
]
