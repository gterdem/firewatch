"""Alert-worthiness predicate shared by the notification path and the banner feed.

ADR-0059 D2 defines the shared predicate:

    is_alert_worthy(threat, threshold) :=
        band_meets(threat.threat_level, threshold)        # severity-band axis (ADR-0036)
        OR (threat.escalation is not None
            AND threat.escalation.tier <= 2)              # action-aware axis (ADR-0058 D2)

The band half uses ``band_meets(level, threshold)`` — the **single source of truth** for
``ThreatLevel`` ordering.  ``webhook_notifier`` imports ``band_meets`` from here so the two
callers cannot drift independently.

Design decisions:
- **Pure, no I/O.** No database access, no network calls, no logging. Safe to call in any
  hot path.
- **Defensive on escalation=None.** When ``threat.escalation`` is absent the tier axis
  evaluates to False; the band axis alone determines worthiness.
- **Tier threshold is <= 2.** Tier 1 (allowed-through) and Tier 2 (block_status_unknown)
  are the "auto-escalating" detections that warrant notification. Tier 3 (blocked-persistent)
  and Tier 4 (one-off block) are below the bar — they may be informational or expected.

Standard alignment:
- OCSF severity_id / disposition_id orthogonality (OCSF 1.8.0): band and tier are independent
  axes, combined by OR — never collapsed into one value (ADR-0036).
- NIST SP 800-61r2 Detection & Analysis: the band axis is the operator's severity gate;
  the tier axis is the action-aware escalation gate.
"""
from __future__ import annotations

from firewatch_sdk.models import ThreatLevelLiteral, ThreatScore

# ---------------------------------------------------------------------------
# Band-ordering: single source of truth for ThreatLevel comparison.
#
# ``webhook_notifier`` imports ``band_meets`` from here so the ordering
# cannot diverge between the notifier and the worthiness predicate.
# ---------------------------------------------------------------------------

_LEVEL_ORDER: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}

# Tier threshold: tiers 1 and 2 are "auto-escalating" (ADR-0059 D3).
# Tier 1 = allowed-through (highest urgency), Tier 2 = block_status_unknown.
# Tiers 3 and 4 (blocked) do not trigger the escalation-aware notification path.
_AUTO_ESCALATE_TIER_MAX = 2


def band_meets(level: str, threshold: str) -> bool:
    """Return True when *level* is at least as severe as *threshold*.

    Uses ``_LEVEL_ORDER`` — the single canonical ordering for ``ThreatLevelLiteral``.
    Both parameters are ``str`` so callers with a widened type (e.g. a plain ``str``
    from a dynamic config dict) do not need a cast.  Unknown strings map to 0 and
    never meet any configured threshold (fail-safe).

    Args:
        level:     The threat level string to evaluate (e.g. ``"HIGH"``).
        threshold: The configured threshold (e.g. ``"CRITICAL"``).

    Returns:
        True if ``level >= threshold`` in the severity ordering.
    """
    return _LEVEL_ORDER.get(level, 0) >= _LEVEL_ORDER.get(threshold, 0)


def is_alert_worthy(threat: ThreatScore, threshold: ThreatLevelLiteral) -> bool:
    """Return True when *threat* is alert-worthy at the given *threshold*.

    Implements the ADR-0059 D2 shared predicate:

        band_meets(threat.threat_level, threshold)
        OR (threat.escalation is not None AND threat.escalation.tier <= _AUTO_ESCALATE_TIER_MAX)

    The two axes are combined by OR and are never collapsed into a single value
    (ADR-0036 separability invariant).

    This predicate is consumed by:
    - ``webhook_notifier.check_and_alert`` when ``notify_on_auto_escalate`` is True (ADR-0059 D3).
    - The banner-feed serializer (issue #650) for the same worthiness decision.

    Args:
        threat:    The ``ThreatScore`` to evaluate.
        threshold: The operator-configured threshold (``RuntimeConfig.alert_threshold``
                   for notifications, or the Triage threshold for the banner).

    Returns:
        True if the threat meets the band threshold OR auto-escalates to tier <= 2.
    """
    if band_meets(threat.threat_level, threshold):
        return True

    # Tier axis: only tiers 1 and 2 are "auto-escalating" for notification purposes.
    # Defensive: if escalation is None the tier half is False (no KeyError, no AttributeError).
    escalation = threat.escalation
    if escalation is not None and escalation.tier <= _AUTO_ESCALATE_TIER_MAX:
        return True

    return False
