"""Per-actor notification transition tracking (ADR-0059 Amendment 1 / issue #74).

``webhook_notifier.check_and_alert`` is otherwise stateless: gate, then post — no
memory of having notified before. Its caller, ``pipeline.background_analyze_and_alert``,
runs per ingested event (``POST /logs``) and per distinct source IP per batch
(``POST /logs/batch``). Without a cadence control, an actor that *stays* in the
alert-worthy population re-notifies on every ingest-triggered analysis: the
Maintainer's 50-events/minute brute-force case would produce ~50 webhook posts a
minute for the duration of the attack (ADR-0059 A1.1's stock-vs-flow correction).

``NotifyTransitionTracker`` is the fix: a small, pure, in-memory per-actor state
machine that answers exactly one question — "did this actor's alert-worthiness
inputs *change* since the last evaluation, in a direction that warrants a fresh
notification?" It does NOT decide whether the actor is currently worthy (that
stays ``escalation.worthiness.is_alert_worthy`` / ``band_meets`` — the single
source of truth, ADR-0059 D2); it only decides *cadence*.

Transition rules (ADR-0059 Amendment 1, issue #74 acceptance criteria):

- **Band axis — "first crosses the band threshold."** Fires when ``band_met``
  flips False -> True since the last evaluation. Does NOT re-fire while
  ``band_met`` stays True across evaluations (this is the pre-existing
  ``band_meets``-repeat-fire bug this issue also fixes — A1.1's "both axes").
- **Tier axis — "enters Tier 1/2 from no-tier, or moves to a louder tier."**
  Fires when the tier enters the auto-escalating range (<= ``tier_ceiling``)
  from outside it (``None`` or a higher/quieter tier number), or moves to a
  numerically lower (louder) tier while already inside the range. Does NOT
  fire on an unchanged tier, nor on a move to a quieter tier within range.
- **"Left and came back" is a new transition, not a duplicate.** Because both
  rules above compare against the immediately-prior evaluation (not the
  last-fired evaluation), an actor whose state falls out of the worthy region
  and later re-enters it fires again — decay-then-recur is a fresh transition.
- **In-memory only.** State lives in a plain dict keyed by actor (source IP),
  scoped to one ``NotifyTransitionTracker`` instance (one per ``WebhookNotifier``
  in practice). It does not survive a process restart — notifying once more
  after a restart is acceptable; permanent silence is not (issue #74).

Standard alignment: this is the same "edge-triggered, not level-triggered" alert
semantics Prometheus Alertmanager and most SIEM/EDR rule engines use to avoid
re-firing on every evaluation tick while a condition remains true.
"""
from __future__ import annotations

from dataclasses import dataclass

# Tier threshold: tiers 1 and 2 are "auto-escalating" (mirrors
# escalation.worthiness._AUTO_ESCALATE_TIER_MAX — kept as an explicit default
# parameter here, not an import, so this module has no dependency on the
# worthiness predicate's internals; the two callers passing the same value is
# enforced by test_issue_74_notify_transition.py, not by a shared import).
_DEFAULT_TIER_CEILING = 2


@dataclass(frozen=True)
class _ActorNotifyState:
    """The last-observed evaluation inputs for one actor."""

    band_met: bool
    tier: int | None


class NotifyTransitionTracker:
    """In-memory per-actor cadence gate: fire only on a genuine state transition.

    Not thread-safe (relies on FireWatch's single-event-loop deployment posture,
    ADR-0023 §F — the same assumption the rest of the notifier stack makes).
    """

    def __init__(self) -> None:
        self._state: dict[str, _ActorNotifyState] = {}

    def transitioned(
        self,
        actor_key: str,
        *,
        band_met: bool,
        tier: int | None,
        tier_axis_enabled: bool,
        tier_ceiling: int = _DEFAULT_TIER_CEILING,
    ) -> bool:
        """Return True when *actor_key*'s state changed in a fire-worthy direction.

        Args:
            actor_key: Stable per-actor key (``ThreatScore.source_ip``).
            band_met: Whether the severity band currently meets the configured
                Notification threshold (``band_meets(threat_level, alert_threshold)``).
            tier: The actor's current ``escalation.tier`` (``None`` for the
                observed stratum — no tier vote at all).
            tier_axis_enabled: Whether the caller's gate mode considers the tier
                axis at all (``RuntimeConfig.notify_on_auto_escalate``). When
                False, tier transitions never contribute — mirrors
                ``is_alert_worthy``'s band-only behaviour with the toggle off.
            tier_ceiling: Tiers <= this value are "auto-escalating". Must match
                the value ``escalation.worthiness.is_alert_worthy`` uses for the
                caller's worthiness decision to stay consistent (default 2).

        Returns:
            True exactly when this evaluation's inputs represent a fresh
            transition per the module-level rules above. The state for
            *actor_key* is always updated to this evaluation's inputs,
            regardless of the return value, so the NEXT call compares against
            what was just observed (not against the last time this returned
            True).
        """
        prev = self._state.get(actor_key)
        tier_in_range = tier_axis_enabled and tier is not None and tier <= tier_ceiling

        if prev is None:
            # No prior evaluation for this actor: any currently-active axis is a
            # fresh entrance (there is nothing to compare against but "absent").
            transitioned = band_met or tier_in_range
        else:
            band_transitioned = band_met and not prev.band_met

            if prev.tier is None or prev.tier > tier_ceiling:
                # Previously outside the auto-escalating range (or no tier vote
                # at all) -- entering it now is itself the transition.
                tier_transitioned = tier_in_range
            else:
                # Already inside the range -- only a LOUDER tier re-fires.
                tier_transitioned = tier_in_range and tier < prev.tier  # type: ignore[operator]

            transitioned = band_transitioned or tier_transitioned

        self._state[actor_key] = _ActorNotifyState(band_met=band_met, tier=tier)
        return transitioned

    def reset(self, actor_key: str | None = None) -> None:
        """Clear tracked state — for *actor_key*, or all actors when None.

        Not required by any production call path today; exposed for tests and
        for a future admin/debug hook (e.g. "re-arm notifications for this IP").
        """
        if actor_key is None:
            self._state.clear()
        else:
            self._state.pop(actor_key, None)
