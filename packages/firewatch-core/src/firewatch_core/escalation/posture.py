"""Enforcement-posture resolution — ADR-0067 D6 (+ Amendment 1), issue #75 Phase A.

Two concerns, both pure (no I/O, no side effects — unit-testable in isolation):

1. ``resolve_posture_map`` — resolve *(instance override OR plugin metadata default)*
   into a per-instance posture map. Shipped at the **full Phase-B signature/map width
   NOW**: the ``instance_overrides`` parameter is present in the interface and is
   always empty/absent in Phase A (populated only by Phase B / issue #44's
   ``instance_loader.py`` key). This is the deliberate pin that keeps Phase B a
   pure additive-data change — it adds a caller-supplied ``instance_overrides``
   mapping, never touches this function's signature or the decider's.

2. ``qualified_tier2_disposition`` — the D6 + Amendment 1 disposition-label table
   for a qualified Tier-2 verdict, given the resolved posture(s) of its contributing
   instances and the actor's tallied BLOCK/DROP count.

Purity constraint (PLUGIN_CONTRACT.md): ``normalize()`` stays pure — posture never
rides on ``SecurityEvent``. It joins core-side at analyze time: the pipeline resolves
the posture map from (instance override OR plugin metadata default) and passes it into
``escalation.decider.decide()`` as an additive parameter (core-internal signature
change, not a contract change — ADR-0067 D6).

Safety property (verified, re-affirmed by Amendment 1 A1.2 — pinned by tests):
``qualified_tier2_disposition`` returns a DISPOSITION LABEL ONLY. No posture value
can ever produce ``block_status="blocked"`` or change a tier — those derive solely
from the per-event BLOCK/DROP tallies computed in ``decider.py``. A mis-declared
posture can manufacture at most false urgency in a label, never false calm and never
tier movement.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping

from firewatch_sdk.models import EnforcementPostureLiteral, EscalationDispositionLiteral

# (source_type, source_id) — the ADR-0016 two-axis source identity. This is the
# instance-key shape shared by the watermark store and the future (#44)
# instance_loader override table.
InstanceKey = tuple[str, str]

# D6 + Amendment 1: the label for a Tier-2 verdict whose contributing instances
# declare a SINGLE, uniform posture. `enforce` is handled separately in
# `qualified_tier2_disposition` (it additionally requires zero BLOCK/DROP — A1.1).
_UNIFORM_POSTURE_DISPOSITION: dict[str, EscalationDispositionLiteral] = {
    "observe": "not_blocked_passive",
    "detect_only": "detected_no_action",
}


def resolve_posture_map(
    instance_keys: Iterable[InstanceKey],
    plugin_defaults: Mapping[str, EnforcementPostureLiteral | None],
    instance_overrides: Mapping[InstanceKey, EnforcementPostureLiteral] | None = None,
) -> dict[InstanceKey, EnforcementPostureLiteral | None]:
    """Resolve (instance override OR plugin default) into a per-instance posture map.

    Args:
        instance_keys:      the ``(source_type, source_id)`` pairs seen in the
                             current analysis window — the pipeline derives this
                             from the actor's events.
        plugin_defaults:     ``source_type -> declared enforcement default``,
                             built from every loaded plugin's
                             ``SourceMetadata.enforcement`` (``None`` for a
                             source_type with no loaded plugin, or a plugin that
                             leaves ``enforcement`` undeclared).
        instance_overrides:  ``(source_type, source_id) -> enforcement`` — the
                             Phase B (#44) per-instance override table. **Always
                             ``None``/empty in Phase A** — the parameter exists
                             now so Phase A ships at full Phase-B signature
                             width and Phase B never touches this interface.
                             When supplied, an override for a given instance key
                             WINS over that instance's plugin default (unit-tested).

    Returns:
        A dict covering every key in ``instance_keys``: the override when present,
        else the plugin default for that instance's ``source_type``, else ``None``
        (undeclared — the conservative, fail-permissive default, ADR-0060 pattern).
    """
    overrides = instance_overrides or {}
    resolved: dict[InstanceKey, EnforcementPostureLiteral | None] = {}
    for key in instance_keys:
        if key in overrides:
            resolved[key] = overrides[key]
        else:
            source_type, _source_id = key
            resolved[key] = plugin_defaults.get(source_type)
    return resolved


def qualified_tier2_disposition(
    postures: Iterable[EnforcementPostureLiteral | None],
    n_block_drop: int,
) -> EscalationDispositionLiteral:
    """The D6 + Amendment 1 disposition-label table for a qualified Tier-2 verdict.

    Args:
        postures:     the resolved posture (or ``None``) for each DISTINCT
                      contributing instance behind this actor's qualifying
                      ALERT/LOG events (one entry per distinct ``(source_type,
                      source_id)``, not one per event).
        n_block_drop: the actor's tallied BLOCK/DROP event count (a
                      ``decider._PartitionTally`` fact) — the Amendment 1 A1.1
                      gate for the `enforce` label.

    Returns:
        - A SINGLE distinct posture is present:
            - ``"observe"``     -> ``"not_blocked_passive"``
            - ``"detect_only"`` -> ``"detected_no_action"``
            - ``"enforce"`` AND ``n_block_drop == 0`` -> ``"not_blocked_enforcing"``
              (Amendment 1 A1.1 — an inline control alerted but did not block; a
              per-sensor fact, not an unknown).
            - ``"enforce"`` with ``n_block_drop > 0``, or ``None`` (undeclared)
              -> ``"block_status_unknown"``.
        - Postures differ across the contributing instances (mixed), or there are
          none -> ``"block_status_unknown"`` (genuinely unknown — a passive sensor
          cannot see what a different, differently-postured sensor did).

    This function is disposition-LABEL-only (the safety property, ADR-0067 A1.2):
    it never touches tier or block_status — those are tally facts owned by
    ``decider.py``, unaffected by any posture value.
    """
    distinct = set(postures)
    if len(distinct) != 1:
        return "block_status_unknown"

    posture = next(iter(distinct))
    if posture is None:
        return "block_status_unknown"
    if posture == "enforce":
        return "not_blocked_enforcing" if n_block_drop == 0 else "block_status_unknown"
    return _UNIFORM_POSTURE_DISPOSITION[posture]
