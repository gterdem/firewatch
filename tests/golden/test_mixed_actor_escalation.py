"""Golden fixture — additive mixed-actor escalation oracle (issue #725, ADR-0058 A1-A5;
issue #42, ADR-0067 D8 re-bless).

Pins the ``block_status='partial'`` + ``disposition_counts`` behaviour introduced by
the decider full-tally rewrite.  This is ADDITIVE coverage only — no existing value in
``tests/golden/fixtures/expected_scores.json`` is modified (ADR-0067 D8 verifies scoring
takes no tier input; that fixture pins scores only, no tier/escalation keys).

EARS acceptance criteria → test mapping:
- EARS-1: WHEN the suite runs the mixed-actor scenario, THE oracle SHALL assert
  ``block_status == 'partial'``.
  → TestMixedActorEscalation.test_block_status_partial

- EARS-2: WHERE the mixed actor has N ALERT + M BLOCK events, THE oracle SHALL assert
  ``disposition_counts == {blocked: M, alert_unknown: N, allowed: 0}``.
  → TestMixedActorEscalation.test_disposition_counts

- EARS-3: WHILE the mixed-actor scenario is added, THE suite SHALL NOT change any
  pre-existing expected_scores.json score / threat_level value.
  → TestExistingScoresUnchanged (verified by the unmodified expected_scores.json)

- EARS-4: WHERE the mixed actor's loudest *qualifying* action is BLOCK/DROP (the 9 ALERT
  events carry no detection and no declared severity — ADR-0067 D1 — so they do not
  qualify), THE oracle SHALL assert tier/disposition reflect that headline (the 3
  confirmed blocks) and the actor is queue-worthy via the band axis / Tier-3 visibility.
  → TestMixedActorEscalation.test_tier_reflects_loudest_action /
    test_disposition_reflects_loudest_action

ADR-0067 D8 — the one, deliberate, architect-signed golden re-bless (issue #42):

| Pin (was)                                                  | New expected value                                        | Why the NEW value is right |
|---|---|---|
| Pure-ALERT actor (5 ALERT, no detections) → `tier == 2`, `disposition == "block_status_unknown"` | `tier is None`, `disposition == "observed"`, `block_status == "unknown"` (unchanged) | A bare, severity-less ALERT population makes no assertion — nothing declared it hostile. Claiming Tier 2 ("needs a BLOCK decision") for it was the flood itself: 100% of a watch-only Suricata/WAF/ClamAV deployment is exactly this shape. `observed` states the honest fact — on the record, no claim — while the band axis still catches genuine accumulation. |
| Mixed actor (9 ALERT + 3 BLOCK, no detections) → `tier == 2`, `disposition == "block_status_unknown"` | `tier == 3`, `disposition == "blocked_persistent"`, `block_status == "partial"` (unchanged), `disposition_counts` (unchanged) | The 9 ALERT events assert nothing (no detection, no declared severity); the 3 BLOCK/DROP events are a confirmed, terminal, persistent outcome. Letting the silent majority (ALERT) outrank the confirmed minority (BLOCK) — as the old pin did — was Amendment 1's bug in mirror image: discarding real evidence in favour of noise. The loudest *qualifying* class must decide, and here that is the perimeter's own confirmed blocks. |

Justification for moving these pinned values, in ADR-0058 D5b's own words: *the old
expected values encoded the blind spot* — here, the flood. No other value in this file
moves; every other pin below is the regression net for this change.

Fixture IPs are RFC 5737 documentation ranges only (203.0.113.x) — not real/routable.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from firewatch_sdk.models import Detection, SecurityEvent
from firewatch_core.escalation.decider import decide

# RFC 5737 TEST-NET-3 — documentation use only; not routable.
_MIXED_IP = "203.0.113.55"
_T0 = datetime(2026, 6, 15, 8, 0, 0, tzinfo=timezone.utc)

# Fixture shape: mirrors the real-world 142.x actor at a small scale.
#   9  ALERT/LOG events  → alert_unknown = 9
#   3  BLOCK/DROP events → blocked = 3
# (kept small for fast fixture; the ratio is representative)
_N_ALERT = 9
_N_BLOCK = 3


def _make_event(action: str, idx: int = 0) -> SecurityEvent:
    """Construct a minimal SecurityEvent with a documentation IP."""
    return SecurityEvent(
        source_type="suricata",
        source_id="pi-home",
        source_ip=_MIXED_IP,
        action=action,  # type: ignore[arg-type]
        timestamp=_T0,
    )


@pytest.fixture(scope="module")
def mixed_actor_verdict():
    """Run decide() over a mixed ALERT+BLOCK actor and return the verdict.

    9 ALERT events + 3 BLOCK/DROP events — events span two terminal disposition
    classes → block_status must be 'partial'.
    """
    events: list[SecurityEvent] = (
        [_make_event("ALERT", i) for i in range(_N_ALERT)]
        + [_make_event("BLOCK", i) for i in range(_N_BLOCK)]
    )
    return decide(events, [])


class TestMixedActorEscalation:
    """Pins the ADR-0058 Amendment 1 mixed-actor behaviour."""

    # EARS-1
    def test_block_status_partial(self, mixed_actor_verdict):
        """Mixed actor (ALERT + BLOCK) MUST have block_status='partial'."""
        assert mixed_actor_verdict.block_status == "partial", (
            f"Expected 'partial', got {mixed_actor_verdict.block_status!r}"
        )

    # EARS-2
    def test_disposition_counts_present(self, mixed_actor_verdict):
        """disposition_counts must be set (not None) for mixed actors."""
        assert mixed_actor_verdict.disposition_counts is not None

    def test_disposition_counts_blocked(self, mixed_actor_verdict):
        """blocked count must equal the number of BLOCK/DROP events."""
        assert mixed_actor_verdict.disposition_counts.blocked == _N_BLOCK

    def test_disposition_counts_alert_unknown(self, mixed_actor_verdict):
        """alert_unknown count must equal the number of ALERT/LOG events."""
        assert mixed_actor_verdict.disposition_counts.alert_unknown == _N_ALERT

    def test_disposition_counts_allowed(self, mixed_actor_verdict):
        """allowed count must be 0 (no ALLOW events in this fixture)."""
        assert mixed_actor_verdict.disposition_counts.allowed == 0

    # EARS-4 / ADR-0067 D8 re-bless: the 9 ALERT events carry no detection and no
    # declared severity, so they do NOT qualify (ADR-0067 D1). The 3 confirmed
    # BLOCK/DROP events are the loudest *qualifying* class and decide the tier.
    def test_tier_reflects_loudest_action(self, mixed_actor_verdict):
        """Tier must be 3 — the confirmed, persistent blocks (ALERT mass is unqualified)."""
        assert mixed_actor_verdict.tier == 3, (
            f"Expected tier 3 (loudest QUALIFYING class = 3 confirmed BLOCK/DROP; "
            f"the 9 ALERT events assert nothing per ADR-0067 D1), got {mixed_actor_verdict.tier}"
        )

    def test_disposition_reflects_loudest_action(self, mixed_actor_verdict):
        """Disposition must be 'blocked_persistent' (the confirmed-block headline)."""
        assert mixed_actor_verdict.disposition == "blocked_persistent"

    def test_justification_is_rule_tagged(self, mixed_actor_verdict):
        """Justification must start with [RULE] per ADR-0035."""
        assert mixed_actor_verdict.justification.startswith("[RULE]")

    def test_justification_contains_no_attacker_fields(self, mixed_actor_verdict):
        """Justification must not embed attacker-controllable category/rule_name text."""
        jst = mixed_actor_verdict.justification
        # The justification must be built from engine integers only; the word
        # "category" or "rule_name" embedding would violate #642/#648.
        # We check that the integer counts appear and that no raw event field
        # names (category, rule_name, payload) appear in the string.
        assert "category" not in jst
        assert "rule_name" not in jst
        assert "payload" not in jst

    def test_justification_contains_block_count(self, mixed_actor_verdict):
        """Justification must include the BLOCK/DROP count integer."""
        assert str(_N_BLOCK) in mixed_actor_verdict.justification

    def test_justification_contains_alert_count(self, mixed_actor_verdict):
        """Justification must include the ALERT/LOG count integer."""
        assert str(_N_ALERT) in mixed_actor_verdict.justification


class TestMixedActorVsSingleClass:
    """Regression guard: single-class actors must be unchanged (EARS-4 of #724)."""

    def test_pure_alert_actor_is_observed(self):
        """ADR-0067 D8 re-bless: a bare, severity-less ALERT population is 'observed'.

        No detection fired and no event declared a qualifying severity — nothing
        asserted this actor is hostile (ADR-0067 D1). ``block_status`` stays
        'unknown' (unchanged truth: ALERT never asserts a terminating verdict).
        """
        events = [_make_event("ALERT") for _ in range(5)]
        verdict = decide(events, [])
        assert verdict.block_status == "unknown"
        assert verdict.tier is None
        assert verdict.disposition == "observed"

    def test_pure_block_actor_persistent_block_status_blocked(self):
        """Pure BLOCK actor (≥3) → block_status='blocked', tier=3."""
        events = [_make_event("BLOCK") for _ in range(3)]
        verdict = decide(events, [])
        assert verdict.block_status == "blocked"
        assert verdict.tier == 3

    def test_pure_block_actor_oneoff_block_status_blocked(self):
        """Pure BLOCK actor (1) → block_status='blocked', tier=4."""
        events = [_make_event("BLOCK")]
        verdict = decide(events, [])
        assert verdict.block_status == "blocked"
        assert verdict.tier == 4

    def test_single_class_has_disposition_counts(self):
        """Single-class actors must also have disposition_counts attached."""
        events = [_make_event("BLOCK") for _ in range(3)]
        verdict = decide(events, [])
        assert verdict.disposition_counts is not None
        assert verdict.disposition_counts.blocked == 3
        assert verdict.disposition_counts.alert_unknown == 0
        assert verdict.disposition_counts.allowed == 0

    def test_allow_with_detection_tier1_unchanged(self):
        """ALLOW + detection → tier=1, block_status='allowed' (no partial)."""
        events = [_make_event("ALLOW")]
        detections = [Detection(
            source_ip=_MIXED_IP,
            rule_name="test_rule",
            score_delta=10,
            reason="test",
        )]
        verdict = decide(events, detections)
        assert verdict.tier == 1
        assert verdict.block_status == "allowed"
        assert verdict.disposition == "allowed_through"
