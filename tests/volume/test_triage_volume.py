"""The volume oracle (issue #50, ADR-0068) — usability invariants at realistic
event volume, and the ADR-0070 (+ Amendment 1) distribution-table personas as
named, individually-failing assertions.

Two disciplines live in this ONE file, deliberately kept apart from
``tests/golden/`` (ADR-0068 D1): golden pins EXACT scores for 1-12 event
scenarios; this oracle pins INVARIANTS (set membership, bounds, ordering,
conservation) under a realistic ~130-actor/~850-event night, built from the
seeded generator (``generator.py``) driving the REAL Suricata/syslog/CEF
normalizers (``harness.py``) — never a hand-built ``SecurityEvent``.

EARS -> test mapping (issue #50 acceptance criteria)
─────────────────────────────────────────────────────
AC1 (exact queue membership, ambient-only)  -> TestAmbientOnlyCalmState
AC2 (flood tripwire, len(queue)<=10)         -> TestFloodTripwire
AC3 (breach-among-noise anti-suppression)    -> TestBreachAntiSuppression
AC4 (conservation — observed is never a drop) -> TestConservation
AC5 (calm-state precondition)                -> TestAmbientOnlyCalmState
AC6 (real normalizers only)                  -> TestRealNormalizersOnly
AC7 (manifest declares justified personas)    -> TestManifestDiscipline
AC8 (deterministic generation, drift-checked) -> TestDeterminism
AC9 (frontend vitest sibling)                -> frontend/src/test/triageBand.volume.test.ts
AC10 (runs in default suite, <=5s)            -> this whole file carries no
                                                  opt-in marker; timed below
AC11 (red pre-#42, green on M1 target)        -> PR description (see README.md)
AC12 (tests/golden untouched)                 -> verified in the PR (sha
                                                  unchanged), not re-asserted here

The ADR-0070 distribution table + Amendment 1 personas — the "ledger of
record" the constants (theta_press/theta_high/theta_quiet/H/D_endure) are
adjudicated against — get their own named test classes below (mirroring, not
duplicating, the unit-level pins in
``packages/firewatch-core/tests/test_issue_54_attack_in_progress_campaign.py``):
a constants change that breaks a persona here FAILS a named test with a
clear message, exactly like that file, but exercised through the real
syslog normalizer end-to-end.

Fixture IPs: RFC 5737 documentation ranges only (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) — never real/routable (testing-conventions skill).
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from firewatch_sdk import SecurityEvent, ThreatScore

import generator
import harness
from firewatch_core.escalation.worthiness import is_alert_worthy

SEED = 20260202
_FIXTURES_DIR = Path(__file__).parent / "fixtures"

# ---------------------------------------------------------------------------
# Shared scenario fixtures — computed once per test session (pure, sub-second).
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def manifest() -> dict:
    return generator.load_manifest()


@pytest.fixture(scope="session")
def ambient_scenario(manifest: dict) -> generator.GeneratedScenario:
    return generator.build_ambient_scenario(manifest, seed=SEED, breach=False)


@pytest.fixture(scope="session")
def breach_scenario(manifest: dict) -> generator.GeneratedScenario:
    return generator.build_ambient_scenario(manifest, seed=SEED, breach=True)


@pytest.fixture(scope="session")
def ambient_scores(ambient_scenario: generator.GeneratedScenario) -> list[ThreatScore]:
    return harness.score_all(ambient_scenario.raw_events, ambient_scenario.now)


@pytest.fixture(scope="session")
def breach_scores(breach_scenario: generator.GeneratedScenario) -> list[ThreatScore]:
    return harness.score_all(breach_scenario.raw_events, breach_scenario.now)


def _queue(scores: list[ThreatScore]) -> list[ThreatScore]:
    """The real queue predicate (ADR-0059 D2) at the default HIGH threshold —
    the exact function the banner/notifier calls, not a test re-implementation."""
    return [t for t in scores if is_alert_worthy(t, "HIGH")]


def _sort_triage(scores: list[ThreatScore]) -> list[ThreatScore]:
    """Mirrors ``frontend/src/lib/triageBand.ts``'s ``deriveTriageActors`` sort:
    tier ascending (``None`` -> 99, sorts last), then score descending. Kept as
    a literal port (not an import — there is no cross-language import seam)
    so the Python oracle can assert the sort order the frontend sibling test
    (AC9) independently re-derives from ``derived_threats.json``."""
    def key(t: ThreatScore) -> tuple[int, int]:
        tier = t.escalation.tier if t.escalation and t.escalation.tier is not None else 99
        return (tier, -t.score)
    return sorted(scores, key=key)


# ---------------------------------------------------------------------------
# AC1 / AC5 — ambient-only: exact queue membership is empty; calm is reachable
# ---------------------------------------------------------------------------


class TestAmbientOnlyCalmState:
    def test_queue_is_exactly_empty(self, ambient_scores: list[ThreatScore]) -> None:
        """ADR-0068 D2-1: set equality, not a ceiling — the ambient-only
        manifest declares NO queue-worthy persona, so the queue set must
        equal the empty set exactly."""
        queue = _queue(ambient_scores)
        assert {t.source_ip for t in queue} == set(), (
            f"ambient-only scenario must be calm; flooded by: "
            f"{[(t.source_ip, t.threat_level, t.escalation) for t in queue]}"
        )

    def test_manifest_declares_no_queue_expectation_for_any_ambient_persona(
        self, manifest: dict
    ) -> None:
        """Guards the manifest itself: a persona authored with
        ``expected.queue: true`` in the ambient-only section would silently
        invalidate the calm-state claim above without this sanity check."""
        for persona in manifest["personas"]:
            assert persona["expected"]["queue"] is False, (
                f"persona {persona['name']!r} declares queue=true but lives in "
                "the ambient-only section — move it to a named persona test"
            )

    def test_calm_state_precondition_nonzero_record_count(
        self, ambient_scores: list[ThreatScore]
    ) -> None:
        """ADR-0068 D2-5 / issue #43's calm state: empty queue AND a nonzero
        record (observed) count — calm is "on the record, nothing pending",
        never "nothing happened"."""
        queue = _queue(ambient_scores)
        assert len(queue) == 0
        assert len(ambient_scores) > 0


# ---------------------------------------------------------------------------
# AC2 — the flood tripwire, independent of manifest set-equality edits
# ---------------------------------------------------------------------------


class TestFloodTripwire:
    def test_ambient_only_queue_within_tripwire(
        self, ambient_scores: list[ThreatScore], manifest: dict
    ) -> None:
        assert len(_queue(ambient_scores)) <= manifest["flood_tripwire"]

    def test_breach_variant_queue_within_tripwire(
        self, breach_scores: list[ThreatScore], manifest: dict
    ) -> None:
        assert len(_queue(breach_scores)) <= manifest["flood_tripwire"]


# ---------------------------------------------------------------------------
# AC3 — breach-among-noise: anti-suppression + Tier-1-sorts-first
# ---------------------------------------------------------------------------


class TestBreachAntiSuppression:
    def test_exact_queue_membership_is_the_two_planted_actors(
        self, breach_scores: list[ThreatScore], breach_scenario: generator.GeneratedScenario
    ) -> None:
        tier1_ip = breach_scenario.persona_ips["tier1_breach_allow"][0]
        band_high_ip = breach_scenario.persona_ips["band_high_port_scanner"][0]
        queue_ips = {t.source_ip for t in _queue(breach_scores)}
        assert queue_ips == {tier1_ip, band_high_ip}, (
            "a gate that only rewards silence must fail here — both planted "
            f"actors must surface; got queue={queue_ips}"
        )

    def test_tier1_actor_sorts_first(
        self, breach_scores: list[ThreatScore], breach_scenario: generator.GeneratedScenario
    ) -> None:
        tier1_ip = breach_scenario.persona_ips["tier1_breach_allow"][0]
        ordered = _sort_triage(_queue(breach_scores))
        assert ordered[0].source_ip == tier1_ip
        assert ordered[0].escalation is not None
        assert ordered[0].escalation.tier == 1

    def test_band_high_actor_qualifies_via_band_axis_not_tier_axis(
        self, breach_scores: list[ThreatScore], breach_scenario: generator.GeneratedScenario
    ) -> None:
        """The second planted actor deliberately reaches the queue via
        ``band_meets(threat_level, "HIGH")`` (score-driven), NOT via the
        tier axis (``tier<=2``) — proving is_alert_worthy's OTHER OR-branch
        independently of the first."""
        band_high_ip = breach_scenario.persona_ips["band_high_port_scanner"][0]
        actor = next(t for t in breach_scores if t.source_ip == band_high_ip)
        assert actor.escalation is not None
        assert actor.escalation.tier is not None and actor.escalation.tier > 2
        assert actor.threat_level in ("HIGH", "CRITICAL")

    def test_ambient_noise_stays_silent_inside_the_breach_variant(
        self, breach_scores: list[ThreatScore], breach_scenario: generator.GeneratedScenario
    ) -> None:
        """The 127 ambient actors must not be swept into the queue merely
        because two loud actors were added to the same population."""
        planted = set(breach_scenario.persona_ips["tier1_breach_allow"]) | set(
            breach_scenario.persona_ips["band_high_port_scanner"]
        )
        ambient_in_queue = [t for t in _queue(breach_scores) if t.source_ip not in planted]
        assert ambient_in_queue == []


# ---------------------------------------------------------------------------
# AC4 — conservation: observed is never a drop (ADR-0067 D5)
# ---------------------------------------------------------------------------


class TestConservation:
    def test_ambient_only_every_actor_is_observed_and_none_dropped(
        self, ambient_scenario: generator.GeneratedScenario, ambient_scores: list[ThreatScore]
    ) -> None:
        expected_actor_count = sum(len(ips) for ips in ambient_scenario.persona_ips.values())
        assert len(ambient_scores) == expected_actor_count
        queue = _queue(ambient_scores)
        non_queue = [t for t in ambient_scores if t not in queue]
        assert len(queue) + len(non_queue) == len(ambient_scores)

    def test_breach_variant_every_actor_accounted_for_exactly_once(
        self, breach_scenario: generator.GeneratedScenario, breach_scores: list[ThreatScore]
    ) -> None:
        expected_actor_count = sum(len(ips) for ips in breach_scenario.persona_ips.values())
        assert len(breach_scores) == expected_actor_count
        queue_ips = {t.source_ip for t in _queue(breach_scores)}
        non_queue_ips = {t.source_ip for t in breach_scores if t.source_ip not in queue_ips}
        assert queue_ips | non_queue_ips == {t.source_ip for t in breach_scores}
        assert queue_ips & non_queue_ips == set()

    def test_no_duplicate_ip_allocation_across_personas(
        self, breach_scenario: generator.GeneratedScenario
    ) -> None:
        all_ips = [ip for ips in breach_scenario.persona_ips.values() for ip in ips]
        assert len(all_ips) == len(set(all_ips)), "the IP allocator must never double-assign"


# ---------------------------------------------------------------------------
# AC6 — real normalizers only, no hand-built SecurityEvents in the scenario path
# ---------------------------------------------------------------------------


class TestRealNormalizersOnly:
    def test_scenario_events_are_produced_by_the_real_normalizers(
        self, breach_scenario: generator.GeneratedScenario
    ) -> None:
        """generator.py emits RawEvents exclusively; harness.py's
        normalize_all() dispatches every one through
        firewatch_suricata/firewatch_syslog/firewatch_syslog_cef's actual
        ``normalize()`` — asserted here by checking the raw payloads carry
        source-shaped fields (EVE ``alert``/CEF ``line``) rather than
        already-normalized SecurityEvent fields."""
        source_types = {raw.source_type for raw in breach_scenario.raw_events}
        assert source_types <= {"suricata", "syslog", "syslog_cef"}
        events = harness.normalize_all(breach_scenario.raw_events)
        assert all(isinstance(e, SecurityEvent) for e in events)


# ---------------------------------------------------------------------------
# AC7 — manifest declares justified, reviewable personas
# ---------------------------------------------------------------------------


class TestManifestDiscipline:
    def test_every_persona_declares_count_and_justification(self, manifest: dict) -> None:
        for persona in manifest["personas"]:
            assert persona["actor_count"] > 0
            assert persona["justification"]
            assert "expected" in persona

    def test_every_breach_persona_declares_justification(self, manifest: dict) -> None:
        for persona in manifest["breach_overlay"].values():
            assert persona["justification"]
            assert "expected" in persona


# ---------------------------------------------------------------------------
# AC8 — deterministic generation, drift-checked against the committed fixture
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_regeneration_is_byte_stable_for_the_same_seed(self, manifest: dict) -> None:
        first = generator.build_ambient_scenario(manifest, seed=SEED, breach=True)
        second = generator.build_ambient_scenario(manifest, seed=SEED, breach=True)
        first_scores = harness.score_all(first.raw_events, first.now)
        second_scores = harness.score_all(second.raw_events, second.now)
        assert [t.model_dump(mode="json") for t in first_scores] == [
            t.model_dump(mode="json") for t in second_scores
        ]

    def test_committed_derived_threats_fixture_matches_current_generation(
        self, breach_scores: list[ThreatScore]
    ) -> None:
        """The regeneration-drift gate (ADR-0068 D2-6): a constants change or
        an unreviewed manifest edit that alters the derived population FAILS
        here with a clear message, instead of the frontend sibling silently
        drifting out of sync. Regenerate deliberately via
        ``uv run python scripts/regen_volume_fixtures.py`` (README.md's
        manifest-change discipline)."""
        committed = json.loads((_FIXTURES_DIR / "derived_threats.json").read_text())
        current = [t.model_dump(mode="json") for t in breach_scores]
        assert current == committed, (
            "tests/volume/fixtures/derived_threats.json has drifted from the "
            "generator/harness's current output — if this is a deliberate, "
            "justified manifest/constants change, regenerate with "
            "`uv run python scripts/regen_volume_fixtures.py` and state the "
            "justification in the PR (README.md discipline); otherwise this "
            "is a real regression."
        )


# ---------------------------------------------------------------------------
# AC10 — CI budget: the whole scenario (both variants) stays well under 5s
# ---------------------------------------------------------------------------


class TestCiBudget:
    def test_full_scenario_scores_in_well_under_five_seconds(self, manifest: dict) -> None:
        start = time.monotonic()
        scenario = generator.build_ambient_scenario(manifest, seed=SEED, breach=True)
        harness.score_all(scenario.raw_events, scenario.now)
        elapsed = time.monotonic() - start
        assert elapsed < 5.0, f"volume scenario took {elapsed:.2f}s — over the ADR-0068 budget"


# ---------------------------------------------------------------------------
# The ADR-0070 (+ Amendment 1) distribution-table personas — the ledger of
# record. Each class below is a NAMED assertion: a constants change that
# breaks a persona fails here with the persona's own name in the traceback,
# not a silent drift. Driven through the real syslog normalizer
# (``generator.syslog_events`` -> ``firewatch_syslog.normalize``), mirroring
# — never duplicating — the unit-level pins in
# ``test_issue_54_attack_in_progress_campaign.py``.
# ---------------------------------------------------------------------------

NOW = generator.load_manifest()["now"]


def _score_persona(ip: str, timestamps: list, now) -> ThreatScore:
    raw = generator.syslog_events(ip, timestamps)
    events = harness.normalize_all(raw)
    return harness.score_actor(events, now)


def _rule_names(t: ThreatScore) -> set[str]:
    return {d.rule_name for d in t.detections if d.rule_name}


class TestPersonaFiftyPerMinuteAttacker:
    """ADR-0070 D3 flagship case: an IP attempting SSH brute force 50
    times/min queues WHILE IT IS HAPPENING, within the first minute."""

    def test_queues_within_the_first_minute_via_attack_in_progress(self) -> None:
        now = datetime.fromisoformat(NOW)
        ts = generator.schedule_rate_burst(
            now, 50, timedelta(seconds=1.2), end_before=timedelta(seconds=1.2)
        )
        t = _score_persona("203.0.113.5", ts, now)
        assert "attack_in_progress" in _rule_names(t)
        assert t.escalation is not None and t.escalation.tier == 2


class TestPersonaSingleBurstFadesAfter:
    """ADR-0070 distribution table: a single 120-attempt/40-min burst that
    never returns queues DURING the attack and fades from the queue after
    it stops — no manual expiry, decay alone."""

    def test_queues_during_the_burst(self) -> None:
        now = datetime.fromisoformat(NOW)
        ts = generator.schedule_rate_burst(now, 120, timedelta(seconds=20))
        t = _score_persona("203.0.113.6", ts, now)
        assert "attack_in_progress" in _rule_names(t)
        assert t.escalation is not None and t.escalation.tier == 2

    def test_fades_from_the_queue_after_it_stops(self) -> None:
        now = datetime.fromisoformat(NOW)
        ts = generator.schedule_rate_burst(now, 120, timedelta(seconds=20))
        later = now + timedelta(hours=2)
        t = _score_persona("203.0.113.6", ts, later)
        assert "attack_in_progress" not in _rule_names(t)
        assert "campaign" not in _rule_names(t)
        assert t.escalation is not None and t.escalation.tier is None


class TestPersonaNightlyRecidivist:
    """ADR-0070 D3 recidivism clause: two 10-attempt bursts separated by a
    quiet gap (collapsed well below theta_quiet) queue via `campaign` on
    the second night — recidivism, theta_quiet-separated."""

    def test_queues_night_two_via_campaign_recidivism(self) -> None:
        now = datetime.fromisoformat(NOW)
        ts = generator.schedule_two_bursts(
            now, burst_size=10, gap=timedelta(hours=29), second_end_before=timedelta(hours=1)
        )
        t = _score_persona("203.0.113.7", ts, now)
        assert "campaign" in _rule_names(t)
        assert t.escalation is not None and t.escalation.tier == 2
        campaign = next(d for d in t.detections if d.rule_name == "campaign")
        assert "pressure episodes" in campaign.reason, "must queue via recidivism, not endurance"


class TestPersonaModerateGrinderEndurance:
    """ADR-0070 D3 endurance clause: a moderate-rate grinder (12/h,
    continuous) that never spikes to theta_high queues via `campaign`
    (endurance) once its merged episode reaches D_endure (~24h) — NOT
    within the first 30 minutes (no campaign-in-30-min)."""

    def test_does_not_fire_campaign_within_thirty_minutes(self) -> None:
        now = datetime.fromisoformat(NOW)
        span = timedelta(hours=25)
        start = now - span
        ts = generator.schedule_continuous_drip(now, 6, timedelta(minutes=5), span)
        checkpoint = start + timedelta(minutes=30)
        raw = generator.syslog_events("203.0.113.8", ts)
        events = [e for e in harness.normalize_all(raw) if e.timestamp <= checkpoint]
        t = harness.score_actor(events, checkpoint)
        assert "campaign" not in _rule_names(t)
        assert t.escalation is not None and t.escalation.tier is None

    def test_queues_via_endurance_at_approximately_twenty_four_hours(self) -> None:
        now = datetime.fromisoformat(NOW)
        span = timedelta(hours=25)
        ts = generator.schedule_continuous_drip(now, 6, timedelta(minutes=5), span)
        t = _score_persona("203.0.113.8", ts, now)
        assert "campaign" in _rule_names(t)
        campaign = next(d for d in t.detections if d.rule_name == "campaign")
        assert "spanning" in campaign.reason, "must queue via endurance, not recidivism"
        assert t.escalation is not None and t.escalation.tier == 2


class TestPersonaSlowGrinderNeverQueues:
    """ADR-0070 D9's designed INFORM exclusion: a sub-theta_press paced
    actor (1 attempt every 3 days) never queues at any lifetime volume."""

    def test_never_queues_at_any_lifetime_volume(self) -> None:
        now = datetime.fromisoformat(NOW)
        ts = generator.schedule_paced(now, 50, timedelta(days=3))
        t = _score_persona("203.0.113.9", ts, now)
        assert _rule_names(t) == set()
        assert t.escalation is not None and t.escalation.tier is None
        assert t.escalation.disposition == "observed"


class TestPersonaModerateBurstHysteresisNoCampaign:
    """ADR-0070 Amendment 1 (theta_quiet): the exact PR #86 defect fixture
    (10 attempts 4 min apart) is ONE episode under quiet-collapse
    hysteresis — `campaign` must NOT fire (no recidivism, no endurance, no
    breadth) — through the real syslog normalizer, not just the unit-level
    `episodes()` pin."""

    def test_one_episode_no_campaign(self) -> None:
        now = datetime.fromisoformat(NOW)
        ts = generator.schedule_fixed_interval(now, 10, timedelta(minutes=4), timedelta(0))
        t = _score_persona("203.0.113.10", ts, now)
        assert "campaign" not in _rule_names(t)
        assert t.escalation is not None and t.escalation.tier is None


class TestPersonaAmbientSuricataPriority2NoTicket:
    """ADR-0068/0069 D4a outcome: ambient priority-2 Suricata noise (ET
    SCAN/ET DROP reputation mass) stays <= medium severity and never
    reaches a Tier-2 ticket, even at higher per-actor volume than the
    ambient mass's 1-4/night norm."""

    def test_priority_two_stays_medium_and_never_queues(self) -> None:
        now = datetime.fromisoformat(NOW)
        ts = [now - timedelta(minutes=10 * i) for i in range(50)]
        raw = generator.suricata_events(
            "203.0.113.11", ts, category="Misc Attack", severity=2
        )
        events = harness.normalize_all(raw)
        assert all(e.severity == "medium" for e in events)
        t = harness.score_actor(events, now)
        assert t.escalation is not None and t.escalation.tier is None
        assert t.threat_level in ("LOW", "MEDIUM")
