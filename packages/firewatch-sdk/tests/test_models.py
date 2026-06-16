"""Tests for firewatch-sdk canonical models (EARS-1, EARS-2 of issue #1)."""
from datetime import datetime, timezone
from typing import Any

import pydantic
import pytest
from pydantic import BaseModel, ValidationError

from firewatch_sdk import (
    Detection,
    FilterSpec,
    RawEvent,
    Sample,
    SecurityEvent,
    ThreatScore,
)

UTC_NOW = datetime(2026, 6, 3, 12, 0, 0, tzinfo=timezone.utc)

ALL_MODELS = [SecurityEvent, RawEvent, ThreatScore, FilterSpec, Detection, Sample]


def _minimal_security_event(**overrides: Any) -> SecurityEvent:
    base: dict[str, Any] = dict(
        source_type="suricata",
        source_id="pi-home",
        timestamp=UTC_NOW,
        source_ip="203.0.113.5",
        action="ALERT",
    )
    base.update(overrides)
    return SecurityEvent(**base)


# ---- EARS-1: the six models exist as Pydantic v2 models ---------------------


def test_pydantic_v2_runtime():
    assert pydantic.VERSION.startswith("2"), pydantic.VERSION


@pytest.mark.parametrize("model", ALL_MODELS)
def test_all_models_are_basemodel(model):
    assert issubclass(model, BaseModel)


def test_minimal_construction():
    _minimal_security_event()
    RawEvent(source_type="suricata", received_at=UTC_NOW, data={"k": "v"})
    Detection(source_ip="203.0.113.5", rule_name="r", score_delta=10, reason="why")
    Sample(
        source_ip="203.0.113.5",
        total_events=1,
        blocked_events=0,
        first_seen=UTC_NOW,
        last_seen=UTC_NOW,
        categories=["sqli"],
        events=[_minimal_security_event()],
    )
    ThreatScore(
        source_ip="203.0.113.5",
        threat_level="HIGH",
        score=80,
        total_events=1,
        blocked_events=0,
        attack_types=["sqli"],
        first_seen=UTC_NOW,
        last_seen=UTC_NOW,
    )
    FilterSpec()  # all fields optional


# ---- EARS-2: SecurityEvent field requirements ------------------------------


def test_securityevent_requires_source_type_and_source_id():
    # both present -> ok
    _minimal_security_event()
    with pytest.raises(ValidationError):
        _minimal_security_event(source_type=None)
    with pytest.raises(ValidationError):
        SecurityEvent(  # source_id missing entirely  # pyright: ignore[reportCallIssue]
            source_type="suricata",
            timestamp=UTC_NOW,
            source_ip="203.0.113.5",
            action="ALERT",
        )


def test_mitre_capec_fields_nullable_default_none():
    ev = _minimal_security_event()
    assert ev.attack_technique is None
    assert ev.attack_tactic is None
    assert ev.kill_chain_phase is None
    assert ev.capec_id is None

    ev2 = _minimal_security_event(
        attack_technique="T1190",
        attack_tactic="TA0001",
        kill_chain_phase="initial-access",
        capec_id="CAPEC-66",
    )
    assert ev2.attack_technique == "T1190"
    assert ev2.attack_tactic == "TA0001"
    assert ev2.kill_chain_phase == "initial-access"
    assert ev2.capec_id == "CAPEC-66"


def test_retains_ocsf_fields():
    ev = _minimal_security_event()
    assert ev.ocsf_class is None
    assert ev.ocsf_category is None
    ev2 = _minimal_security_event(ocsf_class=6004, ocsf_category=6)
    assert ev2.ocsf_class == 6004
    assert ev2.ocsf_category == 6


@pytest.mark.parametrize("action", ["ALLOW", "BLOCK", "DROP", "ALERT", "LOG"])
def test_action_literal_accepts_all_including_LOG(action):
    assert _minimal_security_event(action=action).action == action


def test_action_literal_rejects_off_enum():
    with pytest.raises(ValidationError):
        _minimal_security_event(action="NUKE")


# ---- naming alignment (ADR-0016 / Flag B) ----------------------------------


def test_no_legacy_source_module_field():
    # legacy used source_module; SDK uses the ECS two-axis vocabulary instead.
    assert "source_module" not in SecurityEvent.model_fields
    assert "source_type" in SecurityEvent.model_fields
    assert "source_id" in SecurityEvent.model_fields
    assert "source_module" not in FilterSpec.model_fields
    assert {"source_type", "source_id"} <= set(FilterSpec.model_fields)
    assert "source_modules" not in ThreatScore.model_fields
    assert "source_types" in ThreatScore.model_fields
