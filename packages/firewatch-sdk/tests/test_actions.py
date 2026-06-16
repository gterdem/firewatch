"""Tests for the ADR-0034 SDK action types.

EARS criterion → test mapping
==============================

EARS-ACT-1 (ubiquitous — SDK types exist and are exported):
  The SDK SHALL expose SourceAction, ActionResult, ActionStatus (frozen
  Pydantic v2 models) and the ActionCapable runtime-checkable Protocol.
  -> test_sdk_exports_action_types
  -> test_source_action_is_frozen
  -> test_action_result_is_frozen
  -> test_action_status_is_frozen

EARS-ACT-2 (ubiquitous — SourceAction id validation):
  SourceAction.id MUST match ^[a-z][a-z0-9_]*$.
  -> test_source_action_valid_ids
  -> test_source_action_invalid_id_rejected

EARS-ACT-3 (ubiquitous — SourceMetadata.actions is additive):
  SourceMetadata SHALL gain actions: tuple[SourceAction, ...] = () with
  existing plugins requiring zero edits to keep loading.
  -> test_source_metadata_actions_defaults_to_empty
  -> test_source_metadata_with_actions
  -> test_source_metadata_is_frozen_with_actions

EARS-ACT-4 (ubiquitous — ActionCapable is runtime-checkable):
  ActionCapable is a runtime-checkable Protocol; isinstance works.
  -> test_action_capable_isinstance_positive
  -> test_action_capable_isinstance_negative

EARS-ACT-5 (ubiquitous — NULL_ACTION_STATUS sentinel):
  NULL_ACTION_STATUS is an ActionStatus with all fields at their defaults.
  -> test_null_action_status_defaults

EARS-ACT-6 (ubiquitous — ActionResult defaults):
  ActionResult.detail defaults to empty dict.
  -> test_action_result_defaults
  -> test_action_status_defaults

NB-5 (security — SourceAction.provides element validation):
  Each element of SourceAction.provides MUST match ^[a-z_][a-z0-9_]*$
  and have max_length=64.  Invalid elements SHALL be rejected by Pydantic.
  -> test_source_action_valid_provides_elements
  -> test_source_action_invalid_provides_element_rejected
  -> test_source_action_provides_element_too_long_rejected
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from firewatch_sdk import (
    NULL_ACTION_STATUS,
    ActionCapable,
    ActionResult,
    ActionStatus,
    SourceAction,
    SourceMetadata,
)


# --------------------------------------------------------------------------- #
# EARS-ACT-1: SDK types exist and are exported                                 #
# --------------------------------------------------------------------------- #


def test_sdk_exports_action_types():
    """All four action types are importable from the SDK top-level."""
    # If any of these raise ImportError the test fails at collection time.
    assert SourceAction is not None
    assert ActionResult is not None
    assert ActionStatus is not None
    assert ActionCapable is not None
    assert NULL_ACTION_STATUS is not None


def test_source_action_is_frozen():
    """SourceAction instances are frozen (immutable)."""
    action = SourceAction(id="fetch_rules", label="Fetch Rules", description="Download rules")
    with pytest.raises((TypeError, ValidationError)):
        action.label = "changed"  # type: ignore[misc]


def test_action_result_is_frozen():
    """ActionResult instances are frozen."""
    result = ActionResult(ok=True, message="done")
    with pytest.raises((TypeError, ValidationError)):
        result.ok = False  # type: ignore[misc]


def test_action_status_is_frozen():
    """ActionStatus instances are frozen."""
    status = ActionStatus(last_run_at=1.0)
    with pytest.raises((TypeError, ValidationError)):
        status.last_run_at = 2.0  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# EARS-ACT-2: SourceAction.id validation                                       #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("action_id", [
    "fetch_rules",
    "reload",
    "sync",
    "fetch_ruleset",
    "a",
    "abc123",
    "fetch_rules_now",
])
def test_source_action_valid_ids(action_id: str):
    """SourceAction accepts ids matching ^[a-z][a-z0-9_]*$."""
    action = SourceAction(id=action_id, label="Test", description="Test action")
    assert action.id == action_id


@pytest.mark.parametrize("bad_id", [
    "_fetch",       # leading underscore
    "1fetch",       # leading digit
    "Fetch",        # uppercase
    "fetch-rules",  # hyphen
    "fetch rules",  # space
    "",             # empty
    "FETCH",        # all uppercase
])
def test_source_action_invalid_id_rejected(bad_id: str):
    """SourceAction rejects ids that do not match the pattern."""
    with pytest.raises(ValidationError):
        SourceAction(id=bad_id, label="Test", description="Test action")


# --------------------------------------------------------------------------- #
# EARS-ACT-3: SourceMetadata.actions is additive                              #
# --------------------------------------------------------------------------- #


def test_source_metadata_actions_defaults_to_empty():
    """Existing plugins omitting 'actions' get an empty tuple — zero edits needed."""
    meta = SourceMetadata(
        type_key="syslog",
        display_name="Syslog",
        version="1.0.0",
        flavor="push",
    )
    assert meta.actions == ()


def test_source_metadata_with_actions():
    """A plugin can declare actions in SourceMetadata."""
    action = SourceAction(id="fetch_rules", label="Fetch Rules", description="Download rules")
    meta = SourceMetadata(
        type_key="myplug",
        display_name="My Plugin",
        version="1.0.0",
        flavor="pull",
        actions=(action,),
    )
    assert len(meta.actions) == 1
    assert meta.actions[0].id == "fetch_rules"


def test_source_metadata_is_frozen_with_actions():
    """SourceMetadata with actions is still frozen."""
    action = SourceAction(id="reload", label="Reload", description="Reload config")
    meta = SourceMetadata(
        type_key="myplug",
        display_name="My Plugin",
        version="1.0.0",
        flavor="pull",
        actions=(action,),
    )
    with pytest.raises((TypeError, ValidationError)):
        meta.actions = ()  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# EARS-ACT-4: ActionCapable is runtime-checkable                              #
# --------------------------------------------------------------------------- #


class _GoodCapable:
    """Minimal class satisfying the ActionCapable protocol structurally."""
    async def run_action(self, action_id: str, cfg: object, ctx: object) -> ActionResult:
        return ActionResult(ok=True, message="done")

    async def action_status(self, action_id: str, cfg: object, ctx: object) -> ActionStatus:
        return ActionStatus()


class _MissingRunAction:
    """Has action_status but not run_action — does NOT satisfy ActionCapable."""
    async def action_status(self, action_id: str, cfg: object, ctx: object) -> ActionStatus:
        return ActionStatus()


class _Empty:
    """Has neither method."""
    pass


def test_action_capable_isinstance_positive():
    """A class implementing both run_action and action_status satisfies ActionCapable."""
    assert isinstance(_GoodCapable(), ActionCapable)


def test_action_capable_isinstance_negative():
    """A class missing run_action does not satisfy ActionCapable."""
    assert not isinstance(_MissingRunAction(), ActionCapable)
    assert not isinstance(_Empty(), ActionCapable)


# --------------------------------------------------------------------------- #
# EARS-ACT-5: NULL_ACTION_STATUS sentinel                                     #
# --------------------------------------------------------------------------- #


def test_null_action_status_defaults():
    """NULL_ACTION_STATUS is an ActionStatus with all fields at defaults."""
    assert NULL_ACTION_STATUS.last_run_at is None
    assert NULL_ACTION_STATUS.stale is None
    assert NULL_ACTION_STATUS.message is None
    assert NULL_ACTION_STATUS.detail == {}


# --------------------------------------------------------------------------- #
# EARS-ACT-6: default field values                                             #
# --------------------------------------------------------------------------- #


def test_action_result_defaults():
    """ActionResult.detail defaults to empty dict."""
    result = ActionResult(ok=True, message="ok")
    assert result.detail == {}


def test_action_status_defaults():
    """ActionStatus all fields default to None/empty."""
    status = ActionStatus()
    assert status.last_run_at is None
    assert status.stale is None
    assert status.message is None
    assert status.detail == {}


def test_source_action_all_defaults():
    """SourceAction fields long_running, confirm, provides have correct defaults."""
    action = SourceAction(id="sync", label="Sync", description="Sync now")
    assert action.long_running is False
    assert action.confirm is None
    assert action.provides == ()


def test_source_action_provides_tuple():
    """SourceAction.provides accepts a tuple of strings."""
    action = SourceAction(
        id="fetch",
        label="Fetch",
        description="Fetch rules",
        provides=("rule_descriptions",),
    )
    assert action.provides == ("rule_descriptions",)


# --------------------------------------------------------------------------- #
# NB-5: SourceAction.provides element validation                              #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("tag", [
    "rule_descriptions",
    "rules",
    "_internal",
    "_rule_data",
    "abc123",
    "a",
    "_",
])
def test_source_action_valid_provides_elements(tag: str):
    """NB-5: provides elements matching ^[a-z_][a-z0-9_]*$ are accepted."""
    action = SourceAction(
        id="fetch",
        label="Fetch",
        description="Fetch rules",
        provides=(tag,),
    )
    assert tag in action.provides


@pytest.mark.parametrize("bad_tag", [
    "Rule_Descriptions",   # uppercase
    "rule-descriptions",   # hyphen
    "1rules",              # leading digit
    "fetch rules",         # space
    "fetch/rules",         # slash
    "",                    # empty string
])
def test_source_action_invalid_provides_element_rejected(bad_tag: str):
    """NB-5: provides elements not matching the pattern are rejected by Pydantic."""
    with pytest.raises(ValidationError):
        SourceAction(
            id="fetch",
            label="Fetch",
            description="Fetch rules",
            provides=(bad_tag,),
        )


def test_source_action_provides_element_too_long_rejected():
    """NB-5: a provides element exceeding 64 characters is rejected."""
    long_tag = "a" * 65
    with pytest.raises(ValidationError):
        SourceAction(
            id="fetch",
            label="Fetch",
            description="Fetch rules",
            provides=(long_tag,),
        )
