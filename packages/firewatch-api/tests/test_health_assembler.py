"""Tests for the source-health assembler (ADR-0032, issue #133).

EARS → test mapping
────────────────────

U1 (ubiquitous — generic):
  The assembler SHALL NOT hard-code any source name; it iterates the registry.
  → test_assembler_is_generic_over_source_type

A1 (event-driven — list membership from registry):
  WHEN assemble_source_health is called, the result SHALL contain one entry
  per installed plugin regardless of whether it has events.
  → test_one_entry_per_installed_plugin
  → test_installed_plugin_with_no_events_appears

A2 (event-driven — event counts and recency):
  WHEN a plugin has store rows, event_count and last_event_at SHALL reflect them.
  → test_event_count_and_last_event_at_populated_from_store

A3 (state-driven — supervisor present):
  WHILE supervisor is injected, each entry SHALL carry supervisor_state and last_error.
  → test_supervisor_state_included_when_supervisor_present
  → test_supervisor_absent_gives_null_state

A4 (event-driven — health computation):
  red   if supervisor_state is parked or backoff
  → test_health_red_when_supervisor_parked
  → test_health_red_when_supervisor_backoff
  → test_health_red_when_last_error_set

  not_configured  if no config section
  → test_health_not_configured_when_no_config

  ok if configured and recent events
  → test_health_ok_when_recent_events

  amber if configured and no events
  → test_health_amber_when_configured_no_events

  amber if configured and stale events
  → test_health_amber_when_stale_events

A5 (red beats ok — precedence):
  A supervisor error MUST override recency (red beats ok).
  → test_red_beats_ok

A6 (no supervisor — 503-safe degradation):
  WHILE no supervisor is injected, health SHALL be not_configured/amber/ok (never red),
  and the route SHALL still return 200.
  → test_no_supervisor_health_never_red

C1 (contract — exhaustive vocabulary lock, issue #279):
  The assembler SHALL only ever emit health ∈ {ok, amber, red, not_configured}.
  → test_assembler_emits_only_canonical_vocabulary

A7 (security — no secrets echoed):
  source_health[] entries SHALL carry only identity/health fields.
  → test_no_secret_fields_in_entries

A8 (resilience — failing plugin metadata does not break response):
  A plugin whose metadata() raises SHALL be omitted without a 500.
  → test_failing_plugin_metadata_omitted

Hardening tests (issue #147):

NB-1 (last_error sanitization — value-level):
  WHEN last_error contains IP addresses or credential-pattern substrings,
  the sanitized value returned in source_health[] SHALL NOT contain them.
  → test_last_error_ip_address_stripped
  → test_last_error_credential_pattern_stripped
  → test_last_error_truncated_at_200_chars
  → test_last_error_benign_message_preserved
  → test_last_error_none_remains_none

NB-2 (_has_config broad except returns False):
  WHEN the config store raises an unexpected exception (not KeyError/AttributeError),
  _has_config SHALL return False, showing the source as not_configured (grey).
  → test_has_config_unexpected_exception_returns_false

NB-3 (source_id cardinality cap per type):
  WHEN more than SOURCE_ID_CAP_PER_TYPE unique source_ids exist for a type,
  _instance_ids_for_type SHALL return at most SOURCE_ID_CAP_PER_TYPE entries
  and emit a warning log.
  → test_instance_ids_cardinality_cap_enforced
  → test_instance_ids_under_cap_unaffected

Orphan reconciliation tests (issue #280, ADR-0031/ADR-0032):

OR-1 (main regression — orphan bare-type id dropped when shadowed by named instance):
  WHEN source_id == source_type AND event_count == 0 AND at least one other
  source_id for the same type exists (from supervisor or store), THEN
  _instance_ids_for_type SHALL exclude the bare-type id (stale pre-instance-naming
  registration) so it does NOT produce a duplicate health entry.
  → test_orphan_bare_type_id_dropped_when_shadowed_by_named_instance
  → test_orphan_bare_type_id_dropped_integration

OR-2 (bare id with events is kept — not an orphan):
  WHEN source_id == source_type AND event_count > 0, the id MUST NOT be dropped
  (it is a legitimately-named instance whose source_id happens to equal the type_key).
  → test_bare_type_id_with_events_not_dropped

OR-3 (single bare id with no other instance is kept — fallback row, not orphan):
  WHEN source_id == source_type AND no other source_id exists for the type, the
  id is NOT an orphan — it is the normal default or the only known instance, and
  MUST remain so the fallback grey row logic still fires.
  → test_single_bare_type_id_without_other_instances_kept

OR-4 (named instance only — no bare id in play — unaffected):
  WHEN only a named instance (source_id != source_type) exists, no orphan
  reconciliation applies; the named instance is kept.
  → test_named_instance_only_unaffected_by_orphan_reconciliation

OR-5 (multi-type safety — reconciliation is per-type, not cross-type):
  Orphan reconciliation for one source type MUST NOT affect other types.
  → test_orphan_reconciliation_does_not_affect_other_types
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import BaseModel

from firewatch_api.health_assembler import (
    FRESHNESS_MINUTES,
    SOURCE_ID_CAP_PER_TYPE,
    assemble_source_health,
    _compute_health,
    _epoch_to_iso,
    _has_config,
    _instance_ids_for_type,
    _sanitize_error,
    _supervisor_map,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeMeta:
    def __init__(self, type_key: str, display_name: str = "Fake", flavor: str = "pull") -> None:
        self.type_key = type_key
        self.display_name = display_name
        self.flavor = flavor


class _FakePlugin:
    def __init__(
        self,
        type_key: str,
        display_name: str = "Fake",
        flavor: str = "pull",
        raise_on_metadata: bool = False,
    ) -> None:
        self._type_key = type_key
        self._display_name = display_name
        self._flavor = flavor
        self._raise = raise_on_metadata

    def metadata(self) -> _FakeMeta:
        if self._raise:
            raise RuntimeError("simulated metadata failure")
        return _FakeMeta(self._type_key, self._display_name, self._flavor)

    def config_schema(self) -> type[BaseModel]:
        class _Cfg(BaseModel):
            pass
        return _Cfg


class _FakeStatus:
    def __init__(
        self,
        source_type: str,
        source_id: str,
        state: str = "running",
        last_error: str | None = None,
    ) -> None:
        self.source_type = source_type
        self.source_id = source_id
        self.state = state
        self.last_error = last_error


class _FakeSupervisor:
    def __init__(self, statuses: list[_FakeStatus] | None = None) -> None:
        self._statuses = statuses or []

    def status(self) -> list[_FakeStatus]:
        return list(self._statuses)


class _FakeConfigStore:
    """Config store that reports whether a source key is present."""

    def __init__(self, configured_types: set[str] | None = None) -> None:
        self._configured = configured_types or set()

    def get_source_raw(self, type_key: str) -> dict[str, Any]:
        if type_key in self._configured:
            return {"host": "example.internal"}
        raise KeyError(type_key)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _recent_ts() -> str:
    """ISO timestamp within the freshness window."""
    dt = datetime.now(timezone.utc) - timedelta(minutes=FRESHNESS_MINUTES - 1)
    return dt.isoformat()


def _stale_ts() -> str:
    """ISO timestamp outside the freshness window."""
    dt = datetime.now(timezone.utc) - timedelta(minutes=FRESHNESS_MINUTES + 10)
    return dt.isoformat()


def _store_row(
    source_type: str,
    source_id: str,
    event_count: int = 1,
    last_event_at: str | None = None,
) -> dict[str, Any]:
    return {
        "source_type": source_type,
        "source_id": source_id,
        "event_count": event_count,
        "last_event_at": last_event_at or _recent_ts(),
    }


# ---------------------------------------------------------------------------
# _compute_health unit tests
# ---------------------------------------------------------------------------


def test_compute_health_red_parked() -> None:
    assert _compute_health(
        has_config=True,
        last_event_at=_recent_ts(),
        supervisor_state="parked",
        last_error=None,
    ) == "red"


def test_compute_health_red_backoff() -> None:
    assert _compute_health(
        has_config=True,
        last_event_at=_recent_ts(),
        supervisor_state="backoff",
        last_error=None,
    ) == "red"


def test_compute_health_red_last_error() -> None:
    assert _compute_health(
        has_config=True,
        last_event_at=_recent_ts(),
        supervisor_state="running",
        last_error="connection refused",
    ) == "red"


def test_compute_health_not_configured() -> None:
    assert _compute_health(
        has_config=False,
        last_event_at=None,
        supervisor_state=None,
        last_error=None,
    ) == "not_configured"


def test_compute_health_ok_recent() -> None:
    """Canonical vocabulary: fresh events → "ok" (ADR-0032 §B, issue #279 erratum)."""
    assert _compute_health(
        has_config=True,
        last_event_at=_recent_ts(),
        supervisor_state="running",
        last_error=None,
    ) == "ok"


def test_compute_health_amber_no_events() -> None:
    assert _compute_health(
        has_config=True,
        last_event_at=None,
        supervisor_state=None,
        last_error=None,
    ) == "amber"


def test_compute_health_amber_stale() -> None:
    assert _compute_health(
        has_config=True,
        last_event_at=_stale_ts(),
        supervisor_state="running",
        last_error=None,
    ) == "amber"


# ---------------------------------------------------------------------------
# assemble_source_health tests
# ---------------------------------------------------------------------------


def test_one_entry_per_installed_plugin() -> None:
    """A1: one entry per plugin in the registry."""
    registry = {
        "suricata": _FakePlugin("suricata"),
        "azure_waf": _FakePlugin("azure_waf"),
    }
    result = assemble_source_health(
        registry=registry,
        store_rows=[],
        supervisor=None,
        config_store=None,
    )
    assert len(result) == 2
    types = {e["source_type"] for e in result}
    assert types == {"suricata", "azure_waf"}


def test_installed_plugin_with_no_events_appears() -> None:
    """A1: a plugin with no store rows still appears with zero event_count."""
    registry = {"suricata": _FakePlugin("suricata")}
    result = assemble_source_health(
        registry=registry,
        store_rows=[],
        supervisor=None,
        config_store=None,
    )
    assert len(result) == 1
    entry = result[0]
    assert entry["event_count"] == 0
    assert entry["last_event_at"] is None


def test_event_count_and_last_event_at_populated_from_store() -> None:
    """A2: event_count and last_event_at come from store rows."""
    ts = _recent_ts()
    registry = {"suricata": _FakePlugin("suricata")}
    store_rows = [_store_row("suricata", "suricata", event_count=42, last_event_at=ts)]
    result = assemble_source_health(
        registry=registry,
        store_rows=store_rows,
        supervisor=None,
        config_store=None,
    )
    assert result[0]["event_count"] == 42
    assert result[0]["last_event_at"] == ts


def test_supervisor_state_included_when_supervisor_present() -> None:
    """A3: supervisor_state is populated when supervisor is injected."""
    registry = {"suricata": _FakePlugin("suricata")}
    sup = _FakeSupervisor([_FakeStatus("suricata", "suricata", state="running")])
    result = assemble_source_health(
        registry=registry,
        store_rows=[],
        supervisor=sup,
        config_store=None,
    )
    assert result[0]["supervisor_state"] == "running"


def test_supervisor_absent_gives_null_state() -> None:
    """A3: supervisor_state is null when no supervisor is injected."""
    registry = {"suricata": _FakePlugin("suricata")}
    result = assemble_source_health(
        registry=registry,
        store_rows=[],
        supervisor=None,
        config_store=None,
    )
    assert result[0]["supervisor_state"] is None
    assert result[0]["last_error"] is None


def test_health_red_when_supervisor_parked() -> None:
    """A4: health=red when supervisor state is parked."""
    registry = {"suricata": _FakePlugin("suricata")}
    sup = _FakeSupervisor([_FakeStatus("suricata", "suricata", state="parked")])
    cfg = _FakeConfigStore(configured_types={"suricata"})
    result = assemble_source_health(
        registry=registry,
        store_rows=[_store_row("suricata", "suricata")],
        supervisor=sup,
        config_store=cfg,
    )
    assert result[0]["health"] == "red"


def test_health_red_when_supervisor_backoff() -> None:
    """A4: health=red when supervisor state is backoff."""
    registry = {"suricata": _FakePlugin("suricata")}
    sup = _FakeSupervisor([_FakeStatus("suricata", "suricata", state="backoff")])
    cfg = _FakeConfigStore(configured_types={"suricata"})
    result = assemble_source_health(
        registry=registry,
        store_rows=[_store_row("suricata", "suricata")],
        supervisor=sup,
        config_store=cfg,
    )
    assert result[0]["health"] == "red"


def test_health_red_when_last_error_set() -> None:
    """A4: health=red when last_error is set on supervisor status."""
    registry = {"suricata": _FakePlugin("suricata")}
    sup = _FakeSupervisor([
        _FakeStatus("suricata", "suricata", state="running", last_error="timeout")
    ])
    cfg = _FakeConfigStore(configured_types={"suricata"})
    result = assemble_source_health(
        registry=registry,
        store_rows=[_store_row("suricata", "suricata")],
        supervisor=sup,
        config_store=cfg,
    )
    assert result[0]["health"] == "red"


def test_health_not_configured_when_no_config() -> None:
    """A4: health=not_configured when no config section."""
    registry = {"suricata": _FakePlugin("suricata")}
    # config_store has no entry for "suricata"
    cfg = _FakeConfigStore(configured_types=set())
    result = assemble_source_health(
        registry=registry,
        store_rows=[],
        supervisor=None,
        config_store=cfg,
    )
    assert result[0]["health"] == "not_configured"


def test_health_ok_when_recent_events() -> None:
    """A4: health=ok when configured and events are recent (ADR-0032 §B, issue #279)."""
    registry = {"suricata": _FakePlugin("suricata")}
    cfg = _FakeConfigStore(configured_types={"suricata"})
    result = assemble_source_health(
        registry=registry,
        store_rows=[_store_row("suricata", "suricata", last_event_at=_recent_ts())],
        supervisor=None,
        config_store=cfg,
    )
    assert result[0]["health"] == "ok"


def test_health_amber_when_configured_no_events() -> None:
    """A4: health=amber when configured but no events."""
    registry = {"suricata": _FakePlugin("suricata")}
    cfg = _FakeConfigStore(configured_types={"suricata"})
    result = assemble_source_health(
        registry=registry,
        store_rows=[],
        supervisor=None,
        config_store=cfg,
    )
    assert result[0]["health"] == "amber"


def test_health_amber_when_stale_events() -> None:
    """A4: health=amber when configured and last event is stale."""
    registry = {"suricata": _FakePlugin("suricata")}
    cfg = _FakeConfigStore(configured_types={"suricata"})
    result = assemble_source_health(
        registry=registry,
        store_rows=[_store_row("suricata", "suricata", last_event_at=_stale_ts())],
        supervisor=None,
        config_store=cfg,
    )
    assert result[0]["health"] == "amber"


def test_red_beats_ok() -> None:
    """A5: supervisor error overrides recency — red beats ok (ADR-0032 Decision C)."""
    registry = {"suricata": _FakePlugin("suricata")}
    sup = _FakeSupervisor([_FakeStatus("suricata", "suricata", state="parked")])
    cfg = _FakeConfigStore(configured_types={"suricata"})
    result = assemble_source_health(
        registry=registry,
        store_rows=[_store_row("suricata", "suricata", last_event_at=_recent_ts())],
        supervisor=sup,
        config_store=cfg,
    )
    assert result[0]["health"] == "red"


def test_no_supervisor_health_never_red() -> None:
    """A6: without a supervisor, health is never red (only not_configured/amber/ok)."""
    registry = {
        "suricata": _FakePlugin("suricata"),
        "azure_waf": _FakePlugin("azure_waf"),
    }
    cfg = _FakeConfigStore(configured_types={"suricata"})
    result = assemble_source_health(
        registry=registry,
        store_rows=[_store_row("suricata", "suricata", last_event_at=_recent_ts())],
        supervisor=None,
        config_store=cfg,
    )
    healths = {e["health"] for e in result}
    assert "red" not in healths


def test_assembler_emits_only_canonical_vocabulary() -> None:
    """C1 (issue #279): assembler ONLY ever emits health ∈ {ok, amber, red, not_configured}.

    Exhaustive contract test: exercises every reachable branch of _compute_health
    (ok, amber-no-events, amber-stale, red-parked, red-backoff, red-last_error,
    not_configured) and asserts each result is in the canonical set.

    Any future vocabulary drift (e.g. re-introducing "green") will fail CI here
    before it ships a gray dot to the analyst.
    """
    _CANONICAL: frozenset[str] = frozenset({"ok", "amber", "red", "not_configured"})

    # Branch: ok — configured source with recent events, running supervisor
    assert _compute_health(
        has_config=True,
        last_event_at=_recent_ts(),
        supervisor_state="running",
        last_error=None,
    ) in _CANONICAL

    # Branch: amber — configured, no events
    assert _compute_health(
        has_config=True,
        last_event_at=None,
        supervisor_state=None,
        last_error=None,
    ) in _CANONICAL

    # Branch: amber — configured, stale events
    assert _compute_health(
        has_config=True,
        last_event_at=_stale_ts(),
        supervisor_state="running",
        last_error=None,
    ) in _CANONICAL

    # Branch: red — parked supervisor
    assert _compute_health(
        has_config=True,
        last_event_at=_recent_ts(),
        supervisor_state="parked",
        last_error=None,
    ) in _CANONICAL

    # Branch: red — backoff supervisor
    assert _compute_health(
        has_config=True,
        last_event_at=_recent_ts(),
        supervisor_state="backoff",
        last_error=None,
    ) in _CANONICAL

    # Branch: red — last_error set
    assert _compute_health(
        has_config=True,
        last_event_at=_recent_ts(),
        supervisor_state="running",
        last_error="connection refused",
    ) in _CANONICAL

    # Branch: not_configured — no config section
    assert _compute_health(
        has_config=False,
        last_event_at=None,
        supervisor_state=None,
        last_error=None,
    ) in _CANONICAL

    # Exhaustive value check: confirm the exact return values (not just membership).
    # If someone adds a new branch returning a different string, this catches it.
    assert _compute_health(
        has_config=True,
        last_event_at=_recent_ts(),
        supervisor_state="running",
        last_error=None,
    ) == "ok"

    assert _compute_health(
        has_config=False,
        last_event_at=None,
        supervisor_state=None,
        last_error=None,
    ) == "not_configured"


def test_no_secret_fields_in_entries() -> None:
    """A7: entries carry only identity/health fields — no secrets."""
    registry = {"suricata": _FakePlugin("suricata")}
    result = assemble_source_health(
        registry=registry,
        store_rows=[],
        supervisor=None,
        config_store=None,
    )
    entry = result[0]
    forbidden = {"password", "token", "secret", "key", "credential", "api_key"}
    for field in forbidden:
        assert field not in entry, f"Secret field {field!r} must not appear in entry"
    # Ensure all expected identity/health fields are present
    for expected in (
        "source_type", "source_id", "display_name", "flavor",
        "health", "supervisor_state", "last_event_at", "event_count", "last_error",
    ):
        assert expected in entry, f"Expected field {expected!r} missing from entry"


def test_failing_plugin_metadata_omitted() -> None:
    """A8: a plugin whose metadata() raises is omitted without breaking the response."""
    registry = {
        "broken": _FakePlugin("broken", raise_on_metadata=True),
        "suricata": _FakePlugin("suricata"),
    }
    result = assemble_source_health(
        registry=registry,
        store_rows=[],
        supervisor=None,
        config_store=None,
    )
    # "broken" must be absent; "suricata" must still appear
    types = {e["source_type"] for e in result}
    assert "broken" not in types
    assert "suricata" in types


def test_assembler_is_generic_over_source_type() -> None:
    """U1: assembler does not hard-code any source name."""
    # Use an entirely novel source type name — assembler must handle it.
    registry = {"my_custom_source": _FakePlugin("my_custom_source")}
    result = assemble_source_health(
        registry=registry,
        store_rows=[_store_row("my_custom_source", "my_custom_source")],
        supervisor=None,
        config_store=None,
    )
    assert len(result) == 1
    assert result[0]["source_type"] == "my_custom_source"


# ---------------------------------------------------------------------------
# Regression tests for issue #144
# ---------------------------------------------------------------------------


def test_custom_source_id_instance_reflected() -> None:
    """A1 (issue #144): installed suricata running as 'vm-target' with 50 events.

    The health row MUST reflect source_id='vm-target' and event_count=50.
    It MUST NOT produce an empty suricata/suricata row.

    Fixture IP 192.0.2.10 is from RFC 5737 documentation range (non-routable).
    """
    registry = {"suricata": _FakePlugin("suricata")}
    # Store row uses the real instance name, not the type_key
    store_rows = [_store_row("suricata", "vm-target", event_count=50, last_event_at=_recent_ts())]
    # Supervisor also knows the instance as "vm-target"
    sup = _FakeSupervisor([_FakeStatus("suricata", "vm-target", state="running")])
    cfg = _FakeConfigStore(configured_types={"suricata"})

    result = assemble_source_health(
        registry=registry,
        store_rows=store_rows,
        supervisor=sup,
        config_store=cfg,
    )

    # Exactly one row for suricata
    suricata_rows = [e for e in result if e["source_type"] == "suricata"]
    assert len(suricata_rows) == 1, "Expected exactly one row for suricata"

    row = suricata_rows[0]
    # Must reflect the real instance, not synthesise type_key/type_key
    assert row["source_id"] == "vm-target", (
        f"Expected source_id='vm-target', got {row['source_id']!r} — "
        "assembler is inventing a type_key row instead of joining the real instance"
    )
    assert row["event_count"] == 50, (
        f"Expected event_count=50, got {row['event_count']} — missed vm-target's events"
    )
    assert row["health"] in {"ok", "amber"}, (
        f"Expected ok or amber (recent events, no error), got {row['health']!r}"
    )


def test_no_instance_falls_back_to_grey_row() -> None:
    """A2 (issue #144): installed-but-not-configured source produces one grey row keyed by type_key.

    No supervisor instance, no store rows, no config → not_configured (grey).
    """
    registry = {"syslog": _FakePlugin("syslog")}
    cfg = _FakeConfigStore(configured_types=set())  # syslog not configured

    result = assemble_source_health(
        registry=registry,
        store_rows=[],
        supervisor=None,
        config_store=cfg,
    )

    assert len(result) == 1
    row = result[0]
    assert row["source_type"] == "syslog"
    assert row["source_id"] == "syslog"
    assert row["health"] == "not_configured"
    assert row["event_count"] == 0
    assert row["last_event_at"] is None


def test_multi_instance_produces_one_row_per_instance() -> None:
    """A3 (issue #144): two running instances of one type → two separate health rows, no crash.

    Instance IPs in comments use RFC 5737 range (192.0.2.0/24) — non-routable.
    inst-a represents host at 192.0.2.10; inst-b represents host at 192.0.2.20.
    """
    registry = {"suricata": _FakePlugin("suricata")}
    store_rows = [
        _store_row("suricata", "inst-a", event_count=30, last_event_at=_recent_ts()),
        _store_row("suricata", "inst-b", event_count=20, last_event_at=_stale_ts()),
    ]
    sup = _FakeSupervisor([
        _FakeStatus("suricata", "inst-a", state="running"),
        _FakeStatus("suricata", "inst-b", state="running"),
    ])
    cfg = _FakeConfigStore(configured_types={"suricata"})

    result = assemble_source_health(
        registry=registry,
        store_rows=store_rows,
        supervisor=sup,
        config_store=cfg,
    )

    suricata_rows = [e for e in result if e["source_type"] == "suricata"]
    assert len(suricata_rows) == 2, f"Expected 2 rows for 2 instances, got {len(suricata_rows)}"

    by_id = {r["source_id"]: r for r in suricata_rows}
    assert "inst-a" in by_id
    assert "inst-b" in by_id
    assert by_id["inst-a"]["event_count"] == 30
    assert by_id["inst-b"]["event_count"] == 20
    assert by_id["inst-a"]["health"] == "ok"
    assert by_id["inst-b"]["health"] == "amber"


def test_not_configured_shows_grey_not_amber() -> None:
    """A4 (issue #144): installed source with no config section shows grey (not_configured), not amber.

    Previously the _has_config fallback (except Exception: return True) could
    make a no-config source show amber.  This regression test pins the correct behaviour.
    """
    registry = {"azure_waf": _FakePlugin("azure_waf")}
    # config_store present but azure_waf has no entry
    cfg = _FakeConfigStore(configured_types=set())

    result = assemble_source_health(
        registry=registry,
        store_rows=[],
        supervisor=None,
        config_store=cfg,
    )

    assert len(result) == 1
    assert result[0]["health"] == "not_configured", (
        f"Expected not_configured (grey), got {result[0]['health']!r} — "
        "not-configured source must not show amber"
    )


def test_red_beats_grey_for_stale_erroring_instance() -> None:
    """A5 (issue #144): supervisor error/parked still fires red even when source has no config.

    Per ADR-0032 C: red is priority 1 and beats everything, including grey.
    This covers the edge case where config was removed but a stale instance is stuck in error.
    """
    registry = {"suricata": _FakePlugin("suricata")}
    # No config section — would normally be grey
    cfg = _FakeConfigStore(configured_types=set())
    # But there is a stale instance stuck in parked/error state
    sup = _FakeSupervisor([_FakeStatus("suricata", "suricata", state="parked")])

    result = assemble_source_health(
        registry=registry,
        store_rows=[],
        supervisor=sup,
        config_store=cfg,
    )

    assert len(result) == 1
    assert result[0]["health"] == "red", (
        f"Expected red (supervisor parked beats grey), got {result[0]['health']!r}"
    )


def test_default_source_id_still_works() -> None:
    """A6 (issue #144): when source_id == type_key (the default), existing behaviour is preserved."""
    registry = {"azure_waf": _FakePlugin("azure_waf")}
    ts = _recent_ts()
    store_rows = [_store_row("azure_waf", "azure_waf", event_count=100, last_event_at=ts)]
    sup = _FakeSupervisor([_FakeStatus("azure_waf", "azure_waf", state="running")])
    cfg = _FakeConfigStore(configured_types={"azure_waf"})

    result = assemble_source_health(
        registry=registry,
        store_rows=store_rows,
        supervisor=sup,
        config_store=cfg,
    )

    assert len(result) == 1
    row = result[0]
    assert row["source_id"] == "azure_waf"
    assert row["event_count"] == 100
    assert row["last_event_at"] == ts
    assert row["health"] == "ok"


# ---------------------------------------------------------------------------
# Hardening tests (issue #147)
# ---------------------------------------------------------------------------

_IP_PATTERN = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


def test_last_error_ip_address_stripped() -> None:
    """NB-1: last_error values containing IPv4 addresses are sanitized before reaching /stats.

    RFC 5737 documentation IPs (192.0.2.x, 198.51.100.x, 203.0.113.x) plus
    RFC 1918 and loopback are used in the fixture — all must be stripped.
    """
    raw_errors = [
        "Connection refused: 192.0.2.55:22",
        "SSH banner from 198.51.100.10: OpenSSH_8.9",
        "Timeout connecting to host 203.0.113.99 port 514",
        "10.0.0.1 unreachable",
        "172.16.5.3: connection reset",
        "192.168.1.254 auth failed",
    ]
    for raw in raw_errors:
        sanitized = _sanitize_error(raw)
        assert sanitized is not None
        assert not _IP_PATTERN.search(sanitized), (
            f"IP address found in sanitized last_error {sanitized!r} "
            f"(original: {raw!r})"
        )


def test_last_error_credential_pattern_stripped() -> None:
    """NB-1: last_error values containing credential-looking tokens are sanitized.

    Patterns stripped include: password=, token=, key=, secret=, credential=.
    """
    cases: list[tuple[str, list[str]]] = [
        ("Auth failed: password=hunter2", ["hunter2"]),
        ("Invalid token=eyJhbGciOiJIUzI1NiJ9.payload", ["eyJhbGciOiJIUzI1NiJ9.payload"]),
        ("API key=sk-abc123def456 rejected", ["sk-abc123def456"]),
        ("secret=supersecret leaked", ["supersecret"]),
        ("credential=mypassword invalid", ["mypassword"]),
    ]
    for raw, forbidden_values in cases:
        sanitized = _sanitize_error(raw)
        assert sanitized is not None
        for bad in forbidden_values:
            assert bad not in sanitized, (
                f"Credential value {bad!r} found in sanitized last_error "
                f"{sanitized!r} (original: {raw!r})"
            )


def test_last_error_truncated_at_200_chars() -> None:
    """NB-1: last_error values longer than 200 characters are truncated."""
    long_msg = "x" * 300
    sanitized = _sanitize_error(long_msg)
    assert sanitized is not None
    assert len(sanitized) <= 200, (
        f"Expected sanitized error to be at most 200 chars, got {len(sanitized)}"
    )


def test_last_error_benign_message_preserved() -> None:
    """NB-1: sanitization does not destroy benign error messages."""
    benign = "connection timeout after 30s"
    sanitized = _sanitize_error(benign)
    assert sanitized == benign, (
        f"Benign error message altered: {sanitized!r} != {benign!r}"
    )


def test_last_error_none_remains_none() -> None:
    """NB-1: _sanitize_error(None) returns None (no last_error present)."""
    assert _sanitize_error(None) is None


def test_last_error_sanitized_in_assembled_entry() -> None:
    """NB-1 (integration): last_error in assembled source_health[] row is sanitized.

    Ensures sanitization is applied end-to-end by assemble_source_health.
    Fixture IP is RFC 5737 (192.0.2.5) — non-routable documentation range.
    """
    registry = {"suricata": _FakePlugin("suricata")}
    sup = _FakeSupervisor([
        _FakeStatus(
            "suricata", "suricata",
            state="backoff",
            last_error="SSH connection refused: 192.0.2.5:22",
        )
    ])
    cfg = _FakeConfigStore(configured_types={"suricata"})
    result = assemble_source_health(
        registry=registry,
        store_rows=[],
        supervisor=sup,
        config_store=cfg,
    )
    assert len(result) == 1
    row = result[0]
    assert row["last_error"] is not None, "last_error should be set (supervisor reported error)"
    assert not _IP_PATTERN.search(row["last_error"]), (
        f"IP address leaked in assembled last_error: {row['last_error']!r}"
    )


def test_has_config_unexpected_exception_returns_false() -> None:
    """NB-2: _has_config returns False (not True) on unexpected config-store errors.

    Previously `except Exception: return True` silently reported the source as
    configured on any store failure. The fix returns False so the source shows
    as not_configured (grey) rather than amber.
    """

    class _BrokenConfigStore:
        def get_source_raw(self, type_key: str) -> dict[str, object]:
            raise RuntimeError("disk I/O error — simulated store failure")

    result = _has_config(_BrokenConfigStore(), "suricata")
    assert result is False, (
        "Expected _has_config to return False on unexpected store exception, "
        f"got {result!r} — broad except must not silently report 'configured'"
    )


def test_has_config_unexpected_exception_shows_grey_in_assembler() -> None:
    """NB-2 (integration): a broken config store shows not_configured (grey) in /stats."""

    class _BrokenConfigStore:
        def get_source_raw(self, type_key: str) -> dict[str, object]:
            raise RuntimeError("simulated store failure")

    registry = {"suricata": _FakePlugin("suricata")}
    result = assemble_source_health(
        registry=registry,
        store_rows=[],
        supervisor=None,
        config_store=_BrokenConfigStore(),
    )
    assert len(result) == 1
    assert result[0]["health"] == "not_configured", (
        f"Expected not_configured (grey) when config store raises unexpectedly, "
        f"got {result[0]['health']!r}"
    )


def test_instance_ids_cardinality_cap_enforced() -> None:
    """NB-3: _instance_ids_for_type caps unique source_ids at SOURCE_ID_CAP_PER_TYPE."""
    type_key = "suricata"
    over_limit = SOURCE_ID_CAP_PER_TYPE + 10
    store_map: dict[tuple[str, str], dict[str, object]] = {
        (type_key, f"inst-{i}"): {"event_count": 1, "last_event_at": None}
        for i in range(over_limit)
    }
    sup_map: dict[tuple[str, str], dict[str, object]] = {}

    ids = _instance_ids_for_type(type_key, sup_map, store_map)
    assert len(ids) <= SOURCE_ID_CAP_PER_TYPE, (
        f"Expected at most {SOURCE_ID_CAP_PER_TYPE} source_ids, got {len(ids)}"
    )


def test_instance_ids_cardinality_cap_warning_logged(caplog: pytest.LogCaptureFixture) -> None:
    """NB-3: a WARNING is emitted when the cardinality cap is hit."""
    type_key = "suricata"
    over_limit = SOURCE_ID_CAP_PER_TYPE + 5
    store_map: dict[tuple[str, str], dict[str, object]] = {
        (type_key, f"inst-{i}"): {"event_count": 1, "last_event_at": None}
        for i in range(over_limit)
    }
    sup_map: dict[tuple[str, str], dict[str, object]] = {}

    with caplog.at_level(logging.WARNING):
        ids = _instance_ids_for_type(type_key, sup_map, store_map)

    assert len(ids) <= SOURCE_ID_CAP_PER_TYPE
    assert any("cap" in record.message.lower() or "cardinality" in record.message.lower()
               for record in caplog.records), (
        "Expected a warning log about cardinality cap being hit"
    )


def test_instance_ids_under_cap_unaffected() -> None:
    """NB-3: when source_id count is under SOURCE_ID_CAP_PER_TYPE, all ids are returned."""
    type_key = "suricata"
    count = SOURCE_ID_CAP_PER_TYPE - 1
    store_map: dict[tuple[str, str], dict[str, object]] = {
        (type_key, f"inst-{i}"): {"event_count": 1, "last_event_at": None}
        for i in range(count)
    }
    sup_map: dict[tuple[str, str], dict[str, object]] = {}

    ids = _instance_ids_for_type(type_key, sup_map, store_map)
    assert len(ids) == count, (
        f"Expected all {count} source_ids (under cap), got {len(ids)}"
    )


# ---------------------------------------------------------------------------
# Orphan reconciliation tests (issue #280, ADR-0031 §B / ADR-0032)
# ---------------------------------------------------------------------------


def test_orphan_bare_type_id_dropped_when_shadowed_by_named_instance() -> None:
    """OR-1: bare-type source_id with 0 events is dropped when a named instance exists.

    Reproduces the live symptom: suricata/suricata (running, 0 events) + suricata/vm-target
    (1239 events) — the assembler should return only ["vm-target"], not ["suricata", "vm-target"].

    The orphan pattern: source_id == source_type AND zero events AND another instance exists.
    This is the stale pre-instance-naming registration (ADR-0031 §B) that must not survive.
    """
    type_key = "suricata"
    # Orphan: bare-type id in supervisor, 0 events (pre-instance-naming registration)
    sup_map: dict[tuple[str, str], dict[str, Any]] = {
        (type_key, type_key): {"state": "running", "last_error": None},
        (type_key, "vm-target"): {"state": "running", "last_error": None},
    }
    store_map: dict[tuple[str, str], dict[str, Any]] = {
        (type_key, "vm-target"): {"event_count": 1239, "last_event_at": _recent_ts()},
        # Note: no store row for (suricata, suricata) — 0 events
    }

    ids = _instance_ids_for_type(type_key, sup_map, store_map)

    assert "vm-target" in ids, "Named instance vm-target must be retained"
    assert type_key not in ids, (
        f"Orphan bare-type id {type_key!r} (0 events, shadowed by vm-target) must be dropped; "
        f"got ids={ids!r}"
    )
    assert len(ids) == 1, f"Expected exactly 1 id after orphan removal, got {ids!r}"


def test_orphan_bare_type_id_dropped_integration() -> None:
    """OR-1 (integration): assemble_source_health returns exactly one suricata row (vm-target).

    End-to-end scenario matching the live bug: two source_ids in supervisor, one with events.
    The response must contain exactly one entry for suricata, keyed by the real instance name.
    """
    registry = {"suricata": _FakePlugin("suricata")}
    cfg = _FakeConfigStore(configured_types={"suricata"})
    sup = _FakeSupervisor([
        _FakeStatus("suricata", "suricata", state="running"),   # orphan — 0 events
        _FakeStatus("suricata", "vm-target", state="running"),  # real instance
    ])
    store_rows = [
        _store_row("suricata", "vm-target", event_count=1239, last_event_at=_recent_ts()),
        # no store row for suricata/suricata — confirms 0 events
    ]

    result = assemble_source_health(
        registry=registry,
        store_rows=store_rows,
        supervisor=sup,
        config_store=cfg,
    )

    suricata_rows = [e for e in result if e["source_type"] == "suricata"]
    assert len(suricata_rows) == 1, (
        f"Expected exactly one suricata row, got {len(suricata_rows)}: "
        f"{[r['source_id'] for r in suricata_rows]!r}"
    )
    row = suricata_rows[0]
    assert row["source_id"] == "vm-target", (
        f"The surviving row must be the real instance 'vm-target', not {row['source_id']!r}"
    )
    assert row["event_count"] == 1239
    assert row["health"] == "ok", (
        f"vm-target with recent events must be 'ok', got {row['health']!r}"
    )


def test_bare_type_id_with_events_not_dropped() -> None:
    """OR-2: bare-type source_id with events is NOT dropped — it is a real instance.

    If source_id == type_key but the store shows events, the instance is legitimate
    (it may just happen to have been named the same as the type_key).
    """
    type_key = "azure_waf"
    # The default single-instance era: source_id == type_key, has events
    sup_map: dict[tuple[str, str], dict[str, Any]] = {
        (type_key, type_key): {"state": "running", "last_error": None},
    }
    store_map: dict[tuple[str, str], dict[str, Any]] = {
        (type_key, type_key): {"event_count": 500, "last_event_at": _recent_ts()},
    }

    ids = _instance_ids_for_type(type_key, sup_map, store_map)

    assert type_key in ids, (
        f"Bare-type id {type_key!r} with events must NOT be dropped; got ids={ids!r}"
    )
    assert len(ids) == 1


def test_single_bare_type_id_without_other_instances_kept() -> None:
    """OR-3: bare-type id with 0 events but no other instance is kept (not an orphan).

    This is the brand-new default installation: suricata configured, no syncs yet,
    source_id == type_key.  With no competing named instance, nothing is shadowed,
    so the bare id must survive to produce the fallback grey/amber row.
    """
    type_key = "suricata"
    # Supervisor shows the instance (just registered, idle), no store events yet
    sup_map: dict[tuple[str, str], dict[str, Any]] = {
        (type_key, type_key): {"state": "idle", "last_error": None},
    }
    store_map: dict[tuple[str, str], dict[str, Any]] = {}

    ids = _instance_ids_for_type(type_key, sup_map, store_map)

    assert type_key in ids, (
        f"Single bare-type id {type_key!r} with no other instances must be kept; "
        f"got ids={ids!r}"
    )
    assert len(ids) == 1


def test_named_instance_only_unaffected_by_orphan_reconciliation() -> None:
    """OR-4: a type with only a named instance (no bare-type id) is completely unaffected."""
    type_key = "suricata"
    sup_map: dict[tuple[str, str], dict[str, Any]] = {
        (type_key, "vm-target"): {"state": "running", "last_error": None},
    }
    store_map: dict[tuple[str, str], dict[str, Any]] = {
        (type_key, "vm-target"): {"event_count": 100, "last_event_at": _recent_ts()},
    }

    ids = _instance_ids_for_type(type_key, sup_map, store_map)

    assert ids == ["vm-target"], (
        f"Named-only instance must survive unchanged; got ids={ids!r}"
    )


def test_orphan_reconciliation_does_not_affect_other_types() -> None:
    """OR-5: orphan removal for suricata must not alter azure_waf rows.

    The reconciliation is strictly per-type; no cross-type contamination is allowed.
    """
    # suricata has an orphan (bare-type, 0 events) + a real named instance
    # azure_waf has only its default instance (bare-type, has events)
    sup_map: dict[tuple[str, str], dict[str, Any]] = {
        ("suricata", "suricata"): {"state": "running", "last_error": None},
        ("suricata", "vm-target"): {"state": "running", "last_error": None},
        ("azure_waf", "azure_waf"): {"state": "running", "last_error": None},
    }
    store_map: dict[tuple[str, str], dict[str, Any]] = {
        ("suricata", "vm-target"): {"event_count": 500, "last_event_at": _recent_ts()},
        ("azure_waf", "azure_waf"): {"event_count": 200, "last_event_at": _recent_ts()},
    }

    suricata_ids = _instance_ids_for_type("suricata", sup_map, store_map)
    azure_ids = _instance_ids_for_type("azure_waf", sup_map, store_map)

    # suricata orphan is removed; only vm-target survives
    assert "vm-target" in suricata_ids
    assert "suricata" not in suricata_ids, (
        f"suricata orphan must be dropped; got suricata_ids={suricata_ids!r}"
    )

    # azure_waf default instance is unaffected (it has events)
    assert "azure_waf" in azure_ids, (
        f"azure_waf default instance must be kept; got azure_ids={azure_ids!r}"
    )


# ---------------------------------------------------------------------------
# R1 tests (ADR-0032 Amendment 1, issue #377)
# ---------------------------------------------------------------------------
# R1-1: _epoch_to_iso converts epoch float to ISO8601 UTC string correctly.
# R1-2: _epoch_to_iso returns None when passed None.
# R1-3: _compute_health color rules are UNCHANGED (regression guard for R1).
#        No staleness-to-red must ever creep in — green/amber boundary is
#        FRESHNESS_MINUTES; stale-but-no-error is always amber, never red.
# R1-4: FRESHNESS_MINUTES constant is exported and equals 5.
# ---------------------------------------------------------------------------


def test_epoch_to_iso_known_epoch() -> None:
    """R1-1: _epoch_to_iso converts a known epoch float to ISO8601 UTC.

    The exact epoch 1_749_600_000.0 corresponds to 2025-06-11T00:00:00+00:00.
    """
    result = _epoch_to_iso(1_749_600_000.0)
    assert result is not None
    # Must parse as a valid ISO8601 datetime
    parsed = datetime.fromisoformat(result)
    assert parsed.tzinfo is not None, "ISO result must carry timezone"
    # Must round-trip back to the same epoch (within floating-point tolerance)
    assert abs(parsed.timestamp() - 1_749_600_000.0) < 1.0


def test_epoch_to_iso_returns_none_for_none() -> None:
    """R1-2: _epoch_to_iso(None) → None (push sources / pre-first-cycle)."""
    assert _epoch_to_iso(None) is None


def test_compute_health_color_rules_unchanged_regression_guard() -> None:
    """R1-3: _compute_health rules are unchanged after Amendment R1.

    Exhaustively verify that NO staleness-to-red was introduced:
    - stale events → amber (not red)
    - red requires parked/backoff state OR last_error
    - freshness boundary is FRESHNESS_MINUTES, not 2m or 60m
    """
    # stale-but-no-error is amber (Decision C / Resolved decision 1)
    stale_ts = (
        datetime.now(timezone.utc) - timedelta(minutes=FRESHNESS_MINUTES + 30)
    ).isoformat()
    assert _compute_health(
        has_config=True,
        last_event_at=stale_ts,
        supervisor_state="running",
        last_error=None,
    ) == "amber", "stale-but-running must be amber, never red (ADR-0032 Decision C)"

    # Very stale (>60m) is still amber when supervisor is healthy
    very_stale_ts = (
        datetime.now(timezone.utc) - timedelta(minutes=90)
    ).isoformat()
    assert _compute_health(
        has_config=True,
        last_event_at=very_stale_ts,
        supervisor_state="running",
        last_error=None,
    ) == "amber", ">60m stale-but-running must be amber, not red (no recency-to-red threshold)"

    # recent events → ok (green boundary = FRESHNESS_MINUTES, not 2m)
    recent_ts = (
        datetime.now(timezone.utc) - timedelta(minutes=FRESHNESS_MINUTES - 1)
    ).isoformat()
    assert _compute_health(
        has_config=True,
        last_event_at=recent_ts,
        supervisor_state="running",
        last_error=None,
    ) == "ok", f"events within {FRESHNESS_MINUTES}m must be ok (green boundary is FRESHNESS_MINUTES)"

    # parked → red (error-path still works)
    assert _compute_health(
        has_config=True,
        last_event_at=recent_ts,
        supervisor_state="parked",
        last_error=None,
    ) == "red", "parked state must be red"

    # backoff → red
    assert _compute_health(
        has_config=True,
        last_event_at=recent_ts,
        supervisor_state="backoff",
        last_error=None,
    ) == "red", "backoff state must be red"

    # last_error set → red (even if running)
    assert _compute_health(
        has_config=True,
        last_event_at=recent_ts,
        supervisor_state="running",
        last_error="connection refused",
    ) == "red", "last_error set must be red regardless of state"


def test_freshness_minutes_constant_exported() -> None:
    """R1-4: FRESHNESS_MINUTES is exported and equals 5 (ADR-0032 Decision C)."""
    from firewatch_api.health_assembler import FRESHNESS_MINUTES as FM
    assert FM == 5, f"Expected FRESHNESS_MINUTES=5, got {FM}"


# ---------------------------------------------------------------------------
# R2 tests (ADR-0032 Amendment 1, issue #378)
# ---------------------------------------------------------------------------
# R2-1: _supervisor_map carries last_sync_at (raw float), last_sync_status,
#        last_sync_ingested when the InstanceStatus DTO provides them.
# R2-2: _supervisor_map uses None defaults when the DTO lacks the fields.
# R2-3: assemble_source_health emits last_sync_at as ISO8601 (epoch→ISO
#        conversion). Verify with a known epoch float.
# R2-4: assemble_source_health emits last_sync_status and last_sync_ingested.
# R2-5: last_sync_at is None for a source with no completed sync (push/pre-cycle).
# R2-6: _compute_health output is byte-identical when sync fields are present
#        (contract test — additive fields must not alter health computation).
# ---------------------------------------------------------------------------


class _FakeStatusWithSync:
    """Extended fake InstanceStatus DTO carrying ADR-0031 §F sync fields."""

    def __init__(
        self,
        source_type: str,
        source_id: str,
        state: str = "running",
        last_error: str | None = None,
        last_sync_at: float | None = None,
        last_sync_status: str | None = None,
        last_sync_ingested: int = 0,
    ) -> None:
        self.source_type = source_type
        self.source_id = source_id
        self.state = state
        self.last_error = last_error
        self.last_sync_at = last_sync_at
        self.last_sync_status = last_sync_status
        self.last_sync_ingested = last_sync_ingested


class _FakeSupervisorWithSync:
    def __init__(self, statuses: list[_FakeStatusWithSync]) -> None:
        self._statuses = statuses

    def status(self) -> list[_FakeStatusWithSync]:
        return list(self._statuses)


def test_supervisor_map_carries_sync_fields() -> None:
    """R2-1: _supervisor_map includes last_sync_at, last_sync_status, last_sync_ingested."""
    epoch = 1_749_600_000.0
    sup = _FakeSupervisorWithSync([
        _FakeStatusWithSync(
            source_type="suricata",
            source_id="suricata",
            state="running",
            last_sync_at=epoch,
            last_sync_status="ok",
            last_sync_ingested=42,
        )
    ])
    result = _supervisor_map(sup)
    entry = result[("suricata", "suricata")]
    assert entry["last_sync_at"] == epoch
    assert entry["last_sync_status"] == "ok"
    assert entry["last_sync_ingested"] == 42


def test_supervisor_map_defaults_sync_fields_to_none() -> None:
    """R2-2: _supervisor_map uses None/0 defaults when DTO lacks sync fields."""
    # _FakeStatus (no sync attrs) simulates a pre-ADR-0031 DTO
    sup = _FakeSupervisor([
        _FakeStatus(source_type="suricata", source_id="suricata", state="running")
    ])
    result = _supervisor_map(sup)
    entry = result[("suricata", "suricata")]
    assert entry.get("last_sync_at") is None
    assert entry.get("last_sync_status") is None
    assert entry.get("last_sync_ingested") == 0


def test_assemble_emits_last_sync_at_as_iso() -> None:
    """R2-3: assemble_source_health converts last_sync_at epoch float to ISO8601."""
    epoch = 1_749_600_000.0
    plugin = _FakePlugin("suricata", "Suricata IDS/IPS", "pull")
    sup = _FakeSupervisorWithSync([
        _FakeStatusWithSync(
            source_type="suricata",
            source_id="suricata",
            state="running",
            last_sync_at=epoch,
            last_sync_status="ok",
            last_sync_ingested=10,
        )
    ])
    config_store = _FakeConfigStore(configured_types={"suricata"})
    entries = assemble_source_health(
        registry={"suricata": plugin},
        store_rows=[],
        supervisor=sup,
        config_store=config_store,
    )
    assert entries, "Expected at least one entry"
    entry = entries[0]
    iso = entry["last_sync_at"]
    assert iso is not None, "last_sync_at must not be None when sync occurred"
    # Must be a valid ISO8601 string
    parsed = datetime.fromisoformat(iso)
    assert abs(parsed.timestamp() - epoch) < 1.0, (
        f"ISO8601 round-trip failed: expected ~{epoch}, got {parsed.timestamp()}"
    )


def test_assemble_emits_last_sync_status_and_ingested() -> None:
    """R2-4: assemble_source_health emits last_sync_status and last_sync_ingested."""
    plugin = _FakePlugin("suricata", "Suricata IDS/IPS", "pull")
    sup = _FakeSupervisorWithSync([
        _FakeStatusWithSync(
            source_type="suricata",
            source_id="suricata",
            state="running",
            last_sync_at=1_749_600_000.0,
            last_sync_status="no_data",
            last_sync_ingested=0,
        )
    ])
    config_store = _FakeConfigStore(configured_types={"suricata"})
    entries = assemble_source_health(
        registry={"suricata": plugin},
        store_rows=[],
        supervisor=sup,
        config_store=config_store,
    )
    entry = entries[0]
    assert entry["last_sync_status"] == "no_data"
    assert entry["last_sync_ingested"] == 0


def test_assemble_last_sync_at_null_when_no_sync() -> None:
    """R2-5: last_sync_at is null when no completed sync (pre-first-cycle)."""
    plugin = _FakePlugin("suricata", "Suricata IDS/IPS", "pull")
    sup = _FakeSupervisorWithSync([
        _FakeStatusWithSync(
            source_type="suricata",
            source_id="suricata",
            state="running",
            last_sync_at=None,
            last_sync_status=None,
            last_sync_ingested=0,
        )
    ])
    config_store = _FakeConfigStore(configured_types={"suricata"})
    entries = assemble_source_health(
        registry={"suricata": plugin},
        store_rows=[],
        supervisor=sup,
        config_store=config_store,
    )
    entry = entries[0]
    assert entry["last_sync_at"] is None
    assert entry["last_sync_status"] is None


def test_compute_health_unchanged_when_sync_fields_present() -> None:
    """R2-6: _compute_health contract — adding sync fields to assembler must not
    alter health output (additive-only change).

    Verify that for every (has_config, last_event_at, supervisor_state, last_error)
    combination the health value is byte-identical regardless of whether
    last_sync_at / last_sync_status are populated.  This is the integration
    regression guard: _compute_health's signature is untouched.
    """
    recent = _recent_ts()
    stale = _stale_ts()

    cases = [
        dict(has_config=True, last_event_at=recent, supervisor_state="running", last_error=None),
        dict(has_config=True, last_event_at=stale, supervisor_state="running", last_error=None),
        dict(has_config=True, last_event_at=None, supervisor_state="running", last_error=None),
        dict(has_config=True, last_event_at=recent, supervisor_state="parked", last_error=None),
        dict(has_config=True, last_event_at=recent, supervisor_state="backoff", last_error=None),
        dict(has_config=False, last_event_at=None, supervisor_state=None, last_error=None),
        dict(has_config=True, last_event_at=recent, supervisor_state="running", last_error="err"),
    ]
    expected = ["ok", "amber", "amber", "red", "red", "not_configured", "red"]

    for case, exp in zip(cases, expected):
        result = _compute_health(**case)  # type: ignore[arg-type]
        assert result == exp, (
            f"_compute_health({case}) → {result!r}, expected {exp!r}. "
            "R2 must not alter health computation."
        )
