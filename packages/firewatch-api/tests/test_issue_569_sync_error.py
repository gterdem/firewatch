"""Tests for issue #569 — POST /sync/{type_key} structured JSON error on failure.

EARS acceptance criteria → test mapping
=========================================

EARS-569-1 (event-driven — sync failure → structured JSON, not plain-text 500):
  WHEN a sync request to a parked/misconfigured source fails (run_pull_cycle_for
  raises), THE SYSTEM SHALL return a structured JSON error body and an appropriate
  HTTP status, not a raw 500 plain-text body.
  -> test_sync_failure_returns_structured_json_not_plaintext_500
  -> test_sync_failure_status_is_not_500

EARS-569-2 (event-driven — known error type → descriptive message):
  WHEN the underlying cause is a known condition (e.g. WorkspaceNotFoundError
  or AzureWAFAuthError), THE SYSTEM SHALL surface a descriptive, non-stack-trace
  message in the error body.
  -> test_sync_known_error_type_in_message
  -> test_sync_error_body_has_code_and_message_fields
  -> test_sync_auth_error_descriptive_message

EARS-569-3 (ubiquitous — no secret/stack leak):
  THE SYSTEM SHALL log the exception server-side and NOT include a stack trace or
  internal path in the client response body.
  -> test_sync_error_body_has_no_traceback_content
  -> test_sync_error_body_has_no_internal_path

EARS-569-4 (regression — success path unchanged):
  WHEN the sync succeeds, the route SHALL still return 200 with ok=True.
  -> test_sync_success_still_returns_200

EARS-569-5 (regression — 404 guards unchanged):
  WHEN type_key or source_id is unknown, the route SHALL still return 404.
  -> test_sync_unknown_type_returns_404_unchanged
  -> test_sync_unknown_source_id_returns_404_unchanged
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from fastapi.testclient import TestClient
from pydantic import BaseModel

from firewatch_sdk import RawEvent, SecurityEvent, SourceMetadata
from firewatch_api.app import create_app


# --------------------------------------------------------------------------- #
# Fake helpers                                                                 #
# --------------------------------------------------------------------------- #


class _FakeCfg(BaseModel):
    note: str = "fake"


class _FakePullPlugin:
    """Minimal fake pull plugin for sync route tests."""

    def __init__(self, type_key: str = "fake_source") -> None:
        self._type_key = type_key

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key=self._type_key,
            display_name="Fake Source",
            version="0.1.0",
            flavor="pull",
        )

    def config_schema(self) -> type[BaseModel]:
        return _FakeCfg

    def validate_config(self, cfg: dict[str, Any]) -> None:
        _FakeCfg.model_validate(cfg)

    def normalize(self, raw: RawEvent, source_id: str) -> SecurityEvent:
        return SecurityEvent(
            source_type=self._type_key,
            source_id=source_id,
            timestamp=raw.received_at,
            source_ip="192.0.2.10",
            action="ALERT",
        )

    async def health_check(self, cfg: BaseModel) -> bool:
        return True


class _FailingSupervisor:
    """Fake supervisor whose run_pull_cycle_for raises a configurable exception.

    Used to simulate parked/misconfigured sources that cause collection errors
    (e.g. AzureWAFAuthError, WorkspaceNotFoundError).
    """

    def __init__(
        self,
        exc: BaseException | None = None,
        source_type: str = "fake_source",
        source_id: str = "fake_source",
    ) -> None:
        self._exc = exc if exc is not None else RuntimeError("simulated pull cycle error")
        self._source_type = source_type
        self._source_id = source_id
        self.run_cycle_calls: list[tuple[str, str]] = []

    def status(self) -> list[Any]:
        return []

    def get_instance(self, source_type: str, source_id: str) -> Any | None:
        if source_type == self._source_type and source_id == self._source_id:
            return object()  # non-None sentinel
        return None

    async def run_pull_cycle_for(self, source_type: str, source_id: str) -> int:
        self.run_cycle_calls.append((source_type, source_id))
        raise self._exc


class _OkSupervisor:
    """Fake supervisor whose run_pull_cycle_for succeeds."""

    def __init__(
        self,
        source_type: str = "fake_source",
        source_id: str = "fake_source",
        events_ingested: int = 0,
    ) -> None:
        self._source_type = source_type
        self._source_id = source_id
        self._events_ingested = events_ingested
        self.run_cycle_calls: list[tuple[str, str]] = []

    def status(self) -> list[Any]:
        return []

    def get_instance(self, source_type: str, source_id: str) -> Any | None:
        if source_type == self._source_type and source_id == self._source_id:
            return object()
        return None

    async def run_pull_cycle_for(self, source_type: str, source_id: str) -> int:
        self.run_cycle_calls.append((source_type, source_id))
        return self._events_ingested


# --------------------------------------------------------------------------- #
# Client builder                                                               #
# --------------------------------------------------------------------------- #


def _make_client(
    supervisor: Any,
    type_key: str = "fake_source",
) -> TestClient:
    config_store = MagicMock()
    config_store.get_runtime.return_value = __import__(
        "firewatch_sdk", fromlist=["RuntimeConfig"]
    ).RuntimeConfig()
    app = create_app(
        registry={type_key: _FakePullPlugin(type_key)},
        supervisor=supervisor,
        config_store=config_store,
    )
    return TestClient(app, raise_server_exceptions=False)


# --------------------------------------------------------------------------- #
# EARS-569-1: sync failure → structured JSON, not plain-text 500             #
# --------------------------------------------------------------------------- #


def test_sync_failure_returns_structured_json_not_plaintext_500() -> None:
    """EARS-569-1: a failing run_pull_cycle_for returns JSON, not a plain-text 500.

    WHEN a sync request fails (run_pull_cycle_for raises), THE SYSTEM SHALL
    return a JSON-parseable body with a structured 'detail.error' envelope,
    not plain text.

    FastAPI wraps HTTPException.detail under the top-level 'detail' key; the
    structured error envelope lives at detail.error (issue #569 shape contract).
    """
    sup = _FailingSupervisor(exc=RuntimeError("workspace not found"))
    client = _make_client(sup)

    resp = client.post("/sync/fake_source?source_id=fake_source")

    # Must be JSON — not a plain-text stack trace.
    body = resp.json()
    # FastAPI wraps HTTPException.detail under 'detail'; our envelope is nested there.
    assert "detail" in body, (
        f"Response must contain 'detail' key (FastAPI envelope); got: {body!r}"
    )
    detail = body["detail"]
    assert isinstance(detail, dict), f"'detail' must be a dict; got {type(detail)}"
    assert "error" in detail, (
        f"'detail' must contain 'error' key; got: {detail!r}"
    )


def test_sync_failure_status_is_not_500() -> None:
    """EARS-569-1: a failing sync SHALL NOT return a raw 500.

    The appropriate status for an upstream collection failure is 502 (Bad Gateway)
    or another non-500 client-readable code — never a bare unhandled 500.
    """
    sup = _FailingSupervisor(exc=RuntimeError("workspace not found"))
    client = _make_client(sup)

    resp = client.post("/sync/fake_source?source_id=fake_source")

    assert resp.status_code != 500, (
        f"Expected a non-500 status for sync failure; got {resp.status_code}"
    )
    # The status must be a client-meaningful error code.
    assert resp.status_code in (400, 502, 503, 422), (
        f"Unexpected status {resp.status_code}; expected 400/502/503/422"
    )


# --------------------------------------------------------------------------- #
# EARS-569-2: known error type → descriptive message                         #
# --------------------------------------------------------------------------- #


class _FakeWorkspaceNotFoundError(RuntimeError):
    """Simulates a WorkspaceNotFoundError without importing the azure-waf package."""


class _FakeAuthError(RuntimeError):
    """Simulates an authentication failure without importing the azure-waf package."""


def test_sync_error_body_has_code_and_message_fields() -> None:
    """EARS-569-2: the structured JSON error body SHALL contain 'code' and 'message'.

    The 'error' envelope (at body['detail']['error']) must carry both fields so
    the UI can render a user-friendly message without parsing a raw exception string.
    """
    sup = _FailingSupervisor(exc=RuntimeError("workspace not found"))
    client = _make_client(sup)

    resp = client.post("/sync/fake_source?source_id=fake_source")

    body = resp.json()
    # FastAPI wraps HTTPException.detail under 'detail'.
    err = body["detail"]["error"]
    assert "code" in err, f"'code' missing from error envelope: {err!r}"
    assert "message" in err, f"'message' missing from error envelope: {err!r}"
    assert isinstance(err["code"], str), "'code' must be a string"
    assert isinstance(err["message"], str), "'message' must be a string"
    assert err["message"], "'message' must not be empty"


def test_sync_known_error_type_in_message() -> None:
    """EARS-569-2: a known error type (e.g. WorkspaceNotFoundError) surfaces
    its type name in the error message so the UI can render a descriptive hint.
    """
    exc = _FakeWorkspaceNotFoundError("No workspace found for ID abc123")
    sup = _FailingSupervisor(exc=exc)
    client = _make_client(sup)

    resp = client.post("/sync/fake_source?source_id=fake_source")

    body = resp.json()
    # FastAPI wraps HTTPException.detail under 'detail'.
    err = body["detail"]["error"]
    # Message must be descriptive, not the generic FastAPI default.
    assert err["message"] != "Internal Server Error", (
        "Error message must be descriptive, not the generic 'Internal Server Error'"
    )
    # The exception class name or a meaningful keyword must appear.
    assert (
        "_FakeWorkspaceNotFoundError" in err["message"]
        or "workspace" in err["message"].lower()
        or "not found" in err["message"].lower()
    ), (
        f"Expected the error type or a meaningful description in the message; "
        f"got: {err['message']!r}"
    )


def test_sync_auth_error_descriptive_message() -> None:
    """EARS-569-2: an auth error surfaces a descriptive non-opaque message."""
    exc = _FakeAuthError("DefaultAzureCredential: no suitable credential found")
    sup = _FailingSupervisor(exc=exc)
    client = _make_client(sup)

    resp = client.post("/sync/fake_source?source_id=fake_source")

    body = resp.json()
    # FastAPI wraps HTTPException.detail under 'detail'.
    err = body["detail"]["error"]
    # Message must not be empty and must not be a generic placeholder.
    assert err["message"], "Message must not be empty"
    assert err["message"] not in ("error", "unknown", "Internal Server Error"), (
        "Message must be descriptive"
    )


# --------------------------------------------------------------------------- #
# EARS-569-3: no secret/stack leak                                           #
# --------------------------------------------------------------------------- #


def test_sync_error_body_has_no_traceback_content() -> None:
    """EARS-569-3: the response body SHALL NOT contain traceback/stack-trace content.

    Internal paths, 'Traceback (most recent call last)', or 'File "' markers
    must not appear in the client response — these leak internal file paths
    and implementation details.
    """
    sup = _FailingSupervisor(exc=RuntimeError("connection refused"))
    client = _make_client(sup)

    resp = client.post("/sync/fake_source?source_id=fake_source")

    body_text = resp.text
    # Standard Python traceback markers must not appear.
    assert "Traceback (most recent call last)" not in body_text, (
        "Stack trace must not leak to the client"
    )
    assert 'File "' not in body_text, (
        "File paths must not leak to the client"
    )


def test_sync_error_body_has_no_internal_path() -> None:
    """EARS-569-3: internal Python paths and module names must not leak.

    A raw exception with __file__ paths or repr() of an exception chain must
    never reach the client response body.
    """
    exc = RuntimeError("failed to connect to host 192.0.2.1")
    sup = _FailingSupervisor(exc=exc)
    client = _make_client(sup)

    resp = client.post("/sync/fake_source?source_id=fake_source")

    body_text = resp.text
    # These strings indicate stack trace or internal path leakage.
    for forbidden in ("site-packages", "orchestrator.py"):
        assert forbidden not in body_text, (
            f"Internal path fragment {forbidden!r} must not appear in response"
        )


# --------------------------------------------------------------------------- #
# EARS-569-4: success path regression                                         #
# --------------------------------------------------------------------------- #


def test_sync_success_still_returns_200() -> None:
    """EARS-569-4: a successful sync still returns 200 with ok=True and events_ingested.

    The error-handling wrapper must not break the success path.
    """
    sup = _OkSupervisor(events_ingested=5)
    client = _make_client(sup)

    resp = client.post("/sync/fake_source?source_id=fake_source")

    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["events_ingested"] == 5
    assert sup.run_cycle_calls == [("fake_source", "fake_source")]


# --------------------------------------------------------------------------- #
# EARS-569-5: 404 guard regression                                           #
# --------------------------------------------------------------------------- #


def test_sync_unknown_type_returns_404_unchanged() -> None:
    """EARS-569-5: unknown type_key still returns 404 (404 guard unchanged)."""
    sup = _OkSupervisor()
    client = _make_client(sup)

    resp = client.post("/sync/unknown_type?source_id=fake_source")

    assert resp.status_code == 404


def test_sync_unknown_source_id_returns_404_unchanged() -> None:
    """EARS-569-5: unknown source_id still returns 404 (404 guard unchanged)."""
    sup = _OkSupervisor()
    client = _make_client(sup)

    resp = client.post("/sync/fake_source?source_id=does_not_exist")

    assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# events_ingested in POST /sync response (manual-sync count bug fix)          #
# --------------------------------------------------------------------------- #


def test_sync_response_includes_events_ingested_when_nonzero() -> None:
    """POST /sync SHALL include events_ingested=N in the 200 response when N>0.

    The UI uses this to display "Sync: Complete — N ingested".
    """
    sup = _OkSupervisor(events_ingested=79)
    client = _make_client(sup)

    resp = client.post("/sync/fake_source?source_id=fake_source")

    assert resp.status_code == 200
    body = resp.json()
    assert "events_ingested" in body, (
        f"Response must contain 'events_ingested'; got: {body!r}"
    )
    assert body["events_ingested"] == 79


def test_sync_response_events_ingested_zero_when_no_new_rows() -> None:
    """POST /sync SHALL include events_ingested=0 when no net-new rows were inserted.

    The UI can distinguish 'ok but nothing new' (no_data) from a real ingestion.
    """
    sup = _OkSupervisor(events_ingested=0)
    client = _make_client(sup)

    resp = client.post("/sync/fake_source?source_id=fake_source")

    assert resp.status_code == 200
    body = resp.json()
    assert body["events_ingested"] == 0
