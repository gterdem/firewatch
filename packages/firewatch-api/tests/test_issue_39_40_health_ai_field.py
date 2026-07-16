"""Tests for GET /health's additive ``ai`` field and inertness (issue #39 AC6).

EARS criteria mapped to tests:

EARS-1 — GET /health SHALL gain an additive field
        ``ai: "active"|"disabled"|"unreachable"``.
        -> test_health_ai_field_present_and_one_of_three_values

EARS-2 — WHEN ``ai_enabled=false``, GET /health SHALL NOT dial the inference
        endpoint (inertness principle, ADR-0066) and SHALL report
        ``ai="disabled"``.
        -> test_health_ai_disabled_never_dials_endpoint
        -> test_health_ai_disabled_reports_disabled

EARS-3 — ``ollama_connected`` is retained (deprecated), ``true`` iff
        ``ai == "active"``.
        -> test_ollama_connected_true_iff_ai_active
        -> test_ollama_connected_false_when_ai_disabled
        -> test_ollama_connected_false_when_ai_unreachable

EARS-4 — WHEN ``ai_enabled=true`` and the probe succeeds/fails, GET /health
        SHALL report ``ai="active"``/``ai="unreachable"`` respectively (a
        dial-time fault surfaces as 'unreachable', never 'disabled').
        -> test_health_ai_active_when_probe_succeeds
        -> test_health_ai_unreachable_when_probe_fails

Security: all base_urls are loopback; no real network calls (httpx patched).
"""
from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from firewatch_api.app import create_app


class _FakeConfigStore:
    """Minimal ConfigStore fake exposing only get_runtime (issue #39/#40 tests)."""

    def __init__(self, *, ai_enabled: bool = True, ollama_base_url: str = "http://127.0.0.1:11434") -> None:
        self._ai_enabled = ai_enabled
        self._ollama_base_url = ollama_base_url

    def get_runtime(self) -> Any:
        from firewatch_sdk import RuntimeConfig

        return RuntimeConfig.model_validate(
            {"ai_enabled": self._ai_enabled, "ollama_base_url": self._ollama_base_url}
        )

    def set_runtime(self, updates: dict[str, Any]) -> None:
        pass


def _make_client(config_store: Any) -> TestClient:
    from _api_fakes import FakePullPlugin

    app = create_app(registry={"suricata": FakePullPlugin()}, config_store=config_store)
    return TestClient(app)


# ---------------------------------------------------------------------------
# EARS-1: additive ai field, one of three closed values
# ---------------------------------------------------------------------------


def test_health_ai_field_present_and_one_of_three_values() -> None:
    """GET /health response includes an 'ai' field with a closed-vocabulary value."""
    client = _make_client(_FakeConfigStore(ai_enabled=False))
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["ai"] in ("active", "disabled", "unreachable")


# ---------------------------------------------------------------------------
# EARS-2: ai_enabled=false -> no dial, ai="disabled"
# ---------------------------------------------------------------------------


def test_health_ai_disabled_never_dials_endpoint() -> None:
    """WHEN ai_enabled=false, GET /health must NOT dial the inference endpoint.

    Inertness principle (ADR-0066 / issue #40): an off subsystem must never
    dial, resolve, or crash.
    """
    client = _make_client(_FakeConfigStore(ai_enabled=False))
    with patch("httpx.AsyncClient") as mock_client:
        resp = client.get("/health")
    assert resp.status_code == 200
    mock_client.assert_not_called()


def test_health_ai_disabled_reports_disabled() -> None:
    """WHEN ai_enabled=false, GET /health reports ai='disabled' — a choice, not a fault."""
    client = _make_client(_FakeConfigStore(ai_enabled=False))
    resp = client.get("/health")
    assert resp.json()["ai"] == "disabled"


# ---------------------------------------------------------------------------
# EARS-3: ollama_connected mirrors ai=="active" (deprecated compat field)
# ---------------------------------------------------------------------------


def test_ollama_connected_false_when_ai_disabled() -> None:
    client = _make_client(_FakeConfigStore(ai_enabled=False))
    resp = client.get("/health")
    data = resp.json()
    assert data["ai"] == "disabled"
    assert data["ollama_connected"] is False


def test_ollama_connected_true_iff_ai_active() -> None:
    """ollama_connected=True exactly when ai=='active' (probe succeeds, ai_enabled=true)."""
    client = _make_client(_FakeConfigStore(ai_enabled=True))

    class _OkResponse:
        status_code = 200

    class _OkClient:
        async def __aenter__(self) -> "_OkClient":
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def get(self, *a: object, **kw: object) -> _OkResponse:
            return _OkResponse()

    with patch("httpx.AsyncClient", return_value=_OkClient()):
        resp = client.get("/health")

    data = resp.json()
    assert data["ai"] == "active"
    assert data["ollama_connected"] is True


def test_ollama_connected_false_when_ai_unreachable() -> None:
    client = _make_client(_FakeConfigStore(ai_enabled=True))

    class _FailingClient:
        async def __aenter__(self) -> "_FailingClient":
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def get(self, *a: object, **kw: object) -> None:
            raise OSError("connection refused")

    with patch("httpx.AsyncClient", return_value=_FailingClient()):
        resp = client.get("/health")

    data = resp.json()
    assert data["ai"] == "unreachable"
    assert data["ollama_connected"] is False


# ---------------------------------------------------------------------------
# EARS-4: ai_enabled=true -> probe result determines active/unreachable
# ---------------------------------------------------------------------------


def test_health_ai_active_when_probe_succeeds() -> None:
    client = _make_client(_FakeConfigStore(ai_enabled=True))

    class _OkResponse:
        status_code = 200

    class _OkClient:
        async def __aenter__(self) -> "_OkClient":
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def get(self, *a: object, **kw: object) -> _OkResponse:
            return _OkResponse()

    with patch("httpx.AsyncClient", return_value=_OkClient()):
        resp = client.get("/health")
    assert resp.json()["ai"] == "active"


def test_health_ai_unreachable_when_probe_fails() -> None:
    """A dial-time fault surfaces as 'unreachable', never 'disabled' (issue #40)."""
    client = _make_client(_FakeConfigStore(ai_enabled=True))

    class _FailingClient:
        async def __aenter__(self) -> "_FailingClient":
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def get(self, *a: object, **kw: object) -> None:
            raise OSError("connection refused")

    with patch("httpx.AsyncClient", return_value=_FailingClient()):
        resp = client.get("/health")
    data = resp.json()
    assert data["ai"] == "unreachable"
    assert data["ai"] != "disabled", (
        "A dial-time fault must surface as 'unreachable', never 'disabled' "
        "(off is a choice, unreachable is a fault — issue #40)."
    )


if __name__ == "__main__":
    pytest.main([__file__])
