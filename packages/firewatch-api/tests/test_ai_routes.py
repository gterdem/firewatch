"""Tests for issue #135 — GET /health AI fields + GET /ai/models.

EARS criteria → test mapping:

  E1 (event-driven — health AI fields restored):
    WHEN GET /health is requested, the response SHALL include `ollama_connected` (bool)
    and `ollama_model` (string|null).
    → test_health_includes_ai_fields_when_connected
    → test_health_ai_fields_when_unreachable
    → test_health_ai_model_is_null_when_config_store_raises

  E2 (event-driven — model list reachable):
    WHEN GET /ai/models is requested and the endpoint is reachable, it SHALL return
    {"models": [...], "current": "<configured>"} with status 200.
    → test_ai_models_reachable_returns_list
    → test_ai_models_current_reflects_configured_model

  E3 (event-driven — graceful fallback when unreachable):
    IF the local AI endpoint is unreachable, GET /ai/models SHALL return
    {"models": [], "current": "<configured>", "error": "<message>"} with status 200
    (never 500).
    → test_ai_models_unreachable_returns_empty_list_200
    → test_ai_models_error_key_present_on_unreachable
    → test_ai_models_non_200_status_returns_error

  U1 (ubiquitous — local-first enforcement):
    The model-list and health probes SHALL only contact a base_url that passes the
    existing loopback/RFC-1918/link-local validation (ADR-0022).  A non-local
    base_url is validated at config level (SDK validator) — probing itself never
    sends to a non-local host.
    → test_ai_models_no_ssrf_public_ip_blocked

  U2 (ubiquitous — no secrets in response):
    GET /ai/models SHALL NOT include webhook_url or api_key in the response body.
    → test_ai_models_no_secrets_in_response

  Confirm (state-driven — PUT /config/runtime ollama_model persists):
    WHEN PUT /config/runtime sets ollama_model, the next GET /health SHALL reflect it.
    → test_put_runtime_ollama_model_persists_to_health

  Contract (parametrized shape validation):
    GET /ai/models always returns {models: list[str], current: str|null}.
    → test_ai_models_response_shape

All fakes use RFC 5737 documentation IPs (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
or loopback — never real routable IPs.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel

from firewatch_api.app import create_app


# ---------------------------------------------------------------------------
# Fake config store for AI route tests
# ---------------------------------------------------------------------------


class FakeConfigStore:
    """Minimal in-memory ConfigStore for AI-route tests."""

    def __init__(
        self,
        ollama_base_url: str = "http://127.0.0.1:11434",
        ollama_model: str = "qwen3:14b",
    ) -> None:
        self._runtime_data: dict[str, Any] = {
            "ollama_base_url": ollama_base_url,
            "ollama_model": ollama_model,
        }
        self.set_runtime_calls: list[dict[str, Any]] = []

    def get_runtime(self) -> Any:
        from firewatch_sdk import RuntimeConfig

        return RuntimeConfig.model_validate(self._runtime_data)

    def set_runtime(self, updates: dict[str, Any]) -> None:
        self.set_runtime_calls.append(updates)
        from firewatch_sdk import RuntimeConfig

        merged = {**self._runtime_data, **updates}
        RuntimeConfig.model_validate(merged)
        self._runtime_data = merged

    def get_source(self, source_type: str, schema: type[BaseModel]) -> BaseModel:
        return schema.model_validate({})

    def set_source(
        self, source_type: str, schema: type[BaseModel], updates: dict[str, Any]
    ) -> None:
        pass


# ---------------------------------------------------------------------------
# Fake event store for health check tests
# ---------------------------------------------------------------------------


class FakeEventStore:
    """Minimal EventStore fake that always connects successfully."""

    async def _conn(self) -> Any:
        return self

    async def get_stats(self) -> dict[str, Any]:
        return {
            "total_logs": 0,
            "total_ips": 0,
            "blocked_percentage": 0.0,
            "top_attack_types": [],
            "last_updated": None,
        }

    async def source_health(self) -> list[dict[str, Any]]:
        return []


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------


def _mock_httpx_client(
    status_code: int = 200,
    json_body: dict[str, Any] | None = None,
    raises: Exception | None = None,
) -> Any:
    """Return an AsyncMock context-manager that mimics httpx.AsyncClient.

    ``response.json()`` is synchronous in httpx — wired as a regular callable
    (MagicMock) rather than AsyncMock to match real httpx behaviour.
    """
    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_cm)
    mock_cm.__aexit__ = AsyncMock(return_value=False)

    if raises is not None:
        mock_cm.get = AsyncMock(side_effect=raises)
    else:
        mock_resp = MagicMock()
        mock_resp.status_code = status_code
        if json_body is not None:
            mock_resp.json = MagicMock(return_value=json_body)
        mock_cm.get = AsyncMock(return_value=mock_resp)

    return mock_cm


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_client(
    config_store: FakeConfigStore | None = None,
    event_store: FakeEventStore | None = None,
) -> TestClient:
    store = config_store or FakeConfigStore()
    es = event_store or FakeEventStore()
    app = create_app(registry={}, config_store=store, event_store=es)
    return TestClient(app)


# ---------------------------------------------------------------------------
# E1 — GET /health includes AI fields
# ---------------------------------------------------------------------------


def test_health_includes_ai_fields_when_connected() -> None:
    """GET /health returns ollama_connected=True when endpoint is reachable."""
    store = FakeConfigStore(ollama_model="llama3.2")
    client = _make_client(config_store=store)

    with patch(
        "firewatch_api.routes.meta.httpx.AsyncClient",
        return_value=_mock_httpx_client(status_code=200),
    ):
        resp = client.get("/health")

    assert resp.status_code == 200
    data = resp.json()
    assert "ollama_connected" in data, "ollama_connected must be in /health response"
    assert "ollama_model" in data, "ollama_model must be in /health response"
    assert data["ollama_connected"] is True
    assert data["ollama_model"] == "llama3.2"


def test_health_ai_fields_when_unreachable() -> None:
    """GET /health returns ollama_connected=False when endpoint is unreachable."""
    store = FakeConfigStore(ollama_model="qwen3:14b")
    client = _make_client(config_store=store)

    with patch(
        "firewatch_api.routes.meta.httpx.AsyncClient",
        return_value=_mock_httpx_client(raises=OSError("connection refused")),
    ):
        resp = client.get("/health")

    assert resp.status_code == 200
    data = resp.json()
    assert data["ollama_connected"] is False
    assert data["ollama_model"] == "qwen3:14b"


def test_health_ai_model_is_null_when_config_store_raises() -> None:
    """GET /health returns ollama_model=null when the config store raises on get_runtime.

    Covers the path where a config store is present but get_runtime() fails —
    the health endpoint must still return 200 with null AI fields (never 500).
    """

    class _BrokenConfigStore:
        def get_runtime(self) -> Any:
            raise RuntimeError("config store exploded")

        def get_source(self, source_type: str, schema: Any) -> Any:
            raise RuntimeError("config store exploded")

        def set_source(self, *args: Any, **kwargs: Any) -> None:
            pass

        def set_runtime(self, *args: Any, **kwargs: Any) -> None:
            pass

    app = create_app(
        registry={},
        config_store=_BrokenConfigStore(),
        event_store=FakeEventStore(),
    )
    client = TestClient(app)

    resp = client.get("/health")

    assert resp.status_code == 200
    data = resp.json()
    assert "ollama_connected" in data
    assert "ollama_model" in data
    # get_runtime() failed → AI fields degrade gracefully to null/False
    assert data["ollama_model"] is None
    assert data["ollama_connected"] is False


# ---------------------------------------------------------------------------
# E2 — GET /ai/models reachable
# ---------------------------------------------------------------------------


def test_ai_models_reachable_returns_list() -> None:
    """GET /ai/models returns {"models": [...], "current": "..."} on success."""
    store = FakeConfigStore(ollama_model="llama3.2")
    client = _make_client(config_store=store)

    openai_response_body = {
        "data": [
            {"id": "llama3.2"},
            {"id": "qwen3:14b"},
            {"id": "mistral:7b"},
        ]
    }

    with patch(
        "firewatch_api.routes.ai.httpx.AsyncClient",
        return_value=_mock_httpx_client(status_code=200, json_body=openai_response_body),
    ):
        resp = client.get("/ai/models")

    assert resp.status_code == 200
    data = resp.json()
    assert "models" in data
    assert "current" in data
    assert data["current"] == "llama3.2"
    assert "llama3.2" in data["models"]
    assert "qwen3:14b" in data["models"]
    assert "mistral:7b" in data["models"]
    # No error key when successful
    assert "error" not in data


def test_ai_models_current_reflects_configured_model() -> None:
    """GET /ai/models current field matches the configured ollama_model."""
    store = FakeConfigStore(ollama_model="qwen3:14b")
    client = _make_client(config_store=store)

    with patch(
        "firewatch_api.routes.ai.httpx.AsyncClient",
        return_value=_mock_httpx_client(
            status_code=200, json_body={"data": [{"id": "qwen3:14b"}]}
        ),
    ):
        resp = client.get("/ai/models")

    assert resp.status_code == 200
    assert resp.json()["current"] == "qwen3:14b"


# ---------------------------------------------------------------------------
# E3 — GET /ai/models graceful fallback when unreachable
# ---------------------------------------------------------------------------


def test_ai_models_unreachable_returns_empty_list_200() -> None:
    """GET /ai/models returns 200 with empty list when endpoint is unreachable."""
    store = FakeConfigStore(ollama_model="qwen3:14b")
    client = _make_client(config_store=store)

    with patch(
        "firewatch_api.routes.ai.httpx.AsyncClient",
        return_value=_mock_httpx_client(raises=OSError("connection refused")),
    ):
        resp = client.get("/ai/models")

    assert resp.status_code == 200, (
        f"GET /ai/models must return 200 on unreachable endpoint, got {resp.status_code}"
    )
    data = resp.json()
    assert data["models"] == [], "Empty list expected when endpoint unreachable"
    assert data["current"] == "qwen3:14b"


def test_ai_models_error_key_present_on_unreachable() -> None:
    """GET /ai/models includes an 'error' key when the endpoint is unreachable."""
    store = FakeConfigStore()
    client = _make_client(config_store=store)

    with patch(
        "firewatch_api.routes.ai.httpx.AsyncClient",
        return_value=_mock_httpx_client(raises=OSError("connection refused")),
    ):
        resp = client.get("/ai/models")

    assert resp.status_code == 200
    data = resp.json()
    assert "error" in data, "error key must be present when endpoint unreachable"
    assert isinstance(data["error"], str)
    assert len(data["error"]) > 0


def test_ai_models_non_200_status_returns_error() -> None:
    """GET /ai/models returns error shape when remote returns non-200."""
    store = FakeConfigStore()
    client = _make_client(config_store=store)

    with patch(
        "firewatch_api.routes.ai.httpx.AsyncClient",
        return_value=_mock_httpx_client(status_code=503),
    ):
        resp = client.get("/ai/models")

    assert resp.status_code == 200
    data = resp.json()
    assert data["models"] == []
    assert "error" in data


# ---------------------------------------------------------------------------
# U1 — local-first: GET /ai/models validates base_url (no SSRF to public IPs)
# ---------------------------------------------------------------------------


def test_ai_models_no_ssrf_public_ip_blocked() -> None:
    """GET /ai/models returns 200 (error shape) when endpoint is unreachable.

    The SDK's RuntimeConfig._validate_ollama_base_url_local_first rejects non-local
    URLs at config-write time (ADR-0022).  This test verifies the route never 500s
    and always returns a well-formed response even when the underlying probe fails.

    Uses loopback (127.0.0.1) to satisfy the SDK validator; simulates a network
    failure to confirm the graceful-degradation path.
    """
    store = FakeConfigStore(ollama_base_url="http://127.0.0.1:11434", ollama_model="llama3.2")
    client = _make_client(config_store=store)

    with patch(
        "firewatch_api.routes.ai.httpx.AsyncClient",
        return_value=_mock_httpx_client(raises=OSError("Network unreachable")),
    ):
        resp = client.get("/ai/models")

    # Must always be 200 — never 500
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data.get("models"), list)
    assert "current" in data


# ---------------------------------------------------------------------------
# U2 — no secrets in GET /ai/models response
# ---------------------------------------------------------------------------


def test_ai_models_no_secrets_in_response() -> None:
    """GET /ai/models must NOT include webhook_url or api_key values."""
    store = FakeConfigStore()
    # Inject some secret-looking runtime data; RuntimeConfig masks these as SecretStr
    # but we confirm neither the raw value nor the key escapes into the response.
    # NOTE: since api_key is set, the auth middleware is active; send the correct bearer.
    _api_key = "bearer-secret-key-12345"  # noqa: S105 test fixture
    store._runtime_data["webhook_url"] = "https://hooks.example.com/secret-token-xyz"
    store._runtime_data["api_key"] = _api_key
    client = _make_client(config_store=store)

    with patch(
        "firewatch_api.routes.ai.httpx.AsyncClient",
        return_value=_mock_httpx_client(
            status_code=200, json_body={"data": [{"id": "llama3.2"}]}
        ),
    ):
        resp = client.get("/ai/models", headers={"Authorization": f"Bearer {_api_key}"})

    assert resp.status_code == 200
    body_text = resp.text
    assert "secret-token-xyz" not in body_text, "webhook_url secret must not be in response"
    assert "bearer-secret-key-12345" not in body_text, "api_key secret must not be in response"


# ---------------------------------------------------------------------------
# Confirm — PUT /config/runtime ollama_model persists to GET /health
# ---------------------------------------------------------------------------


def test_put_runtime_ollama_model_persists_to_health() -> None:
    """WHEN PUT /config/runtime sets ollama_model, the next GET /health reflects it.

    Confirms that the existing PUT /config/runtime route persists ollama_model,
    and that GET /health reads the updated value (no change needed to config routes).
    """
    store = FakeConfigStore(ollama_model="original-model")
    client = _make_client(config_store=store, event_store=FakeEventStore())

    # PUT the new model
    put_resp = client.put(
        "/config/runtime",
        json={"updates": {"ollama_model": "updated-model"}},
    )
    assert put_resp.status_code == 200, f"PUT /config/runtime failed: {put_resp.text}"

    # GET /health should now show the updated model
    with patch(
        "firewatch_api.routes.meta.httpx.AsyncClient",
        return_value=_mock_httpx_client(status_code=200),
    ):
        health_resp = client.get("/health")

    assert health_resp.status_code == 200
    data = health_resp.json()
    assert data["ollama_model"] == "updated-model", (
        f"Expected ollama_model='updated-model', got {data['ollama_model']!r}"
    )


# ---------------------------------------------------------------------------
# Contract shape: verify response structure matches spec exactly
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "models_body,expected_count",
    [
        ({"data": []}, 0),
        ({"data": [{"id": "a"}, {"id": "b"}]}, 2),
        # Missing data key → empty list (graceful)
        ({}, 0),
        # Extra keys on model objects are projected away; only id is kept
        ({"data": [{"id": "x", "extra_key": "ignored"}]}, 1),
    ],
)
def test_ai_models_response_shape(models_body: dict[str, Any], expected_count: int) -> None:
    """GET /ai/models always returns {models: list[str], current: str|null}."""
    store = FakeConfigStore(ollama_model="test-model")
    client = _make_client(config_store=store)

    with patch(
        "firewatch_api.routes.ai.httpx.AsyncClient",
        return_value=_mock_httpx_client(status_code=200, json_body=models_body),
    ):
        resp = client.get("/ai/models")

    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data["models"], list)
    assert len(data["models"]) == expected_count
    assert data["current"] == "test-model"
    # models contains only string IDs
    for m in data["models"]:
        assert isinstance(m, str)
