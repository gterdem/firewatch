"""Tests for POST /logs/nl-query route (ML-6 / ADR-0049 / issue #434).

EARS mapping:
  EARS-1: LLM output validated before execution — response carries validated FilterSpec.
  EARS-2: OOV/low-confidence → degraded=true, filter_spec.q = nl_text.
  EARS-3: provenance tag ("ai" / "ai_degraded") returned for frontend chip rendering.
  EARS-4: vocabulary from store at runtime — tested via the engine/vocab layer.
  EARS-5: zero-egress — parse_nl_query is mocked; no real LLM call.

Security boundary verified here:
  - config_store=None → 503 (base_url cannot be resolved).
  - Malformed request body → 422 (Pydantic validation).
  - Degraded parse stays as q= — never a fabricated filter.

All IPs use RFC 5737 / RFC 1918 ranges (192.0.2.0/24, 198.51.100.0/24, 10.x.x.x).
"""
from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from firewatch_sdk.models import FilterSpec

from firewatch_api.app import create_app
from firewatch_api.deps import get_config_store


# ---------------------------------------------------------------------------
# Fake config store
# ---------------------------------------------------------------------------


class _FakeConfigStore:
    """Minimal config store for the NL query route tests."""

    def get_runtime(self) -> Any:
        from firewatch_sdk import RuntimeConfig

        return RuntimeConfig(
            ollama_base_url="http://127.0.0.1:11434",
            ollama_model="llama3",
        )


# ---------------------------------------------------------------------------
# Fake NlQueryResult shapes
# ---------------------------------------------------------------------------


def _make_result(
    filter_spec: FilterSpec,
    degraded: bool = False,
    provenance: str = "ai",
    error: str | None = None,
) -> Any:
    """Build a fake NlQueryResult-like object."""
    from firewatch_core.nl_query.engine import NlQueryResult

    return NlQueryResult(
        filter_spec=filter_spec,
        degraded=degraded,
        provenance=provenance,
        error=error,
    )


# ---------------------------------------------------------------------------
# Client fixture helpers
# ---------------------------------------------------------------------------


def _make_client(config_store: Any = None) -> TestClient:
    """Create a TestClient with the given config_store injected."""
    app = create_app()
    cs = config_store if config_store is not None else _FakeConfigStore()
    app.dependency_overrides[get_config_store] = lambda: cs
    return TestClient(app)


def _make_client_no_store() -> TestClient:
    """Create a TestClient with no config_store (→ 503)."""
    app = create_app()
    app.dependency_overrides[get_config_store] = lambda: None
    return TestClient(app)


# ---------------------------------------------------------------------------
# EARS-1: validated FilterSpec returned
# ---------------------------------------------------------------------------


class TestNlQueryValidParse:
    """EARS-1 — validated LLM parse returns a structured FilterSpec."""

    def test_valid_parse_returns_200(self) -> None:
        """POST /logs/nl-query returns 200 on a valid NL query."""
        client = _make_client()
        fake_result = _make_result(
            FilterSpec(action="BLOCK", severity="high"),
            degraded=False,
            provenance="ai",
        )
        with patch(
            "firewatch_api.routes.nl_query.parse_nl_query",
            new=AsyncMock(return_value=fake_result),
        ):
            res = client.post("/logs/nl-query", json={"query": "show high severity blocked traffic"})

        assert res.status_code == 200

    def test_valid_parse_response_shape(self) -> None:
        """Response has filter_spec, degraded, provenance keys."""
        client = _make_client()
        fake_result = _make_result(
            FilterSpec(action="BLOCK", severity="high"),
            degraded=False,
            provenance="ai",
        )
        with patch(
            "firewatch_api.routes.nl_query.parse_nl_query",
            new=AsyncMock(return_value=fake_result),
        ):
            res = client.post("/logs/nl-query", json={"query": "blocked high severity"})

        body = res.json()
        assert "filter_spec" in body
        assert "degraded" in body
        assert "provenance" in body
        assert "error" in body

    def test_valid_parse_filter_spec_contains_fields(self) -> None:
        """Validated parse populates filter_spec with the parsed fields (EARS-1)."""
        client = _make_client()
        fake_result = _make_result(
            FilterSpec(action="BLOCK", severity="high"),
            degraded=False,
            provenance="ai",
        )
        with patch(
            "firewatch_api.routes.nl_query.parse_nl_query",
            new=AsyncMock(return_value=fake_result),
        ):
            res = client.post("/logs/nl-query", json={"query": "blocked high"})

        body = res.json()
        assert body["filter_spec"].get("action") == "BLOCK"
        assert body["filter_spec"].get("severity") == "high"
        assert not body["degraded"]

    def test_valid_parse_provenance_is_ai(self) -> None:
        """Provenance is 'ai' when parse succeeds (EARS-3)."""
        client = _make_client()
        fake_result = _make_result(
            FilterSpec(severity="critical"),
            degraded=False,
            provenance="ai",
        )
        with patch(
            "firewatch_api.routes.nl_query.parse_nl_query",
            new=AsyncMock(return_value=fake_result),
        ):
            res = client.post("/logs/nl-query", json={"query": "critical events"})

        assert res.json()["provenance"] == "ai"

    def test_filter_spec_excludes_none_fields(self) -> None:
        """filter_spec in response omits None fields (only non-None values)."""
        client = _make_client()
        fake_result = _make_result(
            FilterSpec(action="ALERT"),
            degraded=False,
            provenance="ai",
        )
        with patch(
            "firewatch_api.routes.nl_query.parse_nl_query",
            new=AsyncMock(return_value=fake_result),
        ):
            res = client.post("/logs/nl-query", json={"query": "alerts"})

        body = res.json()
        # cursor, ip, severity, etc. should NOT appear (they are None)
        spec = body["filter_spec"]
        assert "action" in spec
        assert "cursor" not in spec
        assert "ip" not in spec


# ---------------------------------------------------------------------------
# EARS-2: OOV / low-confidence → degraded
# ---------------------------------------------------------------------------


class TestNlQueryDegradedParse:
    """EARS-2 — degraded parse falls back to q= free-text."""

    def test_degraded_parse_is_200(self) -> None:
        """Degraded parse still returns HTTP 200 (not an error condition)."""
        client = _make_client()
        nl = "show me something"
        fake_result = _make_result(
            FilterSpec(q=nl),
            degraded=True,
            provenance="ai_degraded",
            error="LLM confidence too low",
        )
        with patch(
            "firewatch_api.routes.nl_query.parse_nl_query",
            new=AsyncMock(return_value=fake_result),
        ):
            res = client.post("/logs/nl-query", json={"query": nl})

        assert res.status_code == 200

    def test_degraded_parse_sets_degraded_flag(self) -> None:
        """Response degraded=true when parse fell back to q= (EARS-2)."""
        client = _make_client()
        nl = "something unknown"
        fake_result = _make_result(
            FilterSpec(q=nl),
            degraded=True,
            provenance="ai_degraded",
        )
        with patch(
            "firewatch_api.routes.nl_query.parse_nl_query",
            new=AsyncMock(return_value=fake_result),
        ):
            res = client.post("/logs/nl-query", json={"query": nl})

        body = res.json()
        assert body["degraded"] is True
        assert body["provenance"] == "ai_degraded"

    def test_degraded_filter_spec_carries_q(self) -> None:
        """Degraded filter_spec.q equals the original NL query."""
        client = _make_client()
        nl = "query that triggered degradation"
        fake_result = _make_result(
            FilterSpec(q=nl),
            degraded=True,
            provenance="ai_degraded",
        )
        with patch(
            "firewatch_api.routes.nl_query.parse_nl_query",
            new=AsyncMock(return_value=fake_result),
        ):
            res = client.post("/logs/nl-query", json={"query": nl})

        body = res.json()
        assert body["filter_spec"].get("q") == nl

    def test_degraded_filter_spec_has_no_action_or_severity(self) -> None:
        """Degraded response must not carry hallucinated field values."""
        client = _make_client()
        nl = "unrecognized query"
        fake_result = _make_result(
            FilterSpec(q=nl),
            degraded=True,
            provenance="ai_degraded",
        )
        with patch(
            "firewatch_api.routes.nl_query.parse_nl_query",
            new=AsyncMock(return_value=fake_result),
        ):
            res = client.post("/logs/nl-query", json={"query": nl})

        spec = res.json()["filter_spec"]
        assert "action" not in spec
        assert "severity" not in spec


# ---------------------------------------------------------------------------
# EARS-3: provenance tag in response
# ---------------------------------------------------------------------------


class TestNlQueryProvenance:
    """EARS-3 — provenance tag drives the AI provenance chip on the frontend."""

    def test_provenance_ai_on_success(self) -> None:
        """provenance='ai' when validation succeeded."""
        client = _make_client()
        fake_result = _make_result(FilterSpec(protocol="TCP"), degraded=False, provenance="ai")
        with patch(
            "firewatch_api.routes.nl_query.parse_nl_query",
            new=AsyncMock(return_value=fake_result),
        ):
            res = client.post("/logs/nl-query", json={"query": "TCP traffic"})
        assert res.json()["provenance"] == "ai"

    def test_provenance_ai_degraded_on_fallback(self) -> None:
        """provenance='ai_degraded' when validation fell back to q=."""
        client = _make_client()
        fake_result = _make_result(
            FilterSpec(q="something"), degraded=True, provenance="ai_degraded"
        )
        with patch(
            "firewatch_api.routes.nl_query.parse_nl_query",
            new=AsyncMock(return_value=fake_result),
        ):
            res = client.post("/logs/nl-query", json={"query": "something"})
        assert res.json()["provenance"] == "ai_degraded"


# ---------------------------------------------------------------------------
# Security: 503 when config_store is absent
# ---------------------------------------------------------------------------


class TestNlQueryNoStore:
    """503 when config_store is absent — base_url cannot be resolved (security)."""

    def test_no_config_store_returns_503(self) -> None:
        """Missing config_store returns 503 (endpoint cannot be resolved)."""
        client = _make_client_no_store()
        res = client.post("/logs/nl-query", json={"query": "anything"})
        assert res.status_code == 503

    def test_503_detail_mentions_config(self) -> None:
        """503 detail message is informative."""
        client = _make_client_no_store()
        res = client.post("/logs/nl-query", json={"query": "anything"})
        detail = res.json().get("detail", "")
        assert "Config store" in detail or "config" in detail.lower()


# ---------------------------------------------------------------------------
# Validation: 422 on malformed request body
# ---------------------------------------------------------------------------


class TestNlQueryValidation:
    """422 on malformed request body (Pydantic validation)."""

    def test_missing_query_field_returns_422(self) -> None:
        """Request body without 'query' field → 422."""
        client = _make_client()
        res = client.post("/logs/nl-query", json={"model": "llama3"})
        assert res.status_code == 422

    def test_empty_body_returns_422(self) -> None:
        """Empty request body → 422."""
        client = _make_client()
        res = client.post("/logs/nl-query", json={})
        assert res.status_code == 422

    def test_model_override_accepted(self) -> None:
        """Optional model field is accepted alongside query."""
        client = _make_client()
        fake_result = _make_result(FilterSpec(action="BLOCK"), degraded=False, provenance="ai")
        with patch(
            "firewatch_api.routes.nl_query.parse_nl_query",
            new=AsyncMock(return_value=fake_result),
        ):
            res = client.post(
                "/logs/nl-query",
                json={"query": "blocked traffic", "model": "mistral:7b"},
            )
        assert res.status_code == 200

    def test_empty_string_query_returns_422(self) -> None:
        """SHOULD-FIX-1: empty string query (min_length=1) → 422 before engine runs."""
        client = _make_client()
        res = client.post("/logs/nl-query", json={"query": ""})
        assert res.status_code == 422

    def test_oversized_query_returns_422(self) -> None:
        """SHOULD-FIX-1: query > 500 chars → 422 before engine runs."""
        client = _make_client()
        huge_query = "x" * 501
        res = client.post("/logs/nl-query", json={"query": huge_query})
        assert res.status_code == 422

    def test_max_length_query_accepted(self) -> None:
        """SHOULD-FIX-1: exactly 500-char query is at the cap and accepted (200 OK)."""
        client = _make_client()
        max_query = "a" * 500
        fake_result = _make_result(FilterSpec(q=max_query), degraded=True, provenance="ai_degraded")
        with patch(
            "firewatch_api.routes.nl_query.parse_nl_query",
            new=AsyncMock(return_value=fake_result),
        ):
            res = client.post("/logs/nl-query", json={"query": max_query})
        assert res.status_code == 200

    def test_oversized_model_returns_422(self) -> None:
        """SHOULD-FIX-1: model name > 200 chars → 422 before engine runs."""
        client = _make_client()
        huge_model = "m" * 201
        res = client.post(
            "/logs/nl-query", json={"query": "test", "model": huge_model}
        )
        assert res.status_code == 422
