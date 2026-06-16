"""Tests for MK-4 — GET /ai/engine attestation endpoint + assembler (issue #409, ADR-0047).

EARS criteria → test mapping:

  E1 (event-driven — DTO shape):
    WHEN GET /ai/engine is requested, THE response SHALL return the attestation DTO
    with fields: model, runtime_profile, endpoint_host, endpoint_validated_local,
    analyses_count, last_analysis_at (ADR-0047 D3).
    → test_engine_endpoint_returns_dto_shape
    → test_engine_endpoint_status_200

  E2 (event-driven — endpoint_host is host:port only):
    WHEN GET /ai/engine is requested, THE endpoint_host field SHALL be host:port
    only — never credentials, base path, or query string (OWASP API8).
    → test_endpoint_host_strips_credentials
    → test_endpoint_host_includes_port
    → test_endpoint_host_no_credentials_in_response

  E3 (event-driven — endpoint_validated_local is provable):
    WHEN the configured base_url passes the ADR-0022 local-first guard, THE
    endpoint_validated_local field SHALL be true (derived from _is_local_host,
    not asserted unconditionally).
    → test_endpoint_validated_local_true_for_loopback
    → test_endpoint_validated_local_for_rfc1918

  E4 (event-driven — ledger counters degrade gracefully):
    WHEN the ledger is not yet available (pre-#407), GET /ai/engine SHALL return
    analyses_count=null and last_analysis_at=null, with status 200 (no 500).
    → test_engine_no_ledger_returns_null_counters
    → test_engine_no_ledger_never_500

  E5 (event-driven — ledger counters from ledger when available):
    WHEN a ledger is available and get_summary() returns data, THE DTO SHALL
    reflect analyses_count and last_analysis_at from the ledger.
    → test_engine_with_ledger_returns_counts
    → test_engine_ledger_failure_degrades_gracefully

  E6 (event-driven — runtime_profile derived from config):
    THE runtime_profile SHALL be "ollama" when port is 11434, and "llama.cpp"
    otherwise (ADR-0042 hybrid profiles).
    → test_runtime_profile_ollama_port_11434
    → test_runtime_profile_llamacpp_other_port

  U1 (ubiquitous — class-C route, loopback-open):
    GET /ai/engine SHALL be a class-C route (ADR-0026): accessible on loopback,
    key-gated when exposed.  Route must not require auth on loopback.
    → test_engine_route_accessible_no_auth

  U2 (ubiquitous — claim is scoped to AI inference):
    The DTO field ``endpoint_validated_local`` SHALL be derived from the actual
    base_url value (not hardcoded True), so the claim is provable from config.
    → test_endpoint_validated_local_derivation_is_not_hardcoded

Assembler unit tests (pure, no FastAPI):
    → test_assembler_no_ledger_fields_are_null
    → test_assembler_with_ledger_populates_counts
    → test_assembler_ledger_exception_yields_null
    → test_assembler_endpoint_host_no_userinfo
    → test_assembler_ipv6_endpoint_host
    → test_assembler_runtime_profile_ollama
    → test_assembler_runtime_profile_llamacpp

All fakes use RFC 5737 documentation IPs or loopback — never real routable IPs.
"""
from __future__ import annotations

from typing import Any
import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel

from firewatch_api.app import create_app
from firewatch_api.routes.attestation import (
    _endpoint_host_from_base_url,
    _endpoint_validated_local,
    _runtime_profile_from_base_url,
    build_attestation_dto,
)


# ---------------------------------------------------------------------------
# Fake helpers
# ---------------------------------------------------------------------------


class FakeRuntimeConfig:
    """Minimal stand-in for RuntimeConfig for assembler unit tests."""

    def __init__(
        self,
        ollama_base_url: str = "http://127.0.0.1:11434",
        ollama_model: str = "qwen3:14b",
    ) -> None:
        self.ollama_base_url = ollama_base_url
        self.ollama_model = ollama_model


class FakeConfigStore:
    """Minimal in-memory ConfigStore for route-level tests."""

    def __init__(
        self,
        ollama_base_url: str = "http://127.0.0.1:11434",
        ollama_model: str = "qwen3:14b",
    ) -> None:
        self._runtime_data: dict[str, Any] = {
            "ollama_base_url": ollama_base_url,
            "ollama_model": ollama_model,
        }

    def get_runtime(self) -> Any:
        from firewatch_sdk import RuntimeConfig

        return RuntimeConfig.model_validate(self._runtime_data)

    def set_runtime(self, updates: dict[str, Any]) -> None:
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


class FakeLedger:
    """Minimal ledger fake returning pre-set summary data."""

    def __init__(self, analyses_count: int = 42, last_analysis_at: str | None = "2026-06-12T10:00:00Z") -> None:
        self._summary = {
            "analyses_count": analyses_count,
            "last_analysis_at": last_analysis_at,
        }

    def get_summary(self) -> dict[str, Any]:
        return dict(self._summary)


class BrokenLedger:
    """Ledger that always raises on get_summary()."""

    def get_summary(self) -> dict[str, Any]:
        raise RuntimeError("ledger unavailable")


def _make_client(
    config_store: FakeConfigStore | None = None,
    ledger: Any | None = None,
) -> TestClient:
    store = config_store or FakeConfigStore()
    app = create_app(registry={}, config_store=store)
    # Inject ledger via app state (used by the engine route dep).
    app.state.analysis_ledger = ledger
    return TestClient(app)


# ---------------------------------------------------------------------------
# E1 — DTO shape
# ---------------------------------------------------------------------------


def test_engine_endpoint_status_200() -> None:
    """GET /ai/engine returns HTTP 200."""
    client = _make_client()
    resp = client.get("/ai/engine")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"


def test_engine_endpoint_returns_dto_shape() -> None:
    """GET /ai/engine returns the full attestation DTO with all required fields."""
    client = _make_client()
    resp = client.get("/ai/engine")
    assert resp.status_code == 200
    data = resp.json()
    required_keys = {
        "model",
        "runtime_profile",
        "endpoint_host",
        "endpoint_validated_local",
        "analyses_count",
        "last_analysis_at",
    }
    missing = required_keys - set(data.keys())
    assert not missing, f"DTO missing required keys: {missing}"


# ---------------------------------------------------------------------------
# E2 — endpoint_host is host:port only
# ---------------------------------------------------------------------------


def test_endpoint_host_includes_port() -> None:
    """endpoint_host includes the port number."""
    client = _make_client(FakeConfigStore(ollama_base_url="http://127.0.0.1:11434"))
    resp = client.get("/ai/engine")
    assert resp.status_code == 200
    host = resp.json()["endpoint_host"]
    assert ":" in host, f"endpoint_host must include port, got {host!r}"
    assert host == "127.0.0.1:11434"


def test_endpoint_host_strips_credentials() -> None:
    """endpoint_host must not contain userinfo/credentials (OWASP API8).

    The SDK RuntimeConfig validator already rejects non-local URLs, so we test
    the assembler helper directly with a hypothetical URL containing userinfo.
    """
    # Test the helper directly — SDK would reject this in production,
    # but we confirm the assembler strips it regardless.
    result = _endpoint_host_from_base_url("http://user:pass@127.0.0.1:11434")
    assert "@" not in result, f"Credentials found in endpoint_host: {result!r}"
    assert "user" not in result
    assert "pass" not in result
    assert result == "127.0.0.1:11434"


def test_endpoint_host_no_credentials_in_response() -> None:
    """GET /ai/engine response body must not contain credential-like strings."""
    client = _make_client(FakeConfigStore(ollama_base_url="http://127.0.0.1:11434"))
    resp = client.get("/ai/engine")
    body_text = resp.text
    # Confirm no auth-header-like patterns in the response
    assert "Authorization" not in body_text
    assert "Bearer" not in body_text


# ---------------------------------------------------------------------------
# E3 — endpoint_validated_local is provable
# ---------------------------------------------------------------------------


def test_endpoint_validated_local_true_for_loopback() -> None:
    """endpoint_validated_local is True when base_url points to loopback."""
    client = _make_client(FakeConfigStore(ollama_base_url="http://127.0.0.1:11434"))
    resp = client.get("/ai/engine")
    assert resp.status_code == 200
    assert resp.json()["endpoint_validated_local"] is True


def test_endpoint_validated_local_for_rfc1918() -> None:
    """endpoint_validated_local is True for RFC 1918 LAN addresses (ADR-0022)."""
    # RFC 1918 — 10/8 range (valid for local-first)
    client = _make_client(FakeConfigStore(ollama_base_url="http://10.0.0.1:11434"))
    resp = client.get("/ai/engine")
    assert resp.status_code == 200
    assert resp.json()["endpoint_validated_local"] is True


# ---------------------------------------------------------------------------
# E4 — ledger counters degrade gracefully when not available
# ---------------------------------------------------------------------------


def test_engine_no_ledger_returns_null_counters() -> None:
    """When no ledger is present, analyses_count and last_analysis_at are null."""
    client = _make_client(ledger=None)
    resp = client.get("/ai/engine")
    assert resp.status_code == 200
    data = resp.json()
    assert data["analyses_count"] is None, "analyses_count must be null when ledger absent"
    assert data["last_analysis_at"] is None, "last_analysis_at must be null when ledger absent"


def test_engine_no_ledger_never_500() -> None:
    """GET /ai/engine must never return 500 when ledger is absent (pre-#407 degrade)."""
    client = _make_client(ledger=None)
    resp = client.get("/ai/engine")
    assert resp.status_code != 500, f"Unexpected 500 when ledger absent: {resp.text}"
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# E5 — ledger counters from ledger when available
# ---------------------------------------------------------------------------


def test_engine_with_ledger_returns_counts() -> None:
    """When a ledger is available, analyses_count and last_analysis_at are populated."""
    ledger = FakeLedger(analyses_count=17, last_analysis_at="2026-06-12T08:30:00Z")
    client = _make_client(ledger=ledger)
    resp = client.get("/ai/engine")
    assert resp.status_code == 200
    data = resp.json()
    assert data["analyses_count"] == 17
    assert data["last_analysis_at"] == "2026-06-12T08:30:00Z"


def test_engine_ledger_failure_degrades_gracefully() -> None:
    """When the ledger raises, analyses_count and last_analysis_at degrade to null (no 500)."""
    client = _make_client(ledger=BrokenLedger())
    resp = client.get("/ai/engine")
    assert resp.status_code == 200
    data = resp.json()
    assert data["analyses_count"] is None
    assert data["last_analysis_at"] is None


# ---------------------------------------------------------------------------
# E6 — runtime_profile derived from config
# ---------------------------------------------------------------------------


def test_runtime_profile_ollama_port_11434() -> None:
    """runtime_profile is 'ollama' when base_url uses port 11434."""
    client = _make_client(FakeConfigStore(ollama_base_url="http://127.0.0.1:11434"))
    resp = client.get("/ai/engine")
    assert resp.status_code == 200
    assert resp.json()["runtime_profile"] == "ollama"


def test_runtime_profile_llamacpp_other_port() -> None:
    """runtime_profile is 'llama.cpp' when base_url uses a non-11434 port."""
    client = _make_client(FakeConfigStore(ollama_base_url="http://127.0.0.1:8080"))
    resp = client.get("/ai/engine")
    assert resp.status_code == 200
    assert resp.json()["runtime_profile"] == "llama.cpp"


# ---------------------------------------------------------------------------
# U1 — class-C route, loopback-open (no auth needed on loopback)
# ---------------------------------------------------------------------------


def test_engine_route_accessible_no_auth() -> None:
    """GET /ai/engine is accessible without auth header (class-C, loopback-open, ADR-0026)."""
    client = _make_client()
    resp = client.get("/ai/engine")
    # Must not get 401 or 403 on loopback (class-C, no key required by default)
    assert resp.status_code not in (401, 403), (
        f"Class-C route must be accessible on loopback without auth, got {resp.status_code}"
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# U2 — claim is scoped to AI inference (not hardcoded)
# ---------------------------------------------------------------------------


def test_endpoint_validated_local_derivation_is_not_hardcoded() -> None:
    """endpoint_validated_local is computed from config, not hardcoded True.

    We mock ``_is_local_host`` to return False and confirm the assembler
    propagates that value — proving the field is derived from the predicate,
    not asserted unconditionally.  (In production, RuntimeConfig would reject
    any non-local URL before it ever reaches this path, but the assembler
    itself must not bypass the derivation.)
    """
    from unittest.mock import patch

    from firewatch_api.routes import attestation as attestation_mod

    with patch.object(attestation_mod, "_is_local_host", return_value=False):
        result = _endpoint_validated_local("http://127.0.0.1:11434")

    assert result is False, (
        "endpoint_validated_local must reflect _is_local_host return value, "
        "not hardcode True — derivation proof failed"
    )


# ---------------------------------------------------------------------------
# Assembler unit tests (pure, no FastAPI)
# ---------------------------------------------------------------------------


def test_assembler_no_ledger_fields_are_null() -> None:
    """build_attestation_dto with no ledger yields null for counter fields."""
    from firewatch_sdk import RuntimeConfig

    runtime = RuntimeConfig.model_validate({
        "ollama_base_url": "http://127.0.0.1:11434",
        "ollama_model": "llama3.2",
    })
    dto = build_attestation_dto(runtime, ledger=None)
    assert dto["analyses_count"] is None
    assert dto["last_analysis_at"] is None


def test_assembler_with_ledger_populates_counts() -> None:
    """build_attestation_dto with a ledger populates count and timestamp."""
    from firewatch_sdk import RuntimeConfig

    runtime = RuntimeConfig.model_validate({
        "ollama_base_url": "http://127.0.0.1:11434",
        "ollama_model": "qwen3:14b",
    })
    ledger = FakeLedger(analyses_count=99, last_analysis_at="2026-06-01T00:00:00Z")
    dto = build_attestation_dto(runtime, ledger=ledger)
    assert dto["analyses_count"] == 99
    assert dto["last_analysis_at"] == "2026-06-01T00:00:00Z"


def test_assembler_ledger_exception_yields_null() -> None:
    """build_attestation_dto with a broken ledger returns null (not raises)."""
    from firewatch_sdk import RuntimeConfig

    runtime = RuntimeConfig.model_validate({
        "ollama_base_url": "http://127.0.0.1:11434",
        "ollama_model": "qwen3:14b",
    })
    dto = build_attestation_dto(runtime, ledger=BrokenLedger())
    assert dto["analyses_count"] is None
    assert dto["last_analysis_at"] is None


def test_assembler_endpoint_host_no_userinfo() -> None:
    """_endpoint_host_from_base_url strips userinfo from URLs."""
    result = _endpoint_host_from_base_url("http://admin:secret@127.0.0.1:11434/v1")
    assert "@" not in result
    assert "admin" not in result
    assert "secret" not in result
    assert result == "127.0.0.1:11434"


def test_assembler_ipv6_endpoint_host() -> None:
    """_endpoint_host_from_base_url handles IPv6 loopback correctly."""
    result = _endpoint_host_from_base_url("http://[::1]:11434")
    assert result == "[::1]:11434"


def test_assembler_runtime_profile_ollama() -> None:
    """_runtime_profile_from_base_url returns 'ollama' for port 11434."""
    assert _runtime_profile_from_base_url("http://127.0.0.1:11434") == "ollama"
    assert _runtime_profile_from_base_url("http://localhost:11434") == "ollama"


def test_assembler_runtime_profile_llamacpp() -> None:
    """_runtime_profile_from_base_url returns 'llama.cpp' for non-11434 ports."""
    assert _runtime_profile_from_base_url("http://127.0.0.1:8080") == "llama.cpp"
    assert _runtime_profile_from_base_url("http://10.0.0.1:9000") == "llama.cpp"


def test_assembler_endpoint_host_default_port_http() -> None:
    """_endpoint_host_from_base_url uses port 80 when no port specified for http."""
    result = _endpoint_host_from_base_url("http://127.0.0.1")
    assert result == "127.0.0.1:80"


def test_assembler_endpoint_host_default_port_https() -> None:
    """_endpoint_host_from_base_url uses port 443 when no port specified for https."""
    result = _endpoint_host_from_base_url("https://192.168.1.1")
    assert result == "192.168.1.1:443"


@pytest.mark.parametrize(
    "base_url,expected_model,expected_profile",
    [
        ("http://127.0.0.1:11434", "qwen3:14b", "ollama"),
        ("http://127.0.0.1:8080", "llama3.2", "llama.cpp"),
        ("http://10.0.0.5:11434", "mistral:7b", "ollama"),
    ],
)
def test_assembler_full_dto_shape(
    base_url: str, expected_model: str, expected_profile: str
) -> None:
    """build_attestation_dto produces a complete DTO with all required keys."""
    from firewatch_sdk import RuntimeConfig

    runtime = RuntimeConfig.model_validate({
        "ollama_base_url": base_url,
        "ollama_model": expected_model,
    })
    dto = build_attestation_dto(runtime, ledger=None)

    required_keys = {
        "model",
        "runtime_profile",
        "endpoint_host",
        "endpoint_validated_local",
        "analyses_count",
        "last_analysis_at",
    }
    assert required_keys == set(dto.keys())
    assert dto["model"] == expected_model
    assert dto["runtime_profile"] == expected_profile
    assert isinstance(dto["endpoint_host"], str)
    assert isinstance(dto["endpoint_validated_local"], bool)
