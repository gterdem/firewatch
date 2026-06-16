"""Tests for issue #548 — per-route-class auth middleware (ADR-0026 Decisions 2-3 + Amendment 1).

EARS criterion → test mapping
─────────────────────────────

Event-driven: api_key unset + loopback → all routes open (no auth):
  TestNoKeyAllRoutesOpen
    test_no_key_class_c_open
    test_no_key_class_a_open
    test_no_key_class_b_open

Event-driven: api_key set → any route without bearer → 401:
  TestKeySetNoBearerIs401
    test_key_set_no_bearer_class_c_is_401
    test_key_set_no_bearer_class_a_is_401
    test_key_set_no_bearer_class_b_is_401

Event-driven: api_key set + wrong bearer → 401:
  TestKeySetWrongBearerIs401
    test_key_set_wrong_bearer_class_c_is_401
    test_key_set_wrong_bearer_class_a_is_401
    test_key_set_wrong_bearer_class_b_is_401

Event-driven: api_key set + correct bearer → served (non-401):
  TestKeySetCorrectBearerServed
    test_key_set_correct_bearer_class_c_served
    test_key_set_correct_bearer_class_a_served
    test_key_set_correct_bearer_class_b_served

ADR-0026 Amendment 1 regression: loopback + key set → ENFORCED (not dormant):
  TestLoopbackWithKeyEnforced
    test_loopback_with_key_no_bearer_is_401
    test_loopback_with_key_wrong_bearer_is_401
    test_loopback_with_key_correct_bearer_is_served

WWW-Authenticate header on 401 (RFC 6750 §3):
  TestWWWAuthenticateHeader
    test_401_has_www_authenticate_bearer

api_key never leaked in 401:
  TestKeyNeverLeaked
    test_key_not_in_401_response_body
    test_key_not_in_401_response_headers

Credential extraction (RFC 6750):
  TestCredentialExtraction
    test_extract_valid_bearer
    test_extract_missing_header_returns_none
    test_extract_non_bearer_scheme_returns_none
    test_extract_empty_after_bearer_returns_none
    test_extract_whitespace_only_token_returns_none
    test_extract_case_insensitive_bearer

Constant-time compare (ubiquitous EARS):
  TestConstantTimeCompare
    test_verify_uses_hmac_compare_digest
    test_no_direct_equality_in_verify

Posture policy (unit tests on posture.py):
  TestPosturePolicy
    test_no_key_class_a_is_noop
    test_no_key_class_b_is_noop
    test_no_key_class_c_is_noop
    test_key_set_class_a_gates
    test_key_set_class_b_gates
    test_key_set_class_c_gates
    test_posture_keys_on_key_not_bind

Posture is FastAPI-free:
  TestPostureIsolated
    test_posture_no_fastapi_import

Route class coverage:
  TestRouteClassCoverage
    test_all_routes_have_route_class
    test_route_class_enum_has_a_b_c

Hard floor A/B:
  TestHardFloorAB
    test_class_a_route_gated_with_key
    test_class_b_route_gated_with_key
    test_class_a_passes_with_correct_bearer
    test_class_b_passes_with_correct_bearer

verify_bearer_token unit tests:
  TestVerifyBearerToken
    test_matching_token_returns_true
    test_wrong_token_returns_false
    test_none_token_returns_false
    test_empty_token_returns_false
    test_whitespace_token_returns_false
    test_none_configured_no_key_returns_false

Fixtures use RFC 5737 documentation IPs (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
and placeholder bearer tokens — never real/public IPs or real secrets.
"""
from __future__ import annotations

import inspect

from fastapi.testclient import TestClient
from pydantic import SecretStr

# ---------------------------------------------------------------------------
# Placeholder test credential (RFC 5737 spirit — not a real secret)
# ---------------------------------------------------------------------------

_PLACEHOLDER_KEY = "test-placeholder-key-for-548"  # noqa: S105 test fixture only


def _make_client(api_key: str | None) -> TestClient:
    """Build a TestClient backed by create_app with a fake config_store."""
    from unittest.mock import MagicMock

    from firewatch_api.app import create_app
    from firewatch_sdk.config import RuntimeConfig

    runtime = RuntimeConfig(
        api_key=SecretStr(api_key) if api_key is not None else None,
        bind_address="127.0.0.1",
    )
    config_store = MagicMock()
    config_store.get_runtime.return_value = runtime

    app = create_app(config_store=config_store)
    return TestClient(app, raise_server_exceptions=True)


def _bearer(key: str = _PLACEHOLDER_KEY) -> dict[str, str]:
    """Return an Authorization header dict for the given key."""
    return {"Authorization": f"Bearer {key}"}


# Smoke paths — one per route class, all available without optional deps.
# Class C: GET /sources/types (discovery — always available)
_CLASS_C_PATH = "/sources/types"
# Class A: PUT /config/runtime (config-mutating — always available)
_CLASS_A_PATH = "/config/runtime"
# Class B: POST /logs (write door — auth check fires before pipeline check)
_CLASS_B_PATH = "/logs"


# ---------------------------------------------------------------------------
# No key → all routes open
# ---------------------------------------------------------------------------


class TestNoKeyAllRoutesOpen:
    """When api_key is unset the loopback trust boundary applies — no auth."""

    def test_no_key_class_c_open(self) -> None:
        client = _make_client(api_key=None)
        resp = client.get(_CLASS_C_PATH)
        assert resp.status_code != 401

    def test_no_key_class_a_open(self) -> None:
        client = _make_client(api_key=None)
        resp = client.put(_CLASS_A_PATH, json={})
        assert resp.status_code != 401

    def test_no_key_class_b_open(self) -> None:
        client = _make_client(api_key=None)
        resp = client.post(
            _CLASS_B_PATH,
            json={"source_type": "x", "source_id": "y", "data": {}},
        )
        assert resp.status_code != 401


# ---------------------------------------------------------------------------
# Key set + no bearer → 401
# ---------------------------------------------------------------------------


class TestKeySetNoBearerIs401:
    """When api_key is set, any request without a valid bearer must return 401."""

    def test_key_set_no_bearer_class_c_is_401(self) -> None:
        client = _make_client(api_key=_PLACEHOLDER_KEY)
        assert client.get(_CLASS_C_PATH).status_code == 401

    def test_key_set_no_bearer_class_a_is_401(self) -> None:
        client = _make_client(api_key=_PLACEHOLDER_KEY)
        assert client.put(_CLASS_A_PATH, json={}).status_code == 401

    def test_key_set_no_bearer_class_b_is_401(self) -> None:
        client = _make_client(api_key=_PLACEHOLDER_KEY)
        resp = client.post(
            _CLASS_B_PATH,
            json={"source_type": "x", "source_id": "y", "data": {}},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Key set + wrong bearer → 401
# ---------------------------------------------------------------------------


class TestKeySetWrongBearerIs401:
    """A mismatched bearer must return 401 (constant-time comparison)."""

    def test_key_set_wrong_bearer_class_c_is_401(self) -> None:
        client = _make_client(api_key=_PLACEHOLDER_KEY)
        resp = client.get(_CLASS_C_PATH, headers={"Authorization": "Bearer wrong-token"})
        assert resp.status_code == 401

    def test_key_set_wrong_bearer_class_a_is_401(self) -> None:
        client = _make_client(api_key=_PLACEHOLDER_KEY)
        resp = client.put(
            _CLASS_A_PATH,
            json={},
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert resp.status_code == 401

    def test_key_set_wrong_bearer_class_b_is_401(self) -> None:
        client = _make_client(api_key=_PLACEHOLDER_KEY)
        resp = client.post(
            _CLASS_B_PATH,
            json={"source_type": "x", "source_id": "y", "data": {}},
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Key set + correct bearer → served (not 401)
# ---------------------------------------------------------------------------


class TestKeySetCorrectBearerServed:
    """A correct bearer token must let the request pass to the handler."""

    def test_key_set_correct_bearer_class_c_served(self) -> None:
        client = _make_client(api_key=_PLACEHOLDER_KEY)
        resp = client.get(_CLASS_C_PATH, headers=_bearer())
        assert resp.status_code != 401

    def test_key_set_correct_bearer_class_a_served(self) -> None:
        client = _make_client(api_key=_PLACEHOLDER_KEY)
        # May 422/400 from handler, but NOT 401
        resp = client.put(_CLASS_A_PATH, json={}, headers=_bearer())
        assert resp.status_code != 401

    def test_key_set_correct_bearer_class_b_served(self) -> None:
        client = _make_client(api_key=_PLACEHOLDER_KEY)
        # May 422/503 from handler, but NOT 401
        resp = client.post(
            _CLASS_B_PATH,
            json={"source_type": "x", "source_id": "y", "data": {}},
            headers=_bearer(),
        )
        assert resp.status_code != 401


# ---------------------------------------------------------------------------
# ADR-0026 Amendment 1 regression: loopback + key set → ENFORCED
# ---------------------------------------------------------------------------


class TestLoopbackWithKeyEnforced:
    """Enforce-when-set: a configured key is enforced on loopback too (Amendment 1)."""

    def test_loopback_with_key_no_bearer_is_401(self) -> None:
        """key set + loopback bind + no bearer → 401 (not open/dormant)."""
        client = _make_client(api_key=_PLACEHOLDER_KEY)
        resp = client.get(_CLASS_C_PATH)
        assert resp.status_code == 401, (
            "ADR-0026 Amendment 1 violation: a configured api_key must be enforced "
            "even on loopback — enforce-when-set, not dormant-on-loopback"
        )

    def test_loopback_with_key_wrong_bearer_is_401(self) -> None:
        client = _make_client(api_key=_PLACEHOLDER_KEY)
        resp = client.get(_CLASS_C_PATH, headers={"Authorization": "Bearer bad-token"})
        assert resp.status_code == 401

    def test_loopback_with_key_correct_bearer_is_served(self) -> None:
        client = _make_client(api_key=_PLACEHOLDER_KEY)
        resp = client.get(_CLASS_C_PATH, headers=_bearer())
        assert resp.status_code != 401


# ---------------------------------------------------------------------------
# WWW-Authenticate header on 401 (RFC 6750 §3)
# ---------------------------------------------------------------------------


class TestWWWAuthenticateHeader:
    """RFC 6750 §3: 401 responses MUST include WWW-Authenticate: Bearer."""

    def test_401_has_www_authenticate_bearer(self) -> None:
        client = _make_client(api_key=_PLACEHOLDER_KEY)
        resp = client.get(_CLASS_C_PATH)
        assert resp.status_code == 401
        www_auth = resp.headers.get("www-authenticate", "")
        assert www_auth.startswith("Bearer"), (
            f"Expected WWW-Authenticate: Bearer ..., got: {www_auth!r}"
        )


# ---------------------------------------------------------------------------
# api_key never leaked in 401 response
# ---------------------------------------------------------------------------


class TestKeyNeverLeaked:
    """The api_key value must not appear in any 401 response."""

    def test_key_not_in_401_response_body(self) -> None:
        client = _make_client(api_key=_PLACEHOLDER_KEY)
        resp = client.get(_CLASS_C_PATH)
        assert resp.status_code == 401
        assert _PLACEHOLDER_KEY not in resp.text, (
            "api_key value must not be leaked in the 401 response body"
        )

    def test_key_not_in_401_response_headers(self) -> None:
        client = _make_client(api_key=_PLACEHOLDER_KEY)
        resp = client.get(_CLASS_C_PATH)
        all_headers = " ".join(f"{k}:{v}" for k, v in resp.headers.items())
        assert _PLACEHOLDER_KEY not in all_headers, (
            "api_key value must not be leaked in 401 response headers"
        )


# ---------------------------------------------------------------------------
# Credential extraction — RFC 6750 parsing (unit tests on auth/credential.py)
# ---------------------------------------------------------------------------


class TestCredentialExtraction:
    """Bearer extraction from Authorization header (RFC 6750)."""

    def _extract(self, header: str | None) -> str | None:
        from firewatch_api.auth.credential import extract_bearer_token
        return extract_bearer_token(header)

    def test_extract_valid_bearer(self) -> None:
        assert self._extract("Bearer my-token-value") == "my-token-value"

    def test_extract_missing_header_returns_none(self) -> None:
        assert self._extract(None) is None

    def test_extract_non_bearer_scheme_returns_none(self) -> None:
        assert self._extract("Basic dXNlcjpwYXNz") is None

    def test_extract_empty_after_bearer_returns_none(self) -> None:
        assert self._extract("Bearer ") is None

    def test_extract_whitespace_only_token_returns_none(self) -> None:
        assert self._extract("Bearer    ") is None

    def test_extract_case_insensitive_bearer(self) -> None:
        """RFC 6750 scheme name is case-insensitive."""
        result = self._extract("bearer my-token")
        assert result == "my-token"


# ---------------------------------------------------------------------------
# Constant-time comparison (ubiquitous EARS criterion)
# ---------------------------------------------------------------------------


class TestConstantTimeCompare:
    """Credential check MUST use hmac.compare_digest."""

    def test_verify_uses_hmac_compare_digest(self) -> None:
        from firewatch_api.auth import credential
        src = inspect.getsource(credential)
        assert "compare_digest" in src, (
            "credential.py must use hmac.compare_digest for constant-time comparison"
        )

    def test_no_direct_equality_in_verify(self) -> None:
        """verify_bearer_token must not use == for comparison (timing-attack risk)."""
        from firewatch_api.auth.credential import verify_bearer_token
        verify_src = inspect.getsource(verify_bearer_token)
        # If == appears, compare_digest must also appear (i.e. == is not the comparison)
        if "==" in verify_src:
            assert "compare_digest" in verify_src, (
                "verify_bearer_token must use compare_digest if any == is present"
            )


# ---------------------------------------------------------------------------
# Posture policy (unit tests — FastAPI-free)
# ---------------------------------------------------------------------------


class TestPosturePolicy:
    """auth/posture.py is the pure policy: (api_key, route_class) → gate | no_op."""

    def _posture(self):
        from firewatch_api.auth.posture import AuthPosture
        return AuthPosture

    def test_no_key_class_a_is_noop(self) -> None:
        from firewatch_api.auth.classes import RouteClass
        assert self._posture().should_gate(api_key=None, route_class=RouteClass.A) is False

    def test_no_key_class_b_is_noop(self) -> None:
        from firewatch_api.auth.classes import RouteClass
        assert self._posture().should_gate(api_key=None, route_class=RouteClass.B) is False

    def test_no_key_class_c_is_noop(self) -> None:
        from firewatch_api.auth.classes import RouteClass
        assert self._posture().should_gate(api_key=None, route_class=RouteClass.C) is False

    def test_key_set_class_a_gates(self) -> None:
        from firewatch_api.auth.classes import RouteClass
        assert self._posture().should_gate(api_key=SecretStr("s"), route_class=RouteClass.A) is True

    def test_key_set_class_b_gates(self) -> None:
        from firewatch_api.auth.classes import RouteClass
        assert self._posture().should_gate(api_key=SecretStr("s"), route_class=RouteClass.B) is True

    def test_key_set_class_c_gates(self) -> None:
        from firewatch_api.auth.classes import RouteClass
        assert self._posture().should_gate(api_key=SecretStr("s"), route_class=RouteClass.C) is True

    def test_posture_keys_on_key_not_bind(self) -> None:
        """should_gate must not take a bind_address parameter (keys on key only)."""
        from firewatch_api.auth.posture import AuthPosture
        sig = inspect.signature(AuthPosture.should_gate)
        params = list(sig.parameters.keys())
        assert "bind" not in params and "bind_address" not in params, (
            "posture.should_gate must not branch on bind address (ADR-0026 Amendment 1)"
        )


# ---------------------------------------------------------------------------
# Posture is FastAPI-free (testable in isolation)
# ---------------------------------------------------------------------------


class TestPostureIsolated:
    """posture.py must not import FastAPI."""

    def test_posture_no_fastapi_import(self) -> None:
        import importlib.util
        import sys

        mod_name = "firewatch_api.auth.posture"
        if mod_name in sys.modules:
            src = inspect.getsource(sys.modules[mod_name])
        else:
            spec = importlib.util.find_spec(mod_name)
            assert spec is not None, "firewatch_api.auth.posture module not found"
            assert spec.origin is not None
            with open(spec.origin) as f:
                src = f.read()

        assert "fastapi" not in src.lower(), (
            "auth/posture.py must not import FastAPI — it is a pure policy module"
        )


# ---------------------------------------------------------------------------
# Route class coverage — every mounted route must be classified
# ---------------------------------------------------------------------------


class TestRouteClassCoverage:
    """Every APIRoute on the app must carry an explicit RouteClass."""

    def test_all_routes_have_route_class(self) -> None:
        from unittest.mock import MagicMock

        from fastapi.routing import APIRoute

        from firewatch_api.app import create_app
        from firewatch_api.auth.classes import ROUTE_CLASS_STATE_KEY
        from firewatch_sdk.config import RuntimeConfig

        config_store = MagicMock()
        config_store.get_runtime.return_value = RuntimeConfig()
        app = create_app(config_store=config_store)

        unclassified = []
        for route in app.routes:
            if not isinstance(route, APIRoute):
                continue
            rc = getattr(route.endpoint, ROUTE_CLASS_STATE_KEY, None)
            if rc is None:
                unclassified.append(f"{sorted(route.methods or [])} {route.path}")

        assert not unclassified, (
            "The following routes have no RouteClass declaration "
            "(must be A, B, or C per ADR-0026 Decision 3):\n"
            + "\n".join(f"  {r}" for r in unclassified)
        )

    def test_route_class_enum_has_a_b_c(self) -> None:
        from firewatch_api.auth.classes import RouteClass
        assert {rc.name for rc in RouteClass} == {"A", "B", "C"}


# ---------------------------------------------------------------------------
# Hard floor A/B: gated whenever a key is set, no relaxation possible
# ---------------------------------------------------------------------------


class TestHardFloorAB:
    """Class A and B are gated whenever a key is set (non-negotiable floor)."""

    def test_class_a_route_gated_with_key(self) -> None:
        client = _make_client(api_key=_PLACEHOLDER_KEY)
        assert client.put(_CLASS_A_PATH, json={}).status_code == 401

    def test_class_b_route_gated_with_key(self) -> None:
        client = _make_client(api_key=_PLACEHOLDER_KEY)
        resp = client.post(
            _CLASS_B_PATH,
            json={"source_type": "x", "source_id": "y", "data": {}},
        )
        assert resp.status_code == 401

    def test_class_a_passes_with_correct_bearer(self) -> None:
        client = _make_client(api_key=_PLACEHOLDER_KEY)
        resp = client.put(_CLASS_A_PATH, json={}, headers=_bearer())
        assert resp.status_code != 401

    def test_class_b_passes_with_correct_bearer(self) -> None:
        client = _make_client(api_key=_PLACEHOLDER_KEY)
        resp = client.post(
            _CLASS_B_PATH,
            json={"source_type": "x", "source_id": "y", "data": {}},
            headers=_bearer(),
        )
        assert resp.status_code != 401


# ---------------------------------------------------------------------------
# verify_bearer_token unit tests
# ---------------------------------------------------------------------------


class TestVerifyBearerToken:
    """Unit tests for the constant-time token verification function."""

    def _verify(self, provided: str | None, configured: SecretStr | None) -> bool:
        from firewatch_api.auth.credential import verify_bearer_token
        return verify_bearer_token(provided, configured)

    def test_matching_token_returns_true(self) -> None:
        assert self._verify("abc123", SecretStr("abc123")) is True

    def test_wrong_token_returns_false(self) -> None:
        assert self._verify("wrong", SecretStr("abc123")) is False

    def test_none_token_returns_false(self) -> None:
        assert self._verify(None, SecretStr("abc123")) is False

    def test_empty_token_returns_false(self) -> None:
        assert self._verify("", SecretStr("abc123")) is False

    def test_whitespace_token_returns_false(self) -> None:
        assert self._verify("   ", SecretStr("abc123")) is False

    def test_none_configured_returns_false(self) -> None:
        """When no key is configured, verify must never return True."""
        assert self._verify("anything", None) is False


# ---------------------------------------------------------------------------
# /docs and /openapi.json — gated when api_key is set (Finding 4)
# ---------------------------------------------------------------------------


class TestOpenAPIDocsGated:
    """GET /openapi.json and GET /docs must return 401 when api_key is set.

    AuthMiddleware gates ALL routes — including FastAPI's built-in OpenAPI schema
    and Swagger UI endpoints — when api_key is configured.  This test locks in
    that behaviour so a future FastAPI upgrade or router change cannot silently
    expose the schema without credentials.
    """

    def test_openapi_json_returns_401_when_key_set(self) -> None:
        client = _make_client(api_key=_PLACEHOLDER_KEY)
        resp = client.get("/openapi.json")
        assert resp.status_code == 401, (
            f"Expected 401 for /openapi.json when api_key is set; got {resp.status_code}"
        )
        assert "Bearer" in resp.headers.get("WWW-Authenticate", ""), (
            "401 response missing WWW-Authenticate: Bearer (RFC 6750 §3)"
        )

    def test_docs_returns_401_when_key_set(self) -> None:
        client = _make_client(api_key=_PLACEHOLDER_KEY)
        resp = client.get("/docs")
        assert resp.status_code == 401, (
            f"Expected 401 for /docs when api_key is set; got {resp.status_code}"
        )

    def test_openapi_json_open_when_no_key(self) -> None:
        """Schema is accessible without credentials when no api_key is configured."""
        client = _make_client(api_key=None)
        resp = client.get("/openapi.json")
        assert resp.status_code == 200, (
            f"Expected 200 for /openapi.json when no api_key; got {resp.status_code}"
        )
