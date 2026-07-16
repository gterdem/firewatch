"""Tests for GET/PUT /config/sources/{type_key} and GET/PUT /config/runtime.

MA.3b (issue #45) EARS criteria → test mapping:

  Ubiquitous (source-agnostic):
    U1 — The routes module must not import any concrete plugin or hardcode a source name.
         → test_config_routes_no_concrete_plugin_import

  Ubiquitous (secret not echoed):
    U2 — A GET /config/sources/{type_key} response must never contain a stored SecretStr
         value in plaintext.
         → test_get_source_config_does_not_echo_secret

  Event-driven (valid PUT persists):
    E1 — When a valid PUT /config/sources/{type_key} is received, it shall validate
         updates against the plugin schema and persist atomically via ConfigStore.set_source.
         → test_put_source_config_valid_persists
    E2 — Round-trip: GET after PUT returns the persisted values.
         → test_get_after_put_returns_persisted_values
    E3 — When a valid PUT /config/runtime is received, it shall persist via
         ConfigStore.set_runtime.
         → test_put_runtime_config_valid_persists
    E4 — GET /config/runtime returns the current runtime config.
         → test_get_runtime_config_returns_config

  Unwanted (invalid PUT rejected, nothing persisted):
    W1 — If a PUT body fails schema validation, the route shall reject it (4xx) and
         persist nothing.
         → test_put_source_config_invalid_body_rejected_nothing_persisted
    W2 — If a PUT targets an env-locked key, the route shall reject it.
         → test_put_source_config_env_locked_field_rejected
    W3 — If a PUT /config/runtime body is env-locked, it shall be rejected.
         → test_put_runtime_config_env_locked_rejected
    W4 — GET /config/sources/{type_key} for an unknown type_key returns 404.
         → test_get_unknown_type_key_returns_404
    W5 — PUT /config/sources/{type_key} for an unknown type_key returns 404.
         → test_put_unknown_type_key_returns_404

  Suricata D5 — reveal-not-require schema shape (ADR-0028):
    S1 — SuricataConfig's JSON Schema 'then' (remote mode) branch adds 'properties'
         (reveal-on-toggle), not merely 'required'.
         → test_suricata_then_branch_adds_properties
    S2 — The 'else' (local mode) branch adds 'properties' for local fields.
         → test_suricata_else_branch_adds_properties

ADR-0026: routes are class A (config-mutating); loopback-only for MA; no auth wired.
"""
from __future__ import annotations

import importlib
import types
from typing import Any

from fastapi.testclient import TestClient
from pydantic import BaseModel, SecretStr

from firewatch_api.app import create_app
from _api_fakes import FakePullPlugin


# ---------------------------------------------------------------------------
# Fake ConfigStore
# ---------------------------------------------------------------------------


class FakeConfigStore:
    """Minimal in-memory ConfigStore for API route tests.

    Tracks whether set_source / set_runtime was called and with what args so
    tests can assert that invalid-PUT attempts do NOT persist.
    """

    def __init__(self) -> None:
        self._source_data: dict[str, dict[str, Any]] = {}
        self._runtime_data: dict[str, Any] = {}
        self.set_source_calls: list[tuple[str, type[BaseModel], dict[str, Any]]] = []
        self.set_runtime_calls: list[dict[str, Any]] = []
        self._env_locked_fields: set[str] = set()
        self._env_locked_runtime_fields: set[str] = set()

    # ---- per-source ----------------------------------------------------------

    def get_source(self, source_type: str, schema: type[BaseModel]) -> BaseModel:
        section = self._source_data.get(source_type, {})
        return schema.model_validate(section)

    def set_source(
        self,
        source_type: str,
        schema: type[BaseModel],
        updates: dict[str, Any],
    ) -> None:
        self.set_source_calls.append((source_type, schema, updates))
        # Simulate env-lock rejection.
        blocked = set(updates) & self._env_locked_fields
        if blocked:
            raise ValueError(
                f"Cannot write config fields currently locked by env vars: "
                f"{sorted(blocked)}."
            )
        # Simulate schema validation rejection.
        merged = {**self._source_data.get(source_type, {}), **updates}
        schema.model_validate(merged)  # raises ValidationError on bad data
        self._source_data[source_type] = merged

    # ---- runtime -------------------------------------------------------------

    def get_runtime(self) -> Any:
        from firewatch_sdk import RuntimeConfig

        return RuntimeConfig.model_validate(self._runtime_data)

    def set_runtime(self, updates: dict[str, Any]) -> None:
        self.set_runtime_calls.append(updates)
        blocked = set(updates) & self._env_locked_runtime_fields
        if blocked:
            raise ValueError(
                f"Cannot write config fields currently locked by env vars: "
                f"{sorted(blocked)}."
            )
        from firewatch_sdk import RuntimeConfig

        merged = {**self._runtime_data, **updates}
        RuntimeConfig.model_validate(merged)
        self._runtime_data = merged


# ---------------------------------------------------------------------------
# Fake plugin with a SecretStr field
# ---------------------------------------------------------------------------


class _SecretConfig(BaseModel):
    """Config model with a SecretStr field — used to test secret non-echo."""

    host: str = "192.0.2.1"
    api_key: SecretStr | None = None


class FakeSecretPlugin:
    """Fake plugin whose config_schema has a SecretStr field."""

    def metadata(self) -> Any:
        from firewatch_sdk import SourceMetadata

        return SourceMetadata(
            type_key="fakesecret",
            display_name="Fake Secret Plugin",
            version="1.0.0",
            flavor="pull",
        )

    def config_schema(self) -> type[BaseModel]:
        return _SecretConfig

    def validate_config(self, cfg: dict[str, Any]) -> None:
        _SecretConfig.model_validate(cfg)

    def normalize(self, raw: Any, source_id: str) -> Any:
        raise NotImplementedError

    async def health_check(self, cfg: BaseModel) -> bool:
        return True


# ---------------------------------------------------------------------------
# Helper builders
# ---------------------------------------------------------------------------


def _make_registry(*plugins: Any) -> dict[str, Any]:
    return {p.metadata().type_key: p for p in plugins}


def _make_client(
    registry: dict[str, Any],
    config_store: FakeConfigStore | None = None,
) -> TestClient:
    store = config_store or FakeConfigStore()
    app = create_app(registry=registry, config_store=store)
    return TestClient(app)


# ---------------------------------------------------------------------------
# U1 — source-agnostic: no concrete plugin import in config routes
# ---------------------------------------------------------------------------


def test_config_routes_no_concrete_plugin_import() -> None:
    """The config routes module imports only SDK/core — no concrete plugin or legacy."""
    config_module = importlib.import_module("firewatch_api.routes.config")
    forbidden = ("firewatch_suricata", "firewatch_syslog", "legacy")
    for name, obj in vars(config_module).items():
        if isinstance(obj, types.ModuleType):
            for prefix in forbidden:
                assert not obj.__name__.startswith(prefix), (
                    f"firewatch_api.routes.config imports forbidden module {obj.__name__}"
                )


# ---------------------------------------------------------------------------
# U2 — secret not echoed on GET
# ---------------------------------------------------------------------------


def test_get_source_config_does_not_echo_secret() -> None:
    """GET /config/sources/{type_key} must never echo a stored SecretStr in plaintext.

    A stored SSH key / API key must not appear as a raw string in the response body.
    """
    plugin = FakeSecretPlugin()
    store = FakeConfigStore()
    store._source_data["fakesecret"] = {
        "host": "192.0.2.1",
        "api_key": "super-secret-value",
    }
    client = _make_client(_make_registry(plugin), store)

    resp = client.get("/config/sources/fakesecret")

    assert resp.status_code == 200
    body_text = resp.text
    assert "super-secret-value" not in body_text, (
        "SecretStr value must NOT be echoed back in the GET response. "
        f"Response body: {body_text!r}"
    )


# ---------------------------------------------------------------------------
# E1 — valid PUT persists via ConfigStore.set_source
# ---------------------------------------------------------------------------


def test_put_source_config_valid_persists() -> None:
    """Valid PUT /config/sources/{type_key} calls ConfigStore.set_source."""
    plugin = FakePullPlugin("suricata")
    store = FakeConfigStore()
    client = _make_client(_make_registry(plugin), store)

    resp = client.put(
        "/config/sources/suricata",
        json={"updates": {"host": "192.0.2.100", "port": 2222}},
    )

    assert resp.status_code == 200
    assert len(store.set_source_calls) == 1
    type_key, schema_cls, updates = store.set_source_calls[0]
    assert type_key == "suricata"
    assert updates["host"] == "192.0.2.100"
    assert updates["port"] == 2222


# ---------------------------------------------------------------------------
# E2 — round-trip: GET after PUT returns persisted values
# ---------------------------------------------------------------------------


def test_get_after_put_returns_persisted_values() -> None:
    """GET /config/sources/{type_key} after PUT returns the stored values."""
    plugin = FakePullPlugin("suricata")
    store = FakeConfigStore()
    client = _make_client(_make_registry(plugin), store)

    put_resp = client.put(
        "/config/sources/suricata",
        json={"updates": {"host": "192.0.2.200", "port": 2222}},
    )
    assert put_resp.status_code == 200

    get_resp = client.get("/config/sources/suricata")
    assert get_resp.status_code == 200
    data = get_resp.json()
    assert data["host"] == "192.0.2.200"
    assert data["port"] == 2222


# ---------------------------------------------------------------------------
# E3 — valid PUT /config/runtime persists
# ---------------------------------------------------------------------------


def test_put_runtime_config_valid_persists() -> None:
    """Valid PUT /config/runtime calls ConfigStore.set_runtime."""
    store = FakeConfigStore()
    client = _make_client({}, store)

    resp = client.put(
        "/config/runtime",
        json={"updates": {"alert_threshold": "HIGH"}},
    )

    assert resp.status_code == 200
    assert len(store.set_runtime_calls) == 1
    assert store.set_runtime_calls[0]["alert_threshold"] == "HIGH"


# ---------------------------------------------------------------------------
# E4 — GET /config/runtime returns current config
# ---------------------------------------------------------------------------


def test_get_runtime_config_returns_config() -> None:
    """GET /config/runtime returns the current RuntimeConfig as a JSON object."""
    store = FakeConfigStore()
    store._runtime_data = {"alert_threshold": "MEDIUM", "alert_on_sync": False}
    client = _make_client({}, store)

    resp = client.get("/config/runtime")

    assert resp.status_code == 200
    data = resp.json()
    assert data["alert_threshold"] == "MEDIUM"
    assert data["alert_on_sync"] is False


# ---------------------------------------------------------------------------
# W1 — invalid PUT rejected, nothing persisted
# ---------------------------------------------------------------------------


def test_put_source_config_invalid_body_rejected_nothing_persisted() -> None:
    """PUT with an invalid body (fails schema validation) is rejected 4xx; nothing persisted.

    The fake plugin's _FakePullConfig requires 'port' to be an integer.
    We send a non-integer port to trigger a ValidationError.
    """
    plugin = FakePullPlugin("suricata")
    store = FakeConfigStore()
    client = _make_client(_make_registry(plugin), store)

    # 'port' must be an int; "not_a_port" is invalid.
    resp = client.put(
        "/config/sources/suricata",
        json={"updates": {"port": "not_a_port"}},
    )

    assert resp.status_code in (400, 422), (
        f"Expected 4xx for invalid body, got {resp.status_code}"
    )
    # The store's _source_data must not contain the bad value.
    assert "not_a_port" not in str(store._source_data), (
        "Invalid value must not be persisted in the store"
    )


# ---------------------------------------------------------------------------
# W2 — env-locked field PUT rejected
# ---------------------------------------------------------------------------


def test_put_source_config_env_locked_field_rejected() -> None:
    """PUT targeting an env-locked key must be rejected (4xx); nothing persisted."""
    plugin = FakePullPlugin("suricata")
    store = FakeConfigStore()
    store._env_locked_fields = {"host"}  # simulate env lock on 'host'
    client = _make_client(_make_registry(plugin), store)

    resp = client.put(
        "/config/sources/suricata",
        json={"updates": {"host": "192.0.2.99"}},
    )

    assert resp.status_code in (400, 409, 422), (
        f"Expected 4xx for env-locked field, got {resp.status_code}"
    )
    # The value must not have been committed to the store's _source_data.
    assert store._source_data.get("suricata", {}).get("host") != "192.0.2.99", (
        "Env-locked value must not be persisted"
    )


# ---------------------------------------------------------------------------
# W3 — env-locked runtime field rejected
# ---------------------------------------------------------------------------


def test_put_runtime_config_env_locked_rejected() -> None:
    """PUT /config/runtime with an env-locked field must be rejected (4xx)."""
    store = FakeConfigStore()
    store._env_locked_runtime_fields = {"alert_threshold"}
    client = _make_client({}, store)

    resp = client.put(
        "/config/runtime",
        json={"updates": {"alert_threshold": "LOW"}},
    )

    assert resp.status_code in (400, 409, 422), (
        f"Expected 4xx for env-locked runtime field, got {resp.status_code}"
    )


# ---------------------------------------------------------------------------
# W4/W5 — unknown type_key → 404
# ---------------------------------------------------------------------------


def test_get_unknown_type_key_returns_404() -> None:
    """GET /config/sources/nonexistent returns 404."""
    client = _make_client({})

    resp = client.get("/config/sources/nonexistent")

    assert resp.status_code == 404


def test_put_unknown_type_key_returns_404() -> None:
    """PUT /config/sources/nonexistent returns 404."""
    client = _make_client({})

    resp = client.put(
        "/config/sources/nonexistent",
        json={"updates": {"foo": "bar"}},
    )

    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# S1/S2 — Suricata D5: reveal-not-require (ADR-0028)
# ---------------------------------------------------------------------------


def test_suricata_then_branch_adds_properties() -> None:
    """SuricataConfig's JSON Schema 'then' (remote mode) branch adds 'properties'.

    ADR-0028 D5: the 'then' branch must add 'properties' (reveal-on-toggle),
    not merely 'required'. This ensures rjsf shows the SSH fields when remote
    mode is selected, rather than keeping them always-visible and just required.
    """
    from firewatch_suricata.config import SuricataConfig

    schema = SuricataConfig.model_json_schema()

    assert "then" in schema, "JSON Schema must have a 'then' branch"
    then_branch = schema["then"]
    assert "properties" in then_branch, (
        "The 'then' branch (remote mode) must add 'properties' to reveal SSH fields "
        "(ADR-0028 D5: reveal-not-require). "
        f"Got 'then' = {then_branch!r}"
    )
    # The properties dict must contain at least one SSH field.
    remote_fields = {"remote_host", "remote_port", "remote_user", "remote_key", "remote_path"}
    revealed = set(then_branch["properties"].keys())
    assert revealed & remote_fields, (
        f"'then' properties must include at least one SSH field. "
        f"Got: {revealed!r}"
    )


def test_suricata_else_branch_adds_properties() -> None:
    """SuricataConfig's JSON Schema 'else' (local mode) branch adds 'properties'.

    Symmetric check: the 'else' branch should similarly add 'properties' for
    local-mode fields (reveal-not-require convention for both branches).
    """
    from firewatch_suricata.config import SuricataConfig

    schema = SuricataConfig.model_json_schema()

    assert "else" in schema, "JSON Schema must have an 'else' branch"
    else_branch = schema["else"]
    assert "properties" in else_branch, (
        "The 'else' branch (local mode) must add 'properties' to reveal local fields "
        "(ADR-0028 D5: reveal-not-require). "
        f"Got 'else' = {else_branch!r}"
    )
    assert "local_path" in else_branch["properties"], (
        "The 'else' branch must include 'local_path' in properties"
    )


# ---------------------------------------------------------------------------
# Secret: SSH key specifically absent from GET response
# ---------------------------------------------------------------------------


def test_get_source_config_ssh_key_not_in_response() -> None:
    """A stored SSH key (SecretStr) is NOT present in the GET response body.

    This is the specific case called out in the issue: a stored SSH key
    must not leak through the GET endpoint.
    """
    plugin = FakeSecretPlugin()
    store = FakeConfigStore()
    store._source_data["fakesecret"] = {
        "host": "192.0.2.1",
        "api_key": "-----BEGIN RSA PRIVATE KEY-----",
    }
    client = _make_client(_make_registry(plugin), store)

    resp = client.get("/config/sources/fakesecret")

    assert resp.status_code == 200
    body_text = resp.text
    assert "BEGIN RSA PRIVATE KEY" not in body_text, (
        "SSH private key content leaked in GET response — SecretStr must be masked/omitted."
    )


# ---------------------------------------------------------------------------
# PUT /config/sources/{type_key} with empty updates
# ---------------------------------------------------------------------------


def test_put_source_config_empty_updates_accepted() -> None:
    """PUT with empty updates dict is accepted (no-op write is valid)."""
    plugin = FakePullPlugin("suricata")
    store = FakeConfigStore()
    client = _make_client(_make_registry(plugin), store)

    resp = client.put(
        "/config/sources/suricata",
        json={"updates": {}},
    )

    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# GET /config/runtime secret fields not echoed
# ---------------------------------------------------------------------------


def test_get_runtime_config_webhook_url_not_echoed_in_plaintext() -> None:
    """GET /config/runtime must not echo webhook_url (SecretStr) in plaintext."""
    store = FakeConfigStore()
    # webhook_url is a SecretStr in RuntimeConfig; seed it via raw dict
    store._runtime_data = {"webhook_url": "https://hooks.example.com/secret-token-xyz"}
    client = _make_client({}, store)

    resp = client.get("/config/runtime")

    assert resp.status_code == 200
    body_text = resp.text
    assert "secret-token-xyz" not in body_text, (
        "webhook_url secret value must not appear in plaintext in GET /config/runtime response. "
        f"Response: {body_text!r}"
    )


# ---------------------------------------------------------------------------
# issue #494 — webhook_url_set boolean (ADR-0006 / ADR-0035 honesty)
# ---------------------------------------------------------------------------


def test_get_runtime_config_webhook_url_set_true_when_configured() -> None:
    """GET /config/runtime SHALL return webhook_url_set=true when a webhook URL is configured.

    Ubiquitous (backend) EARS: the endpoint returns a non-secret boolean indicating
    whether a webhook URL is configured, so the UI can show honest "set" state across
    sessions without echoing the secret value (ADR-0006).
    """
    store = FakeConfigStore()
    store._runtime_data = {"webhook_url": "https://hooks.example.com/secret-token"}
    client = _make_client({}, store)

    resp = client.get("/config/runtime")

    assert resp.status_code == 200
    body = resp.json()
    assert body["webhook_url_set"] is True, (
        "webhook_url_set must be True when a webhook URL is configured. "
        f"Response: {body!r}"
    )
    # Secret must never be echoed
    assert "secret-token" not in resp.text, (
        "webhook_url secret value must not appear in plaintext in GET /config/runtime response."
    )


def test_get_runtime_config_webhook_url_set_false_when_not_configured() -> None:
    """GET /config/runtime SHALL return webhook_url_set=false when no webhook URL is set.

    Verifies the honest negative — the boolean must be false when webhook_url is None,
    not just when it is absent from the response (ADR-0035 honesty).
    """
    store = FakeConfigStore()
    # No webhook_url — defaults to None in RuntimeConfig
    store._runtime_data = {}
    client = _make_client({}, store)

    resp = client.get("/config/runtime")

    assert resp.status_code == 200
    body = resp.json()
    assert body["webhook_url_set"] is False, (
        "webhook_url_set must be False when no webhook URL is configured. "
        f"Response: {body!r}"
    )


def test_get_runtime_config_webhook_url_never_returned() -> None:
    """GET /config/runtime MUST NOT return the webhook_url value, even as null.

    Constraint (ADR-0006): the secret value is never echoed.  The response must
    expose only the boolean ``webhook_url_set`` flag, not the SecretStr contents.
    This test asserts the secret is absent AND that webhook_url_set is the only
    webhook-related field in the response that carries information about it.
    """
    store = FakeConfigStore()
    store._runtime_data = {"webhook_url": "https://hooks.example.com/super-secret-abc"}
    client = _make_client({}, store)

    resp = client.get("/config/runtime")

    assert resp.status_code == 200
    body = resp.json()
    # The secret value must not appear in the response text at all
    assert "super-secret-abc" not in resp.text
    # The boolean flag must be present and true
    assert "webhook_url_set" in body
    assert body["webhook_url_set"] is True


# ---------------------------------------------------------------------------
# issue #550 — api_key_set boolean (ADR-0006 / ADR-0035 honesty; PR #558 contract gap)
# ---------------------------------------------------------------------------


def test_get_runtime_config_api_key_set_true_when_configured() -> None:
    """GET /config/runtime SHALL return api_key_set=true when an API key is configured.

    Ubiquitous (backend) EARS: the endpoint returns a non-secret boolean indicating
    whether an API key is configured, so the UI can show honest "set" state across
    sessions without echoing the secret value (ADR-0006, issue #550).

    The configured api_key activates the #559 auth middleware, so the request must
    include the matching bearer token (Authorization: Bearer <key>).
    """
    _api_key = "super-secret-api-key-value"  # noqa: S105 test fixture
    store = FakeConfigStore()
    store._runtime_data = {"api_key": _api_key}
    client = _make_client({}, store)

    resp = client.get(
        "/config/runtime",
        headers={"Authorization": f"Bearer {_api_key}"},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["api_key_set"] is True, (
        "api_key_set must be True when an API key is configured. "
        f"Response: {body!r}"
    )
    # Secret must never be echoed
    assert "super-secret-api-key-value" not in resp.text, (
        "api_key secret value must not appear in plaintext in GET /config/runtime response."
    )


def test_get_runtime_config_api_key_set_false_when_not_configured() -> None:
    """GET /config/runtime SHALL return api_key_set=false when no API key is set.

    Verifies the honest negative — the boolean must be false when api_key is None,
    not just when it is absent from the response (ADR-0035 honesty, issue #550).
    """
    store = FakeConfigStore()
    # No api_key — defaults to None in RuntimeConfig
    store._runtime_data = {}
    client = _make_client({}, store)

    resp = client.get("/config/runtime")

    assert resp.status_code == 200
    body = resp.json()
    assert body["api_key_set"] is False, (
        "api_key_set must be False when no API key is configured. "
        f"Response: {body!r}"
    )


# ---------------------------------------------------------------------------
# issue #661 — notify_on_auto_escalate round-trip (ADR-0059 D3)
# ---------------------------------------------------------------------------


def test_get_runtime_config_notify_on_auto_escalate_default_false() -> None:
    """GET /config/runtime SHALL include notify_on_auto_escalate=false by default (ADR-0059 D3).

    The field is a plain bool (not a secret) so it flows through model_dump() and
    _mask_secrets() untouched — no allowlist plumbing needed.
    """
    store = FakeConfigStore()
    store._runtime_data = {}
    client = _make_client({}, store)

    resp = client.get("/config/runtime")

    assert resp.status_code == 200
    body = resp.json()
    assert "notify_on_auto_escalate" in body, (
        "notify_on_auto_escalate must be present in GET /config/runtime response. "
        f"Keys returned: {list(body.keys())!r}"
    )
    assert body["notify_on_auto_escalate"] is False, (
        "Default notify_on_auto_escalate must be False (ADR-0059 D3 — quiet chat by default). "
        f"Response: {body!r}"
    )


def test_put_runtime_config_notify_on_auto_escalate_round_trips() -> None:
    """PUT /config/runtime with notify_on_auto_escalate=true persists and is returned by GET.

    Verifies the full round-trip: write True, read it back from GET — so the frontend
    toggle can persist and reload state.
    """
    store = FakeConfigStore()
    client = _make_client({}, store)

    put_resp = client.put(
        "/config/runtime",
        json={"updates": {"notify_on_auto_escalate": True}},
    )
    assert put_resp.status_code == 200

    get_resp = client.get("/config/runtime")
    assert get_resp.status_code == 200
    body = get_resp.json()
    assert body["notify_on_auto_escalate"] is True, (
        "notify_on_auto_escalate must be True after PUT with True. "
        f"Response: {body!r}"
    )


def test_get_runtime_config_api_key_never_returned() -> None:
    """GET /config/runtime MUST NOT return the api_key value, even as null.

    Constraint (ADR-0006, issue #550): the secret value is never echoed.  The response
    must expose only the boolean ``api_key_set`` flag, not the SecretStr contents.
    This test asserts the secret is absent AND that api_key_set is the only
    api-key-related field in the response that carries information about it.

    The configured api_key activates the #559 auth middleware, so the request must
    include the matching bearer token (Authorization: Bearer <key>).
    """
    _api_key = "raw-secret-must-not-appear-abc123"  # noqa: S105 test fixture
    store = FakeConfigStore()
    store._runtime_data = {"api_key": _api_key}
    client = _make_client({}, store)

    resp = client.get(
        "/config/runtime",
        headers={"Authorization": f"Bearer {_api_key}"},
    )

    assert resp.status_code == 200
    body = resp.json()
    # The secret value must not appear in the response text at all
    assert "raw-secret-must-not-appear-abc123" not in resp.text
    # The boolean flag must be present and true
    assert "api_key_set" in body
    assert body["api_key_set"] is True


# ---------------------------------------------------------------------------
# Security fix: "input" key stripped from 422 responses (PR #46 review)
# ---------------------------------------------------------------------------


class _RequiredFieldConfig(BaseModel):
    """Config model with a required field (no default) — used to test input stripping.

    Pydantic v2 echoes the full submitted input dict in the "input" key of a
    "missing" validation error. A required field without a default is the
    canonical trigger. This model exists only for this security test.
    """

    required_secret: str  # no default → triggers "missing" error type
    host: str = "127.0.0.1"


class _RequiredFieldPlugin:
    """Fake plugin whose config schema has a required field — no default."""

    def metadata(self) -> Any:
        from firewatch_sdk import SourceMetadata

        return SourceMetadata(
            type_key="requiredfieldplugin",
            display_name="Required Field Plugin",
            version="1.0.0",
            flavor="pull",
        )

    def config_schema(self) -> type[BaseModel]:
        return _RequiredFieldConfig

    def validate_config(self, cfg: dict[str, Any]) -> None:
        _RequiredFieldConfig.model_validate(cfg)

    def normalize(self, raw: Any, source_id: str) -> Any:
        raise NotImplementedError

    async def health_check(self, cfg: BaseModel) -> bool:
        return True


def test_put_422_does_not_echo_submitted_secret_in_input_key() -> None:
    """Fix 1 (PR #46): 422 response body must NOT reflect submitted secret values.

    Pydantic v2's ValidationError.errors() includes an "input" key per error dict,
    which for a "missing"-type error echoes the full submitted input dict. If a future
    plugin has a required field without a default, a PUT with a secret-containing body
    would be reflected back verbatim in the 422 detail. Stripping "input" prevents that.

    Two assertions:
      1. The secret value is not present anywhere in the response body text.
      2. No error dict in the returned detail contains the "input" key.
    """
    plugin = _RequiredFieldPlugin()
    store = FakeConfigStore()
    client = _make_client(_make_registry(plugin), store)

    # Submit a body that omits the required field but includes a secret-looking value.
    # The missing "required_secret" field will trigger Pydantic's "missing" error
    # which (without the fix) would echo {"host": "...", "my_api_token": "..."} in "input".
    secret_value = "s3cr3t-api-t0k3n-SHOULD-NOT-APPEAR"
    resp = client.put(
        "/config/sources/requiredfieldplugin",
        json={"updates": {"host": "192.0.2.1", "my_api_token": secret_value}},
    )

    assert resp.status_code == 422, (
        f"Expected 422 for missing required field, got {resp.status_code}. "
        f"Body: {resp.text!r}"
    )

    # The secret must not appear anywhere in the response text.
    assert secret_value not in resp.text, (
        f"Secret value was reflected back in the 422 response body: {resp.text!r}"
    )

    # The "input" key must be absent from every error dict.
    detail = resp.json().get("detail", [])
    assert isinstance(detail, list), f"Expected list detail, got: {detail!r}"
    for err in detail:
        assert "input" not in err, (
            f"'input' key found in 422 error dict (latent secret-echo risk): {err!r}"
        )


def test_put_422_input_stripping_on_runtime_config() -> None:
    """Fix 1 (PR #46): "input" stripped from PUT /config/runtime 422 response too.

    Asserts that the stripping transform is applied to the runtime PUT handler,
    not just the per-source PUT handler. Uses a direct ValidationError to confirm
    the transform is symmetric across both routes.
    """
    from pydantic import ValidationError as PydanticValidationError

    # Directly verify the stripping transform on a real ValidationError payload.
    # This is the most robust check: it doesn't depend on RuntimeConfig having a
    # required-no-default field, and it proves the transform itself is correct.
    try:
        _RequiredFieldConfig.model_validate({"host": "192.0.2.1"})  # missing required_secret
    except PydanticValidationError as exc:
        raw_errors = exc.errors()
        # At least one error must have an "input" key (the thing we strip).
        assert any("input" in e for e in raw_errors), (
            "Test setup error: expected Pydantic to include 'input' in errors() — "
            "if Pydantic changed this behaviour, the test logic needs updating."
        )
        # Apply the same stripping transform used in app.py.
        stripped = [{k: v for k, v in e.items() if k != "input"} for e in raw_errors]
        for err in stripped:
            assert "input" not in err, (
                f"Stripping transform did not remove 'input' key: {err!r}"
            )
    else:
        raise AssertionError(
            "Expected _RequiredFieldConfig.model_validate to raise ValidationError "
            "when required_secret is missing — test setup is broken."
        )


# ---------------------------------------------------------------------------
# Security fix: GET /config/sources/{type_key} ValueError → 400 (PR #46 review)
# ---------------------------------------------------------------------------


def test_get_source_config_value_error_returns_400() -> None:
    """Fix 2 (PR #46): GET /config/sources/{type_key} maps ValueError → 400.

    A ValueError from ConfigStore.get_source (e.g. invalid format for type_key)
    must produce a 400 Bad Request, matching the PUT handler's error mapping rather
    than falling through to a 500 Internal Server Error.
    """

    class _ValueErrorStore(FakeConfigStore):
        """ConfigStore that raises ValueError on get_source."""

        def get_source(self, source_type: str, schema: type[BaseModel]) -> BaseModel:
            raise ValueError(f"Invalid source type format: {source_type!r}")

    plugin = FakePullPlugin("suricata")
    store = _ValueErrorStore()
    client = _make_client(_make_registry(plugin), store)

    resp = client.get("/config/sources/suricata")

    assert resp.status_code == 400, (
        f"Expected 400 for ValueError from ConfigStore.get_source, got {resp.status_code}. "
        f"Body: {resp.text!r}"
    )


# ---------------------------------------------------------------------------
# Issue #527 — invalid ollama_base_url returns 500 instead of 422
#
# Root cause: Pydantic's ValidationError.errors() for value_error-type
# validators (e.g. the ADR-0022 local-first URL check) includes a live
# ValueError object in the "ctx" key.  That object is NOT JSON-serializable;
# FastAPI raises a TypeError during response serialization, which becomes a
# 500.  Fix: strip "ctx" alongside "input" in _sanitize_validation_errors.
# ---------------------------------------------------------------------------


def test_put_runtime_invalid_ollama_base_url_returns_422_not_500() -> None:
    """PUT /config/runtime with a non-local ollama_base_url must return 422, not 500.

    Issue #527 root cause: the ADR-0022 field validator raises a value_error
    which Pydantic annotates with a live ValueError in the 'ctx' key.  That
    object is not JSON-serializable; without the fix FastAPI converts the
    TypeError into a 500.  The fix strips 'ctx' alongside 'input'.

    EARS unwanted: PUT /config/runtime with an ollama_base_url that violates the
    local-first invariant (ADR-0022) shall be rejected with 422, not 500.
    """
    store = FakeConfigStore()
    client = _make_client({}, store)

    # A public/cloud URL — rejected by the ADR-0022 local-first validator.
    resp = client.put(
        "/config/runtime",
        json={"updates": {"ollama_base_url": "https://224.0.0.1/v1"}},
    )

    assert resp.status_code == 422, (
        f"Expected 422 for non-local ollama_base_url, got {resp.status_code}. "
        f"Body: {resp.text!r}"
    )
    detail = resp.json().get("detail", [])
    assert isinstance(detail, list) and len(detail) > 0, (
        f"Expected a list of error dicts in 'detail', got: {detail!r}"
    )
    # The human-readable message must name the offending field.
    detail_text = str(detail)
    assert "ollama_base_url" in detail_text or "loopback" in detail_text or "ADR-0022" in detail_text, (
        f"422 detail should reference ollama_base_url/ADR-0022: {detail_text!r}"
    )


def test_put_runtime_invalid_ollama_base_url_no_ctx_or_input_in_response() -> None:
    """PUT /config/runtime 422 for ollama_base_url must not echo 'ctx' or 'input'.

    Security: 'input' would echo the submitted URL (potential secret-echo).
    Correctness: 'ctx' contains a live ValueError that is not JSON-serializable
    (issue #527 root cause).  Both must be absent from the 422 response body.
    """
    store = FakeConfigStore()
    client = _make_client({}, store)

    resp = client.put(
        "/config/runtime",
        json={"updates": {"ollama_base_url": "https://224.0.0.1/v1"}},
    )

    assert resp.status_code == 422, (
        f"Expected 422, got {resp.status_code}. Body: {resp.text!r}"
    )
    detail = resp.json().get("detail", [])
    assert isinstance(detail, list), f"Expected list detail, got: {detail!r}"
    for err in detail:
        assert "ctx" not in err, (
            f"'ctx' key found in 422 error dict — contains non-serializable ValueError "
            f"(issue #527 root cause): {err!r}"
        )
        assert "input" not in err, (
            f"'input' key found in 422 error dict (latent secret-echo risk): {err!r}"
        )


def test_put_runtime_valid_ollama_base_url_returns_200() -> None:
    """PUT /config/runtime with a valid local ollama_base_url returns 200.

    Regression guard: the fix must not break the happy path.
    """
    store = FakeConfigStore()
    client = _make_client({}, store)

    resp = client.put(
        "/config/runtime",
        json={"updates": {"ollama_base_url": "http://127.0.0.1:11434"}},
    )

    assert resp.status_code == 200, (
        f"Expected 200 for valid local ollama_base_url, got {resp.status_code}. "
        f"Body: {resp.text!r}"
    )


def test_put_422_ctx_stripped_alongside_input() -> None:
    """The _sanitize_validation_errors helper strips both 'ctx' and 'input' (issue #527).

    Direct unit test of _sanitize_validation_errors: verifies the transform on a
    real ValidationError that has both 'input' and 'ctx' keys (value_error type).
    """
    from pydantic import BaseModel as PBM, ValidationError as PydanticValidationError, field_validator

    from firewatch_api.routes.config import _sanitize_validation_errors

    class _UrlModel(PBM):
        url: str = "http://localhost"

        @field_validator("url")
        @classmethod
        def _reject_all(cls, v: str) -> str:
            raise ValueError(f"Rejected: {v!r}")

    try:
        _UrlModel.model_validate({"url": "http://example.com"})
    except PydanticValidationError as exc:
        raw = exc.errors()
        # Confirm both 'input' and 'ctx' are present in the raw errors (test setup).
        assert any("input" in e for e in raw), (
            "Test setup error: expected 'input' in raw Pydantic errors()"
        )
        assert any("ctx" in e for e in raw), (
            "Test setup error: expected 'ctx' in raw Pydantic errors() for value_error"
        )
        sanitized = _sanitize_validation_errors(exc)
        for err in sanitized:
            assert "input" not in err, f"'input' not stripped: {err!r}"
            assert "ctx" not in err, f"'ctx' not stripped (issue #527 root cause): {err!r}"
            # msg must still be present
            assert "msg" in err, f"'msg' was incorrectly stripped: {err!r}"
    else:
        raise AssertionError("Expected _UrlModel.model_validate to raise ValidationError")
