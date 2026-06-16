"""Tests for GET /sources/types — MA.3 (issue #32) EARS criteria.

EARS → test mapping:
  E1 (event-driven): When GET /sources/types is called, the API shall return one entry
     per discovered plugin, each including its JSON Schema.
     → test_returns_one_entry_per_plugin, test_each_entry_has_required_fields,
       test_config_schema_is_valid_json_schema

  E2 (ubiquitous): The endpoint shall import only SDK/core/loader — never a concrete
     plugin and never legacy/.
     → test_no_concrete_plugin_import

  E3 (state-driven): While a plugin fails to load, it shall be omitted from the
     response and shall not break the response for others.
     → test_broken_plugin_omitted_response_still_200

  E4 (unwanted): If no plugins are installed, the endpoint shall return an empty list
     (200), not an error.
     → test_empty_registry_returns_200_with_empty_list

  ADR-0026: The application shall bind loopback (127.0.0.1) by default.
     → test_default_bind_is_loopback
"""
import importlib
import types

import jsonschema
from fastapi.testclient import TestClient

from firewatch_api.app import create_app
from _api_fakes import FakePullPlugin, FakePullPluginWithProduces, FakePushPlugin


# --------------------------------------------------------------------------- #
# Helpers                                                                       #
# --------------------------------------------------------------------------- #


def _make_registry(*plugins):
    """Build a fake registry dict from fake plugin instances."""
    return {p.metadata().type_key: p for p in plugins}


def _make_client_with_registry(registry: dict) -> TestClient:
    """Create a TestClient with a fully-patched loader registry."""
    app = create_app(registry=registry)
    return TestClient(app)


# --------------------------------------------------------------------------- #
# E1: event-driven — one entry per plugin, correct fields + JSON Schema        #
# --------------------------------------------------------------------------- #


def test_returns_one_entry_per_plugin():
    """GET /sources/types returns exactly one entry per installed plugin."""
    pull = FakePullPlugin("suricata")
    push = FakePushPlugin("syslog")
    client = _make_client_with_registry(_make_registry(pull, push))

    resp = client.get("/sources/types")

    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 2
    type_keys = {e["type_key"] for e in data}
    assert type_keys == {"suricata", "syslog"}


def test_each_entry_has_required_fields():
    """Each entry includes type_key, display_name, flavor, version, and config_schema."""
    pull = FakePullPlugin("suricata")
    client = _make_client_with_registry(_make_registry(pull))

    resp = client.get("/sources/types")

    assert resp.status_code == 200
    entry = resp.json()[0]
    assert entry["type_key"] == "suricata"
    assert entry["display_name"] == "Fake Pull Source"
    assert entry["flavor"] == "pull"
    assert entry["version"] == "1.2.3"
    assert isinstance(entry["config_schema"], dict), "config_schema must be a JSON object"


def test_push_plugin_flavor_is_push():
    """Push plugins report flavor='push'."""
    push = FakePushPlugin("syslog")
    client = _make_client_with_registry(_make_registry(push))

    resp = client.get("/sources/types")
    entry = resp.json()[0]

    assert entry["flavor"] == "push"


def test_config_schema_is_valid_json_schema():
    """config_schema for each plugin is a valid JSON Schema object (Draft 7 / 2020-12)."""
    pull = FakePullPlugin("suricata")
    push = FakePushPlugin("syslog")
    client = _make_client_with_registry(_make_registry(pull, push))

    resp = client.get("/sources/types")
    entries = {e["type_key"]: e for e in resp.json()}

    # jsonschema.Draft7Validator checks the schema itself is structurally valid.
    for key, entry in entries.items():
        schema = entry["config_schema"]
        assert isinstance(schema, dict), f"config_schema for {key} is not a dict"
        # Validate that the schema is itself a valid meta-schema.
        jsonschema.Draft7Validator.check_schema(schema)


def test_config_schema_contains_properties():
    """config_schema carries 'properties' with the model's fields."""
    pull = FakePullPlugin("suricata")
    client = _make_client_with_registry(_make_registry(pull))

    resp = client.get("/sources/types")
    schema = resp.json()[0]["config_schema"]

    # _FakePullConfig has 'host' and 'port' fields.
    assert "properties" in schema
    assert "host" in schema["properties"]
    assert "port" in schema["properties"]


# --------------------------------------------------------------------------- #
# E2: ubiquitous — no concrete plugin import in the API routes module          #
# --------------------------------------------------------------------------- #


def test_no_concrete_plugin_import():
    """The routes module imports only SDK/core/loader — not suricata, syslog, or legacy."""
    routes_module = importlib.import_module("firewatch_api.routes.sources")
    for name, obj in vars(routes_module).items():
        if isinstance(obj, types.ModuleType):
            assert "firewatch_suricata" not in obj.__name__, (
                f"routes.sources imports concrete plugin firewatch_suricata via {name}"
            )
            assert "firewatch_syslog" not in obj.__name__, (
                f"routes.sources imports concrete plugin firewatch_syslog via {name}"
            )
            assert "legacy" not in obj.__name__, (
                f"routes.sources imports legacy/ module via {name}"
            )


def test_app_module_does_not_import_concrete_plugins():
    """The app module itself must not import concrete plugin packages."""
    app_module = importlib.import_module("firewatch_api.app")
    forbidden = ("firewatch_suricata", "firewatch_syslog", "legacy")
    for name, obj in vars(app_module).items():
        if isinstance(obj, types.ModuleType):
            for forbidden_prefix in forbidden:
                assert not obj.__name__.startswith(forbidden_prefix), (
                    f"firewatch_api.app imports forbidden module {obj.__name__}"
                )


# --------------------------------------------------------------------------- #
# E3: state-driven — broken plugin omitted, others still returned             #
# --------------------------------------------------------------------------- #


def test_broken_plugin_omitted_response_still_200(monkeypatch):
    """A plugin that raises during load is omitted; the rest are still returned.

    The registry passed to create_app already reflects the post-load state
    (the loader itself handles resilience). This test exercises the endpoint's
    own resilience: a plugin whose config_schema() or metadata() raises at
    *serve time* must not 500 the response.
    """
    class BrokenSchemaPlugin:
        def metadata(self):
            from firewatch_sdk import SourceMetadata
            return SourceMetadata(
                type_key="broken",
                display_name="Broken Plugin",
                version="0.0.1",
                flavor="pull",
            )

        def config_schema(self):
            raise RuntimeError("schema exploded at serve time")

    pull = FakePullPlugin("suricata")
    registry = {"broken": BrokenSchemaPlugin(), "suricata": pull}

    app = create_app(registry=registry)
    client = TestClient(app)

    resp = client.get("/sources/types")

    assert resp.status_code == 200
    data = resp.json()
    type_keys = {e["type_key"] for e in data}
    assert "broken" not in type_keys, "Broken plugin must be omitted"
    assert "suricata" in type_keys, "Healthy plugin must still be present"


def test_loader_broken_plugin_omitted_via_empty_registry():
    """If the loader already filtered the broken plugin, the endpoint sees only healthy ones.

    The core loader's resilience is tested in test_loader.py; here we only verify
    that the endpoint correctly reflects whatever registry it was given.
    """
    pull = FakePullPlugin("suricata")
    # Simulates a registry where 'broken' was already skipped by the loader.
    client = _make_client_with_registry(_make_registry(pull))

    resp = client.get("/sources/types")

    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["type_key"] == "suricata"


# --------------------------------------------------------------------------- #
# E4: unwanted — empty installed set returns 200 + empty list                  #
# --------------------------------------------------------------------------- #


def test_empty_registry_returns_200_with_empty_list():
    """When no plugins are installed, GET /sources/types returns 200 + []."""
    client = _make_client_with_registry({})

    resp = client.get("/sources/types")

    assert resp.status_code == 200
    assert resp.json() == []


# --------------------------------------------------------------------------- #
# ADR-0026: loopback bind default                                               #
# --------------------------------------------------------------------------- #


def test_default_bind_is_loopback():
    """The server's default bind address is 127.0.0.1 (ADR-0026 Decision 1).

    We verify the exported DEFAULT_HOST constant — the uvicorn startup code reads
    this value. The actual socket binding is exercised by the serve command (MA.6);
    here we assert the seam is correct.
    """
    from firewatch_api.server import DEFAULT_HOST

    assert DEFAULT_HOST == "127.0.0.1", (
        f"Default bind must be loopback (127.0.0.1), got {DEFAULT_HOST!r}. "
        "Per ADR-0026 Decision 1: loopback bind, no app auth for MA."
    )


def test_default_port():
    """The default port is exposed as a constant for MA.6 to consume."""
    from firewatch_api.server import DEFAULT_PORT

    assert isinstance(DEFAULT_PORT, int)
    assert DEFAULT_PORT == 8000


# --------------------------------------------------------------------------- #
# ADR-0060: produces key in each /sources/types entry                          #
# --------------------------------------------------------------------------- #


def test_entry_has_produces_key_when_empty():
    """GET /sources/types includes a 'produces' key (sorted list) even when empty.

    A plugin with the default empty produces (= produces-all) SHALL expose
    'produces': [] in the discovery entry — the key is always present (ADR-0060 D3).
    """
    pull = FakePullPlugin("suricata")
    client = _make_client_with_registry(_make_registry(pull))

    resp = client.get("/sources/types")

    assert resp.status_code == 200
    entry = resp.json()[0]
    assert "produces" in entry, "produces key must be present in every entry"
    assert entry["produces"] == [], "empty produces frozenset → empty sorted list"


def test_entry_produces_is_sorted_list_of_strings():
    """When a plugin declares produces, the entry exposes it as a sorted list of strings.

    ADR-0060 D3: 'produces': sorted(meta.produces) per plugin entry.
    """
    declared = frozenset({"protocol", "destination_ip", "source_ip"})
    plugin = FakePullPluginWithProduces("waf", produces=declared)
    client = _make_client_with_registry(_make_registry(plugin))

    resp = client.get("/sources/types")

    assert resp.status_code == 200
    entry = resp.json()[0]
    assert "produces" in entry
    result = entry["produces"]
    assert isinstance(result, list)
    # Must be sorted
    assert result == sorted(result)
    # Must contain exactly the declared fields
    assert set(result) == declared


def test_each_entry_always_has_produces_key():
    """Every entry — regardless of whether produces is declared — has the 'produces' key."""
    pull = FakePullPlugin("suricata")
    push = FakePushPlugin("syslog")
    client = _make_client_with_registry(_make_registry(pull, push))

    resp = client.get("/sources/types")

    assert resp.status_code == 200
    for entry in resp.json():
        assert "produces" in entry, f"Entry {entry['type_key']} missing 'produces' key"


def test_produces_key_is_additive_alongside_existing_fields():
    """The 'produces' key coexists with type_key, display_name, flavor, version, etc."""
    plugin = FakePullPluginWithProduces(
        "testsrc",
        produces=frozenset({"http_url", "http_host"}),
    )
    client = _make_client_with_registry(_make_registry(plugin))

    resp = client.get("/sources/types")

    entry = resp.json()[0]
    # All existing required fields are still present
    assert entry["type_key"] == "testsrc"
    assert entry["display_name"] == "Fake Producing Pull Source"
    assert entry["flavor"] == "pull"
    assert entry["version"] == "1.0.0"
    assert "config_schema" in entry
    assert "actions" in entry
    # And the new additive key
    assert entry["produces"] == sorted(["http_url", "http_host"])
