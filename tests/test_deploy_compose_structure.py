"""Lightweight structural tests for deploy/docker-compose.yml (MI-3, ADR-0042).

These tests parse the compose file with PyYAML and assert the invariants
mandated by the issue spec and ADR-0026 / ADR-0042:

- All three profiles ('default', 'lean', 'rules-only') are declared.
- The `firewatch` service publishes a host port only for the nginx surface
  (port 80 of its shared netns), NOT the raw API port 8000.
- The `nginx` service uses network_mode: "service:firewatch" (shared netns).
- The `ollama` service belongs only to the 'default' profile.
- The `llama` service belongs only to the 'lean' profile.
- Neither inference service (ollama, llama) publishes host ports (no cloud
  egress path, ADR-0022).
- The `rules-only` profile (issue #4) starts only `firewatch` + `nginx` — no
  inference service (`ollama`, `llama`) is a member of it.
- The entrypoint in deploy/Dockerfile binds --host 127.0.0.1.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

DEPLOY_DIR = Path(__file__).parent.parent / "deploy"
COMPOSE_FILE = DEPLOY_DIR / "docker-compose.yml"
APP_DOCKERFILE = DEPLOY_DIR / "Dockerfile"
README_FILE = DEPLOY_DIR / "README.md"


@pytest.fixture(scope="module")
def compose() -> dict:  # type: ignore[type-arg]
    """Parsed docker-compose.yml as a Python dict."""
    return yaml.safe_load(COMPOSE_FILE.read_text())


# ---------------------------------------------------------------------------
# Profile declarations
# ---------------------------------------------------------------------------


def test_default_profile_declared_on_firewatch(compose: dict) -> None:
    """firewatch service must be in the 'default' profile."""
    profiles = compose["services"]["firewatch"]["profiles"]
    assert "default" in profiles, f"Expected 'default' in firewatch profiles, got {profiles}"


def test_lean_profile_declared_on_firewatch(compose: dict) -> None:
    """firewatch service must be in the 'lean' profile."""
    profiles = compose["services"]["firewatch"]["profiles"]
    assert "lean" in profiles, f"Expected 'lean' in firewatch profiles, got {profiles}"


def test_ollama_only_in_default_profile(compose: dict) -> None:
    """ollama service must appear only in the 'default' profile."""
    profiles = compose["services"]["ollama"]["profiles"]
    assert profiles == ["default"], f"ollama profiles should be ['default'], got {profiles}"


def test_llama_only_in_lean_profile(compose: dict) -> None:
    """llama service must appear only in the 'lean' profile."""
    profiles = compose["services"]["llama"]["profiles"]
    assert profiles == ["lean"], f"llama profiles should be ['lean'], got {profiles}"


# ---------------------------------------------------------------------------
# rules-only profile (issue #4): firewatch + nginx only, zero AI footprint
# ---------------------------------------------------------------------------


def test_rules_only_profile_declared_on_firewatch(compose: dict) -> None:
    """firewatch service must be in the 'rules-only' profile."""
    profiles = compose["services"]["firewatch"]["profiles"]
    assert "rules-only" in profiles, (
        f"Expected 'rules-only' in firewatch profiles, got {profiles}"
    )


def test_rules_only_profile_declared_on_nginx(compose: dict) -> None:
    """nginx service must be in the 'rules-only' profile."""
    profiles = compose["services"]["nginx"]["profiles"]
    assert "rules-only" in profiles, (
        f"Expected 'rules-only' in nginx profiles, got {profiles}"
    )


def test_ollama_not_in_rules_only_profile(compose: dict) -> None:
    """ollama must NOT be a member of the 'rules-only' profile (zero AI footprint)."""
    profiles = compose["services"]["ollama"]["profiles"]
    assert "rules-only" not in profiles, (
        f"ollama must not appear in the rules-only profile, got {profiles}"
    )


def test_llama_not_in_rules_only_profile(compose: dict) -> None:
    """llama must NOT be a member of the 'rules-only' profile (zero AI footprint)."""
    profiles = compose["services"]["llama"]["profiles"]
    assert "rules-only" not in profiles, (
        f"llama must not appear in the rules-only profile, got {profiles}"
    )


def test_only_firewatch_and_nginx_in_rules_only_profile(compose: dict) -> None:
    """No service other than firewatch/nginx may belong to 'rules-only'.

    This is the structural guarantee behind "zero AI footprint": bringing up
    `--profile rules-only` must never start an inference container, now or if
    a future service is added to the compose file.
    """
    members = {
        name
        for name, svc in compose["services"].items()
        if "rules-only" in svc.get("profiles", [])
    }
    assert members == {"firewatch", "nginx"}, (
        f"rules-only profile must contain exactly {{'firewatch', 'nginx'}}, got {members}"
    )


# ---------------------------------------------------------------------------
# nginx shared-netns topology (ADR-0026)
# ---------------------------------------------------------------------------


def test_nginx_uses_shared_netns(compose: dict) -> None:
    """nginx must use network_mode: service:firewatch (shared netns topology)."""
    network_mode = compose["services"]["nginx"].get("network_mode", "")
    assert network_mode == "service:firewatch", (
        f"nginx must share firewatch's netns via "
        f"network_mode: 'service:firewatch', got {network_mode!r}"
    )


def test_nginx_does_not_declare_ports(compose: dict) -> None:
    """nginx must NOT declare its own ports (shared netns; ports on firewatch service)."""
    nginx_ports = compose["services"]["nginx"].get("ports", [])
    assert nginx_ports == [], (
        f"nginx should declare no ports (shared netns with firewatch); got {nginx_ports}"
    )


def test_firewatch_publishes_port_80_not_8000(compose: dict) -> None:
    """firewatch publishes host:80 (nginx surface) — NOT the raw API port 8000.

    The port mapping must map the host port to container port 80, never to 8000.
    Container port 8000 (API) must not appear in any host-published mapping.
    """
    ports = compose["services"]["firewatch"].get("ports", [])
    assert ports, "firewatch must publish at least one host port (for the nginx surface)"

    for mapping in ports:
        mapping_str = str(mapping)
        # Extract the container-side port (right side of the colon in "HOST:CONTAINER").
        parts = mapping_str.split(":")
        container_port = parts[-1].strip()
        assert container_port == "80", (
            f"firewatch should publish host→80 (nginx), not {mapping_str!r}. "
            "Port 8000 (loopback API) must never be host-published."
        )


# ---------------------------------------------------------------------------
# No host-published API port on inference services (ADR-0022)
# ---------------------------------------------------------------------------


def test_ollama_has_no_host_published_ports(compose: dict) -> None:
    """ollama must NOT publish host ports (no egress path; reachable only via fwnet)."""
    ports = compose["services"]["ollama"].get("ports", [])
    assert ports == [], f"ollama must not publish host ports; got {ports}"


def test_llama_has_no_host_published_ports(compose: dict) -> None:
    """llama must NOT publish host ports (no egress path; reachable only via fwnet)."""
    ports = compose["services"]["llama"].get("ports", [])
    assert ports == [], f"llama must not publish host ports; got {ports}"


# ---------------------------------------------------------------------------
# Named volumes declared
# ---------------------------------------------------------------------------


def test_fw_data_volume_declared(compose: dict) -> None:
    """fw_data named volume must be declared for the SQLite event store."""
    volumes = compose.get("volumes", {})
    assert "fw_data" in volumes, f"fw_data volume not found in top-level volumes: {volumes.keys()}"


def test_ollama_models_volume_declared(compose: dict) -> None:
    """ollama_models named volume must be declared for the Ollama model store."""
    volumes = compose.get("volumes", {})
    assert "ollama_models" in volumes, (
        f"ollama_models volume not found: {volumes.keys()}"
    )


# ---------------------------------------------------------------------------
# Dockerfile entrypoint binds loopback (ADR-0026 Decision 1)
# ---------------------------------------------------------------------------


def test_app_dockerfile_entrypoint_binds_loopback() -> None:
    """The app Dockerfile ENTRYPOINT must include --host 127.0.0.1."""
    content = APP_DOCKERFILE.read_text()
    assert "--host" in content and "127.0.0.1" in content, (
        "deploy/Dockerfile ENTRYPOINT must bind --host 127.0.0.1 (ADR-0026 Decision 1). "
        f"Snippet: {content[-500:]}"
    )
    # Confirm it does NOT contain 0.0.0.0 as the bind address for the API.
    # (0.0.0.0 would bypass the bind guard without an API key.)
    entrypoint_lines = [
        line for line in content.splitlines()
        if "ENTRYPOINT" in line or "CMD" in line
    ]
    for line in entrypoint_lines:
        assert "0.0.0.0" not in line, (
            f"Dockerfile ENTRYPOINT/CMD must not bind 0.0.0.0: {line!r}"
        )


# ---------------------------------------------------------------------------
# GGUF lean profile: model bind-mounted, never baked in (ADR-0042)
# ---------------------------------------------------------------------------


def test_llama_gguf_is_bind_mount_not_volume(compose: dict) -> None:
    """lean llama service must use a bind-mount for the GGUF, not a named volume."""
    llama_volumes = compose["services"]["llama"].get("volumes", [])
    assert llama_volumes, "llama service must declare a volume for the GGUF"

    # At least one mount must be a bind type (operator-supplied file path).
    bind_mounts = [
        v for v in llama_volumes
        if isinstance(v, dict) and v.get("type") == "bind"
    ]
    assert bind_mounts, (
        "llama GGUF must be a bind-mount (operator-supplied path), not a named volume. "
        f"Got: {llama_volumes}"
    )


# ---------------------------------------------------------------------------
# fwnet bridge network declared
# ---------------------------------------------------------------------------


def test_fwnet_network_declared(compose: dict) -> None:
    """fwnet bridge network must be declared."""
    networks = compose.get("networks", {})
    assert "fwnet" in networks, f"fwnet network not found in top-level networks: {networks.keys()}"


# ---------------------------------------------------------------------------
# Security: no live .env committed / present (BLOCKING-2)
# ---------------------------------------------------------------------------


def test_deploy_env_file_absent() -> None:
    """deploy/.env must NOT be present — only deploy/.env.example should exist.

    A live .env may contain operator secrets; it is gitignored and must never
    be committed.  .env.example is the checked-in template.
    """
    env_file = DEPLOY_DIR / ".env"
    assert not env_file.exists(), (
        "deploy/.env must not be present in the repository tree. "
        "Only deploy/.env.example should exist.  Remove the live .env file."
    )


# ---------------------------------------------------------------------------
# Security: Ollama image must be pinned — not ':latest' (BLOCKING-3)
# ---------------------------------------------------------------------------


def test_ollama_image_is_not_latest(compose: dict) -> None:
    """ollama image must be pinned to a specific version tag, not ':latest'.

    Pinning prevents silent drift when Docker Hub updates the 'latest' tag,
    which could introduce breaking API changes or security regressions.
    """
    image = compose["services"]["ollama"].get("image", "")
    assert image, "ollama service must declare an image"
    assert not image.endswith(":latest"), (
        f"ollama image must be pinned to a specific version tag, not ':latest'. "
        f"Got: {image!r}.  Update docker-compose.yml to a specific tag "
        f"(e.g. ollama/ollama:0.30.8)."
    )


# ---------------------------------------------------------------------------
# deploy/README.md documents the rules-only profile (issue #4)
# ---------------------------------------------------------------------------


def test_readme_has_rules_only_profile_table_row() -> None:
    """The profile comparison table must gain a 'rules-only' row."""
    content = README_FILE.read_text()
    assert "`rules-only`" in content, (
        "deploy/README.md must document the 'rules-only' profile in the "
        "profile table."
    )


def test_readme_has_rules_only_start_stop_section() -> None:
    """The README must document start/stop commands for the rules-only profile."""
    content = README_FILE.read_text()
    assert "--profile rules-only up -d" in content, (
        "deploy/README.md must show the rules-only start command "
        "(docker compose --profile rules-only up -d)."
    )
    assert "--profile rules-only down" in content, (
        "deploy/README.md must show the rules-only stop command "
        "(docker compose --profile rules-only down)."
    )


def test_readme_documents_measured_idle_footprint_for_rules_only() -> None:
    """The idle footprint must be recorded as a measured number, not estimated.

    Guards against a regression back to a bare 'TODO' placeholder with no
    measurement methodology attached.
    """
    content = README_FILE.read_text()
    assert "rules-only" in content.lower()
    # A measured-footprint section must reference how the number was obtained.
    assert "docker stats" in content, (
        "deploy/README.md must describe how the rules-only idle footprint was "
        "measured (docker stats), not just assert a number."
    )


def test_readme_documents_lan_upgrade_path() -> None:
    """The README must document the rules-only -> LAN-endpoint upgrade path.

    Per ADR-0022, an operator on a rules-only box can later point
    FIREWATCH_OLLAMA_BASE_URL at another machine on the LAN and flip
    FIREWATCH_AI_ENABLED to enable narration, with no image rebuild.
    """
    content = README_FILE.read_text()
    assert "FIREWATCH_OLLAMA_BASE_URL" in content
    assert "FIREWATCH_AI_ENABLED" in content
    assert "rebuild" in content.lower(), (
        "deploy/README.md must state that the upgrade path requires no image "
        "rebuild."
    )


# ---------------------------------------------------------------------------
# rules-only profile keeps AI disabled by construction (issue #4, honest
# ai_status='disabled' surface — never 'error'/'unavailable')
# ---------------------------------------------------------------------------


def test_firewatch_env_ai_enabled_is_overridable_per_invocation(compose: dict) -> None:
    """FIREWATCH_AI_ENABLED must remain a plain env-var override (no hardcoding).

    The rules-only profile relies on operators/docs setting
    FIREWATCH_AI_ENABLED=false for the invocation (documented in
    deploy/README.md) — the compose file itself must keep this variable
    overridable rather than hardcoding `true` for all profiles, which would
    make the documented rules-only invocation impossible.
    """
    env = compose["services"]["firewatch"]["environment"]
    assert env["FIREWATCH_AI_ENABLED"] == "${FIREWATCH_AI_ENABLED:-true}", (
        f"FIREWATCH_AI_ENABLED must stay an overridable env-var default, got {env!r}"
    )
