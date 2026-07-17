"""Config domain models and the ConfigStore port.

The ``ConfigStore`` port is the *only* legal way to read or write configuration in
FireWatch.  No process global, no per-plugin ``build_config()`` singleton.

``RuntimeConfig`` carries the typed runtime settings every component needs (thresholds,
webhook URL, AI endpoint).  Per-source config is validated generically against each
plugin's ``config_schema()`` Pydantic model — core never hardcodes knowledge of a
specific source.

Secrets use ``SecretStr``; they must never appear in logs or ``repr`` output.

ADR-0006: env vars > ``firewatch_config.json`` > defaults (enforced by the adapter;
the port itself is shape-only).
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Any, Protocol, runtime_checkable

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from firewatch_sdk.models import ThreatLevelLiteral

# Geo provider values (ADR-0039).
GeoProviderLiteral = Literal["offline", "online"]


# ---------------------------------------------------------------------------
# Runtime config model (typed; owned by core)
# ---------------------------------------------------------------------------


def _is_local_ip_literal(host: str) -> bool | None:
    """Classify *host* as a local/non-local IP literal, PURELY syntactically.

    Returns ``True`` when *host* parses as an IP literal that is loopback,
    RFC 1918, or link-local; ``False`` when it parses as an IP literal that is
    NOT local (a public/cloud address is rejected at config-write time,
    ADR-0022/ADR-0066); ``None`` when *host* is not an IP literal at all (a
    hostname — the caller must NOT reject these; see module docstring below).

    ADR-0066 (inertness principle): this function performs NO DNS resolution
    and NO network I/O — it is pure and fast, exactly the same posture this
    module already takes for the webhook validator's canonical-IP fast path.
    Locality for HOSTNAMES is enforced later, at the dial boundary
    (``OpenAIEngine.__init__`` / first use), which only ever runs when
    ``ai_enabled=true`` — an off subsystem must never resolve, dial, or crash.

    NB-4: 0.0.0.0 (unspecified address, RFC 5735 sec 3) is explicitly rejected.
    """
    host = host.strip("[]")
    if host.lower() == "localhost":
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return None
    if addr.is_unspecified:
        return False
    return bool(addr.is_loopback or addr.is_private or addr.is_link_local)


class RuntimeConfig(BaseModel):
    """Typed runtime settings for FireWatch (the "global" config, now a value object).

    ``webhook_url`` is a ``SecretStr`` — it may carry tokens/credentials in the URL.
    It is never emitted in logs, repr, or JSON serialization unless explicitly extracted
    with ``.get_secret_value()``.

    Defaults mirror the v1 ``FireWatchConfig`` constants (ported, not imported from legacy/).
    """

    model_config = ConfigDict(
        # Reject unknown keys so callers cannot accidentally fat-finger a field.
        extra="forbid",
    )

    alert_threshold: ThreatLevelLiteral = Field(
        default="CRITICAL",
        description="Minimum threat level that triggers an alert (LOW/MEDIUM/HIGH/CRITICAL).",
    )
    triage_threshold: ThreatLevelLiteral = Field(
        default="HIGH",
        description=(
            "Minimum threat level for an actor to enter the triage banner by severity "
            "(ADR-0059 D1 — Triage threshold). Default HIGH preserves the existing "
            "hard-coded {CRITICAL, HIGH} banner band exactly. The action-aware escalation "
            "tier always surfaces in the banner regardless of this threshold."
        ),
    )
    alert_on_sync: bool = Field(
        default=True,
        description="Send a digest alert after every sync run.",
    )
    webhook_url: SecretStr | None = Field(
        default=None,
        description="Outbound webhook URL. May contain auth tokens — stored as SecretStr.",
    )
    notify_on_auto_escalate: bool = Field(
        default=True,
        description=(
            "When True, also send webhook notifications for detections that auto-escalate "
            "to tier 1 or tier 2 (allowed-through / block-status-unknown), even when their "
            "severity band is below the Notification threshold (ADR-0059 D3 mechanism; "
            "ADR-0059 Amendment 1, default; issue #74). "
            "Default True (flipped from the original D3 default of False by ADR-0059 "
            "Amendment 1 A1.1): a HIGH ALERT / escalation-tier actor now notifies out of the "
            "box when a webhook is configured, because the ADR-0067 assertion gate already "
            "bounds the population that can reach tier <= 2 — quiet chat is preserved by the "
            "gate, not by this toggle. The toggle still exists so an operator can opt back OUT "
            "to band-only notifications. Existing persisted configs keep their stored value; "
            "only the default for absent values changed (no migration). Firing cadence is "
            "governed by transition semantics (webhook_notifier.check_and_alert) — the "
            "notifier fires on state transitions, not on every re-evaluation of an unchanged "
            "state."
        ),
    )
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        description=(
            "Base URL of the OpenAI-compatible local inference endpoint (ADR-0022). "
            "Must resolve to loopback, RFC 1918, or link-local — cloud endpoints are "
            "rejected at config-write time (defense-in-depth, ADR-0022)."
        ),
    )
    ollama_model: str = Field(
        default="qwen3:14b",
        description="Model name to pass in inference requests.",
    )
    ai_enabled: bool = Field(
        default=True,
        description=(
            "Enable the AI analysis engine (ADR-0022, issue #54). "
            "When False the pipeline produces rule+detection-only scores "
            "with ai_status='disabled' and never contacts the inference endpoint. "
            "Toggle via FIREWATCH_AI_ENABLED env var or config write."
        ),
    )
    api_key: SecretStr | None = Field(
        default=None,
        description=(
            "Optional shared secret that gates the API when it is bound to a "
            "non-loopback address (ADR-0026 Decision 2).  Off by default — no key "
            "is required for the loopback-only MA posture.  Must be set before "
            "binding a non-loopback address (ADR-0026 Decision 4 fail-closed guard). "
            "Supply via FIREWATCH_API_KEY env var (12-Factor III, ADR-0006)."
        ),
    )
    bind_address: str = Field(
        default="127.0.0.1",
        description=(
            "IP address the API server binds to (ADR-0026 Decision 1).  "
            "Default is loopback (127.0.0.1) — the trust boundary for single-host "
            "deployments is the OS/loopback interface, not an application credential.  "
            "Override for reverse-proxy or LAN deployments; the fail-closed startup "
            "guard (ADR-0026 Decision 4, MP.2) rejects a non-loopback bind_address "
            "when api_key is unset.  This field is NOT a secret — it is visible in "
            "the config schema.  Supply via FIREWATCH_BIND_ADDRESS env var (ADR-0006)."
        ),
    )
    geo_provider: GeoProviderLiteral = Field(
        default="offline",
        description=(
            "Geo-enrichment provider (ADR-0039). "
            "'offline' (default): DB-IP Lite MMDB files are downloaded once on first "
            "run and all lookups are local — zero network egress after that. "
            "'online': uses ip-api.com (explicit opt-in). "
            "EGRESS DISCLOSURE — online/free tier: requests are made over plaintext "
            "HTTP (ip-api.com free plan is HTTP-only); the IPs being looked up are "
            "sent to ip-api.com. Use the 'offline' default for air-gapped or "
            "privacy-sensitive deployments. "
            "Set via FIREWATCH_GEO_PROVIDER env var or config write."
        ),
    )

    @field_validator("ollama_base_url")
    @classmethod
    def _validate_ollama_base_url_local_first(cls, v: str) -> str:
        """Reject a literal cloud IP; let hostnames pass syntactically (ADR-0066).

        Inertness principle (ADR-0066, refining ADR-0022's enforcement point):
        this validator must stay PURE and FAST — no DNS resolution, no network
        I/O — because it runs at config-parse time regardless of whether AI is
        even enabled. A hostname-based ``ollama_base_url`` (e.g. the Compose
        default ``http://ollama:11434``) is accepted here unconditionally, even
        when it is currently unresolvable — resolution is itself a TOCTOU
        vector, the same rationale this module already applies to the webhook
        validator's canonical-IP fast path (``_assert_webhook_url_safe``).

        Scheme and IP-literal locality checks remain: a literal cloud IP
        (e.g. ``https://203.0.113.10``) is still rejected here, at
        config-write time. The *resolving* local-first check for hostnames
        moves entirely to the dial boundary (``OpenAIEngine.__init__`` / first
        use, ``firewatch_core.adapters.ai_openai``), which only ever runs when
        ``ai_enabled=true`` — an off subsystem never resolves, dials, or
        crashes (issue #40).
        """
        from urllib.parse import urlparse

        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                f"ollama_base_url scheme must be 'http' or 'https', got "
                f"{parsed.scheme!r} (ADR-0022)."
            )
        host = parsed.hostname or ""
        if not host:
            raise ValueError(
                f"Cannot determine host from ollama_base_url={v!r} — rejecting (ADR-0022)."
            )
        locality = _is_local_ip_literal(host)
        if locality is False:
            raise ValueError(
                f"ollama_base_url {v!r} (host={host!r}) is a literal IP address that "
                "is not loopback/RFC 1918/LAN.  FireWatch local-first invariant "
                "(ADR-0022) prohibits sending telemetry data to a public or cloud "
                "endpoint.  Use Ollama (http://127.0.0.1:11434), vLLM, or another "
                "local runtime."
            )
        # locality is True (a local IP literal) or None (a hostname — passes
        # syntactically; locality is enforced at the dial boundary, ADR-0066).
        return v

    @field_validator("webhook_url")
    @classmethod
    def _validate_webhook_url_ssrf(cls, v: SecretStr | None) -> SecretStr | None:
        """Anti-SSRF validation for the outbound webhook URL (OWASP API7, ADR-0026 §note).

        Rejects, at config-write time:
          - non-``http``/``https`` schemes (no ``file://``, ``gopher://`` …);
          - the literal host ``localhost``;
          - IP-literal hosts in loopback / link-local (incl. the 169.254.169.254
            cloud-metadata address) / multicast / reserved / unspecified ranges.

        RFC 1918 LAN addresses are intentionally ALLOWED — a self-hosted webhook
        receiver is a legitimate use and the operator is trusted. Hostname targets
        are not DNS-resolved here (a validator must stay pure/fast, and resolution
        is itself a TOCTOU/SSRF vector); DNS-rebinding to an internal host is a
        residual handled by network egress policy (documented on #55).
        """
        if v is not None:
            _assert_webhook_url_safe(v.get_secret_value())
        return v


def _is_blocked_webhook_address(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if *addr* is in a range blocked for outbound webhooks (anti-SSRF).

    RFC 1918 private ranges are intentionally ALLOWED — a self-hosted LAN webhook
    receiver is a legitimate operator use case.  IPv6 ULA (fc00::/7, ``is_private``
    for v6) is likewise allowed for symmetry with that decision.

    Blocked: loopback, link-local (includes the 169.254.169.254 cloud-metadata
    prefix), multicast, reserved (includes 0.0.0.0/8, 240.0.0.0/4), and
    unspecified addresses.
    """
    return bool(
        addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _assert_webhook_url_safe(url: str) -> None:
    """Raise ``ValueError`` if *url* is an unsafe outbound-webhook target (anti-SSRF).

    Validates at config-write time:
    - Non-``http``/``https`` schemes are rejected.
    - The literal hostname ``localhost`` is rejected.
    - IP-literal hosts (canonical *and* non-canonical: decimal, octal, hex, trailing-dot)
      whose address is loopback / link-local / multicast / reserved / unspecified are
      rejected.  Non-canonical forms (e.g. ``2130706433``, ``0x7f.0.0.1``) that
      ``ipaddress.ip_address()`` cannot parse are resolved via ``socket.getaddrinfo``
      and every resolved address is checked.
    - RFC 1918 LAN addresses are ALLOWED (self-hosted receiver is operator-trusted).

    Residual risk: DNS-rebinding — a hostname that resolves cleanly at config-write
    time may later rebind to an internal address.  This is mitigated by network
    egress policy outside FireWatch (documented on issue #55 / ADR-0026).
    """
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"webhook_url scheme must be 'http' or 'https', got {parsed.scheme!r} "
            "(anti-SSRF, ADR-0026)."
        )
    host = parsed.hostname or ""
    if not host:
        raise ValueError(f"webhook_url {url!r} has no host (anti-SSRF, ADR-0026).")
    if host.lower() == "localhost":
        raise ValueError("webhook_url host 'localhost' is blocked (anti-SSRF, ADR-0026).")

    # Try to parse as a canonical IP literal first.
    try:
        ip = ipaddress.ip_address(host)
        if _is_blocked_webhook_address(ip):
            raise ValueError(
                f"webhook_url host {host!r} ({ip}) is in a blocked range "
                "(loopback/link-local/metadata/reserved) — anti-SSRF (ADR-0026, OWASP API7)."
            )
        return
    except ValueError as exc:
        # Re-raise if we ourselves raised it above (blocked canonical IP).
        if "blocked range" in str(exc):
            raise

    # Not a canonical IP literal — could be a hostname OR a non-canonical IP encoding
    # (decimal integer, octal, hex-dotted, trailing-dot, …).  Resolve and re-check every
    # address the OS would connect to, so encoded bypasses (e.g. http://2130706433/,
    # http://0x7f.0.0.1/, http://017700000001/) are caught here.
    try:
        resolved = socket.getaddrinfo(host, None)
    except OSError:
        # Genuinely unresolvable hostname — network egress policy governs.
        return

    for _family, _type, _proto, _canonname, sockaddr in resolved:
        ip_str = str(sockaddr[0])
        try:
            resolved_ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _is_blocked_webhook_address(resolved_ip):
            raise ValueError(
                f"webhook_url host {host!r} resolves to {resolved_ip} which is in a blocked "
                "range (loopback/link-local/metadata/reserved) — anti-SSRF "
                "(ADR-0026, OWASP API7)."
            )


# ---------------------------------------------------------------------------
# ConfigStore port (typing.Protocol — shape-only, no implementation here)
# ---------------------------------------------------------------------------


@runtime_checkable
class ConfigStore(Protocol):
    """Port for reading and writing FireWatch configuration.

    Core and plugins interact with config exclusively through this port.  No component
    may keep its own process-global config singleton.

    Resolution precedence (ADR-0006) is enforced by the adapter:
        env vars  >  firewatch_config.json  >  defaults

    While an env var is set for a field, writes to that field are rejected — the env
    layer is read-only from the store's perspective.

    Persistence is atomic: a write either fully commits or leaves the previous state
    intact (no half-written files).

    On load, if the persisted file is corrupt, the adapter falls back to last-known-good
    (or built-in defaults) and emits a warning rather than failing to start (ADR-0023).
    """

    # ---- runtime config -------------------------------------------------------

    def get_runtime(self) -> RuntimeConfig:
        """Return the current resolved RuntimeConfig (env > file > default)."""
        ...

    def set_runtime(self, updates: dict[str, Any]) -> None:
        """Validate ``updates`` against ``RuntimeConfig``, then persist atomically.

        Raises ``ValueError`` if any key in ``updates`` is currently locked by an
        env var (env > file > default enforced, not just merged).
        Raises ``pydantic.ValidationError`` if the merged config is invalid.
        Does NOT mutate state on failure.
        """
        ...

    # ---- per-source config ----------------------------------------------------

    def get_source(self, source_type: str, schema: type[BaseModel]) -> BaseModel:
        """Return the resolved config for *source_type*, validated against *schema*.

        The caller (always core, never a plugin) supplies the plugin's ``config_schema()``
        return value as *schema*.  Core stays source-agnostic; the plugin owns the schema.

        Resolution order: env vars (``FIREWATCH_<SOURCE_TYPE>_*``) > file section
        (``"<source_type>"`` key in ``firewatch_config.json``) > Pydantic defaults.
        """
        ...

    def set_source(
        self, source_type: str, schema: type[BaseModel], updates: dict[str, Any]
    ) -> None:
        """Validate *updates* against *schema*, then persist atomically.

        Raises ``ValueError`` if any key is env-locked.
        Raises ``pydantic.ValidationError`` if the merged config is invalid.
        Does NOT mutate state on failure.
        """
        ...
