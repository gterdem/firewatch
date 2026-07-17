"""Attestation DTO assembler for GET /ai/engine (ADR-0047, issue #409).

This module is a **pure assembler** — no I/O, no FastAPI, no httpx.
All four strip lines are derived from enforced sources, never asserted:

| DTO field               | Derived from                                              |
|-------------------------|-----------------------------------------------------------|
| model                   | RuntimeConfig.ollama_model (validated config)             |
| runtime_profile         | RuntimeConfig.ollama_base_url port heuristic (ADR-0042)   |
| endpoint_host           | RuntimeConfig.ollama_base_url host:port only (OWASP API8) |
| endpoint_validated_local| ADR-0022 _is_local_host constructor guard (provable)      |
| analyses_count          | ai_analyses row count from ledger (NULL if absent)        |
| last_analysis_at        | max(created_at) from ledger (NULL if absent)              |

The "0 cloud AI calls" claim is NOT stored here — it belongs in the UI strip
and derives from the same constructor guard (ADR-0047 derivation table row 4).
The DTO sets ``endpoint_validated_local`` which is the machine-readable proof.

Dependency rule: imports firewatch-sdk only. Never imports legacy/.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Any
from urllib.parse import urlparse

from firewatch_sdk.config import RuntimeConfig

# ---------------------------------------------------------------------------
# Helper: extract host:port from base_url
# ---------------------------------------------------------------------------


def _endpoint_host_from_base_url(base_url: str) -> str:
    """Extract host:port from a base_url — never credentials (OWASP API8).

    Returns the normalized ``host:port`` string.  When no explicit port is
    present, the standard port for the scheme is used (80/443).  IPv6
    addresses are returned with brackets, e.g. ``[::1]:11434``.

    Examples::

        "http://127.0.0.1:11434"  -> "127.0.0.1:11434"
        "http://localhost:11434"  -> "localhost:11434"
        "https://192.168.1.5"     -> "192.168.1.5:443"
        "http://[::1]:11434"      -> "[::1]:11434"
    """
    parsed = urlparse(base_url)
    host = parsed.hostname or "127.0.0.1"
    # Re-bracket IPv6 addresses.
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"

    if parsed.port is not None:
        return f"{host}:{parsed.port}"

    # Fall back to scheme default ports.
    default_port = 443 if parsed.scheme == "https" else 80
    return f"{host}:{default_port}"


# ---------------------------------------------------------------------------
# Helper: derive runtime profile label
# ---------------------------------------------------------------------------


def _runtime_profile_from_base_url(base_url: str) -> str:
    """Derive the runtime profile label from the configured base_url (ADR-0042).

    Heuristic: port 11434 is the Ollama default.  Any other port under a
    local address is assumed to be the llama.cpp ``lean`` profile (or an
    alternative OpenAI-compatible server).

    Returns:
        ``"ollama"`` when port is 11434 (the Ollama default, ADR-0042).
        ``"llama.cpp"`` for any other port.

    This is a best-effort label — it is used for display derivation only
    (ADR-0047 derivation table); no control flow depends on it.
    """
    parsed = urlparse(base_url)
    port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
    return "ollama" if port == 11434 else "llama.cpp"


# ---------------------------------------------------------------------------
# Helper: provable endpoint locality check
# ---------------------------------------------------------------------------
#
# NB (ADR-0066 / issues #39-#40): the SDK config validator (firewatch_sdk.
# config._validate_ollama_base_url_local_first) became PURE/syntactic — it no
# longer resolves hostnames (the inertness principle: a validator must not
# dial/resolve, and resolution is itself a TOCTOU vector). A local resolving
# copy is kept HERE, scoped to this read-time attestation assembler, which is
# a deliberate exception documented alongside the module's "pure — no I/O"
# claim above: this one predicate performs a DNS lookup so the
# ``endpoint_validated_local`` claim stays honest for hostname-configured
# endpoints (e.g. the Compose default ``http://ollama:11434``) — mirroring
# the resolving check that now lives at ``OpenAIEngine.__init__`` (the dial
# boundary), the only other place this proof is made.


def _is_local_host(host: str) -> bool:
    """Return True if *host* resolves to a loopback, RFC 1918, or link-local address.

    Mirrors ``OpenAIEngine._is_local_address`` (``firewatch_core.adapters.ai_openai``)
    — the same predicate the dial boundary itself uses to decide whether to
    refuse a non-local endpoint (ADR-0022). Fail-closed: DNS failure or any
    other resolution error is treated as non-local.
    """
    host = host.strip("[]")
    if host.lower() == "localhost":
        return True
    try:
        addr = ipaddress.ip_address(host)
        if addr.is_unspecified:
            return False
        return bool(addr.is_loopback or addr.is_private or addr.is_link_local)
    except ValueError:
        pass
    try:
        resolved = socket.getaddrinfo(host, None)
        for _family, _type, _proto, _canonname, sockaddr in resolved:
            ip_str = str(sockaddr[0])
            try:
                addr = ipaddress.ip_address(ip_str)
                if addr.is_unspecified:
                    continue
                if addr.is_loopback or addr.is_private or addr.is_link_local:
                    return True
            except ValueError:
                continue
        return False
    except OSError:
        return False


def _endpoint_validated_local(base_url: str) -> bool:
    """Return True when the endpoint host is a validated local address (ADR-0022).

    Uses ``_is_local_host`` (this module) — the same proof the dial boundary
    (``OpenAIEngine.__init__``) makes. It is computed here (not hardcoded) so
    the claim is provable from the actual current config value, not asserted
    unconditionally.
    """
    parsed = urlparse(base_url)
    host = parsed.hostname or ""
    if not host:
        return False
    return _is_local_host(host)


# ---------------------------------------------------------------------------
# DTO assembler
# ---------------------------------------------------------------------------


def build_attestation_dto(
    runtime: RuntimeConfig,
    ledger: Any | None = None,
) -> dict[str, Any]:
    """Assemble the attestation DTO (ADR-0047 D3) from validated config + ledger.

    All fields are derived from enforced sources:

    - ``model`` / ``runtime_profile`` / ``endpoint_host`` /
      ``endpoint_validated_local`` — from ``RuntimeConfig`` (already
      validated by the SDK constructor guard at config-write time, ADR-0022).
    - ``analyses_count`` / ``last_analysis_at`` — from the MK-2 ledger
      (issue #407).  When the ledger is ``None`` (not yet deployed) or
      raises, both fields degrade to ``None`` honestly.

    Args:
        runtime: A validated ``RuntimeConfig`` instance.
        ledger:  An optional ``AnalysisLedger``-compatible object.  Must
                 expose ``get_summary()`` returning a dict with keys
                 ``"analyses_count": int`` and ``"last_analysis_at": str | None``.
                 Pass ``None`` when the ledger is not yet available (pre-#407);
                 the DTO omits count/timestamp rather than fabricating zeros.

    Returns:
        A plain ``dict`` suitable for JSON serialization.  ``None`` values
        are included so the caller knows the field exists but is absent —
        the UI strip omits those lines per ADR-0047.
    """
    base_url = runtime.ollama_base_url

    dto: dict[str, Any] = {
        "model": runtime.ollama_model,
        "runtime_profile": _runtime_profile_from_base_url(base_url),
        "endpoint_host": _endpoint_host_from_base_url(base_url),
        "endpoint_validated_local": _endpoint_validated_local(base_url),
        # Ledger fields: None until #407 ledger is wired in.
        "analyses_count": None,
        "last_analysis_at": None,
    }

    if ledger is not None:
        try:
            summary = ledger.get_summary()
            dto["analyses_count"] = summary.get("analyses_count")
            dto["last_analysis_at"] = summary.get("last_analysis_at")
        except Exception:
            # Ledger read failure is non-fatal (ADR-0047 additive coupling).
            # Leave both fields as None; log nothing here (assembler is pure).
            pass

    return dto
