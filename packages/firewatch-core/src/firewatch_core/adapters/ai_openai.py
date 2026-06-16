"""OpenAIEngine — local LLM threat analyzer via OpenAI-compatible /v1 endpoint.

This is the concrete implementation of the AIEngine port (firewatch-sdk ports.py)
targeting the OpenAI-compatible ``/v1/chat/completions`` API. It replaces the legacy
``OllamaEngine`` which called Ollama's native ``/api/generate`` endpoint.

ADR-0022 (supersedes ADR-0004): keep local-first invariant but relax runtime lock-in.
Ollama remains the default (http://127.0.0.1:11434); any OpenAI-compatible server works:
vLLM, SGLang, llama.cpp, LM Studio.

Local-first enforcement
-----------------------
At construction, ``base_url`` is validated to resolve to a loopback address
(127.x, ::1, localhost) or an RFC 1918 / LAN address (10/8, 172.16/12, 192.168/16).
Any other host raises ``LocalFirstViolation`` — fail-closed; no HTTP request is ever
sent to a public or cloud host (ADR-0022).

For hostname-based URLs, the hostname is resolved once at construction time, and
``base_url`` is rewritten to use the validated numeric IP, eliminating any DNS
re-resolution at request time (DNS-rebinding TOCTOU mitigation, NB-1).

qwen3 quirk (ai-engine-invariants skill — do NOT "fix" this)
--------------------------------------------------------------
Ollama's ``format:"json"`` constraint makes qwen3 return an empty ``{}``.
``_use_response_format_json()`` detects ``qwen3`` in the model name and omits
``response_format`` entirely.  ``_extract_json()`` then does an outermost-brace walk
to find the JSON inside the reasoning/thinking prefix that qwen3 emits.

Graceful degradation
--------------------
Any exception (timeout, connection error, non-JSON, schema-invalid JSON) is caught and
the documented fallback envelope is returned.  The pipeline stays alive.

Concurrency note (ai-engine-invariants skill)
---------------------------------------------
Ollama serializes requests per GPU; vLLM/SGLang sustain far more.  The appropriate
concurrency limit is runtime-dependent — do NOT hardcode a fixed value here.

MK-2 additive metadata surface (ADR-0044 §4)
---------------------------------------------
``analyze_concise_with_meta`` and ``analyze_detailed_with_meta`` expose
``(validated_dict, AnalysisCallMeta)`` for the verdict-ledger write path.
These methods are ADDITIVE — they do not change prompts, sampling, ``stream: False``,
the qwen3 quirk, or validation order (ai-engine-invariants).  The existing
``analyze_concise`` / ``analyze_detailed`` are unchanged.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import socket
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx

from firewatch_core.ai.prompts import format_concise, format_detailed

logger = logging.getLogger("firewatch.ai_openai")

# ---------------------------------------------------------------------------
# Closed-schema validation constants (issue #16 / ai-engine-invariants)
# ---------------------------------------------------------------------------

_VALID_THREAT_LEVELS = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})
_VALID_ATTACK_STAGES = frozenset({
    "reconnaissance",
    "exploitation",
    "brute_force",
    "data_exfiltration",
    "automated_scanning",
})
_VALID_RECOMMENDED_ACTIONS = frozenset({"block", "investigate", "monitor", "ignore"})

# ---------------------------------------------------------------------------
# NB-5: Allowlist projection — known schema keys (closed schema from issue #16)
# Extra keys that an LLM adds beyond the schema are silently dropped on return.
# ---------------------------------------------------------------------------

_KNOWN_CONCISE_KEYS: frozenset[str] = frozenset({
    "threat_level",
    "confidence",
    "intent",
    "attack_stage",
    "insights",
    "recommended_action",
    "ai_status",
})

_KNOWN_DETAILED_KEYS: frozenset[str] = frozenset({
    "threat_level",
    "confidence",
    "intent",
    "attack_stage",
    "insights",
    "recommended_action",
    "executive_summary",
    "attack_progression",
    "ioc_indicators",
    "false_positive_likelihood",
    "ai_status",
})


# ---------------------------------------------------------------------------
# MK-2: Additive call-metadata carrier (ADR-0044 §4)
# ---------------------------------------------------------------------------


@dataclass
class AnalysisCallMeta:
    """Metadata produced by a single LLM call, surfaced additively for ledger persistence.

    ADR-0044 §4: these fields are captured at call time and passed to the verdict
    ledger WITHOUT altering any prompt, validation, sampling, or scoring path.

    Fields
    ------
    prompt_text:        The exact prompt string sent to the endpoint.
    response_text:      The raw content string returned by the model.
    latency_ms:         Wall-clock time from POST to first content byte (ms).
    prompt_tokens:      From the endpoint ``usage.prompt_tokens`` block when present.
    completion_tokens:  From the endpoint ``usage.completion_tokens`` block when present.
                        Both token counts are None when the endpoint omits the usage block
                        — they are NEVER fabricated (ADR-0044 §2).
    """

    prompt_text: str
    response_text: str
    latency_ms: float
    prompt_tokens: int | None
    completion_tokens: int | None


# ---------------------------------------------------------------------------
# Local-first enforcement
# ---------------------------------------------------------------------------


class LocalFirstViolation(ValueError):
    """Raised at construction when base_url resolves to a non-local host.

    ADR-0022: the adapter must never send data to a public or cloud endpoint.
    This error fires at __init__ time so no HTTP request can be attempted.
    """


def _is_local_address(host: str) -> bool:
    """Return True if *host* resolves to a loopback or RFC 1918 / LAN address.

    Resolution rules (in order):
    1. ``localhost`` -> loopback (RFC 6761).
    2. Parse as an IP address directly (no DNS lookup for IP literals).
    3. For hostnames, attempt a DNS lookup; use the first resolved address.
       If DNS fails, conservatively return False (fail-closed).

    Allowed ranges (ADR-0022):
    - Loopback: 127.0.0.0/8, ::1/128
    - RFC 1918 private: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    - Link-local: 169.254.0.0/16, fe80::/10

    NB-4: 0.0.0.0 is explicitly rejected. Python 3.12 marks 0.0.0.0/8 as
    is_private=True, but 0.0.0.0 is the "unspecified address" (RFC 5735 sec 3,
    not loopback or a LAN address) and connecting to it has OS-defined semantics
    that are NOT equivalent to loopback.
    """
    # Normalise: strip IPv6 brackets
    host = host.strip("[]")

    # 1. localhost shortcut
    if host.lower() == "localhost":
        return True

    # 2. Try parsing as a literal IP first (no DNS)
    try:
        addr = ipaddress.ip_address(host)
        # NB-4: reject the unspecified address (0.0.0.0 / ::).
        # Python 3.12 classifies 0.0.0.0/8 as is_private=True, but 0.0.0.0 is
        # the "unspecified address" (RFC 5735 sec 3), not loopback or a LAN address.
        if addr.is_unspecified:
            return False
        return addr.is_loopback or addr.is_private or addr.is_link_local
    except ValueError:
        pass

    # 3. Hostname: DNS lookup — fail-closed on any error
    try:
        resolved = socket.getaddrinfo(host, None)
        for _family, _type, _proto, _canonname, sockaddr in resolved:
            ip_str = str(sockaddr[0])
            try:
                addr = ipaddress.ip_address(ip_str)
                # NB-4: also reject unspecified from DNS results
                if addr.is_unspecified:
                    continue
                if addr.is_loopback or addr.is_private or addr.is_link_local:
                    return True
            except ValueError:
                continue
        return False
    except OSError:
        # DNS resolution failure -> reject (fail-closed)
        logger.warning(
            "DNS resolution failed for %r — rejecting as non-local (fail-closed, ADR-0022)",
            host,
        )
        return False


def _resolve_to_ip(host: str) -> str | None:
    """Resolve *host* to its first local IP string, or None if not resolvable locally.

    Used by ``_validate_local_first`` to pin the numeric IP into base_url (NB-1).
    Only called for non-IP-literal, non-localhost hostnames.
    Returns None on DNS failure (caller treats as non-local).
    """
    try:
        resolved = socket.getaddrinfo(host, None)
        for _family, _type, _proto, _canonname, sockaddr in resolved:
            ip_str = str(sockaddr[0])
            try:
                addr = ipaddress.ip_address(ip_str)
                if addr.is_unspecified:
                    continue
                if addr.is_loopback or addr.is_private or addr.is_link_local:
                    return ip_str
            except ValueError:
                continue
    except OSError:
        pass
    return None


def _validate_local_first(base_url: str) -> str:
    """Validate that *base_url* points to a local host and return the pinned URL.

    Raises LocalFirstViolation if the host is not local.

    For hostname-based URLs, resolves the hostname once and rewrites ``base_url``
    to use the validated numeric IP (NB-1 DNS-rebinding TOCTOU mitigation).
    IP-literal base_urls and ``localhost`` are returned with only trailing-slash
    normalization applied.
    """
    parsed = urlparse(base_url)
    host = parsed.hostname or ""
    if not host:
        raise LocalFirstViolation(
            f"Cannot determine host from base_url={base_url!r} — rejecting (ADR-0022)"
        )

    # localhost -> always local; keep as-is (resolves to 127.0.0.1 on all platforms)
    if host.lower() == "localhost":
        return base_url.rstrip("/")

    # IP literal path: validate directly, no DNS, return normalised url
    try:
        addr = ipaddress.ip_address(host)
        # NB-4: unspecified address is rejected
        if addr.is_unspecified or not (addr.is_loopback or addr.is_private or addr.is_link_local):
            raise LocalFirstViolation(
                f"base_url {base_url!r} (host={host!r}) does not resolve to a loopback "
                "or RFC 1918/LAN address.  FireWatch local-first invariant (ADR-0022) "
                "prohibits sending telemetry data to a public or cloud endpoint.  "
                "Use Ollama (http://127.0.0.1:11434), vLLM, or another local runtime."
            )
        return base_url.rstrip("/")
    except ValueError:
        pass

    # Hostname path: resolve once, pin numeric IP into base_url (NB-1 TOCTOU fix)
    pinned_ip = _resolve_to_ip(host)
    if pinned_ip is None:
        raise LocalFirstViolation(
            f"base_url {base_url!r} (host={host!r}) does not resolve to a loopback "
            "or RFC 1918/LAN address.  FireWatch local-first invariant (ADR-0022) "
            "prohibits sending telemetry data to a public or cloud endpoint.  "
            "Use Ollama (http://127.0.0.1:11434), vLLM, or another local runtime."
        )

    # Rewrite netloc: replace hostname with pinned numeric IP, preserve port
    port = parsed.port
    if ":" in pinned_ip:
        # IPv6 address: bracket it
        netloc = f"[{pinned_ip}]" if port is None else f"[{pinned_ip}]:{port}"
    else:
        netloc = pinned_ip if port is None else f"{pinned_ip}:{port}"

    pinned_url = urlunparse((
        parsed.scheme,
        netloc,
        parsed.path,
        parsed.params,
        parsed.query,
        parsed.fragment,
    ))
    return pinned_url.rstrip("/")


# ---------------------------------------------------------------------------
# JSON extraction (ported verbatim from legacy/adapters/ai/ollama.py:113-135)
# ---------------------------------------------------------------------------


def _extract_json(text: str) -> dict[str, Any]:
    """Extract a JSON object from text that may contain a reasoning prefix.

    Ported verbatim from ``legacy/adapters/ai/ollama.py`` (lines 113-135).
    The outermost-brace walk is intentionally left unchanged — it handles the
    qwen3 ``<think>...</think>`` prefix that precedes the JSON object.

    Do NOT "fix" or simplify this — see ai-engine-invariants skill.
    """
    text = text.strip()
    try:
        return json.loads(text)  # type: ignore[no-any-return]
    except json.JSONDecodeError:
        pass
    depth = 0
    start: int | None = None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    return json.loads(text[start : i + 1])  # type: ignore[no-any-return]
                except json.JSONDecodeError:
                    start = None
    raise ValueError("No valid JSON object found in response")


# ---------------------------------------------------------------------------
# Schema validation (closed schema from issue #16 / ai-engine-invariants)
# ---------------------------------------------------------------------------


def _validate_concise_schema(data: dict[str, Any]) -> None:
    """Validate *data* against the closed concise-response schema.

    Raises ValueError if any field is missing or has an out-of-contract value.
    Intentionally strict — invalid LLM output triggers graceful degradation.
    """
    if "threat_level" not in data:
        raise ValueError("Missing 'threat_level' in LLM response")
    if data["threat_level"] not in _VALID_THREAT_LEVELS:
        raise ValueError(
            f"Invalid threat_level {data['threat_level']!r}; "
            f"must be one of {sorted(_VALID_THREAT_LEVELS)}"
        )
    if "confidence" not in data:
        raise ValueError("Missing 'confidence' in LLM response")
    conf = float(data["confidence"])
    if not (0.0 <= conf <= 1.0):
        raise ValueError(f"confidence {conf} out of range [0, 1]")
    if "attack_stage" not in data:
        raise ValueError("Missing 'attack_stage' in LLM response")
    if data["attack_stage"] not in _VALID_ATTACK_STAGES:
        raise ValueError(
            f"Invalid attack_stage {data['attack_stage']!r}; "
            f"must be one of {sorted(_VALID_ATTACK_STAGES)}"
        )
    if "recommended_action" not in data:
        raise ValueError("Missing 'recommended_action' in LLM response")
    if data["recommended_action"] not in _VALID_RECOMMENDED_ACTIONS:
        raise ValueError(
            f"Invalid recommended_action {data['recommended_action']!r}; "
            f"must be one of {sorted(_VALID_RECOMMENDED_ACTIONS)}"
        )


def _validate_detailed_schema(data: dict[str, Any]) -> None:
    """Validate *data* against the closed detailed-response schema.

    Applies concise validation first (all concise fields are required), then
    checks detailed-only fields.

    NB-3 (issue #306): 'skipped' is a pipeline-only stamp (ADR-0035 honesty rule).
    A misbehaving LLM returning ai_status='skipped' must be rejected here so the
    fallback path triggers — the pipeline is the sole authority over that value.
    """
    _validate_concise_schema(data)
    # NB-3: reject 'skipped' — only the pipeline may stamp this value.
    if data.get("ai_status") == "skipped":
        raise ValueError(
            "ai_status='skipped' is a pipeline-only stamp and must not appear in "
            "LLM output (NB-3, issue #306)"
        )
    # detailed-specific required fields (loop variable named req_field to avoid
    # shadowing the stdlib 'field' function — ruff F402 prevention)
    for req_field in ("executive_summary", "attack_progression", "insights", "ioc_indicators"):
        if req_field not in data:
            raise ValueError(f"Missing '{req_field}' in detailed LLM response")
    if "false_positive_likelihood" in data:
        fpl = float(data["false_positive_likelihood"])
        if not (0.0 <= fpl <= 1.0):
            raise ValueError(f"false_positive_likelihood {fpl} out of range [0, 1]")


# ---------------------------------------------------------------------------
# Fallback envelopes (ported from legacy/adapters/ai/ollama.py:58-65 and 95-107)
# ---------------------------------------------------------------------------


def _concise_fallback() -> dict[str, Any]:
    """Return the graceful-degradation envelope for concise analysis.

    NB-6: uses a fixed string in the insights field — never embeds raw exception
    text to avoid leaking internal error details to callers.
    """
    return {
        "threat_level": "UNKNOWN",
        "confidence": 0.0,
        "intent": "AI analysis unavailable",
        "attack_stage": "reconnaissance",
        "insights": ["AI classification failed: LLM endpoint error"],
        "recommended_action": "investigate",
        "ai_status": "unavailable",
    }


def _detailed_fallback() -> dict[str, Any]:
    """Return the graceful-degradation envelope for detailed analysis.

    NB-6: uses fixed strings in the ioc_indicators field — never embeds raw
    exception text to avoid leaking internal error details to callers.
    """
    return {
        "threat_level": "UNKNOWN",
        "confidence": 0.0,
        "executive_summary": "Detailed AI analysis unavailable.",
        "intent": "AI analysis failed",
        "attack_stage": "reconnaissance",
        "attack_progression": [],
        "insights": {"patterns": [], "risks": [], "mitigations": []},
        "ioc_indicators": ["Analysis failed: LLM endpoint error"],
        "recommended_action": "investigate",
        "false_positive_likelihood": 0.5,
        "ai_status": "unavailable",
    }


# ---------------------------------------------------------------------------
# OpenAIEngine
# ---------------------------------------------------------------------------


class OpenAIEngine:
    """Threat analyzer using a local OpenAI-compatible /v1/chat/completions endpoint.

    Implements the AIEngine port (firewatch-sdk ports.py:147-181) structurally —
    satisfies ``isinstance(engine, AIEngine)`` via ``runtime_checkable`` Protocol.

    Parameters
    ----------
    base_url:
        Base URL of the local OpenAI-compatible server.  Default is Ollama at
        ``http://127.0.0.1:11434``.  Must resolve to a loopback or RFC 1918
        address — public/cloud hosts raise ``LocalFirstViolation`` at construction
        (ADR-0022, fail-closed).

        For hostname-based URLs (e.g. ``http://myhost:11434``), the hostname is
        resolved once at construction time and the stored ``base_url`` is rewritten
        to use the validated numeric IP (e.g. ``http://127.0.0.1:11434``), so
        every subsequent request hits the validated address with no DNS re-resolution
        (NB-1 DNS-rebinding TOCTOU mitigation).

        ``base_url`` is read-only after construction (NB-2); use a new engine
        instance to change the endpoint.
    model:
        Model name to send in the request body (e.g. ``"llama3.2"``, ``"qwen3:8b"``).
    timeout:
        HTTP timeout in seconds for analysis requests (not the availability check).
        Tune per runtime — Ollama is single-GPU-serial, vLLM/SGLang handle concurrency
        differently.  Do NOT hardcode a small value for concurrency limiting.
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:11434",
        model: str = "llama3.2",
        timeout: float = 120.0,
    ) -> None:
        # NB-1 + NB-2: validate, pin numeric IP for hostname URLs, store as private.
        # base_url is exposed read-only via @property below.
        self._base_url = _validate_local_first(base_url)
        self.model = model
        self.timeout = timeout

    # NB-2: read-only property — no setter, so engine.base_url = "..." is rejected.
    @property
    def base_url(self) -> str:
        """The validated (and IP-pinned for hostname URLs) base URL.

        Read-only after construction (NB-2).  Assigning to this attribute raises
        ``AttributeError``.
        """
        return self._base_url

    # ------------------------------------------------------------------
    # qwen3 format quirk (ai-engine-invariants — do NOT remove)
    # ------------------------------------------------------------------

    def _use_response_format_json(self) -> bool:
        """Return True unless the model is a qwen3 variant.

        qwen3 returns empty ``{}`` when ``response_format: {type: json_object}`` is
        set — omit the field for those models and rely on ``_extract_json`` instead.
        Do NOT remove this; see ai-engine-invariants skill.
        """
        return "qwen3" not in self.model.lower()

    # ------------------------------------------------------------------
    # Internal LLM calls
    # ------------------------------------------------------------------

    async def _call_endpoint(self, prompt: str) -> dict[str, Any]:
        """POST *prompt* to /v1/chat/completions and return the parsed JSON dict.

        Uses the OpenAI-compatible messages format:
            {"role": "user", "content": <prompt>}

        Raises on HTTP errors or JSON parse failures — callers wrap in try/except.
        """
        url = f"{self._base_url}/v1/chat/completions"
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
        }
        if self._use_response_format_json():
            body["response_format"] = {"type": "json_object"}

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(url, json=body)
            response.raise_for_status()
            result = response.json()
            content = result["choices"][0]["message"]["content"]
            return _extract_json(content)

    async def _call_endpoint_with_meta(
        self, prompt: str
    ) -> tuple[dict[str, Any], AnalysisCallMeta]:
        """POST *prompt* and return ``(parsed_dict, AnalysisCallMeta)``.

        MK-2 (ADR-0044 §4): additive metadata surface for verdict-ledger persistence.
        Behaviour is identical to ``_call_endpoint`` — prompt, body construction,
        stream:False, qwen3 quirk, and _extract_json are all unchanged.  The only
        addition is capturing the raw content string, wall-clock latency, and the
        optional ``usage`` block from the response.

        Raises on HTTP errors or JSON parse failures (same as _call_endpoint).
        """
        url = f"{self._base_url}/v1/chat/completions"
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
        }
        if self._use_response_format_json():
            body["response_format"] = {"type": "json_object"}

        t_start = time.monotonic()
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(url, json=body)
            response.raise_for_status()
            result = response.json()

        latency_ms = round((time.monotonic() - t_start) * 1000, 2)
        content: str = result["choices"][0]["message"]["content"]
        parsed = _extract_json(content)

        # Capture token usage when present — never fabricate (ADR-0044 §2).
        usage = result.get("usage") or {}
        prompt_tokens: int | None = usage.get("prompt_tokens")
        completion_tokens: int | None = usage.get("completion_tokens")

        meta = AnalysisCallMeta(
            prompt_text=prompt,
            response_text=content,
            latency_ms=latency_ms,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )
        return parsed, meta

    # ------------------------------------------------------------------
    # Public AIEngine interface (ai-engine-invariants — unchanged)
    # ------------------------------------------------------------------

    async def is_available(self) -> bool:
        """Return True if the local endpoint is reachable within 5 seconds.

        Checks ``GET {base_url}/v1/models`` — the standard OpenAI-compatible
        health-check path (all supported runtimes expose it).
        """
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self._base_url}/v1/models")
                return response.status_code == 200
        except Exception:
            return False

    async def analyze_concise(
        self,
        ip: str,
        total_events: int,
        blocked_events: int,
        rules_triggered: int,
        first_seen: str,
        last_seen: str,
        samples: list[dict[str, Any]],
        security_mode: bool = False,
        correlations: list[Any] | None = None,
    ) -> dict[str, Any]:
        """Return a concise threat assessment for *ip*.

        Builds the prompt via ``format_concise`` (issue #16, NB-1 hardened),
        posts to the endpoint, validates the closed schema, and returns the
        parsed dict projected to known keys (NB-5).  On any error returns
        ``_concise_fallback()`` — never raises.
        """
        prompt = format_concise(
            ip=ip,
            total_events=total_events,
            blocked_events=blocked_events,
            rules_triggered=rules_triggered,
            first_seen=first_seen,
            last_seen=last_seen,
            samples=samples,
            security_mode=security_mode,
            correlations=correlations,
        )
        try:
            parsed = await self._call_endpoint(prompt)
            _validate_concise_schema(parsed)
            logger.info("AI concise summary for %s: threat_level=%s", ip, parsed.get("threat_level"))
            # NB-5: project to known keys only — drop any extra fields the LLM added
            return {k: parsed[k] for k in _KNOWN_CONCISE_KEYS if k in parsed}
        except Exception as exc:
            # NB-6: log type + fixed message; never propagate raw exception text
            logger.warning(
                "AI concise analysis failed for %s: %s — LLM endpoint error",
                ip,
                type(exc).__name__,
            )
            return _concise_fallback()

    async def analyze_detailed(
        self,
        ip: str,
        total_events: int,
        blocked_events: int,
        rules_triggered: int,
        first_seen: str,
        last_seen: str,
        samples: list[dict[str, Any]],
        security_mode: bool = False,
        correlations: list[Any] | None = None,
    ) -> dict[str, Any]:
        """Return a detailed threat assessment for *ip*.

        Builds the prompt via ``format_detailed`` (issue #16, NB-1 hardened),
        posts to the endpoint, validates the closed schema, and returns the
        parsed dict projected to known keys (NB-5).  On any error returns
        ``_detailed_fallback()`` — never raises.
        """
        prompt = format_detailed(
            ip=ip,
            total_events=total_events,
            blocked_events=blocked_events,
            rules_triggered=rules_triggered,
            first_seen=first_seen,
            last_seen=last_seen,
            samples=samples,
            security_mode=security_mode,
            correlations=correlations,
        )
        try:
            parsed = await self._call_endpoint(prompt)
            _validate_detailed_schema(parsed)
            logger.info("AI detailed analysis for %s: threat_level=%s", ip, parsed.get("threat_level"))
            # NB-5: project to known keys only — drop any extra fields the LLM added
            return {k: parsed[k] for k in _KNOWN_DETAILED_KEYS if k in parsed}
        except Exception as exc:
            # NB-6: log type + fixed message; never propagate raw exception text
            logger.warning(
                "AI detailed analysis failed for %s: %s — LLM endpoint error",
                ip,
                type(exc).__name__,
            )
            return _detailed_fallback()

    # ------------------------------------------------------------------
    # MK-2 additive metadata surface (ADR-0044 §4)
    # ------------------------------------------------------------------

    async def analyze_concise_with_meta(
        self,
        ip: str,
        total_events: int,
        blocked_events: int,
        rules_triggered: int,
        first_seen: str,
        last_seen: str,
        samples: list[dict[str, Any]],
        security_mode: bool = False,
        correlations: list[Any] | None = None,
    ) -> tuple[dict[str, Any], AnalysisCallMeta | None]:
        """Return ``(validated_dict, AnalysisCallMeta | None)`` for concise analysis.

        MK-2 (ADR-0044 §4): additive metadata surface for verdict-ledger persistence.
        Prompt construction, sampling, ``stream:False``, qwen3 quirk, schema validation,
        and fallback envelope semantics are ALL UNCHANGED (ai-engine-invariants).

        On success: returns the validated projected dict + populated AnalysisCallMeta.
        On any error: returns ``(_concise_fallback(), None)`` — meta is None on the
        fallback path so callers can identify unavailable results without checking
        ``ai_status`` (the pipeline uses meta is None as the skip-ledger guard).
        """
        prompt = format_concise(
            ip=ip,
            total_events=total_events,
            blocked_events=blocked_events,
            rules_triggered=rules_triggered,
            first_seen=first_seen,
            last_seen=last_seen,
            samples=samples,
            security_mode=security_mode,
            correlations=correlations,
        )
        try:
            parsed, meta = await self._call_endpoint_with_meta(prompt)
            _validate_concise_schema(parsed)
            logger.info(
                "AI concise summary for %s: threat_level=%s", ip, parsed.get("threat_level")
            )
            projected = {k: parsed[k] for k in _KNOWN_CONCISE_KEYS if k in parsed}
            return projected, meta
        except Exception as exc:
            logger.warning(
                "AI concise analysis failed for %s: %s — LLM endpoint error",
                ip,
                type(exc).__name__,
            )
            return _concise_fallback(), None

    async def analyze_detailed_with_meta(
        self,
        ip: str,
        total_events: int,
        blocked_events: int,
        rules_triggered: int,
        first_seen: str,
        last_seen: str,
        samples: list[dict[str, Any]],
        security_mode: bool = False,
        correlations: list[Any] | None = None,
    ) -> tuple[dict[str, Any], AnalysisCallMeta | None]:
        """Return ``(validated_dict, AnalysisCallMeta | None)`` for detailed analysis.

        MK-2 (ADR-0044 §4): additive metadata surface — see analyze_concise_with_meta.
        All ai-engine-invariants are preserved: same prompt, same validation order,
        same fallback semantics.  Meta is None on any error / fallback path.
        """
        prompt = format_detailed(
            ip=ip,
            total_events=total_events,
            blocked_events=blocked_events,
            rules_triggered=rules_triggered,
            first_seen=first_seen,
            last_seen=last_seen,
            samples=samples,
            security_mode=security_mode,
            correlations=correlations,
        )
        try:
            parsed, meta = await self._call_endpoint_with_meta(prompt)
            _validate_detailed_schema(parsed)
            logger.info(
                "AI detailed analysis for %s: threat_level=%s", ip, parsed.get("threat_level")
            )
            projected = {k: parsed[k] for k in _KNOWN_DETAILED_KEYS if k in parsed}
            return projected, meta
        except Exception as exc:
            logger.warning(
                "AI detailed analysis failed for %s: %s — LLM endpoint error",
                ip,
                type(exc).__name__,
            )
            return _detailed_fallback(), None
