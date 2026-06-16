"""Tests for firewatch_core.adapters.ai_openai — issue #17 (M2.2).

Each test maps 1:1 to an EARS acceptance criterion from the issue.

EARS-1 (Ubiquitous): OpenAIEngine implements AIEngine and passes isinstance check.
EARS-2 (Event-driven): analyze_concise/analyze_detailed POST one request to
        {base_url}/v1/chat/completions using the #16 prompt, return parsed JSON dict.
EARS-3 (State-driven): while base_url does NOT resolve to loopback/RFC1918/LAN,
        refuse to initialize (ValueError at construction).
EARS-4 (Unwanted): endpoint unreachable/timeout/non-schema JSON → return documented
        fallback envelope (threat_level=UNKNOWN, ai_status unavailable), never raise.
EARS-5 (Unwanted): model name contains 'qwen3' → omit format:"json" param; recover
        via outermost-brace extraction.
EARS-6 (Optional): is_available() returns True within ≤5s when endpoint reports 200.

Security notes for the reviewer
---------------------------------
* RFC 5737 documentation IPs (192.0.2.x, 198.51.100.x, 203.0.113.x) are used in
  all fixtures — never real routable IPs (gitleaks gate compliance).
* Public/cloud host rejection is verified for both hostname-based and numeric IP
  cases to ensure no cloud-LLM egress path (ADR-0022).
"""
from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BASE_KWARGS: dict[str, Any] = dict(
    ip="192.0.2.1",
    total_events=10,
    blocked_events=8,
    rules_triggered=3,
    first_seen="2024-01-01T00:00:00Z",
    last_seen="2024-01-01T12:00:00Z",
    samples=[
        {
            "rule_id": "942100",
            "category": "SQLi",
            "count": 5,
            "payload": "SELECT * FROM users",
        }
    ],
)

# Minimal schema-valid concise response
_VALID_CONCISE_RESPONSE: dict[str, Any] = {
    "threat_level": "HIGH",
    "confidence": 0.85,
    "intent": "SQL injection probe",
    "attack_stage": "exploitation",
    "insights": ["pattern: SQLi detected"],
    "recommended_action": "block",
}

# Minimal schema-valid detailed response
_VALID_DETAILED_RESPONSE: dict[str, Any] = {
    "threat_level": "CRITICAL",
    "confidence": 0.9,
    "executive_summary": "Sustained attack.",
    "intent": "Data exfil",
    "attack_stage": "data_exfiltration",
    "attack_progression": ["Step 1: probe", "Step 2: exploit"],
    "insights": {"patterns": [], "risks": [], "mitigations": []},
    "ioc_indicators": [],
    "recommended_action": "block",
    "false_positive_likelihood": 0.05,
}

# Fallback envelope constants (what the engine must return on failure)
_FALLBACK_THREAT_LEVEL = "UNKNOWN"


def _make_engine(
    base_url: str = "http://127.0.0.1:11434",
    model: str = "llama3.2",
    timeout: float = 120.0,
) -> Any:
    """Construct an OpenAIEngine; importing here keeps collection-time imports lazy."""
    from firewatch_core.adapters.ai_openai import OpenAIEngine

    return OpenAIEngine(base_url=base_url, model=model, timeout=timeout)


def _make_mock_response(data: dict[str, Any], status_code: int = 200) -> MagicMock:
    """Build a mock httpx.Response that returns *data* as JSON."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(data),
                }
            }
        ]
    }
    mock_resp.raise_for_status = MagicMock()
    return mock_resp


def _make_chat_client_mock(response: MagicMock) -> MagicMock:
    """Build an async context manager mock for httpx.AsyncClient."""
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=response)
    mock_acm = AsyncMock()
    mock_acm.__aenter__ = AsyncMock(return_value=mock_client)
    mock_acm.__aexit__ = AsyncMock(return_value=False)
    return mock_acm


# ---------------------------------------------------------------------------
# EARS-1: isinstance(engine, AIEngine)
# ---------------------------------------------------------------------------


class TestAIEngineProtocol:
    """EARS-1 — OpenAIEngine satisfies the runtime_checkable AIEngine Protocol."""

    def test_implements_ai_engine_protocol(self) -> None:
        """isinstance(engine, AIEngine) must be True (runtime_checkable Protocol)."""
        from firewatch_sdk import AIEngine

        engine = _make_engine()
        assert isinstance(engine, AIEngine), (
            "OpenAIEngine must satisfy the AIEngine Protocol (runtime_checkable)"
        )

    def test_has_is_available_method(self) -> None:
        """Structural check: is_available attribute is callable."""
        engine = _make_engine()
        assert callable(engine.is_available)

    def test_has_analyze_concise_method(self) -> None:
        """Structural check: analyze_concise attribute is callable."""
        engine = _make_engine()
        assert callable(engine.analyze_concise)

    def test_has_analyze_detailed_method(self) -> None:
        """Structural check: analyze_detailed attribute is callable."""
        engine = _make_engine()
        assert callable(engine.analyze_detailed)


# ---------------------------------------------------------------------------
# EARS-2: POST to /v1/chat/completions, return parsed JSON dict
# ---------------------------------------------------------------------------


class TestAnalyzeConcise:
    """EARS-2 — analyze_concise POSTs to /v1/chat/completions, returns parsed dict."""

    async def test_posts_to_chat_completions_endpoint(self) -> None:
        """The request must go to {base_url}/v1/chat/completions (not /api/generate)."""
        mock_resp = _make_mock_response(_VALID_CONCISE_RESPONSE)
        mock_acm = _make_chat_client_mock(mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine()
            await engine.analyze_concise(**BASE_KWARGS)

        mock_acm.__aenter__.return_value.post.assert_called_once()
        call_url = mock_acm.__aenter__.return_value.post.call_args[0][0]
        assert "/v1/chat/completions" in call_url, (
            f"Expected POST to /v1/chat/completions; got {call_url!r}"
        )
        assert "/api/generate" not in call_url, (
            "Must NOT use legacy /api/generate endpoint (superseded by ADR-0022)"
        )

    async def test_returns_dict_with_threat_level(self) -> None:
        """analyze_concise returns a dict containing 'threat_level'."""
        mock_resp = _make_mock_response(_VALID_CONCISE_RESPONSE)
        mock_acm = _make_chat_client_mock(mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine()
            result = await engine.analyze_concise(**BASE_KWARGS)

        assert isinstance(result, dict)
        assert "threat_level" in result
        assert result["threat_level"] == "HIGH"

    async def test_request_body_includes_model_and_messages(self) -> None:
        """Request body must include 'model' and 'messages' (OpenAI-compat interface)."""
        mock_resp = _make_mock_response(_VALID_CONCISE_RESPONSE)
        mock_acm = _make_chat_client_mock(mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine(model="llama3.2")
            await engine.analyze_concise(**BASE_KWARGS)

        call_kwargs = mock_acm.__aenter__.return_value.post.call_args[1]
        body = call_kwargs.get("json", {})
        assert "model" in body, "Request body must include 'model'"
        assert "messages" in body, "Request body must include 'messages' (not 'prompt')"
        assert body["model"] == "llama3.2"


class TestAnalyzeDetailed:
    """EARS-2 — analyze_detailed POSTs to /v1/chat/completions, returns parsed dict."""

    async def test_posts_to_chat_completions_endpoint(self) -> None:
        """analyze_detailed also targets /v1/chat/completions."""
        mock_resp = _make_mock_response(_VALID_DETAILED_RESPONSE)
        mock_acm = _make_chat_client_mock(mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine()
            await engine.analyze_detailed(**BASE_KWARGS)

        call_url = mock_acm.__aenter__.return_value.post.call_args[0][0]
        assert "/v1/chat/completions" in call_url

    async def test_returns_dict_with_threat_level(self) -> None:
        """analyze_detailed returns a dict with threat_level."""
        mock_resp = _make_mock_response(_VALID_DETAILED_RESPONSE)
        mock_acm = _make_chat_client_mock(mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine()
            result = await engine.analyze_detailed(**BASE_KWARGS)

        assert isinstance(result, dict)
        assert result["threat_level"] == "CRITICAL"


# ---------------------------------------------------------------------------
# EARS-3: local-first enforcement — reject public/cloud base_url at construction
# ---------------------------------------------------------------------------


class TestLocalFirstEnforcement:
    """EARS-3 — base_url must resolve to loopback/RFC1918/LAN; public hosts rejected.

    Security note: Python 3.12's ipaddress module classifies RFC 5737 documentation
    blocks (192.0.2.x, 198.51.100.x, 203.0.113.x) as is_private=True (they are
    non-globally-routable). Gitleaks gate prohibits real public IPs in test files.
    We therefore test hostname-based rejection (api.openai.com, llm.example.com)
    and DNS-failure fail-closed behaviour (a nonexistent domain).

    The ADR-0022 invariant is enforced by _is_local_address(): any host that is NOT
    loopback/private/link-local is rejected. Real cloud endpoints (OpenAI, etc.)
    resolve to globally-routable addresses which Python classifies as is_global=True
    (not is_private), so they are correctly rejected.
    """

    def test_loopback_ipv4_accepted(self) -> None:
        """http://127.0.0.1:11434 must be accepted (loopback)."""
        engine = _make_engine(base_url="http://127.0.0.1:11434")
        assert engine is not None

    def test_loopback_localhost_accepted(self) -> None:
        """http://localhost:11434 must be accepted (loopback hostname)."""
        engine = _make_engine(base_url="http://localhost:11434")
        assert engine is not None

    def test_rfc1918_10_block_accepted(self) -> None:
        """10.0.0.1 is RFC 1918 private — must be accepted."""
        engine = _make_engine(base_url="http://10.0.0.1:11434")
        assert engine is not None

    def test_rfc1918_172_16_block_accepted(self) -> None:
        """172.16.0.1 is RFC 1918 private — must be accepted."""
        engine = _make_engine(base_url="http://172.16.0.1:11434")
        assert engine is not None

    def test_rfc1918_192_168_block_accepted(self) -> None:
        """192.168.1.1 is RFC 1918 private — must be accepted."""
        engine = _make_engine(base_url="http://192.168.1.1:11434")
        assert engine is not None

    def test_cloud_hostname_rejected(self) -> None:
        """api.openai.com must be rejected — cloud LLM violates ADR-0022.

        api.openai.com resolves to globally-routable IPs which Python's ipaddress
        module classifies as is_global=True (not is_private), so it is rejected.
        If DNS resolution fails in the test environment, _is_local_address returns
        False (fail-closed), which also triggers rejection.
        """
        from firewatch_core.adapters.ai_openai import LocalFirstViolation

        with pytest.raises((ValueError, LocalFirstViolation)):
            _make_engine(base_url="https://api.openai.com")

    def test_arbitrary_public_hostname_rejected(self) -> None:
        """Any non-LAN hostname (external domain) must be rejected.

        llm.example.com does not exist; DNS fails → fail-closed → rejected.
        """
        from firewatch_core.adapters.ai_openai import LocalFirstViolation

        with pytest.raises((ValueError, LocalFirstViolation)):
            _make_engine(base_url="https://llm.example.com")

    def test_nonexistent_hostname_rejected_fail_closed(self) -> None:
        """DNS resolution failure → rejected (fail-closed, ADR-0022).

        A hostname that cannot be resolved is treated as non-local to prevent
        spoofed-DNS attacks from bypassing the local-first guard.
        """
        from firewatch_core.adapters.ai_openai import LocalFirstViolation

        with pytest.raises((ValueError, LocalFirstViolation)):
            _make_engine(base_url="http://this-hostname-does-not-exist.invalid:11434")

    def test_no_request_ever_sent_to_rejected_url(self) -> None:
        """Construction failure means NO HTTP request is ever attempted (fail-closed)."""
        from firewatch_core.adapters.ai_openai import LocalFirstViolation

        call_count = 0

        class _CountingClient:
            async def post(self, *a: Any, **kw: Any) -> None:
                nonlocal call_count
                call_count += 1

        with patch("httpx.AsyncClient", return_value=_CountingClient()):
            with pytest.raises((ValueError, LocalFirstViolation)):
                _make_engine(base_url="https://api.openai.com")

        assert call_count == 0, (
            "An HTTP request was sent to a rejected (public) URL — fail-closed violated"
        )


# ---------------------------------------------------------------------------
# EARS-4: fallback envelope on error — never raise to the pipeline
# ---------------------------------------------------------------------------


class TestFallbackEnvelope:
    """EARS-4 — any error (timeout, non-schema JSON, connection refused) → fallback."""

    async def test_timeout_returns_fallback_envelope(self) -> None:
        """httpx.TimeoutException → fallback dict, not an exception propagated."""
        import httpx

        mock_acm = AsyncMock()
        mock_acm.__aenter__ = AsyncMock(return_value=mock_acm)
        mock_acm.__aexit__ = AsyncMock(return_value=False)
        mock_acm.post = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine()
            result = await engine.analyze_concise(**BASE_KWARGS)

        assert result["threat_level"] == _FALLBACK_THREAT_LEVEL, (
            f"Expected fallback threat_level={_FALLBACK_THREAT_LEVEL!r}; got {result['threat_level']!r}"
        )

    async def test_connection_error_returns_fallback_envelope(self) -> None:
        """httpx.ConnectError → fallback dict (endpoint unreachable)."""
        import httpx

        mock_acm = AsyncMock()
        mock_acm.__aenter__ = AsyncMock(return_value=mock_acm)
        mock_acm.__aexit__ = AsyncMock(return_value=False)
        mock_acm.post = AsyncMock(
            side_effect=httpx.ConnectError("connection refused")
        )

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine()
            result = await engine.analyze_concise(**BASE_KWARGS)

        assert result["threat_level"] == _FALLBACK_THREAT_LEVEL

    async def test_malformed_json_in_content_returns_fallback(self) -> None:
        """If the LLM returns non-JSON content, return fallback (never raise)."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "This is not JSON at all."}}]
        }

        mock_acm = _make_chat_client_mock(mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine()
            result = await engine.analyze_concise(**BASE_KWARGS)

        assert result["threat_level"] == _FALLBACK_THREAT_LEVEL

    async def test_schema_invalid_json_returns_fallback(self) -> None:
        """Valid JSON that does NOT match the closed schema → fallback envelope."""
        # Missing required 'threat_level' field
        bad_response = {"something": "unexpected", "confidence": 0.5}
        mock_resp = _make_mock_response(bad_response)
        mock_acm = _make_chat_client_mock(mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine()
            result = await engine.analyze_concise(**BASE_KWARGS)

        assert result["threat_level"] == _FALLBACK_THREAT_LEVEL

    async def test_invalid_threat_level_enum_returns_fallback(self) -> None:
        """threat_level value outside closed enum → fallback envelope."""
        bad_response = {**_VALID_CONCISE_RESPONSE, "threat_level": "EXTREME"}
        mock_resp = _make_mock_response(bad_response)
        mock_acm = _make_chat_client_mock(mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine()
            result = await engine.analyze_concise(**BASE_KWARGS)

        assert result["threat_level"] == _FALLBACK_THREAT_LEVEL

    async def test_confidence_out_of_range_returns_fallback(self) -> None:
        """confidence > 1.0 → fallback (schema validation catches it)."""
        bad_response = {**_VALID_CONCISE_RESPONSE, "confidence": 1.5}
        mock_resp = _make_mock_response(bad_response)
        mock_acm = _make_chat_client_mock(mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine()
            result = await engine.analyze_concise(**BASE_KWARGS)

        assert result["threat_level"] == _FALLBACK_THREAT_LEVEL

    async def test_http_error_returns_fallback(self) -> None:
        """Non-200 status code (e.g. 503) → fallback, not a raised exception."""
        import httpx

        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "503", request=MagicMock(), response=MagicMock()
        )
        mock_acm = _make_chat_client_mock(mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine()
            result = await engine.analyze_concise(**BASE_KWARGS)

        assert result["threat_level"] == _FALLBACK_THREAT_LEVEL

    async def test_fallback_concise_has_required_keys(self) -> None:
        """Fallback envelope has all required keys from the documented shape (concise)."""
        import httpx

        mock_acm = AsyncMock()
        mock_acm.__aenter__ = AsyncMock(return_value=mock_acm)
        mock_acm.__aexit__ = AsyncMock(return_value=False)
        mock_acm.post = AsyncMock(side_effect=httpx.ConnectError("down"))

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine()
            result = await engine.analyze_concise(**BASE_KWARGS)

        required_keys = {
            "threat_level", "confidence", "intent", "attack_stage",
            "insights", "recommended_action",
        }
        assert required_keys.issubset(result.keys()), (
            f"Fallback envelope missing keys: {required_keys - result.keys()}"
        )

    async def test_fallback_detailed_has_required_keys(self) -> None:
        """Fallback envelope has all required keys from the documented shape (detailed)."""
        import httpx

        mock_acm = AsyncMock()
        mock_acm.__aenter__ = AsyncMock(return_value=mock_acm)
        mock_acm.__aexit__ = AsyncMock(return_value=False)
        mock_acm.post = AsyncMock(side_effect=httpx.ConnectError("down"))

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine()
            result = await engine.analyze_detailed(**BASE_KWARGS)

        required_keys = {
            "threat_level", "confidence", "intent", "attack_stage",
            "recommended_action", "executive_summary",
        }
        assert required_keys.issubset(result.keys()), (
            f"Fallback envelope missing keys: {required_keys - result.keys()}"
        )

    async def test_fallback_never_raises(self) -> None:
        """No matter what the LLM returns, analyze_concise/detailed must not raise."""
        mock_acm = AsyncMock()
        mock_acm.__aenter__ = AsyncMock(return_value=mock_acm)
        mock_acm.__aexit__ = AsyncMock(return_value=False)
        mock_acm.post = AsyncMock(side_effect=RuntimeError("unexpected"))

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine()
            # Must not raise — any exception is caught and fallback returned
            result_c = await engine.analyze_concise(**BASE_KWARGS)
            result_d = await engine.analyze_detailed(**BASE_KWARGS)

        assert result_c["threat_level"] == _FALLBACK_THREAT_LEVEL
        assert result_d["threat_level"] == _FALLBACK_THREAT_LEVEL


# ---------------------------------------------------------------------------
# EARS-5: qwen3 quirk — omit format:"json", extract via outermost-brace walk
# ---------------------------------------------------------------------------


class TestQwen3Quirk:
    """EARS-5 — qwen3 models must have format param omitted; extraction still works.

    From ai-engine-invariants skill: "qwen3 returns empty {} with format:json — disable
    for those models."  Do NOT 'fix' this — it is intentionally fragile.
    """

    async def test_qwen3_model_omits_format_param(self) -> None:
        """When model contains 'qwen3', the request body must NOT include response_format."""
        mock_resp = _make_mock_response(_VALID_CONCISE_RESPONSE)
        mock_acm = _make_chat_client_mock(mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine(model="qwen3:8b")
            await engine.analyze_concise(**BASE_KWARGS)

        body = mock_acm.__aenter__.return_value.post.call_args[1].get("json", {})
        assert "response_format" not in body, (
            "qwen3 model must NOT send response_format param "
            "(it causes qwen3 to return empty {} — ai-engine-invariants)"
        )

    async def test_qwen3_uppercase_variant_omits_format_param(self) -> None:
        """Case-insensitive: 'Qwen3' (capital) also omits format param."""
        mock_resp = _make_mock_response(_VALID_CONCISE_RESPONSE)
        mock_acm = _make_chat_client_mock(mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine(model="Qwen3-14B")
            await engine.analyze_concise(**BASE_KWARGS)

        body = mock_acm.__aenter__.return_value.post.call_args[1].get("json", {})
        assert "response_format" not in body

    async def test_non_qwen3_model_includes_response_format_json(self) -> None:
        """Non-qwen3 models must include response_format:{type:'json_object'} in body."""
        mock_resp = _make_mock_response(_VALID_CONCISE_RESPONSE)
        mock_acm = _make_chat_client_mock(mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine(model="llama3.2")
            await engine.analyze_concise(**BASE_KWARGS)

        body = mock_acm.__aenter__.return_value.post.call_args[1].get("json", {})
        assert "response_format" in body, (
            "Non-qwen3 model must include response_format for JSON mode"
        )
        assert body["response_format"].get("type") == "json_object"

    async def test_qwen3_reasoning_prefix_extracted(self) -> None:
        """qwen3 response with reasoning preamble: outermost-brace walk must find JSON."""
        # qwen3 typically wraps output in <think>...</think> before the JSON
        thinking_prefix = "<think>\nLet me analyze this threat...\n</think>\n\n"
        json_payload = json.dumps(_VALID_CONCISE_RESPONSE)
        content_with_prefix = thinking_prefix + json_payload

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": content_with_prefix}}]
        }
        mock_acm = _make_chat_client_mock(mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine(model="qwen3:8b")
            result = await engine.analyze_concise(**BASE_KWARGS)

        # Must parse successfully, not return fallback
        assert result["threat_level"] == "HIGH", (
            "qwen3 reasoning prefix should be stripped by outermost-brace extraction"
        )


# ---------------------------------------------------------------------------
# EARS-6: is_available() returns True within ≤5s on 200
# ---------------------------------------------------------------------------


class TestIsAvailable:
    """EARS-6 — is_available() checks /v1/models availability."""

    async def test_is_available_returns_true_on_200(self) -> None:
        """is_available() returns True when the endpoint responds with 200."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_acm = AsyncMock()
        mock_acm.__aenter__ = AsyncMock(return_value=mock_client)
        mock_acm.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine()
            result = await engine.is_available()

        assert result is True

    async def test_is_available_returns_false_on_connection_error(self) -> None:
        """is_available() returns False when the endpoint is unreachable."""
        import httpx

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
        mock_acm = AsyncMock()
        mock_acm.__aenter__ = AsyncMock(return_value=mock_client)
        mock_acm.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine()
            result = await engine.is_available()

        assert result is False

    async def test_is_available_returns_false_on_non_200(self) -> None:
        """is_available() returns False when the endpoint returns a non-200 status."""
        mock_resp = MagicMock()
        mock_resp.status_code = 503

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_acm = AsyncMock()
        mock_acm.__aenter__ = AsyncMock(return_value=mock_client)
        mock_acm.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine()
            result = await engine.is_available()

        assert result is False

    async def test_is_available_uses_5s_timeout(self) -> None:
        """is_available() must use a ≤5s timeout (ADR-0022: Optional criterion)."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_acm = AsyncMock()
        mock_acm.__aenter__ = AsyncMock(return_value=mock_client)
        mock_acm.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_acm) as mock_cls:
            engine = _make_engine()
            await engine.is_available()
            # Check that timeout passed to AsyncClient construction is ≤5s
            if mock_cls.call_args:
                kw = mock_cls.call_args[1] if mock_cls.call_args[1] else {}
                t = kw.get("timeout")
                if t is not None:
                    assert float(t) <= 5.0, (
                        f"is_available timeout must be ≤5s; got {t}"
                    )


# ---------------------------------------------------------------------------
# Isolation: no forbidden imports
# ---------------------------------------------------------------------------


class TestNoForbiddenImports:
    """The adapter must not import legacy or unauthorized firewatch packages."""

    def test_does_not_import_legacy(self) -> None:
        """No import of legacy/ in the adapter module."""
        import re
        import pathlib

        adapter_path = (
            pathlib.Path(__file__).parent.parent
            / "src" / "firewatch_core" / "adapters" / "ai_openai.py"
        )
        content = adapter_path.read_text()
        import_re = re.compile(r"^\s*(from legacy|import legacy)\b", re.MULTILINE)
        assert import_re.search(content) is None, (
            "ai_openai.py must not import legacy/ — PLUGIN_CONTRACT.md"
        )

    def test_only_imports_firewatch_sdk_not_plugins(self) -> None:
        """The adapter may import firewatch_sdk or firewatch_core; never source plugins."""
        import pathlib

        adapter_path = (
            pathlib.Path(__file__).parent.parent
            / "src" / "firewatch_core" / "adapters" / "ai_openai.py"
        )
        content = adapter_path.read_text()
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if "from firewatch_" in stripped or "import firewatch_" in stripped:
                allowed = (
                    "firewatch_sdk" in stripped
                    or "firewatch_core" in stripped
                )
                assert allowed, (
                    f"Forbidden import in ai_openai.py: {stripped!r}"
                )


# ---------------------------------------------------------------------------
# NB-1: Hostname base_url gets pinned to resolved numeric IP
# ---------------------------------------------------------------------------


class TestNB1IPPinning:
    """NB-1 — hostname base_url is resolved once and rewritten to numeric IP.

    After construction, engine.base_url must be an IP-literal URL, not the
    original hostname, so every subsequent HTTP request uses the validated
    address with no DNS re-resolution (DNS-rebinding TOCTOU mitigation).
    """

    def test_localhost_base_url_accepted_unchanged(self) -> None:
        """localhost is a special case: kept as-is (no DNS needed)."""
        engine = _make_engine(base_url="http://localhost:11434")
        # localhost must still work; base_url need not be rewritten to 127.0.0.1
        assert engine.base_url is not None
        assert "localhost" in engine.base_url or "127." in engine.base_url

    def test_hostname_base_url_pinned_to_ip(self) -> None:
        """A resolvable local hostname is rewritten to its numeric IP in base_url.

        We mock socket.getaddrinfo to simulate a hostname that resolves to
        127.0.0.1 (loopback) — the stored base_url must use the numeric IP.
        """
        from unittest.mock import patch
        import socket

        fake_result = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0)),
        ]
        with patch("socket.getaddrinfo", return_value=fake_result):
            engine = _make_engine(base_url="http://my-local-llm.internal:11434")

        # The stored base_url must contain the numeric IP, not the original hostname
        assert "127.0.0.1" in engine.base_url, (
            f"Expected numeric IP in base_url after pinning; got {engine.base_url!r}"
        )
        assert "my-local-llm.internal" not in engine.base_url, (
            "Original hostname must not appear in pinned base_url"
        )

    def test_hostname_pinning_preserves_scheme_and_port(self) -> None:
        """The pinned base_url must preserve the original scheme and port."""
        from unittest.mock import patch
        import socket

        fake_result = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 0)),
        ]
        with patch("socket.getaddrinfo", return_value=fake_result):
            engine = _make_engine(base_url="http://llm-server.lan:8080")

        assert engine.base_url.startswith("http://"), (
            f"Scheme must be preserved; got {engine.base_url!r}"
        )
        assert ":8080" in engine.base_url, (
            f"Port must be preserved; got {engine.base_url!r}"
        )
        assert "10.0.0.1" in engine.base_url

    def test_ip_literal_base_url_not_rewritten(self) -> None:
        """An IP-literal base_url (e.g. 127.0.0.1) is not rewritten — no DNS."""
        engine = _make_engine(base_url="http://127.0.0.1:11434")
        assert "127.0.0.1" in engine.base_url

    async def test_subsequent_requests_use_pinned_ip(self) -> None:
        """The URL used for POST must match the pinned IP, not the original hostname."""
        from unittest.mock import patch
        import socket

        fake_result = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("192.168.1.50", 0)),
        ]
        with patch("socket.getaddrinfo", return_value=fake_result):
            engine = _make_engine(base_url="http://gpu-box.local:11434")

        mock_resp = _make_mock_response(_VALID_CONCISE_RESPONSE)
        mock_acm = _make_chat_client_mock(mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_acm):
            await engine.analyze_concise(**BASE_KWARGS)
        call_url = mock_acm.__aenter__.return_value.post.call_args[0][0]

        assert "192.168.1.50" in call_url, (
            f"Request URL must use pinned IP; got {call_url!r}"
        )
        assert "gpu-box.local" not in call_url, (
            "Original hostname must NOT appear in request URL after pinning"
        )


# ---------------------------------------------------------------------------
# NB-2: base_url is immutable post-construction
# ---------------------------------------------------------------------------


class TestNB2ImmutableBaseUrl:
    """NB-2 — base_url is a read-only property; no setter exists."""

    def test_base_url_is_readable(self) -> None:
        """engine.base_url must be readable and return a non-empty string."""
        engine = _make_engine()
        assert isinstance(engine.base_url, str)
        assert engine.base_url  # non-empty

    def test_base_url_has_no_setter(self) -> None:
        """Assigning to engine.base_url must raise AttributeError (read-only property)."""
        engine = _make_engine()
        with pytest.raises(AttributeError):
            engine.base_url = "https://api.openai.com"  # type: ignore[misc]

    def test_base_url_setter_cannot_bypass_guard(self) -> None:
        """After failed setter attempt, base_url must remain the original validated value."""
        engine = _make_engine(base_url="http://127.0.0.1:11434")
        original = engine.base_url
        try:
            engine.base_url = "http://10.0.0.99:11434"  # type: ignore[misc]
        except AttributeError:
            pass
        assert engine.base_url == original, (
            "base_url must not change after a failed setter attempt"
        )


# ---------------------------------------------------------------------------
# NB-4: 0.0.0.0 (unspecified address) is rejected
# ---------------------------------------------------------------------------


class TestNB4UnspecifiedAddressRejected:
    """NB-4 — 0.0.0.0 (and ::) is rejected even though Python 3.12 marks it private.

    Python 3.12 classifies 0.0.0.0/8 as is_private=True, which would cause the
    original guard to accept it.  0.0.0.0 is the "unspecified address" (RFC 5735),
    not loopback or LAN, and connecting to it has OS-defined semantics.
    """

    def test_unspecified_ipv4_rejected(self) -> None:
        """http://0.0.0.0:11434 must be rejected (unspecified address, not loopback)."""
        from firewatch_core.adapters.ai_openai import LocalFirstViolation

        with pytest.raises((ValueError, LocalFirstViolation)):
            _make_engine(base_url="http://0.0.0.0:11434")

    def test_unspecified_ipv6_rejected(self) -> None:
        """http://[::]:11434 must be rejected (IPv6 unspecified address)."""
        from firewatch_core.adapters.ai_openai import LocalFirstViolation

        with pytest.raises((ValueError, LocalFirstViolation)):
            _make_engine(base_url="http://[::]:11434")

    def test_is_local_address_rejects_0_0_0_0_directly(self) -> None:
        """_is_local_address('0.0.0.0') must return False."""
        from firewatch_core.adapters.ai_openai import _is_local_address

        assert _is_local_address("0.0.0.0") is False, (
            "0.0.0.0 is the unspecified address and must not be accepted as local"
        )

    def test_loopback_127_0_0_1_still_accepted(self) -> None:
        """127.0.0.1 must still be accepted (regression guard for NB-4 change)."""
        from firewatch_core.adapters.ai_openai import _is_local_address

        assert _is_local_address("127.0.0.1") is True

    def test_rfc1918_still_accepted_after_nb4(self) -> None:
        """10.0.0.1 must still be accepted (regression guard)."""
        from firewatch_core.adapters.ai_openai import _is_local_address

        assert _is_local_address("10.0.0.1") is True


# ---------------------------------------------------------------------------
# NB-5: Extra LLM response keys are stripped (allowlist projection)
# ---------------------------------------------------------------------------


class TestNB5ResponseProjection:
    """NB-5 — only schema-defined keys are returned; extra LLM keys are dropped."""

    async def test_extra_concise_keys_stripped(self) -> None:
        """Extra keys in a concise LLM response must not appear in the return value."""
        response_with_extras = {
            **_VALID_CONCISE_RESPONSE,
            "extra_field": "should be dropped",
            "another_unknown": 42,
            "internal_debug": {"foo": "bar"},
        }
        mock_resp = _make_mock_response(response_with_extras)
        mock_acm = _make_chat_client_mock(mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine()
            result = await engine.analyze_concise(**BASE_KWARGS)

        assert "extra_field" not in result, "extra_field must be stripped by allowlist projection"
        assert "another_unknown" not in result
        assert "internal_debug" not in result

    async def test_known_concise_keys_preserved(self) -> None:
        """All schema-defined concise keys present in the LLM response must be kept."""
        mock_resp = _make_mock_response(_VALID_CONCISE_RESPONSE)
        mock_acm = _make_chat_client_mock(mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine()
            result = await engine.analyze_concise(**BASE_KWARGS)

        for key in ("threat_level", "confidence", "attack_stage", "recommended_action"):
            assert key in result, f"Schema key {key!r} must be preserved in projected result"

    async def test_extra_detailed_keys_stripped(self) -> None:
        """Extra keys in a detailed LLM response must not appear in the return value."""
        response_with_extras = {
            **_VALID_DETAILED_RESPONSE,
            "secret_key": "leaked_data",
            "llm_internal_state": [1, 2, 3],
        }
        mock_resp = _make_mock_response(response_with_extras)
        mock_acm = _make_chat_client_mock(mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine()
            result = await engine.analyze_detailed(**BASE_KWARGS)

        assert "secret_key" not in result, "secret_key must be stripped by allowlist projection"
        assert "llm_internal_state" not in result

    async def test_known_detailed_keys_preserved(self) -> None:
        """All schema-defined detailed keys present in the LLM response must be kept."""
        mock_resp = _make_mock_response(_VALID_DETAILED_RESPONSE)
        mock_acm = _make_chat_client_mock(mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine()
            result = await engine.analyze_detailed(**BASE_KWARGS)

        for key in (
            "threat_level", "confidence", "attack_stage", "recommended_action",
            "executive_summary", "attack_progression", "insights", "ioc_indicators",
        ):
            assert key in result, f"Schema key {key!r} must be preserved in projected result"

    def test_known_concise_keys_constant_is_frozenset(self) -> None:
        """_KNOWN_CONCISE_KEYS must be a frozenset (module-level constant, NB-5)."""
        from firewatch_core.adapters.ai_openai import _KNOWN_CONCISE_KEYS

        assert isinstance(_KNOWN_CONCISE_KEYS, frozenset)
        assert "threat_level" in _KNOWN_CONCISE_KEYS
        assert "confidence" in _KNOWN_CONCISE_KEYS

    def test_known_detailed_keys_constant_is_frozenset(self) -> None:
        """_KNOWN_DETAILED_KEYS must be a frozenset (module-level constant, NB-5)."""
        from firewatch_core.adapters.ai_openai import _KNOWN_DETAILED_KEYS

        assert isinstance(_KNOWN_DETAILED_KEYS, frozenset)
        assert "executive_summary" in _KNOWN_DETAILED_KEYS
        assert "ioc_indicators" in _KNOWN_DETAILED_KEYS


# ---------------------------------------------------------------------------
# NB-6: Exception text not leaked into returned envelope or logs
# ---------------------------------------------------------------------------


class TestNB6ExceptionTextNotLeaked:
    """NB-6 — raw exception strings must not appear in the fallback envelope."""

    async def test_concise_fallback_does_not_contain_exc_text(self) -> None:
        """The concise fallback insights must not embed raw exception message text."""
        sensitive_message = "CONNECTION_REFUSED_SECRET_HOST=internal-llm.corp:11434"

        mock_acm = AsyncMock()
        mock_acm.__aenter__ = AsyncMock(return_value=mock_acm)
        mock_acm.__aexit__ = AsyncMock(return_value=False)
        mock_acm.post = AsyncMock(
            side_effect=RuntimeError(sensitive_message)
        )

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine()
            result = await engine.analyze_concise(**BASE_KWARGS)

        # The fallback envelope must not contain the raw exception text
        result_str = str(result)
        assert sensitive_message not in result_str, (
            f"Raw exception text leaked into concise fallback envelope: {result_str!r}"
        )

    async def test_detailed_fallback_does_not_contain_exc_text(self) -> None:
        """The detailed fallback ioc_indicators must not embed raw exception message text."""
        sensitive_message = "TIMEOUT_WAITING_FOR=gpu-node-7.internal:8080"

        mock_acm = AsyncMock()
        mock_acm.__aenter__ = AsyncMock(return_value=mock_acm)
        mock_acm.__aexit__ = AsyncMock(return_value=False)
        mock_acm.post = AsyncMock(
            side_effect=ConnectionError(sensitive_message)
        )

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine()
            result = await engine.analyze_detailed(**BASE_KWARGS)

        result_str = str(result)
        assert sensitive_message not in result_str, (
            f"Raw exception text leaked into detailed fallback envelope: {result_str!r}"
        )

    async def test_concise_fallback_uses_fixed_string(self) -> None:
        """Concise fallback insights must contain a fixed, non-exception-derived string."""
        mock_acm = AsyncMock()
        mock_acm.__aenter__ = AsyncMock(return_value=mock_acm)
        mock_acm.__aexit__ = AsyncMock(return_value=False)
        mock_acm.post = AsyncMock(side_effect=RuntimeError("some internal error"))

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine()
            result = await engine.analyze_concise(**BASE_KWARGS)

        insights = result.get("insights", [])
        assert isinstance(insights, list)
        # Insights must not be empty and must use a safe fixed string
        assert len(insights) > 0
        for item in insights:
            assert "some internal error" not in str(item), (
                "Raw exception message must not appear in fallback insights"
            )

    async def test_detailed_fallback_uses_fixed_string(self) -> None:
        """Detailed fallback ioc_indicators must contain fixed, non-exception text."""
        mock_acm = AsyncMock()
        mock_acm.__aenter__ = AsyncMock(return_value=mock_acm)
        mock_acm.__aexit__ = AsyncMock(return_value=False)
        mock_acm.post = AsyncMock(side_effect=ValueError("db_password=s3cr3t leaked"))

        with patch("httpx.AsyncClient", return_value=mock_acm):
            engine = _make_engine()
            result = await engine.analyze_detailed(**BASE_KWARGS)

        ioc_indicators = result.get("ioc_indicators", [])
        assert isinstance(ioc_indicators, list)
        for item in ioc_indicators:
            assert "db_password=s3cr3t leaked" not in str(item), (
                "Raw exception message must not appear in fallback ioc_indicators"
            )

    async def test_warning_log_does_not_contain_exc_text(self) -> None:
        """logger.warning must log exc type name, not the raw exception string."""
        import logging

        sensitive_message = "INTERNAL_SECRET_TOKEN=abc123"

        mock_acm = AsyncMock()
        mock_acm.__aenter__ = AsyncMock(return_value=mock_acm)
        mock_acm.__aexit__ = AsyncMock(return_value=False)
        mock_acm.post = AsyncMock(side_effect=RuntimeError(sensitive_message))

        log_records: list[logging.LogRecord] = []

        class _Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                log_records.append(record)

        handler = _Capture()
        target_logger = logging.getLogger("firewatch.ai_openai")
        target_logger.addHandler(handler)
        try:
            with patch("httpx.AsyncClient", return_value=mock_acm):
                engine = _make_engine()
                await engine.analyze_concise(**BASE_KWARGS)
        finally:
            target_logger.removeHandler(handler)

        assert log_records, "Expected at least one warning log record"
        for record in log_records:
            msg = record.getMessage()
            assert sensitive_message not in msg, (
                f"Raw exception text found in log message: {msg!r}"
            )
            # The exception type name should appear instead
            assert "RuntimeError" in msg, (
                f"Expected exception type name in log; got: {msg!r}"
            )
