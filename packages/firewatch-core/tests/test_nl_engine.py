"""Tests for nl_query/engine.py — EARS-1, EARS-2, EARS-5 (end-to-end parse, degrade).

EARS mapping:
  EARS-1: LLM output validated before execution.
  EARS-2: OOV/low-confidence → degrade to q=.
  EARS-5: zero-egress (no real network call in tests; mocked httpx).
"""
from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from firewatch_sdk.models import FilterSpec

from firewatch_core.nl_query.engine import (
    NlQueryResult,
    PROVENANCE_AI,
    PROVENANCE_DEGRADED,
    _extract_json_from_text,
    parse_nl_query,
)
from firewatch_core.nl_query.vocabulary import get_vocabulary


VOCAB = get_vocabulary()


def _make_httpx_response(payload: dict, status: int = 200) -> MagicMock:
    """Build a mock httpx response with a JSON payload."""
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = payload
    resp.raise_for_status = MagicMock()
    if status >= 400:
        resp.raise_for_status.side_effect = Exception(f"HTTP {status}")
    return resp


def _llm_response(filters: dict, confidence: float = 0.9) -> dict:
    """Build a minimal OpenAI-compatible LLM response."""
    content = json.dumps({"confidence": confidence, "filters": filters})
    return {
        "choices": [{"message": {"content": content}}],
    }


class TestExtractJsonFromText:
    """_extract_json_from_text works for qwen3-style wrapped JSON."""

    def test_plain_json(self) -> None:
        """Plain JSON string is extracted correctly."""
        text = '{"confidence": 0.9, "filters": {"action": "BLOCK"}}'
        result = _extract_json_from_text(text)
        assert result is not None
        assert result["confidence"] == 0.9

    def test_json_in_prose(self) -> None:
        """JSON object embedded in prose is found."""
        text = 'Here is my answer: {"confidence": 0.8, "filters": {}} done.'
        result = _extract_json_from_text(text)
        assert result is not None
        assert result["confidence"] == 0.8

    def test_no_json(self) -> None:
        """Text with no JSON object returns None."""
        assert _extract_json_from_text("no JSON here") is None

    def test_malformed_json(self) -> None:
        """Malformed JSON brace returns None."""
        assert _extract_json_from_text("{bad json") is None


@pytest.mark.asyncio
class TestParseNlQuery:
    """parse_nl_query end-to-end (mocked LLM)."""

    async def test_valid_parse_returns_filterspec(self) -> None:
        """Valid LLM response produces a non-degraded FilterSpec."""
        llm_resp = _llm_response({"action": "BLOCK", "severity": "high"})
        mock_resp = _make_httpx_response(llm_resp)

        with patch("firewatch_core.nl_query.engine.httpx") as mock_httpx:
            client = AsyncMock()
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            client.post = AsyncMock(return_value=mock_resp)
            mock_httpx.AsyncClient.return_value = client

            result = await parse_nl_query(
                "show high severity blocked traffic",
                base_url="http://127.0.0.1:11434",
                model="llama3",
                vocab=VOCAB,
            )

        assert isinstance(result, NlQueryResult)
        assert not result.degraded
        assert result.provenance == PROVENANCE_AI
        assert isinstance(result.filter_spec, FilterSpec)
        assert result.filter_spec.action == "BLOCK"
        assert result.filter_spec.severity == "high"

    async def test_low_confidence_degrades_to_q(self) -> None:
        """Low-confidence LLM response → degraded FilterSpec(q=nl_text)."""
        llm_resp = _llm_response({"action": "BLOCK"}, confidence=0.2)
        mock_resp = _make_httpx_response(llm_resp)

        nl = "show me blocked stuff"
        with patch("firewatch_core.nl_query.engine.httpx") as mock_httpx:
            client = AsyncMock()
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            client.post = AsyncMock(return_value=mock_resp)
            mock_httpx.AsyncClient.return_value = client

            result = await parse_nl_query(nl, vocab=VOCAB)

        assert result.degraded
        assert result.provenance == PROVENANCE_DEGRADED
        assert result.filter_spec.q == nl
        assert result.filter_spec.action is None

    async def test_oov_field_degrades_to_q(self) -> None:
        """LLM emitting OOV-only fields → degrade to q=."""
        content = json.dumps({
            "confidence": 0.95,
            "filters": {"fake_column": "val"},
        })
        llm_resp = {"choices": [{"message": {"content": content}}]}
        mock_resp = _make_httpx_response(llm_resp)

        nl = "unknown query"
        with patch("firewatch_core.nl_query.engine.httpx") as mock_httpx:
            client = AsyncMock()
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            client.post = AsyncMock(return_value=mock_resp)
            mock_httpx.AsyncClient.return_value = client

            result = await parse_nl_query(nl, vocab=VOCAB)

        assert result.degraded
        assert result.filter_spec.q == nl

    async def test_network_error_degrades_gracefully(self) -> None:
        """Network failure → degraded, no exception raised (EARS-2)."""
        nl = "show me alerts"
        with patch("firewatch_core.nl_query.engine.httpx") as mock_httpx:
            client = AsyncMock()
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            client.post = AsyncMock(side_effect=Exception("connection refused"))
            mock_httpx.AsyncClient.return_value = client

            result = await parse_nl_query(nl, vocab=VOCAB)

        assert result.degraded
        assert result.provenance == PROVENANCE_DEGRADED
        assert result.filter_spec.q == nl
        assert result.error is not None

    async def test_malformed_json_response_degrades(self) -> None:
        """Malformed JSON content → degrade."""
        mock_resp = _make_httpx_response({
            "choices": [{"message": {"content": "not json at all"}}],
        })

        nl = "something"
        with patch("firewatch_core.nl_query.engine.httpx") as mock_httpx:
            client = AsyncMock()
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            client.post = AsyncMock(return_value=mock_resp)
            mock_httpx.AsyncClient.return_value = client

            result = await parse_nl_query(nl, vocab=VOCAB)

        assert result.degraded
        assert result.filter_spec.q == nl

    async def test_qwen3_json_in_prose_extracted(self) -> None:
        """qwen3-style response wrapping JSON in prose is handled."""
        inner = json.dumps({"confidence": 0.88, "filters": {"severity": "critical"}})
        prose_content = f"<think>Let me parse this...</think> {inner}"
        llm_resp = {"choices": [{"message": {"content": prose_content}}]}
        mock_resp = _make_httpx_response(llm_resp)

        with patch("firewatch_core.nl_query.engine.httpx") as mock_httpx:
            client = AsyncMock()
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            client.post = AsyncMock(return_value=mock_resp)
            mock_httpx.AsyncClient.return_value = client

            result = await parse_nl_query(
                "show critical events", model="qwen3:8b", vocab=VOCAB
            )

        assert not result.degraded
        assert result.filter_spec.severity == "critical"

    async def test_raw_candidate_not_on_result(self) -> None:
        """SHOULD-FIX-2: raw_candidate must NOT be present on the returned dataclass.

        The unvalidated LLM dict is logged at DEBUG level inside engine.py but
        never returned — preventing accidental serialisation by future routes.
        """
        llm_resp = _llm_response({"protocol": "TCP"}, confidence=0.9)
        mock_resp = _make_httpx_response(llm_resp)

        with patch("firewatch_core.nl_query.engine.httpx") as mock_httpx:
            client = AsyncMock()
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            client.post = AsyncMock(return_value=mock_resp)
            mock_httpx.AsyncClient.return_value = client

            result = await parse_nl_query("TCP traffic", vocab=VOCAB)

        assert not hasattr(result, "raw_candidate"), (
            "raw_candidate must not be on NlQueryResult — SHOULD-FIX-2"
        )
        # Validate the parse still worked correctly.
        assert not result.degraded
        assert result.filter_spec.protocol == "TCP"

    async def test_non_local_base_url_degrades_not_calls_out(self) -> None:
        """BLOCKING-1: non-local base_url degrades to q= without making any HTTP call.

        ADR-0022 local-first self-enforcement: parse_nl_query must call
        _validate_local_first before any httpx I/O.  When the guard raises
        LocalFirstViolation, the engine must degrade to q= (fail-closed) and
        must NOT proceed to make any outbound HTTP request.

        Note: Python 3.12 ipaddress classifies RFC 5737 documentation IPs
        (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) as is_private=True,
        so they pass _validate_local_first at the library level.  We mock the
        guard to raise LocalFirstViolation — this tests the engine's fail-closed
        contract without needing a real non-local address.
        """
        from firewatch_core.adapters.ai_openai import LocalFirstViolation

        nl = "show me blocked traffic"
        with (
            patch(
                "firewatch_core.nl_query.engine._validate_local_first",
                side_effect=LocalFirstViolation("non-local host rejected by ADR-0022"),
            ) as mock_guard,
            patch("firewatch_core.nl_query.engine.httpx") as mock_httpx,
        ):
            client = AsyncMock()
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            client.post = AsyncMock()  # must NOT be called
            mock_httpx.AsyncClient.return_value = client

            result = await parse_nl_query(
                nl,
                base_url="http://example-host:11434",
                vocab=VOCAB,
            )

        assert result.degraded, "LocalFirstViolation must produce a degraded result"
        assert result.filter_spec.q == nl
        assert result.error is not None
        assert "ADR-0022" in result.error
        # The guard was called with the base_url.
        mock_guard.assert_called_once_with("http://example-host:11434")
        # Critically: no HTTP call was made after the guard raised.
        mock_httpx.AsyncClient.assert_not_called()

    async def test_response_format_omitted_for_qwen3(self) -> None:
        """qwen3 models must NOT receive response_format in the request body."""
        llm_resp = _llm_response({"action": "ALERT"})
        mock_resp = _make_httpx_response(llm_resp)
        posted_body: dict[str, Any] = {}

        async def capture_post(url: str, **kwargs: Any) -> Any:
            posted_body.update(kwargs.get("json", {}))
            return mock_resp

        with patch("firewatch_core.nl_query.engine.httpx") as mock_httpx:
            client = AsyncMock()
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            client.post = AsyncMock(side_effect=capture_post)
            mock_httpx.AsyncClient.return_value = client

            await parse_nl_query("alerts", model="qwen3:8b", vocab=VOCAB)

        assert "response_format" not in posted_body, (
            "qwen3 must NOT receive response_format — it returns empty {}"
        )

    async def test_response_format_sent_for_standard_model(self) -> None:
        """Non-qwen3 models receive response_format: json_object."""
        llm_resp = _llm_response({"action": "BLOCK"})
        mock_resp = _make_httpx_response(llm_resp)
        posted_body: dict[str, Any] = {}

        async def capture_post(url: str, **kwargs: Any) -> Any:
            posted_body.update(kwargs.get("json", {}))
            return mock_resp

        with patch("firewatch_core.nl_query.engine.httpx") as mock_httpx:
            client = AsyncMock()
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            client.post = AsyncMock(side_effect=capture_post)
            mock_httpx.AsyncClient.return_value = client

            await parse_nl_query("blocked", model="llama3", vocab=VOCAB)

        assert posted_body.get("response_format") == {"type": "json_object"}
