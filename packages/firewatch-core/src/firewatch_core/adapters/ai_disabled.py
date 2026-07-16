"""DisabledAIEngine — the rules-only AI engine stub (ADR-0022 #54; ADR-0066 #39/#40).

Relocated from ``firewatch_cli.commands._pipeline_factory._DisabledAIEngine`` to
``firewatch_core`` (issue #39 module sketch): a core-owned adapter is the correct
home since ``firewatch-cli`` is a consumer, not the owner, of the AI engine
contract (CLI importing core is allowed; core never imports a CLI/plugin).

Used in TWO distinct situations, distinguished by the ``fault`` constructor flag
(ADR-0066 — "off is a choice, unreachable is a fault; keep them distinct"):

- ``fault=False`` (default) — ``ai_enabled=false``: an OPERATOR CHOICE.  The
  engine self-reports administrative disablement via the additive
  ``administratively_disabled`` attribute (read with ``getattr`` by the
  pipeline's stamping authority, ``firewatch_core.ai_status``) so every
  analysis surface stamps ``ai_status="disabled"`` — never a fault label.
- ``fault=True`` — ``ai_enabled=true`` but constructing the real ``OpenAIEngine``
  failed (e.g. a misconfigured ``ollama_base_url``, issue #40 AC4).  This is a
  FAULT, not a choice: ``administratively_disabled`` stays ``False`` so the
  stamping authority falls through to the ordinary
  engine-unreachable path (``is_available()`` is unconditionally ``False`` on
  this stub either way) and stamps ``ai_status="unavailable"``.

Neither mode ever contacts an inference endpoint — both are fully inert.
"""
from __future__ import annotations

from typing import Any

__all__ = ["DisabledAIEngine"]


class DisabledAIEngine:
    """Rules-only AI engine stub. Never contacts an inference endpoint.

    See module docstring for the ``fault`` distinction (ADR-0066).
    """

    def __init__(self, *, fault: bool = False) -> None:
        # Additive optional attribute (mirrors the analyze_concise_with_meta
        # detection pattern already used elsewhere in the pipeline): read via
        # getattr, defaults to False for any engine that does not set it
        # (OpenAIEngine, third-party adapters).
        self.administratively_disabled: bool = not fault
        self._envelope_status: str = "unavailable" if fault else "disabled"

    async def is_available(self) -> bool:
        return False

    async def analyze_concise(  # noqa: PLR0913
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
        return {"ai_status": self._envelope_status, "threat_level": "UNKNOWN"}

    async def analyze_detailed(  # noqa: PLR0913
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
        return {"ai_status": self._envelope_status, "threat_level": "UNKNOWN"}
