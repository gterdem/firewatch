"""AI baseline runner — execute all scenarios against the configured engine.

Runs each scenario from the canonical fixture registry through the AI engine
and returns a mapping of ``{category: verdict_record}``.  The caller (CLI or
test) owns I/O — the runner is only responsible for the async engine calls.

Design notes
------------
- Reuses the existing ``OpenAIEngine`` adapter as-is — no new prompt construction.
  The engine's ``analyze_concise`` / ``analyze_detailed`` methods build the prompt
  and call the local endpoint, exactly as the pipeline does at runtime.
- Verdict fields captured: ``threat_level``, ``recommended_action``,
  ``attack_stage``, ``confidence`` — the key closed-schema fields that vary
  meaningfully between model versions.  Extra fields returned by the engine are
  included so operators see the full picture.
- ``BaselineRunError`` is raised (not returned) on engine-unavailable or per-call
  exceptions, so the CLI can distinguish "run error" from "drift detected".

ai-engine-invariants boundary
------------------------------
- DOES NOT modify prompts, scoring, sample-building, or engine selection.
- DOES NOT call the engine from tests without mocking (no live-model CI dependency).
- DOES NOT auto-rebaseline — saving is a deliberate human act.
"""
from __future__ import annotations

from typing import Any

from firewatch_core.ai.baseline.fixtures import SCENARIOS

# ---------------------------------------------------------------------------
# Public exception
# ---------------------------------------------------------------------------

_VERDICT_FIELDS = frozenset({
    "threat_level",
    "recommended_action",
    "attack_stage",
    "confidence",
})


class BaselineRunError(RuntimeError):
    """Raised when the engine is unavailable or a scenario call fails.

    Never raised for verdict drift — that is reported as a non-empty drift list
    from ``report.compare_verdicts``.
    """


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def run_all_scenarios(engine: Any) -> dict[str, dict[str, Any]]:
    """Run every scenario in ``SCENARIOS`` through *engine* and return verdicts.

    Parameters
    ----------
    engine:
        An object implementing the AIEngine protocol
        (``is_available``, ``analyze_concise``, ``analyze_detailed``).

    Returns
    -------
    dict[str, dict[str, Any]]
        Mapping of ``{category: verdict_dict}``.  Each verdict contains
        at minimum ``threat_level``, ``recommended_action``, ``attack_stage``,
        ``confidence``, plus any additional fields returned by the engine.

    Raises
    ------
    BaselineRunError
        If the engine is not available, or if any scenario call raises an
        exception (instead of gracefully returning the fallback envelope).
        The caller must not report partial results as a pass.
    """
    available = await engine.is_available()
    if not available:
        raise BaselineRunError(
            "AI engine is unavailable — cannot run baseline scenarios. "
            "Ensure the local inference endpoint is reachable (ADR-0022)."
        )

    results: dict[str, dict[str, Any]] = {}
    for scenario in SCENARIOS:
        category = scenario["category"]
        fmt = scenario["format"]
        kwargs = scenario["kwargs"]
        try:
            if fmt == "concise":
                raw = await engine.analyze_concise(**kwargs)
            else:
                raw = await engine.analyze_detailed(**kwargs)
        except Exception as exc:
            raise BaselineRunError(
                f"Engine call failed for scenario {category!r}: "
                f"{type(exc).__name__} — {exc}"
            ) from exc

        results[category] = _extract_verdict(raw)

    return results


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_verdict(raw: dict[str, Any]) -> dict[str, Any]:
    """Extract verdict fields from a raw engine response.

    Includes all returned keys so operators see the full model output, but
    always ensures the key verdict fields are present (falling back to
    "UNKNOWN" / 0.0 when the engine returned a fallback envelope).
    """
    verdict: dict[str, Any] = dict(raw)

    # Guarantee the key comparison fields are always present
    verdict.setdefault("threat_level", "UNKNOWN")
    verdict.setdefault("recommended_action", "unknown")
    verdict.setdefault("attack_stage", "unknown")
    verdict.setdefault("confidence", 0.0)

    return verdict
