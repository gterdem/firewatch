"""The ONE stamping authority for ``ai_status`` (ADR-0066, issues #39/#40).

Both pipeline paths (``analyze_ip`` concise, ``analyze_ip_detailed``) call
``resolve_ai_status`` to compute the single closed-vocabulary value that is
written to every analysis payload. This replaces the two divergent stamping
sites that previously existed in ``pipeline.py`` — one dialect per path,
each with its own honesty bugs (ADR-0066 context, defects 1-3).

Vocabulary (``firewatch_sdk.AIStatusLiteral`` — exactly these five values):

======================  =========================================  ============
value                   meaning                                    kind
======================  =========================================  ============
``"active"``            the AI engine analyzed this and verdicted  success
``"disabled"``          AI is off in config; rules scored this      choice (operator)
``"skipped"``           this request asked for rules-only           choice (caller)
``"no_input"``          nothing to send to the AI; rules scored     non-event
``"unavailable"``       AI was wanted but unreachable/errored        fault
======================  =========================================  ============

Truth table (ADR-0066 — evaluated top to bottom; the first match wins):

1. ``caller_opted_out``                      -> ``"skipped"``
2. ``admin_disabled``                        -> ``"disabled"``
3. ``not engine_available``                  -> ``"unavailable"``
4. ``not had_input``                         -> ``"no_input"``
5. engine ran but its envelope signals a
   fallback (``engine_result is None`` or
   ``engine_result["ai_status"] == "unavailable"``) -> ``"unavailable"``
6. otherwise                                 -> ``"active"``

Row 5 is where the ``AIEngine`` port's internal ``ok``/``unavailable``
envelope discriminator (``firewatch_sdk.ports.AIEngine`` docstring) is mapped
to the wire vocabulary and never reaches a client verbatim — a raw ``"ok"``
(or an absent key, which is what a real LLM response usually carries — the
schema does not require the engine to self-report) is treated exactly the
same as any other non-``"unavailable"`` envelope: the pipeline authored
``"active"`` itself.

Callers are responsible for gating expensive work (building samples, calling
the engine) on ``engine_available`` / ``had_input`` themselves — this module
is a pure decision function with no I/O and no side effects, so it is trivial
to exhaustively unit test (see ``test_ai_status.py``).
"""
from __future__ import annotations

from typing import Any

from firewatch_sdk import AIStatusLiteral

__all__ = ["resolve_ai_status"]


def resolve_ai_status(
    *,
    caller_opted_out: bool,
    admin_disabled: bool,
    engine_available: bool,
    had_input: bool,
    engine_result: dict[str, Any] | None,
) -> AIStatusLiteral:
    """Return the single closed-vocabulary ``ai_status`` for one analysis.

    Parameters
    ----------
    caller_opted_out:
        ``True`` when THIS call explicitly asked for rules-only (``use_ai=False``
        / ``include_ai=False``/``ai=false``) — a per-request caller choice.
        Takes precedence over every other input (ADR-0066): a caller who did
        not even ask never learns whether the engine would have been reachable.
    admin_disabled:
        ``True`` when the wired engine self-reports administrative disablement
        (``ai_enabled=false`` at the config layer) — an operator-level choice,
        distinct from a caller opting out of one request.
    engine_available:
        ``True`` when the engine was reachable for this call (i.e. the pipeline
        actually attempted or would have attempted to reach it — callers
        typically derive this from ``AIEngine.is_available()``).
    had_input:
        ``True`` when there was at least one sample to send to the engine.
        Only consulted once ``engine_available`` is ``True`` — no meaning
        otherwise (rows 1-3 above already short-circuit).
    engine_result:
        The validated/projected dict returned by the engine call, or ``None``
        when the call was never attempted, raised, or the engine returned its
        own fallback envelope (``ai_status == "unavailable"`` — the AIEngine
        port's internal discriminator, ``firewatch_sdk.ports.AIEngine``).
        Only consulted once ``had_input`` is ``True``.

    Returns
    -------
    AIStatusLiteral
        Exactly one of ``"active"``, ``"disabled"``, ``"skipped"``,
        ``"no_input"``, ``"unavailable"``.
    """
    if caller_opted_out:
        return "skipped"
    if admin_disabled:
        return "disabled"
    if not engine_available:
        return "unavailable"
    if not had_input:
        return "no_input"
    if engine_result is None or engine_result.get("ai_status") == "unavailable":
        return "unavailable"
    return "active"
