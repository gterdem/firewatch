"""PluginContext — per-instance capability carrier for source collection entrypoints.

Minted by the supervisor (the trusted holder of ``(source_type, source_id)`` per
running instance — ADR-0023) and passed into ``PullSource.collect`` /
``PushSource.start`` as their final required parameter (ADR-0027).

This is the single, forward-compatible channel for per-instance handles (ADR-0025
addendum §3): new capabilities (e.g. a structured logger, a scoped watermark
accessor) ride this carrier as additive fields rather than widening the entrypoint
signatures again.

Design decisions (ADR-0027 §1):
- **Frozen** — a plugin must not mutate its own capability carrier (``frozen=True``
  also makes it hashable and safe to hold across a long-lived ``start()`` listener).
- **``arbitrary_types_allowed=True``** — required because ``kv: ScopedKV`` is a
  runtime-checkable ``Protocol``, not a Pydantic model; Pydantic stores it without
  trying to validate its structure.
- **Minimal field set** — only ``kv`` and ``source_id`` land now; ``logger``/clock
  are deliberately OUT (ADR-0027 §1) to avoid over-committing the contract shape
  before those capabilities are designed.
"""
from __future__ import annotations

from pydantic import BaseModel

from firewatch_sdk.ports import ScopedKV


class PluginContext(BaseModel):
    """Per-instance capabilities handed to a source plugin's collection entrypoint.

    Minted by the supervisor (the trusted holder of ``(source_type, source_id)`` —
    ADR-0023) once per running instance and passed into ``collect()``/``start()``.
    It is the single, forward-compatible channel for per-instance handles
    (ADR-0025 addendum §3): new capabilities ride this carrier instead of widening
    the entrypoint signatures again.

    Fields
    ------
    kv:
        The source-scoped KV view, bound to this plugin's ``type_key`` (ADR-0025).
        This is the ONLY persistence handle a plugin ever receives; a plugin is
        never handed the raw ``EventStore``.  Use ``await ctx.kv.put(ns, k, v)`` /
        ``await ctx.kv.get(ns, k)`` / ``await ctx.kv.get_all(ns)``.
    source_id:
        The user's instance name (ADR-0016).  For labelling/logging ONLY — a plugin
        MUST NOT branch on ``source_id`` for detection (PLUGIN_CONTRACT.md Flag B).
    """

    model_config = {"frozen": True, "arbitrary_types_allowed": True}

    kv: ScopedKV
    source_id: str
