"""Port Protocols — the structural interfaces core and plugins depend on.

These are pure `typing.Protocol`s (no implementations). Concrete adapters live in
firewatch-core (EventStore/AIEngine/Notifier/Enricher) and source plugins
(SourcePlugin + a Pull/Push flavor). The SDK never imports any of those.

Sources of truth: PLUGIN_CONTRACT.md (SourcePlugin / Pull / Push) and the legacy port
shapes (EventStore / AIEngine / Notifier / Enricher), reconciled with the accepted ADRs.
"""
from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from pydantic import BaseModel

from firewatch_sdk.metadata import SourceMetadata
from firewatch_sdk.models import FilterSpec, RawEvent, SecurityEvent, ThreatScore

if TYPE_CHECKING:
    from firewatch_sdk.context import PluginContext

# --------------------------------------------------------------------------- #
# Source plugins (PLUGIN_CONTRACT.md)                                          #
# --------------------------------------------------------------------------- #


@runtime_checkable
class SourcePlugin(Protocol):
    """What every source plugin provides, regardless of flavor.

    The plugin OWNS its raw → SecurityEvent mapping and its config schema. It declares a
    constant ``source_type`` via ``metadata().type_key`` and never branches on
    ``source_id`` for detection (ADR-0016).
    """

    def metadata(self) -> SourceMetadata: ...

    def config_schema(self) -> type[BaseModel]:
        """Pydantic model that drives the UI card; resolved env > file > default."""
        ...

    def validate_config(self, cfg: dict[str, Any]) -> None: ...

    def normalize(self, raw: RawEvent, source_id: str) -> SecurityEvent:
        """Map raw → SecurityEvent, setting source_type, source_id, action, etc."""
        ...

    async def health_check(self, cfg: BaseModel) -> bool: ...


@runtime_checkable
class PullSource(Protocol):
    """Watermark-driven flavor (Suricata SSH, Azure WAF) — ADR-0005.

    ``collect`` yields events newer than ``since`` (an ISO-8601 watermark string, or
    None for the initial window). It must be cancellable and must not raise out of its
    loop (PLUGIN_CONTRACT.md hard rules).

    ``ctx`` is a frozen per-instance capability carrier (ADR-0027) that the supervisor
    mints and passes in.  It carries ``ctx.kv`` (the plugin's scoped KV view,
    ADR-0025) and ``ctx.source_id`` (the user's instance name, for logging only).
    The plugin MUST NOT branch on ``ctx.source_id`` for detection (Flag B).
    ``normalize()`` does NOT receive ``ctx`` — it is a pure mapping with no
    capability need (ADR-0027 §2).
    """

    def collect(
        self, cfg: BaseModel, since: str | None, ctx: "PluginContext"
    ) -> AsyncIterator[RawEvent]: ...


@runtime_checkable
class PushSource(Protocol):
    """Listener flavor (Syslog UDP/TCP) — ADR-0005.

    ``emit`` takes a *batch* so listeners coalesce bursts into one call (Flag C).
    ``start`` runs the listener loop; ``stop`` releases the socket at shutdown.

    ``ctx`` is a frozen per-instance capability carrier (ADR-0027) that the supervisor
    mints and passes in.  It carries ``ctx.kv`` (the plugin's scoped KV view,
    ADR-0025) and ``ctx.source_id`` (the user's instance name, for logging only).
    The plugin MUST NOT branch on ``ctx.source_id`` for detection (Flag B).
    ``stop()`` carries no per-instance capability and is unchanged (ADR-0027 §2).
    """

    async def start(
        self,
        cfg: BaseModel,
        emit: Callable[[list[RawEvent]], Awaitable[None]],
        ctx: "PluginContext",
    ) -> None: ...

    async def stop(self) -> None: ...


# --------------------------------------------------------------------------- #
# Core-side ports (implemented by firewatch-core adapters)                     #
# --------------------------------------------------------------------------- #


@runtime_checkable
class ScopedKV(Protocol):
    """A source-scoped KV view bound to a single plugin's ``type_key``.

    Core constructs one instance per plugin instance and closes over the plugin's
    ``source_type`` (taken from ``metadata().type_key`` at wiring time — never from
    plugin call arguments).  The API takes only ``(namespace, key, value)`` — there is
    **no** ``source_type`` parameter — so a plugin structurally cannot name (let alone
    read or clobber) another plugin's rows.

    This is capability-based isolation, not a checked argument (ADR-0025 addendum,
    OWASP A01 / NIST AC-6 / confused-deputy principle).  The plugin receives this view
    via the ``PluginContext`` passed to its collection entrypoint (finalized with the
    supervisor, #22).  A plugin never receives the raw ``EventStore``.

    ``namespace`` is a free argument — a plugin may organize its *own* scope into
    sub-namespaces (e.g. ``"rule_descriptions"``, ``"cursors"``).  ``source_type`` is the
    only thing closed over, because it is the only thing that crosses the tenant boundary.

    There is a per-``(source_type, namespace)`` row cap enforced by core; exceeding it
    raises ``SourceKVCapExceededError``.
    """

    async def put(self, namespace: str, key: str, value: str) -> None:
        """Upsert ``value`` at ``(bound_source_type, namespace, key)``."""
        ...

    async def get(self, namespace: str, key: str) -> str | None:
        """Return the value at ``(bound_source_type, namespace, key)``, or ``None``."""
        ...

    async def get_all(self, namespace: str) -> dict[str, str]:
        """Return all ``{key: value}`` pairs in ``(bound_source_type, namespace)``."""
        ...


@runtime_checkable
class EventStore(Protocol):
    """Persistence + query layer (ADR-0007). SQLite now, PostgreSQL at M6."""

    # lifecycle
    async def init(self) -> None: ...
    async def close(self) -> None: ...

    # write
    async def save_many(self, events: list[SecurityEvent]) -> int:
        """Persist events. Returns count actually inserted (post-dedup)."""
        ...

    # read — single IP (typed for pipeline use)
    async def get_by_ip(self, ip: str) -> list[SecurityEvent]: ...

    # read — single IP (raw rows, for dashboard drill-down)
    async def get_by_ip_raw(self, ip: str) -> list[dict[str, Any]]: ...

    # read — recent rows (raw, for dashboard "recent logs" tab)
    async def get_recent(self, limit: int) -> list[dict[str, Any]]: ...

    # read — pagination. Returns {logs, next_cursor, has_more, total_matching}.
    async def get_paginated(
        self, limit: int, filters: FilterSpec | None = None
    ) -> dict[str, Any]: ...

    # aggregates
    async def get_all_ips(self) -> list[str]: ...
    async def get_ip_summary(self) -> list[dict[str, Any]]: ...
    async def get_categories(self) -> list[dict[str, Any]]: ...
    async def get_category_summary(self) -> list[dict[str, Any]]:
        """Unique category names with counts for the filter dropdown.

        Returns ``[{"category": str, "count": int}, …]``.
        Added in MB.1 (issue #53) to back the Network Logs category filter.
        """
        ...

    async def get_timeline(
        self, start: str | None, end: str | None
    ) -> list[dict[str, Any]]: ...
    async def get_stats(self) -> dict[str, Any]: ...

    # analytics
    async def get_analytics_geo(self) -> list[dict[str, Any]]: ...
    async def get_analytics_summary(self) -> dict[str, Any]: ...
    async def get_categories_timeline(
        self, start: str | None, end: str | None
    ) -> list[dict[str, Any]]: ...

    # geo (used by the enrich/sync flow; lives in the EventStore — ADR-0007)
    async def get_ips_without_geo(self) -> list[str]: ...
    async def upsert_ip_geo(self, geo_data: list[dict[str, Any]]) -> None: ...
    async def get_ip_geo(self, ip: str) -> dict[str, Any] | None:
        """Return the cached geo row for *ip*, or ``None`` when absent.

        Columns: ``country`` (str), ``city`` (str), ``lat`` (float), ``lon`` (float).
        Added in issue #132 to populate ``ThreatScore.location`` and the
        ``location`` field in the detailed DTO.
        """
        ...

    # watermark — keyed per (source_type, source_id) composite instance (ADR-0007/0016).
    async def get_watermark(self, source_type: str, source_id: str) -> str | None: ...
    async def set_watermark(
        self, ts: str, source_type: str, source_id: str
    ) -> None: ...

    # rule descriptions (ergonomic facade over source_kv; kept for API stability)
    async def upsert_rule_descriptions(self, descs: dict[str, str]) -> None: ...
    async def get_rule_descriptions(self) -> dict[str, str]: ...

    # source-scoped key/value auxiliary state (ADR-0025, section (b)).
    #
    # CORE-PRIVILEGED — these three methods are NOT exposed to plugins.
    # Plugins use the ``ScopedKV`` view (also in this module) which closes over
    # a fixed ``source_type`` so a plugin structurally cannot name another
    # tenant's scope (capability-based isolation; ADR-0025 addendum,
    # OWASP A01 / NIST AC-6).
    #
    # ``source_type`` is the enforced tenant boundary and is INJECTED BY CORE
    # from ``metadata().type_key`` at wiring time — never from plugin call
    # arguments.  One backing row per ``(source_type, namespace, key)``; value
    # is a text/JSON blob.  A per-``(source_type, namespace)`` row cap prevents
    # runaway plugins from bloating the DB (see ``SQLiteEventStore.SOURCE_KV_CAP``).
    async def source_kv_put(
        self, source_type: str, namespace: str, key: str, value: str
    ) -> None:
        """Upsert a key/value pair scoped to ``(source_type, namespace)``.

        **CORE-PRIVILEGED — NOT exposed to plugins; plugins use** ``ScopedKV``.
        ``source_type`` is core-injected from ``metadata().type_key``, never
        plugin input.

        Raises ``SourceKVCapExceededError`` (from firewatch_core) if the
        per-``(source_type, namespace)`` row cap would be exceeded by a *new*
        key.  Updating an existing key never triggers the cap check.
        """
        ...

    async def source_kv_get(
        self, source_type: str, namespace: str, key: str
    ) -> str | None:
        """Return the value for ``(source_type, namespace, key)``, or ``None``.

        **CORE-PRIVILEGED — NOT exposed to plugins; plugins use** ``ScopedKV``.
        ``source_type`` is core-injected from ``metadata().type_key``, never
        plugin input.
        """
        ...

    async def source_kv_get_all(
        self, source_type: str, namespace: str
    ) -> dict[str, str]:
        """Return all ``{key: value}`` pairs in ``(source_type, namespace)``.

        **CORE-PRIVILEGED — NOT exposed to plugins; plugins use** ``ScopedKV``.
        ``source_type`` is core-injected from ``metadata().type_key``, never
        plugin input.
        """
        ...

    # counterfactual impact query (issue #215)
    async def get_ip_counterfactual(self, ip: str) -> dict[str, Any]:
        """Return ``{total_events, blocked_events, unblocked_events}`` for *ip*.

        ``unblocked_events`` = total_events − blocked_events: the count of
        events that were NOT blocked (ALLOW/ALERT/LOG actions) — i.e. what a
        block would have stopped.  Returns all-zero dict when IP is unknown.
        """
        ...

    # housekeeping
    async def clear(self) -> None: ...

    # raw-log retention. Returns rows deleted. Tiered hot/cold is M6.
    async def delete_older_than(self, days: int) -> int: ...


@runtime_checkable
class AIEngine(Protocol):
    """Local LLM threat analysis via an OpenAI-compatible endpoint (ADR-0004/0022).

    Returns the LLM JSON envelope as ``dict``. Signatures mirror v1 so prompts stay
    stable.

    Return contract — two distinct shapes, discriminated by ``ai_status``:

    * **Success** (``ai_status == "ok"``): the dict satisfies the closed
      concise/detailed schema — enum ``threat_level`` in
      {CRITICAL, HIGH, MEDIUM, LOW}, ``attack_stage``, ``recommended_action``,
      ``confidence`` in [0, 1].
    * **Fallback / graceful degradation** (``ai_status == "unavailable"``):
      ``threat_level == "UNKNOWN"`` — deliberately OUTSIDE the closed schema, to
      signal "no AI verdict; fall back to rules-only". The engine NEVER raises to
      the pipeline on endpoint failure, timeout, or malformed response.

    Consumer rule: callers MUST branch on ``ai_status`` BEFORE schema-validating.
    Validating a fallback envelope against the concise/detailed schema will
    (correctly) fail — that divergence is the signal, not an error. Per ADR-0015
    the AI verdict may only ADD to the deterministic score, never lower it, so an
    "unavailable" verdict is a no-op.
    """

    async def is_available(self) -> bool: ...

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
    ) -> dict[str, Any]: ...

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
    ) -> dict[str, Any]: ...


@runtime_checkable
class Notifier(Protocol):
    """Outbound alerts (webhook; Discord/Slack auto-detect)."""

    async def send_alert(self, threat: ThreatScore) -> bool:
        """Unconditionally send the alert. Returns True on success."""
        ...

    async def check_and_alert(self, threat: ThreatScore) -> bool:
        """Send only if the threat meets the configured threshold."""
        ...

    async def send_sync_digest(
        self,
        total_new: int,
        blocked_new: int,
        ip_blocks: list[dict[str, Any]],
        categories: dict[str, int],
    ) -> bool:
        """Send a roll-up digest after a sync run."""
        ...


@runtime_checkable
class Enricher(Protocol):
    """Adds context to events (geo, threat intel, DNS, …). Composed sequentially."""

    name: str

    async def enrich(self, events: list[SecurityEvent]) -> list[SecurityEvent]:
        """Return events with added context. May mutate or return new instances."""
        ...
