"""Typed in-memory fakes for the SDK ports.

Used across the core tests, and as the pyright oracle that the SDK ports are actually
consumable (`store: EventStore = FakeStore()`, etc.). The real SQLite EventStore is #3.
"""
from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel

from firewatch_sdk import (
    FilterSpec,
    PluginContext,
    RawEvent,
    SecurityEvent,
    SourceMetadata,
)


class FakeStore:
    """In-memory EventStore. Only the methods the pipeline uses do real work; the rest
    satisfy the protocol so `store: EventStore = FakeStore()` type-checks."""

    def __init__(self, events: list[SecurityEvent] | None = None) -> None:
        self._events: list[SecurityEvent] = list(events or [])
        self.watermarks: dict[tuple[str, str], str] = {}
        self.get_watermark_calls: list[tuple[str, str]] = []
        self.set_watermark_calls: list[tuple[str, str, str]] = []
        # source_kv in-memory store: (source_type, namespace, key) → value
        self._kv: dict[tuple[str, str, str], str] = {}

    # lifecycle
    async def init(self) -> None: ...
    async def close(self) -> None: ...

    # write
    async def save_many(self, events: list[SecurityEvent]) -> int:
        self._events.extend(events)
        return len(events)

    # read
    async def get_by_ip(self, ip: str) -> list[SecurityEvent]:
        return [e for e in self._events if e.source_ip == ip]

    async def get_by_ip_raw(self, ip: str) -> list[dict[str, Any]]:
        return [e.model_dump() for e in await self.get_by_ip(ip)]

    async def get_events_with_row_ids(self, ip: str) -> list[dict[str, Any]]:
        """Return events with synthetic row ids for the evidence chain (ADR-0041).

        Row ids are assigned as sequential integers starting from 1 (per ip list
        position) so tests can make deterministic assertions about which ids appear
        in the evidence chain.
        """
        events = [e for e in self._events if e.source_ip == ip]
        rows = []
        for idx, e in enumerate(events, start=1):
            rows.append({
                "id": idx,
                "timestamp": e.timestamp.isoformat(),
                "action": e.action,
                "destination_port": e.destination_port,
                "rule_id": e.rule_id,
                "payload_snippet": e.payload_snippet,
                "source_type": e.source_type,
                "category": e.category,
            })
        return rows

    async def get_recent(self, limit: int) -> list[dict[str, Any]]:
        return [e.model_dump() for e in self._events[-limit:]]

    async def get_paginated(
        self, limit: int, filters: FilterSpec | None = None
    ) -> dict[str, Any]:
        return {"logs": [], "next_cursor": None, "has_more": False, "total_matching": 0}

    # aggregates
    async def get_all_ips(self) -> list[str]:
        return sorted({e.source_ip for e in self._events})

    async def get_ip_summary(self) -> list[dict[str, Any]]:
        return []

    async def get_categories(self) -> list[dict[str, Any]]:
        return []

    async def get_category_summary(self) -> list[dict[str, Any]]:
        return []

    async def get_timeline(
        self, start: str | None, end: str | None
    ) -> list[dict[str, Any]]:
        return []

    async def get_stats(self) -> dict[str, Any]:
        return {}

    # analytics
    async def get_analytics_geo(self) -> list[dict[str, Any]]:
        return []

    async def get_analytics_summary(self) -> dict[str, Any]:
        return {}

    async def get_categories_timeline(
        self, start: str | None, end: str | None
    ) -> list[dict[str, Any]]:
        return []

    # geo
    async def get_ips_without_geo(self) -> list[str]:
        return []

    async def upsert_ip_geo(self, geo_data: list[dict[str, Any]]) -> None: ...

    async def get_ip_geo(self, ip: str) -> dict[str, Any] | None:
        return None

    # watermark — composite (source_type, source_id) key
    async def get_watermark(self, source_type: str, source_id: str) -> str | None:
        self.get_watermark_calls.append((source_type, source_id))
        return self.watermarks.get((source_type, source_id))

    async def set_watermark(
        self, ts: str, source_type: str, source_id: str
    ) -> None:
        self.set_watermark_calls.append((ts, source_type, source_id))
        self.watermarks[(source_type, source_id)] = ts

    # rule descriptions — facade over source_kv, mirroring SQLiteEventStore.
    # Uses INSERT-OR-IGNORE semantics: first-write-wins per rule_id.
    _KV_GLOBAL = "_global"
    _KV_RULE_NS = "rule_descriptions"

    async def upsert_rule_descriptions(self, descs: dict[str, str]) -> None:
        """INSERT-OR-IGNORE: first-seen description wins on duplicate rule_id."""
        for rid, desc in descs.items():
            key = (self._KV_GLOBAL, self._KV_RULE_NS, rid)
            if key not in self._kv:  # first-write-wins
                self._kv[key] = desc

    async def get_rule_descriptions(self) -> dict[str, str]:
        return await self.source_kv_get_all(self._KV_GLOBAL, self._KV_RULE_NS)

    # source_kv — in-memory implementation for tests (ADR-0025 (b)).
    #
    # CORE-PRIVILEGED: these three methods are NOT exposed to plugins.
    # Plugins use the ScopedKV view (firewatch_sdk.ports.ScopedKV).
    # Cap is NOT enforced in the fake; cap behaviour is tested against SQLiteEventStore.
    async def source_kv_put(
        self, source_type: str, namespace: str, key: str, value: str
    ) -> None:
        """CORE-PRIVILEGED — NOT exposed to plugins; plugins use ScopedKV."""
        self._kv[(source_type, namespace, key)] = value

    async def source_kv_get(
        self, source_type: str, namespace: str, key: str
    ) -> str | None:
        """CORE-PRIVILEGED — NOT exposed to plugins; plugins use ScopedKV."""
        return self._kv.get((source_type, namespace, key))

    async def source_kv_get_all(
        self, source_type: str, namespace: str
    ) -> dict[str, str]:
        """CORE-PRIVILEGED — NOT exposed to plugins; plugins use ScopedKV."""
        return {
            k: v
            for (st, ns, k), v in self._kv.items()
            if st == source_type and ns == namespace
        }

    # counterfactual impact (issue #215)
    async def get_ip_counterfactual(self, ip: str) -> dict[str, Any]:
        """Return counterfactual impact counts for *ip* (issue #215).

        Computes over the in-memory events: total, blocked (BLOCK/DROP), unblocked.
        """
        events = [e for e in self._events if e.source_ip == ip]
        total = len(events)
        blocked = sum(1 for e in events if e.action in {"BLOCK", "DROP"})
        return {"total_events": total, "blocked_events": blocked, "unblocked_events": total - blocked}

    # housekeeping
    async def clear(self) -> None:
        self._events.clear()
        self._kv.clear()

    async def delete_older_than(self, days: int) -> int:
        return 0


class FakeAIEngine:
    """Records call counts and returns a scripted concise result."""

    def __init__(self, result: dict[str, Any] | None = None, fail: bool = False) -> None:
        self.result = result if result is not None else {
            "threat_level": "LOW", "confidence": 0.0, "insights": [],
        }
        self.fail = fail
        self.concise_calls = 0
        self.detailed_calls = 0

    async def is_available(self) -> bool:
        return not self.fail

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
        self.concise_calls += 1
        if self.fail:
            raise RuntimeError("AI engine unavailable")
        return self.result

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
        self.detailed_calls += 1
        if self.fail:
            raise RuntimeError("AI engine unavailable")
        return self.result


class _FakeConfig(BaseModel):
    note: str = "fake"


class FakePullPlugin:
    """A SourcePlugin + PullSource emitting a scripted batch of raws."""

    def __init__(
        self, type_key: str = "suricata", raws: list[RawEvent] | None = None
    ) -> None:
        self._type_key = type_key
        self._raws = raws or []
        self.collect_since: str | None | object = "<unset>"

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key=self._type_key,
            display_name=self._type_key,
            version="0.1.0",
            flavor="pull",
        )

    def config_schema(self) -> type[BaseModel]:
        return _FakeConfig

    def validate_config(self, cfg: dict[str, Any]) -> None:
        _FakeConfig.model_validate(cfg)

    def normalize(self, raw: RawEvent, source_id: str) -> SecurityEvent:
        return SecurityEvent(
            source_type=raw.source_type,
            source_id=source_id,
            timestamp=raw.received_at,
            source_ip=str(raw.data.get("src_ip", "0.0.0.0")),
            action="ALERT",
        )

    async def health_check(self, cfg: BaseModel) -> bool:
        return True

    async def collect(
        self, cfg: BaseModel, since: str | None, ctx: PluginContext
    ) -> AsyncIterator[RawEvent]:
        self.collect_since = since
        for raw in self._raws:
            yield raw


def make_event(
    *,
    source_ip: str = "203.0.113.5",
    source_type: str = "suricata",
    source_id: str = "pi-home",
    action: str = "BLOCK",
    timestamp: datetime | None = None,
    destination_port: int | None = None,
    payload_snippet: str | None = None,
    rule_id: str | None = None,
    category: str | None = None,
    event_id: str | None = None,
    severity: str | None = None,
) -> SecurityEvent:
    """Construct a SecurityEvent with sensible defaults for tests.

    ``severity`` (issue #42, ADR-0067 D1b) — additive, default None (undeclared).
    Set to "high"/"critical" on an ALERT event to satisfy the assertion gate
    without needing a correlation-rule detection.
    """
    return SecurityEvent(
        source_type=source_type,
        source_id=source_id,
        source_ip=source_ip,
        action=action,  # type: ignore[arg-type]
        timestamp=timestamp or datetime(2026, 6, 3, 12, 0, 0, tzinfo=timezone.utc),
        destination_port=destination_port,
        payload_snippet=payload_snippet,
        rule_id=rule_id,
        category=category,
        event_id=event_id,
        severity=severity,  # type: ignore[arg-type]
    )


# Unused-name guard so the batch-emit callback type is referenced for pyright parity.
_EmitType = Callable[[list[RawEvent]], Awaitable[None]]
