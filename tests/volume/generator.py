"""The volume oracle's seeded generator (ADR-0068 D3).

Pure: ``(manifest, seed) -> list[RawEvent]``. No scoring imports here — this
module's only concern is *expansion*: manifest personas + the recorded
templates in ``tests/golden/fixtures`` (Suricata EVE JSON) and
``packages/sources/syslog/tests`` (the "Failed password"/"Accepted password"
line shape) become RawEvents. ``harness.py`` owns turning those into
SecurityEvents via the REAL normalizers and scoring them.

Every timestamp is derived from the manifest's own ``now`` anchor plus a
declared offset/schedule — never ``datetime.now()`` and never ``random`` at
module scope. The one stateful piece (``random.Random(seed)``) is threaded
through explicitly so two calls with the same ``(manifest, seed)`` produce
byte-identical output (ADR-0068 D2-6 — the determinism invariant the
regeneration test enforces).

IPs are RFC 5737 documentation addresses only (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) — never real/routable (testing-conventions skill).
"""
from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from firewatch_sdk import RawEvent

_FIXTURES_DIR = Path(__file__).parent
_GOLDEN_FIXTURES_DIR = _FIXTURES_DIR.parent / "golden" / "fixtures"
_MANIFESTS_DIR = _FIXTURES_DIR / "manifests"

# Source instance ids — constant per source_type (PLUGIN_CONTRACT.md source_id
# is a caller-supplied label; the normalizer never branches on it, Flag B).
SOURCE_ID_SURICATA = "pi-volume-oracle"
SOURCE_ID_SYSLOG = "auth-volume-oracle"
SOURCE_ID_SYSLOG_CEF = "cef-volume-oracle"

# ---------------------------------------------------------------------------
# RFC 5737 IP pool — deterministic sequential allocation, no collisions.
# ---------------------------------------------------------------------------

_RFC5737_RANGES = ("203.0.113", "198.51.100", "192.0.2")


def _ip_pool() -> list[str]:
    """All usable host addresses (.2-.254) across the three RFC 5737 /24s —
    759 addresses, allocated sequentially in manifest-declaration order so
    the same manifest always assigns the same IP to the same persona slot."""
    return [f"{octets}.{host}" for octets in _RFC5737_RANGES for host in range(2, 255)]


class _IpAllocator:
    """Hands out RFC 5737 IPs one at a time, in a fixed deterministic order."""

    def __init__(self) -> None:
        self._pool = iter(_ip_pool())

    def next(self) -> str:
        try:
            return next(self._pool)
        except StopIteration as exc:  # pragma: no cover - budget guard
            raise RuntimeError(
                "volume oracle IP pool exhausted (759 RFC 5737 addresses) — "
                "shrink the manifest's actor counts"
            ) from exc


# ---------------------------------------------------------------------------
# Recorded templates
# ---------------------------------------------------------------------------


def _load_eve_template(filename: str) -> dict[str, Any]:
    """Load a recorded Suricata EVE JSON template from tests/golden/fixtures."""
    with (_GOLDEN_FIXTURES_DIR / filename).open() as fh:
        data: dict[str, Any] = json.load(fh)
    return data


# ADR-0068 D3: templates are the recorded real logs already in-tree — realism
# anchors to captured traffic, not invented shapes.
_EVE_RECON_TEMPLATE = _load_eve_template("eve_05_recon_alert.json")
_EVE_PORTSCAN_TEMPLATE = _load_eve_template("eve_02_port_scan_block.json")
_EVE_WEBATTACK_TEMPLATE = _load_eve_template("eve_01_web_attack_alert.json")

# packages/sources/syslog/tests/test_plugin.py's recorded line shape.
_SYSLOG_FAILED_PASSWORD = "Failed password for root from {ip} port {port} ssh2"
_SYSLOG_ACCEPTED_PASSWORD = "Accepted password for admin from {ip} port {port} ssh2"


# ---------------------------------------------------------------------------
# Schedule helpers — pure (rng, now, ...) -> list[datetime]
# ---------------------------------------------------------------------------


def schedule_uniform_spread(
    rng: random.Random, now: datetime, count: int, spread: timedelta
) -> list[datetime]:
    """``count`` timestamps drawn uniformly from ``(now - spread, now)``."""
    return sorted(
        now - timedelta(seconds=rng.uniform(0, spread.total_seconds())) for _ in range(count)
    )


def schedule_fixed_interval(
    now: datetime, count: int, interval: timedelta, end_before: timedelta
) -> list[datetime]:
    """``count`` timestamps ``interval`` apart, the last landing at
    ``now - end_before`` (a burst that already happened and stopped)."""
    last = now - end_before
    return [last - interval * (count - 1 - i) for i in range(count)]


def schedule_rate_burst(
    now: datetime, count: int, interval: timedelta, end_before: timedelta = timedelta(0)
) -> list[datetime]:
    """Alias of ``schedule_fixed_interval`` — named separately for callers
    describing a dense attack rate (e.g. 50/min) rather than an ambient burst."""
    return schedule_fixed_interval(now, count, interval, end_before)


def schedule_two_bursts(
    now: datetime,
    burst_size: int,
    gap: timedelta,
    second_end_before: timedelta,
) -> list[datetime]:
    """One ``burst_size``-event simultaneous burst, then a second identical
    burst ``gap`` later, ending ``second_end_before`` before ``now`` —
    the recidivist shape (ADR-0070 D3 recidivism clause)."""
    second_at = now - second_end_before
    first_at = second_at - gap
    return [first_at] * burst_size + [second_at] * burst_size


def schedule_continuous_drip(
    now: datetime,
    initial_burst: int,
    period: timedelta,
    span: timedelta,
    end_before: timedelta = timedelta(0),
) -> list[datetime]:
    """An initial simultaneous burst followed by a periodic drip filling the
    dip between what would otherwise be separate excursions — the moderate
    grinder / endurance shape (ADR-0070 D3 endurance clause,
    ``test_issue_54_attack_in_progress_campaign.py``'s
    ``_continuous_pressure_events`` mirrored here through the real
    normalizer)."""
    start = now - end_before - span
    out = [start] * initial_burst
    t = period
    while t <= span:
        out.append(start + t)
        t += period
    return out


def schedule_paced(now: datetime, count: int, period: timedelta) -> list[datetime]:
    """``count`` timestamps ``period`` apart, ending at ``now`` — a
    sub-theta_press paced actor (ADR-0070 D9's designed INFORM exclusion)."""
    return [now - period * (count - 1 - i) for i in range(count)]


# ---------------------------------------------------------------------------
# Template expansion — one actor's timestamps -> RawEvents
# ---------------------------------------------------------------------------


def suricata_events(
    ip: str,
    timestamps: list[datetime],
    *,
    category: str,
    severity: int,
    template: dict[str, Any] | None = None,
    action: str = "allowed",
    destination_ports: list[int] | None = None,
) -> list[RawEvent]:
    """Expand a recorded Suricata EVE template into RawEvents for one actor.

    ``severity`` is the manifest's declared, classification.config-justified
    integer priority (ADR-0068 fact 1) — never the template's own recorded
    value, which reflects that one archived capture, not the persona being
    modelled.
    """
    base = template if template is not None else _EVE_RECON_TEMPLATE
    out: list[RawEvent] = []
    for i, ts in enumerate(timestamps):
        data = json.loads(json.dumps(base))  # deep copy, no shared mutable state
        data["timestamp"] = ts.isoformat()
        data["src_ip"] = ip
        data["alert"]["category"] = category
        data["alert"]["severity"] = severity
        data["alert"]["action"] = action
        if destination_ports:
            data["dest_port"] = destination_ports[i % len(destination_ports)]
        out.append(RawEvent(source_type="suricata", received_at=ts, data=data))
    return out


def syslog_events(
    ip: str, timestamps: list[datetime], *, line_template: str = _SYSLOG_FAILED_PASSWORD
) -> list[RawEvent]:
    """Expand the recorded "Failed password"/"Accepted password" line shape
    (``packages/sources/syslog/tests/test_plugin.py``) into RawEvents."""
    out: list[RawEvent] = []
    for ts in timestamps:
        line = line_template.format(ip=ip, port=44000 + (hash((ip, ts)) % 1000))
        out.append(RawEvent(
            source_type="syslog",
            received_at=ts,
            data={"line": line, "client_ip": ip},
        ))
    return out


def syslog_cef_allow_event(ip: str, ts: datetime, *, dest_ip: str = "192.0.2.1") -> RawEvent:
    """One CEF firewall-style ALLOW event (``act=permit`` -> ADR-0070 D3's
    ALLOW census: syslog_cef's generic CEF path, ``registry.py``)."""
    line = (
        "CEF:0|Fortinet|FortiGate|6.4.5|9999|connection allowed|3|"
        f"src={ip} dst={dest_ip} spt=51234 dpt=443 proto=TCP act=permit"
    )
    return RawEvent(
        source_type="syslog_cef", received_at=ts, data={"line": line, "client_ip": ip}
    )


# ---------------------------------------------------------------------------
# Generated scenario container
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GeneratedScenario:
    """The output of expanding a manifest: RawEvents plus a name -> IPs index
    so tests can address "the 50/min attacker's actor" without re-deriving
    the IP allocation order."""

    raw_events: list[RawEvent]
    persona_ips: dict[str, list[str]] = field(default_factory=dict)
    now: datetime = field(default_factory=lambda: datetime(1970, 1, 1))


def load_manifest(path: Path | None = None) -> dict[str, Any]:
    manifest_path = path or (_MANIFESTS_DIR / "ambient_night.json")
    with manifest_path.open() as fh:
        data: dict[str, Any] = json.load(fh)
    return data


def _expand_ambient_persona(
    persona: dict[str, Any], rng: random.Random, ips: _IpAllocator, now: datetime
) -> tuple[list[RawEvent], list[str]]:
    kind = persona["kind"]
    actor_count = persona["actor_count"]
    actor_ips: list[str] = []
    events: list[RawEvent] = []

    if kind == "suricata_ambient":
        spread = timedelta(hours=persona["spread_hours"])
        for _ in range(actor_count):
            ip = ips.next()
            actor_ips.append(ip)
            n = rng.randint(persona["min_events"], persona["max_events"])
            ts = schedule_uniform_spread(rng, now, n, spread)
            events += suricata_events(
                ip, ts, category=persona["category"], severity=persona["severity"]
            )
    elif kind == "syslog_ambient":
        spread = timedelta(hours=persona["spread_hours"])
        for _ in range(actor_count):
            ip = ips.next()
            actor_ips.append(ip)
            n = rng.randint(persona["min_events"], persona["max_events"])
            ts = schedule_uniform_spread(rng, now, n, spread)
            events += syslog_events(ip, ts)
    elif kind == "syslog_fixed_interval":
        for _ in range(actor_count):
            ip = ips.next()
            actor_ips.append(ip)
            ts = schedule_fixed_interval(
                now,
                persona["count"],
                timedelta(minutes=persona["interval_minutes"]),
                timedelta(hours=persona["end_before_hours"]),
            )
            events += syslog_events(ip, ts)
    else:  # pragma: no cover - manifest authoring error
        raise ValueError(f"unknown persona kind: {kind!r}")

    return events, actor_ips


def _expand_breach_overlay(
    overlay: dict[str, Any], ips: _IpAllocator, now: datetime
) -> tuple[list[RawEvent], dict[str, list[str]]]:
    events: list[RawEvent] = []
    persona_ips: dict[str, list[str]] = {}

    tier1 = overlay["tier1_actor"]
    ip = ips.next()
    persona_ips[tier1["name"]] = [ip]
    end_before = timedelta(minutes=tier1["end_before_minutes"])
    allow_ts = now - end_before
    corroborating_ts = allow_ts + timedelta(minutes=1)
    events.append(syslog_cef_allow_event(ip, allow_ts))
    events += suricata_events(
        ip, [corroborating_ts], category="Web Application Attack", severity=1,
        template=_EVE_WEBATTACK_TEMPLATE,
    )

    band_high = overlay["band_high_actor"]
    ip = ips.next()
    persona_ips[band_high["name"]] = [ip]
    count = band_high["count"]
    ts = schedule_fixed_interval(
        now, count, timedelta(minutes=5), timedelta(minutes=band_high["end_before_minutes"])
    )
    ports = [21, 22, 23, 25, 80, 443, 3389, 8080, 8443, 9000][:count]
    events += suricata_events(
        ip, ts, category="Detection of a Network Scan", severity=1, action="blocked",
        template=_EVE_PORTSCAN_TEMPLATE, destination_ports=ports,
    )

    return events, persona_ips


def build_ambient_scenario(
    manifest: dict[str, Any], seed: int, *, breach: bool = False
) -> GeneratedScenario:
    """Expand the manifest into a full night of RawEvents.

    ``breach=False`` (default) is the ambient-only variant — pure noise, no
    planted breach (ADR-0068 D2-5, the calm-reachability invariant).
    ``breach=True`` additionally overlays the two anti-suppression personas
    (ADR-0068 D2-3): a Tier-1 ALLOW+detection actor and a band-HIGH
    accumulator, both inside the SAME ambient noise.
    """
    now = datetime.fromisoformat(manifest["now"])
    rng = random.Random(seed)
    ips = _IpAllocator()

    all_events: list[RawEvent] = []
    persona_ips: dict[str, list[str]] = {}
    for persona in manifest["personas"]:
        events, actor_ips = _expand_ambient_persona(persona, rng, ips, now)
        all_events += events
        persona_ips[persona["name"]] = actor_ips

    if breach:
        events, overlay_ips = _expand_breach_overlay(manifest["breach_overlay"], ips, now)
        all_events += events
        persona_ips.update(overlay_ips)

    return GeneratedScenario(raw_events=all_events, persona_ips=persona_ips, now=now)
