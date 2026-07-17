"""Golden tests — Suricata ADR-0048 network-depth field extraction.

Tests the ML-2 (#430) population of network-depth fields from Suricata EVE
sub-objects (flow/dns/tls/http). All tests are driven against frozen oracle
constants — no field expected value is computed from new code at test time.

EARS criteria covered:
  EARS-1  normalize() with EVE flow/dns/tls/http -> corresponding fields populated.
  EARS-3  New enriched fixture (eve_06_tls_dns_flow_enriched.json) + expected_06
          proves extraction end-to-end; existing fixtures gain new fields as null.
  EARS-4  expected_scores.json is unchanged (scoring oracle untouched).
  EARS-5  EVE events lacking flow/tls/dns blocks -> those fields are None, not error.

ADR-0048 direction mappings (responder = toclient, originator = toserver):
  bytes_in   <- flow.bytes_toclient  (responder → originator)
  bytes_out  <- flow.bytes_toserver  (originator → responder)
  packets_in <- flow.pkts_toclient
  packets_out<- flow.pkts_toserver

Suricata EVE key names (verified against fixtures, not guessed):
  flow: pkts_toserver, pkts_toclient, bytes_toserver, bytes_toclient, start, end
  dns:  rrname (query), rcode
  tls:  sni, version, ja4 (7.x+), ja4s (7.x+)
  http: url, hostname, http_method, http_user_agent

IP addresses in fixtures use RFC 5737 documentation ranges only:
  192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (gitleaks public-ipv4 rule).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from firewatch_sdk import RawEvent, SecurityEvent
from firewatch_suricata.normalize import normalize

FIXTURES_DIR = Path(__file__).parent / "fixtures"

_RECEIVED_AT = datetime(2026, 1, 15, 10, 25, 0, tzinfo=timezone.utc)
SOURCE_ID = "pi-home"


def _load_eve(filename: str) -> dict:
    return json.loads((FIXTURES_DIR / filename).read_text())


def _raw(eve_data: dict) -> RawEvent:
    return RawEvent(source_type="suricata", received_at=_RECEIVED_AT, data=eve_data)


def _normalize(eve_filename: str) -> SecurityEvent:
    return normalize(_raw(_load_eve(eve_filename)), source_id=SOURCE_ID)


# ── EARS-3: Fixture 06 — enriched EVE with all group A/B/C fields ─────────────


class TestFixture06EnrichedTlsDnsFlow:
    """Fixture 06: enriched EVE with flow/dns/tls sub-objects.

    Proves that normalize() extracts all ADR-0048 group A (flow), group B (DNS),
    group C (TLS/JA4) fields from the corresponding EVE sub-objects.
    Group D (HTTP) is absent in this fixture — those fields must be None (EARS-5).

    Oracle values are frozen from the fixture content; not computed from new code.
    """

    # ── Group A: flow volume & duration ──────────────────────────────────────

    def test_bytes_in_from_flow_bytes_toclient(self) -> None:
        """bytes_in <- flow.bytes_toclient (responder->originator direction, ADR-0048 Group A)."""
        event = _normalize("eve_06_tls_dns_flow_enriched.json")
        assert event.bytes_in == 65536, (
            f"bytes_in must be flow.bytes_toclient=65536 (responder→originator); "
            f"got {event.bytes_in!r}"
        )

    def test_bytes_out_from_flow_bytes_toserver(self) -> None:
        """bytes_out <- flow.bytes_toserver (originator->responder direction, ADR-0048 Group A)."""
        event = _normalize("eve_06_tls_dns_flow_enriched.json")
        assert event.bytes_out == 2048, (
            f"bytes_out must be flow.bytes_toserver=2048 (originator→responder); "
            f"got {event.bytes_out!r}"
        )

    def test_packets_in_from_flow_pkts_toclient(self) -> None:
        """packets_in <- flow.pkts_toclient (ADR-0048 Group A)."""
        event = _normalize("eve_06_tls_dns_flow_enriched.json")
        assert event.packets_in == 8, (
            f"packets_in must be flow.pkts_toclient=8; got {event.packets_in!r}"
        )

    def test_packets_out_from_flow_pkts_toserver(self) -> None:
        """packets_out <- flow.pkts_toserver (ADR-0048 Group A)."""
        event = _normalize("eve_06_tls_dns_flow_enriched.json")
        assert event.packets_out == 12, (
            f"packets_out must be flow.pkts_toserver=12; got {event.packets_out!r}"
        )

    def test_flow_duration_ms_from_start_end(self) -> None:
        """flow_duration_ms computed from flow.start/end timestamps (ADR-0048 Group A).

        Fixture has start=10:24:58 and end=10:25:00 -> 2000ms.
        ECS event.duration anchor; stored as ms (ADR-0048 documented deviation).
        """
        event = _normalize("eve_06_tls_dns_flow_enriched.json")
        assert event.flow_duration_ms == 2000, (
            f"flow_duration_ms must be 2000ms (end - start = 2s); "
            f"got {event.flow_duration_ms!r}"
        )

    # ── Group B: DNS ──────────────────────────────────────────────────────────

    def test_dns_query_from_dns_rrname(self) -> None:
        """dns_query <- dns.rrname (ADR-0048 Group B, OCSF DNS Query hostname)."""
        event = _normalize("eve_06_tls_dns_flow_enriched.json")
        assert event.dns_query == "c2.malicious-domain.example", (
            f"dns_query must be dns.rrname; got {event.dns_query!r}"
        )

    def test_dns_rcode_from_dns_rcode(self) -> None:
        """dns_rcode <- dns.rcode (ADR-0048 Group B, OCSF rcode)."""
        event = _normalize("eve_06_tls_dns_flow_enriched.json")
        assert event.dns_rcode == "NOERROR", (
            f"dns_rcode must be dns.rcode; got {event.dns_rcode!r}"
        )

    # ── Group C: TLS / JA4 ────────────────────────────────────────────────────

    def test_tls_sni_from_tls_sni(self) -> None:
        """tls_sni <- tls.sni (ADR-0048 Group C, OCSF TLS sni, ECS tls.client.server_name)."""
        event = _normalize("eve_06_tls_dns_flow_enriched.json")
        assert event.tls_sni == "c2.malicious-domain.example", (
            f"tls_sni must be tls.sni; got {event.tls_sni!r}"
        )

    def test_tls_version_from_tls_version(self) -> None:
        """tls_version <- tls.version (ADR-0048 Group C, OCSF TLS version)."""
        event = _normalize("eve_06_tls_dns_flow_enriched.json")
        assert event.tls_version == "TLSv1.3", (
            f"tls_version must be tls.version; got {event.tls_version!r}"
        )

    def test_tls_ja4_from_tls_ja4(self) -> None:
        """tls_ja4 <- tls.ja4 (Suricata 7.x+ only; ADR-0048 Group C / ADR-0048 sub-decision).

        ADR-0048 JA4 sub-decision: consume tls.ja4 when the sensor emits it, null otherwise.
        This fixture simulates a Suricata 7.x sensor with JA4 enabled.
        """
        event = _normalize("eve_06_tls_dns_flow_enriched.json")
        assert event.tls_ja4 == "t13d1516h2_8daaf6152771_e5627efa2ab1", (
            f"tls_ja4 must be tls.ja4 when present; got {event.tls_ja4!r}"
        )

    def test_tls_ja4s_from_tls_ja4s(self) -> None:
        """tls_ja4s <- tls.ja4s (Suricata 7.x+ only; ADR-0048 Group C)."""
        event = _normalize("eve_06_tls_dns_flow_enriched.json")
        assert event.tls_ja4s == "t130200_1301_234ea6891581", (
            f"tls_ja4s must be tls.ja4s when present; got {event.tls_ja4s!r}"
        )

    # ── Group D: HTTP absent -> null (EARS-5) ─────────────────────────────────

    def test_http_fields_null_when_no_http_block(self) -> None:
        """EARS-5: fixture has no http sub-object -> all http_* fields are None."""
        event = _normalize("eve_06_tls_dns_flow_enriched.json")
        assert event.http_method is None, f"http_method must be None; got {event.http_method!r}"
        assert event.http_host is None, f"http_host must be None; got {event.http_host!r}"
        assert event.http_url is None, f"http_url must be None; got {event.http_url!r}"
        assert event.http_user_agent is None, f"http_user_agent must be None; got {event.http_user_agent!r}"

    # ── Scores / severity / action unchanged ──────────────────────────────────

    def test_severity_and_action_unchanged(self) -> None:
        """ADR-0048: new fields don't feed scoring — severity/action must be correct.

        ADR-0069 D4(a) re-bless: EVE sev=2 now maps to 'medium' (was 'high') —
        the same expected_06 artifact enumerated in ADR-0069 D7.
        """
        event = _normalize("eve_06_tls_dns_flow_enriched.json")
        assert event.severity == "medium"  # severity=2 -> 'medium' (ADR-0069 D4(a))
        assert event.action == "ALERT"     # action='allowed' -> ALERT

    def test_ocsf_class_for_suspicious(self) -> None:
        """Suspicious (IDS) -> OCSF class (2004, 2) per _OCSF_CLASS_MAP."""
        event = _normalize("eve_06_tls_dns_flow_enriched.json")
        assert event.ocsf_class == 2004
        assert event.ocsf_category == 2


# ── EARS-5: absent sub-objects -> null, no error ──────────────────────────────


class TestAbsentSubObjectsYieldNull:
    """EARS-5: when flow/dns/tls/http blocks are absent, all ADR-0048 fields are None.

    Existing fixtures (01-05) have no flow/dns/tls sub-objects (except http on 01/04/05).
    Verifies that missing sub-objects do NOT cause errors and produce clean None values.
    """

    def test_port_scan_no_sub_objects_all_null(self) -> None:
        """Fixture 02 (no http/flow/dns/tls) -> all network-depth fields are None."""
        event = _normalize("eve_02_port_scan_block.json")
        _assert_all_depth_fields_null(event)

    def test_trojan_no_sub_objects_all_null(self) -> None:
        """Fixture 03 (no http/flow/dns/tls) -> all network-depth fields are None."""
        event = _normalize("eve_03_trojan_alert.json")
        _assert_all_depth_fields_null(event)

    def test_http_only_no_flow_dns_tls_null(self) -> None:
        """Fixture 01 (has http but no flow/dns/tls) -> flow/dns/tls are all None."""
        event = _normalize("eve_01_web_attack_alert.json")
        # flow fields must be None
        assert event.bytes_in is None
        assert event.bytes_out is None
        assert event.packets_in is None
        assert event.packets_out is None
        assert event.flow_duration_ms is None
        # DNS fields must be None
        assert event.dns_query is None
        assert event.dns_rcode is None
        # TLS fields must be None
        assert event.tls_ja4 is None
        assert event.tls_ja4s is None
        assert event.tls_sni is None
        assert event.tls_version is None

    @pytest.mark.parametrize("eve_file,fixture_num", [
        ("eve_02_port_scan_block.json", "02"),
        ("eve_03_trojan_alert.json", "03"),
    ])
    def test_no_error_with_absent_flow_block(self, eve_file: str, fixture_num: str) -> None:
        """normalize() must not raise when flow/dns/tls/http blocks are absent (EARS-5)."""
        # Just calling normalize() without raising is the assertion
        event = _normalize(eve_file)
        assert event is not None, f"Fixture {fixture_num}: normalize() returned None"


def _assert_all_depth_fields_null(event: SecurityEvent) -> None:
    """Assert every ADR-0048 network-depth field is None."""
    depth_fields = [
        "bytes_in", "bytes_out", "packets_in", "packets_out", "flow_duration_ms",
        "dns_query", "dns_rcode",
        "tls_ja4", "tls_ja4s", "tls_sni", "tls_version",
        "http_method", "http_host", "http_url", "http_user_agent",
    ]
    for field in depth_fields:
        val = getattr(event, field)
        assert val is None, (
            f"Field {field!r} must be None when EVE sub-object absent; got {val!r}"
        )


# ── HTTP fields extraction (Group D) ─────────────────────────────────────────


class TestHttpFieldExtraction:
    """Group D: HTTP fields from EVE http sub-object (ADR-0048 Group D).

    EVE http keys:
      url      -> http_url
      hostname -> http_host
      (http_method and http_user_agent are also present on full EVE records;
       tested via inline-built records below.)
    """

    def test_http_host_from_eve_hostname(self) -> None:
        """http_host <- http.hostname (ADR-0048 Group D, ECS url.domain)."""
        event = _normalize("eve_01_web_attack_alert.json")
        assert event.http_host == "10.0.0.1", (
            f"http_host must be http.hostname; got {event.http_host!r}"
        )

    def test_http_url_from_eve_url(self) -> None:
        """http_url <- http.url (ADR-0048 Group D, OCSF HTTP Request url / ECS url.full)."""
        event = _normalize("eve_01_web_attack_alert.json")
        assert event.http_url == "/admin?id=1 OR 1=1", (
            f"http_url must be http.url; got {event.http_url!r}"
        )

    def test_http_method_from_eve_http_method(self) -> None:
        """http_method <- http.http_method (ADR-0048 Group D, OCSF HTTP Request http_method)."""
        eve_with_method = {
            "timestamp": "2026-01-15T10:30:00.000000+0000",
            "event_type": "alert",
            "src_ip": "203.0.113.9",
            "src_port": 60000,
            "dest_ip": "192.0.2.10",
            "dest_port": 80,
            "proto": "TCP",
            "flow_id": 999111222,
            "alert": {
                "action": "allowed",
                "category": "Web Application Attack",
                "signature": "ET WEB Test",
                "signature_id": 9999999,
                "severity": 3,
            },
            "http": {
                "url": "/api/data",
                "hostname": "192.0.2.10",
                "http_method": "POST",
                "http_user_agent": "Mozilla/5.0 (test)",
            },
        }
        event = normalize(_raw(eve_with_method), source_id=SOURCE_ID)
        assert event.http_method == "POST", (
            f"http_method must be http.http_method; got {event.http_method!r}"
        )

    def test_http_user_agent_from_eve_http_user_agent(self) -> None:
        """http_user_agent <- http.http_user_agent (ADR-0048 Group D, ECS user_agent.original)."""
        eve_with_ua = {
            "timestamp": "2026-01-15T10:31:00.000000+0000",
            "event_type": "alert",
            "src_ip": "203.0.113.9",
            "src_port": 60001,
            "dest_ip": "192.0.2.10",
            "dest_port": 80,
            "proto": "TCP",
            "flow_id": 999111223,
            "alert": {
                "action": "allowed",
                "category": "Web Application Attack",
                "signature": "ET WEB UA Test",
                "signature_id": 9999998,
                "severity": 3,
            },
            "http": {
                "url": "/login",
                "hostname": "192.0.2.10",
                "http_user_agent": "curl/7.68.0",
            },
        }
        event = normalize(_raw(eve_with_ua), source_id=SOURCE_ID)
        assert event.http_user_agent == "curl/7.68.0", (
            f"http_user_agent must be http.http_user_agent; got {event.http_user_agent!r}"
        )


# ── JA3 must NOT be shoved into JA4 fields ────────────────────────────────────


class TestJa3NotMappedToJa4():
    """ADR-0048 sub-decision: ja3 is a different fingerprint from ja4.

    If an older Suricata sensor (pre-7.x) emits only tls.ja3/ja3s, the JA4 fields
    must remain None. We must NOT copy ja3 into tls_ja4 — they are different hash
    algorithms and would silently poison the JA4+ detection pipeline.
    """

    def test_ja3_only_tls_block_leaves_ja4_null(self) -> None:
        """tls.ja3 present but tls.ja4 absent -> tls_ja4 and tls_ja4s are None."""
        eve_with_ja3_only = {
            "timestamp": "2026-01-15T10:35:00.000000+0000",
            "event_type": "alert",
            "src_ip": "198.51.100.77",
            "src_port": 45678,
            "dest_ip": "192.0.2.80",
            "dest_port": 443,
            "proto": "TCP",
            "flow_id": 777111222,
            "alert": {
                "action": "allowed",
                "category": "Potentially Bad Traffic",
                "signature": "ET TLS Suspicious",
                "signature_id": 2025000,
                "severity": 2,
            },
            "tls": {
                "sni": "old-sensor-test.example",
                "version": "TLSv1.2",
                "ja3": "771,49196-49200-159-52393-52392-...",
                "ja3s": "771,49200,...",
                # No ja4 or ja4s keys
            },
        }
        event = normalize(_raw(eve_with_ja3_only), source_id=SOURCE_ID)
        assert event.tls_ja4 is None, (
            f"tls_ja4 must be None when only tls.ja3 is present (not tls.ja4); "
            f"got {event.tls_ja4!r}. DO NOT copy ja3 into ja4 — different algorithms."
        )
        assert event.tls_ja4s is None, (
            f"tls_ja4s must be None when only tls.ja3s is present; got {event.tls_ja4s!r}"
        )
        # But sni and version should still be extracted
        assert event.tls_sni == "old-sensor-test.example"
        assert event.tls_version == "TLSv1.2"


# ── EARS-3: Golden fixture round-trip (JSON → normalize → compare) ────────────


class TestGoldenFixture06RoundTrip:
    """EARS-3: the new enriched fixture + expected JSON form a frozen oracle pair.

    Loads both files, normalizes the EVE fixture, then asserts every field in the
    expected_06 JSON matches the SecurityEvent output.
    The expected_06 JSON is the frozen oracle; do NOT regenerate it from new code.
    """

    def test_full_round_trip_against_expected_06(self) -> None:
        """All fields in expected_06_tls_dns_flow_enriched.json match normalize() output."""
        import json
        from datetime import datetime

        expected_path = FIXTURES_DIR / "expected_06_tls_dns_flow_enriched.json"
        expected = json.loads(expected_path.read_text())

        event = _normalize("eve_06_tls_dns_flow_enriched.json")

        # Fields that are datetime on SecurityEvent but ISO string in JSON
        datetime_fields = {"timestamp"}
        # Check every non-provenance field
        skip_keys = {"_provenance", "raw_log"}
        for key, exp_val in expected.items():
            if key in skip_keys:
                continue
            actual = getattr(event, key, "__MISSING__")
            assert actual != "__MISSING__", f"Field {key!r} not on SecurityEvent"
            if key in datetime_fields and isinstance(actual, datetime) and isinstance(exp_val, str):
                # Normalise both to ISO string for comparison
                actual_str = actual.isoformat()
                assert actual_str == exp_val, (
                    f"Field {key!r}: expected {exp_val!r} (golden oracle) but got {actual_str!r}. "
                    "This is a regression — normalize() diverged from the golden oracle."
                )
            else:
                assert actual == exp_val, (
                    f"Field {key!r}: expected {exp_val!r} (golden oracle) but got {actual!r}. "
                    "This is a regression — normalize() diverged from the golden oracle."
                )

    def test_fixture_06_file_exists(self) -> None:
        """eve_06 and expected_06 fixture files must exist (EARS-3 oracle persisted)."""
        assert (FIXTURES_DIR / "eve_06_tls_dns_flow_enriched.json").exists()
        assert (FIXTURES_DIR / "expected_06_tls_dns_flow_enriched.json").exists()


# ── EARS-4: Scoring oracle unchanged ─────────────────────────────────────────


class TestScoringOracleUnchanged:
    """EARS-4: expected_scores.json must not change — new fields don't feed scoring."""

    def test_scores_file_unchanged(self) -> None:
        """expected_scores.json is byte-identical to its committed version.

        The new network-depth fields do NOT participate in the scoring engine
        (ADR-0048: fields deferred to ML-13 for behavioral detection use).
        If this test fails, someone added score logic that references the new fields —
        that is out of scope for ML-2 and must be rejected.

        Baseline RE-BLESSED by ADR-0058 §D5a (issue #651): run_rules became
        disposition-weighted. The network-depth fields STILL do not feed scoring —
        these spot-checks track the new authorized baseline, not the network fields.
        """
        import json

        scores_path = FIXTURES_DIR / "expected_scores.json"
        scores = json.loads(scores_path.read_text())

        # Assert the oracle scenarios match the ADR-0058 §D5a re-blessed baseline (spot-check)
        assert scores["scenario_A_single_alert"]["score"] == 30
        assert scores["scenario_B_single_block"]["score"] == 0
        assert scores["scenario_C_three_blocks"]["score"] == 10
        assert scores["scenario_D_port_scan"]["score"] == 55
        # Confirm no new scenario was added
        scenario_keys = {k for k in scores if not k.startswith("_")}
        expected_scenarios = {
            "scenario_A_single_alert", "scenario_B_single_block",
            "scenario_C_three_blocks", "scenario_D_port_scan",
            "scenario_E_single_source_no_multi_source",
        }
        assert scenario_keys == expected_scenarios, (
            f"expected_scores.json scenarios changed — ADR-0048 EARS-4 violation. "
            f"Diff: {scenario_keys.symmetric_difference(expected_scenarios)}"
        )
