"""Tests for Suricata plugin SourceMetadata.produces declaration (ADR-0060, #664 Part 1).

EARS criterion → test mapping
==============================

EARS-SP-1 (ubiquitous — produces is declared):
  The Suricata plugin SHALL declare a non-empty produces set on its metadata.
  -> test_suricata_declares_produces

EARS-SP-2 (ubiquitous — declared fields are valid SecurityEvent fields):
  Every member of the suricata produces set SHALL be a valid SecurityEvent field.
  -> test_suricata_produces_all_valid_fields

EARS-SP-3 (ubiquitous — L3/L4 transport fields included):
  Suricata emits destination_ip, destination_port, protocol — these SHALL be
  in its produces set (it is a broad L3–L7 IDS/IPS sensor).
  -> test_suricata_produces_l3_l4_fields

EARS-SP-4 (ubiquitous — network-depth ADR-0048 fields included):
  Suricata emits flow/dns/tls/http sub-object fields — the canonical fields
  it actually populates SHALL be in its produces set.
  -> test_suricata_produces_network_depth_fields

EARS-SP-5 (ubiquitous — fields Suricata does NOT populate excluded):
  Fields Suricata's normalize() never sets (e.g. file_* from ADR-0055,
  dns_answer, kill_chain_phase, capec_id) SHALL NOT be in produces
  (or if included that would be incorrect per the spec).
  -> test_suricata_does_not_produce_file_fields
  -> test_suricata_does_not_produce_dns_answer

EARS-SP-6 (ubiquitous — produces is a frozenset):
  The produces attribute SHALL be a frozenset.
  -> test_suricata_produces_is_frozenset
"""
from __future__ import annotations

from firewatch_sdk.models import SecurityEvent
from firewatch_suricata.plugin import SuricataSource


def _meta():
    return SuricataSource().metadata()


# --------------------------------------------------------------------------- #
# EARS-SP-1: produces is declared (non-empty)                                  #
# --------------------------------------------------------------------------- #

def test_suricata_declares_produces():
    """Suricata plugin declares a non-empty produces set."""
    meta = _meta()
    assert len(meta.produces) > 0, "Suricata must declare a non-empty produces set"


# --------------------------------------------------------------------------- #
# EARS-SP-2: all declared fields are valid SecurityEvent fields                 #
# --------------------------------------------------------------------------- #

def test_suricata_produces_all_valid_fields():
    """Every member of Suricata's produces set is a valid SecurityEvent field name."""
    valid = frozenset(SecurityEvent.model_fields.keys())
    meta = _meta()
    invalid = meta.produces - valid
    assert not invalid, (
        f"Suricata produces contains invalid SecurityEvent field names: {sorted(invalid)}"
    )


# --------------------------------------------------------------------------- #
# EARS-SP-3: L3/L4 transport fields present (Suricata IS an L3–L7 sensor)     #
# --------------------------------------------------------------------------- #

def test_suricata_produces_l3_l4_fields():
    """Suricata's produces includes L3/L4 transport fields it actually sets."""
    meta = _meta()
    required = {"source_ip", "source_port", "destination_ip", "destination_port", "protocol"}
    missing = required - meta.produces
    assert not missing, (
        f"Suricata produces is missing L3/L4 transport fields: {sorted(missing)}"
    )


# --------------------------------------------------------------------------- #
# EARS-SP-4: network-depth ADR-0048 fields present                             #
# --------------------------------------------------------------------------- #

def test_suricata_produces_network_depth_fields():
    """Suricata's produces includes the ADR-0048 network-depth fields it populates."""
    meta = _meta()
    # Flow fields (Group A)
    flow_fields = {"bytes_in", "bytes_out", "packets_in", "packets_out", "flow_duration_ms"}
    # DNS fields (Group B)
    dns_fields = {"dns_query", "dns_rcode"}
    # TLS fields (Group C) — ja4/ja4s are Suricata 7.x+ but they ARE set when present
    tls_fields = {"tls_ja4", "tls_ja4s", "tls_sni", "tls_version"}
    # HTTP fields (Group D)
    http_fields = {"http_method", "http_host", "http_url", "http_user_agent"}

    expected = flow_fields | dns_fields | tls_fields | http_fields
    missing = expected - meta.produces
    assert not missing, (
        f"Suricata produces is missing network-depth fields: {sorted(missing)}"
    )


# --------------------------------------------------------------------------- #
# EARS-SP-5: fields Suricata never emits are excluded                          #
# --------------------------------------------------------------------------- #

def test_suricata_does_not_produce_file_fields():
    """Suricata's normalize() never populates file_* ADR-0055 fields — not in produces."""
    meta = _meta()
    file_fields = {"file_sha256", "file_md5", "file_sha1", "file_name", "file_mime_type"}
    incorrectly_declared = file_fields & meta.produces
    assert not incorrectly_declared, (
        f"Suricata produces incorrectly declares file fields it does not emit: "
        f"{sorted(incorrectly_declared)}"
    )


def test_suricata_does_not_produce_dns_answer():
    """Suricata's normalize() never populates dns_answer (ADR-0055) — not in produces."""
    meta = _meta()
    assert "dns_answer" not in meta.produces, (
        "Suricata normalize() never sets dns_answer; it must not be in produces"
    )


# --------------------------------------------------------------------------- #
# EARS-SP-6: type check                                                        #
# --------------------------------------------------------------------------- #

def test_suricata_produces_is_frozenset():
    """Suricata's produces is a frozenset."""
    meta = _meta()
    assert isinstance(meta.produces, frozenset)
