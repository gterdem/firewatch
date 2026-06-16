"""Tests for SourceMetadata.produces field (ADR-0060, issue #664 Part 1).

EARS criterion → test mapping
==============================

EARS-P-1 (ubiquitous — default empty frozenset):
  SourceMetadata SHALL accept construction without specifying `produces`;
  the default SHALL be frozenset() (empty).
  -> test_produces_defaults_to_empty_frozenset
  -> test_metadata_without_produces_loads_fine

EARS-P-2 (ubiquitous — empty means produces-all):
  Empty `produces` SHALL be treated as "produces everything" (backward-compat).
  The field value itself is frozenset() — the interpretation is at the consumer.
  -> test_empty_produces_is_frozenset

EARS-P-3 (ubiquitous — valid canonical fields accepted):
  SourceMetadata SHALL accept a frozenset of known SecurityEvent field names.
  -> test_valid_produces_accepted
  -> test_produces_is_frozenset_of_strings

EARS-P-4 (ubiquitous — unknown field names rejected at construction):
  WHEN a produces member is not a SecurityEvent field name, construction
  SHALL raise ValidationError (fail-closed typo guard).
  -> test_unknown_field_rejected
  -> test_typo_field_rejected
  -> test_mixed_valid_and_invalid_rejected

EARS-P-5 (ubiquitous — frozen model stays frozen):
  SourceMetadata remains frozen (immutable) when produces is set.
  -> test_metadata_with_produces_is_frozen

EARS-P-6 (ubiquitous — exported from SDK root):
  No-regression: SourceMetadata is still importable from firewatch_sdk.
  -> test_source_metadata_imported_from_sdk
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from firewatch_sdk import SourceMetadata


# --------------------------------------------------------------------------- #
# EARS-P-1: default empty frozenset                                             #
# --------------------------------------------------------------------------- #

def test_produces_defaults_to_empty_frozenset():
    """SourceMetadata.produces defaults to frozenset()."""
    meta = SourceMetadata(
        type_key="testsrc",
        display_name="Test Source",
        version="1.0.0",
        flavor="pull",
    )
    assert meta.produces == frozenset()


def test_metadata_without_produces_loads_fine():
    """Existing-style construction without produces keyword does not break."""
    # Simulate old plugin that never passed produces.
    meta = SourceMetadata(
        type_key="oldsrc",
        display_name="Old Source",
        version="0.1.0",
        flavor="push",
    )
    assert isinstance(meta.produces, frozenset)


# --------------------------------------------------------------------------- #
# EARS-P-2: empty = produces-all (value check only)                            #
# --------------------------------------------------------------------------- #

def test_empty_produces_is_frozenset():
    """Default produces is an empty frozenset (the produces-all sentinel)."""
    meta = SourceMetadata(
        type_key="testsrc",
        display_name="Test",
        version="1.0.0",
        flavor="pull",
    )
    assert meta.produces == frozenset()
    assert len(meta.produces) == 0


# --------------------------------------------------------------------------- #
# EARS-P-3: valid canonical fields accepted                                     #
# --------------------------------------------------------------------------- #

def test_valid_produces_accepted():
    """A frozenset of valid SecurityEvent field names is accepted."""
    meta = SourceMetadata(
        type_key="testsrc",
        display_name="Test",
        version="1.0.0",
        flavor="pull",
        produces=frozenset({"source_ip", "destination_ip", "protocol", "destination_port"}),
    )
    assert "source_ip" in meta.produces
    assert "destination_ip" in meta.produces
    assert "protocol" in meta.produces
    assert "destination_port" in meta.produces


def test_produces_is_frozenset_of_strings():
    """produces field is a frozenset of str."""
    meta = SourceMetadata(
        type_key="testsrc",
        display_name="Test",
        version="1.0.0",
        flavor="pull",
        produces=frozenset({"http_url", "http_method"}),
    )
    assert isinstance(meta.produces, frozenset)
    for item in meta.produces:
        assert isinstance(item, str)


def test_produces_accepts_all_known_security_event_fields():
    """All SecurityEvent field names (except identity/infra fields) are valid members."""
    # A representative cross-section of canonical fields
    fields = frozenset({
        "source_ip", "source_port", "destination_ip", "destination_port",
        "protocol", "action", "category", "severity", "rule_id", "rule_name",
        "payload_snippet", "geo_country", "geo_city", "geo_lat", "geo_lon",
        "attack_technique", "attack_tactic", "kill_chain_phase", "capec_id",
        "ocsf_class", "ocsf_category",
        "bytes_in", "bytes_out", "packets_in", "packets_out", "flow_duration_ms",
        "dns_query", "dns_rcode",
        "tls_ja4", "tls_ja4s", "tls_sni", "tls_version", "tls_ja3",
        "http_method", "http_host", "http_url", "http_user_agent",
        "file_sha256", "file_md5", "file_sha1", "file_name", "file_mime_type",
        "dns_answer",
        "raw_log",
    })
    meta = SourceMetadata(
        type_key="fullsrc",
        display_name="Full Source",
        version="1.0.0",
        flavor="pull",
        produces=fields,
    )
    assert meta.produces == fields


# --------------------------------------------------------------------------- #
# EARS-P-4: unknown field names rejected (fail-closed typo guard)              #
# --------------------------------------------------------------------------- #

def test_unknown_field_rejected():
    """A produces member that is not a SecurityEvent field raises ValidationError."""
    with pytest.raises(ValidationError):
        SourceMetadata(
            type_key="testsrc",
            display_name="Test",
            version="1.0.0",
            flavor="pull",
            produces=frozenset({"not_a_real_field"}),
        )


def test_typo_field_rejected():
    """A typo like 'destiantion_ip' (misspelled) is rejected at construction."""
    with pytest.raises(ValidationError):
        SourceMetadata(
            type_key="testsrc",
            display_name="Test",
            version="1.0.0",
            flavor="pull",
            produces=frozenset({"destiantion_ip"}),  # typo: 'destiantion' vs 'destination'
        )


def test_mixed_valid_and_invalid_rejected():
    """A mix of valid + invalid field names raises ValidationError (all-or-nothing)."""
    with pytest.raises(ValidationError):
        SourceMetadata(
            type_key="testsrc",
            display_name="Test",
            version="1.0.0",
            flavor="pull",
            produces=frozenset({"source_ip", "totally_made_up_field"}),
        )


# --------------------------------------------------------------------------- #
# EARS-P-5: frozen model stays frozen                                           #
# --------------------------------------------------------------------------- #

def test_metadata_with_produces_is_frozen():
    """SourceMetadata remains frozen (immutable) when produces is set."""
    meta = SourceMetadata(
        type_key="testsrc",
        display_name="Test",
        version="1.0.0",
        flavor="pull",
        produces=frozenset({"source_ip", "protocol"}),
    )
    with pytest.raises(Exception):
        meta.produces = frozenset({"destination_ip"})  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# EARS-P-6: no-regression SDK import                                            #
# --------------------------------------------------------------------------- #

def test_source_metadata_imported_from_sdk():
    """SourceMetadata is still importable from the SDK root."""
    from firewatch_sdk import SourceMetadata as SM  # noqa: F401
    assert SM is SourceMetadata
