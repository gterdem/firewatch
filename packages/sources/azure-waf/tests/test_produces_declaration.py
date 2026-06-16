"""Tests for Azure WAF plugin SourceMetadata.produces declaration (ADR-0060, #664 Part 1).

EARS criterion → test mapping
==============================

EARS-AP-1 (ubiquitous — produces is declared):
  The Azure WAF plugin SHALL declare a non-empty produces set on its metadata.
  -> test_azure_waf_declares_produces

EARS-AP-2 (ubiquitous — declared fields are valid SecurityEvent fields):
  Every member of the azure_waf produces set SHALL be a valid SecurityEvent field.
  -> test_azure_waf_produces_all_valid_fields

EARS-AP-3 (ubiquitous — L7 HTTP fields included):
  Azure WAF sets http_url and http_host — these SHALL be in its produces set.
  -> test_azure_waf_produces_http_fields

EARS-AP-4 (ubiquitous — transport fields NOT included):
  Azure WAF logs do not carry destination_ip, destination_port, protocol —
  these SHALL NOT be in its produces set (ADR-0060, azure-waf-log-standard §3).
  -> test_azure_waf_does_not_produce_destination_ip
  -> test_azure_waf_does_not_produce_destination_port
  -> test_azure_waf_does_not_produce_protocol

EARS-AP-5 (ubiquitous — flow/DNS/TLS fields not included):
  Azure WAF is an L7 HTTP gateway with no access to transport-layer flow stats,
  DNS queries, or TLS handshake fingerprints — these SHALL NOT be in its produces.
  -> test_azure_waf_does_not_produce_flow_fields
  -> test_azure_waf_does_not_produce_dns_fields
  -> test_azure_waf_does_not_produce_tls_fields

EARS-AP-6 (ubiquitous — HTTP fields it does NOT emit excluded):
  Azure WAF diagnostic logs do not carry http_method or http_user_agent —
  these SHALL NOT be in its produces set (no fabrication rule).
  -> test_azure_waf_does_not_produce_http_method
  -> test_azure_waf_does_not_produce_http_user_agent

EARS-AP-7 (ubiquitous — produces is a frozenset):
  -> test_azure_waf_produces_is_frozenset
"""
from __future__ import annotations

from firewatch_azure_waf.plugin import AzureWAFSource
from firewatch_sdk.models import SecurityEvent


def _meta():
    return AzureWAFSource().metadata()


# --------------------------------------------------------------------------- #
# EARS-AP-1: produces is declared (non-empty)                                  #
# --------------------------------------------------------------------------- #

def test_azure_waf_declares_produces():
    """Azure WAF plugin declares a non-empty produces set."""
    meta = _meta()
    assert len(meta.produces) > 0, "Azure WAF must declare a non-empty produces set"


# --------------------------------------------------------------------------- #
# EARS-AP-2: all declared fields are valid SecurityEvent fields                 #
# --------------------------------------------------------------------------- #

def test_azure_waf_produces_all_valid_fields():
    """Every member of Azure WAF's produces set is a valid SecurityEvent field name."""
    valid = frozenset(SecurityEvent.model_fields.keys())
    meta = _meta()
    invalid = meta.produces - valid
    assert not invalid, (
        f"Azure WAF produces contains invalid SecurityEvent field names: {sorted(invalid)}"
    )


# --------------------------------------------------------------------------- #
# EARS-AP-3: L7 HTTP fields it actually populates ARE in produces               #
# --------------------------------------------------------------------------- #

def test_azure_waf_produces_http_fields():
    """Azure WAF's produces includes the HTTP fields its normalize() actually sets."""
    meta = _meta()
    required = {"http_url", "http_host"}
    missing = required - meta.produces
    assert not missing, (
        f"Azure WAF produces is missing HTTP fields it populates: {sorted(missing)}"
    )


# --------------------------------------------------------------------------- #
# EARS-AP-4: destination_ip / destination_port / protocol are ABSENT           #
# --------------------------------------------------------------------------- #

def test_azure_waf_does_not_produce_destination_ip():
    """destination_ip is not in Azure WAF produces (WAF logs do not carry this field)."""
    meta = _meta()
    assert "destination_ip" not in meta.produces, (
        "Azure WAF normalize() never sets destination_ip; it must not be in produces"
    )


def test_azure_waf_does_not_produce_destination_port():
    """destination_port is not in Azure WAF produces (WAF logs do not carry this field)."""
    meta = _meta()
    assert "destination_port" not in meta.produces, (
        "Azure WAF normalize() never sets destination_port; it must not be in produces"
    )


def test_azure_waf_does_not_produce_protocol():
    """protocol is not in Azure WAF produces (WAF logs do not carry this field)."""
    meta = _meta()
    assert "protocol" not in meta.produces, (
        "Azure WAF normalize() never sets protocol; it must not be in produces"
    )


# --------------------------------------------------------------------------- #
# EARS-AP-5: flow / DNS / TLS fields are ABSENT                                #
# --------------------------------------------------------------------------- #

def test_azure_waf_does_not_produce_flow_fields():
    """Azure WAF's produces excludes flow-volume fields (L7 gateway has no flow stats)."""
    meta = _meta()
    flow_fields = {"bytes_in", "bytes_out", "packets_in", "packets_out", "flow_duration_ms"}
    incorrectly_declared = flow_fields & meta.produces
    assert not incorrectly_declared, (
        f"Azure WAF produces incorrectly declares flow fields: {sorted(incorrectly_declared)}"
    )


def test_azure_waf_does_not_produce_dns_fields():
    """Azure WAF's produces excludes DNS fields (L7 HTTP gateway, no DNS query data)."""
    meta = _meta()
    dns_fields = {"dns_query", "dns_rcode", "dns_answer"}
    incorrectly_declared = dns_fields & meta.produces
    assert not incorrectly_declared, (
        f"Azure WAF produces incorrectly declares DNS fields: {sorted(incorrectly_declared)}"
    )


def test_azure_waf_does_not_produce_tls_fields():
    """Azure WAF's produces excludes TLS fingerprint fields (no TLS handshake data in WAF logs)."""
    meta = _meta()
    tls_fields = {"tls_ja4", "tls_ja4s", "tls_sni", "tls_version", "tls_ja3"}
    incorrectly_declared = tls_fields & meta.produces
    assert not incorrectly_declared, (
        f"Azure WAF produces incorrectly declares TLS fields: {sorted(incorrectly_declared)}"
    )


# --------------------------------------------------------------------------- #
# EARS-AP-6: HTTP fields Azure WAF does NOT emit are ABSENT                    #
# --------------------------------------------------------------------------- #

def test_azure_waf_does_not_produce_http_method():
    """http_method is not in Azure WAF produces (not available in WAF diagnostic logs)."""
    meta = _meta()
    assert "http_method" not in meta.produces, (
        "Azure WAF diagnostic logs do not carry http_method; it must not be in produces"
    )


def test_azure_waf_does_not_produce_http_user_agent():
    """http_user_agent is not in Azure WAF produces (not available in WAF diagnostic logs)."""
    meta = _meta()
    assert "http_user_agent" not in meta.produces, (
        "Azure WAF diagnostic logs do not carry http_user_agent; it must not be in produces"
    )


# --------------------------------------------------------------------------- #
# EARS-AP-7: type check                                                        #
# --------------------------------------------------------------------------- #

def test_azure_waf_produces_is_frozenset():
    """Azure WAF's produces is a frozenset."""
    meta = _meta()
    assert isinstance(meta.produces, frozenset)
