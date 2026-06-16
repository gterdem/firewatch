"""Tests for ip_classifier.py — issue #532 / EARS-1/EARS-6.

IP address selection:
  - RFC 1918 / private: 10.x, 172.16.x, 192.168.x (safe for private tests).
  - Routable test IPs: use real-looking but synthetic public IPs that Python's
    ipaddress module treats as globally routable.  We avoid RFC 5737 doc ranges
    (192.0.2/24, 198.51.100/24, 203.0.113/24) because ipaddress.is_global is
    False for those, which would make them all "private" in the classifier.
    Instead we use 1.2.3.4, 5.6.7.8, 9.10.11.12 — all globally routable.

EARS-1: classifier returns one of the five canonical IpClass values.
EARS-6: classification is pure / deterministic / zero-egress.
"""
from __future__ import annotations

import pytest

from firewatch_core.adapters.ip_classifier import classify

# Synthetic globally-routable IPs for tests (verified by Python's ipaddress.is_global).
ROUTABLE_A = "1.2.3.4"
ROUTABLE_B = "5.6.7.8"
ROUTABLE_C = "9.10.11.12"
ROUTABLE_D = "23.195.64.1"
ROUTABLE_E = "45.33.32.156"


# ---------------------------------------------------------------------------
# Private / RFC-1918 range detection
# ---------------------------------------------------------------------------

class TestPrivateClassification:
    """RFC-1918 and non-routable IPs must classify as 'private'."""

    def test_rfc1918_10_block(self):
        assert classify(None, None, "10.0.0.1") == "private"

    def test_rfc1918_172_block(self):
        assert classify(None, None, "172.16.0.1") == "private"

    def test_rfc1918_192_168(self):
        assert classify(None, None, "192.168.1.100") == "private"

    def test_loopback(self):
        assert classify(None, None, "127.0.0.1") == "private"

    def test_link_local(self):
        assert classify(None, None, "169.254.1.1") == "private"

    def test_private_takes_priority_over_datacenter_asn(self):
        """Private IP stays 'private' even if ASN is a cloud provider."""
        assert classify(16509, "Amazon", "10.0.0.1") == "private"

    def test_none_ip_falls_through(self):
        """None IP with no ASN → unresolved (not private — no IP to check range)."""
        result = classify(None, None, None)
        assert result == "unresolved"


# ---------------------------------------------------------------------------
# Datacenter classification
# ---------------------------------------------------------------------------

class TestDatacenterClassification:
    """Known cloud/hosting ASNs must classify as 'datacenter'."""

    @pytest.mark.parametrize("asn,name", [
        (16509, "Amazon"),
        (8075,  "Microsoft Corporation"),
        (15169, "Google LLC"),
        (16276, "OVH SAS"),
        (14061, "DigitalOcean LLC"),
        (24940, "Hetzner Online GmbH"),
        (63949, "Akamai Connected Cloud"),
        (20473, "Vultr Holdings LLC"),
        (13335, "Cloudflare Inc."),
        (54113, "Fastly Inc."),
    ])
    def test_known_cloud_asn(self, asn, name):
        assert classify(asn, name, ROUTABLE_A) == "datacenter"

    def test_datacenter_by_as_name_amazon(self):
        """Classifies as datacenter via name fragment when ASN absent."""
        assert classify(None, "Amazon Web Services", ROUTABLE_B) == "datacenter"

    def test_datacenter_by_as_name_google(self):
        assert classify(None, "Google Cloud LLC", ROUTABLE_B) == "datacenter"

    def test_datacenter_by_as_name_microsoft(self):
        assert classify(None, "Microsoft Corporation", ROUTABLE_C) == "datacenter"

    def test_datacenter_by_as_name_cloudflare(self):
        assert classify(None, "Cloudflare, Inc.", ROUTABLE_C) == "datacenter"

    def test_datacenter_name_case_insensitive(self):
        assert classify(None, "AMAZON WEB SERVICES", ROUTABLE_D) == "datacenter"


# ---------------------------------------------------------------------------
# VPN-likely classification
# ---------------------------------------------------------------------------

class TestVpnClassification:
    """Known VPN/anonymiser ASNs must classify as 'vpn-likely'."""

    @pytest.mark.parametrize("asn,name", [
        (39351, "Mullvad Network AB"),
        (11978, "KRYPT TECHNOLOGIES"),  # PIA
        (209103, "Proton AG"),
    ])
    def test_known_vpn_asn(self, asn, name):
        assert classify(asn, name, ROUTABLE_A) == "vpn-likely"

    def test_vpn_by_as_name_mullvad(self):
        assert classify(None, "Mullvad VPN", ROUTABLE_B) == "vpn-likely"

    def test_vpn_by_as_name_nordvpn(self):
        assert classify(None, "NordVPN S.A.", ROUTABLE_C) == "vpn-likely"

    def test_vpn_by_as_name_generic(self):
        assert classify(None, "SomeService VPN LLC", ROUTABLE_D) == "vpn-likely"

    def test_vpn_takes_priority_after_datacenter(self):
        """A VPN-only ASN must return 'vpn-likely' not 'datacenter'."""
        assert classify(39351, "Mullvad Network AB", ROUTABLE_E) == "vpn-likely"


# ---------------------------------------------------------------------------
# Residential classification
# ---------------------------------------------------------------------------

class TestResidentialClassification:
    """Routable IPs with an ASN not in the cloud/VPN sets → 'residential'."""

    def test_isp_asn(self):
        # AS7922 is Comcast — not in DATACENTER_ASNS or VPN_ASNS
        assert classify(7922, "Comcast Cable Communications", ROUTABLE_A) == "residential"

    def test_unknown_asn_with_name(self):
        assert classify(99999, "Some Regional ISP", ROUTABLE_B) == "residential"

    def test_any_asn_not_in_sets(self):
        """Any non-zero ASN not in the cloud/VPN sets → residential."""
        assert classify(1, "IANA", ROUTABLE_C) == "residential"


# ---------------------------------------------------------------------------
# Unresolved classification
# ---------------------------------------------------------------------------

class TestUnresolvedClassification:
    """No ASN data for a routable IP → 'unresolved'."""

    def test_no_asn_no_name(self):
        assert classify(None, None, ROUTABLE_A) == "unresolved"

    def test_no_asn_with_empty_name(self):
        assert classify(None, "", ROUTABLE_B) == "unresolved"

    def test_no_asn_with_none_ip(self):
        """When both ASN and IP are None → unresolved."""
        assert classify(None, None, None) == "unresolved"


# ---------------------------------------------------------------------------
# Priority ordering
# ---------------------------------------------------------------------------

class TestClassificationPriority:
    """Validate the documented priority order (private > datacenter > vpn > residential > unresolved)."""

    def test_private_beats_all(self):
        # Even with a known datacenter ASN + name, private wins
        assert classify(16509, "Amazon", "192.168.1.1") == "private"

    def test_datacenter_asn_beats_vpn_name_fragment(self):
        """When ASN is in datacenter set, AS-name 'vpn' fragment doesn't override.
        Datacenter set is checked BEFORE VPN name check in the priority order."""
        assert classify(16509, "VPN Edge Node Amazon", ROUTABLE_A) == "datacenter"

    def test_residential_fallback_for_unknown_asn(self):
        """An ASN not in either set → residential (better than unresolved)."""
        assert classify(12345, "Some ISP", ROUTABLE_C) == "residential"

    def test_unresolved_when_no_data(self):
        assert classify(None, None, ROUTABLE_D) == "unresolved"
