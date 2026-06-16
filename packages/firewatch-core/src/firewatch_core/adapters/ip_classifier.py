"""IP provenance classifier — issue #532 / ADR-0052.

Classifies every geo point by IP provenance using the ASN data already
stored in the ip_geo cache (issue #211, ECS as.number / as.organization.name).

Classification is **zero-egress** (ADR-0047): no external call is made; the
classifier uses a small bundled ASN set and the ip_address stdlib module.

Taxonomy:
  datacenter  — ASN belonging to a known cloud/hosting provider.
                Country is the hosting location, NOT the actor origin.
  vpn-likely  — ASN belonging to a known VPN / anonymiser provider.
  residential — Has an ASN but not in the above sets (default for routable IPs).
  private     — IP in a non-routable range (RFC 1918, loopback, link-local, …).
  unresolved  — No ASN and no public geo (not yet enriched or truly absent).

The cloud/VPN sets ship as bundled constants — "unknown ASN" falls through to
residential/unresolved honestly rather than guessing.

Security: inputs come from the ip_geo cache (enricher output), not directly
from attacker payloads.  The classifier is a pure function with no side effects.
"""
from __future__ import annotations

from firewatch_core.adapters.geo_ip_utils import is_non_public

# ---------------------------------------------------------------------------
# Bundled ASN sets (zero-egress — no network call, no external feed)
# Source: publicly known AS assignments for major cloud/VPN providers.
# Kept deliberately small and curated; "unknown ASN" stays residential/unresolved.
# ---------------------------------------------------------------------------

# Cloud / datacenter / hosting ASNs.
# Country geo for these is the *server location*, not the actor origin.
# Sources: ARIN/RIPE published assignments; canonical references:
#   AWS:  https://docs.aws.amazon.com/general/latest/gr/aws-ip-ranges.html  (AS16509)
#   Azure: https://www.microsoft.com/en-us/download/details.aspx?id=56519    (AS8075)
#   GCP:   https://cloud.google.com/compute/docs/faq                         (AS15169)
#   OVH:   https://bgp.he.net/AS16276                                        (AS16276)
#   DO:    https://bgp.he.net/AS14061                                        (AS14061)
#   Hetzner: https://bgp.he.net/AS24940                                      (AS24940)
#   Linode/Akamai: https://bgp.he.net/AS63949                                (AS63949)
#   Vultr: https://bgp.he.net/AS20473                                        (AS20473)
#   Cloudflare: https://bgp.he.net/AS13335                                   (AS13335)
#   Fastly: https://bgp.he.net/AS54113                                       (AS54113)
DATACENTER_ASNS: frozenset[int] = frozenset(
    [
        16509,   # AS16509 — Amazon Web Services
        8075,    # AS8075  — Microsoft Corporation (Azure)
        15169,   # AS15169 — Google LLC (GCP)
        16276,   # AS16276 — OVH SAS
        14061,   # AS14061 — DigitalOcean LLC
        24940,   # AS24940 — Hetzner Online GmbH
        63949,   # AS63949 — Akamai Connected Cloud (Linode)
        20473,   # AS20473 — Vultr Holdings LLC
        13335,   # AS13335 — Cloudflare Inc.
        54113,   # AS54113 — Fastly Inc.
        396982,  # AS396982 — Google Cloud LLCF (additional GCP block)
        14618,   # AS14618 — Amazon Technologies Inc. (additional AWS)
        16625,   # AS16625 — Akamai Technologies
        36351,   # AS36351 — SoftLayer Technologies (IBM Cloud)
        8560,    # AS8560  — IONOS SE (1&1)
    ]
)

# VPN / anonymiser ASNs.
# Geographic origin is heavily obscured; treat country as unreliable.
# Sources: public VPN provider ASN assignments.
#   Mullvad: https://bgp.he.net/AS39351                                      (AS39351)
#   NordVPN: https://bgp.he.net/AS212238 (proxy infra)                       (AS212238)
#   ExpressVPN: https://bgp.he.net/AS136258                                  (AS136258)
#   Private Internet Access: https://bgp.he.net/AS11978                      (AS11978)
#   ProtonVPN: https://bgp.he.net/AS209103                                   (AS209103)
VPN_ASNS: frozenset[int] = frozenset(
    [
        39351,   # AS39351  — Mullvad VPN
        212238,  # AS212238 — NordVPN (proxy infrastructure)
        136258,  # AS136258 — ExpressVPN
        11978,   # AS11978  — Private Internet Access (KRYPT TECHNOLOGIES)
        209103,  # AS209103 — Proton AG (ProtonVPN)
    ]
)

# Literal string fragments that also tag a hosting provider when an ASN integer
# is absent but as_name is present.  Lower-cased at match time.
DATACENTER_NAME_FRAGMENTS: tuple[str, ...] = (
    "amazon",
    "aws",
    "microsoft",
    "azure",
    "google",
    "digitalocean",
    "hetzner",
    "ovh",
    "linode",
    "akamai",
    "cloudflare",
    "fastly",
    "vultr",
    "softlayer",
    "ibm cloud",
    "ionos",
    "1&1",
)

VPN_NAME_FRAGMENTS: tuple[str, ...] = (
    "mullvad",
    "nordvpn",
    "expressvpn",
    "private internet access",
    "proton",
    "vpn",
    "anonymizer",
    "anonymiser",
    "tor exit",
)

IpClass = str  # "datacenter" | "vpn-likely" | "residential" | "private" | "unresolved"


def classify(asn: int | None, as_name: str | None, ip: str | None) -> IpClass:
    """Classify an IP by provenance using ASN data and IP-range checks.

    Priority order:
      1. private   — IP is in a non-routable range (RFC 1918 / loopback / …).
      2. datacenter — ASN or AS-name matches a known cloud/hosting provider.
      3. vpn-likely — ASN or AS-name matches a known VPN/anonymiser provider.
      4. residential — Has any ASN (not in the above sets).
      5. unresolved — No ASN data and the IP is routable.

    Parameters
    ----------
    asn:
        Integer AS number from the ip_geo cache, or None.
    as_name:
        AS organisation name from the ip_geo cache, or None.
    ip:
        The source IP string; used for the private-range check.  May be None
        when the cached row has no ip column — falls through to unresolved.

    Returns
    -------
    One of "private", "datacenter", "vpn-likely", "residential", "unresolved".
    """
    # Step 1 — private / non-routable range check.
    if ip and is_non_public(ip):
        return "private"

    # Step 2 — datacenter check by ASN integer first (fastest path).
    if asn is not None and asn in DATACENTER_ASNS:
        return "datacenter"

    # Step 3 — datacenter check by AS-name fragment (fallback when ASN absent).
    if as_name:
        lower = as_name.lower()
        if any(frag in lower for frag in DATACENTER_NAME_FRAGMENTS):
            return "datacenter"

    # Step 4 — VPN check by ASN integer.
    if asn is not None and asn in VPN_ASNS:
        return "vpn-likely"

    # Step 5 — VPN check by AS-name fragment.
    if as_name:
        lower = as_name.lower()
        if any(frag in lower for frag in VPN_NAME_FRAGMENTS):
            return "vpn-likely"

    # Step 6 — has an ASN but not in any special set → residential/ISP.
    if asn is not None:
        return "residential"

    # Step 7 — no ASN data for a routable IP → unresolved.
    return "unresolved"
