"""ArcSight CEF (Common Event Format) parser.

Parses CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extension

Standard reference:
  ArcSight CEF Implementation Standard (HP/Micro Focus)
  https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.4/
  pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf

CEF Extension key=value dictionary (standard keys used here):
  src          -- Source IP address
  dst          -- Destination IP address
  spt          -- Source port
  dpt          -- Destination port
  proto        -- Transport protocol (TCP/UDP/ICMP)
  act          -- Device action (vendor-specific token: deny/drop/permit/allow/block/alert...)
  msg          -- Human-readable description
  request      -- HTTP request URL
  requestMethod -- HTTP request method
  cs1..cs6     -- Custom string fields (vendor-specific labels via cs1Label..cs6Label)

CEF messages often arrive prefixed by a syslog priority envelope
(e.g. "<134>Jan 15 10:00:00 host fw: CEF:0|..."). The parser strips
any content before the first "CEF:" occurrence.

Return type:
  None if the line contains no CEF message.
  dict with keys:
    cef_version, device_vendor, device_product, device_version,
    signature_id, name, cef_severity, ext: dict[str, str]
"""
from __future__ import annotations

import re
from typing import Any

# Regex to locate the start of a CEF message within a syslog line.
# CEF messages may be prefixed by a syslog envelope.
_CEF_START_RE = re.compile(r"CEF:\s*(\d+)\|")

# CEF Extension key=value splitter.
# Values may contain spaces; keys are alphanumeric (no spaces).
# The CEF spec uses unescaped spaces between pairs, and '=' separates key from value.
# Strategy: split on ' key=' boundaries where key matches [A-Za-z][A-Za-z0-9]*.
# This handles multi-word values correctly (e.g. "act=deny blocked traffic").
_EXT_TOKEN_RE = re.compile(r"([A-Za-z][A-Za-z0-9]*)=")


def parse_cef(line: str) -> dict[str, Any] | None:
    """Parse a CEF message from a syslog line.

    Accepts bare CEF messages and syslog-enveloped ones (strips envelope).
    Returns None if the line does not contain a CEF message.

    The returned dict shape::

        {
            "cef_version":    str,   # CEF version field (typically "0")
            "device_vendor":  str,   # DeviceVendor header field
            "device_product": str,   # DeviceProduct header field
            "device_version": str,   # DeviceVersion header field
            "signature_id":   str,   # SignatureID header field (rule ID)
            "name":           str,   # Name header field (human label)
            "cef_severity":   str,   # Severity header field (0-10 string)
            "ext":            dict[str, str],  # Extension key=value pairs
        }
    """
    # Locate "CEF:" in the line — strip any syslog prefix before it.
    m = _CEF_START_RE.search(line)
    if m is None:
        return None

    cef_start = m.start()
    cef_body = line[cef_start:]

    # Split the CEF header on '|' (unescaped pipe).
    # The header has exactly 8 fields; Extension is the 8th (may be absent).
    # Pipe chars inside Extension values should be escaped as \| per the spec,
    # but we split on the first 7 pipes only.
    parts = cef_body.split("|", 7)
    if len(parts) < 7:  # noqa: PLR2004  -- 7 = minimum CEF header fields
        return None

    # parts[0] = "CEF:N" (already matched above)
    cef_version = parts[0].split(":", 1)[1].strip() if ":" in parts[0] else ""
    device_vendor = parts[1]
    device_product = parts[2]
    device_version = parts[3]
    signature_id = parts[4]
    name = parts[5]
    cef_severity = parts[6]
    extension_str = parts[7].strip() if len(parts) > 7 else ""  # noqa: PLR2004

    ext = _parse_extension(extension_str)

    return {
        "cef_version": cef_version,
        "device_vendor": device_vendor,
        "device_product": device_product,
        "device_version": device_version,
        "signature_id": signature_id,
        "name": name,
        "cef_severity": cef_severity,
        "ext": ext,
    }


def _parse_extension(extension_str: str) -> dict[str, str]:
    """Parse the CEF Extension field into a key->value dict.

    The Extension is a space-separated sequence of key=value pairs.
    Values may contain spaces; the boundary of one value is the start of
    the next 'key=' token. This is the approach recommended by the CEF spec
    when keys are unambiguously identifiable (alphanumeric, no spaces).

    Example::
        "src=198.51.100.50 dst=192.0.2.100 spt=54321 act=deny"
        -> {"src": "198.51.100.50", "dst": "192.0.2.100",
            "spt": "54321", "act": "deny"}
    """
    if not extension_str:
        return {}

    # Find all key= positions.
    matches = list(_EXT_TOKEN_RE.finditer(extension_str))
    if not matches:
        return {}

    result: dict[str, str] = {}
    for i, match in enumerate(matches):
        key = match.group(1)
        value_start = match.end()
        # Value ends at start of next key= (or end of string).
        value_end = matches[i + 1].start() if i + 1 < len(matches) else len(extension_str)
        value = extension_str[value_start:value_end].strip()
        result[key] = value

    return result
