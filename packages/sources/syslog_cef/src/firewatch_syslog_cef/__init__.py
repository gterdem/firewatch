"""firewatch_syslog_cef — Generic Syslog/CEF receiver (PUSH).

Vendor-agnostic CEF->OCSF plugin. Parses ArcSight CEF (Common Event Format)
plus RFC 5424 / RFC 3164 syslog framing. Routes vendor action tokens through
a (DeviceVendor, DeviceProduct)->ActionValueTable registry with a generic
default fallback. source_type is always 'syslog_cef' (Flag B).

Standards:
  - ArcSight CEF Implementation Standard
    https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.4/
  - RFC 5424 (modern syslog): https://datatracker.ietf.org/doc/html/rfc5424
  - RFC 3164 (BSD syslog):   https://datatracker.ietf.org/doc/html/rfc3164
  - OCSF schema: https://schema.ocsf.io
"""
