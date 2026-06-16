"""RFC 5424 syslog framing parser.

Standard reference:
  RFC 5424 - The Syslog Protocol (March 2009)
  https://datatracker.ietf.org/doc/html/rfc5424

RFC 5424 message format (section 6):
  SYSLOG-MSG = HEADER SP STRUCTURED-DATA [SP MSG]
  HEADER     = PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID
  PRI        = "<" PRIVAL ">"
  PRIVAL     = 1*3DIGIT  (0-191)
  VERSION    = NONZERO-DIGIT 0*2DIGIT  (must be >= 1)

Example:
  <134>1 2026-01-15T10:00:01Z gateway sshd 1234 - - Failed password for root

Returns None if the line does not conform to RFC 5424 framing (e.g. RFC 3164
or bare message). A result dict has keys: priority, version, timestamp,
hostname, app_name, proc_id, msg_id, structured_data, msg.
"""
from __future__ import annotations

import re

# RFC 5424 header regex (section 6.2).
# PRI = <digits>, VERSION = integer >= 1, remaining fields SP-delimited.
# TIMESTAMP is either a full-date 'T' time (RFC 3339) or '-'.
# STRUCTURED-DATA is '[...]+' or '-'.
_RFC5424_RE = re.compile(
    r"^<(\d{1,3})>"      # PRI: <PRIVAL>
    r"(\d+) "            # VERSION (space after)
    r"(\S+) "            # TIMESTAMP
    r"(\S+) "            # HOSTNAME
    r"(\S+) "            # APP-NAME
    r"(\S+) "            # PROCID
    r"(\S+) "            # MSGID
    r"(\S+)"             # STRUCTURED-DATA (may be '-')
    r"(?: (.*))?$",      # optional MSG (space + rest of line)
    re.DOTALL,
)


def parse_rfc5424(line: str) -> dict[str, str | None] | None:
    """Parse an RFC 5424 syslog message.

    Returns None if the line does not match RFC 5424 framing.
    RFC 3164 lines (no VERSION digit after PRI) return None.

    Result keys:
      priority, version, timestamp, hostname, app_name, proc_id,
      msg_id, structured_data, msg
    """
    m = _RFC5424_RE.match(line)
    if m is None:
        return None

    # RFC 5424 VERSION must be >= 1 (distinguishes it from RFC 3164 which has no version).
    try:
        version = int(m.group(2))
    except ValueError:
        return None
    if version < 1:
        return None

    return {
        "priority": m.group(1),
        "version": m.group(2),
        "timestamp": m.group(3),
        "hostname": m.group(4),
        "app_name": m.group(5),
        "proc_id": m.group(6),
        "msg_id": m.group(7),
        "structured_data": m.group(8),
        "msg": m.group(9),
    }
