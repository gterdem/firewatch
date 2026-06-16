"""RFC 3164 BSD syslog framing parser.

Standard reference:
  RFC 3164 - The BSD Syslog Protocol (August 2001)
  https://datatracker.ietf.org/doc/html/rfc3164

RFC 3164 message format (section 4.1):
  MSG = PRI HEADER MSG
  PRI = "<" PRIVAL ">"
  HEADER = TIMESTAMP SP HOSTNAME
  TIMESTAMP = Mmm DD HH:MM:SS  (e.g. "Jan 15 10:00:01")
  MSG = TAG [CONTENT]

Example:
  <134>Jan 15 10:00:01 gateway sshd[1234]: Failed password for root

Returns None if the line does not conform to RFC 3164 framing.
Result dict has keys: priority, timestamp, hostname, tag, proc_id, msg.
"""
from __future__ import annotations

import re

# Month abbreviations per RFC 3164 section 4.1.2.
_MONTHS = (
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
)
_MONTH_PAT = "|".join(_MONTHS)

# RFC 3164 header: <PRI>Mmm [D]D HH:MM:SS HOSTNAME TAG[PID]: MSG
# Day may be space-padded (single digit) or zero-padded.
_RFC3164_RE = re.compile(
    r"^<(\d{1,3})>"                         # PRI
    rf"({_MONTH_PAT})\s+(\d{{1,2}})"        # Month Day
    r"\s+(\d{2}:\d{2}:\d{2})"              # HH:MM:SS
    r"\s+(\S+)"                             # HOSTNAME
    r"\s+([^\s:\[]+)"                       # TAG (appname, no space/colon/bracket)
    r"(?:\[(\d+)\])?"                       # optional [PID]
    r"[:\s]+(.*)?$",                        # colon/space then MSG
    re.DOTALL,
)


def parse_rfc3164(line: str) -> dict[str, str | None] | None:
    """Parse an RFC 3164 (BSD) syslog message.

    Returns None if the line does not match RFC 3164 framing.

    Result keys:
      priority, month, day, time, hostname, tag, proc_id, msg
    """
    m = _RFC3164_RE.match(line)
    if m is None:
        return None

    return {
        "priority": m.group(1),
        "timestamp": f"{m.group(2)} {m.group(3)} {m.group(4)}",
        "hostname": m.group(5),
        "tag": m.group(6),
        "proc_id": m.group(7),
        "msg": m.group(8),
    }
