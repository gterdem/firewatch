"""Suricata .rules file parser — extracts rule_id (sid) → description (msg) mappings.

Produces ``dict[str, str]`` that callers can persist via the EventStore's
``upsert_rule_descriptions()`` method.  This keeps the rule-description population
fully on the plugin side; the core orchestrator never needs to know the source type.

Design notes
------------
* Only stdlib (``re``, ``pathlib``); no core package imports, no legacy/.
* ``parse_rules_file`` handles one .rules file; ``parse_rules_dir`` aggregates a dir.
* Fail-safe: missing files/dirs return ``{}`` (no raise).
* Comment lines (``#``) are skipped, including disabled rules (``#alert …``).
* Rules without both ``msg:`` and ``sid:`` are skipped.
* NB-4 — File size cap: files larger than ``_MAX_RULES_BYTES`` (50 MB) are read
  line-by-line and parsing stops at the cap to avoid OOM on crafted/huge inputs.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger("firewatch.suricata.rules")

# Regex to extract msg: field value (text between double-quotes after "msg:")
_MSG_RE = re.compile(r'\bmsg\s*:\s*"([^"]*)"')

# Regex to extract sid: field value (digits after "sid:")
_SID_RE = re.compile(r'\bsid\s*:\s*(\d+)')

# Maximum bytes to read from a single .rules file (NB-4: OOM guard)
_MAX_RULES_BYTES = 50 * 1024 * 1024  # 50 MB

# Maximum length for a single rule msg: field value (security-review NB, PR #186).
# Oversized msg strings are silently truncated before KV storage to prevent
# unbounded strings from reaching the store and the UI. 512 chars is generous
# for any real Suricata rule description.
_MAX_MSG_LEN = 512


def parse_rules_file(path: Path | str) -> dict[str, str]:
    """Parse a single Suricata .rules file and return {sid: msg} mappings.

    Parameters
    ----------
    path:
        Path to a ``.rules`` file.

    Returns
    -------
    dict[str, str]
        Mapping of rule SID (as string) to the human-readable ``msg:`` description.
        Returns ``{}`` if the file does not exist or cannot be read.

    Notes
    -----
    Files larger than ``_MAX_RULES_BYTES`` (50 MB) are read line-by-line and
    parsing stops once the cumulative byte count exceeds the cap.  This prevents
    OOM on crafted or accidentally huge ``.rules`` files (NB-4).
    """
    file_path = Path(path)
    if not file_path.exists():
        logger.debug("parse_rules_file: file not found: %s", file_path)
        return {}

    result: dict[str, str] = {}
    bytes_read = 0
    try:
        with file_path.open(encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                bytes_read += len(raw_line.encode("utf-8", errors="replace"))
                if bytes_read > _MAX_RULES_BYTES:
                    logger.warning(
                        "parse_rules_file: %s exceeds %d-byte cap; truncating parse",
                        file_path,
                        _MAX_RULES_BYTES,
                    )
                    break
                stripped = raw_line.strip()
                # Skip blank lines and comments (including disabled rules: #alert ...)
                if not stripped or stripped.startswith("#"):
                    continue

                sid_match = _SID_RE.search(stripped)
                msg_match = _MSG_RE.search(stripped)

                if sid_match and msg_match:
                    sid = sid_match.group(1)
                    msg = msg_match.group(1)[:_MAX_MSG_LEN]
                    result[sid] = msg
    except OSError as exc:
        logger.warning("parse_rules_file: cannot read %s: %s", file_path, exc)
        return {}

    return result


def parse_rules_dir(directory: Path | str) -> dict[str, str]:
    """Parse all ``.rules`` files in *directory* and return combined {sid: msg} mappings.

    Files that are not ``.rules`` are ignored. Non-existent or unreadable directories
    return ``{}``.

    Parameters
    ----------
    directory:
        Path to a directory containing Suricata ``.rules`` files.

    Returns
    -------
    dict[str, str]
        Combined mapping of rule SID → ``msg`` description from all ``.rules`` files.
    """
    dir_path = Path(directory)
    if not dir_path.is_dir():
        logger.debug("parse_rules_dir: not a directory: %s", dir_path)
        return {}

    combined: dict[str, str] = {}
    for rules_file in sorted(dir_path.glob("*.rules")):
        file_result = parse_rules_file(rules_file)
        combined.update(file_result)
        if file_result:
            logger.debug(
                "parse_rules_dir: parsed %d rules from %s",
                len(file_result),
                rules_file.name,
            )

    return combined
