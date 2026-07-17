"""Field-size caps and the valid-verb set for the decisions store (ADR-0072 D2).

Design mirrors ``adapters/cases/caps.py``: bound every free-text field before
it reaches SQLite so a pathological client cannot grow an unbounded LOB.
"""
from __future__ import annotations

from typing import Final

#: The three verbs (ADR-0070 D6 / ADR-0072 D2) — mirrors the DB CHECK constraint.
VALID_VERBS: Final[frozenset[str]] = frozenset({"expected", "dismissed", "false_positive"})

#: Maximum length for the operator-authored `note` field.
MAX_NOTE_CHARS: Final[int] = 2_000

#: Maximum length for `rule_name` (targets a FireWatch rule identity, not free
#: prose — generous bound for defense-in-depth only).
MAX_RULE_NAME_CHARS: Final[int] = 500

#: Maximum length for `actor_ip` (IPv6 literals are <= 45 chars; generous bound).
MAX_ACTOR_IP_CHARS: Final[int] = 64

#: Default / max page size for GET /decisions (ADR-0029 D2 cursor pagination).
DEFAULT_LIMIT: Final[int] = 50
MAX_LIMIT: Final[int] = 200
