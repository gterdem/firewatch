"""Field-size caps and prune-count constants for the cases store (ADR-0053 D4).

Design mirrors ledger/caps.py:
- Note body capped at 32 KiB (conservative; notes are analyst prose, not LLM output).
- Per-case note cap: 200 notes per case (sufficient for any real investigation).
- Per-case event-reference cap: 1 000 refs (prevents unbounded fan-out via link_event).

Security note (OWASP API3:2023 — Excessive Data Exposure):
  body_md is operator-authored text but may embed attacker-controlled content
  (e.g. a paste of a suspicious payload).  Capping at the storage layer prevents
  unbounded LOB growth.  The UI must render body_md as sanitized text/markdown —
  never raw HTML (ADR-0029 D3 / ADR-0053 D2).
"""
from __future__ import annotations

from typing import Final

# Maximum size in characters for a single note body.
# 32 KiB of UTF-8 prose is generous for any analyst note.
MAX_NOTE_BODY_CHARS: Final[int] = 32_768

# Maximum number of notes per case file.
MAX_NOTES_PER_CASE: Final[int] = 200

# Maximum number of event/analysis references linked to a single case.
MAX_EVENTS_PER_CASE: Final[int] = 1_000

# Valid disposition values (EARS-5).
VALID_DISPOSITIONS: Final[frozenset[str]] = frozenset(
    {"true-positive", "false-positive", "benign", "open"}
)

# Valid status values.
VALID_STATUSES: Final[frozenset[str]] = frozenset({"open", "closed"})
