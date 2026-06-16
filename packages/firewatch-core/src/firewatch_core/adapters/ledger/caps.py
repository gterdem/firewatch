"""Field-size caps and prune-count constants for the AI verdict ledger.

ADR-0044 §Security / §6:
- prompt_text and response_text are capped at 64 KiB each (FIELD_CAP_BYTES).
- Per-IP row limit: default 50 (PER_IP_CAP_DEFAULT).
- Global row limit: default 5 000 (GLOBAL_CAP_DEFAULT).

apply_field_caps() is the single enforcement point; the pipeline calls it
before every ledger.save() so caps are applied exactly once.

Security note (OWASP LLM05 / ADR-0044 §Security):
``prompt_text`` contains sentinel-wrapped attacker-controlled payloads.
``response_text`` is the raw model output, also potentially attacker-influenced
via indirect prompt injection (OWASP LLM01).  Capping both fields at the
storage layer prevents unbounded LOB growth and limits the blast radius of
a malicious payload that maximises field sizes.

The truncation sentinel ``[TRUNCATED]`` appended to cut fields is a fixed
ASCII string — it can never itself exceed the cap (11 bytes).
"""
from __future__ import annotations

from typing import Final

# 64 KiB = 65 536 bytes — the maximum stored size for prompt_text / response_text.
FIELD_CAP_BYTES: Final[int] = 64 * 1024

# Per-IP prune cap (ADR-0044 §6).  When a save() would push the row count for
# a given IP beyond this value, the oldest row(s) are deleted first.
PER_IP_CAP_DEFAULT: Final[int] = 50

# Global prune cap (ADR-0044 §6).  When total ai_analyses row count would exceed
# this value, the oldest row(s) are deleted first.
GLOBAL_CAP_DEFAULT: Final[int] = 5_000

# Appended to truncated fields so readers know the content was cut.
_TRUNCATED_SENTINEL: Final[str] = "[TRUNCATED]"


def _cap_text(text: str, cap_bytes: int = FIELD_CAP_BYTES) -> tuple[str, bool]:
    """Return ``(capped_text, was_truncated)``.

    Truncates *text* so that the final string (including the appended
    ``_TRUNCATED_SENTINEL``) encodes to at most *cap_bytes* bytes (UTF-8).

    The cap is applied on the encoded byte string, then decoded back to str to
    ensure the return type is always a valid Unicode string (no partial code-points).
    """
    encoded = text.encode("utf-8")
    if len(encoded) <= cap_bytes:
        return text, False
    # Reserve space for the sentinel so the final encoded size stays within cap_bytes.
    sentinel_bytes = len(_TRUNCATED_SENTINEL.encode("utf-8"))
    content_limit = cap_bytes - sentinel_bytes
    # Slice off incomplete trailing code-point by decoding with errors="ignore"
    # (UTF-8 sequences are at most 4 bytes, so at most 3 bytes are silently
    # dropped at the boundary — acceptable).
    truncated = encoded[:content_limit].decode("utf-8", errors="ignore")
    return truncated + _TRUNCATED_SENTINEL, True


def apply_field_caps(
    prompt_text: str,
    response_text: str,
    cap_bytes: int = FIELD_CAP_BYTES,
) -> tuple[tuple[str, str], dict[str, bool]]:
    """Apply 64 KiB caps to prompt_text and response_text.

    Returns ``((capped_prompt, capped_response), flags)`` where ``flags`` is a
    dict with keys ``"prompt_truncated"`` and/or ``"response_truncated"`` set to
    ``True`` only when the respective field was actually truncated.

    The caller persists ``flags`` as ``flags_json`` in the ai_analyses row so
    readers can detect truncation without re-reading the full text.
    """
    capped_prompt, prompt_truncated = _cap_text(prompt_text, cap_bytes)
    capped_response, response_truncated = _cap_text(response_text, cap_bytes)

    flags: dict[str, bool] = {}
    if prompt_truncated:
        flags["prompt_truncated"] = True
    if response_truncated:
        flags["response_truncated"] = True

    return (capped_prompt, capped_response), flags
