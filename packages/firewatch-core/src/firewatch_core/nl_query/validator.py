"""Strict allowlist validator for LLM-emitted FilterSpec candidates.

ADR-0049 Decision 2 / Security boundary:
  The LLM output is treated as UNTRUSTED input (OWASP LLM01 prompt injection).
  Every field key and value is validated against the runtime vocabulary before
  any FilterSpec is constructed.  Any out-of-vocabulary field or value, or a
  low-confidence parse, degrades gracefully to a plain ``q`` free-text search
  (EARS-1, EARS-2).

Validation rules
----------------
1. Field key must be in the vocabulary (EARS-4 — no unadvertised fields).
2. Enum fields (action, severity) — value must be in the field's examples set
   (case-insensitive for severity; canonical case for action).
3. Substring/exact fields — value is length-capped at MAX_VALUE_LEN (200 chars)
   to prevent oversized inputs.  No structural validation beyond that:
   values always flow through SQLite ? placeholders, never SQL strings.
4. Confidence below CONFIDENCE_THRESHOLD → degrade to q= (EARS-2).
5. Empty candidate dict → degrade to q=.

The resulting FilterSpec is NEVER built from free-form NL→SQL.  It contains
only fields from the closed vocabulary, each carried in a ? placeholder by the
store layer.  This bounds the injection surface to the same level as manual
filter chips (ADR-0049 §No free SQL).

Public API
----------
    validate_candidate(candidate, nl_text, vocab) -> FilterSpec
        Validate and build a FilterSpec from the LLM candidate dict.
        On any violation, returns FilterSpec(q=nl_text) — the safe fallback.

    validate_candidate_strict(candidate, vocab) -> dict[str, str] | None
        Lower-level: returns the cleaned dict or None on any violation.
        Used in tests to inspect the validation result without a fallback.
"""
from __future__ import annotations

import logging
from typing import Any

from firewatch_sdk.models import FilterSpec

from firewatch_core.nl_query.vocabulary import FilterField, get_vocabulary

logger = logging.getLogger("firewatch.nl_query.validator")

# Minimum confidence the LLM must emit for its parse to be accepted.
# Values below this threshold degrade to q= free-text (EARS-2).
CONFIDENCE_THRESHOLD: float = 0.5

# Maximum character length for any single field value.
# Values longer than this are rejected as likely hallucinated or injected.
MAX_VALUE_LEN: int = 200

# The reserved key used by the LLM to communicate its parse confidence.
# The LLM emits {"confidence": 0.0–1.0, "filters": {...}} or a flat dict.
_CONFIDENCE_KEY: str = "confidence"
_FILTERS_KEY: str = "filters"


def _known_vocab_by_key(vocab: list[FilterField]) -> dict[str, FilterField]:
    """Build a key→FilterField lookup dict from the vocabulary list."""
    return {f.key: f for f in vocab}


def _validate_value(field_def: FilterField, raw_value: Any) -> str | None:
    """Validate and normalise a single field value against its field definition.

    Returns the cleaned string value on success, or None on failure.

    Normalisation rules:
    - Value must be a non-empty string (after str() coercion of simple types).
    - Value length must not exceed MAX_VALUE_LEN.
    - Enum fields: value must be in examples (case-insensitive for severity).
    """
    # Coerce to string — LLM may emit numbers for integer-ish values.
    if not isinstance(raw_value, (str, int, float)):
        logger.debug(
            "nl_validator: field=%r has unsupported type %r — rejected",
            field_def.key,
            type(raw_value).__name__,
        )
        return None

    value = str(raw_value).strip()
    if not value:
        return None

    if len(value) > MAX_VALUE_LEN:
        logger.warning(
            "nl_validator: field=%r value length %d exceeds cap %d — rejected",
            field_def.key,
            len(value),
            MAX_VALUE_LEN,
        )
        return None

    if field_def.match_type == "enum":
        # Case-insensitive match for severity; case-preserved for others.
        if field_def.key == "severity":
            normalised = value.lower()
            if normalised not in {e.lower() for e in field_def.examples}:
                logger.debug(
                    "nl_validator: enum field=%r value=%r not in %r — rejected",
                    field_def.key,
                    value,
                    field_def.examples,
                )
                return None
            return normalised
        else:
            # action: case-insensitive match, but return the canonical casing
            # from examples (e.g. "block" → "BLOCK").
            lower_val = value.lower()
            for ex in field_def.examples:
                if ex.lower() == lower_val:
                    return ex  # canonical casing from vocabulary
            logger.debug(
                "nl_validator: enum field=%r value=%r not in %r — rejected",
                field_def.key,
                value,
                field_def.examples,
            )
            return None

    # substring / exact: length already checked above; accept as-is.
    return value


def validate_candidate_strict(
    candidate: dict[str, Any],
    vocab: list[FilterField] | None = None,
) -> dict[str, str] | None:
    """Validate the LLM candidate dict against the vocabulary.

    Parameters
    ----------
    candidate:
        Raw dict from the LLM.  Expected shape:
          ``{"confidence": float, "filters": {"field": "value", ...}}``
        or a flat dict ``{"field": "value", ..., "confidence": float}``.
        Any key not in the vocabulary is silently dropped (strict allowlist).
    vocab:
        Vocabulary to validate against.  Defaults to ``get_vocabulary()``.

    Returns
    -------
    dict[str, str] | None
        Cleaned field→value dict on success, or ``None`` when:
        - confidence < CONFIDENCE_THRESHOLD, OR
        - no valid field/value pairs remain after filtering.
    """
    if vocab is None:
        vocab = get_vocabulary()

    vocab_by_key = _known_vocab_by_key(vocab)

    # Extract confidence — may be top-level or inside a "filters" sub-dict.
    confidence_raw = candidate.get(_CONFIDENCE_KEY)
    if confidence_raw is None and _FILTERS_KEY in candidate:
        # Flat envelope: {"confidence": ..., "filters": {...}}
        # confidence already extracted above; nothing more to do.
        pass

    try:
        confidence = float(confidence_raw) if confidence_raw is not None else 0.0
    except (ValueError, TypeError):
        confidence = 0.0

    if confidence < CONFIDENCE_THRESHOLD:
        logger.info(
            "nl_validator: confidence=%.2f below threshold %.2f — degrading",
            confidence,
            CONFIDENCE_THRESHOLD,
        )
        return None

    # Extract the filter dict — support both the wrapped and flat shapes.
    if _FILTERS_KEY in candidate and isinstance(candidate[_FILTERS_KEY], dict):
        raw_filters: dict[str, Any] = candidate[_FILTERS_KEY]
    else:
        # Flat shape — strip known meta keys.
        raw_filters = {
            k: v
            for k, v in candidate.items()
            if k not in (_CONFIDENCE_KEY, _FILTERS_KEY)
        }

    cleaned: dict[str, str] = {}
    for key, raw_value in raw_filters.items():
        field_def = vocab_by_key.get(key)
        if field_def is None:
            logger.info(
                "nl_validator: key=%r not in vocabulary — rejected (EARS-4)",
                key,
            )
            continue  # strict allowlist: ignore OOV keys

        validated = _validate_value(field_def, raw_value)
        if validated is not None:
            cleaned[key] = validated
        else:
            # SHOULD-FIX-3: sanitize before logging to prevent log-injection.
            # Log a length + control-char-stripped preview, not the raw value.
            _safe_preview = repr(raw_value)[:80]
            logger.info(
                "nl_validator: key=%r value (len=%d, preview=%s) failed validation — rejected",
                key,
                len(str(raw_value)),
                _safe_preview,
            )

    if not cleaned:
        logger.info("nl_validator: no valid fields after validation — degrading")
        return None

    return cleaned


def validate_candidate(
    candidate: dict[str, Any],
    nl_text: str,
    vocab: list[FilterField] | None = None,
) -> tuple[FilterSpec, bool]:
    """Validate the LLM candidate and return a safe FilterSpec.

    This is the primary public entry point.  It always returns a usable
    FilterSpec — on validation failure it degrades to ``FilterSpec(q=nl_text)``
    (EARS-2).

    Parameters
    ----------
    candidate:
        Raw dict emitted by the LLM (see ``validate_candidate_strict``).
    nl_text:
        The original natural-language query string.  Used as the ``q=``
        fallback value when validation fails.
    vocab:
        Vocabulary to validate against.  Defaults to ``get_vocabulary()``.

    Returns
    -------
    (FilterSpec, degraded: bool)
        ``degraded=True`` when the result is a plain ``q=`` fallback (EARS-2).
        ``degraded=False`` when validation succeeded and the FilterSpec carries
        the LLM-parsed fields.
    """
    if vocab is None:
        vocab = get_vocabulary()

    cleaned = validate_candidate_strict(candidate, vocab)
    if cleaned is None:
        logger.info("nl_validator: degrading to q=%r free-text fallback", nl_text[:80])
        return FilterSpec(q=nl_text), True

    # Build FilterSpec from validated field dict.
    # Only fields declared in FilterSpec are accepted (vocabulary already
    # enforces this, but Pydantic validates as the second layer).
    try:
        spec = FilterSpec(**cleaned)
        return spec, False
    except Exception as exc:
        # Defensive: Pydantic rejected a value that slipped through validation.
        # Log and degrade (fail-closed).
        logger.warning(
            "nl_validator: FilterSpec construction failed (%s) — degrading",
            type(exc).__name__,
        )
        return FilterSpec(q=nl_text), True
