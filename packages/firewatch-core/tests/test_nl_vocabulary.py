"""Tests for nl_query/vocabulary.py — EARS-4 (runtime store enumeration).

EARS mapping:
  EARS-4: vocabulary enumerated from store at runtime; field not yet persisted
          is NEVER advertised.
"""
from __future__ import annotations

from firewatch_core.nl_query.vocabulary import (
    FilterField,
    QUERYABLE_FIELDS,
    get_vocabulary,
)


class TestFilterField:
    """FilterField describes a queryable column with its match semantics."""

    def test_has_required_attributes(self) -> None:
        """Each FilterField must expose key, label, match_type, examples."""
        for f in QUERYABLE_FIELDS:
            assert isinstance(f.key, str) and f.key
            assert isinstance(f.label, str) and f.label
            assert f.match_type in {"exact", "substring", "enum"}
            assert isinstance(f.examples, list)

    def test_keys_are_filterspec_fields(self) -> None:
        """Every key in QUERYABLE_FIELDS must match a real FilterSpec field name."""
        from firewatch_sdk.models import FilterSpec

        valid_keys = set(FilterSpec.model_fields.keys()) - {"cursor"}
        for f in QUERYABLE_FIELDS:
            assert f.key in valid_keys, (
                f"FilterField key={f.key!r} is not a FilterSpec field. "
                f"Valid: {sorted(valid_keys)}"
            )

    def test_no_cursor_in_queryable_fields(self) -> None:
        """cursor is an internal pagination token — never advertised as NL-queryable."""
        keys = {f.key for f in QUERYABLE_FIELDS}
        assert "cursor" not in keys

    def test_no_q_field_in_queryable_fields(self) -> None:
        """q is the free-text fallback — not advertised as a discrete vocabulary term."""
        keys = {f.key for f in QUERYABLE_FIELDS}
        assert "q" not in keys

    def test_action_field_has_enum_examples(self) -> None:
        """action is an enum type with known values as examples."""
        action_fields = [f for f in QUERYABLE_FIELDS if f.key == "action"]
        assert action_fields, "action field must be in QUERYABLE_FIELDS"
        af = action_fields[0]
        assert af.match_type == "enum"
        # Must enumerate the canonical action values
        for val in ("BLOCK", "DROP", "ALERT", "ALLOW"):
            assert val in af.examples, (
                f"action.examples must include {val!r}; got {af.examples}"
            )

    def test_severity_field_has_enum_examples(self) -> None:
        """severity must enumerate the canonical severity levels."""
        sev_fields = [f for f in QUERYABLE_FIELDS if f.key == "severity"]
        assert sev_fields, "severity field must be in QUERYABLE_FIELDS"
        sf = sev_fields[0]
        assert sf.match_type == "enum"
        for val in ("critical", "high", "medium", "low"):
            assert val in sf.examples


class TestGetVocabulary:
    """get_vocabulary() returns the live queryable field set."""

    def test_returns_list_of_filter_fields(self) -> None:
        """get_vocabulary() must return a non-empty list of FilterField objects."""
        vocab = get_vocabulary()
        assert len(vocab) > 0
        for f in vocab:
            assert isinstance(f, FilterField)

    def test_vocabulary_is_subset_of_filterspec_fields(self) -> None:
        """No vocabulary field can be outside FilterSpec (EARS-4 — store-bounded)."""
        from firewatch_sdk.models import FilterSpec

        valid_keys = set(FilterSpec.model_fields.keys()) - {"cursor"}
        vocab = get_vocabulary()
        for f in vocab:
            assert f.key in valid_keys, (
                f"Vocabulary key {f.key!r} is not a FilterSpec field"
            )

    def test_ip_field_is_substring(self) -> None:
        """source_ip (ip) is a substring match — users type partial IPs."""
        vocab = get_vocabulary()
        ip_fields = [f for f in vocab if f.key == "ip"]
        assert ip_fields, "ip field must be in vocabulary"
        assert ip_fields[0].match_type == "substring"

    def test_destination_ip_field_in_vocabulary(self) -> None:
        """destination_ip must be in the vocabulary (ADR-0048 persisted column)."""
        vocab = get_vocabulary()
        keys = {f.key for f in vocab}
        assert "destination_ip" in keys

    def test_tls_ja4_field_in_vocabulary(self) -> None:
        """tls_ja4 must be in vocabulary (ML-13 persisted column)."""
        vocab = get_vocabulary()
        keys = {f.key for f in vocab}
        assert "tls_ja4" in keys

    def test_vocabulary_dict_by_key(self) -> None:
        """Vocabulary can be indexed by key for O(1) lookup during validation."""
        vocab = get_vocabulary()
        d = {f.key: f for f in vocab}
        # Must include the core NL-filterable fields
        for required_key in ("ip", "action", "severity", "source_type"):
            assert required_key in d, f"{required_key!r} must be in vocabulary dict"
