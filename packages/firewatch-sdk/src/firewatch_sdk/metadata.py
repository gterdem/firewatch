"""Source-plugin metadata (the value `SourcePlugin.metadata()` returns).

This is a data carrier the plugin constructs about itself — it drives the UI source
card (PLUGIN_CONTRACT.md) — so it is a Pydantic model, not a Protocol.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Import SourceAction at module level so Pydantic can resolve the forward reference
# in the `actions` field at class-build time.  actions.py only imports PluginContext
# under TYPE_CHECKING, so there is no circular import at runtime.
from firewatch_sdk.actions import SourceAction  # noqa: E402 — must follow __future__
# ADR-0067 D6 (issue #75): the enforcement-posture literal lives in models.py
# alongside the other escalation-adjacent literals (SeverityLiteral, etc.).
# models.py imports nothing from metadata.py, so this module-level import carries
# no circular-import risk (same reasoning as the SourceAction import above).
from firewatch_sdk.models import EnforcementPostureLiteral  # noqa: E402 — must follow __future__

FlavorLiteral = Literal["pull", "push"]

# `type_key` flows into every event's `source_type` — and thus event IDs, dedup, and the
# (source_type, source_id) watermark — so it must be a safe key token (PLUGIN_CONTRACT.md).
#
# Pattern `^[a-z][a-z0-9_]*$`: must start with a lowercase letter (not a digit or
# underscore). Leading underscore is RESERVED FOR CORE: core uses underscore-prefixed
# source_type sentinels (e.g. `_global`) for its own internal scopes, so a plugin can never
# declare one and collide with them (ADR-0025 addendum, BLOCKING-2).
TYPE_KEY_PATTERN = r"^[a-z][a-z0-9_]*$"


def _security_event_field_names() -> frozenset[str]:
    """Return the set of declared field names on SecurityEvent.

    Imported lazily to avoid any risk of circular import at module load time
    (models.py imports nothing from metadata.py, so the import is safe; the
    lazy call just makes the dependency direction explicit and testable).
    """
    from firewatch_sdk.models import SecurityEvent  # noqa: PLC0415 — intentional lazy import
    return frozenset(SecurityEvent.model_fields.keys())


class SourceMetadata(BaseModel):
    """What a plugin declares about itself.

    `type_key` is the constant `source_type` the plugin owns — its entry-point key
    (e.g. ``suricata``), ≈ ECS ``event.module`` (ADR-0016). `flavor` selects the
    collection protocol the plugin also implements (PullSource vs PushSource, ADR-0005).

    `actions` is an optional tuple of ``SourceAction`` declarations (ADR-0034).
    Existing plugins that omit this field default to an empty tuple — zero edits
    required to keep them loading.  A plugin that declares actions MUST also
    satisfy the ``ActionCapable`` protocol (checked at serve time).

    `produces` is an optional frozenset of canonical ``SecurityEvent`` field names
    this source can emit (ADR-0060).  The default empty set means "does not declare /
    unknown" which is treated as "produces everything" by consumers — full backward-
    compatibility.  A source opts in to column-hiding by declaring its set.
    Members are validated against ``SecurityEvent.model_fields`` at construction;
    an unknown member (e.g. a typo) fails construction immediately (fail-closed).

    `enforcement` is an optional declared default for the ADR-0067 D6 enforcement-posture
    axis — what this source's producing control COULD have done to traffic it observed
    (`observe` / `enforce` / `detect_only`).  Additive, defaulted to ``None``
    ("undeclared") so every existing plugin stays byte-compatible.  Core resolves this
    per-instance default (`firewatch_core.escalation.posture`) into the posture map the
    decider consumes to replace the generic "block status unknown" Tier-2 label with an
    honest, posture-specific one (issue #75).  Posture is core's interpretation knob, not
    plugin config — declaring it here is the *plugin-declared default* half only; the
    per-instance override (Phase B, issue #44) is core-owned and lives elsewhere.
    """

    model_config = ConfigDict(frozen=True)

    type_key: str = Field(pattern=TYPE_KEY_PATTERN)
    display_name: str
    version: str
    flavor: FlavorLiteral
    # ADR-0034: additive, optional — defaults to empty so existing plugins are
    # unaffected.  SourceAction is imported at module level so Pydantic resolves
    # the type annotation without needing model_rebuild().
    actions: tuple[SourceAction, ...] = ()
    # ADR-0060: canonical SecurityEvent field names this source can emit.
    # Empty (the default) = "produces everything" → no column hiding (backward-compat).
    # Declaring a non-empty set opts the source into structural column hiding.
    # Each member is validated against SecurityEvent.model_fields at construction
    # (fail-closed: an unknown name → ValidationError, catching typos early).
    produces: frozenset[str] = frozenset()
    # ADR-0067 D6 (issue #75, Phase A): declared enforcement-posture default.
    # None (the default) = "undeclared" → the decider keeps the conservative
    # block_status_unknown label for this source's qualified Tier-2 verdicts.
    enforcement: EnforcementPostureLiteral | None = None

    @field_validator("produces", mode="before")
    @classmethod
    def _validate_produces_members(cls, v: object) -> object:
        """Reject any member that is not a SecurityEvent field name.

        This is the fail-closed typo guard (ADR-0060 D1): a misspelled field name
        in a plugin's `produces` declaration would silently hide the wrong column,
        so we reject it at construction time rather than letting it propagate.

        The validator runs in ``mode="before"`` so it sees the raw input (set,
        frozenset, list, …) before Pydantic coerces it to frozenset.
        """
        if not v:
            # Empty set / None / falsy → accept as-is; Pydantic will coerce to frozenset().
            return v
        # Normalise to an iterable of strings for validation.
        members: set[str] = set(v)  # type: ignore[arg-type]
        valid_fields = _security_event_field_names()
        unknown = members - valid_fields
        if unknown:
            sorted_unknown = sorted(unknown)
            raise ValueError(
                f"produces contains field name(s) not present on SecurityEvent: "
                f"{sorted_unknown}. "
                f"Check for typos; valid names are the fields of SecurityEvent."
            )
        return v
