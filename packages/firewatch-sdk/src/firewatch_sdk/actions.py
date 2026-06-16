"""Source maintenance action types (ADR-0034).

Plugins that implement operational actions against a source instance declare
them as ``SourceAction`` entries in ``SourceMetadata.actions``.  The supervisor
discovers actions through the ``ActionCapable`` protocol, invokes them via
``run_action``, and reads per-action status via ``action_status``.

Model hierarchy
---------------
``SourceAction``
    A declarative description of one action a plugin supports.  Frozen —
    the plugin declares this at import time; it never changes at runtime.

``ActionResult``
    The return value of a single ``run_action`` invocation.  Frozen — the
    supervisor serialises this to the caller after the action completes.

``ActionStatus``
    A per-action status snapshot (last-run time, staleness hint, optional
    message).  Returned by ``action_status``; the route zips it with the
    matching ``SourceAction`` declaration to produce the GET response.

``ActionCapable``
    A runtime-checkable Protocol.  Plugins that declare a non-empty
    ``metadata().actions`` MUST also satisfy this protocol (the loader
    validates this via ``isinstance``).
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, field_validator

if TYPE_CHECKING:
    from firewatch_sdk.context import PluginContext

# action_id pattern matches type_key: lowercase letter then lowercase-alnum-underscore.
ACTION_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")

# NB-5: per-element pattern for SourceAction.provides.
# Allows a leading underscore (e.g. "_internal") in addition to a lowercase
# letter, then lowercase alnum + underscore.  max_length=64 is enforced via
# the field_validator below.  Pattern is consistent with common Python
# identifier conventions (snake_case tag names).
_PROVIDES_ELEMENT_PATTERN = re.compile(r"^[a-z_][a-z0-9_]*$")
_PROVIDES_ELEMENT_MAX_LEN = 64


class SourceAction(BaseModel):
    """Declarative description of one maintenance action a plugin supports.

    Fields
    ------
    id:
        Machine-readable identifier.  Pattern ``^[a-z][a-z0-9_]*$`` — same
        token rules as ``type_key``.  Used as the ``{action_id}`` path
        segment in the API routes; MUST NOT be interpolated into a shell,
        path, or URL (ADR-0034 §security).
    label:
        Short human-readable name for the Settings card button.
    description:
        One-sentence explanation of what the action does.
    long_running:
        UI hint only.  ``True`` when the action typically takes more than a
        few seconds (e.g. a full ruleset download).  The v1 API awaits
        completion regardless; progress reporting is deferred to issue #139.
    confirm:
        Optional confirmation prompt shown by the UI before invoking.
        ``None`` means no confirmation is required.
    provides:
        Facet tags that the action produces (e.g. ``("rule_descriptions",)``).
        Each element must match ``^[a-z_][a-z0-9_]*$`` with max_length=64
        (NB-5 — consistent with action_id token rules; blocks injected values).
        Used by the UI to know which data the action refreshes.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    label: str
    description: str
    long_running: bool = False
    confirm: str | None = None
    provides: tuple[str, ...] = ()

    @field_validator("id")
    @classmethod
    def _id_matches_pattern(cls, v: str) -> str:
        if not ACTION_ID_PATTERN.match(v):
            raise ValueError(
                f"action id {v!r} must match ^[a-z][a-z0-9_]*$"
            )
        return v

    @field_validator("provides", mode="before")
    @classmethod
    def _provides_elements_valid(cls, v: object) -> object:
        """NB-5: validate each element of provides for pattern and max_length."""
        if not isinstance(v, (list, tuple)):
            return v  # let pydantic handle type errors
        for element in v:
            if not isinstance(element, str):
                continue  # let pydantic handle type errors
            if len(element) == 0:
                raise ValueError(
                    f"provides element {element!r} must not be empty"
                )
            if len(element) > _PROVIDES_ELEMENT_MAX_LEN:
                raise ValueError(
                    f"provides element {element!r} exceeds max_length={_PROVIDES_ELEMENT_MAX_LEN}"
                )
            if not _PROVIDES_ELEMENT_PATTERN.match(element):
                raise ValueError(
                    f"provides element {element!r} must match ^[a-z_][a-z0-9_]*$"
                )
        return v


class ActionResult(BaseModel):
    """The result of a single ``run_action`` invocation.

    Fields
    ------
    ok:
        ``True`` when the action completed successfully.
    message:
        Human-readable summary of the outcome.
    detail:
        Optional key/value pairs carrying action-specific output (e.g. rule
        counts, file paths).  Strings only — plugins must not embed binary
        data here.
    """

    model_config = ConfigDict(frozen=True)

    ok: bool
    message: str
    detail: dict[str, str] = {}


class ActionStatus(BaseModel):
    """Per-action status snapshot returned by ``action_status``.

    Fields
    ------
    last_run_at:
        Wall-clock timestamp (seconds since epoch) of the most recent
        invocation, or ``None`` if the action has never been run.
    stale:
        Optional staleness hint.  ``True`` when the action's output is
        considered out-of-date (e.g. ruleset not fetched for >24 h).
        ``None`` when the plugin cannot determine freshness.
    message:
        Optional one-line status message (e.g. ``"2 048 rules loaded"``).
    detail:
        Optional supplementary key/value pairs (e.g. ``{"rule_count": "2048"}``).
    """

    model_config = ConfigDict(frozen=True)

    last_run_at: float | None = None
    stale: bool | None = None
    message: str | None = None
    detail: dict[str, str] = {}


# Null-status sentinel used when a plugin's action_status raises: this avoids
# a 500 and signals "status unavailable" to the caller (ADR-0034 §resilience).
NULL_ACTION_STATUS = ActionStatus()


@runtime_checkable
class ActionCapable(Protocol):
    """Protocol for plugins that declare maintenance actions.

    A plugin that includes a non-empty ``metadata().actions`` MUST also
    satisfy this protocol.  The loader validates this via ``isinstance``
    before the plugin is served through discovery or action routes
    (ADR-0034 §loader — resilient-discovery posture: a violating plugin is
    omitted/flagged without breaking discovery for others).

    Both methods receive the same ``cfg`` and ``ctx`` objects as the collection
    entrypoints so plugins can reuse their configuration and KV state.

    ``run_action`` MUST NOT block the event loop for long-running operations;
    it should use ``asyncio.to_thread`` for CPU/IO-bound work.

    ``action_status`` is a READ-ONLY status query.  It MUST NOT trigger
    network calls, SSH connections, or any other side effect — the route
    calls it while assembling the GET response and cannot tolerate network
    latency there (ADR-0034 §long-running-semantics).
    """

    async def run_action(
        self,
        action_id: str,
        cfg: Any,
        ctx: "PluginContext",
    ) -> ActionResult:
        """Execute the named maintenance action and return a result.

        Args:
            action_id: The action's ``SourceAction.id`` (already validated
                       against the declared set by the supervisor before this
                       is called — see ADR-0034).
            cfg:       The plugin's validated config model.
            ctx:       A ``PluginContext`` for the running instance (ADR-0027).

        Returns:
            ``ActionResult(ok=True, …)`` on success; ``ActionResult(ok=False, …)``
            on expected failure.  MUST NOT raise (callers do not catch exceptions
            from this method — an uncaught exception propagates as a 500).
        """
        ...

    async def action_status(
        self,
        action_id: str,
        cfg: Any,
        ctx: "PluginContext",
    ) -> ActionStatus:
        """Return the current status of the named action without side effects.

        This is called on the request path (GET /sources/{type}/actions);
        it MUST be fast and MUST NOT open network connections or read SSH hosts.
        Read from local KV / in-memory state only.

        Args:
            action_id: The action's ``SourceAction.id``.
            cfg:       The plugin's validated config model.
            ctx:       A ``PluginContext`` for the running instance (ADR-0027).

        Returns:
            ``ActionStatus`` snapshot.  A raising implementation is caught by
            the route and replaced with ``NULL_ACTION_STATUS`` (resilient
            degradation — no 500 on a bad status read).
        """
        ...
