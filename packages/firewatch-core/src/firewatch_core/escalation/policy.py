"""Per-detection severity and escalation-policy registry (ADR-0058 D1 — C foundation).

``EscalationPolicyRegistry`` holds the declared metadata for each correlation rule:
a Sigma-anchored ``severity`` level and an ``auto_escalate`` boolean.  It is populated
at module import time by ``detector.py`` (the rule author declares metadata alongside
the rule itself).

Design constraints (ADR-0058 §D1):
- Default is **non-escalating**: any rule not in the registry returns
  ``RulePolicy(severity=None, auto_escalate=False)``.
- No score math, no pipeline wiring in this module.  It is pure data.
- Consumed by ``decider.py`` (issue #648) and by ``detector.py``
  which attaches the policy fields to each ``Detection`` it emits.

Security constraints (issue #648 N-1 / N-2):
- N-1: ``RulePolicy`` is ``frozen=True`` — a shared sentinel returned by
  ``get_or_default()`` cannot be silently mutated by any consumer.
- N-2: ``EscalationPolicyRegistry.finalize()`` locks the registry after
  module-import time; subsequent ``register()`` calls raise ``RuntimeError``.
  Call ``finalize()`` once after all ``detector.py`` registrations are done,
  before the decider consumes ``auto_escalate`` for routing decisions.

Standard anchor:
- Sigma ``level`` severity vocabulary —
  https://sigmahq.io/docs/basics/rules.html
- Elastic Detection Rules ``risk_score`` intent —
  https://www.elastic.co/guide/en/security/current/rules-ui-create.html
"""
from __future__ import annotations

from dataclasses import dataclass, field

from firewatch_sdk.models import SeverityLiteral


@dataclass(frozen=True)
class RulePolicy:
    """Declared escalation metadata for one correlation rule.

    N-1 (issue #648): ``frozen=True`` — the shared ``_DEFAULT_POLICY`` sentinel
    and any policy returned by the registry cannot be mutated by consumers.
    Mutation attempts raise ``dataclasses.FrozenInstanceError`` at runtime and are
    caught by Pyright statically.

    ``severity``       — Sigma-anchored level (``SeverityLiteral | None``).
                         ``None`` means the rule has not declared a severity.
    ``auto_escalate``  — ``True`` when the rule is loud enough to jump the triage
                         queue without waiting for volume or AI confirmation.
                         Consumed by the D2 decider (issue #648).
    """

    severity: SeverityLiteral | None = None
    auto_escalate: bool = field(default=False)


# Module-level sentinel for the non-escalating default.
# frozen=True on RulePolicy ensures this shared object cannot be mutated (N-1).
_DEFAULT_POLICY = RulePolicy(severity=None, auto_escalate=False)


class EscalationPolicyRegistry:
    """Lookup table: rule_name → RulePolicy.

    ``detector.py`` calls ``ESCALATION_POLICY.register(...)`` once per rule at
    module import time.  Call ``finalize()`` once after all registrations to lock
    the registry against post-import writes (N-2).

    Thread-safety: the registry is populated at module import (single-threaded),
    then only read.  No lock needed for normal use.
    """

    def __init__(self) -> None:
        self._policies: dict[str, RulePolicy] = {}
        self._frozen: bool = False

    def finalize(self) -> None:
        """Lock the registry — subsequent ``register()`` calls will raise.

        N-2 (issue #648): call once after ``detector.py`` finishes all
        module-import-time registrations.  Idempotent: calling twice is harmless.
        """
        self._frozen = True

    def register(
        self,
        rule_name: str,
        *,
        severity: SeverityLiteral | None,
        auto_escalate: bool = False,
    ) -> None:
        """Declare the escalation policy for ``rule_name``.

        Called once per rule at module-import time in ``detector.py``.
        Re-registration overwrites the previous entry (safe for test monkeypatching)
        **only before** ``finalize()`` is called.

        Raises ``RuntimeError`` if the registry has been finalized (N-2).
        """
        if self._frozen:
            raise RuntimeError(
                f"EscalationPolicyRegistry is finalized — cannot register "
                f"rule {rule_name!r} after module-import time. "
                "Call register() only at module import in detector.py."
            )
        self._policies[rule_name] = RulePolicy(
            severity=severity,
            auto_escalate=auto_escalate,
        )

    def get(self, rule_name: str) -> RulePolicy | None:
        """Return the declared policy or ``None`` if the rule has not registered."""
        return self._policies.get(rule_name)

    def get_or_default(self, rule_name: str) -> RulePolicy:
        """Return the declared policy, or the non-escalating default sentinel.

        EARS-2: a rule that has not declared metadata defaults to
        ``severity=None, auto_escalate=False`` — zero behaviour change.
        """
        return self._policies.get(rule_name, _DEFAULT_POLICY)


# Singleton used by detector.py.  Import with:
#   from firewatch_core.escalation.policy import ESCALATION_POLICY
ESCALATION_POLICY = EscalationPolicyRegistry()
