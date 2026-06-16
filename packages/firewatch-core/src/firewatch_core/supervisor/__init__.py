"""supervisor — public re-exports for the firewatch_core.supervisor subpackage.

All names that callers (tests, CLI, firewatch_core.__init__) import from
``firewatch_core.supervisor`` are re-exported here so the import surface is
unchanged after the module was carved from a single file into this subpackage.

Concerns live in focused sub-modules:
  - config.py       — SupervisorConfig
  - models.py       — enums, dataclasses, PoisonRecordError
  - policy.py       — pure decision helpers (backoff, storm, DLQ)
  - runners.py      — per-instance coroutines (pull + push)
  - orchestrator.py — Supervisor class (lifecycle, task bookkeeping)
  - status.py       — InstanceStatus read-only DTO (MB.4)
"""
from firewatch_core.supervisor.config import SupervisorConfig
from firewatch_core.supervisor.models import (
    BackpressurePolicy,
    DLQEntry,
    InstanceRecord,
    InstanceState,
    PoisonRecordError,
    SupervisorAlert,
    _policy_for_transport,
)
from firewatch_core.supervisor.orchestrator import Supervisor
from firewatch_core.supervisor.status import InstanceStatus

__all__ = [
    "Supervisor",
    "SupervisorConfig",
    "SupervisorAlert",
    "InstanceRecord",
    "InstanceState",
    "InstanceStatus",
    "BackpressurePolicy",
    "DLQEntry",
    "PoisonRecordError",
    "_policy_for_transport",
]
