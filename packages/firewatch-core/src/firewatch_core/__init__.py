"""firewatch-core — plugin loader, pipeline, and shared scoring/detection helpers.

Depends on firewatch-sdk only. Never imports a plugin package or ``legacy/``.
"""
from firewatch_core.config_store import JsonFileConfigStore
from firewatch_core.detector import BUILTIN_RULES, detect
from firewatch_core.loader import ENTRY_POINT_GROUP, load_source_plugins
from firewatch_core.normalize_helpers import (
    OCSF_CLASS_MAP,
    RULE_CATEGORIES,
    categorize_rule,
    ocsf_for_category,
)
from firewatch_core.pipeline import Pipeline, PullPlugin
from firewatch_core.scoring import build_samples, merge_score, run_rules
from firewatch_core.supervisor import (
    BackpressurePolicy,
    DLQEntry,
    InstanceRecord,
    InstanceState,
    PoisonRecordError,
    Supervisor,
    SupervisorAlert,
    SupervisorConfig,
)

__all__ = [
    # config service
    "JsonFileConfigStore",
    # pipeline
    "Pipeline",
    "PullPlugin",
    # loader
    "load_source_plugins",
    "ENTRY_POINT_GROUP",
    # scoring
    "run_rules",
    "build_samples",
    "merge_score",
    # detector
    "detect",
    "BUILTIN_RULES",
    # normalize helpers
    "categorize_rule",
    "ocsf_for_category",
    "RULE_CATEGORIES",
    "OCSF_CLASS_MAP",
    # supervisor (ADR-0023 / issue #22)
    "Supervisor",
    "SupervisorConfig",
    "SupervisorAlert",
    "InstanceRecord",
    "InstanceState",
    "BackpressurePolicy",
    "DLQEntry",
    "PoisonRecordError",
]
