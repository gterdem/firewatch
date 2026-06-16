"""firewatch-sdk — canonical data models and port protocols.

The single dependency shared by firewatch-core and every source plugin. Contains no
logic and imports neither core, plugins, nor legacy (the dependency rule).
"""
from firewatch_sdk.actions import (
    ACTION_ID_PATTERN,
    NULL_ACTION_STATUS,
    ActionCapable,
    ActionResult,
    ActionStatus,
    SourceAction,
)
from firewatch_sdk.config import ConfigStore, RuntimeConfig
from firewatch_sdk.context import PluginContext
from firewatch_sdk.metadata import FlavorLiteral, SourceMetadata
from firewatch_sdk.models import (
    ActionLiteral,
    AIStatusLiteral,
    AiBoostEvidence,
    Detection,
    DispositionCounts,
    EscalationBlockStatusLiteral,
    EscalationVerdict,
    EventSummary,
    FactorEvidence,
    FilterSpec,
    RawEvent,
    Sample,
    ScoreBreakdownItem,
    ScoreDerivationLiteral,
    SecurityEvent,
    SeverityLiteral,
    ThreatLevelLiteral,
    ThreatScore,
)
from firewatch_sdk.ports import (
    AIEngine,
    Enricher,
    EventStore,
    Notifier,
    PullSource,
    PushSource,
    ScopedKV,
    SourcePlugin,
)

__all__ = [
    # models
    "SecurityEvent",
    "RawEvent",
    "ThreatScore",
    "FilterSpec",
    "Detection",
    "Sample",
    "ScoreBreakdownItem",
    # escalation models (ADR-0058)
    "EscalationVerdict",
    "DispositionCounts",
    # evidence chain (ADR-0041)
    "EventSummary",
    "FactorEvidence",
    "AiBoostEvidence",
    # literals
    "ActionLiteral",
    "SeverityLiteral",
    "ThreatLevelLiteral",
    "AIStatusLiteral",
    "FlavorLiteral",
    "ScoreDerivationLiteral",
    "EscalationBlockStatusLiteral",
    # metadata
    "SourceMetadata",
    # context (ADR-0027)
    "PluginContext",
    # ports
    "SourcePlugin",
    "PullSource",
    "PushSource",
    "ScopedKV",
    "EventStore",
    "AIEngine",
    "Notifier",
    "Enricher",
    # config
    "ConfigStore",
    "RuntimeConfig",
    # maintenance actions (ADR-0034)
    "SourceAction",
    "ActionResult",
    "ActionStatus",
    "ActionCapable",
    "NULL_ACTION_STATUS",
    "ACTION_ID_PATTERN",
]
