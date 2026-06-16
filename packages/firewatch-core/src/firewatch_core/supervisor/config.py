"""Supervisor configuration (ADR-0006 / ADR-0023 §Defaults).

All constants are config-overridable via ``firewatch_config.json``
or env-var injection before constructing the supervisor.
"""
from __future__ import annotations

from pydantic import BaseModel


class SupervisorConfig(BaseModel):
    """Config-overridable defaults for the supervisor (ADR-0006 / ADR-0023 §Defaults).

    All fields have the defaults specified in ADR-0023.  Operators override them via
    ``firewatch_config.json`` or env-var injection before constructing the supervisor.
    """

    # Backoff (ADR-0023 §C)
    backoff_base: float = 1.0       # seconds, base of the exponential
    backoff_cap: float = 300.0      # seconds, ceiling on a single sleep

    # Restart-storm cap (ADR-0023 §D-revised)
    storm_threshold: int = 5        # crashes in rolling window ⇒ park
    storm_window_s: float = 60.0    # rolling window in seconds

    # Dead-letter threshold (ADR-0023 §D-revised)
    dlq_threshold: int = 3          # failures on the *same* record ⇒ dead-letter it

    # Graceful shutdown (ADR-0023 §E / 12-Factor IX)
    shutdown_grace: float = 30.0    # hard deadline before force-cancel

    # Backpressure queue bounds (ADR-0023 §Steals / Cribl/OTel)
    push_queue_maxsize: int = 256   # max outstanding emit batches in push instance queue
