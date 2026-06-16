# ADR-006: Config Priority — Env > File > Default

**Date:** April 2026
**Status:** Accepted

**Decision:** Environment variables override config file values, which override hardcoded defaults.

**Reasoning:** Deploy-time settings (env vars) shouldn't be accidentally overwritten by the UI. The Settings UI writes to `firewatch_config.json` for runtime changes. This is the standard 12-factor app pattern.
