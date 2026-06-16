# ADR-010: Unified Source Cards

**Date:** April 2026
**Status:** Accepted

**Decision:** All source configurations (Azure WAF, Suricata, Syslog) use one `renderSourceCard()` function with per-source config builders.

**Reasoning:** Three different UI patterns for three sources was unmaintainable and inconsistent. One card layout with standard slots (status, config, actions, error) solved 6 UI gaps at once.
