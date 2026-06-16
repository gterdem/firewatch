# ADR-001: Architecture Pattern — Pipeline + Ports and Adapters

**Date:** April 2026
**Status:** Accepted

**Decision:** Use Pipeline + Ports and Adapters, not full hexagonal architecture.

**Alternatives considered:**
- Full hexagonal / clean architecture — rejected as too ceremonial for a single-developer project
- Simple layered (controller → service → repo) — rejected as too coupled, can't swap adapters
- Event-driven / microservices — rejected as massive overkill

**Reasoning:** Pipeline makes data flow explicit (Collect → Normalize → Store → Detect → Score → Alert). Ports (Protocol classes) enable testing with mocks. Adapters are swappable. Core has zero I/O. The pattern gives 80% of hexagonal's benefits with 20% of the complexity.
