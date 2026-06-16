# ADR-008: Frontend — Single-File Dashboard (v1/v2)

**Date:** February 2026
**Status:** Accepted (being superseded — see ADR-009)

**Decision:** Single-file `dashboard.html` with vanilla JS, no build step.

**Reasoning:** No npm, no webpack, changes are instant. Worked well up to v2.0 but approaching the maintainability ceiling at 800+ lines.
