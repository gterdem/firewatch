# ADR-009: Frontend Rewrite — Framework Migration (Planned)

**Date:** April 2026
**Status:** Superseded by ADR-0019 (framework, migration strategy, and component library now decided)

**Decision:** Rewrite frontend from vanilla JS to a proper framework (Vue 3 or React). Incremental migration preferred over big-bang rewrite.

**Reasoning:** 800+ lines of inline JS is unmaintainable. Adding features (WebSocket, auth UI, detection rules editor) will make it worse. A component-based framework enables: reusable components, proper state management, testability, and faster feature development.

**Open questions:**
- Framework choice (Vue 3 vs React) — to be decided
- Migration strategy (incremental wrapper vs clean rewrite) — to be decided
- Component library (Tailwind + headless vs full component lib) — to be decided
