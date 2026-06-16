# ADR-0040: OCSF Export Surface — Read-Only Endpoints Pinned to OCSF 1.8.0 (Refines ADR-0020)

**Date:** June 2026 (accepted 2026-06-12)
**Status:** Accepted (refines ADR-0020 — does NOT supersede it)

**Decision:** Implement the export serializer ADR-0020 already accepted ("an OCSF view at the
API/export boundary") as a concrete, pinned surface:

- **Schema version pinned to OCSF 1.8.0** (current stable at schema.ocsf.io, verified 2026-06-12);
  every exported object carries `metadata.version = "1.8.0"`.
- **Two read-only endpoints** (ADR-0029 cursor-pagination envelope; ADR-0026 read route-class):
  - `GET /export/ocsf/events` — normalized events serialized to their mapped OCSF activity class
    with the ADR-0020 field map (`action` → `disposition_id`/`activity_id`, `severity` →
    `severity_id`, existing `ocsf_class`/`ocsf_category` formalized as `class_uid`/`category_uid`).
  - `GET /export/ocsf/findings` — scored threats serialized as **Detection Finding
    (`class_uid` 2004)** with severity/score mapping, MITRE ATT&CK references (ADR-0014 data), and
    the **`evidences`** attribute (the 1.8.0 class's evidence field, confirmed in its class
    definition) populated from the actor's contributing events, **recomputed at read time**
    (consistent with ADR-0041). The per-factor evidence chain (MI-6) enriches `evidences` later —
    not a blocker.
- **Serializer at the boundary, never an internal rewrite:** pure mapping/serializer modules in the
  API package; the internal `SecurityEvent` model is unchanged (ADR-0020's "lightweight alignment
  now, deepen later" stands).
- **Golden tests pin representative serializations** (at least one Azure-WAF event, one Suricata
  event, one finding) — the ADR-0020 consequence finally honored.

**Alternatives considered:**
- **Track "latest" OCSF instead of pinning a version** — rejected: consumers validate against a
  schema version; an unpinned export silently breaks them on OCSF releases. Pin and bump
  deliberately.
- **Full OCSF attribute-dictionary conformance now** — rejected: re-litigates what ADR-0020 already
  decided against (verbose, heavy, little near-term value for a small tool).
- **Export via a file dump / CLI instead of API endpoints** — rejected: the API is the product's
  integration boundary (ADR-0026/0029 already define auth and pagination there); a second export
  channel duplicates contract surface.
- **OCSF ingestion (import) alongside export** — out of scope; nothing demands it, and ingestion is
  the plugins' job under the source contract.

**Reasoning:** OCSF-native export lets the air-gapped one-box *compose* with bigger stacks —
findings and events forward into any OCSF-consuming pipeline — instead of competing head-on
(differentiation roadmap §A2). Detection Finding 2004 with `evidences` is exactly the
"verdict + the events behind it" shape that the auditable-AI positioning (ADR-0035/0036, MI leg 2)
needs at the export boundary, so the UI evidence payload and the export speak the same vocabulary.
Sources: OCSF schema browser — https://schema.ocsf.io/ (1.8.0 stable; Detection Finding
`class_uid` 2004, `evidences` attribute — verified 2026-06-12); ADR-0020's
[normalization-standards comparison](https://www.query.ai/resources/blogs/cybersecurity-event-data-normalization-standards/).

**Consequences:**
- MI-5 (#386) implements: `ocsf/mapping.py` (pure tables, `OCSF_VERSION = "1.8.0"`),
  `ocsf/serializer.py` (pure functions), `routes/export.py`, golden fixtures.
- The ADR-0020 field map gets written down once, in `mapping.py`, and asserted by goldens.
- Version bumps (e.g. OCSF 1.9/2.0) are deliberate, ADR-noted changes to `OCSF_VERSION` + fixtures.
