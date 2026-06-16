# ADR-020: Event Schema — Lightweight OCSF Alignment

**Date:** June 2026
**Status:** Accepted

**Decision:** Keep FireWatch's bespoke `SecurityEvent` as the internal working model, but make
its alignment to **OCSF (Open Cybersecurity Schema Framework)** *explicit and tracked* instead
of incidental. Concretely:
- Define a documented field map from `SecurityEvent` to OCSF where it maps cleanly:
  `action` → OCSF `disposition_id`/`activity_id`, `severity` → `severity_id`, `category` →
  OCSF class, and formalize the existing `ocsf_class`/`ocsf_category` (already on the model) as
  `class_uid`/`category_uid`.
- Provide an **OCSF view at the API/export boundary** (a serializer), not a rewrite of the
  internal model.
- Defer *full* OCSF object conformance (nested observers, full attribute dictionary) — this is
  "lightweight alignment now, deepen later."

**Alternatives considered:**
- **Full OCSF adoption now (internal model = OCSF objects)** — rejected: OCSF objects are verbose
  and heavy for a small, single-binary tool; would slow M1 and the golden port for little
  near-term value.
- **Stay fully bespoke (status quo)** — rejected: forces per-consumer translation, weakens the
  "integrated SIEM" positioning (ADR-0018), and diverges from the 2026 normalization standard.
- **Standardize on ECS instead of OCSF** — rejected for the *event* schema: ECS is Elastic-ecosystem,
  observability-first; OCSF is the cross-vendor *security* standard. (We already use ECS framing for
  *source identity* — `source_type`/`source_id`; that stays and is complementary, not in conflict.)

**Reasoning:** OCSF became a Linux Foundation project (Nov 2024) and 2025–2026 is the adoption
inflection point for vendor-neutral security normalization; aligning to it makes detections and
exports portable and reduces integration toil. The move is incremental because the model already
carries `ocsf_class`/`ocsf_category` nods — we are formalizing, not inventing. Sources:
[OCSF](https://ocsf.io/), [normalization standards: OCSF vs ECS/CIM/ASIM (Query.ai)](https://www.query.ai/resources/blogs/cybersecurity-event-data-normalization-standards/).

**Consequences:**
- `normalize()` populates the OCSF-mapped fields where derivable; the canonical-schema skill gains
  the OCSF field map.
- An OCSF serializer at the API/export boundary; golden tests assert OCSF fields on representative
  events.
- No change to the internal `SecurityEvent` field set beyond formalizing existing OCSF fields.
- Relates to ADR-0014 (MITRE/CAPEC) — both are "align to the standard vocabulary at normalize-time."
