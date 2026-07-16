# Architecture Decision Records (ADRs)

These are **settled decisions**. Agents must not re-argue an accepted ADR unless
Maintainer explicitly reopens it. To change a decision, **supersede** it with a new ADR
(do not edit the old one) and mark the old one `Superseded by ADR-XXXX`.

**How new ADRs are added:** the architect agent proposes one during a Claude Code
Plan Mode discussion, Maintainer reviews/approves, and it's committed here as the next
number. One decision per file. Keep them small.

**Phase sequencing** (which ADRs land in which release phase) lives in
[`../ROADMAP.md`](../ROADMAP.md). The ADRs here are the *decisions*; the ROADMAP is the *order*.

**Next ADR number:** 0072

| ADR | Title | Status | File |
|-----|-------|--------|------|
| 0001 | Architecture Pattern — Pipeline + Ports and Adapters | Accepted | [0001-architecture-pattern-pipeline-ports-and-adapters.md](0001-architecture-pattern-pipeline-ports-and-adapters.md) |
| 0002 | Single Language — Python | Accepted | [0002-single-language-python.md](0002-single-language-python.md) |
| 0003 | AI Approach — Sampling, Not Per-Log | Accepted | [0003-ai-approach-sampling-not-per-log.md](0003-ai-approach-sampling-not-per-log.md) |
| 0004 | Local-First AI — Ollama Only | Superseded by ADR-0022 | [0004-local-first-ai-ollama-only.md](0004-local-first-ai-ollama-only.md) |
| 0005 | Suricata Collector — SSH Pull | Accepted | [0005-suricata-collector-ssh-pull.md](0005-suricata-collector-ssh-pull.md) |
| 0006 | Config Priority — Env > File > Default | Accepted | [0006-config-priority-env-file-default.md](0006-config-priority-env-file-default.md) |
| 0007 | Storage — SQLite Now, PostgreSQL Later (M6) | Accepted | [0007-storage-sqlite-now-postgresql-later-m6.md](0007-storage-sqlite-now-postgresql-later-m6.md) |
| 0008 | Frontend — Single-File Dashboard (v1/v2) | Accepted (being superseded — see ADR-009) | [0008-frontend-single-file-dashboard-v1-v2.md](0008-frontend-single-file-dashboard-v1-v2.md) |
| 0009 | Frontend Rewrite — Framework Migration (Planned) | Superseded by ADR-0019 | [0009-frontend-rewrite-framework-migration-planned.md](0009-frontend-rewrite-framework-migration-planned.md) |
| 0010 | Unified Source Cards | Accepted | [0010-unified-source-cards.md](0010-unified-source-cards.md) |
| 0011 | Faceted Filters Over Category Tabs | Accepted | [0011-faceted-filters-over-category-tabs.md](0011-faceted-filters-over-category-tabs.md) |
| 0012 | IDS Action Mapping — ALERT Badge | Accepted | [0012-ids-action-mapping-alert-badge.md](0012-ids-action-mapping-alert-badge.md) |
| 0013 | Open Core Licensing | Superseded by ADR-0056 | [0013-open-core-licensing.md](0013-open-core-licensing.md) |
| 0014 | MITRE ATT&CK + CAPEC Native Categorization | Accepted | [0014-mitre-att-ck-capec-native-categorization.md](0014-mitre-att-ck-capec-native-categorization.md) |
| 0015 | Tiered Autonomy for Active Response | Accepted (with Future Reconsideration) | [0015-tiered-autonomy-for-active-response.md](0015-tiered-autonomy-for-active-response.md) |
| 0016 | Multi-Source-Per-Type Architecture | Accepted | [0016-multi-source-per-type-architecture.md](0016-multi-source-per-type-architecture.md) |
| 0017 | Desktop-First UI, Mobile via Bot | Accepted | [0017-desktop-first-ui-mobile-via-bot.md](0017-desktop-first-ui-mobile-via-bot.md) |
| 0018 | Product Positioning — Integrated Open-Source AI SOC Platform | Accepted | [0018-product-positioning-integrated-open-source-ai-soc-platform.md](0018-product-positioning-integrated-open-source-ai-soc-platform.md) |
| 0019 | Frontend Stack — React + react-jsonschema-form | Accepted (supersedes ADR-0009) | [0019-frontend-stack-react-rjsf.md](0019-frontend-stack-react-rjsf.md) |
| 0020 | Event Schema — Lightweight OCSF Alignment | Accepted | [0020-event-schema-lightweight-ocsf-alignment.md](0020-event-schema-lightweight-ocsf-alignment.md) |
| 0021 | Suricata Ingestion — Standard Log-Shipper Push Path Alongside SSH Pull | Accepted (complements ADR-0005) | [0021-suricata-ingestion-shipper-push-path.md](0021-suricata-ingestion-shipper-push-path.md) |
| 0022 | Local Inference Interface — OpenAI-Compatible Endpoint | Accepted (supersedes ADR-0004) | [0022-local-inference-openai-compatible-endpoint.md](0022-local-inference-openai-compatible-endpoint.md) |
| 0023 | Collector Supervisor — Lifecycle & Concurrency Model | Accepted | [0023-collector-supervisor-lifecycle.md](0023-collector-supervisor-lifecycle.md) |
| 0024 | Codebase Lineage — `legacy/` is the Feature/UX Oracle Only; Parity = Feature Parity | Accepted | [0024-lineage-legacy-as-functional-oracle.md](0024-lineage-legacy-as-functional-oracle.md) |
| 0025 | Source-Plugin Database Contract — Canonical Schema + Source-Scoped KV, No Plugin DDL | Accepted | [0025-source-plugin-db-contract.md](0025-source-plugin-db-contract.md) |
| 0026 | API Authentication / Authorization Posture — Loopback-Default, Optional API Key, Per-Route-Class Gating | Accepted | [0026-api-auth-posture.md](0026-api-auth-posture.md) |
| 0027 | The `PluginContext` Injection Seam — Per-Instance Capability Carrier into the Collection Entrypoints | Accepted | [0027-plugincontext-injection-seam.md](0027-plugincontext-injection-seam.md) |
| 0028 | Frontend Project Layout & Toolchain — Standalone `frontend/` Vite App, Per-Language CI, rjsf↔shadcn Convention | Accepted | [0028-frontend-project-layout-and-toolchain.md](0028-frontend-project-layout-and-toolchain.md) |
| 0029 | Read/Query API Contract — Read Surface, Cursor-Pagination Envelope, Response Shapes & SDK↔API Schema Split | Accepted | [0029-read-query-api-contract.md](0029-read-query-api-contract.md) |
| 0030 | Event-Transport Buffer/Ack Seam — In-Process Now, Broker-Optional Later | Proposed | [0030-event-transport-buffer-ack-seam.md](0030-event-transport-buffer-ack-seam.md) |
| 0031 | Collect Trigger — Manual Sync + Persisted Auto-Sync as the Instance-Registration Seam | Accepted | [0031-collect-trigger-sync-autosync-instance-registration.md](0031-collect-trigger-sync-autosync-instance-registration.md) |
| 0032 | "All Sources" = Installed Modules + Honest Colored Health Overlay | Accepted | [0032-all-sources-installed-plus-health-overlay.md](0032-all-sources-installed-plus-health-overlay.md) |
| 0033 | UI Action Seam — `onAction(actor, verb)` (SIEM Alerting Now, SOAR Execution Later) | Accepted | [0033-ui-action-seam-siem-now-soar-later.md](0033-ui-action-seam-siem-now-soar-later.md) |
| 0034 | Source Maintenance Actions Seam — Discovery-Declared Ruleset Manager | Accepted | [0034-source-maintenance-actions-seam.md](0034-source-maintenance-actions-seam.md) |
| 0035 | Analytic Provenance Tagging — `RULE` / `AI` / `AI+RULE` on Every Analyst-Facing Artifact | Accepted | [0035-analytic-provenance-tagging.md](0035-analytic-provenance-tagging.md) |
| 0036 | Score & Confidence Presentation Contract — Banded Labels, Word Confidence, Exposed Contributions | Accepted | [0036-score-confidence-presentation-contract.md](0036-score-confidence-presentation-contract.md) |
| 0037 | Entity Slide-Over Panel — Right-Side Flyout Replaces the Centered IP Drill-Down Modal | Accepted | [0037-entity-slide-over-panel.md](0037-entity-slide-over-panel.md) |
| 0038 | Global Source-Scope Seam — `SourceScopeContext` + `sources=` Read-API Parameter | Proposed (build post-release) | [0038-global-source-scope-seam.md](0038-global-source-scope-seam.md) |
| 0039 | Offline Geolocation Default — DB-IP Lite via First-Run Download (Closes the ip-api Egress) | Accepted | [0039-offline-geolocation-default-dbip-lite-first-run-download.md](0039-offline-geolocation-default-dbip-lite-first-run-download.md) |
| 0040 | OCSF Export Surface — Read-Only Endpoints Pinned to OCSF 1.8.0 | Accepted (refines ADR-0020) | [0040-ocsf-export-surface-pinned-1-8-0.md](0040-ocsf-export-surface-pinned-1-8-0.md) |
| 0041 | Evidence Chain — Recompute Factor→Events at Read Time; Never Persist Event IDs | Accepted | [0041-evidence-chain-recompute-at-read-time.md](0041-evidence-chain-recompute-at-read-time.md) |
| 0042 | Inference Runtime Packaging — Hybrid Compose Profiles (Ollama Default, llama.cpp Lean) | Accepted (complements ADR-0022) | [0042-inference-runtime-packaging-hybrid-profiles.md](0042-inference-runtime-packaging-hybrid-profiles.md) |
| 0043 | The `/ai` Page Becomes "AI Engine" — the Local-AI Accountability Surface | Accepted | [0043-ai-engine-page-identity.md](0043-ai-engine-page-identity.md) |
| 0044 | AI Verdict Ledger — Persist Every Validated AI Analysis | Accepted | [0044-ai-verdict-ledger-persistence.md](0044-ai-verdict-ledger-persistence.md) |
| 0045 | Verdict Feedback Store — Analyst Agree/Disagree as a Local, Additive Table | Accepted | [0045-verdict-feedback-store.md](0045-verdict-feedback-store.md) |
| 0046 | Pipeline Stage Ticker — Fetch-Streamed SSE of Validated Stage Facts (No Raw Tokens) | Accepted | [0046-pipeline-stage-ticker-sse.md](0046-pipeline-stage-ticker-sse.md) |
| 0047 | Zero-Egress Attestation Strip — Derived From Enforced Configuration, Never Asserted | Accepted | [0047-zero-egress-attestation-strip.md](0047-zero-egress-attestation-strip.md) |
| 0048 | Extend SecurityEvent with OCSF-aligned network-depth fields | Accepted | [0048-securityevent-network-depth-fields.md](0048-securityevent-network-depth-fields.md) |
| 0049 | Constrained NL→FilterSpec query grammar (store-schema-bounded) | Accepted | [0049-constrained-nl-filterspec-grammar.md](0049-constrained-nl-filterspec-grammar.md) |
| 0050 | Entity-graph render — d3-force for layout only, drawn to hand-rolled SVG | Accepted | [0050-entity-graph-render-d3force-to-svg.md](0050-entity-graph-render-d3force-to-svg.md) |
| 0051 | Web-Triggered Baseline Save/Compare — Async Background Job + Progress Channel | Accepted | [0051-web-triggered-baseline-async-job.md](0051-web-triggered-baseline-async-job.md) |
| 0052 | Offline Vector Basemap — Bundled Natural Earth World-Outline GeoJSON (Closes CartoDB Tile Egress) | Accepted | [0052-offline-vector-basemap-bundled-world-outline.md](0052-offline-vector-basemap-bundled-world-outline.md) |
| 0053 | AI-Drafted Case File — Surface Identity, Slide-Over Seam, Auth-Aware Note Model | Accepted | [0053-ai-drafted-case-file-surface.md](0053-ai-drafted-case-file-surface.md) |
| 0054 | Internal Decomposition of the SQLite Store via Connection-Sharing Mixins — Single-Owner Connection Preserved (ADR-0023 §F) | Accepted | [0054-sqlite-store-mixin-decomposition.md](0054-sqlite-store-mixin-decomposition.md) |
| 0055 | Extend SecurityEvent with file-IOC, DNS-answer, and JA3 fields (refines ADR-0048) | Accepted | [0055-securityevent-file-ioc-and-dns-answer-fields.md](0055-securityevent-file-ioc-and-dns-answer-fields.md) |
| 0056 | License FireWatch under AGPL-3.0 (supersedes ADR-0013) | Accepted | [0056-licensing-agpl-3.0.md](0056-licensing-agpl-3.0.md) |
| 0057 | Design-System overlay primitives — adopt Radix Popover/Tooltip, retire hand-rolled positioner (tactical-now + #289 migration) | Proposed | [0057-radix-overlay-primitives-for-popovers-and-tooltips.md](0057-radix-overlay-primitives-for-popovers-and-tooltips.md) |
| 0058 | Action-Aware Deterministic Escalation Axis — Rules Escalate Instantly, AI Narrates the Post-Alert Story | Accepted (partially superseded by ADR-0067) | [0058-action-aware-deterministic-escalation-axis.md](0058-action-aware-deterministic-escalation-axis.md) |
| 0059 | Three Named, Purpose-Specific Thresholds (Notification / AI-confidence / Triage) + a Shared Alert-Worthiness Predicate | Accepted | [0059-three-named-thresholds-and-unified-alert-worthiness-predicate.md](0059-three-named-thresholds-and-unified-alert-worthiness-predicate.md) |
| 0060 | Plugin-Declared Field-Production Capability — `SourceMetadata.produces` (structural axis for `/logs` empty-column hiding) | Accepted (D4 superseded by ADR-0063) | [0060-source-metadata-produces-field-capability.md](0060-source-metadata-produces-field-capability.md) |
| 0061 | Entity Relationship Graph Navigation — d3-zoom transform layer, label level-of-detail, focus/context (amends ADR-0050) | Accepted | [0061-entity-relationship-graph-navigation.md](0061-entity-relationship-graph-navigation.md) |
| 0062 | Settings Source Cards — "Active" On-Switch, Collapse-by-Default Layout, Honest Inactive State | Accepted | [0062-settings-active-toggle-collapse-and-honest-state.md](0062-settings-active-toggle-collapse-and-honest-state.md) |
| 0063 | Network Logs Table — Curated "Spine" Columns + Per-Row Detail Panel (SIEM log-explorer pattern) | Accepted | [0063-network-logs-detail-panel-curated-spine.md](0063-network-logs-detail-panel-curated-spine.md) |
| 0064 | App-Wide Live Refresh — One Shared Heartbeat, `dataVersion` Signal, Auto-Refresh-vs-Deferred-Pill by Page Type | Proposed | [0064-app-wide-live-refresh-shared-heartbeat.md](0064-app-wide-live-refresh-shared-heartbeat.md) |
| 0065 | Local-First Endpoint Collection & Solo/Hub Topology — journald-First SDK Readers, Cursor-Based Resume | Accepted (complements ADR-0021) | [0065-local-first-endpoint-collection-solo-hub-topology.md](0065-local-first-endpoint-collection-solo-hub-topology.md) |
| 0066 | Honest AI State Model — Administrative vs Operational State, One Closed `ai_status` Vocabulary | Proposed (refines ADR-0022, ADR-0035 §4) | [0066-honest-ai-state-model-admin-vs-operational.md](0066-honest-ai-state-model-admin-vs-operational.md) |
| 0067 | Assertion-Gated Triage Entry + the `observed` Stratum — Tier 2 Requires a Qualifying Signal | Accepted (partially supersedes ADR-0058 D2; D5(1) corrected by ADR-0070 D7; Amendment 1 accepted 2026-07-16 — `enforce`-cell label + "rare" correction) | [0067-assertion-gated-triage-entry-observed-stratum.md](0067-assertion-gated-triage-entry-observed-stratum.md) |
| 0068 | The Volume Oracle — Usability Invariants at Realistic Event Volume as a Deterministic CI Gate | Proposed | [0068-volume-oracle-usability-invariants-at-realistic-volume.md](0068-volume-oracle-usability-invariants-at-realistic-volume.md) |
| 0069 | Canonical Severity Semantics — Sigma-Anchored Behavioral Definitions for `SecurityEvent.severity` + the Per-Source Mapping Discipline | Proposed (coupled with ADR-0070) | [0069-canonical-severity-semantics-sigma-anchored.md](0069-canonical-severity-semantics-sigma-anchored.md) |
| 0070 | Hostile-Attempt Intensity — Pressure, Attack-in-Progress, and Campaign Detection (Revision 1) | Accepted 2026-07-16 (Revision 1 supersedes the first draft; coupled with ADR-0069 — D8's landing order stands; corrects ADR-0067 D5(1)) | [0070-hostile-attempt-pressure-and-campaign-detection.md](0070-hostile-attempt-pressure-and-campaign-detection.md) |
| 0071 | The Auth-Outcome Contract Vocabulary — `SecurityEvent.outcome`, Outcome-Keyed Correlation, Category Demoted from Routing | Accepted 2026-07-16 (Revision 1 — re-verified against merged main; anti-registry reason (1) retracted, direction unchanged; D5 → issue #76) | [0071-auth-outcome-contract-vocabulary.md](0071-auth-outcome-contract-vocabulary.md) |
