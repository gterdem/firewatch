# FireWatch — Architecture

> Living design doc, maintained by the **architect** agent. Settled decisions live in
> `docs/adr/` and are authoritative; this file describes the current design that
> implements them. If the two ever disagree, the ADR wins.

## Pattern (ADR-0001)
**Pipeline + lightweight Ports & Adapters** — deliberately *not* full hexagonal
(80% of the benefit, 20% of the ceremony). `core/` is pure logic with no I/O;
external systems connect through Protocol **ports**; **adapters** implement them.

Pipeline stages:

```
Collect → Normalize → Enrich → Store → Detect → Score → Alert
```

- **Collect** — source plugins pull (PullSource) or receive (PushSource) raw events.
- **Normalize** — each plugin maps its raw event → `SecurityEvent` (canonical).
- **Enrich** — shared enrichers add geo (ip-api.com) and MITRE/CAPEC where derivable.
- **Store** — `event_store` port (SQLite now, ADR-0007).
- **Detect** — cross-source correlation rules → `Detection`.
- **Score** — dual engine: deterministic rules (instant) + AI sampling (ADR-0003).
- **Alert** — `notifier` port (webhook; Discord/Slack auto-detect).

## Packages (migration from the legacy)

```
core/models.py (SecurityEvent, RawEvent, ThreatScore, FilterSpec, Detection)  → firewatch-sdk
ports/ (Pull/PushCollector, event_store, ai_engine, notifier, enricher)        → firewatch-sdk
core/{pipeline, scoring, detector} + shared normalizer (categorize_rule)       → firewatch-core
adapters/{stores, ai, notifiers} + v1 app/{analyzer, ai_classifier, alerter, sync, store}  → firewatch-core
adapters/collectors/{suricata, syslog} + Azure sync  → packages/sources/{suricata, syslog, azure-waf}
   ↳ each plugin OWNS its raw→SecurityEvent mapping (moved out of the shared normalizer) + its config schema
api/  → firewatch-core/api          config/settings.py → per-plugin config + core settings
dashboard.html  → UI (decision pending, ADR-0009)
```

Dependency rule: plugins and core both depend on `firewatch-sdk`. **Core never imports a plugin; plugins never import core or `legacy/`.**

## Canonical model — `SecurityEvent` (in firewatch-sdk)
From your `core/models.py`, extended for the accepted ADRs:

- `source_ip`, `destination_port`, `protocol`
- `action` ∈ {BLOCK, ALLOW, DROP, ALERT, LOG}  — IDS→ALERT, WAF/IPS→BLOCK (ADR-0012); `LOG` is for non-blocking informational events (e.g. Syslog SSH-Login)
- `rule_id`, `rule_name`, `payload_snippet`
- `timestamp` (UTC ISO-8601), `severity` ∈ {critical, high, medium, low}, `category`
- `source_type` ∈ {azure_waf, suricata, syslog, …} **and `source_id`** (named instance, ADR-0016)
- **`attack_technique` (T####), `attack_tactic` (TA####), `kill_chain_phase`, `capec_id`** — populated at normalize-time (ADR-0014)
- `RawEvent` carries source-specific `data: dict`; `Detection` is unchanged from legacy.
  `FilterSpec` and `ThreatScore` adopt the ECS source vocabulary (ADR-0016 / Flag B):
  `FilterSpec.source_module` → `source_type` + `source_id` (optional filters);
  `ThreatScore.source_modules` → `source_types` (distinct contributing types). Legacy
  `source_module(s)` names are not carried into the SDK.

Dedup unique index includes `source_id` (ADR-0016).

## Multi-source-per-type (ADR-0016)
A plugin defines a source **type**; you run **N named instances** of it (`source_id` like
`pi-home`, `azure-juiceshop`). Filters and dashboards work across sources or per `source_id`.

**Two axes, ECS-aligned (Flag B, settled):** `source_type` ≈ ECS `event.module`/`event.dataset`
(a constant the plugin declares about itself); `source_id` ≈ ECS `observer.name`/`agent.id`
(the user's runtime instance). **Cross-source correlation rules key on `source_type`** — i.e.
"multi-source" means *telemetry-type diversity* (IDS + syslog), matching MITRE ATT&CK Log-Source
semantics and the v1 oracle (where `source_module` was the type). `source_id` is for provenance,
filtering, and watermarking only — never a correlation key. A new plugin therefore joins
correlation for free, just by declaring its `source_type`.

## Collectors — pull vs push (ADR-0005)
- **PullSource** — `collect(since)` on a watermark (Suricata SSH, Azure WAF).
- **PushSource** — `start()/stop()` listener (Syslog UDP/TCP).

**Collection orchestration.** Core owns a thin, single-shot **pull-cycle driver**
`run_pull_cycle(plugin, cfg, source_id)`: read watermark `(source_type, source_id)` →
`plugin.collect` → `plugin.normalize` → `pipeline.ingest` → write watermark. It takes the
plugin via the SDK `PullSource`/`SourcePlugin` protocol (core never imports a plugin). The
**long-running supervisor** (scheduling, PushSource listener lifecycle, per-instance crash
isolation, retries) is M2 — the single-shot driver is what M1 ships and what the golden tests drive.

## Invariants (do not violate without a superseding ADR)
1. **AI sampling** — one LLM call per IP, never per log (ADR-0003).
2. **Local-first** — all inference via a **local OpenAI-compatible endpoint** (Ollama default;
   vLLM/SGLang/llama.cpp/LM Studio supported); **no cloud LLM in the product** (ADR-0004 → ADR-0022).
3. **AI is additive-only to the deterministic score** — it may escalate, never de-escalate.
   (Score-boost design + the injection mitigation below.)
4. **Config precedence** — env vars > `firewatch_config.json` > defaults (ADR-0006).

## Storage (ADR-0007)
A single `event_store` port. SQLite (aiosqlite) now; PostgreSQL at M6 (JSONB for raw,
`tsvector` for search). Watermark keyed per **`(source_type, source_id)`** — `source_id` is
user-supplied and not unique across types, so the watermark uses the composite instance key.

## Security posture — data-plane prompt injection
Attacker payloads enter the prompt through the sample block, so the threat is *indirect*
injection via logged data, not the trusted analyst. Mitigations, in order of effect:
1. **Delimit** sampled payloads as untrusted data; instruct the model never to follow instructions inside them.
2. **Validate** AI output against the closed JSON schema (enum/range-check, reject off-schema → rules-only).
3. **AI additive-only** to the deterministic rule score (invariant 3) — neutralizes "make me look benign".

## Active response (ADR-0015) — design seam, not built now
Reserve a `responder`/actuator port alongside `notifier`. Tiered autonomy
(suggest / one-click / conditional-auto); full autonomy deferred. **Nothing auto-acts on a
single LLM call** — require rules + AI agreement plus the ADR-0015 guardrails.

## UI — settled (ADR-0019, supersedes the ADR-0009 open question)
**React 18/19 + Vite + TypeScript + `react-jsonschema-form` (rjsf) + Tailwind/shadcn.**
Clean rewrite behind the existing API, shipped view-by-view, **Settings/source-cards first**.
Desktop-first; mobile via bots (ADR-0017). The unified source card (ADR-0010) is a component
rendered from each plugin's `config_schema` (Pydantic → JSON Schema → rjsf, with `if/then/else`
for mode toggles and secret widgets), so **plugins contribute their config UI declaratively**.

## Positioning (ADR-0018)
Integrated open-source AI SOC platform: multi-source SIEM + local AI investigation + tunable response.
