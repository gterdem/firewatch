# ADR-0034: Source Maintenance Actions — Plugin-Declared, Generically Rendered (and the Manual Suricata Ruleset Download)

**Date:** 2026-06-10
**Status:** Accepted

> **Naming — do not confuse the two action seams.**
> **ADR-0033** is the **triage action seam**: a UI-internal hook (`onAction(actor, verb)`) over
> *threat actors* (Block / Investigate / Dismiss — SIEM now, SOAR later). **This ADR (0034)** is the
> **source maintenance action seam**: a *plugin-contract* surface where a source plugin declares
> operational actions against *its own source instance* (e.g. "Download ruleset"), and core/UI
> discover and render them generically. They share nothing but the word "action": 0033 never touches
> the plugin contract; 0034 never touches threat actors or triage.

**Relates to:** ADR-0010/0019/0028 (schema-driven source cards — zero per-source frontend code; this
ADR extends that thesis from *config forms* to *action buttons*), ADR-0025 (+ addendum — source-scoped
`ScopedKV` is the only plugin persistence; where the downloaded catalog and its metadata live),
ADR-0027 (`PluginContext` — the capability carrier the action entrypoint receives; supervisor is the
single minter), ADR-0031 (collect-trigger — `POST /sync/{type}` / `POST /sources/{type}/test` are the
hard-coded per-source-action pattern this ADR generalizes), ADR-0026 (auth posture — the action route
is class B), ADR-0005 (Suricata SSH pull — the transport the ruleset download reuses), ADR-0033
(cross-reference only, see naming note). Issues: **#165** (KV cap must fit ~50k ET Open rules — hard
dependency), #139 (deferred source diagnostics — the future progress/status surface for long-running
actions), #138/#163 (MF source-card controls / Settings restyle — UI siblings), #150 (rule-desc
producer this ADR reworks for remote mode).

---

## Context

The live-systems run (2026-06-10, real ET Open ruleset) exposed the gap: Suricata's rule-description
producer (`firewatch_suricata/plugin.py::_write_rule_descriptions`, issue #150) only reads a **local**
`rules_path`. On a remote sensor the operator hand-copied the 43 MB ruleset to the FireWatch host —
exactly the manual toil a plugin should absorb. The obvious fix ("plugin downloads its ruleset") raises
two architectural questions:

1. **Transfer policy.** ET Open is ~43 MB / ~50k rules (live measurement; ET Pro is larger). Users on
   metered or restricted links must never get a surprise transfer. **Maintainer's decision (binding): the
   download is MANUAL-ONLY** — a button, never an automatic fetch (not on first sync, not daily), with
   the size shown before/while downloading. FireWatch *informs* about freshness; the *user* decides.
2. **Modularity.** "A Suricata download button" must not become `if source === 'suricata'` in core or
   frontend. The existing per-source action pattern is already two hard-coded routes
   (`POST /sources/{type}/test`, `POST /sync/{type}`) plus a frontend branch
   (`SourceCard.tsx`: `isSuricata` → `<SuricataControls/>`). A third hard-coded action would entrench
   the anti-pattern the platform exists to avoid.

The settled FireWatch answer for config is *declare → discover → render*: the plugin declares a
Pydantic `config_schema()`, discovery serves it, rjsf renders it, zero core/frontend edits per source
(ADR-0010/0019/0028). This ADR applies the identical shape to **operational actions**.

---

## Decision

### A. Plugins declare maintenance actions in `SourceMetadata`

`SourceMetadata` gains an additive, default-empty field; `SourceAction` is a frozen value object
(same rule as `SourceMetadata`: carriers are frozen models, not Protocols):

```python
# firewatch-sdk
class SourceAction(BaseModel):
    model_config = ConfigDict(frozen=True)
    id: str                          # ^[a-z][a-z0-9_]*$, unique within the plugin
    label: str                       # button text, e.g. "Download ruleset"
    description: str                 # help/tooltip text
    long_running: bool = False       # UI: spinner + extended timeout + stays disabled while running
    confirm: str | None = None       # pre-flight confirmation prose (size warning lives here);
                                     # None = invoke without confirmation
    provides: tuple[str, ...] = ()   # declared facets this action supplies, e.g. ("rule_descriptions",)

class SourceMetadata(BaseModel):
    ...                              # existing fields unchanged
    actions: tuple[SourceAction, ...] = ()   # additive; default () = no buttons, no migration
```

- **`provides` is the generic linkage for contextual hints.** `"rule_descriptions"` is the first
  well-known facet: any UI surface that hits a missing rule name can ask "does this event's source
  declare an action providing `rule_descriptions`?" and render a generic hint — no type-key branch.
  Facet strings are documented in PLUGIN_CONTRACT.md as they are introduced (core recognizes facets
  it knows; unknown facets are inert metadata, forward-compatible).
- **`confirm` carries the informational payload** (Maintainer's "inform the user of the size"). It is
  static declared prose (e.g. "~40–60 MB for ET Open"); the *live* size comes from the status surface
  (§C), not from metadata.

### B. Plugins that declare actions implement one optional capability protocol

```python
# firewatch-sdk
@runtime_checkable
class ActionCapable(Protocol):
    async def run_action(
        self, action_id: str, cfg: BaseModel, ctx: PluginContext
    ) -> ActionResult: ...
    async def action_status(
        self, action_id: str, cfg: BaseModel, ctx: PluginContext
    ) -> ActionStatus: ...

class ActionResult(BaseModel):       # frozen
    ok: bool
    message: str                     # human-readable outcome ("Downloaded 43.1 MB, 49,812 rules")
    detail: dict[str, str] = {}      # small string map; never large payloads

class ActionStatus(BaseModel):       # frozen
    last_run_at: str | None = None   # ISO-8601 of last successful run
    stale: bool | None = None        # True = upstream changed since last run; None = unknown
    message: str | None = None       # plugin-provided prose ("Ruleset updated on sensor 2026-06-09…")
    detail: dict[str, str] = {}
```

- **Invariant (loader/discovery-checked):** `metadata().actions` non-empty ⇒ the plugin satisfies
  `ActionCapable`. Empty ⇒ the methods need not exist. `run_action`/`action_status` with an
  undeclared `action_id` raise `ValueError` (core maps to 404).
- **The plugin supplies the prose; the UI stays generic.** `ActionStatus.message` and
  `stale` are how "ruleset updated on sensor since last download" reaches the card without the
  frontend knowing what a ruleset is. The UI renders: last-run date, a highlighted stale indicator
  when `stale is True`, and the message verbatim.
- **`ctx` is the standard ADR-0027 carrier** — `ctx.kv` is where action state (and its products) are
  persisted (ADR-0025). No new capability surface is opened: an action gets exactly what `collect()`
  gets.

### C. Core surface: supervisor executes; API exposes two generic routes; discovery serves declarations

- **Supervisor** (the single `PluginContext` minter, ADR-0027) gains two thin methods on the
  orchestrator, mirroring `run_pull_cycle_for`:
  - `run_action_for(type_key, source_id, action_id) -> ActionResult` — mints `ctx`, validates the
    action is declared, awaits `plugin.run_action(...)`, and on success runs the **same post-cycle
    promotion hook** the pipeline already runs (`_promote_rule_descriptions(source_type)` is already
    generic over the KV namespace), so an action's KV writes become visible to `/rules` and `/logs`
    without a collect cycle.
  - `action_status_for(type_key, source_id, action_id) -> ActionStatus` — mints `ctx`, awaits
    `plugin.action_status(...)`. MUST be cheap (KV reads; no network — see §D).
  - No serialization against a concurrent pull cycle is guaranteed in v1: KV writes are idempotent
    upserts, and actions must be written to tolerate interleaving (documented in the contract).
- **API** (new module `routes/source_actions.py` — `routes/sources.py` is already ~600 lines):
  - `GET  /sources/{type_key}/actions?source_id=` → declared `SourceAction`s zipped with their
    `ActionStatus`. Read-class route; must not touch the network.
  - `POST /sources/{type_key}/actions/{action_id}?source_id=` → `run_action_for`, awaited
    synchronously (same posture as `POST /sync/{type}`); returns `ActionResult`. 404 for unknown
    type/instance/action. **Auth class B** (action-triggering, ADR-0026): loopback-only now, behind
    the API-key gate the moment the API leaves loopback. No new SSRF vector: the action's network
    target comes from the already-validated, already-class-A source config (same argument as
    ADR-0031 §E) — `action_id` selects among *declared* ids, never reaches a shell or URL.
  - **Progress for long-running actions is deferred to the #139 diagnostics surface.** v1 is
    await-until-done + `long_running` as a UI hint (spinner, extended timeout). If real progress
    percent is ever needed, it rides `InstanceStatus`/#139 — explicitly out of scope here.
- **Discovery** (`GET /sources/types`): each entry gains `"actions": [SourceAction…]` (serialized
  declarations only — no status; discovery stays static and cheap).
- **Frontend**: a generic `SourceActions` component on the Settings source card renders one button
  per declared action (confirm dialog when `confirm` is set; spinner/disable when `long_running`),
  plus the status row (last-run date, stale highlight, message). It replaces the
  `isSuricata`/`SuricataControls` *placement* pattern for declared actions (the Test/Sync controls
  themselves are #138's generalization — siblings, not merged). **A generic hint modal**: when a
  rendered rule has no name AND the event's source declares an action with
  `"rule_descriptions" ∈ provides`, show "Rule descriptions for this source aren't loaded — download
  in Settings → {display_name} ({confirm/size text})". Driven entirely by declared metadata + the
  missing field — never by `type_key`.

### D. The first consumer: Suricata `fetch_ruleset` (manual-only, freshness-informed)

Suricata declares exactly one action:

```python
SourceAction(
    id="fetch_ruleset",
    label="Download ruleset",
    description="Fetch the sensor's Suricata ruleset and load rule descriptions (SID → name).",
    long_running=True,
    confirm="Downloads the ruleset from the sensor over the existing SSH connection "
            "(~40–60 MB for ET Open). FireWatch never downloads rulesets automatically.",
    provides=("rule_descriptions",),
)
```

1. **Manual-only (binding).** The ONLY trigger is the user clicking the button (→ the POST route).
   No fetch on first sync, no scheduled fetch, no fetch-on-stale. Deviation from the
   auto-update convention of IDS rule managers (e.g. `suricata-update`, which is built to be cron'd)
   is deliberate and recorded: FireWatch is the *consumer* of the sensor's already-managed ruleset,
   not its rule manager — and surprise multi-MB transfers on metered links are an operator-hostile
   default. The sensor's own update tooling remains the system of record for rule content.
2. **Transport = the plugin's existing SSH channel** (ADR-0005 collector credentials/connect helper;
   `verify_host_key` semantics unchanged). Remote mode streams the configured rules path (file or
   directory of `.rules`); **local mode reads the local path directly**. No new auth surface, no new
   outbound endpoint class (no HTTP rule-source URLs — that would be a new SSRF surface and a rule-
   manager responsibility, both rejected).
3. **Stored products (all in suricata's `ScopedKV`, ADR-0025 — no new tables):**
   - namespace `rule_descriptions`: SID → msg (the existing promoted namespace, #150) —
     **requires #165** (cap must fit ≥ ~50k entries; without it the download is silently truncated).
   - namespace `ruleset_meta`: `pulled_at`, `size_bytes`, `sha256` (computed **streaming during the
     download only** — never hash 43 MB remotely per cycle), source path/host, and the last observed
     remote `mtime`/`size`.
4. **Freshness = cheap remote `stat`, user decides.** During each remote-mode collect cycle (riding
   the SSH session the collector already opens) the plugin stats the rules path (mtime/size only)
   and records it in `ruleset_meta`. `action_status("fetch_ruleset")` compares stored stat vs the
   download's recorded stat → `stale=True` + message with both dates. FireWatch **informs**; the user
   clicks download or doesn't. Settings load never opens SSH (status reads KV only).
5. **Graceful degradation (pinned, already true today).** Without a downloaded ruleset, nothing
   breaks: collection, scoring, and correlation run on rule IDs; `/logs` falls back to showing the
   bare `rule_id`. The new modal (§C) is the only added behavior on the missing-name path.
6. **Producer rework (closes the hand-copy workaround).** `rules_path` semantics become
   mode-relative: the path on the *collection host* (local FS in local mode; the sensor in remote
   mode). Remote mode **stops** parsing a local path each cycle (the live finding's broken path) and
   does only the cheap stat; local mode keeps the per-cycle producer (a local read is not a
   "transfer") with #165's change-detection.

---

## Alternatives considered

- **A third hard-coded route + frontend branch (`POST /sources/suricata/ruleset`, extend
  `SuricataControls`).** Rejected: entrenches the exact per-source wiring the platform forbids
  (ADR-0010's "install ⇒ appears, uninstall ⇒ gone" cannot hold if core/frontend carry per-source
  action code). The seam costs one contract field + one optional protocol and pays for every future
  source (e.g. an Azure WAF "refresh CRS rule catalog", a GeoIP "download database").
- **Auto-download (on first sync / scheduled / on-stale), like `suricata-update` cron.** Rejected by
  Maintainer (binding): surprise multi-MB transfers on metered/restricted links; FireWatch is not the
  sensor's rule manager. Freshness *information* + a one-click manual action covers the operator
  need without the policy risk.
- **Plugin-defined arbitrary HTTP sub-routes (Grafana `CallResource` model: core proxies
  `/api/plugins/{id}/resources/*` to the plugin).** Rejected for now: maximally flexible, but it
  hands plugins an open HTTP surface (auth, input validation, and OpenAPI coverage per plugin —
  OWASP API5 function-level-authz risk multiplies per route) and the UI cannot render "a button" from
  an opaque route. Declared actions with fixed `id`/`label`/`confirm` are renderable, enumerable,
  and reviewable. The CallResource shape remains the documented escalation path if a future plugin
  genuinely needs request/response richness beyond `run_action`.
- **A generic job framework (202 + job-id polling) for long-running actions.** Rejected (YAGNI): one
  awaited call matches the existing `POST /sync` posture; the 43 MB pull is seconds-to-a-minute on
  realistic links. The upgrade path (progress via `InstanceStatus`/#139) is reserved, not built.
- **Auto-render a form from a per-action input schema (Backstage scaffolder-action / Home Assistant
  service-fields model).** Deferred: v1 actions take no user input (the config they need is the
  source config). An optional `input_schema` field can be added additively to `SourceAction` later
  without breaking declared actions.
- **Store the ruleset file on disk instead of parsed entries in KV.** Rejected: core owns
  persistence (ADR-0025); a plugin writing files invents a parallel store with no cap, no M6
  Postgres story, and no tenant boundary. Only the parsed catalog + metadata are kept; the raw file
  is discarded after streaming parse+hash.

## Reasoning

- **Declare → discover → render is the platform's proven shape.** It is how config cards already
  work (ADR-0010/0019), and it matches how mature plugin hosts expose plugin-contributed operations
  generically: VS Code extensions declare commands (`contributes.commands`: id + title) and the host
  renders them in a generic palette; Home Assistant integrations declare services/actions
  (name, description, fields) that the frontend renders without integration-specific UI; Backstage
  scaffolder actions are registered by id and enumerated for discovery. None of these hosts hard-code
  a plugin's button; neither does FireWatch.
- **The seam is small because everything it needs already exists.** `ScopedKV` (ADR-0025) stores the
  products, `PluginContext` (ADR-0027) carries the capability, the supervisor mints contexts and
  already exposes per-instance verbs (`run_pull_cycle_for`), the pipeline already promotes the
  `rule_descriptions` namespace, and the discovery endpoint already serves per-plugin metadata. The
  ADR adds one metadata field, one optional protocol, two routes, and two supervisor methods.
- **Manual-only with freshness signals is the user-sovereign default.** The system carries the
  information cost (one stat per cycle, bytes); the user carries the transfer decision. This is the
  same "inform, don't act" posture as ADR-0015's Suggest tier and ADR-0031's user-decides sync model.

## Consequences

- **PLUGIN_CONTRACT.md** gains a "Source maintenance actions (optional)" section: `SourceAction`,
  `ActionCapable`, the declared-⇒-implemented invariant, the `provides` facet registry
  (`rule_descriptions` first), idempotency/interleaving expectations, and the no-auto-transfer norm
  for large-payload actions.
- **firewatch-sdk**: `SourceAction`/`ActionResult`/`ActionStatus` models + `ActionCapable` protocol;
  `SourceMetadata.actions` (additive, default `()` — existing plugins unaffected).
- **firewatch-core**: supervisor `run_action_for`/`action_status_for`; post-action promotion reuse.
- **firewatch-api**: `routes/source_actions.py` (GET list+status, POST run); discovery entries gain
  `actions`. Class B gating rides the existing ADR-0026 plan.
- **suricata plugin**: declares `fetch_ruleset`; new `ruleset.py` module; producer rework (§D.6).
  Depends on **#165**.
- **frontend**: generic `SourceActions` card section + generic missing-rule-name hint modal; removes
  the need for any future per-source control component (the existing `SuricataControls` Test/Sync
  generalization remains #138's scope).
- The `isSuricata` branch in `SourceCard.tsx` is *not* extended — declared actions render generically
  from day one.

## Out of scope (this ADR)

- **Progress/percent for long-running actions** — reserved for the #139 diagnostics surface.
- **Per-action input schemas / parameterized actions** — additive later (`input_schema` field).
- **Plugin-defined HTTP sub-routes (CallResource-style)** — documented escalation path, not built.
- **Any rule-management capability** (enabling/disabling rules, `suricata-update` orchestration,
  rule-source URLs/HTTP fetch) — FireWatch consumes the sensor's ruleset; it does not manage it.
- **Scheduled/auto download of anything** — rejected by decision, not deferred.
- **The KV cap fix itself** — that is #165 (hard dependency, separately tracked).
- **#138's Test/Sync generalization and #163's Settings restyle** — siblings touched only at the
  integration point (where the buttons sit on the card).

## References / standards consulted

- VS Code extension API — `contributes.commands` (declared id/title; host renders the palette
  generically): https://code.visualstudio.com/api/references/contribution-points#contributes.commands
- Home Assistant developer docs — integration service/action registration (`services.yaml`:
  name/description/fields; generic frontend rendering):
  https://developers.home-assistant.io/docs/dev_101_services/
- Backstage — scaffolder custom actions (registered by id, enumerable at `/create/actions`):
  https://backstage.io/docs/features/software-templates/writing-custom-actions
- Grafana backend plugins — resource handlers (`CallResource`, `/api/plugins/{id}/resources/*`) as
  the rejected/escalation-path alternative:
  https://grafana.com/developers/plugin-tools/key-concepts/backend-plugins/
- `suricata-update` (the OISF rule manager whose auto-update convention this ADR deliberately does
  NOT adopt — deviation recorded in §D.1): https://suricata-update.readthedocs.io/
- OWASP API Security Top 10 (2023) — API5 function-level authorization (why enumerable declared
  actions beat open plugin sub-routes), API7 SSRF (why targets stay in class-A-reviewed config):
  https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- Internal: ADR-0005, ADR-0010, ADR-0019, ADR-0025 (+ addendum), ADR-0026, ADR-0027, ADR-0031,
  ADR-0033 (naming disambiguation); issues #165, #150, #139, #138, #163; live-systems findings
  2026-06-10 (43 MB ET Open, ~50k rules, hand-copied `rules_path`).
