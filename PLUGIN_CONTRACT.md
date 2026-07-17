# PLUGIN_CONTRACT.md — Telemetry Source Plugin Contract (v1.5)

> **Architect-owned.** Implementation work does not edit this file. A needed change is
> raised as a `contract-change` issue and, if it alters a settled decision, a new ADR in
> `docs/adr/` for Maintainer's approval.

## What a source plugin is
A source plugin packages **one telemetry source type** (e.g. `suricata`, `azure_waf`,
`syslog`) as an installable package under `packages/sources/<type>/`, auto-discovered via
entry points. Adding a source requires **zero edits to `firewatch-core`**.

A plugin defines a **type**; the user runs **N named instances** of it, each with its own
config and `source_id` (e.g. `pi-home`, `azure-juiceshop`). (ADR-0016)

### `source_type` vs `source_id` (ECS-aligned — read this)
- **`source_type`** — a constant your plugin declares about itself in `metadata()` (your
  entry-point key, e.g. `suricata`). ≈ ECS `event.module`/`event.dataset`.
- **`source_id`** — the *user's* runtime instance name, passed into `normalize(raw, source_id)`.
  ≈ ECS `observer.name`/`agent.id`. You never invent or branch on it.

**Built-in cross-source correlation keys on `source_type`** ("multi-source" = telemetry-type
diversity, e.g. IDS + syslog — MITRE ATT&CK Log-Source semantics). Consequence for authors:
your source **joins correlation automatically** by declaring its `source_type` — there is no
correlation code to write, and you must not reason about `source_id` for detection. The store
watermarks per `(source_type, source_id)`; you do not manage that.

## Registration (entry point)
```toml
# packages/sources/suricata/pyproject.toml
[project.entry-points."firewatch.sources"]
suricata = "firewatch_suricata.plugin:SuricataSource"
```

## Two flavors (ADR-0005 + Syslog) — anchored on the existing Pull/Push collector protocols
```python
# firewatch-sdk
class PullSource(Protocol):      # watermark-driven: Suricata SSH, Azure WAF
    def collect(
        self, cfg: BaseModel, since: str | None, ctx: PluginContext
    ) -> AsyncIterator[RawEvent]: ...

class PushSource(Protocol):      # listener: Syslog UDP/TCP
    # emit takes a *batch* — listeners coalesce UDP/TCP bursts into one call
    # (matches the v1 EventCallback shape; avoids per-datagram await overhead).
    async def start(
        self,
        cfg: BaseModel,
        emit: Callable[[list[RawEvent]], Awaitable[None]],
        ctx: PluginContext,
    ) -> None: ...
    async def stop(self) -> None: ...
```

### The collection context (`ctx: PluginContext`) — ADR-0027
Both entrypoints receive a **`PluginContext`** as their final parameter — a frozen value object the
**supervisor mints per running instance** and passes in (it is the trusted holder of your instance's
`(source_type, source_id)` — ADR-0023). It is the single, forward-compatible channel for per-instance
capabilities:
```python
# firewatch-sdk
class PluginContext(BaseModel):
    model_config = {"frozen": True, "arbitrary_types_allowed": True}
    kv: ScopedKV          # your source-scoped KV view, bound to your type_key (ADR-0025)
    source_id: str        # your instance name (ADR-0016) — labelling/logging ONLY, never branch on it
```
- **`ctx.kv`** is the ONLY persistence handle you ever receive (see Database contract below); you are
  never handed a raw `EventStore`.
- **`ctx.source_id`** is your instance name for log lines/metrics; you MUST NOT branch on it for
  detection (Flag B).
- **`stop()` is unchanged** — it carries no per-instance capability.
- **Forward-compatibility:** new per-instance handles (e.g. a logger) are added as new `PluginContext`
  fields, NEVER as new positional parameters — so a plugin that ignores them keeps working. `ctx` does
  NOT touch the output path: `collect` still yields `RawEvent`, `start` still calls
  `emit(list[RawEvent])`, and `normalize()` stays a pure mapping with no `ctx`.

## Every plugin provides
```python
def metadata(self) -> SourceMetadata: ...        # type key, display_name, version, flavor (pull|push)
def config_schema(self) -> type[BaseModel]: ...  # Pydantic; drives the UI card; resolved env > file > default
def validate_config(self, cfg: dict) -> None: ...
def normalize(self, raw: RawEvent, source_id: str) -> SecurityEvent: ...   # the plugin OWNS its mapping
async def health_check(self, cfg: BaseModel) -> bool: ...
```

`SourceMetadata` is a **frozen Pydantic v2 model** (a value object the plugin constructs and
returns), NOT a Protocol — only the behavioral interfaces (`SourcePlugin`, `PullSource`,
`PushSource`, `EventStore`, `AIEngine`, `Notifier`, `Enricher`) are Protocols:

```python
# firewatch-sdk
class SourceMetadata(BaseModel):
    model_config = {"frozen": True}
    type_key: str                    # entry-point key; becomes the event's source_type (e.g. "suricata")
    display_name: str                # human label for the UI source card
    version: str                     # plugin version (SemVer string)
    flavor: Literal["pull", "push"]  # typed discriminator for the loader
```
`type_key` flows into `source_type` (and thus event IDs, dedup, and the
`(source_type, source_id)` watermark) — constrain it to **`^[a-z][a-z0-9_]*$`** (must start with a
lowercase letter). A **leading underscore is RESERVED FOR CORE**: core uses underscore-prefixed
`source_type` sentinels (e.g. `_global`) for its own internal scopes, so a plugin can never declare
one and collide with them (ADR-0025 addendum, BLOCKING-2). The scaffold tool enforces the same
pattern.

## Source maintenance actions (optional) — ADR-0034
A plugin MAY declare **maintenance actions** — operational verbs against its own source instance
(e.g. Suricata's `fetch_ruleset`) — that the Settings source card renders **generically**: declared ⇒
button appears; nothing declared ⇒ no button; zero core/frontend edits per source. (Do not confuse
with the ADR-0033 *triage* action seam, which is UI-internal and never touches this contract.)

```python
# firewatch-sdk
class SourceAction(BaseModel):       # frozen value object
    id: str                          # ^[a-z][a-z0-9_]*$, unique within your plugin
    label: str                       # button text ("Download ruleset")
    description: str                 # help/tooltip
    long_running: bool = False       # UI shows spinner + extended timeout
    confirm: str | None = None       # pre-flight confirmation prose — put size/cost warnings here
    provides: tuple[str, ...] = ()   # well-known facets this action supplies (see registry below)

class SourceMetadata(BaseModel):
    ...
    actions: tuple[SourceAction, ...] = ()   # default () — declaring nothing is the norm
```

**If (and only if) `metadata().actions` is non-empty, your plugin MUST also implement:**

```python
# firewatch-sdk
@runtime_checkable
class ActionCapable(Protocol):
    async def run_action(self, action_id: str, cfg: BaseModel, ctx: PluginContext) -> ActionResult: ...
    async def action_status(self, action_id: str, cfg: BaseModel, ctx: PluginContext) -> ActionStatus: ...
```

`ActionResult` = frozen `{ok: bool, message: str, detail: dict[str, str]}`. `ActionStatus` = frozen
`{last_run_at: str | None, stale: bool | None, message: str | None, detail: dict[str, str]}` — your
plugin supplies the human prose; the UI renders it verbatim plus a stale highlight. Rules:

- **Persistence:** action products and state go through `ctx.kv` ONLY (the Database contract below
  applies unchanged). After a successful `run_action`, core re-runs the same KV promotion it runs
  post-collect-cycle (e.g. the `rule_descriptions` namespace), so results are visible without a sync.
- **`action_status` MUST be cheap** — KV reads only, never network/SSH (it is called on Settings
  load). Record any remote freshness probe during your `collect()` cycle instead.
- **Idempotent + interleaving-tolerant:** core does not serialize an action against a concurrent
  collect cycle; KV writes are idempotent upserts.
- **Unknown `action_id`** → raise `ValueError` (core maps it to 404). Undeclared actions are
  unreachable: the route validates against your declared ids.
- **No automatic large transfers, ever.** An action that moves a non-trivial payload (rulesets,
  databases) runs ONLY on the user's explicit click and MUST state its approximate size in
  `confirm`. Your plugin must degrade gracefully when the action has never been run (Suricata:
  scoring/correlation run on rule IDs; `/logs` shows the bare `rule_id`).
- Trigger surface: `POST /sources/{type_key}/actions/{action_id}` (auth class B, ADR-0026);
  declarations ride `GET /sources/types`; status rides `GET /sources/{type_key}/actions`.

**`provides` facet registry** (well-known strings; unknown facets are inert/forward-compatible):
- `rule_descriptions` — the action populates the `rule_descriptions` KV namespace (rule-id → name).
  The UI uses this to show a generic "rule names missing — download in Settings" hint.

## `normalize()` responsibilities
Map raw → `SecurityEvent` and MUST set:
- `source_type` **and** `source_id`
- `action` with correct semantics — IDS detections → `ALERT`, WAF/IPS blocks → `BLOCK` (ADR-0012)
- `severity` (see **Severity semantics** below — the levels have defined meanings), `category`,
  `rule_id`, `rule_name`, `payload_snippet`
- **`attack_technique` / `attack_tactic` / `kill_chain_phase` / `capec_id`** where derivable from
  source metadata — Suricata ET Open `mitre_*` tags, OWASP CRS CAPEC tags (ADR-0014)

Unmapped vendor fields stay in `RawEvent.data` — never invent new top-level fields. This is the
ECS/OCSF "extension attributes overlay one schema" model — not parallel storage (see Database
contract below). Never fabricate transport fields you do not have (no placeholder
`destination_port`/`protocol`); leave them unset and keep the raw in `RawEvent.data`.

### Severity semantics (ADR-0069) — what the five levels mean

`severity` is a **routing input, not decoration**: an `ALERT` whose source-declared severity is
`high` or `critical` qualifies its actor for the triage queue on its own (ADR-0067 D1(b)). Your
mapping therefore carries a contract obligation, defined here.

**Normative vocabulary.** FireWatch adopts the Sigma `level` definitions as the meaning of the
five levels (FireWatch's `info` = Sigma's `informational`; the SDK literal keeps the short
spelling). Quoted verbatim from the Sigma specification
(<https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md>):

> "The level field contains one of five string values. It describes the criticality of a
> triggered rule. While `low` and `medium` level events have an informative character, events
> with `high` and `critical` level should lead to immediate reviews by security analysts.
>
> - `informational`: Rule is intended for enrichment of events, e.g. by tagging them. No case or
>   alerting should be triggered by such rules because it is expected that a huge amount of
>   events will match these rules.
> - `low`: Notable event but rarely an incident. Low rated events can be relevant in high numbers
>   or combination with others. Immediate reaction shouldn't be necessary, but a regular review
>   is recommended.
> - `medium`: Relevant event that should be reviewed manually on a more frequent basis.
> - `high`: Relevant event that should trigger an internal alert and requires a prompt review.
> - `critical`: Highly relevant event that indicates an incident. Critical events should be
>   reviewed immediately. It is used only for cases in which probability borders certainty."

**The operational clause (ADR-0069 D1) — how a mapping is judged:**

> **`severity ∈ {high, critical}` on an ALERT is an assertion that this event, on its own,
> belongs in the triage queue (ADR-0067 D1(b)).** A mapping is therefore correct only if the
> events it labels `high`+ are ones an operator should promptly review one at a time.
> **Corollary (the distribution rule): any event class that is ambient at volume on a healthy
> deployment maps to at most `medium` — by definition, not by tuning.** Escalation of ambient
> classes is the job of the correlation rules (ADR-0067 D1(a)) and the band axis (ADR-0067 D5),
> which exist precisely to turn volume and combination into a claim.

**The mapping discipline (ADR-0069 D3) — what every plugin author MUST do:**

1. **Translate the vendor's own published scale where one exists; cite it.** If the source
   declares severity (Suricata priority, CEF 0–10, Windows Event level, Zeek notice…), the
   normalizer *translates* that scale per the vendor's published semantics into the Sigma-defined
   levels — it never re-scores individual events. (syslog_cef's CEF 0–10 banding per the ArcSight
   spec is the reference implementation of this pattern.)
2. **Justify every band against the definitions above** — in the mapping-table comment, with the
   vendor doc URL.
3. **State the distribution.** The plugin's PR must say what the source's *ambient mass* (what a
   healthy, internet-exposed deployment generates continuously) maps to and what its *genuine
   assertions* (events an operator should see one at a time) map to, and show the ambient mass
   lands ≤ `medium` (the corollary above). "What does a healthy night look like?" is an
   acceptance question, not an afterthought.
4. **Fail quiet.** Missing/unparseable vendor severity maps to `low` (telemetry-grade), never to
   a gate-qualifying level, and never fabricated upward. (Consistent with ADR-0067 D3:
   undeclared severity never queues.)
5. **Contested calls are adjudicated by the volume oracle** (ADR-0068 / `tests/volume/`): if a
   mapping floods the queue under a realistic manifest, the mapping is wrong — mechanically.

**OCSF note (ADR-0069 D2):** OCSF 1.8.0 `severity_id` stays the *export encoding*
(info=1 … critical=5, ADR-0040); FireWatch maps to OCSF's identifiers, not its level prose.
Where OCSF's prose diverges from Sigma's (notably `medium`), Sigma governs the internal meaning.

## Config (ADR-0006)
`config_schema` is a Pydantic model. Resolution precedence: **env vars > `firewatch_config.json` > defaults.**
Secrets use `SecretStr`, never plain `str`. The schema is what the UI renders the source's config card from.
**`SecretStr` fields MUST default to `None`** (never a literal string): the discovery endpoint
(`GET /sources/types`, MA.3) serves `config_schema().model_json_schema()`, and Pydantic emits a
field's `default` verbatim — a non-`None` secret default would leak into the schema response.

## Hard rules
- Depend on `firewatch-sdk` **only**. Never import `firewatch-core`. Never import `legacy/`.
- `collect()` / the listener must be **cancellable** and must **not raise out of their loop** —
  one failing instance must never crash the supervisor or other sources.
- If logged payloads reach the LLM, they must be **delimited as untrusted data** (see ARCHITECTURE.md security posture).

## Database contract (ADR-0025)
**A source plugin never touches the database directly. It owns `normalize()` and its config
schema; the core owns all persistence and all DDL.**

1. **No DDL, ever.** A plugin does not open a DB connection and does not ship
   `CREATE`/`ALTER`/`DROP`/migrations. (This is the same boundary as "never import `firewatch-core`":
   core owns persistence.)
2. **Primary path — normalize into `SecurityEvent`.** Correlation-relevant data becomes typed
   fields; vendor leftovers stay in `RawEvent.data` (the OCSF/ECS extension model).
3. **Auxiliary state — a source-scoped KV VIEW (`ScopedKV`).** For generic state that is not an
   event (rule-description catalogs, signature maps, a cursor richer than the watermark), core
   hands your plugin a **`ScopedKV` view bound to your `type_key`**. Its API takes only
   `(namespace, key, value)` — there is **no `source_type` parameter**:
   `await kv.put(namespace, key, value)` / `await kv.get(namespace, key) -> str | None` /
   `await kv.get_all(namespace) -> dict[str, str]`. **`source_type` is the enforced tenant boundary
   and is closed over by core — you never supply it, so you structurally cannot name (let alone read
   or clobber) another plugin's rows.** This is capability-based isolation, not a checked argument
   (ADR-0025 addendum; OWASP A01 / NIST AC-6). You receive the view as **`ctx.kv`** on the
   `PluginContext` passed to your collection entrypoint (`collect`/`start`) — see "The collection
   context" above (ADR-0027); you never receive the raw `EventStore`. The raw `source_kv_*(source_type, …)` methods on `EventStore` are **core-privileged
   and never exposed to plugins.** The existing `*_rule_descriptions`, watermark, and geo helpers are
   ergonomic specializations of the same backing store. There is a per-`(source_type, namespace)`
   size cap; exceeding it raises.
4. **All schema is core-owned and reviewed.** A genuinely new column/table is a `contract-change`
   issue → an ADR → a core schema edit. Adding a **source** = zero core edits; adding a **new
   storage shape** is deliberately a core decision (preserves ADR-0007's one-class Postgres swap).
5. **Escape hatch (documented, NOT built).** If a future source ever needs storage the generic
   KV/event model cannot express, the *only* sanctioned path is the Backstage shape: the plugin
   **declares** tables/migrations declaratively in its manifest, **core validates and runs** them
   under a `src_<source_type>_*` namespace and emits backend-appropriate DDL, and the plugin
   accesses them only via SDK methods scoped to its namespace — never a raw connection, never
   cross-plugin reads. This is defined so no plugin invents a WordPress-style answer; it is built
   only when a real source needs it.

## Definition of done (a source is complete when)
- [ ] entry point registered and discovered by the loader
- [ ] `normalize()` emits a valid `SecurityEvent`, incl. action mapping + MITRE/CAPEC where available
- [ ] `config_schema` renders a config card; env > file > default honored
- [ ] golden tests pass: sample vendor logs → expected `SecurityEvent`s pinned to the **canonical
      standard** (OCSF/ADR-0020 + MITRE/ADR-0014 + action/ADR-0012), NOT to any legacy classification
      output (ADR-0024). Build fixtures to the published standard; never record them from `legacy/`.
- [ ] `security-reviewer`: no blocking findings (incl. payloads delimited if they reach the LLM)

## Reference implementation
`packages/sources/suricata/` (migrated from `adapters/collectors/suricata.py`) is the canonical
PullSource example: SSH/local modes, `SSHConnectionError` remediation, watermark, mocked-SSH tests.

## Governance
The architect owns this contract. Changes are a `contract-change` issue plus a new ADR if a settled
decision is affected. See `docs/adr/`.

## Changelog

### v1.5 — `SourceMetadata.enforcement` — enforcement-posture default (ADR-0067 D6, issue #75)

`SourceMetadata` gains 1 new **additive, defaulted** field (`area:sdk`):

- `enforcement: Literal["observe", "enforce", "detect_only"] | None = None` —
  what this source's producing control COULD have done to traffic it observed.
  `None` (the default) means "undeclared" — the escalation decider keeps the
  conservative `block_status_unknown` label for this source's qualified Tier-2
  verdicts, exactly as before this field existed. Declaring a value narrows that
  label to an honest, posture-specific one (`not_blocked_passive` / `detected_no_action`
  / `not_blocked_enforcing`, ADR-0067 D6 + Amendment 1) the moment the actor's
  contributing instances declare a single, uniform posture.

**Plugin author impact: none required, declaring is encouraged.** Every existing
plugin that omits `enforcement` remains conformant — construction is unaffected and
behaviour is byte-identical (every qualified Tier-2 verdict keeps today's generic
label). This is the ADR-0048/0055/0060 additive-growth pattern; no PLUGIN_CONTRACT
break. Posture is **per-instance, not per-plugin** in general (e.g. Suricata can run
IDS or inline IPS) — this field is only the *plugin-declared default* half; the
core-owned per-instance override lands in Phase B (issue #44) and does not change
this field's shape.

In-tree plugins declaring a default in this issue: `suricata`/`syslog`/`linux_auth` →
`observe`; `clamav` → `detect_only`; `aws_network_firewall` → `enforce`. `azure_waf`
deliberately declares nothing (its posture is per-policy Detection/Prevention — set
per instance in Phase B).

Standard anchor: OCSF 1.8.0 `action_id` 3 Observed / 2 Denied —
https://schema.ocsf.io/api/1.8.0/classes/detection_finding (backs `observe`/`enforce`;
`detect_only` is FireWatch's label for a host control that detects without removing,
no direct OCSF `action_id` equivalent).

### v1.4 — ADR-0069 D5 severity semantics become contract surface (issue #70)

**No model or signature change.** `SecurityEvent.severity` has carried the five-level
`SeverityLiteral` (`info`/`low`/`medium`/`high`/`critical`) since v1.0 with no stated meaning;
ADR-0067 D1(b) made it a triage-routing input, so the levels now have **defined, normative
semantics** — the new "Severity semantics" subsection under `normalize()` responsibilities:

- The Sigma `level` vocabulary is normative (quoted verbatim there, with source URL);
  FireWatch's `info` = Sigma's `informational` (the SDK literal spelling stands — ADR-0069 D1).
- The operational clause: `high`+ on an ALERT asserts the event belongs in the triage queue on
  its own; anything ambient at volume on a healthy deployment maps to at most `medium`.
- The five-rule mapping discipline (translate-and-cite the vendor scale, justify each band,
  state the ambient/assertion distribution, fail quiet to `low`, volume-oracle adjudication)
  — ADR-0069 D3.

**Plugin author impact: normative for every mapping.** Existing plugins' signatures are
untouched; in-tree severity recalibrations to these semantics are tracked in their own issues
(#68 suricata/aws-nfw, #69 syslog/syslog_cef fallback; Azure WAF in M3 — ADR-0069 D4).

Standard anchors: Sigma specification `level` —
https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md;
OCSF 1.8.0 `severity_id` (export encoding only, identifiers not prose — ADR-0069 D2, ADR-0040) —
https://schema.ocsf.io/api/1.8.0/classes/detection_finding.

### v1.3 — ADR-0058 §D3 per-detection severity + escalation metadata (issue #NNN)

`Detection` gains 2 new **additive, defaulted** fields (`area:sdk`):

- `severity: SeverityLiteral | None = None` — Sigma-anchored severity level
  (`info`/`low`/`medium`/`high`/`critical`).  Populated by `detector.py` rules that have
  declared a severity in `escalation.policy.ESCALATION_POLICY`.  `None` when the producing
  rule has not declared a level (the default — zero behaviour change).

- `auto_escalate: bool = False` — `True` when the rule is loud enough to jump the triage
  queue without waiting for volume or AI confirmation.  Consumed by the D2 decider (issue
  #NNN, not built here).  Defaults to `False` — non-escalating.

**Plugin author impact: none.** Both fields are optional with safe defaults.  Existing
plugins that construct `Detection(...)` without these fields remain conformant — they resolve
to `severity=None, auto_escalate=False`.  This is the ADR-0048/0055 additive-growth
pattern; no PLUGIN_CONTRACT break.

Standard anchor: Sigma `level` vocabulary —
https://sigmahq.io/docs/basics/rules.html (backs the five severity levels).
Elastic Detection Rules `risk_score` (0-100 ordinal) —
https://www.elastic.co/guide/en/security/current/rules-ui-create.html (backs `auto_escalate` weighting).

### v1.2 — ADR-0055 file-IOC, DNS-answer, JA3 fields (issue #NNN)

`SecurityEvent` gains 7 new **optional/nullable** fields (all default to `None`):

**Group E — File IOC** (OCSF `File` object + `Fingerprint`/`hashes[]` array):
`file_sha256`, `file_md5`, `file_sha1`, `file_name`, `file_mime_type`

OCSF alignment: `File.hashes[].value` with algorithm_id 3 (SHA-256), 1 (MD5), 2 (SHA-1).
ECS alignment: `file.hash.sha256`, `file.hash.md5`, `file.hash.sha1`, `file.name`, `file.mime_type`.
`file_sha256` is queryable via `FilterSpec` (threat-intel IOC pivot).

**Group F — DNS answers** (OCSF DNS Activity class_uid 4003, `answers[]` array):
`dns_answer` — resolved A/AAAA/CNAME values, comma-joined for flat scalar storage.
OCSF alignment: `answers[].rdata` (split at the OCSF export boundary).
ECS alignment: `dns.answers[].data` / `dns.resolved_ip`.
Queryable via `FilterSpec` for passive-DNS pivoting.

**Group G — JA3 fingerprint** (OCSF TLS object on Network Activity 4001):
`tls_ja3` — JA3 client fingerprint (stock-Zeek default; ECS `tls.client.ja3`).
Coexists with `tls_ja4`/`tls_ja4s` (ADR-0048/ML-13); JA3 for sensor compatibility, JA4 as the forward direction.
`tls_ja3s` (server) is deliberately excluded — analysts pivot on the client fingerprint.

**Plugin author impact: none.** Every new field is optional and defaults to `None`. Existing plugins
require no changes and remain conformant — they simply leave these fields unpopulated. Sources
populate the subset they have; the core never fabricates a value. The store gains the matching
columns via idempotent additive migration (NB-10, same pattern as NB-5/NB-6/NB-7).

### v1.1 — ADR-0048 network-depth fields (ML-1, issue #NNN)

`SecurityEvent` gains 16 new **optional/nullable** fields (all default to `None`):

**Group A — flow volume & duration** (OCSF Network Activity 4001):
`bytes_in`, `bytes_out`, `packets_in`, `packets_out`, `flow_duration_ms`

**Group B — DNS** (OCSF DNS Activity 4003):
`dns_query`, `dns_rcode`

**Group C — TLS / JA4 fingerprint** (OCSF TLS object on 4001):
`tls_ja4`, `tls_ja4s`, `tls_sni`, `tls_version`

**Group D — HTTP** (OCSF HTTP Activity 4002):
`http_method`, `http_host`, `http_url`, `http_user_agent`

**`destination_ip`** (was on the model since v1 but dropped at the store boundary; now persisted).

**Plugin author impact: none.** Every new field is optional and defaults to `None`. Existing plugins
require no changes and remain conformant — they simply leave these fields unpopulated. Sources populate
the subset they have; the core never fabricates a value. The store gains the matching columns via
idempotent additive migration (NB-7, same pattern as NB-5/NB-6).

### v1.0 — Initial contract
Established `SourcePlugin`, `PullSource`, `PushSource` protocols; `SourceMetadata`, `PluginContext`,
`ScopedKV`; `normalize()` responsibilities; database contract (ADR-0025).

