# ADR-0025: Source-Plugin Database Contract — Canonical Schema + Source-Scoped KV, No Plugin DDL

**Date:** 2026-06-04
**Status:** Accepted

**Relates to:** ADR-0007 (storage: SQLite now, PostgreSQL at M6 — "one class to replace"),
ADR-0016 (multi-source-per-type; `source_type`/`source_id`), ADR-0020 (lightweight-OCSF
normalization), PLUGIN_CONTRACT.md (the source-plugin interface).
**Evidence:** `docs/research/db-modularity-best-practices.md`.

---

## Context

Third parties will write source plugins that ship as packages and run **in the FireWatch process
against a shared database**. We must settle exactly how a plugin is allowed to touch persistence,
balancing modularity, community-contribution safety, and the non-negotiable "core owns
persistence." `docs/research/db-modularity-best-practices.md` surveyed comparable extensible
platforms and the SIEM normalization standards to ground this; the three candidate levels are:

- **(a) Canonical schema + tags.** Core owns ONE schema; events carry `source_type`/`source_id`;
  no per-source tables. FireWatch already does this (`sqlite_store.py` `logs` table, ADR-0016).
- **(b) PLUS a generic, source-scoped auxiliary KV surface via core methods.** Plugins call typed
  `EventStore` methods (the existing `upsert_rule_descriptions`/`get_rule_descriptions`,
  generalized); plugins never write DDL.
- **(c) Plugins ship their OWN tables/migrations**, read/written directly by the plugin — the
  generalized form of v1's `suricata_categories`-baked-into-the-schema smell.

---

## Decision

**Adopt (a) + a tightened (b). Explicitly reject open (c). Define — but do NOT build — a
constrained-(c) escape hatch in the contract.**

1. **No DDL, ever, from a plugin.** A plugin does not import `firewatch-core`, does not open a DB
   connection, and does not ship `CREATE`/`ALTER`/`DROP`/migrations. (Reinforces the existing hard
   rule: depend on `firewatch-sdk` only.) Core owns **all** schema and **all** DDL.

2. **Primary path = (a): normalize into `SecurityEvent`.** Correlation-relevant data becomes typed
   fields (action, severity, category, MITRE/CAPEC, OCSF class); vendor-specific leftovers stay in
   `RawEvent.data`. This is the ECS/OCSF "extension attributes overlay one schema" model, not
   parallel storage.

3. **Auxiliary state = (b): a small, generic, source-scoped key/value surface on the `EventStore`
   protocol, callable only through the SDK.** Generalize the existing `rule_descriptions` path into
   namespaced primitives the core implements once and that work identically on SQLite now and
   Postgres at M6:
   - `source_kv_put(source_type, namespace, key, value)` / `source_kv_get(source_type, namespace,
     key)` (plus a `source_kv_get_all(source_type, namespace)` read) — for rule descriptions,
     signature catalogs, small lookup maps, plugin-private cursors richer than a watermark.
   - The existing typed helpers (`*_rule_descriptions`, watermark, geo) remain as ergonomic
     specializations layered over the same backing store.
   - **`source_type` is the enforced tenant boundary and is INJECTED BY CORE, never supplied by the
     plugin.** The plugin's declared `source_type` (constrained `^[a-z0-9_]+$`, already in the
     contract) scopes every row, so one plugin can neither read nor clobber another's rows. This is
     the Backstage isolation principle applied **without** granting DDL.
   - One backing table keyed on `(source_type, namespace, key)`. Value is a TEXT/JSON blob; the SDK
     exposes a typed wrapper. The store enforces a per-`(source_type, namespace)` size/row cap to
     prevent a runaway plugin bloating the DB.

4. **All schema is core-owned and reviewed.** Any genuinely new column/table is a `contract-change`
   issue → an ADR → a core schema edit (GitLab's "schema is a reviewed artifact" discipline).
   Adding a **source** still requires zero core edits; adding a **new storage shape** is
   deliberately a core decision. This preserves ADR-0007's "one class (`SQLiteEventStore`) to
   replace" property for the M6 Postgres swap.

5. **Escape hatch for constrained (c) — documented, NOT built.** *If and only if* a future source
   needs storage the generic KV/event model genuinely cannot express, the path is the Backstage
   shape, never WordPress's:
   - the plugin **declares** its tables/migrations **declaratively in its manifest** (not as
     executable SQL);
   - **core validates and runs** the migration (core owns DDL), enforces a `src_<source_type>_*`
     table namespace, and emits backend-appropriate DDL (SQLite/Postgres) so M6 stays a core
     concern;
   - the plugin reads/writes **only via SDK methods** scoped to its namespace — never a raw
     connection, never cross-plugin reads.
   This keeps "core owns persistence" intact even in the escape-hatch case. It is built only when a
   real source demonstrably needs it — not preemptively.

---

## Alternatives considered

- **Open (c): plugins ship and run their own tables/migrations directly (WordPress `dbDelta`
  model).** Rejected. The research documents its failure modes: orphaned tables and DB bloat,
  prefix collisions, `dbDelta`'s inability to reliably drop columns, and migration-hell on core
  upgrades. It is also a **privilege-escalation surface** — a plugin that can `CREATE`/`ALTER`/`DROP`
  can touch core tables (`logs`, `sync_state`) — and it **couples every community plugin to the M6
  Postgres swap** (hand-written SQLite DDL is not valid Postgres DDL), defeating ADR-0007.
  ([WordPress plugin tables][wp-tables], [dbDelta limits][wp-dbdelta], [orphaned-table debt][wp-junk],
  [WP Trac #50799][wp-trac]; multi-tenant isolation risk: [Redis][mt-redis], [Bytebase][mt-bytebase]).
- **(a) alone (no auxiliary state at all — OTel/Grafana "stateless transformer" purity).** Rejected
  as slightly too strict for FireWatch: rule-description catalogs and richer-than-watermark cursors
  are real, generic needs already present (`rule_descriptions`). The minimal, mediated KV surface
  (b) covers them without opening DDL — matching Sentry's "extensions go through a service layer,
  never direct DB."
- **Build the constrained-(c) escape hatch now.** Rejected (YAGNI): the research shows *no*
  realistic near-term source (Suricata, Azure WAF, Syslog) clears the bar for plugin-owned storage —
  every need is an event field (a) or generic scoped state (b). Defining the safe shape in the
  contract is cheap and prevents a future ad-hoc WordPress-style answer; building it now is
  speculative.

---

## Reasoning

- **The SIEM/observability standard is "normalize everything into one schema."** ECS exists so that
  "existing searches and dashboards can be leveraged" instead of new per-source content; OCSF is an
  "extensible, vendor-agnostic" common schema vendors map *into*. Both handle vendor nuance with
  **extension attributes / `unmapped` overlays on the common classes, not parallel storage**
  ([ECS][ecs-blog], [ECS][ecs-norm]; [OCSF][ocsf-home], [OCSF CONTRIBUTING][ocsf-contrib]).
  FireWatch's value — cross-source correlation keyed on `source_type`, unified dashboards, one AI
  scoring path — *depends on* every source sharing `SecurityEvent`. A source that needs its own
  tables to be useful is, by definition, not normalized.
- **Mature extensible platforms mediate plugin state; they do not hand out the DB.** Sentry routes
  integrations through a service/API layer with no direct DB; OTel/Grafana keep plugins stateless
  and push state outward; GitLab centralizes *all* schema in a reviewed database dictionary with no
  third-party-table path; Backstage is the *only* "safe (c)," and only because the framework issues
  the client and **enforces** per-plugin namespace isolation with no cross-plugin reads
  ([Sentry][sentry-arch], [GitLab][gitlab-dict], [Backstage][bs-db]). FireWatch's `EventStore`
  protocol is exactly that mediating layer; (a)+(b) is the consensus shape.
- **(a)+(b) is small and mostly built.** The `rule_descriptions` path already exists; the work is to
  generalize it into one namespaced, `source_type`-scoped KV surface on the `EventStore` protocol
  and write the rules down. It introduces no new dependency and preserves ADR-0007's single-class
  swap.

---

## Consequences

- **PLUGIN_CONTRACT.md** gains a "Database contract" section: no plugin DDL / no DB connection;
  primary path = normalize into `SecurityEvent`; auxiliary state = the source-scoped KV surface
  (core injects `source_type`); the documented-not-built constrained-(c) escape hatch.
- **`EventStore` protocol (SDK)** gains `source_kv_put` / `source_kv_get` / `source_kv_get_all`
  (with `source_type` as the first, core-injected argument); the existing `*_rule_descriptions` /
  watermark / geo helpers remain. (Implementation is a core task on the base-infra milestone; the
  architect only specifies the signature here.)
- **`SQLiteEventStore`** gains one `source_kv` backing table keyed on `(source_type, namespace,
  key)` with a per-scope cap; M6 Postgres re-implements the same method.
- Adding a source = zero core edits (unchanged). Adding a new storage *shape* = a deliberate core
  decision (ADR + core schema edit).

---

## References / standards consulted

- ECS normalization philosophy: [ecs-blog][ecs-blog], [ecs-norm][ecs-norm].
- OCSF common schema + extensibility: [ocsf-home][ocsf-home], [ocsf-contrib][ocsf-contrib].
- Sentry mediated integration architecture: [sentry-arch][sentry-arch].
- GitLab database dictionary (centrally-governed schema): [gitlab-dict][gitlab-dict].
- WordPress plugin tables (cautionary tale): [wp-tables][wp-tables], [wp-dbdelta][wp-dbdelta],
  [wp-junk][wp-junk], [wp-trac][wp-trac].
- Backstage per-plugin isolated DB service (the safe (c)): [bs-db][bs-db].
- Multi-tenant data-isolation risk: [mt-redis][mt-redis], [mt-bytebase][mt-bytebase].
- Internal: `docs/research/db-modularity-best-practices.md`, ADR-0007, ADR-0016, ADR-0020.

[ecs-blog]: https://www.elastic.co/blog/introducing-the-elastic-common-schema
[ecs-norm]: https://www.elastic.co/elasticsearch/common-schema
[ocsf-home]: https://ocsf.io/
[ocsf-contrib]: https://github.com/ocsf/ocsf-schema/blob/main/CONTRIBUTING.md
[sentry-arch]: https://develop.sentry.dev/application-architecture/overview/
[gitlab-dict]: https://docs.gitlab.com/development/database/database_dictionary/
[wp-tables]: https://developer.wordpress.org/plugins/creating-tables-with-plugins/
[wp-dbdelta]: https://vulnwp.org/blog/wordpress-dbdelta-example-create-custom-plugin-table
[wp-junk]: https://blog.cogitactive.com/website/hidden-plugin-junk-database-manually/
[wp-trac]: https://core.trac.wordpress.org/ticket/50799
[bs-db]: https://backstage.io/docs/backend-system/core-services/database/
[mt-redis]: https://redis.io/blog/data-isolation-multi-tenant-saas/
[mt-bytebase]: https://www.bytebase.com/blog/multi-tenant-database-architecture-patterns-explained/

---

## Addendum (2026-06-04): scoped-KV enforcement mechanism

**Status: this ADR remains Accepted.** This addendum does NOT reverse Decision §3 — it pins the
*mechanism* that realizes "`source_type` is the enforced tenant boundary and is INJECTED BY CORE,
never supplied by the plugin." A security review of PR #38 (#30) found the as-implemented surface
exposes `source_kv_*(source_type, …)` with `source_type` as a free caller argument and no scoped
wrapper (BLOCKING-1): nothing structurally prevents a plugin from naming another tenant's scope.
The original wording ("injected by core") described the intent but left the seam unspecified, so
the implementation satisfied the letter (core *can* inject) without the guarantee (a plugin
*cannot* forge). This addendum closes that gap.

### Standard consulted (why a scoped view, not a documented convention)

"Pass the tenant id and document that callers must not lie" is a checked-permission model — it
relies on every caller (including third-party plugins) behaving. The published standard for this
class of boundary is **capability-based security / no ambient authority**: the object a principal
holds *is* its authority, and it has no vocabulary to name authority it was not granted. A plugin
that holds only a view bound to its own `type_key` cannot *express* another tenant's scope —
isolation by construction, not by audit. This also directly answers the **confused-deputy**
problem (a privileged component performing an action on behalf of a less-privileged caller using
the caller-supplied name). Grounding:

- **OWASP A01:2021 — Broken Access Control**, whose canonical failures include "permitting
  viewing or editing someone else's account by providing its unique identifier (insecure direct
  object reference)" — which is exactly what a free `source_type` argument is. ([owasp-a01][owasp-a01])
- **NIST SP 800-53 Rev. 5 — AC-6 Least Privilege / AC-3 Access Enforcement**: enforce the minimum
  authority necessary; the mechanism, not policy text, must constrain it. ([nist-ac6][nist-ac6])
- **Capability-based security / confused deputy** (Hardy, "The Confused Deputy"): designate
  authority by an unforgeable reference rather than a forgeable name. ([confused-deputy][confused-deputy])
- This matches the Backstage precedent already cited in this ADR: the framework *issues the
  scoped client* to each plugin and the plugin never names another plugin's namespace. ([bs-db][bs-db])

FireWatch deviates from "just check the argument" deliberately: plugins are third-party,
in-process, and untrusted-by-default, so the boundary must hold structurally.

### 1. Plugins receive a scoped KV VIEW, never the raw `EventStore`

Core hands each plugin a `ScopedKV` bound to that plugin's `type_key`. The view's API takes only
`(namespace, key, value)` — **no `source_type` parameter** — so a plugin structurally cannot name
another source's scope. Defined in the SDK as a `Protocol`:

```python
# firewatch-sdk: firewatch_sdk.ports
@runtime_checkable
class ScopedKV(Protocol):
    """A source-scoped KV view. The bound source_type is closed over by core at
    construction; it is NOT an argument here, so a plugin cannot address another
    tenant's scope (capability-based isolation; ADR-0025 addendum)."""
    async def put(self, namespace: str, key: str, value: str) -> None: ...
    async def get(self, namespace: str, key: str) -> str | None: ...
    async def get_all(self, namespace: str) -> dict[str, str]: ...
```

`namespace` remains a free argument (a plugin may organize its OWN scope into namespaces);
`source_type` is the only thing closed over, because it is the only thing that crosses the tenant
boundary.

### 2. The raw `source_kv_*(source_type, …)` methods are CORE-PRIVILEGED

`EventStore.source_kv_put / source_kv_get / source_kv_get_all` keep their `source_type`-first
signatures and stay on the `EventStore` protocol, but are **core-privileged**: callable only by
core (e.g. the `_global/rule_descriptions` facade and the future supervisor), never handed to a
plugin. A plugin never receives an `EventStore`. The contract states this in prose and the SDK
docstring marks these three methods "core-privileged — not exposed to plugins; plugins use
`ScopedKV`." The `EventStore` protocol is the *mediating layer* (Sentry's service-layer model);
`ScopedKV` is the *capability* core mints from it.

### 3. Construction + injection seam

Core constructs the view by closing over the store and the plugin's `type_key`:

```python
# firewatch-core (NOT in the SDK — the SDK ships only the Protocol):
class _CoreScopedKV:                       # implements firewatch_sdk.ports.ScopedKV
    def __init__(self, store: EventStore, source_type: str) -> None:
        self._store, self._st = store, source_type
    async def put(self, namespace, key, value):
        await self._store.source_kv_put(self._st, namespace, key, value)
    async def get(self, namespace, key):
        return await self._store.source_kv_get(self._st, namespace, key)
    async def get_all(self, namespace):
        return await self._store.source_kv_get_all(self._st, namespace)
```

`source_type` passed to `_CoreScopedKV` is taken from `plugin.metadata().type_key` at wiring time
— never from plugin call arguments.

**Seam choice: the scoped KV is delivered as one field on a `PluginContext` that core/the
supervisor constructs per instance and passes into the collection entrypoints** — i.e.
`collect(cfg, since, ctx)` for `PullSource` and `start(cfg, emit, ctx)` for `PushSource`, where
`ctx.kv` is the plugin's `ScopedKV`. Rationale:

- **It is the supervisor's job to mint capabilities (#22).** The supervisor already owns
  per-instance lifecycle and is the single place that knows `(source_type, source_id)` for each
  running instance (ADR-0023). Minting the scoped view there keeps capability creation in exactly
  one trusted location and keeps the dependency rule intact (core depends on the SDK `ScopedKV`
  protocol; the plugin imports only the SDK).
- **A context object is forward-compatible.** It lets later seams (a scoped watermark accessor, a
  logger, the instance's `source_id`) ride the same channel without re-touching every plugin
  signature — versus widening `collect`/`start` argument-by-argument. `source_id` belongs on the
  context too (a plugin legitimately needs its own instance name; it must still never branch on it
  for detection — ADR-0016).
- **Alternatives rejected:** (a) *inject at plugin instantiation* (constructor/factory) — rejected
  because the SDK deliberately specifies no plugin constructor, and instantiation happens at
  discovery/load time before the supervisor knows the instance; a per-instance capability is
  cleaner minted per-run. (b) *a fourth bare positional arg on `collect`/`start`* — rejected as
  not forward-compatible (every future per-instance handle would change the protocol signature
  again). The context object is the standard "request/invocation context" shape.

This is a **PLUGIN_CONTRACT change** (it adds a parameter to the `PullSource.collect` /
`PushSource.start` signatures and a new SDK `PluginContext` carrier). It is recorded here as the
mechanism; the exact `PluginContext` field set is finalized with the supervisor (#22) so the two
land together. Until #22 lands, core's single-shot `pipeline.run_pull_cycle` constructs the
context. **The `ScopedKV` protocol and the core `_CoreScopedKV` adapter can land in PR #38
now**; the context wiring lands with #22. No plugin is ever handed an `EventStore` in the interim.

### 4. `type_key` tightened to `^[a-z][a-z0-9_]*$` — underscore prefix is core-reserved (BLOCKING-2)

`TYPE_KEY_PATTERN` changes from `^[a-z0-9_]+$` to **`^[a-z][a-z0-9_]*$`** (must start with a
lowercase letter). Consequence: an underscore-prefixed token (e.g. `_global`) can **never** be a
plugin's `type_key`. The rule is: **a leading underscore marks a CORE-RESERVED scope.** This closes
the sentinel-collision (BLOCKING-2) — core uses `source_type = '_global'` as the backing scope for
the rule-descriptions facade, and the tightened regex guarantees no plugin can ever declare
`type_key = "_global"` and collide with (or read/clobber) that core scope. Core-reserved sentinels
are the only `source_type` values permitted to begin with `_`; the validator that rejects plugin
keys does not constrain core's internal sentinels.

Ripple: the scaffold tool (#34 / PR #37) validates the old `^[a-z0-9_]+$` in
`firewatch_cli/scaffold.py` (`_TYPE_KEY_RE`), its CLI help text, and its generated templates/
docstrings — all must be updated to the new leading-alpha pattern so the scaffold cannot emit a
plugin the SDK will reject at load.

### Implementation spec for the PR #38 backend-dev

Bundle the following into the #38 fix (all in core/SDK; no plugin edits):

1. **`ScopedKV` Protocol** — add to `firewatch_sdk/ports.py` exactly as in §1 (runtime-checkable,
   `put`/`get`/`get_all`, no `source_type` arg). Export it from the SDK package.
2. **`_CoreScopedKV` adapter** — add to firewatch-core (NOT the SDK), per §3, implementing
   `ScopedKV` by delegating to the three raw `source_kv_*` methods with the bound `type_key`.
   Add a core factory (e.g. `EventStore`-agnostic `scoped_kv(store, source_type) -> ScopedKV`).
3. **Core-privileged docstrings** — on `EventStore.source_kv_put/get/get_all` (SDK protocol AND
   the SQLite/in-memory impls): mark "core-privileged; NOT exposed to plugins — plugins use
   `ScopedKV`. `source_type` is core-injected from `metadata().type_key`, never plugin input."
4. **`type_key` regex** — change `TYPE_KEY_PATTERN` in `firewatch_sdk/metadata.py` to
   `r"^[a-z][a-z0-9_]*$"`; update the SDK tests (`test_ports.py`) to assert `_global`, `_x`, and
   a leading-digit/underscore token are now rejected, and that core-reserved `_global` is NOT a
   valid plugin key.
5. **Scaffold alignment (#34 / PR #37)** — update `_TYPE_KEY_RE`, the CLI help string, and the
   generated template docstrings/comments to `^[a-z][a-z0-9_]*$`; update the scaffold tests. (If
   #37 is still open, fold this into that PR or note the dependency.)
6. **BLOCKING-3 — atomic cap check + insert.** Wrap the per-scope cap `COUNT(*)` check and the
   subsequent `INSERT`/`INSERT OR REPLACE` in a single `BEGIN IMMEDIATE` transaction so two
   concurrent `source_kv_put` calls cannot both read `count < cap` and both insert, breaching the
   cap (TOCTOU). `BEGIN IMMEDIATE` acquires the write lock up front; an upsert of an *existing*
   key stays exempt from the cap (row count does not grow) but must still run inside the same
   transaction for consistency.
7. **NB-4 — migrate legacy `rule_descriptions` rows on `init()`.** Deployed DBs created before
   this change hold a populated `rule_descriptions` table. In `init()`, after creating `source_kv`
   and if a `rule_descriptions` table exists, copy its rows into `source_kv` under
   `(source_type='_global', namespace='rule_descriptions', key=rule_id, value=description)` with
   INSERT-OR-IGNORE (first-write-wins, idempotent on re-run), so no deployed data is lost when the
   facade switches its backing store. Keep the migration idempotent and guarded by a table-exists
   check.

Gates unchanged: `ruff`, `pyright`, `pytest` (incl. `tests/golden` parity), security-reviewer clean.

[owasp-a01]: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
[nist-ac6]: https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element=AC-6
[confused-deputy]: https://en.wikipedia.org/wiki/Confused_deputy_problem
