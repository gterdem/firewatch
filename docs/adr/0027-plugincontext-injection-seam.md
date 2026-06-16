# ADR-0027: The `PluginContext` Injection Seam — Per-Instance Capability Carrier into the Collection Entrypoints

**Date:** 2026-06-04
**Status:** Accepted

**Resolved on acceptance (Maintainer, 2026-06-04):** backward-compat option **(a)** — `ctx` is a *required*
parameter via one rollout PR. And `run_pull_cycle` **requires `ctx` from its caller** (the supervisor,
or a single-shot/CLI caller mints its own); there is NO internal fallback-mint — one minter pattern,
no ambient authority.

**Relates to:** ADR-0025 (source-plugin DB contract + addendum: plugins receive a `ScopedKV`
capability view, not the raw `EventStore`), ADR-0023 (collector supervisor — the trusted holder of
each instance's `(source_type, source_id)`), ADR-0016 (multi-source-per-type; `source_type` is a
plugin constant, `source_id` is the user's instance name), ADR-0019 (config-card schema discovery —
unaffected), PLUGIN_CONTRACT.md (the `PullSource.collect` / `PushSource.start` signatures this ADR
changes). Implements the seam pinned in the ADR-0025 addendum §3.

**Implements / unblocks issues:** #22 (collector supervisor), #37 (scaffold tool), #38 (`ScopedKV` /
`_CoreScopedKV` landing). Produces a new `contract-change` rollout issue (drafted below, NOT filed).

---

## Context

The ADR-0025 addendum settled *what* a plugin may touch in persistence (a `ScopedKV` view bound to
its own `type_key`, never the raw `EventStore`) and *who* closes over the tenant boundary (core, via
`_CoreScopedKV(store, type_key)`). It pinned the **delivery seam in prose** — "the scoped KV is
delivered as one field on a `PluginContext` that core/the supervisor constructs per instance and
passes into the collection entrypoints" — but explicitly deferred the exact `PluginContext` field set
and signature change to "be finalized with the supervisor (#22) so the two land together." The
supervisor is now built (PR #40) and the scaffold is built (PR #37); both predate this seam. This ADR
finalizes the carrier, the exact signatures, the minting wiring point, the migration strategy, and
the PR-#40 reconciliation.

This is a **deliberate design decision**, not a transcription: the addendum left five things open,
and points 1–5 below settle each one with the relevant standard cited.

### How the code actually invokes the entrypoints today (load-bearing)

- **Push** is direct: `Supervisor._run_push_instance` calls `push_plugin.start(rec.cfg, emit)`
  (supervisor.py). The supervisor is the immediate caller.
- **Pull is one hop removed.** The supervisor does **not** call `plugin.collect` directly. It calls
  `self._pipeline.run_pull_cycle(rec.plugin, rec.cfg, rec.source_id)`; inside the pipeline,
  `run_pull_cycle` opens the watermark and runs `async for raw in plugin.collect(cfg, since): …`
  (pipeline.py). So for the pull flavor, `ctx` must flow **supervisor → `run_pull_cycle` →
  `plugin.collect`**. This is why the rollout (below) touches `pipeline.run_pull_cycle` as well as the
  two plugins and the supervisor.

The minting authority is still the supervisor (it alone holds `(source_type, source_id)` per
instance, ADR-0023); the pipeline is a pass-through conduit for the pull path, not a second minter.

---

## Decision

### 1. `PluginContext` field set — minimal, frozen, forward-compatible

`PluginContext` is a **frozen Pydantic v2 value object** in the SDK (`firewatch_sdk.context`),
constructed by the supervisor per running instance and passed into the collection entrypoints. It is
a value object, not a `Protocol` — same call as `SourceMetadata` (PLUGIN_CONTRACT.md: only behavioral
interfaces are Protocols; carriers are frozen models). Frozen because a plugin must not mutate its own
capability carrier, and `frozen=True` makes the carrier hashable and safe to hold across a long-lived
`start()` listener.

```python
# firewatch-sdk: firewatch_sdk.context
class PluginContext(BaseModel):
    """Per-instance capabilities handed to a source plugin's collection entrypoint.

    Minted by the supervisor (the trusted holder of (source_type, source_id) — ADR-0023)
    once per running instance and passed into collect()/start(). It is the single,
    forward-compatible channel for per-instance handles (ADR-0025 addendum §3): new
    capabilities ride this carrier instead of widening the entrypoint signatures again.
    """
    model_config = {"frozen": True, "arbitrary_types_allowed": True}

    kv: ScopedKV          # source-scoped KV view, bound to this plugin's type_key (ADR-0025)
    source_id: str        # the user's instance name (ADR-0016); for labelling/logging ONLY,
                          # NEVER branched on for detection (PLUGIN_CONTRACT.md Flag B)
```

`arbitrary_types_allowed=True` is required because `kv: ScopedKV` is a runtime-checkable `Protocol`,
not a Pydantic model; Pydantic stores it without trying to validate its structure.

**Included now:** `kv` and `source_id` — exactly the two the addendum named. `kv` is the whole point
of the seam. `source_id` rides the context because a plugin legitimately needs its own instance name
(for log lines, metrics labels, transient in-memory keys) and it is per-instance, so the context is
its natural home; it stays a labelling-only value (Flag B forbids branching on it for detection).

**Decided OUT (justified):**

- **`logger` — OUT (for now).** Tempting (per-instance, structured), but adding it now over-commits
  the contract to a logging shape we have not settled (stdlib `logging.Logger`? a structured-logging
  Protocol? OTel?). 12-Factor XI ("treat logs as event streams") says the app should write
  unbuffered to `stdout` and let the execution environment route — a plugin calling
  `logging.getLogger(__name__)` already gets that for free, with no new contract surface. Putting a
  concrete `Logger` on a frozen public carrier would freeze a premature decision. **The whole reason
  `PluginContext` is a carrier is so a `logger` field can be added later without re-touching any
  signature** — which is the forward-compatibility argument for the carrier, realized. Defer until a
  plugin demonstrably needs supervisor-correlated logging, then add it as a non-breaking field.
- **clock / now-provider — OUT.** A `now()` injector exists to make time testable. FireWatch's
  testability need here is already met without it: `PullSource.collect` receives `since` (an explicit
  watermark string the test controls) and pull cadence/timeouts are the **supervisor's** concern, not
  the plugin's — the supervisor owns intervals and backoff (ADR-0023) and is independently testable
  with a fake clock. A plugin that needs "now" for a `received_at` stamp can call
  `datetime.now(timezone.utc)`; injecting a clock to make that one call mockable is speculative
  generality (YAGNI) and would couple every plugin to a core-defined time Protocol. Add later via the
  same carrier if a real need appears.

Forward-compatibility rule recorded in the contract: **new per-instance handles are added as new
fields on `PluginContext`, never as new positional parameters on `collect`/`start`.** Because the
carrier is the last parameter and new fields are additive, this stays backward-compatible for plugins
that ignore them.

### 2. Exact entrypoint signatures — `ctx` is the last keyword-capable parameter

```python
# firewatch-sdk: firewatch_sdk.ports
class PullSource(Protocol):
    def collect(
        self, cfg: BaseModel, since: str | None, ctx: PluginContext
    ) -> AsyncIterator[RawEvent]: ...

class PushSource(Protocol):
    async def start(
        self,
        cfg: BaseModel,
        emit: Callable[[list[RawEvent]], Awaitable[None]],
        ctx: PluginContext,
    ) -> None: ...
    async def stop(self) -> None: ...   # unchanged
```

`ctx` is added as the **final required positional-or-keyword parameter**. It is passed
**positionally** by the supervisor/pipeline (callers are core, so the order is owned by core), but
plugins and tests may name it `ctx=` for clarity. It is **not** keyword-only: keeping it positional
mirrors `cfg`/`since`/`emit` and keeps the protocol shape uniform.

`stop()` is **unchanged** — it takes no per-instance capability; it only signals the already-running
`start()` to exit.

**`RawEvent` / `emit` flows are unaffected.** `PluginContext` is an *input* capability carrier; it
does not touch the *output* path. `collect` still yields `RawEvent`s; `start` still calls
`emit(list[RawEvent])`. `ctx` gives the plugin a way to read/write its own scoped KV *while*
producing events; it never wraps, gates, or reshapes the event stream. Normalization
(`normalize(raw, source_id)`) is likewise untouched — it is a pure mapping with no capability need,
so it does **not** receive `ctx` (deliberately: keep the pure function pure).

### 3. Who mints it, and where (the wiring point)

The **supervisor** mints `PluginContext`, because it is the single trusted component that knows
`(source_type, source_id)` for each running instance (ADR-0023) and already owns per-instance
lifecycle. Minting is two lines at instance start, using core's `_CoreScopedKV` factory (ADR-0025
addendum §3 / PR #38):

```python
# firewatch-core: Supervisor, at instance startup (per InstanceRecord rec)
from firewatch_core.scoped_kv import scoped_kv        # the ADR-0025 §3 factory (NOT in the SDK)
from firewatch_sdk.context import PluginContext

source_type = rec.plugin.metadata().type_key          # NOT from any plugin call argument
kv = scoped_kv(self._pipeline.store, source_type)      # closes over store + type_key
ctx = PluginContext(kv=kv, source_id=rec.source_id)
```

`source_type` for the bound KV is taken from `rec.plugin.metadata().type_key` (a plugin *constant*),
never from a plugin-supplied call argument — preserving the capability-isolation guarantee of the
ADR-0025 addendum (a plugin cannot name another tenant's scope). The `EventStore` reached via
`self._pipeline.store` is **never** handed to the plugin; only the derived `ScopedKV` view is.

**Two wiring sites, because of the pull/push asymmetry (point Context above):**

- **Push** — the supervisor passes `ctx` directly: `await push_plugin.start(rec.cfg, emit, ctx)` in
  `_run_push_instance`.
- **Pull** — the supervisor mints `ctx` and threads it through the pipeline:
  `await self._pipeline.run_pull_cycle(rec.plugin, rec.cfg, rec.source_id, ctx)`, and
  `run_pull_cycle` forwards it: `async for raw in plugin.collect(cfg, since, ctx): …`. The pipeline
  is a pass-through conduit on this path; it does **not** mint (it must not — it does not own the
  trust boundary). Minting `ctx` once per pull cycle is correct and cheap (`_CoreScopedKV` is a thin
  wrapper closing over the store), and keeps the ctx fresh if config/store ever rotates.

  (Note: per the ADR-0025 addendum, until #22 landed, `core.pipeline.run_pull_cycle` was to construct
  the context itself for single-shot use. With #22 now landed, the supervisor is the canonical minter
  and `run_pull_cycle` gains a `ctx` parameter; a single-shot/CLI caller that invokes
  `run_pull_cycle` outside the supervisor mints its own `ctx` the same two-line way. The factory lives
  in core, so any in-core caller can mint; no plugin ever can.)

### 4. Migration strategy — **hard signature change in one rollout PR** (recommended)

Two candidates were weighed:

- **(a) Hard signature change.** `ctx: PluginContext` is a **required** parameter; one rollout PR
  updates the SDK protocols, both merged plugins (suricata `collect`, syslog `start`), the scaffold
  templates (#37), `pipeline.run_pull_cycle`, and the supervisor (#40) wiring together, plus their
  tests.
- **(b) Optional transition param.** `ctx: PluginContext | None = None`, adopted incrementally;
  callers pass `ctx` when ready, plugins tolerate `None`.

**Recommendation: (a), the hard signature change in a single rollout PR.** Rationale:

- **The SDK's standing rule is "no optional-None footguns."** PLUGIN_CONTRACT.md already forces
  `SecretStr` defaults to be the *only* place `None` defaults are mandated, precisely because a
  silent `None` in the schema is a leak/footgun; the project's design value is explicit contracts.
  An `Optional[ctx]=None` permanently bakes a "is `ctx` here or not?" branch into **every** plugin's
  `collect`/`start` and into the scaffold template forever — every third-party author would copy a
  `if ctx is None:` guard. That is the exact ambient-vs-explicit smell the ADR-0025 addendum just
  removed from the KV surface. **Re-introducing an optional capability carrier one ADR later would
  contradict the addendum.**
- **The blast radius is small and fully in-tree.** The entire surface is: 2 SDK protocols, 2 plugins,
  1 pipeline method, 1 supervisor (2 call sites), the scaffold templates, and their tests
  (~14 `collect(...)` + ~5 `start(...)` call sites in tests). All of it is first-party and in this
  repo. There are **zero external plugins** — nothing third-party is broken by a hard change, because
  nothing third-party exists yet. The cost of (b)'s incrementalism buys nothing here.
- **No plugin uses `ScopedKV` yet.** Neither suricata nor syslog reads/writes scoped KV today, so the
  rollout is purely *mechanical signature threading* — add `ctx` to the two entrypoints and ignore it
  in the body. There is no behavioral migration to stage; (b)'s "adopt incrementally" advantage
  (let plugins migrate at their own pace) is moot when migration = "accept one more parameter you
  don't use yet."
- **Testability favors (a).** With a required `ctx`, every test constructs a `PluginContext` (with a
  trivial in-memory `ScopedKV` fake) and the type checker (`pyright`, a gate) *proves* every call
  site is updated — a missed site is a red build, not a latent `None`. With (b), `pyright` stays green
  even where a caller forgot to pass `ctx`, so the bug surfaces only at runtime when a plugin finally
  touches `ctx.kv`. The SDK should ship a tiny `InMemoryScopedKV` test double (dict-backed) so plugin
  authors and golden tests construct a `PluginContext` in one line — this also serves the rebuilt
  golden oracle.
- **Contract cleanliness is the architect's mandate.** The contract reads cleaner with one required,
  always-present carrier than with an optional one carrying a "may be absent" caveat into perpetuity.

**Deviation note:** the usual reason to prefer (b) is to avoid breaking downstream consumers across a
release boundary (SemVer "don't break the public API"). That reason is **absent pre-1.0 with zero
external plugins** — `firewatch-sdk` is `0.x`, where a breaking minor is permitted (SemVer §4: "Major
version zero … anything MAY change at any time"). Recorded so a future reader does not mistake this
for cavalier API breakage: it is a deliberate, justified pre-1.0 hardening.

### 5. Reconcile with PR #40 (supervisor) — **merge as-is; add `ctx` minting in the ADR-0027 rollout**

PR #40 is built and tested (26 EARS-mapped tests) and drives pull (`run_pull_cycle`) and push
(`start`) **without** minting `ctx`, because it predates this seam and `ScopedKV` / `_CoreScopedKV`
(PR #38) had not landed when it was written.

**Recommendation: merge PR #40 as-is, and add the `ctx`-minting + signature threading in the ADR-0027
rollout PR.** Rationale:

- **Nothing needs `ctx` until a plugin uses scoped KV.** No source reads/writes KV today, so a
  supervisor that doesn't yet mint `ctx` is not *wrong* — it is *incomplete against a contract that
  does not yet exist on main*. Holding #40 hostage to a not-yet-merged seam (#38 + this ADR) inverts
  the dependency: #40 is the *consumer* of the minting factory, and the factory (`scoped_kv`) lands in
  #38, not #40.
- **Sequencing is clean and already implied by the ADR-0025 addendum** ("the context wiring lands
  with #22 … the `ScopedKV` protocol and the core `_CoreScopedKV` adapter can land in PR #38 now"):
  1. **#38** lands `ScopedKV` (SDK) + `_CoreScopedKV`/`scoped_kv` (core) + the tightened `type_key`
     regex. No entrypoint signatures change.
  2. **#40** merges as-is — supervisor lifecycle, isolation, backoff, DLQ, backpressure, shutdown —
     none of which depends on `ctx`. Its tests stay green.
  3. **#37** merges (or rebases) the scaffold; the ADR-0027 rollout updates its templates.
  4. **ADR-0027 rollout PR** (drafted below) does the signature change end-to-end, including the two
     supervisor call sites and `run_pull_cycle`. Because #40 is already merged, this PR edits a known
     supervisor on main rather than racing an open PR.
- **Reworking #40 before merge is the wrong order and costlier.** It would force #40 to either (i)
  depend on #38 + an un-accepted ADR (this one, still *Proposed*), or (ii) speculatively invent the
  `PluginContext` shape inside the supervisor PR — pre-empting this ADR's decision and risking
  divergence from the field set settled in §1. Merging #40 now and threading `ctx` in a focused,
  reviewable rollout keeps each PR single-purpose (one issue → one PR) and keeps the seam decision in
  the ADR where it belongs.

**One guard to add to #40 at merge (non-blocking, mechanical):** none required for correctness, but
the rollout PR must update #40's `_run_push_instance` (`start(rec.cfg, emit)` →
`start(rec.cfg, emit, ctx)`) and its `run_pull_cycle` call (add `ctx`). These are noted in the
rollout file-by-file below so nothing is missed.

---

## Alternatives considered

- **Inject `ctx` at plugin instantiation (constructor/factory).** Rejected (already rejected in the
  ADR-0025 addendum, re-affirmed): the SDK specifies no plugin constructor, and instantiation happens
  at discovery/load time, before the supervisor knows the instance's `(source_type, source_id)`. A
  per-instance capability is cleaner minted per-run.
- **A fourth bare positional arg on `collect`/`start` instead of a carrier.** Rejected: not
  forward-compatible — every future per-instance handle (logger, clock, scoped watermark accessor)
  would change the protocol signature again and re-touch every plugin. The carrier amortizes that to
  zero future signature churn (the standard "invocation context" object pattern — gRPC `Context`,
  AWS Lambda `context`, ASGI `scope`, Temporal `Context`).
- **Optional `ctx: PluginContext | None = None` (migration option (b)).** Rejected as the *contract*
  shape — see §4. (It is a legitimate *technique* when external consumers exist; they don't here, and
  it permanently dirties the contract.)
- **Pass the raw `EventStore` and let plugins derive their own scope.** Rejected by the ADR-0025
  addendum (capability isolation / confused-deputy). Restated here only to note `PluginContext.kv`
  is the *sole* persistence handle a plugin ever receives.
- **Put `logger`/clock on the carrier now.** Rejected as premature (§1) — YAGNI + over-committing the
  contract; the carrier exists precisely so these can be added later without breakage.

---

## Reasoning

- **Capability passing + invocation-context object are the settled standards here.** The carrier
  realizes capability-based security (the plugin holds only the authority it was granted, ADR-0025
  addendum / OWASP A01 / NIST AC-6 / the confused-deputy paper) *and* the ubiquitous "request/
  invocation context" pattern (gRPC `Context`, AWS Lambda `context` object, ASGI `scope`, Temporal
  activity `Context`): one immutable, framework-minted object that carries per-invocation handles so
  the call signature stays stable as capabilities grow.
- **Minting in the supervisor keeps capability creation in exactly one trusted place** and preserves
  the dependency rule: core depends on the SDK `ScopedKV` / `PluginContext`; the plugin imports only
  the SDK; the SDK ships only the Protocol + the frozen carrier, never an implementation.
- **The hard, required-parameter change is the cleaner contract** and is safe pre-1.0 with zero
  external plugins; the type checker turns "did every caller update?" from a runtime risk into a
  compile-time guarantee.

---

## Consequences

- **`firewatch-sdk`** gains `firewatch_sdk.context.PluginContext` (frozen Pydantic model: `kv`,
  `source_id`) and a tiny `InMemoryScopedKV` test double (dict-backed, in a test-support module) so
  plugins/golden tests construct a `PluginContext` in one line. `PullSource.collect` and
  `PushSource.start` gain a required final `ctx: PluginContext` parameter.
- **PLUGIN_CONTRACT.md** updates the two signatures and the "Auxiliary state" bullet to state the
  plugin receives `ctx.kv` (this ADR finalizes the previously-deferred wording).
- **suricata + syslog** plugins accept (and currently ignore) `ctx` on `collect` / `start`.
- **`firewatch-core`** `pipeline.run_pull_cycle` gains a `ctx` parameter and forwards it to
  `collect`; the **supervisor** mints `PluginContext` per instance via `scoped_kv(store, type_key)`
  and passes it to both flavors.
- **scaffold (#37)** templates emit the new signatures (and the already-tightened `type_key` regex).
- **No behavioral change** to event flow, scoring, or watermarks; golden parity (ADR-0024) is
  unaffected — every change is signature threading until a plugin opts into `ctx.kv`.
- **Sequencing:** #38 → merge #40 as-is → #37 → ADR-0027 rollout PR (the only PR that changes
  signatures).

---

## References / standards consulted

- Capability-based security / confused deputy, OWASP A01, NIST SP 800-53 AC-6/AC-3 — see the ADR-0025
  addendum reference block (this ADR inherits that grounding for the KV capability).
- 12-Factor XI — Logs as event streams (basis for keeping `logger` OFF the carrier for now):
  [12factor-logs][12f-logs].
- SemVer §4 — Major version zero (basis for the safe pre-1.0 breaking change): [semver][semver].
- Invocation-context object precedent: gRPC `Context`, AWS Lambda handler `context`, ASGI `scope`,
  Temporal activity `Context` (industry-ubiquitous "per-call context carrier" shape).
- Internal: ADR-0025 (+ addendum §3), ADR-0023, ADR-0016, ADR-0019; PLUGIN_CONTRACT.md;
  `packages/firewatch-core` supervisor (PR #40) and `pipeline.run_pull_cycle`.

[12f-logs]: https://12factor.net/logs
[semver]: https://semver.org/#spec-item-4

---

## Draft implementation issue (NOT filed — for Maintainer to file after acceptance)

> **Title:** contract-change(M2): thread `PluginContext` into `collect`/`start` — SDK carrier +
> supervisor minting (ADR-0027)
>
> **Intent:** Realize the ADR-0027 seam: add the `PluginContext` carrier to the SDK, add the required
> `ctx` parameter to `PullSource.collect` / `PushSource.start`, and mint `ctx` per instance in the
> supervisor (via the ADR-0025 §3 `scoped_kv` factory). One rollout PR (hard signature change, ADR-0027
> §4). Depends on #38 (`ScopedKV` / `scoped_kv` landed) and on #40 (supervisor) being merged first.
>
> **EARS acceptance criteria (sketch):**
> - **Ubiquitous:** The SDK SHALL expose `firewatch_sdk.context.PluginContext` as a frozen Pydantic v2
>   model with fields `kv: ScopedKV` and `source_id: str`, and a dict-backed `InMemoryScopedKV` test
>   double.
> - **Ubiquitous:** `PullSource.collect` SHALL be `collect(self, cfg, since, ctx: PluginContext)` and
>   `PushSource.start` SHALL be `start(self, cfg, emit, ctx: PluginContext)`; `stop()` SHALL be
>   unchanged.
> - **Event-driven:** WHEN the supervisor starts a pull instance, it SHALL mint
>   `ctx = PluginContext(kv=scoped_kv(store, plugin.metadata().type_key), source_id=rec.source_id)`
>   and pass it through `run_pull_cycle` to `collect`.
> - **Event-driven:** WHEN the supervisor starts a push instance, it SHALL mint `ctx` the same way and
>   call `start(cfg, emit, ctx)`.
> - **Unwanted:** The supervisor SHALL derive the KV's `source_type` ONLY from
>   `plugin.metadata().type_key`, NEVER from a plugin call argument (capability isolation, ADR-0025).
> - **Ubiquitous:** A plugin SHALL never receive a raw `EventStore`; only `ctx.kv` (`ScopedKV`).
> - **State-driven:** Golden parity (ADR-0024) and all existing supervisor/plugin tests SHALL remain
>   green (pure signature threading; no behavioral change).
>
> **File-by-file rollout:**
> 1. **SDK — `packages/firewatch-sdk/src/firewatch_sdk/context.py`** (new): `PluginContext` frozen
>    model (`kv`, `source_id`); export from `firewatch_sdk/__init__.py`.
> 2. **SDK — test support:** `InMemoryScopedKV` dict-backed double (e.g.
>    `firewatch_sdk/testing.py` or a `tests` support module) implementing `ScopedKV`.
> 3. **SDK — `firewatch_sdk/ports.py`:** add `ctx: PluginContext` to `PullSource.collect` and
>    `PushSource.start`; update docstrings.
> 4. **suricata — `packages/sources/suricata/src/firewatch_suricata/plugin.py`:** accept `ctx` on
>    `collect` (ignore body for now); update `health_check`'s internal `collect` probe call to pass a
>    throwaway `ctx` or refactor to not need one. Update `tests/test_plugin.py` (~14 `collect(...)`
>    call sites) to pass a `PluginContext`.
> 5. **syslog — `packages/sources/syslog/src/firewatch_syslog/plugin.py`:** accept `ctx` on `start`
>    (ignore body for now). Update `tests/test_plugin.py` (~5 `start(...)` call sites).
> 6. **core — `packages/firewatch-core/src/firewatch_core/pipeline.py`:** add `ctx: PluginContext` to
>    `run_pull_cycle` and forward to `plugin.collect(cfg, since, ctx)`; update single-shot/CLI callers
>    to mint their own `ctx`.
> 7. **core — supervisor (`firewatch_core/supervisor.py`, post-#40-merge):** mint `ctx` per instance
>    via `scoped_kv(self._pipeline.store, rec.plugin.metadata().type_key)`; pass to
>    `run_pull_cycle(..., ctx)` (pull) and `start(rec.cfg, emit, ctx)` (push). Update the 26
>    supervisor tests' fakes/pipeline stub to accept `ctx`.
> 8. **scaffold (#37) — `firewatch_cli/scaffold.py` templates:** emit `collect(self, cfg, since, ctx)`
>    / `start(self, cfg, emit, ctx)` and a comment that `ctx.kv` is the only persistence handle;
>    update the generated `tests/` to construct a `PluginContext`.
> 9. **docs:** mark ADR-0027 Accepted; reflect the final signatures in PLUGIN_CONTRACT.md (already
>    drafted alongside this ADR).
>
> **Out of scope:** building `ScopedKV` / `_CoreScopedKV` / `scoped_kv` (that is #38); any plugin
> *using* `ctx.kv` for real (a later per-source task); adding `logger`/clock to `PluginContext`
> (future non-breaking field); the constrained-(c) storage escape hatch (ADR-0025, documented-not-built).
