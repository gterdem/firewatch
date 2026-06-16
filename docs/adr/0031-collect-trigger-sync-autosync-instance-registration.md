# ADR-0031: Collect Trigger — Manual Sync + Persisted Auto-Sync as the Instance-Registration Seam

**Date:** June 2026
**Status:** Accepted (2026-06-10)

**Implements / closes the seam for:** the "configure-but-nothing-collects" gap — configuring a
source in Settings writes only its config section (`PUT /config/sources/{type}` →
`ConfigStore.set_source` → `firewatch_config.json[<type>]`) and never creates a *runnable*
instance. The supervisor only runs what is declared under `_instances`
(`instance_loader.py`; read by `firewatch-cli .../commands/run.py`). Nothing in the UI or API
writes `_instances`, so after configuring in the UI and running `firewatch run`, **zero sources
collect** until `firewatch_config.json` is hand-edited.

**Relates to:** ADR-0006 (config precedence env > file > default; `_runtime`/`_instances` are
core-owned underscore keys), ADR-0016 (multi-source-per-type; watermark on `(source_type,
source_id)`), ADR-0023 (collector supervisor lifecycle — `add_pull`/`add_push`,
`run_pull_cycle_for`, `reload_config` last-known-good seam, push always-on listeners),
ADR-0026 (auth posture — this is a **class-A config-mutating + class-B action-triggering** write
surface), ADR-0029 (read/control API contract — `POST /sync/{type}` already lives here),
PLUGIN_CONTRACT.md (pull vs push flavors).

**Standards consulted:** Splunk modular-input *data-input enable/disable + interval* model and
checkpoint semantics; Elastic Beats/Filebeat input enable + scan-interval; OpenTelemetry Collector
receiver scrape-interval; OPAMP remote-config supervisor (live config change without restart);
12-Factor III (config in the environment/store, not code); OWASP API Security Top 10 2023 (API5
function-level authz, API7 SSRF on action-triggering writes). These ground the choice of a
*persisted, store-driven, per-source interval-and-enablement* model over an in-process toggle.

---

## Context

Maintainer rejected an explicit enable/disable button for sources. Instead FireWatch adopts v1's
**sync / auto-sync** model (legacy is the UX oracle only — read, never import):

- **Manual "Sync now"** = one on-demand pull cycle. Already exists in v2 as
  `POST /sync/{type_key}?source_id=...` → `supervisor.run_pull_cycle_for(type, id)`. (Legacy
  oracle: `POST /sync`, `POST /sync/suricata`.)
- **Auto-sync** = a persisted, per-source toggle + interval. When ON, the source's supervised pull
  instance is registered and scheduled on that interval; when OFF the source stays configured but
  is collectable only via manual Sync. (Legacy oracle: `PUT /config/auto-sync` + `_auto_sync_loop`,
  with the Suricata twin — both in-memory `app.state` tasks, which v2 replaces with persisted
  `_instances` + the supervisor.)

**Auto-sync subsumes enable/disable.** "Disable a source" = auto-sync OFF (keep config, sync
manually). The motivating reasons for a disable button — Azure query cost, maintenance windows,
muting a noisy source — are all served by auto-sync OFF.

**Pull vs push is a hard split.** Sync / auto-sync is a *pull* concept (Azure WAF, Suricata-over-
SSH). *Push* sources (Syslog, a Suricata log-shipper per ADR-0021) are always-on listeners; their
card shows **listener status** ("listening on :514"), never Sync controls. The source's declared
`flavor` (PLUGIN_CONTRACT.md `SourceMetadata.flavor`) drives which controls and status appear — no
per-source frontend branching.

**Today's gap, precisely.** `Supervisor.add_pull`/`add_push` append to `self._instances`, but
`_launch` only fires inside `startup()`. There is **no public runtime registration path**
(register + launch a new instance into an already-running supervisor) and **no runtime interval-
change path** (`reload_config` swaps `cfg` but does not touch `_pull_interval`). The auto-sync ON
write therefore needs *both*: a durable record (so it survives restart) **and** a live supervisor
mutation (so it takes effect without `firewatch run` restart).

This ADR settles the persistence shape, the derivation of the instance, the runtime mutation
surface, and the status/health surface, before any code is written.

---

## Decision

### A. Auto-sync state is persisted as the `_instances` entry itself — there is no second toggle field

The presence of an `_instances[]` entry for `(source_type, source_id)` **is** "auto-sync ON". There
is no parallel `auto_sync: true/false` field to drift out of sync with it. The entry already carries
everything needed (`source_type`, `source_id`, `flavor`, `interval`, `extra_cfg`;
`instance_loader.InstanceConfig`).

- **Auto-sync ON** → core writes/updates the `_instances` entry for the source **and** registers +
  launches the instance in the running supervisor.
- **Auto-sync OFF** → core removes the `_instances` entry **and** stops + deregisters the instance
  from the running supervisor. The source's config section (`firewatch_config.json[<type>]`) is left
  untouched — the source stays configured and manually-syncable.

This keeps a **single source of truth** (the file the supervisor already reads at boot, ADR-0023 §F
last-known-good seam) and makes the boot path and the runtime path converge: `firewatch run`'s
`_register_instances` already turns `_instances` into `add_pull`/`add_push`, so a persisted entry is
honored on the next restart with no extra code.

*Rejected alternative:* a separate `_auto_sync` map keyed by type. Rejected — it duplicates the
instance identity already in `_instances` and creates a two-writes-must-agree invariant
(the legacy in-memory `app.state.auto_sync_task` + `source_sync_status` split is exactly the drift
we are leaving behind).

### B. Single-instance-per-type now; `source_id` defaults to `type_key`

For the current scope a source type runs **at most one** auto-sync instance, whose `source_id`
defaults to its `type_key` (e.g. `azure_waf` → instance `azure_waf`). This matches the UI's
one-card-per-installed-type model (ADR-0010) and the discovery endpoint's one-entry-per-type shape.

The `_instances` schema is **already** multi-instance-capable (ADR-0016; it is a list keyed on
`(source_type, source_id)`), so this is a *UI/endpoint* simplification, not a data-model
constraint. **Multi-instance management (N named instances of one type via the UI) is explicitly
out of scope** and deferred; the persistence shape does not need to change to add it later.

### C. Manual Sync is unchanged and works without auto-sync

`POST /sync/{type_key}?source_id=...` stays as-is (one `run_pull_cycle_for`). It requires the
instance to be *known to the supervisor* (`get_instance` 404-guard). To make manual Sync work for a
**configured-but-auto-sync-OFF** source, the supervisor must know the instance exists in a
**non-scheduled / parked-idle** state. Therefore:

- **Configured (config section present) ⇒ a supervisor record exists**, in a new **`idle`**
  disposition (registered, not scheduled, not crash-looping). Manual Sync runs one cycle against it;
  auto-sync ON transitions it to `running` (scheduled).
- This is the seam that makes manual Sync independent of auto-sync, exactly as the legacy oracle
  behaves (`POST /sync/suricata` works whether or not the auto-sync loop is running).

> **Implementation note (status enum):** `InstanceStatus.state` is today
> `running|backoff|parked|stopped` (ADR-0023). This ADR adds an **`idle`** state =
> "registered/configured, not scheduled" (auto-sync OFF). `idle` is distinct from `stopped`
> (lifecycle-terminal) and from `parked` (storm-disabled). The supervisor's `_maybe_signal_stopped`
> predicate (ADR-0023 §D.1) treats `idle` like `parked`/`stopped` — an all-`idle` supervisor with an
> API attached is the **zero-forward-progress-but-serving** case, which is the §D.1 zero-instance
> exception's sibling: an attached API keeps the process alive. This `idle`-state amendment to
> ADR-0023 is **approved**; ADR-0023 carries an amendment note cross-referencing this ADR.

### D. Runtime mutation surface on the supervisor (no restart) — three new public methods

The supervisor gains a minimal public runtime-control surface (consumed only by the API control
routes; hosts still own teardown per ADR-0023 §F):

| Method | Effect |
|---|---|
| `register_idle(plugin, cfg, *, source_id, flavor, interval, transport) -> InstanceRecord` | Add a record in `idle` (configured, not scheduled). Idempotent per `(type,id)`. |
| `enable_pull(type, id, *, interval) -> None` | Transition an `idle` pull record to `running`: set interval, `_launch`. Idempotent. |
| `disable(type, id) -> None` | Stop/cancel the instance's task (graceful, ADR-0023 §E cancellation) and return it to `idle`. |
| `set_interval(type, id, interval) -> None` | Change a running pull instance's `_pull_interval` live; takes effect on the next scheduling tick (no task restart). |

`set_interval` is the **runtime interval-change path** ADR-0023 left as a gap (`reload_config`
covers `cfg`, not interval). It mutates `rec._pull_interval`; the runner loop reads the interval at
the top of each sleep, so the change applies on the next cycle without cancelling the in-flight pull.

Push sources do **not** get `enable_pull`/`set_interval` (no Sync/interval concept). A push source is
"on" whenever it is configured: configuring a push source registers it and `start()`s its listener;
there is no auto-sync toggle for push. Its card shows listener status from `InstanceStatus`.

*Forward-compatibility:* these compose with ADR-0023's existing `add_pull`/`add_push`/`startup`
(boot path) and `reload_config` (config hot-swap seam) — they do not replace them. `register_idle`
is the runtime analogue of the boot-time `add_*` + the `idle` initial state.

### E. The API write surface (auth class A+B; SSRF-aware)

Two control routes, both **class A (config-mutating, persists `_instances`) and class B
(action-triggering, starts/stops a live collection task)** under ADR-0026. They are the highest-
impact write surface in the product after `PUT /config/*`:

- `PUT  /sources/{type_key}/auto-sync` body `{ "enabled": bool, "interval_seconds": int }`
  → on enable: `register_idle` (if absent) + `enable_pull` + persist `_instances`;
    on disable: `disable` + remove `_instances`; on interval-only change: `set_interval` + persist.
  Returns the resulting auto-sync state (enabled, interval, derived `source_id`).
- `GET  /sources/{type_key}/auto-sync` → `{ enabled, interval_seconds, source_id, last_sync }`.

Manual `POST /sync/{type_key}` is unchanged.

**Auth forward-constraint (binding):** because these routes mutate runtime collection behavior, when
the API is exposed beyond loopback they are gated at the **class-A minimum** (ADR-0026) — i.e. the
API-key gate, same as `PUT /config/*`. They MUST NOT be served on a non-loopback bind without the
gate (fail-closed, ADR-0026 Decision 4). The interval is bounded — **floor 30 s, ceiling 24 h** — to
prevent an interval of `0` becoming a busy-loop DoS against the upstream — recorded for the
security-reviewer. The pull *target* (Azure workspace, SSH host) is set in the **source config**
(already class-A, already SSRF-reviewed at config-write); auto-sync only toggles *whether* that
already-validated target is polled, so it introduces no new outbound-URL injection vector.

### F. Status / last-sync / ingested / error surfacing

The supervisor's `InstanceStatus` DTO (ADR-0023, frozen, the only read seam) already carries
`state`, `attempt`, `total_crashes`, `total_dlq`, `dropped_count`, `last_success_at`. This ADR adds
the user-facing last-sync facts the legacy oracle surfaced (`last_sync_result`:
status/ingested/timestamp):

- `last_sync_at: float | None` — wall-clock of the last completed cycle (manual or scheduled).
- `last_sync_ingested: int` — events ingested on that cycle.
- `last_sync_status: "ok" | "no_data" | "error"` and `last_error: str | None` — the cycle outcome.

These are **read** through `Supervisor.status()` (never raw internals) and rendered on the source
card. They are the data behind the "last sync time / ingested count / error" the source card shows,
and they feed the deferred Settings-diagnostics view (see ADR/issue for §D-of-the-plan).

---

## Consequences

**Positive**
- The "configure ⇒ nothing collects" trap is closed: enabling auto-sync (or configuring a push
  source) is the *only* user action needed to start collection — no hand-edit of
  `firewatch_config.json`.
- One source of truth: `_instances` is both the persisted record and what the boot path already
  reads — runtime and restart converge.
- Modularity preserved: the registration path is driven by `flavor` and the generic supervisor API;
  zero per-source branches, zero core edits to add a source.
- Manual Sync and auto-sync are orthogonal and both work, matching the v1 mental model operators
  already know.

**Negative / accepted**
- A new **`idle`** supervisor state and three runtime-control methods enlarge the supervisor surface
  (ADR-0023 amendment needed — flagged). Accepted: it is the minimum surface that makes
  configured-but-not-scheduled a first-class, isolatable state.
- The auto-sync write path is a genuinely higher-impact surface (it starts/stops live collection);
  it must ship behind the class-A gate the moment the API leaves loopback (ADR-0026).
- Single-instance-per-type is a UI simplification, not a data limit; multi-instance UI is deferred.

---

## Alternatives considered

- **Explicit enable/disable toggle** — *rejected by Maintainer.* Auto-sync OFF already expresses
  "disabled, keep config, sync manually"; a second toggle is redundant and re-introduces the
  two-flags-must-agree drift.
- **Separate `_auto_sync` persistence map** (§A) — *rejected:* duplicates instance identity already
  in `_instances`; recreates the legacy in-memory drift this design removes.
- **In-process-only auto-sync (legacy `app.state.auto_sync_task`)** — *rejected:* not durable across
  restart and not the supervisor's responsibility; v2 already has a supervisor that owns scheduling.
- **Auto-sync ON writes config but defers instance-creation to next restart** — *rejected:* leaves
  the exact "I turned it on and nothing happens" gap; the live mutation (§D) is the point.

---

## Resolved decisions (approved 2026-06-10)

1. **ADR-0023 `idle`-state amendment — approved.** The new `idle` state + the `register_idle`/
   `enable_pull`/`disable`/`set_interval` surface and the §D.1 stop-predicate's treatment of `idle`
   (treated like `parked`/`stopped`) are accepted. ADR-0023 carries a short amendment note
   cross-referencing this ADR (§C).
2. **`source_id` default = `type_key`** for the single-instance era (§B) — confirmed as the default.
3. **Interval bounds — floor 30 s / ceiling 24 h** (§E) — confirmed.

---

## References

- Splunk — modular-input data inputs (enable/disable + interval) & checkpointing —
  https://docs.splunk.com/Documentation/Splunk/latest/AdvancedDev/ModInputsScripts — backs §A/§B
  (per-input enablement + interval as the standard collection-control unit).
- Elastic Beats — input `enabled` + `scan_frequency` —
  https://www.elastic.co/guide/en/beats/filebeat/current/configuration-filebeat-options.html —
  backs §A (enablement is a per-input persisted flag, not a global toggle).
- OpenTelemetry Collector — receiver `collection_interval` —
  https://opentelemetry.io/docs/collector/configuration/ — backs §D (`set_interval` live interval).
- OpenTelemetry OpAMP Supervisor — remote config without restart —
  https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/cmd/opampsupervisor/README.md
  — backs §D (runtime mutation surface; complements ADR-0023's last-known-good seam).
- OWASP API Security Top 10 (2023) — API5 (function-level authz), API7 (SSRF) —
  https://owasp.org/API-Security/editions/2023/en/0x11-t10/ — backs §E (class-A+B gating, bounded
  interval, no new outbound-URL vector).
- 12-Factor III — Config — https://12factor.net/config — backs §A (config in the store the process
  reads, not in code or process-only memory).
