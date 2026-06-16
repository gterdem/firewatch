# ADR-0023: Collector Supervisor — Lifecycle & Concurrency Model

**Date:** June 2026
**Status:** Accepted (2026-06-03)

> **Amendment (2026-06-10, via ADR-0031):** the supervisor gains an **`idle`** state —
> "registered/configured, not scheduled" — for a source that is configured but has auto-sync OFF.
> `idle` is distinct from `stopped` (lifecycle-terminal) and `parked` (storm-disabled): a manual
> `POST /sync/{type}` runs one cycle against an `idle` instance without auto-sync running, and
> turning auto-sync ON transitions it to `running`. The §D.1 stop predicate treats `idle` like
> `parked`/`stopped` (an `idle` instance is not making forward progress), so the zero-instance
> exception's reasoning extends to an all-`idle` supervisor with an attached API: the API keeps the
> process alive and serving. ADR-0031 (§C/§D) adds the matching runtime-control methods
> (`register_idle`/`enable_pull`/`disable`/`set_interval`). See ADR-0031 for the full rationale; this
> note records the state-machine change without otherwise altering this ADR.

**Implements / referenced by:** issue #22 (M2.7 — Long-running collector supervisor);
issue #75 (run-loop — co-hosting the API server; see §F).
**Relates to:** PLUGIN_CONTRACT.md:88-89 (the supervisor the contract already promises),
ADR-0006 (config precedence), ADR-0007 (storage; full WAL deferred to M6/Postgres),
ADR-0016 (multi-source-per-type; watermark keyed on `(source_type, source_id)`),
ADR-0021 (no mandatory bus).

---

## Context

M1 shipped a **single-shot** pull cycle (`pipeline.run_pull_cycle`, `pipeline.py:78-108`):
something external must call it once per instance per tick. There is no long-running owner that
schedules pulls on an interval, runs PushSource listeners (`start`/`stop`, needed by #21 Syslog),
isolates a crashing instance from its siblings, retries with backoff, or shuts down gracefully.

Yet **PLUGIN_CONTRACT.md:88-89 already promises one**: "one failing instance must never crash the
supervisor or other sources." That promise has no implementation. This ADR settles the
concurrency/lifecycle model for that supervisor before any code is written (the issue is
architect-blocking).

Constraints that shape the decision:
- **Modularity / dependency rule.** Core imports SDK protocols only — never a concrete plugin,
  never `legacy/`. The supervisor must drive heterogeneous instances behind the `SourcePlugin`
  contract without knowing their internals.
- **Multi-source-per-type (ADR-0016).** Many instances of the same source type run concurrently,
  each keyed on `(source_type, source_id)`. The supervisor schedules per instance and never
  re-keys a watermark.
- **Pull + push under one supervisor.** PullSources need interval scheduling around
  `run_pull_cycle`; PushSources need their listener `start(cfg, emit)` held open for the process
  lifetime and `stop()`'d on shutdown. Both flavors must live under the same lifecycle owner so
  crash isolation, backoff, and graceful shutdown are uniform.
- **Verify, don't assume.** The model is grounded in published resilience practice (Erlang/OTP
  supervision, Python structured-concurrency semantics, AWS backoff+jitter, Google SRE on
  cascading failures, 12-Factor disposability) rather than convenience. Where FireWatch deviates
  from a "textbook" structured-concurrency default, the deviation is recorded below.

---

## Decision

### A. Per-instance supervised tasks (one_for_one), NOT a shared TaskGroup

Each source instance runs in its own `asyncio.Task` created with `loop.create_task(...)`. The
supervisor holds a **strong reference** to every task in a tracked set and attaches
`task.add_done_callback(...)` to observe completion/failure and (re)schedule. Keeping the strong
reference is required: per the asyncio docs, the event loop keeps only a *weak* reference to tasks,
so an un-referenced task can be garbage-collected mid-flight.

We deliberately do **not** wrap the instances in a single `asyncio.TaskGroup`. TaskGroup
(PEP 654 / Python 3.11+) implements **all-or-nothing** structured concurrency: the first unhandled
exception in any child cancels every sibling and aborts the group. That is the opposite of what a
collector supervisor needs — one bad source must not take down the other twenty. The supervised-set
model maps directly to **Erlang/OTP `one_for_one`** supervision: when a child dies, only that child
is restarted; siblings are untouched. TaskGroup's semantics correspond to OTP `one_for_all`, which
we explicitly reject for inter-source isolation.

(We still use structured concurrency *within* a single instance's own cycle where all-or-nothing is
the correct semantic — e.g. a fan-out inside one `run_pull_cycle`. The one_for_one boundary is at
the **instance** level.)

### B. Single-process asyncio now; documented graduation triggers to subprocess

The supervisor runs all instances as tasks in **one process, one event loop**. This is the right
default: our sources are I/O-bound (SSH pulls, socket listeners, HTTP), which asyncio handles well,
and a single process is the simplest thing that satisfies the contract.

A source instance **graduates to its own subprocess** (process-per-source, supervised the same
one_for_one way at the OS level) when **any** of these concrete triggers holds:
1. **Native / unsafe code** — the source links a C/native library that can segfault or corrupt the
   interpreter; an in-process crash there kills *all* sources, defeating isolation.
2. **Can block the loop** — the source does blocking/CPU-heavy work it cannot make awaitable
   (no async API, no clean `run_in_executor` boundary); it would stall the shared loop and starve
   siblings.
3. **Needs its own memory/CPU budget** — the source must be independently resource-limited
   (cgroup/ulimit) or OOM-isolated.

Until a trigger fires, single-process is preferred (12-Factor: simple, disposable processes).
Process-per-source is the **graduation path**, designed-for but not built now.

### C. Full-jitter capped exponential backoff at the restart boundary

When an instance's cycle fails, the supervisor waits before restarting it using the **AWS "Full
Jitter"** formula:

```
sleep = random_between(0, min(backoff_cap, backoff_base * 2 ** attempt))
```

Full Jitter (not "Equal Jitter", not plain exponential) is chosen because it maximally
de-synchronizes a fleet of instances that fail together (e.g. a shared upstream outage), preventing
a thundering-herd retry storm — the failure mode Google SRE's "Addressing Cascading Failures"
warns about.

Backoff lives at the **restart boundary**, and the attempt counter **resets to zero on a
successful cycle**. A source that pulls fine for hours and then has one transient hiccup starts its
next backoff from `attempt=0`, not from a stale high count.

### D-revised. Retry-forever-capped, with BOTH safety rails (storm cap + dead-letter), never silent

The supervisor retries a failing instance **indefinitely** (a transient upstream may recover at any
time; we do not permanently disable a source on its own). Backoff is capped at `backoff_cap` so the
retry interval plateaus rather than growing unbounded. Two rails bound the failure modes, and
**both surface an operator-visible alert — neither is ever silent**:

- **Restart-storm cap → park + alert.** If an instance crashes more than `storm_threshold` (=5)
  times within a **rolling 60s window**, the supervisor **parks** it (stops auto-restarting) and
  emits a high-severity alert. Parking prevents a hard-looping instance (e.g. a config that can
  never succeed) from burning CPU and flooding logs forever. For M2 a parked instance resumes
  **only via operator action / process restart**; the last-known-good config seam (below) is the
  designated hook for a future hot-reload resume, but full hot-reload is out of scope for M2. This
  is the OTP **max-restart-intensity** principle: a supervisor that restarts too fast for too long
  shuts that child down rather than thrash.
- **Dead-letter path → drop poison record + advance watermark, then alert.** If the **same record**
  (not the instance overall — `dlq_threshold` counts failures on one individual record, not total
  failures across records) fails processing `dlq_threshold` (K=3) times, the supervisor routes that
  record to a dead-letter
  sink, **advances the watermark past it**, and emits an alert. This unblocks the instance from a
  single "poison" record that would otherwise wedge the watermark forever, while preserving the bad
  record for inspection. This is the Logstash DLQ / Fluent Bit retry-then-shed pattern.

The two rails are orthogonal: the storm cap protects against an instance that *can't start*; the
DLQ protects against an instance that *starts but chokes on one record*.

### D.1 Terminal condition — all-parked stops the supervisor (issue #75)

The two rails above bound *individual* failure modes while the supervisor keeps
running. There is one **terminal** case they do not cover: when **every**
registered instance has parked (or otherwise stopped) and **none** remains
RUNNING or BACKOFF, the supervisor can make **zero forward progress** — every
source is crash-looped into park, and only operator action can revive it (§D).
Continuing to run in that state serves a frozen, dishonestly-"live" SOC view
indefinitely, which is strictly worse than stopping loudly: the storm alert that
caused the final park is already on the wire (§D "neither is ever silent").

The supervisor therefore treats **all-parked as a stop condition** and signals
it to its host (`firewatch run`, §F). Per-instance isolation is unchanged: a
*single* park never stops siblings (§A one_for_one). The supervisor stops only
when there is nothing left to isolate.

**Stop predicate (exact).** The supervisor is *stopped* when either:
1. `shutdown()` has been initiated (explicit call or SIGTERM/SIGINT, §E); OR
2. **≥1 instance was ever registered** AND **no registered instance is in
   RUNNING or BACKOFF** (i.e. every instance is now PARKED or STOPPED).

`BACKOFF` counts as *still making progress* — it has a scheduled relaunch and
may recover — so an instance mid-backoff keeps the supervisor alive.

**Zero-instance exception.** A supervisor with **no** registered instances (e.g.
`firewatch run` started against an empty `_instances` to serve the UI while
sources are added later via the API) has nothing parked; clause (2) requires
"≥1 instance was ever registered", so an empty supervisor **never** satisfies
the stop predicate on its own and serves indefinitely until `shutdown()`.

**Detection is level-triggered and re-evaluated on every terminal transition.**
Each time an instance leaves the progress-capable set (a storm-park, or a task
completing without restart), the supervisor re-evaluates the predicate and, when
it first becomes true, emits a single high-severity log line
(`supervisor.stopping … no forward progress possible`) and sets the public stop
signal. This is consistent with §D "neither is ever silent": the transition to
stopped is logged, not silent. The triggering source-level storm alert(s)
already fired at each park, so no second per-source page is emitted for the same
root cause.

**Public seam.** The stop condition is exposed as `await
supervisor.wait_until_stopped()` — an awaitable that resolves on **either**
clause above. It is the *only* supported way a host learns the supervisor
stopped; hosts MUST NOT reach into supervisor internals (no private event/state
access). `wait_until_stopped()` does not itself perform teardown — it reports
the condition; the host (§F) runs the ordered shutdown in response.

### E. Bounded-grace graceful shutdown with a hard deadline

On `SIGTERM`/`SIGINT` the supervisor:
1. stops accepting new work — no new pull cycles are scheduled;
2. calls `stop()` on every PushSource listener;
3. cancels in-flight pull tasks (cooperative cancellation; the contract requires `collect()` to be
   cancellable, PLUGIN_CONTRACT.md:88);
4. waits up to `shutdown_grace` for tasks to finish flushing their current batch;
5. at the **hard deadline**, force-cancels whatever remains and exits.

This is 12-Factor IX (disposability): fast, graceful shutdown on SIGTERM with a bounded ceiling so a
wedged task can never block process exit indefinitely.

### Steals (smaller settled points folded in)

- **Backoff at the restart boundary, reset on success** — see C. (OTP child-restart semantics.)
- **Config'd Block-vs-Drop per transport (backpressure).** When a downstream (pipeline/store) is
  slower than ingest, behavior is **split by transport**:
  - **UDP syslog → Drop-newest + increment a `dropped` counter** (surfaced as a metric/alert). UDP
    is already lossy; *blocking* a UDP socket loses datagrams anyway AND can stall the event loop,
    so dropping explicitly with a counter is strictly better and observable.
  - **TCP / file → Block (apply backpressure upstream).** These transports have flow control
    (TCP windows, file offsets); blocking propagates backpressure to the sender without data loss.
  This is the Cribl/OTel backpressure guidance applied per-transport. Defaults are config-overridable.
- **Last-known-good config SEAM.** The supervisor reads each instance's config through a seam that
  can hold a **last-known-good** snapshot, so a future hot-reload can swap config atomically and
  **roll back** to the last good config if the new one fails validation/startup. We **design the
  seam now**; full hot-reload (file-watch + atomic instance swap) is **out of scope** for this ADR
  and deferred to a later issue. Grounded in OpAMP's remote-config + supervisor model.

### F. Co-hosting the API server in `firewatch run` (issue #75)

`firewatch run` co-hosts the REST API **as an `asyncio.Task` on the supervisor's single event loop** —
**not** as a second-loop daemon thread. This reaffirms **§B (single process, single event loop)** and
extends it from "all sources on one loop" to "sources **and** the API on one loop."

**Why one loop (the #75 bug class).** `SQLiteEventStore` holds **one loop-bound `aiosqlite`
connection** (`sqlite_store.py:204`). A second event loop (daemon thread) sharing that connection
raises `got Future attached to a different loop` — a structural cross-loop defect, not a tuning issue.
**One loop = one connection = the entire bug class ceases to exist.** Critically, this needs **no SQLite
WAL and no `busy_timeout`**, so it **preserves ADR-0007's "WAL deferred to M6/Postgres"**: we do not
pull durability/concurrency machinery forward merely to make a second loop safe.

**Lifecycle ownership.** `firewatch run` calls **`supervisor.startup()`** (not `run()`), then runs the
API as a uvicorn server task on the same loop (`asyncio.create_task(server.serve())`). Shutdown is
ordered, and `firewatch run`'s outer `try/finally` is the single place the ordered sequence lives:
1. stop accepting new HTTP (uvicorn stops serving new connections),
2. **drain uvicorn** (`server.should_exit = True`; let in-flight requests finish, then `await` the
   server task),
3. **`supervisor.shutdown()`** within the §E bounded grace (`shutdown_grace`, force-cancel at the hard
   deadline),
4. **`store.close()`** last, after both the API and the supervisor have released the loop-bound
   connection.

**Signal ownership — uvicorn captures the signals; `firewatch run` owns the ordered shutdown.**
uvicorn's `Server.serve()` **unconditionally** enters `capture_signals()`, which installs `SIGTERM`/
`SIGINT` handlers with `signal.signal()` (it does this even when an asyncio loop handler is available,
and there is **no** `install_signal_handlers` knob to disable it in the supported version). FireWatch
therefore does **not** install an asyncio-level (`loop.add_signal_handler`) handler for these signals —
it would be silently clobbered by `capture_signals` the moment the server task runs, so it is dead code
that merely *looks* live. Instead:
- A signal sets uvicorn's `should_exit`; `serve()` returns; the **server task completes**; and the
  ordered shutdown above runs from `firewatch run`'s `finally`. uvicorn is the *trigger*; `firewatch
  run` is the *sequencer*. The "one place owns shutdown ordering" goal §F was written for is met by the
  single `finally`, not by owning the OS signal.
- On clean exit, `capture_signals` **re-raises** the captured signal (`signal.raise_signal`) against the
  handler that was installed *before* the server task started. `firewatch run` installs a **no-op
  `signal.signal` handler for `SIGTERM`/`SIGINT` before creating the server task** so this re-raise
  lands on a no-op rather than the default disposition (which would terminate the process *before* the
  ordered cleanup finishes), and restores the true previous handlers in its own `finally`. This keeps
  uvicorn's signal lifecycle intact while guaranteeing ordered shutdown completes.
- The run loop awaits **`FIRST_COMPLETED` of {server task, `supervisor.wait_until_stopped()`}**, so a
  supervisor that parks all instances on a restart storm (§D.1 stop predicate) or otherwise loses all
  forward progress *also* drives shutdown. The supervisor-side trigger is the **public awaitable seam**
  `wait_until_stopped()` (§D.1) — **not** any private attribute: the run loop has no visibility into
  supervisor internals, and the seam resolves precisely on the §D.1 predicate (all-parked, with the
  zero-instance exception) **or** on an explicit `shutdown()`. On the supervisor-stopped branch
  `firewatch run` sets `server.should_exit = True`, awaits the drained server task, then runs the same
  ordered `finally`. Either trigger — signal (via uvicorn) or supervisor-stopped (via the seam) —
  converges on one shutdown path. (The earlier, since-corrected sketch that awaited a private
  `_shutdown_event`-style attribute was both a private-attr violation **and** semantically dead — that
  attribute is set only by `shutdown()` itself, so it could never fire on the park-all case it was meant
  to catch; the public `wait_until_stopped()` seam, which the all-parked detection sets independently,
  fixes both defects.)

**Supervisor API surface for §F.** `startup()` and `shutdown()` (§E) are composed with one **added**
public awaitable, `wait_until_stopped()` (§D.1), which the run loop selects on alongside the server task.
No other supervisor surface is needed: `firewatch run` still owns the ordered teardown; the supervisor
only *reports* — via this one seam — that it has stopped (all-parked per §D.1, or `shutdown()` done).

**Recorded trade.** A shared loop means a **pathological blocking request handler could stall ingest**
(it would block the same loop the pull/push tasks run on). This is **accepted under §B**: the read
handlers are `await`ed `aiosqlite` queries (already non-blocking), and the §B "can block the loop"
graduation trigger remains the escape hatch if a future handler genuinely needs to block (it would move
to a subprocess/executor boundary, same as a blocking source).

**Rejected alternatives.**
- **(b) Two connections + SQLite WAL** — *rejected.* Makes cross-loop access the *intended* design and
  **pulls WAL forward from M6**, contradicting ADR-0007. Larger blast radius (concurrency tuning,
  `busy_timeout`) to solve a problem that one loop dissolves for free.
- **(c) FastAPI-lifespan with a second connection** — *rejected* for the same reason as (b): it
  legitimizes a two-connection / cross-loop topology and pulls WAL forward, for no benefit over the
  single-loop task.
- **(e) Two separate DB files (API reads one, supervisor writes the other)** — *rejected:* the
  dashboard would read a **stale** database (the API's file would lag the supervisor's writes),
  defeating the point of a live SOC view.
- **Bypass `capture_signals` and own the OS signal directly (asyncio `loop.add_signal_handler`)** —
  *rejected.* `serve()` always enters `capture_signals()` (no `sockets=` or config bypass), so the only
  way to own the signal is to re-implement `serve()` against uvicorn's private `startup`/`main_loop`/
  `shutdown` internals — fragile across uvicorn upgrades. Letting uvicorn capture the signal and
  sequencing teardown from `firewatch run`'s `finally` achieves the same single-owner ordering without
  forking uvicorn's lifecycle.

**Forward link (ADR-0030).** This single-loop co-hosting is correct for the **rung-0** deployment
(single process, single loop). When FireWatch graduates to **multi-process per §B** / **multi-node per
ADR-0030's transport ladder**, §F is **superseded by genuine process separation** — at which point
SQLite-WAL/Postgres (ADR-0007) **and** an external broker (ADR-0030 rung 2) become appropriate
*together*, because cross-process/cross-host is exactly the tier where the shared-loop assumption no
longer holds.

---

## Default constants (all config-overridable per ADR-0006)

| Constant | Default | Meaning |
|----------|---------|---------|
| `backoff_base` | `1s` | base of the exponential backoff |
| `backoff_cap` | `300s` (5 min) | ceiling on a single backoff sleep |
| `storm_threshold` | `5 crashes / 60s` | exceed ⇒ **park** the instance + alert |
| `dlq_threshold` (K) | `3 failures on the same record` | exceed ⇒ dead-letter the record, advance watermark, alert |
| `shutdown_grace` | `30s` | hard deadline for graceful shutdown before force-cancel |

Backpressure mode default: **UDP = Drop-newest+counter; TCP/file = Block** (per-transport, overridable).

---

## Consequences

**Positive**
- The contract's promise (PLUGIN_CONTRACT.md:88-89) is finally backed by a model: one_for_one
  isolation means a crashing instance is contained and restarted without touching siblings.
- Pull and push instances share one uniform lifecycle (backoff, storm cap, DLQ, shutdown).
- No silent failure: park-on-storm and dead-letter-on-poison both alert.
- Core stays SDK-only; the supervisor drives instances purely through the `SourcePlugin` contract.
- Single-process keeps M2 simple; the subprocess graduation path is written down, not hand-waved.

**Negative / accepted trade-offs**
- **HONEST residual gap — at-least-once with possible duplicates.** State (watermark advance) is
  in-memory until persisted. A **hard crash mid-cycle** (process killed after emitting events but
  before durably advancing the watermark) re-reads from the last persisted watermark on restart,
  producing **duplicate events**. Those duplicates are **absorbed by the existing dedup unique
  index** on the store, so at-least-once does not surface as user-visible double-counting. This is
  the *exact* trade Splunk documents for in-memory + persistent-queue modular-input checkpoints. We
  accept at-least-once for M2.
- **Deferred durability.** A full **disk-WAL + end-to-end acks** (exactly-once-ish, durable replay)
  is **out of scope here** and deferred to **M6 / Postgres (ADR-0007)**. The DLQ sink in D-revised
  is the only durable artifact this ADR mandates now.
- A parked instance requires operator/config action to resume — intentional (it can't self-succeed),
  but it is an operational touch-point that must be visible in the UI/alerts.

---

## Alternatives considered

- **One shared `asyncio.TaskGroup` for all instances** — *rejected.* TaskGroup is all-or-nothing
  (PEP 654): the first child exception cancels every sibling (OTP `one_for_all`). That violates
  per-instance crash isolation, which is the supervisor's whole reason to exist.
- **Process-per-source now** — *rejected for M2.* Heavier (IPC, N processes, supervision at the OS
  level) than I/O-bound sources need today. Adopted only when a Decision-B graduation trigger fires;
  the path is designed-for.
- **Fixed-interval retry** — *rejected.* No jitter ⇒ synchronized fleet-wide retry storms against a
  recovering upstream (the cascading-failure / thundering-herd anti-pattern). Full Jitter (C) chosen
  instead.
- **Stop/disable a source after N failures (give up)** — *rejected* as the *only* behavior: a
  transient upstream can recover hours later; we should keep trying (capped). The storm cap (D)
  parks only a *hard-looping* instance and still alerts, rather than silently giving up.
- **Full persistent queue / disk-WAL now** — *deferred,* not rejected. Correct long-term durability
  story, but it belongs with the Postgres storage work (ADR-0007, M6); building it now would
  over-build M2.

---

## References (each mapped to the decision it backs)

- **Erlang/OTP supervisor principles** — https://www.erlang.org/doc/system/sup_princ.html —
  backs **A** (one_for_one vs one_for_all) and the **storm cap** in **D-revised**
  (max-restart-intensity ⇒ shut the child down).
- **PEP 654 (exception groups) / asyncio Task & TaskGroup** — https://peps.python.org/pep-0654/ —
  backs **A**: TaskGroup's all-or-nothing cancellation semantics are why we use a tracked set of
  `create_task` + `add_done_callback` (with strong refs) instead.
- **AWS — Exponential Backoff And Jitter** —
  https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/ — backs **C** (the Full
  Jitter formula).
- **Google SRE — Addressing Cascading Failures** —
  https://sre.google/sre-book/addressing-cascading-failures/ — backs **C/D** (jitter + capped retry
  to avoid retry storms / thundering herd) and **B** (fault-isolation framing).
- **12-Factor IX — Disposability** — https://12factor.net/disposability — backs **E** (fast,
  graceful SIGTERM shutdown with a bounded grace) and **B** (single disposable process default).
- **OpenTelemetry Collector — resiliency** — https://opentelemetry.io/docs/collector/resiliency/ —
  backs **B** (single-process agent/supervisor model) and the retry/backpressure framing.
- **OpenTelemetry — OpAMP Supervisor** —
  https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/cmd/opampsupervisor/README.md —
  backs the **last-known-good config SEAM** steal (remote-config supervisor with rollback).
- **Cribl Stream — backpressure** — https://docs.cribl.io/stream/backpressure-impacts-sources/ —
  backs the **Block-vs-Drop per-transport** backpressure steal.
- **Logstash — Dead Letter Queues** —
  https://www.elastic.co/guide/en/logstash/current/dead-letter-queues.html — backs the
  **dead-letter path** in **D-revised**.
- **Fluent Bit — Scheduling and Retries** —
  https://docs.fluentbit.io/manual/administration/scheduling-and-retries — backs **C** (scheduled
  retry/backoff) and the retry-then-shed shape of the DLQ in **D-revised**.
- **Splunk — modular-input checkpoints (in-memory + persistent queue)** —
  https://docs.splunk.com/Documentation/SplunkCloud/latest/AdvancedDev/ModInputsCheckpoint — backs
  the **HONEST residual gap** in Consequences (at-least-once with possible duplicates on hard crash).
