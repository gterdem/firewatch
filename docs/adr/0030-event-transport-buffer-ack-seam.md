# ADR-0030: Event-Transport Buffer/Ack Seam — In-Process Now, Broker-Optional Later

**Date:** June 2026
**Status:** Proposed

**Relates to:** ADR-0007 (storage — "SQLite now, Postgres later via one adapter swap"; this ADR
applies the *same* port-and-adapter swap philosophy to transport), ADR-0023 (collector supervisor —
single-process/single-loop default + documented graduation triggers; this ADR adds the *transport*
rung to that same ladder), ADR-0016 (multi-source-per-type; watermarks keyed on
`(source_type, source_id)` — the existing at-least-once replay baseline), ADR-0025 (canonical
`SecurityEvent` — the unit that flows across this seam), ADR-0020 (lightweight OCSF alignment — the
schema the seam carries; transport is orthogonal to schema). **Does NOT relate to** ADR-0029's
forward-link to "a future auth ADR" — see the numbering note in the README; auth takes 0031.
**Standards / prior-art consulted:** Vector, OpenTelemetry Collector, Logstash, Fluent Bit/Fluentd,
Cribl Stream, Wazuh, Security Onion, Benthos/Redpanda Connect, OCSF (transport-agnostic).

**Scope of this ADR:** establish the **decision, the seam, and the graduation ladder** only. It is a
**PLANNED graduation, not built now**, and is **explicitly NOT part of the #75 run-loop fix**
(ADR-0023 §F). Defining the actual buffer/ack `Protocol` signature is a deliberately-deferred future
task; this ADR describes the contract conceptually so the seam is reserved, not so it is implemented.

---

## Context

FireWatch today moves events from collection to processing/storage over a **single in-process
asyncio pipeline**: a source instance's `run_pull_cycle` (or a PushSource listener) emits normalized
`SecurityEvent`s that flow, in the same event loop, into scoring/detection and then the
`EventStore`. There is no queue object between "collected" and "processed"; the seam is implicit in
the `await` chain. Durability across a crash is provided **not** by a buffer but by **watermarks**
(ADR-0016): on restart, an instance re-reads from its last persisted position. ADR-0023 already
records the consequence — **at-least-once with possible duplicates** on a hard mid-cycle crash,
absorbed by the store's dedup unique index.

As FireWatch graduates toward a plugin-distributable v2 and (per ADR-0023 §B) toward optional
multi-process / multi-node deployments, a recurring architectural question surfaces: *do we need an
event bus?* The convenient-but-wrong answer is "add Kafka." Before settling, we checked what the
dominant log/telemetry pipelines and the security-domain exemplars actually do, because the cost of
getting this wrong is a hard broker dependency baked into core/SDK — exactly the kind of coupling the
dependency rule (core never imports a plugin; plugins/core depend only on the SDK) exists to prevent.

**What the industry actually does — the seam, not the bus.** Vector, Fluent Bit/Fluentd, the
OpenTelemetry Collector, Logstash, and Cribl Stream all share one shape: an **in-process pipeline
with a per-output buffer that DEFAULTS to in-memory** and can be **switched to a disk-backed
write-ahead-log** for durability. Kafka/Redis/NATS appear only as **optional connectors at the edge**,
never as the internal bus:

- **Vector** buffers default to in-memory; disk buffers are a write-ahead log fsync'd on an interval,
  paired with **end-to-end acknowledgements** so a source only acks its upstream once the event is
  durably handled downstream.
- **OpenTelemetry Collector** runs a single-process pipeline; its `sending_queue` can be made
  **persistent via the `file_storage` extension (a WAL)**, and its resiliency guidance reserves a
  **message queue specifically for "critical data paths across network boundaries"** — i.e. the
  cross-host tier, not the in-process default.
- **Logstash** persistent queues (disk + checkpointing) are explicitly marketed as letting you
  **"absorb bursts without needing an external buffering mechanism like Redis or Apache Kafka"** —
  the local WAL *removes* the external queue layer for single-node deployments.
- **Fluent Bit / Fluentd** offer filesystem buffering as the durable rung over memory buffering.
- **Cribl Stream** uses on-disk **persistent queues** (a disk spool) for backpressure/durability,
  with Kafka as an *optional destination*, not the internal transport.

**Security-domain exemplars (most relevant — FireWatch is a Suricata-fed SOC tool).**
- **Wazuh** uses entirely its **own in-process FIFO queues** (`wazuh-remoted` → `wazuh-analysisd`
  over `/var/ossec/queue/`) with **no broker at all** — but **drops events on saturation**. It proves
  a broker-free SOC pipeline is viable at scale; its drop-on-saturation is the failure mode we want a
  durable rung to be *able* to avoid when it matters.
- **Security Onion** is the Suricata pipeline that *graduated* to a broker — and the broker is
  **Redis, not Kafka** — introduced **only for multi-node outage decoupling**: "if the manager goes
  down, the search nodes keep pulling from the queue." This is the canonical evidence for *when* and
  *which* broker: Redis, at the multi-node tier, for cross-host outage decoupling — not as a day-one
  internal bus.

**Two broker-free durability philosophies exist**, and FireWatch already sits in one of them:
(i) **local disk WAL** (Vector / OTel / Logstash / Fluentd / Cribl); (ii) **replay-from-source / no
local state**, relying on the source's own position/acks (Benthos / Redpanda Connect). FireWatch's
**watermarks are camp (ii)** — we already have the replay-from-source durability story; we just have
not *named* it as the transport seam's baseline. A disk-WAL adapter (camp (i)) is an optional future
rung on top, not a precondition.

**Standards govern schema, not transport.** OCSF is **explicitly transport-agnostic**; ECS and the
OpenTelemetry semantic conventions are *field schemas*. None of them prescribe an event bus. So the
internal transport is a **free architecture choice**, not a compliance requirement — FireWatch
already normalizes everything to its canonical `SecurityEvent` (ADR-0020 / ADR-0025), and that
canonical event is the only thing that ever needs to cross this seam.

The conclusion writes itself: model the **seam** (a buffer + ack port) the way ADR-0007 modelled
storage (a port with a default adapter and a documented later swap), default it to today's in-process
pipeline, and reserve — without building — a disk-WAL rung and an external-broker rung for the
multi-node tier. We do **not** build a bespoke distributed bus, and we do **not** couple core/SDK to
any broker.

---

## Decision

### A. Model the collect→process seam as a thin buffer/ack PORT in `firewatch-sdk`

The boundary between **collection** (sources emitting normalized `SecurityEvent`s) and
**processing/storage** (scoring, detection, `EventStore`) is named as a **buffer + acknowledgement
port** living in the SDK alongside the other ports. Conceptually the port carries two responsibilities
(described here, **not** pinned to a signature — see Scope):

- **Publish / consume.** A producer hands a normalized `SecurityEvent` (or a small batch) to the
  buffer; a consumer pulls events for processing. The unit is always the **canonical `SecurityEvent`**
  (ADR-0025) — sources never see, name, or depend on the transport.
- **Acknowledgement + backpressure.** A consumer **acks** an event once it is durably handled
  (scored + persisted, or dead-lettered per ADR-0023 §D). Until then the event is "in-flight." When
  the consumer is slower than the producer, the port exposes **backpressure** so the producer blocks
  (or, per ADR-0023's per-transport rule, drops-with-counter for inherently-lossy UDP). This is the
  same publish/ack/backpressure shape Vector's end-to-end acknowledgements and OTel's `sending_queue`
  expose — generalized to one port with swappable adapters.

The ack semantic is what lets the **durability rung** be an adapter detail rather than a core change:
"acked = safe to advance the watermark / drop the in-flight copy" is identical whether the buffer is
an in-memory `asyncio.Queue`, a disk WAL, or an external broker's commit.

### B. Default adapter = today's in-process asyncio pipeline; watermark replay = the at-least-once baseline

The **default and only adapter built now** is the existing **in-process asyncio pipeline**: the
implicit `await` chain becomes the trivial buffer adapter (in-memory, loop-local), and "ack" is the
existing "scored + persisted" step. The **durability baseline is unchanged and explicitly named**:
**watermark replay-from-source (ADR-0016) = at-least-once**, with duplicates absorbed by the store's
dedup unique index (ADR-0023 Consequences). FireWatch is camp (ii) — replay-from-source — by default;
this ADR does not add any new durability mechanism, it *names the one we have* as the seam's baseline.

### C. The graduation ladder (explicit triggers per rung)

Mirroring ADR-0023 §B's subprocess ladder, transport graduates **one rung at a time, only when a
concrete trigger fires**:

| Rung | Adapter | Durability | Graduation trigger |
|---|---|---|---|
| **0 (now)** | In-process asyncio pipeline (in-memory, loop-local) | Watermark replay-from-source = **at-least-once** (ADR-0016) | Default. Single-process / single-loop (ADR-0023 §B, §F). |
| **1 (optional)** | **Disk-WAL buffer** (local write-ahead log, fsync'd on interval; Vector/OTel/Logstash model) | Local **crash-durable replay** of in-flight events; removes mid-batch loss without an external service (Logstash: "without … Redis or Kafka") | **Mid-batch crash-loss matters** — i.e. re-reading from the watermark is too coarse/expensive (large in-flight batches, costly re-pull, or a source whose replay window is bounded), OR the operator wants Wazuh-style saturation *without* Wazuh's drop. Stays single-host. |
| **2 (optional)** | **External broker**, **Redis-before-Kafka** | Cross-host durable queue; outage decoupling | **Multi-node / fan-out / cross-host replay** — collection and processing run on **different hosts**, or one stream fans out to multiple consumers, or a downstream-outage must not stall ingest across the network. This is OTel's "message queue for critical data paths **across network boundaries**" and Security Onion's exact Redis trigger ("manager down ⇒ search nodes keep pulling"). |

**Redis before Kafka** is a deliberate ordering, grounded in Security Onion (a Suricata pipeline that
chose Redis, not Kafka, for multi-node decoupling): Redis covers the cross-host outage-decoupling and
fan-out cases at far lower operational weight; Kafka's partitioned-log / long-retention / replay
guarantees are a *further* rung only justified by genuine high-throughput multi-consumer replay needs
FireWatch does not have today. Each rung is an **adapter behind the port** (A) — adopting it is a
config/wiring swap, **never** a core or SDK edit, exactly as ADR-0007 promises for SQLite→Postgres.

### D. What we explicitly REJECT

- **A bespoke distributed event bus.** No homegrown cross-host queue/broker protocol. If/when rung 2
  is reached we adopt a battle-tested broker (Redis, then Kafka) behind the port — we do not invent
  transport.
- **A hard Kafka (or any broker) dependency in core or the SDK.** Core/SDK depend on the **port**, not
  on any broker client. A broker client lives only in its optional adapter package, pulled in only
  when rung 2 is configured. This preserves the dependency rule and keeps the default install
  broker-free (Wazuh-style).
- **A broker — or any transport awareness — inside a source module.** Sources emit normalized
  `SecurityEvent`s and **never see transport**. The Suricata plugin (and every future source) is
  unaware of which rung is in use; it publishes to the seam, full stop. A source must never import a
  buffer adapter, a broker client, or the port's concrete type.
- **Building rungs 1–2 now.** This is a reserved seam and a written-down ladder, not an
  implementation. No disk-WAL, no Redis, no broker code ships from this ADR.

---

## Consequences

**Positive**
- The "do we need Kafka?" question is settled with a standards-grounded **no (not now)**, and a clear
  **when/which** if it ever changes — removing a recurring source of architectural drift.
- The seam is reserved in the SDK, so adopting a durability/broker rung later is an **adapter swap**
  (ADR-0007 philosophy) rather than a core refactor — the dependency rule is preserved by construction.
- Sources stay transport-agnostic forever: adding the disk-WAL or Redis rung requires **zero source
  edits** (the modularity non-negotiable), because the seam sits below the `SourcePlugin` boundary.
- The existing watermark/at-least-once story is finally **named as the baseline**, so future
  durability work has an explicit starting rung rather than an implicit one.

**Negative / accepted trade-offs**
- **The default rung keeps ADR-0023's honest gap**: in-memory + watermark replay is at-least-once;
  a hard mid-cycle crash re-reads from the last persisted watermark and can re-emit events (absorbed
  by dedup). This ADR does **not** close that gap — it names rung 1 (disk-WAL) as the place it gets
  closed, when the trigger fires. No regression, but no improvement either, by design.
- **A reserved-but-undefined port carries a small risk of mis-shaped abstraction** if we guess the
  signature now. We mitigate by **not** pinning the signature in this ADR (Scope) — only the
  responsibilities — so the concrete `Protocol` is designed against a real rung-1 need, not in the
  abstract.
- **Single-loop co-hosting (ADR-0023 §F) is rung-0-only.** The moment FireWatch graduates to
  multi-process (ADR-0023 §B) / multi-node (rung 2 here), the single-loop co-hosting of the API server
  is superseded by genuine process separation — at which point WAL/Postgres (ADR-0007) and a broker
  become appropriate *together*. This ADR makes that linkage explicit so the rungs are adopted as a
  coherent set, not piecemeal.

---

## Alternatives considered

- **Adopt Kafka now as the internal event bus** — *rejected.* No current trigger (single-host,
  single-analyst, I/O-bound sources). It would bake a heavy broker dependency into the default install
  and into core/SDK, violating the dependency rule, for zero present benefit. None of the surveyed
  pipelines (Vector/OTel/Logstash/Fluent Bit/Cribl) use a broker as the *internal* bus; Kafka is
  always an optional edge connector. Reserved as the *top* rung (2b), Redis-first.
- **Build a bespoke distributed event bus** — *rejected.* Inventing cross-host transport is exactly
  the wheel the industry has standardized (Redis/NATS/Kafka). We adopt a proven broker behind the port
  if/when rung 2 is reached; we never write our own.
- **Disk-WAL buffer now (skip the in-memory default)** — *rejected as premature, reserved as rung 1.*
  Correct durability rung, but it adds fsync/WAL complexity before a trigger justifies it; FireWatch's
  watermark replay already provides at-least-once. Logstash/Vector/OTel all *default* to memory and
  switch to disk on need — we follow that default.
- **Wazuh-style own-FIFO-queues with drop-on-saturation as the permanent model** — *partially adopted,
  rejected as the ceiling.* Our rung 0 *is* essentially own-in-process-queues; but Wazuh's
  **drop-on-saturation** is a data-loss mode we want the *option* to avoid (rung 1's disk-WAL, or
  ADR-0023's per-transport block-vs-drop), so we do not enshrine drop-on-saturation as the only story.
- **No seam at all — leave the `await` chain implicit forever** — *rejected.* Without a named port,
  every future durability/broker change becomes a core refactor touching the pipeline, which is
  precisely the coupling ADR-0007's port-swap philosophy avoids for storage. Naming the seam now (even
  with a trivial default adapter) makes later rungs additive.
- **Couple transport choice to a standard (OCSF/ECS/OTel)** — *rejected as a category error.* Those
  standards govern **schema**, not transport (OCSF is explicitly transport-agnostic). Transport is a
  free internal-architecture choice; we cite the standards only to confirm we are *not* constrained.

---

## References (each mapped to the decision it backs)

- **Vector — buffering model (memory default; disk = WAL fsync'd on interval)** —
  https://vector.dev/docs/architecture/buffering-model/ — backs **A** (per-output buffer w/ swappable
  durability) and **C** rung 1 (disk-WAL).
- **Vector — end-to-end acknowledgements** —
  https://vector.dev/docs/about/under-the-hood/architecture/end-to-end-acknowledgements/ — backs **A**
  (the ack semantic = "durably handled before upstream ack").
- **OpenTelemetry Collector — exporterhelper (persistent `sending_queue` via `file_storage`)** —
  https://github.com/open-telemetry/opentelemetry-collector/blob/main/exporter/exporterhelper/README.md
  — backs **A** + **C** rung 1 (WAL queue as an extension, not the default).
- **OpenTelemetry Collector — resiliency ("message queue for critical data paths across network
  boundaries")** — https://opentelemetry.io/docs/collector/resiliency/ — backs **C** rung 2 trigger
  (broker only across network boundaries).
- **Logstash — persistent queues ("absorb bursts without … Redis or Apache Kafka")** —
  https://www.elastic.co/docs/reference/logstash/persistent-queues and
  https://www.elastic.co/blog/logstash-persistent-queue — backs **C** rung 1 (local WAL *removes* the
  external queue for single-node).
- **Fluent Bit — buffering & storage (filesystem buffering)** —
  https://docs.fluentbit.io/manual/administration/buffering-and-storage ; **Fluentd — buffer** —
  https://docs.fluentd.org/buffer — backs **C** rung 1 (memory→filesystem buffer rung).
- **Cribl Stream — persistent queues (disk spool; Kafka optional destination)** —
  https://docs.cribl.io/stream/persistent-queues/ — backs **A**/**C** (disk-spool buffer; broker as
  optional edge).
- **Wazuh — server queues (own in-process FIFO; drops on saturation, no broker)** —
  https://documentation.wazuh.com/current/user-manual/manager/wazuh-server-queue.html — backs **B**
  (broker-free SOC pipeline is viable) and the rejected-ceiling alternative (drop-on-saturation).
- **Security Onion — architecture (Redis introduced for multi-node outage decoupling)** —
  https://docs.securityonion.net/en/2.4/architecture.html — backs **C** rung 2 (Redis-before-Kafka, at
  the multi-node tier, for "manager down ⇒ search nodes keep pulling").
- **Benthos / Redpanda Connect (replay-from-source / no local state philosophy)** —
  https://github.com/redpanda-data/connect — backs **B** (FireWatch is camp (ii); watermarks = the
  baseline).
- **OCSF is transport-agnostic (schema, not transport)** —
  https://www.deepwatch.com/glossary/open-cybersecurity-schema-framework-ocsf/ — backs **D** /
  Alternatives (transport is a free choice; standards govern schema only).
- **Internal:** ADR-0007 (port-swap philosophy), ADR-0023 (supervisor ladder, §B/§F, at-least-once
  gap), ADR-0016 (watermarks = replay baseline), ADR-0025 (canonical `SecurityEvent` = the unit on the
  seam), ADR-0020 (OCSF alignment — schema, orthogonal to transport).
