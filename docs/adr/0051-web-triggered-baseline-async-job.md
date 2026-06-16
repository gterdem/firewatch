# ADR-0051: Web-Triggered Baseline Save/Compare — Async Background Job + Progress Channel

**Date:** June 2026
**Status:** Accepted

**Supersedes (in part):** ADR-0043 — specifically its line *"Out of scope: UI-triggered
baseline runs (CLI-triggered in MK)."* That single out-of-scope item is **reversed** by this ADR.
ADR-0043 otherwise stands unchanged (the page identity, composition, bounded-pane rules, and the
"renders retrospective/validated artifacts" framing all remain in force; this ADR only adds the
operator-initiated *write* path that produces those artifacts).

**Relates to:** ADR-0022 (local inference / zero-egress), ADR-0026 (auth posture, route classes),
ADR-0035 (analytic provenance), ADR-0043 (AI Engine page identity), ADR-0046 (SSE stage ticker —
the reused progress-channel pattern).

**Source:** product-strategist report `scratch/buglist_ai-engine_opus.md` (Problem 5, rec #2 and the
Flags/reconciliation block); research `scratch/research/model-trust-drift-research.md` (§2, §3, §5,
Whitespace #2).

---

## Context

The Model Trust panel (ADR-0043 page block 4, `DriftPanel.tsx`) surfaces verdict-drift across local
model swaps. Today its only entry point is the CLI: `firewatch ai-baseline --save` records the
trust baseline, `--compare` re-runs the canonical scenarios and writes a drift report that the
read-only `GET /ai/baseline/drift` then surfaces. The web panel is **read-only** — a first-time
operator lands on an empty state that tells them to open a terminal, which Maintainer flagged in the
walkthrough as the worst-explained surface on the page ("I have no idea what this panel is about…
I need to run from the CLI, which doesn't make any sense to me").

ADR-0043 deliberately scoped UI-triggered runs out of MK. The strategist re-examined the three
reasons the runs were CLI-only and found that **none of them require a terminal**:

1. **Performance** — a save/compare run pushes every canonical scenario through the live local
   model (seconds-to-minutes), so it was kept off the synchronous request path. → argues for an
   *async job*, not for CLI-only.
2. **Deliberate act** — saving a baseline overwrites the operator's *trust anchor*, so it was kept
   from being a silent one-click action. → argues for a *confirm step*, not for CLI-only. A confirm
   modal is *more* explicit and auditable than typing a flag, not less.
3. **Scriptable CI gate** — `--compare` exits non-zero on drift, so engineers can wire it into CI.
   → this is preserved by *keeping the CLI*, not by withholding the UI. It is not either/or.

The competitive research is blunt that CLI-only baseline creation is the exact friction operators
hate and is rare in MLOps: "nearly all offer async web UI + progress" (§3, Whitespace #2);
async background jobs are the standard MLOps pattern across Databricks/GCP/AWS (§3). LangSmith
ships precisely this split — no-code UI for operators, API/CLI for engineers (§3). FireWatch already
built the hard part (the verdict-pinning baseline + diff); the only gap is an operator-grade trigger.

## Decision

1. **Add an operator-initiated write path for baseline save and compare, run as an async background
   job, exposed in the Model Trust panel — without removing the CLI.** The CLI remains the
   scriptable CI gate (its non-zero-on-drift contract is unchanged). The web path is additive.

2. **Two legitimate constraints from ADR-0043 are preserved in the web, not dropped:**
   - *Deliberate act* → **save is gated behind a confirm modal** ("This will record your current
     model's verdicts as the trust baseline, replacing the previous one. Continue?"). Compare does
     not overwrite the anchor, so it needs no destructive-confirm (a plain action button is fine).
   - *Slow run* → the job runs **asynchronously with a progress channel** (e.g. "Scoring scenario
     12 of 25…") and a completion toast. It never blocks the page or the request thread.

3. **Write endpoints (Route class C — read/operator, ADR-0026; loopback-open, key-gated when the
   API is exposed beyond loopback):**
   - `POST /ai/baseline/jobs` — body `{ "mode": "save" | "compare" }`; enqueues one baseline job
     and returns `{ "job_id": "<uuid>", "status": "queued" }` (HTTP 202). A **single-flight guard**
     allows at most one baseline job in flight at a time (the local model has one GPU slot; reuse
     the `_in_flight` guard idea from `ai_stream.py`). A second enqueue while one is running returns
     **409** with the running `job_id`.
   - `GET /ai/baseline/jobs/{job_id}` — poll fallback; returns the current job status DTO.

4. **Progress channel — reuse the ADR-0046 SSE pattern (it generalizes):**
   - `GET /ai/baseline/jobs/{job_id}/stream` returns `text/event-stream`, framed exactly like
     `ai_stream.py` (`event: <type>\ndata: <json>\n\n`, WHATWG HTML §9.2), consumed via `fetch` +
     `Authorization` header (no `EventSource`/cookie assumptions — ADR-0046 D2).
   - **Closed event vocabulary only** (the ADR-0046 D3 / ADR-0035 invariant): the stream emits
     `event: progress` frames carrying *only* a closed-schema status dict
     (`{ "scenario_index", "scenario_total", "scenario_category" }`) and exactly one terminal frame
     — `event: done` carrying the validated job-result DTO (for `compare`, the same shape
     `GET /ai/baseline/drift` already returns; for `save`, the baseline-status shape
     `GET /ai/baseline` returns), or `event: error` carrying a client-composed message.
     **Raw model text, prompts, exception strings, and attacker-sourced data are never emitted.**
   - **Cancel-on-disconnect** as in ADR-0046 §5: client disconnect cancels the job task, propagating
     `CancelledError` into the engine call, closing the upstream httpx request and releasing the
     model slot. **`stream: False` to the upstream local endpoint is unchanged** (ai-engine
     invariants — the baseline runner does not enable token streaming; only *our* job-progress SSE
     is added, derived from per-scenario completion, not from upstream tokens).

5. **Module layout (the job seam lives in firewatch-core; the API only adapts it):**
   ```
   firewatch_core/ai/baseline/
     job.py        # BaselineJob model (id, mode, status, scenario_index/total, result|error)
                   #   + JobStatus enum (queued|running|done|error|cancelled)
     job_runner.py # async run_save_job / run_compare_job: drive run_all_scenarios,
                   #   emit per-scenario progress to a sink (mirrors StageEmitter),
                   #   write the baseline / drift-report files (reuses runner.py +
                   #   drift_report.py as-is — no new prompt/scoring code)
     job_store.py  # process-local in-memory registry of jobs + single-flight guard
                   #   (one-process model, ADR-0023 §F; broker-optional later per ADR-0030)
   firewatch_api/routes/
     ai_baseline_jobs.py  # POST /ai/baseline/jobs, GET .../{id}, GET .../{id}/stream
                          #   (thin: validates, enqueues, adapts the progress sink to SSE)
   firewatch_cli/commands/ai_baseline.py  # UNCHANGED behavior; may call the shared
                                          #   job_runner internally, but the exit-code gate stands.
   firewatch-ui (ai/drift/):
     useBaselineJob.ts    # enqueue + subscribe-to-progress hook (fetch SSE, AbortController)
     SaveBaselineButton.tsx / CompareNowButton.tsx + confirm modal + progress + toast
   ```
   This is a *sketch*, not a straitjacket — the concern split (model · runner · store · route · UI
   hook) is the architecturally load-bearing part. The progress sink is the same shape as
   ADR-0046's `StageEmitter` (an `asyncio.Queue`-backed emitter) so the SSE route is a near-copy.

6. **Zero-egress holds (ADR-0022).** The job calls only the validated local inference endpoint —
   identical to the CLI path. No new network destination is introduced; the SSE channel is
   loopback/local to the operator's own box. The progress channel carries no telemetry off the host.

## Alternatives considered

- **Keep CLI-only (status quo, ADR-0043 as written)** — rejected: it is the documented MLOps
  anti-pattern for an operator audience (§3, Whitespace #2), it dead-ends the panel's actual users,
  and the three rationales for it (perf / deliberate / scriptable) are satisfied better by
  async-job + confirm-modal + keep-the-CLI than by withholding the UI.
- **Synchronous `POST` that runs the scenarios inline and returns the report** — rejected: a
  seconds-to-minutes call blocks the request thread and the page; violates the "never on the main
  path" MLOps convention (§3) and risks request timeouts. The job seam exists precisely to avoid
  this.
- **A new polling-only status endpoint (no SSE)** — viable and kept as the *fallback*
  (`GET /ai/baseline/jobs/{job_id}`), but SSE is preferred for live progress because the ADR-0046
  channel already exists and generalizes cleanly (closed-vocabulary frames, cancel-on-disconnect,
  fetch+header auth). Polling alone would re-implement progress with worse latency.
- **A general-purpose job queue / broker now (Celery, etc.)** — rejected as premature: the
  single-process deployment model (ADR-0023 §F) makes a process-local in-memory `job_store` correct
  and simplest; ADR-0030 already reserves the broker-optional seam for later if needed.
- **Web-triggered runs that *also* auto-save a new baseline on a schedule** — out of scope here and
  scoped compare-only when it lands (it brushes the deliberate-act principle); see the scheduled-
  drift issue (post-release, future).

## Reasoning

- **NIST AI RMF 1.0** — the MEASURE/MANAGE functions call for ongoing measurement of AI system
  performance and for actions to be *traceable and operator-controllable*. Putting baseline
  save/compare in the operator's hands (with an explicit confirm + audited trigger) directly serves
  "accountable and transparent" without weakening the trust anchor.
- **OCSF analytic provenance (ADR-0035)** — both sides of every diff remain AI-chipped with their
  authoring model named; the job result DTO carries the same provenance the read endpoints already
  enforce, so the write path adds no un-provenanced artifact.
- **MLOps async-job convention (research §3)** — async, off-main-path, with progress + notification
  is the cross-vendor standard (Databricks/GCP/AWS); the operator/engineer UI-vs-CLI split mirrors
  LangSmith. FireWatch deliberately *follows* the standard here rather than deviating.
- **Reuse over invention (ADR-0046)** — the SSE stage-ticker already solved the hard parts
  (closed-vocabulary frames, fetch+header auth, cancel-on-disconnect, single-flight). The baseline
  progress channel is the same pattern with a different (smaller, even safer) event vocabulary, so
  the marginal complexity is low and the security invariants are inherited.
- **Zero-egress is non-negotiable (ADR-0022)** — the only network call remains the local inference
  endpoint, identical to the CLI; the feature changes *who can trigger* the run, not *where data
  goes*.

## Out of scope

- **Scheduled / recurring drift checks** — a separate future issue; when built it is **compare-only**
  (never auto-*saves* a baseline) to preserve the deliberate-act trust anchor.
- **Changing what a baseline contains, the scenarios, prompts, scoring, or the drift diff math** —
  the job reuses `runner.py` + `drift_report.py` as-is (ai-engine invariants).
- **Multi-tenant / cross-process job orchestration / a real broker** — deferred to the ADR-0030 seam
  if/when the single-process model is outgrown.
- **Baseline history / versioning** (keeping prior baselines) — latest-wins file behavior is
  unchanged here.

## References

- NIST AI RMF 1.0 — MEASURE & MANAGE functions; "accountable and transparent" characteristic.
- OCSF `analytic` object (Rule vs Learning analytics) — provenance grounding (ADR-0035).
- WHATWG HTML §9.2 Server-Sent Events (wire format) — as already used by ADR-0046.
- MLOps async sync/async task pattern (research §3, cited link in
  `scratch/research/model-trust-drift-research.md`); LangSmith operator-UI / engineer-API split.
- Internal: ADR-0022, ADR-0023 §F, ADR-0026, ADR-0030, ADR-0035, ADR-0043, ADR-0046.
- Source: `scratch/buglist_ai-engine_opus.md` Problem 5 rec #2 + Flags block;
  `scratch/research/model-trust-drift-research.md` §2/§3/§5, Whitespace #2/#3.
