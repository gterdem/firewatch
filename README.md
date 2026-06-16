# FireWatch

**An integrated, self-hosted AI SOC platform — multi-source detection, local-only AI investigation, and tunable response, in one tool you can audit.**

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![Code of Conduct](https://img.shields.io/badge/Contributor%20Covenant-2.1-purple.svg)](CODE_OF_CONDUCT.md)

FireWatch ingests security telemetry from pluggable sources — Azure Web Application
Firewall (WAF), Suricata, AWS Network Firewall, vendor-agnostic Syslog/CEF — normalizes
it to one canonical schema, scores attacker IP addresses with a **deterministic rule
engine plus a local language model**, and gives you a triage dashboard. Everything runs
on hardware you control: no telemetry ever leaves your machine, and the AI never gets the
final word.

> **SOC** = Security Operations Center · **SIEM** = Security Information and Event
> Management (collecting and analyzing security events) · **SOAR** = Security Orchestration,
> Automation and Response (acting on them). FireWatch is a SIEM with AI investigation
> today; tunable response (SOAR) is a deliberate next step, behind a seam already in the
> code.

---

## The distinctive bets

- **Modular, zero-core-edit source plugins.** A new telemetry source is a *new package*
  implementing one contract — discovered via entry points, with **zero edits to the
  core**. Install a source and its config UI, storage, and dashboard views appear;
  uninstall it and they're gone. The core never imports a plugin. ([PLUGIN_CONTRACT.md](PLUGIN_CONTRACT.md))
- **Local-first, zero-egress AI — enforced, not promised.** Inference targets a local
  OpenAI-compatible endpoint (Ollama by default; vLLM, llama.cpp, LM Studio, SGLang also
  work). The adapter *refuses to construct* against a non-local host, so "local" can never
  quietly become a hosted API. ([ADR-0022](docs/adr/0022-local-inference-openai-compatible-endpoint.md))
- **Deterministic + AI dual engine.** A readable rule engine sets the base score
  instantly; a local model may then add a *bounded* boost on top. If the model is wrong,
  offline, or hallucinating, the deterministic floor stands — and FireWatch labels
  "rules-only" mode on screen rather than faking output. ([ADR-0003](docs/adr/0003-ai-approach-sampling-not-per-log.md))
- **Action-aware escalation & triage (SIEM now, SOAR later).** Scoring is aware of what an
  event's action actually *was* — it surfaces what got **through**, not just what was
  blocked — and routes findings into a triage queue. Active response (auto-block) is the
  next milestone, gated behind an explicit, evidence-bound seam. ([ADR-0058](docs/adr/0058-action-aware-deterministic-escalation-axis.md), [ADR-0033](docs/adr/0033-ui-action-seam-siem-now-soar-later.md))

---

## Screenshot

<!-- TODO: Replace with intro gif upload. -->


---

## Quickstart

FireWatch ships a one-command Docker stack: the application, an nginx reverse proxy, and a
local inference runtime. Only the dashboard is published to the host; the inference engine
has no host port and the raw API binds loopback only.

> **Prerequisites:** Docker 20+ and Docker Compose v2 (`docker compose version`), and a
> clone of this repository.

```bash
# From the repo root — bring up the default stack (sensible defaults built in):
docker compose -f deploy/docker-compose.yml --profile default up -d
```

> The compose file ships working defaults (dashboard on port 8080, AI enabled).
> To customize, create `deploy/.env` and set any of the variables documented at
> the top of `deploy/docker-compose.yml` before starting.

The stack comes up in order: Ollama → FireWatch API → nginx. AI scoring starts once a
model is available — pull a small 3B-class model to get going:

```bash
docker compose -f deploy/docker-compose.yml --profile default \
    exec ollama ollama pull qwen2.5:3b
```

Then open the dashboard and check health:

```bash
curl -fsS http://localhost:8080/        # dashboard (through nginx)
curl -fsS http://localhost:8080/health  # API health
```

**Two deploy profiles** (ADR-0042): `default` uses [Ollama](https://ollama.com) (best
model UX, GPU auto-detect); `lean` uses [llama.cpp `llama-server`](https://github.com/ggerganov/llama.cpp)
with an operator-supplied GGUF model file (minimal footprint, air-gapped-friendly).
Profile selection changes only wiring — the FireWatch source is identical in both. Full
instructions, the lean path, and a bare-metal `pipx` option are in
[`deploy/README.md`](deploy/README.md).

> **Packaging in progress.** A polished one-command install (published Docker images and a
> PyPI release) is on the [roadmap](docs/ROADMAP.md). The steps above are the real,
> working path today — built from the repo.

**Deployment posture today:** a single operator on a local (loopback) host. Network-exposed,
multi-user hardening is on the roadmap — run FireWatch on your own machine for now.

---

## Available today

Shipped and tested capabilities:

- **Source plugins:** Azure WAF · Suricata IDS/IPS · AWS Network Firewall · Syslog
  (UDP/TCP) · Syslog/CEF (vendor-agnostic). Each is a package under `packages/sources/`,
  added with zero core edits.
- **Standards-grounded normalization.** Events map to one canonical schema aligned with
  [OCSF](https://schema.ocsf.io/) (the Open Cybersecurity Schema Framework — a common event
  shape) and [MITRE ATT&CK](https://attack.mitre.org/) technique context, populated at
  normalize time. ([ADR-0020](docs/adr/0020-event-schema-lightweight-ocsf-alignment.md), [ADR-0014](docs/adr/0014-mitre-att-ck-capec-native-categorization.md))
- **Dual-engine scoring.** Deterministic rules (brute force, port scan, SQL-injection /
  cross-site-scripting payload patterns, blocked-event volume) plus an optional, bounded
  local-AI boost.
- **Action-aware escalation & triage.** Distinguishes blocked from allowed/dropped events
  and routes findings into a triage queue.
- **Cross-source correlation** keyed on telemetry type — a new plugin joins correlation
  for free, just by declaring its source type. (Intrusion Detection System + Syslog, etc.)
- **On-device inference** with zero external egress, including a verified
  [air-gapped mode](docs/air-gapped-mode.md).
- **Schema-driven settings UI.** Each plugin's configuration card is generated from its
  Pydantic config schema — no per-source frontend code. ([ADR-0010](docs/adr/0010-unified-source-cards.md), [ADR-0019](docs/adr/0019-frontend-stack-react-rjsf.md))
- **Provenance-tagged, evidence-linked scores** (see the AI section below).

---

<!-- Summary→checklist trace (rule 1 of docs/ai-claims-checklist.md):
     local-only/cloud-refused → rows 1, 2 · deterministic floor / bounded boost → rows 3, 5
     rules-only degradation, labeled → row 12 · provenance + factor/evidence linkage → rows 6, 9
     (row 9 evidence-chain shipped — #NNN merged; endpoint + evidence.py on main) · prompt pinning → rows 7, 8
     ai-baseline operator-recorded → rows 10, 11. "Pluggable sources" is an architecture claim
     (PLUGIN_CONTRACT.md), not an AI claim — no row needed. -->

## How FireWatch's AI works (and how you can audit it)

Most AI security tools ask you to trust a verdict you cannot inspect. FireWatch is built
the other way around: the AI is **structurally contained**, and every claim below is backed
by a test or an accepted design decision you can read in this repository. The full
claim-by-claim mapping lives in [docs/ai-claims-checklist.md](docs/ai-claims-checklist.md) —
the copy on this page is not allowed to outrun it.

**1. Inference is local-only. No cloud LLM — enforced, not promised.**
All inference targets a local OpenAI-compatible endpoint (Ollama by default; vLLM,
llama.cpp, LM Studio, and SGLang also work). The adapter refuses to construct against a
non-loopback / non-private host, so "local" can never quietly become a hosted API. Your
WAF/IDS logs stay on hardware you control.
([ADR-0022](docs/adr/0022-local-inference-openai-compatible-endpoint.md); enforced in
`packages/firewatch-core/src/firewatch_core/adapters/ai_openai.py`.) For fully offline
operation, see [Air-gapped mode](docs/air-gapped-mode.md) — a verified zero-egress
configuration, not an adjective.

**2. The AI can only *add* to a deterministic score — never replace it, never lower it.**
A rule engine produces the base score first: brute force, port scan, SQLi/XSS payload
patterns, blocked-event volume — plain, readable Python in
`packages/firewatch-core/src/firewatch_core/scoring.py`. The model may then add a *bounded*
boost (+20 for a high-confidence CRITICAL verdict, +10 for HIGH, nothing otherwise);
correlation detections add at most +30; the total is capped at 100. If the model is wrong,
offline, or hallucinating, the deterministic floor stands. This is simultaneously the
scoring design and a prompt-injection mitigation: an attacker who somehow swayed the model
still cannot suppress their own score.

**3. The model's output schema is closed. It cannot invent score fields.**
LLM responses are validated against a fixed schema (threat-level enum, confidence in 0..1,
a fixed key set). Unknown keys are dropped; an invalid value rejects the entire response and
FireWatch falls back to the rules-only score. Every number in a FireWatch score comes from
your event data or a fixed constant in `scoring.py` — never from model free text.

**4. The prompt path is regression-pinned in CI.**
The exact prompt text the model sees is byte-pinned by committed baselines
(`tests/golden/ai/`). Any change to the prompts fails CI unless it is an explicit, reviewed
rebaseline. Attacker-controlled payloads enter the prompt only inside `<untrusted_data>`
sentinels — and a dedicated test fails if that wrapping is ever dropped. The
prompt-injection posture is something you can diff, not a black box.

**5. Every score explains itself — provenance-tagged and evidence-linked.**
Each score carries a derivation tag (`RULE` vs `AI+RULE` — was the AI boost actually
applied, or is this pure rule output?) and an additive factor breakdown that sums exactly to
the number on screen. An **evidence chain** maps each factor to the specific stored events
that produced it, recomputed from your data at read time so the explanation can never
silently drift from the score it explains.
([ADR-0035](docs/adr/0035-analytic-provenance-tagging.md) provenance tagging,
[ADR-0041](docs/adr/0041-evidence-chain-recompute-at-read-time.md) evidence chain — both shipped;
the chain is served by `GET /threats/{ip}/evidence`, recomputed at read time in `evidence.py`.)

**6. You can regression-test your own model's verdicts.**
```
firewatch ai-baseline --save      # record what YOUR model concludes on a canonical scenario set
firewatch ai-baseline --compare   # re-run later; exits non-zero if any verdict drifted
```
Run it after a model swap, a quantization change, or a runtime upgrade. Verdicts are
model-dependent — so the baseline is **operator-recorded on your hardware**, not a vendor
promise. FireWatch pins the prompt path centrally and hands you the tool to pin verdicts on
your own setup.

### What we deliberately do NOT claim

- We do **not** claim the AI "never hallucinates" or is "always correct." We claim
  hallucination is *contained*: it cannot lower a score, invent score fields, or inject
  numbers — and any contribution it does make is tagged and bounded.
- We do **not** ship "tested verdicts." Verdicts depend on the model and runtime *you* run.
  What is vendor-tested is the structure around the model (prompt text, schema, merge math);
  what tests verdicts is `ai-baseline`, run by you.
- If the AI engine is unreachable, FireWatch keeps working in rules-only mode and labels it
  on screen — it does not fake AI output.

---

## Architecture at a glance

FireWatch is a pipeline with lightweight ports and adapters: `core/` is pure logic with no
I/O; external systems connect through Protocol **ports**; **adapters** implement them. Every
telemetry source is a plugin behind one contract.

```
                        ┌─────────────── source plugins (zero core edits) ───────────────┐
   Azure WAF  ─┐        │  each plugin owns its raw → SecurityEvent mapping + config      │
   Suricata   ─┤        │                                                                 │
   AWS NFW    ─┼──────► │  Collect ─► Normalize ─► Enrich ─► Store ─► Detect ─► Score ─► Alert
   Syslog/CEF ─┘        │                                              (rules + local AI) │
                        └─────────────────────────────────────────────────────────────────┘
                                                                              │
                                          firewatch-core (pipeline)  ◄─── firewatch-sdk ───►  plugins
                                                                              │
                                                                       REST API ─► React UI
```

**The dependency rule:** plugins and core both depend on `firewatch-sdk`. The core never
imports a plugin; plugins never import the core. Adding a source therefore cannot — by
construction — require touching the core.

Read more: [ARCHITECTURE.md](ARCHITECTURE.md) (the design) ·
[PLUGIN_CONTRACT.md](PLUGIN_CONTRACT.md) (the source-plugin interface) ·
[docs/adr/](docs/adr/) (the *why* behind every settled decision).

---

## Add a source

A new telemetry source is a **new package implementing one contract** — a backend
`normalize()` plus a config schema and a Pull or Push collector. You get a Settings UI card,
source-scoped storage, dashboard views, correlation, and golden-test scaffolding *for free*:
zero frontend code, zero database schema changes, zero core edits. Scaffold one with
`firewatch new-source <name>`.

Start with [PLUGIN_CONTRACT.md](PLUGIN_CONTRACT.md) (normative) and the
[module-author guide](docs/module-author-guide.md). The canonical reference implementation
is `packages/sources/suricata/`.

---

## Roadmap

The narrative of where FireWatch is and where it's going — what's available now, what's in
progress for the first public release, and what comes after (AI narrative triage, a
glass-box AI surface, then tunable SOAR response) — lives in
[docs/ROADMAP.md](docs/ROADMAP.md). Day-to-day work is tracked in
[GitHub issues and milestones](https://github.com/gterdem/firewatch/milestones).

> FireWatch ships at **v0.x** until the plugin contract is proven in the open; a stable
> **1.0** and a contract-stability policy follow once it has settled. ([ADR-0056](docs/adr/0056-licensing-agpl-3.0.md))

---

## Contributing

Contributions are welcome — new sources, bug fixes, and docs especially. See
[CONTRIBUTING.md](CONTRIBUTING.md) for how to build, test, and open a pull request (the
quality gates are `ruff` + `pyright` + `pytest`, including the golden regression tests).
This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md), and
commits are signed off under the [Developer Certificate of Origin](DCO). Security issues
follow the coordinated-disclosure policy in [SECURITY.md](SECURITY.md).

---

## License

FireWatch is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)** — one
license for the whole repository (core, SDK, first-party source plugins, and frontend). If
you run a modified FireWatch as a network service, AGPL-3.0 §13 requires you to offer your
modified source to its users. See [LICENSE](LICENSE) and the rationale in
[ADR-0056](docs/adr/0056-licensing-agpl-3.0.md).

---

## Documentation

- [FAQ.md](FAQ.md) — frequently asked questions
- [ARCHITECTURE.md](ARCHITECTURE.md) — system design
- [PLUGIN_CONTRACT.md](PLUGIN_CONTRACT.md) — the source-plugin interface
- [docs/ROADMAP.md](docs/ROADMAP.md) — where FireWatch is going
- [deploy/README.md](deploy/README.md) — running FireWatch (Docker profiles + bare-metal)
- [docs/module-author-guide.md](docs/module-author-guide.md) — writing a source plugin
- [docs/air-gapped-mode.md](docs/air-gapped-mode.md) — verified zero-egress operation
- [docs/adr/](docs/adr/) — accepted design decisions
- [docs/ai-claims-checklist.md](docs/ai-claims-checklist.md) — every public AI claim, mapped to the code/test/ADR that enforces it
