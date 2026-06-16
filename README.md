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

<img width="800" height="450" alt="FireWatch-Intro" src="https://github.com/user-attachments/assets/331a3ca1-e0f4-4e04-b6f6-00af78d48df7" />

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

## How FireWatch's AI works (and how you can audit it)

All AI inference runs on a local endpoint you control — the adapter refuses to connect to
any non-local host, so "local-only" is enforced in code, not promised in a policy. The AI
is additive-only on top of a deterministic scoring floor: a rule engine runs first; the
model may add a bounded boost; if the model is wrong, offline, or hallucinating, the rule
score stands. Every score is provenance-tagged (`RULE` vs `AI+RULE`) and carries an
evidence chain you can inspect.

Full trust model and claim-by-claim auditing: [AI: Trust & Auditability](docs/ai-trust-and-auditability.md).

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

A new telemetry source is a **new package implementing one contract** — zero core edits,
ever. Start with [PLUGIN_CONTRACT.md](PLUGIN_CONTRACT.md) (the normative interface) and the
[module-author guide](docs/module-author-guide.md) (what to write, what you get for free,
and the reference implementation in `packages/sources/suricata/`).

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
- [docs/ai-trust-and-auditability.md](docs/ai-trust-and-auditability.md) — full AI trust model: six auditable claims, what FireWatch does not claim, and the prompt-injection posture
- [docs/ai-claims-checklist.md](docs/ai-claims-checklist.md) — every public AI claim, mapped to the code/test/ADR that enforces it
