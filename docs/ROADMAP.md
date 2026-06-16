# FireWatch Roadmap

**Living document.** This is the narrative of where FireWatch is and where it's
going — what's available now and what's planned. Day-to-day work is tracked in the
project's [GitHub issues and milestones](https://github.com/gterdem/firewatch/milestones);
the design decisions behind everything here live in [`docs/adr/`](adr/).

## What FireWatch is

A modular, local-first threat-monitoring platform. Telemetry sources — Azure WAF,
Suricata, AWS Network Firewall, Syslog/CEF, and more — are **plugins against a
single contract**: adding a source is a new package, with zero edits to the core.

Scoring is a **dual engine**: deterministic rules for instant, auditable detection,
paired with a local on-device language model for narrative triage. No telemetry
leaves your machine.

The guiding bets:

- **Modular by default** — install a source and its UI and storage appear; uninstall it and they're gone.
- **Local & auditable AI** — inference runs on-device, with zero external egress.
- **A real SOC on one box** — designed to run offline / air-gapped on modest hardware.
- **SIEM now, SOAR later** — alert and triage today; active response is a deliberate next step.

## Available today

- **Sources:** Azure WAF · Suricata · AWS Network Firewall · Syslog/CEF (vendor-agnostic).
- **Normalization** grounded in open standards — [OCSF](https://schema.ocsf.io/)
  for event shape and [MITRE ATT&CK](https://attack.mitre.org/) for technique context.
- **Dual-engine scoring** — deterministic rules plus local language-model triage.
- **Action-aware escalation** — surfaces what actually got *through*, not just what was blocked.
- **Live, auto-updating console** — every view refreshes as new telemetry lands; aggregate pages update in place, busy tables and the relationship graph offer a "new data — load now" control so your scroll, filters, and focus are never yanked out from under you.
- **Triage you can manage** — acknowledge or dismiss noisy actors and have it *stick* across reloads, with acknowledged actors automatically re-surfacing when they do something new.
- **AI-drafted case files** — turn an AI verdict into a persisted case with timeline, notes, disposition, and an AI-drafted summary.
- **On-device inference** — narrative triage with zero external egress.
- **Schema-driven settings** — the configuration UI is generated per installed plugin, with honest source state (a source is "active" only when it's really collecting).

> **Deployment posture today:** a single operator on a local (loopback) host.
> Network-exposed, multi-user hardening is on the roadmap below — run it on your
> own machine for now.

## In progress — preparing the first public release

The run-up to going open source:

- **Packaging** — one-command install via Docker Compose (with bundled inference) and PyPI.
- **Documentation** — getting-started, [FAQ](../FAQ.md), the [plugin-authoring guide](module-author-guide.md), and [air-gapped operation](air-gapped-mode.md).
- **Release hardening** — a pre-public review pass across the surface.
- **Licensing & community files** — AGPL-3.0 plus the standard health/governance files. ✅

## Next — standout features + launch (v0.x)

The features that make FireWatch distinct, landed *before* the public announcement:

- **AI narrative triage** — auto-generated, evidence-linked alert stories that explain what happened and why it matters, on top of the deterministic score (the AI explains; it never silently drives the number).
- **Glass-box AI surface** — inspectable verdicts, prompt transparency, and **model-trust / drift visibility** (save a baseline of how your local model judges a fixed scenario set, then check whether its judgment has drifted after a model or runtime change).
- **Launch** — PyPI + Docker, a how-to guide and wiki, and the public announcement.

> FireWatch ships at **v0.x** until the plugin contract is proven in the open; a
> stable **1.0** and a contract-stability policy follow once it has settled.

## After launch — active response (SOAR)

Moving from *alerting* to *acting*, behind the same action seam the platform
already exposes:

- **Tiered-autonomy responder** — suggest → one-click → conditional-auto, so you choose how much the system does on its own.
- **Evidence-gated auto-block** — automated blocking gated on deterministic evidence, with an evidence-linked audit trail for every action.

## Beyond 1.0 — steady state

- **More sources** — pfSense, Zeek, Palo Alto, GCP, and beyond — each a package, zero core edits (hopefuly).
- **Case management at scale** — a case inbox across investigations, with dispositions and filtering, on top of today's per-verdict case files.
- **Scale** — PostgreSQL plus a durable event transport.
- **Trust & hardening** — scheduled model-drift checks and an ongoing security-hardening track ahead of network-exposed, multi-user deployment.

## Exploring / community-driven

Ideas we're interested in, demand-gated and open to contribution:

- **AI-assisted plugin authoring** — paste sample logs, get a drafted `normalize()` plus golden tests.
- **Read-only MCP server** — expose FireWatch's findings to AI assistants, read-only.
- **Richer querying** — source-scope filtering (scope the whole console to a chosen subset of sources), multiple instances of one source type, and deeper geo enrichment (ISP/ASN pivots, VPN/Tor/hosting flags).

## Contribute a source

A new telemetry source is a **new package implementing one contract** — no core
changes, ever. Start with [`PLUGIN_CONTRACT.md`](../PLUGIN_CONTRACT.md) and the
[module-author guide](module-author-guide.md).
