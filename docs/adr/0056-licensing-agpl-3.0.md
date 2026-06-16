# ADR-0056: License FireWatch under AGPL-3.0 (supersedes ADR-0013)

**Date:** 2026-06-14
**Status:** Accepted

**Supersedes:** ADR-0013 (Open-Core Licensing). **Relates to:** ADR-0018 (Product
Positioning — Integrated Open-Source AI SOC Platform), the pre-launch checklist
(`docs/pre-release-checklist.md`), and `docs/ROADMAP.md` Phase 3 (licensing + community files).

---

## Context

ADR-0013 (Proposed, April 2026) framed FireWatch as **open-core**: a free rule-based tier and a
paid "Pro" tier gating AI analysis, NL search, correlation, detection rules, and PostgreSQL. That
ADR encoded a **monetization** model — AI as the paywall line.

The project's goal has since changed and is now explicit: FireWatch exists for **career/reputation
and personal use, NOT monetization.** There is no plan to sell a Pro tier, run a hosted SaaS, or
build a licensing business. Open-core only makes sense when someone is monetizing the closed half;
with no monetization, the open-core split is pure cost — it splinters the codebase, forces a
free/paid feature boundary through the product's core value (AI), and weakens the "genuinely open"
story that ADR-0018 stakes the positioning on.

We must therefore pick a license deliberately, before the repo goes public, because **a license
choice is effectively irreversible once code is published** (every prior contributor/consumer holds
rights under the published terms; relicensing requires consent or a rewrite).

## Decision

1. **License FireWatch under the GNU Affero General Public License, version 3.0 (AGPL-3.0).**
   One license for the whole repository (core, SDK, first-party source plugins, frontend).
2. **Version `0.x` until the plugin contract is proven**, then cut **1.0.0** with an explicit
   **contract-stability policy** (semantic versioning of `firewatch-sdk` / `PLUGIN_CONTRACT.md`;
   breaking the plugin contract requires a major bump and an ADR). v0.x signals "API/contract may
   still move"; 1.0.0 signals "the contract is a promise." The contract-proof source builds
   (#603 → #604 → #605 → #606) are what graduate us from 0.x toward 1.0.
3. **Reject open-core / source-available (BSL, SSPL) and permissive (MIT/Apache-2.0).**

## Rationale

- **AGPL is the de-facto norm for open security *platforms*.** The peer set FireWatch positions
  against (ADR-0018) ships AGPL-3.0: **Grafana**, **TheHive**, **MISP** (AGPL-3.0), **Velociraptor**
  (AGPL-3.0), **Wazuh** (GPL-family). Matching the community's expected license lowers adoption
  friction and signals "this is a real open platform," which directly serves the career/reputation
  goal.
- **AGPL is OSI-approved "Open Source."** It keeps full OSI open-source credibility — unlike
  source-available licenses (BSL, SSPL), which the OSI does **not** recognize as open source. For a
  reputation/career artifact, keeping the genuine "open source" label matters.
- **Network copyleft fits a server/SaaS-shaped product.** FireWatch is a long-running networked
  service (a SOC dashboard + API). Plain GPL-3.0's copyleft is not triggered by "use over a network"
  (the ASP/SaaS loophole); **AGPL-3.0 §13 closes it** — anyone who runs a modified FireWatch as a
  network service must offer their modified source to users. This **prevents a closed commercial fork
  or hosted SaaS from privatizing improvements** without a licensing-business relationship — exactly
  the protection a non-monetizing author wants (contributions flow back; no one out-competes the
  origin with a proprietary derivative).
- **Permissive (MIT/Apache-2.0) was considered and rejected** *for this goal*: permissive maximizes
  reuse but lets a vendor wrap FireWatch into a closed product and give nothing back. Acceptable if
  the goal were maximum ecosystem spread; not aligned with "keep the platform open and improvements
  shared."

## Cautionary tales (why BSL/SSPL were rejected)

The 2018–2024 "source-available" wave — **MongoDB → SSPL**, **Elastic → SSPL/Elastic License**,
**HashiCorp (Terraform) → BSL**, **Redis → RSALv2/SSPL** — was each a *monetization-defense* move by
a VC-backed company against cloud hyperscalers. Each triggered: loss of the OSI "open source" label,
community **forks** (OpenSearch from Elasticsearch, OpenTofu from Terraform, Valkey from Redis), and
real reputational/community backlash. FireWatch has **no monetization to defend**, so it inherits all
the cost of source-available (lost open-source credibility, community distrust, fork risk) and none
of the benefit. AGPL gives the network-copyleft protection these projects wanted **while staying OSI
open source** — the right tool when the goal is reputation, not revenue.

## Alternatives considered

- **Keep ADR-0013 open-core (free + paid Pro tier)** — *rejected.* It is a monetization model; there
  is no monetization. Splits the codebase and paywalls the core AI value for no benefit.
- **MIT / Apache-2.0 (permissive)** — *rejected* for this goal. Allows closed forks that give nothing
  back; weakens the "shared open platform" intent. (Apache-2.0 remains worth a second look *only* for
  `firewatch-sdk` if SDK adoption friction proves real — see Open question.)
- **GPL-3.0 (non-network copyleft)** — *rejected.* Leaves the SaaS/network loophole open; for a
  networked service, AGPL-3.0 is the matched-strength choice and the security-platform norm.
- **BSL / SSPL (source-available)** — *rejected.* Not OSI open source; carries the documented
  backlash/fork risk above with zero monetization upside here.

## Companion-file checklist (pre-launch — Phase 3, before the repo goes public)

These are net-new (none exist in the repo today) and are tracked in `docs/ROADMAP.md` Phase 3:

- [ ] **`LICENSE`** — the full, verbatim AGPL-3.0 text (unmodified), at repo root.
- [ ] **Per-package license metadata** — set `license = "AGPL-3.0-only"` (SPDX) and the OSI license
  classifier in each `packages/*/pyproject.toml` and the frontend `package.json`.
- [ ] **`SECURITY.md`** — coordinated vulnerability-disclosure policy (contact, supported versions,
  embargo expectation). Security-community table stakes.
- [ ] **`CONTRIBUTING.md`** — how to build/test/PR, the gates, and the contribution license terms.
- [ ] **DCO (Developer Certificate of Origin)** — lightweight `Signed-off-by` sign-off (the
  security-community/kernel norm), **not** a heavyweight CLA. Add a `DCO` file + note in
  `CONTRIBUTING.md`; optionally a DCO check in CI.
- [ ] **`NOTICE`** — only if required to attribute bundled third-party assets (e.g. the
  ADR-0039 DB-IP Lite geo data, the ADR-0052 Natural Earth basemap, any vendored fonts/icons).
  Audit redistributed assets for attribution obligations before launch.
- [ ] **Per-file SPDX headers** — optional but recommended: `SPDX-License-Identifier: AGPL-3.0-only`.

## Caveat — get a final IP-lawyer review before going public

This ADR is an engineering/strategy decision, not legal advice. Because the license choice is
**near-irreversible once the repo is public**, a qualified IP/open-source lawyer should review the
final license + companion files (especially the DCO/contribution terms, any bundled-asset NOTICE
obligations, and AGPL §13's network-service implications) **before** the first public push. This
review is a Phase-3 gate.

## Consequences

- **ADR-0013 is marked `Superseded by ADR-0056`** in its header and in the ADR index; its open-core
  free/paid split is withdrawn. There is no "Pro tier."
- ADR-0018's "open-source AI SOC platform" positioning is reinforced — the license now matches the
  claim (genuinely OSI open source, AGPL like its peers).
- Downstream redistributors/SaaS operators of FireWatch are bound by AGPL-3.0 §13 (offer modified
  source to network users). This is intended.
- The companion files above become pre-launch blockers (ROADMAP Phase 3).

## Open question (surfaced, not blocking)

- **SDK relicensing escape hatch?** If `firewatch-sdk` adoption proves blocked by AGPL (e.g. a
  closed-source shop wants to write a private source plugin and AGPL deters them), a *future* ADR
  could consider a more permissive license **for the SDK only** (Apache-2.0/LGPL), keeping the core
  AGPL. Not decided now — flagged so we recognize the lever if SDK-adoption friction shows up.

## References

- **AGPL-3.0 full text** — https://www.gnu.org/licenses/agpl-3.0.en.html
- **OSI license list (AGPL-3.0 is OSI-approved; SSPL is not)** — https://opensource.org/licenses/
  and https://opensource.org/blog/the-sspl-is-not-an-open-source-license
- **AGPL-3.0 §13 (network/remote-interaction copyleft)** — the SaaS-loophole closure relative to GPL-3.0.
- **SPDX identifier `AGPL-3.0-only`** — https://spdx.org/licenses/AGPL-3.0-only.html
- **Developer Certificate of Origin (DCO) 1.1** — https://developercertificate.org/
- **Peer security-platform licenses:** Grafana, TheHive, MISP, Velociraptor, Wazuh — AGPL/GPL-family
  (back the "norm for security platforms" claim).
- **Source-available cautionary tales:** MongoDB SSPL; Elastic SSPL/Elastic-License → OpenSearch fork;
  HashiCorp BSL → OpenTofu fork; Redis RSALv2/SSPL → Valkey fork.
- **Internal:** ADR-0013 (superseded), ADR-0018 (positioning), `docs/ROADMAP.md` Phase 3,
  `docs/pre-release-checklist.md`.
