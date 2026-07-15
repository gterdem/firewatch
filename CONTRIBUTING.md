# Contributing to FireWatch

Thanks for your interest in FireWatch — a modular, self-hosted, local-first
threat-monitoring platform. This guide covers how to propose changes, the quality
gates every change must pass, the modularity rules that keep the platform
pluggable, and the licensing terms your contribution falls under.

Please also read [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) (how we work together)
and [`SECURITY.md`](SECURITY.md) (report vulnerabilities privately — **not** as a
public issue or PR).

## The contribution flow: one issue → one branch → one PR

1. **Start from an issue.** Open or pick a GitHub issue describing the change.
   For anything non-trivial (a new feature, an architectural choice, a new
   source), agree on the approach on the issue first.
2. **One branch per issue.** Branch off `main`; keep the branch scoped to that
   one issue.
3. **One PR per issue.** Open a pull request that closes exactly that issue. Keep
   PRs focused and reviewable; fill in the PR template checklist.
4. **Green gates + review.** All gates below must pass, and changes that touch
   the data plane / AI path get a security review (see below) before merge.

## Build and test — the gates

FireWatch uses [`uv`](https://docs.astral.sh/uv/) for the Python workspace. From
the repo root, "done" means all three of these are green:

```bash
uv run ruff check .     # lint
uv run pyright          # type check
uv run pytest           # tests, including tests/golden
```

For the frontend (`frontend/`):

```bash
npm run lint
npm run typecheck
npm run test
```

Notes:

- `tests/golden` is the **regression oracle** — normalization and AI-prompt
  baselines are byte-pinned. If a change legitimately updates them, rebaseline
  explicitly and call it out in the PR; don't silently overwrite a baseline.
- Run the full suite (`uv run pytest -n auto`) before opening the PR.

## Secret scanning — full history, not a scoped diff

CI's `gitleaks` workflow scans the **entire git history** (`fetch-depth: 0`), matching
what a clone of this public repo exposes. Before opening a PR, run the same check
locally:

```bash
scripts/gitleaks-full.sh
```

This is the exact command CI runs — a clean result here means CI's `gitleaks` job will
be clean too. Two things it is **not** equivalent to, and which have caused false
"looks clean" reports before:

- The committed pre-commit hook (`.githooks/pre-commit`) only scans **staged**
  changes, and doesn't fire in every checkout (e.g. an isolated agent worktree).
- Scoping the scan to your own commits (e.g. `gitleaks git
  --log-opts="origin/main..HEAD"`) misses false positives already baked into
  history by earlier/other commits — CI scans everything, so a scoped local check
  can pass while CI still fails on the same string.

Fixtures must use non-routable/documentation IPs — see the `public-ipv4` rule notes in
`.gitleaks.toml` and the `testing-conventions` skill.

## Security review for data-plane changes

FireWatch ingests **attacker-controlled telemetry** and runs **local-only AI
scoring**. Changes to the data plane — normalization, the AI prompt/scoring path,
or any active-response gating — must keep the containment guarantees intact
(local-only inference, untrusted-data sentinels, the AI can only add a bounded
boost). These changes require a security review before merge. See `SECURITY.md`
for the threat model.

## Modularity and dependency rules (non-negotiable)

FireWatch's core value is that **telemetry sources are plugins against a single
contract**. Keep it that way:

- **A new source = a new package** under `packages/sources/`, implementing the
  `SourcePlugin` contract and registered via entry points. Adding a source must
  require **zero edits to `firewatch-core`**.
- **The dependency rule.** Plugins and core both depend on `firewatch-sdk`.
  **Core never imports a plugin. Plugins never import core.**

The contract is owned by [`PLUGIN_CONTRACT.md`](PLUGIN_CONTRACT.md); the design by
[`ARCHITECTURE.md`](ARCHITECTURE.md); settled decisions live in
[`docs/adr/`](docs/adr/). Defer to those, in that order.

## Coding standards

- Keep changes small and focused — touch only what the issue needs.
- Prefer focused modules over monoliths (target ≤ ~500 lines per file, one class
  ≈ one concern).
- Find root causes; no temporary patches.

## Sign your work — Developer Certificate of Origin (DCO)

FireWatch uses the [Developer Certificate of Origin](DCO) (DCO 1.1) — a
lightweight sign-off, **not** a CLA. By signing off you certify that you wrote
the contribution (or have the right to submit it) under the project's license.

Add a `Signed-off-by` line to every commit:

```
Signed-off-by: Your Name <your.email@example.com>
```

The easiest way is `git commit -s` (use your real name and a reachable email).
The full text is in the [`DCO`](DCO) file at the repo root.

## Licensing of contributions

FireWatch is licensed under the **GNU Affero General Public License v3.0
(AGPL-3.0-only)** — see [`LICENSE`](LICENSE) and the rationale in
[ADR-0056](docs/adr/0056-licensing-agpl-3.0.md). **By contributing, you agree
that your contribution is licensed under AGPL-3.0-only**, the same terms as the
rest of the project. There is no separate copyright assignment; you keep
copyright in your work and license it under AGPL-3.0 (certified via the DCO
sign-off above).
