# Security Policy

FireWatch is a threat-monitoring platform; we take the security of the project —
and of the deployments that run it — seriously. Thank you for helping keep it and
its users safe.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.** Public issues
are visible to everyone and would disclose the problem before a fix is available.

Report privately through one of these channels:

1. **GitHub private security advisories (preferred).** On the repository, go to
   the **Security** tab → **Report a vulnerability**. This opens a private
   advisory visible only to you and the maintainers.
2. **Email.** galiperdem@gmail.com

Please include, where you can:

- A description of the issue and its impact.
- The affected component (core, SDK, a specific source plugin, the API, or the
  frontend) and version / commit.
- Steps to reproduce, a proof of concept, or a failing test.
- Any suggested remediation.

## Coordinated disclosure and timeline

We follow coordinated (responsible) disclosure:

- **Acknowledgement:** we aim to acknowledge a valid report within **3 business
  days**.
- **Assessment:** we will confirm the issue and assess severity, and keep you
  updated on progress.
- **Embargo:** please keep the report private until a fix is released and an
  advisory is published. We aim to resolve confirmed vulnerabilities within
  **90 days**; we will coordinate the disclosure date with you and credit you in
  the advisory unless you prefer to remain anonymous.

## Supported versions

FireWatch is pre-1.0 (`0.x`); the plugin contract may still move (see
[ADR-0056](docs/adr/0056-licensing-agpl-3.0.md)). Until 1.0, security fixes land
on the latest `0.x` line / `main`. Once 1.0 is cut, this table will name the
supported release lines.

| Version | Supported          |
| ------- | ------------------ |
| `0.x` (latest `main`) | :white_check_mark: |
| older `0.x` tags      | :x:                |

## Scope and threat model

FireWatch is **local-first and zero-egress by design**: telemetry and AI
inference stay on hardware the operator controls. Inference targets a local
OpenAI-compatible endpoint, and the adapter refuses non-loopback / non-private
hosts (see [ADR-0022](docs/adr/0022-local-inference-openai-compatible-endpoint.md)
and [docs/air-gapped-mode.md](docs/air-gapped-mode.md)). A break in that boundary
— a path that causes log data to leave the operator's network — is in scope.

Because FireWatch ingests **attacker-controlled telemetry**, the following
data-plane concerns are explicitly **in scope** for reports:

- **Prompt injection / AI containment.** Attacker-controlled log content reaches
  the AI prompt. The design contains this (untrusted data is wrapped in
  sentinels; the model can only add a bounded score boost and cannot lower a
  score, invent score fields, or inject numbers). A way to defeat that
  containment — to make attacker text suppress a score, exfiltrate data, or
  escape the untrusted-data wrapping — is a security issue.
- **Active-response / action gating.** Any path that lets attacker-influenced
  input trigger an automated response, or that bypasses the gating around
  active-response actions, is in scope.
- **Egress / zero-egress bypass.** Any way to make FireWatch send log data or
  inference to a non-local host contrary to its local-only guarantees.

Out of scope: vulnerabilities in third-party dependencies (report those upstream;
tell us if FireWatch's usage is exploitable), and findings that require an
already-compromised host or operator-level access the threat model assumes is
trusted.
