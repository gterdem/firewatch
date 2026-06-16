# ADR-005: Suricata Collector — SSH Pull

**Date:** April 2026
**Status:** Accepted

**Decision:** Pull Suricata logs via SSH (`asyncssh`), not push via agent or syslog.

**Alternatives considered:**
- Syslog push — rejected because workstation is behind NAT (VM can't push to you)
- Agent on remote host — rejected because it requires installing software on the source
- Persistent SSH tail — rejected as too complex (reconnection, file rotation handling)

**Reasoning:** SSH is already open and authenticated. No agent needed. asyncssh reads `~/.ssh/config` natively. Pull-based sync with watermarks fits the existing PullCollector pattern.

---

## Update — 2026-06-03: SSH host-key verification (PR #14 security review)

This amends the Decision and Consequences without reopening the core "SSH pull"
choice above (still Accepted). It records how the SSH transport authenticates the
remote sensor's identity, a question surfaced by the PR #14 security review.

**Decision (host-key verification):** The Suricata pull transport verifies the
remote host key **by default**. There is a single, explicit, config-gated opt-out.

- **Default (secure):** host-key verification is ON. asyncssh validates the remote
  host key against the system `known_hosts`. If the host key is unknown or has
  changed, the connection **fails closed** — no logs are pulled. This is the
  expected SSH client behavior and the only configuration that defends against an
  active man-in-the-middle on the sensor link.
- **Opt-out (explicit):** a `verify_host_key: bool = True` field on the plugin
  config. Setting it to `false` disables verification (asyncssh `known_hosts=None`)
  and emits a runtime **warning** on every connection. It is:
  - **config-surfaced** — it appears in the UI/JSON-Schema config for the plugin,
    so an operator must deliberately set it; it is *never* an environment-variable
    default and *never* silent.
  - **scoped** — intended ONLY for ephemeral / frequently-rebuilt home-lab or
    cloud sensors whose host key legitimately rotates (e.g. a VM reimaged on each
    boot), where pinning a key in `known_hosts` would otherwise force the
    connection to fail closed on every rebuild.

**Security rationale:**
- **Secure-by-default.** Verification ON is the secure default; the operator must
  take an explicit, visible action to weaken it. This follows the NIST SP 800-160v1
  / SP 800-53 secure-defaults and least-functionality posture and OWASP's
  "secure defaults" / fail-securely design principles.
- **MITM risk of the opt-out.** `known_hosts=None` accepts *any* host key, which
  removes the only server-authentication guarantee SSH provides at connect time
  and exposes the link to a man-in-the-middle who can impersonate the sensor and
  feed forged or withheld telemetry. RFC 4251 §3 and §9.3.4 are explicit that the
  client MUST check the server host key and that failing to do so leaves the
  protocol open to MITM; the host-key trust model is described in RFC 4251 §4.1,
  and RFC 4252 (§9, host-based authentication) likewise assumes a verified host
  identity. Disabling verification is therefore a *documented, justified deviation
  from the RFC-expected default* for a constrained operational case — not an
  oversight. The deviation is bounded (single boolean, single source type, loud
  warning) and reversible.

**Consequences:**
- The default path requires the operator to have the sensor's key in `known_hosts`
  (or `~/.ssh/known_hosts` reachable to the process) before first pull; a key
  change after a legitimate sensor rebuild surfaces as a fail-closed error, which
  is the intended, auditable signal.
- Choosing the opt-out trades MITM protection for not having to manage rotating
  keys; the per-connection warning keeps that trade visible in the logs.

**Standards cited:**
- RFC 4251 (SSH Protocol Architecture) §3 (security model), §4.1 (host keys /
  trust model), §9.3.4 (man-in-the-middle).
- RFC 4252 (SSH Authentication Protocol) §9 (host-based authentication assumes a
  verified host identity).
- NIST SP 800-53 / SP 800-160v1 — secure defaults, least functionality.
- OWASP secure-design principles — "secure defaults" and "fail securely".
