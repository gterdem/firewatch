# ADR-021: Suricata Ingestion — Standard Log-Shipper Push Path Alongside SSH Pull

**Date:** June 2026
**Status:** Accepted (complements ADR-0005; does not supersede it)

**Decision:** Keep the Suricata **SSH-pull** collector (ADR-0005) as the zero-install convenience
for homelab / single-host use, **and** add the industry-standard ingestion path: a log shipper —
**Filebeat (Suricata module), Fluent Bit, or Vector** — tails `eve.json` and forwards it to a
FireWatch **PushSource** (a generic EVE-over-HTTP / JSON-lines listener, or the existing syslog
listener carrying JSON). Document shipper → PushSource as the **recommended** path for
production and multi-host deployments; SSH-pull stays as the easy on-ramp.

**Alternatives considered:**
- **SSH-pull only (status quo)** — rejected as the *only* path: `grep`-over-SSH polling is
  non-standard, doesn't scale across many hosts, and couples ingestion to SSH availability.
- **Require a message bus (Kafka/Redis) in front** — rejected for now: too heavy for the target
  user; Kafka is the high-throughput gold standard and can be an optional downstream later, but
  it should not be mandatory.
- **Ship a FireWatch-specific agent** — rejected: reintroduces the agent-install burden ADR-0005
  deliberately avoided; the standard shippers already exist and are well-maintained.

**Reasoning:** The standard way to move Suricata `eve.json` is a log shipper (Filebeat has a
first-party Suricata module; Fluent Bit and Vector are the 2026 defaults), optionally via a bus.
FireWatch already has a **PushSource** flavor (used by Syslog), so the standard path is a natural
fit rather than new architecture. Offering it keeps FireWatch interoperable with existing SOC
pipelines and lets the community use the normal path. Sources:
[Filebeat Suricata module](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-module-suricata),
[2026 log-collector landscape (Fluent Bit/Vector)](https://victoriametrics.com/blog/log-collectors-benchmark-2026/).

**Consequences:**
- Add a generic EVE-over-push source (HTTP JSON-lines, or reuse the syslog listener) as a
  PushSource, reusing the same Suricata `normalize()`.
- README/docs gain a "recommended: ship eve.json via Filebeat/Fluent Bit/Vector" section.
- No change to the existing SSH-pull collector; this is additive. Out of scope for M1 (Suricata
  PullSource ships first); this is an M2+ ingestion option.
