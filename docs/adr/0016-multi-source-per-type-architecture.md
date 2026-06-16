# ADR-016: Multi-Source-Per-Type Architecture

**Date:** April 2026
**Status:** Accepted

**Decision:** Lift the current "one source per type" assumption. Each event will carry both `source_type` (azure_waf, suricata, syslog) and `source_id` (a user-provided name like "pi-home" or "azure-juiceshop-lab"). Settings and config support N named sources per type. Filters and dashboards work across sources or per-source.

**Alternatives considered:**
- Multiple FireWatch instances, one per environment — rejected for solo operators because of duplicate maintenance, no cross-environment correlation, and aggregation complexity
- Multi-instance with central aggregator — rejected as enterprise-only, "you're back to building Splunk"
- Continue with one-source-per-type and add it later — rejected because the current schema's `source` column is the foundation and changing it later means a data migration

**Reasoning:** Maintainer's actual usage is multi-environment from day one (Pi home network + Azure Juice Shop labs + AWS labs + GCP labs + future production). The same attacker hitting two environments should appear as one threat, not two. The `source_id` field is also the foundation for the SMB use case (monitor multiple branch offices, multiple cloud accounts, one home server — one FireWatch). Costs almost nothing now if done before the frontend rewrite; expensive to retrofit later.

**Schema change:** Add `source_id TEXT` column to `logs` table. Default existing rows to `'default'`. Update unique dedup index to include source_id.
