# ADR-013: Open Core Licensing

**Date:** April 2026
**Status:** Superseded by ADR-0056

> **Superseded (2026-06-14).** This open-core decision was a **monetization** model (free
> rule-based tier + paid AI "Pro" tier). FireWatch's goal is now **career/reputation and personal
> use, not monetization**, so the open-core split has no payoff and only costs (splits the codebase,
> paywalls the core AI value). **ADR-0056 replaces it with a single AGPL-3.0 license for the whole
> project.** There is no "Pro tier." Do not act on the decision below — see ADR-0056.

**Decision (withdrawn):** Free tier: unlimited sources/logs, rule-based scoring. Pro tier: AI analysis, NL search, correlation, detection rules, PostgreSQL.

**Reasoning (historical):** AI is the natural dividing line — it requires GPU hardware and is the unique differentiator. The free tier must be genuinely useful, not crippled.
