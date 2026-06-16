# ADR-018: Product Positioning — Integrated Open-Source AI SOC Platform

**Date:** April 2026
**Status:** Accepted

**Decision:** Position FireWatch as the integrated open-source AI SOC platform — combining SIEM (multi-source ingestion, MITRE-mapped detection), AI investigation (local LLM), and tunable response (per ADR-015) in one tool. Not "yet another SIEM."

**Market context:** Commercial AI SOC platforms (CrowdStrike Falcon Next-Gen SIEM, Cortex XSIAM, Stellar Cyber, Anvilogic) integrate detection + investigation + response in one product. They are priced from $10,000 to $500,000+ per year. The open-source equivalent today is three separate products wired together — Wazuh (SIEM) + Shuffle (SOAR) + TheHive (case management) — each with its own deployment, configuration, and learning curve. There is currently no open-source product that ships all three in one tool with native AI investigation.

**Alternatives considered:**
- Position as "open-source Splunk alternative" — rejected. Splunk is a log analytics platform; FireWatch is opinionated for security. The comparison undersells the AI/integration angle.
- Position as "open-source Wazuh alternative" — rejected. Wazuh is bigger in scope (XDR, agents, FIM). FireWatch is narrower and doesn't compete on agent-based endpoint coverage.
- Position as "AI-native SIEM" only — rejected. Underplays the integrated response capability that's actually a differentiator.

**Reasoning:** The positioning shapes everything downstream — the README, the landing page, the feature roadmap, the conference talk, the resume bullet point. "Integrated open-source AI SOC platform" is specific, defensible, and currently unoccupied in the open-source space. It also aligns naturally with the open-core monetization path: free tier gets the integrated SIEM+investigation+suggest-mode response; paid tier gets pre-built integrations (Azure NSG, AWS WAF, Cloudflare auto-block adapters), multi-tenant, SSO, and the conditional-auto tier with vendor-managed safety profiles.

**Implication for naming/messaging:** When describing FireWatch, lead with "integrated" and "open-source." Examples:
- README first line: "An integrated open-source AI SOC platform — detection, AI investigation, and tunable response in one tool. Local-first."
- Comparison table on the landing page: FireWatch vs. Wazuh+Shuffle+TheHive (three tools, no AI) vs. Cortex XSIAM (one tool, $$$, cloud-only).
