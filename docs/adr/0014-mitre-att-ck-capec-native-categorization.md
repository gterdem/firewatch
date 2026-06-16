# ADR-014: MITRE ATT&CK + CAPEC Native Categorization

**Date:** April 2026
**Status:** Accepted

**Decision:** Extract and store MITRE ATT&CK technique/tactic IDs and CAPEC pattern IDs as first-class columns in the `logs` table, populated at normalize-time from source-specific metadata.

**Alternatives considered:**
- Keep free-text `category` only — rejected as inconsistent across sources, not searchable as structured data, no kill chain view possible
- Add ATT&CK as a separate enrichment table joined at query time — rejected as added complexity for a small write-once value
- Wait for users to ask for it — rejected because it changes the schema; better done before frontend rewrite than after

**Reasoning:** Suricata's ET Open ruleset already includes `mitre_technique_id` and `mitre_technique_name` metadata in alert events. OWASP CRS (which Azure WAF is built on) uses CAPEC tags — also a MITRE project. Both can be extracted at normalize-time with no new dependencies. ATT&CK coverage is the #1 evaluation criterion for modern AI SOC platforms (per Underdefense's 2026 vendor comparison: 25% weighting). For FireWatch this unlocks: unified vocabulary across all sources, ATT&CK matrix dashboard view, kill-chain progression analysis, better LLM prompts (the AI can reason about tactics, not just rule names), and a real career/positioning differentiator.

**New schema columns:**
- `attack_technique` — e.g., `T1190`
- `attack_tactic` — e.g., `TA0001`
- `kill_chain_phase` — derived from tactic
- `capec_id` — for WAF rules where applicable

**Implementation order:** Before frontend rewrite. The frontend should be designed against the enriched schema.
