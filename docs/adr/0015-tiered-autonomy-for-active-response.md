# ADR-015: Tiered Autonomy for Active Response

**Date:** April 2026
**Status:** Accepted (with Future Reconsideration)

**Decision:** FireWatch will support active response (blocking IPs, generating blocklists, integrating with upstream firewalls) through a tiered autonomy model. Three tiers will be implemented; a fourth (full autonomy) is explicitly deferred for future reconsideration but not permanently rejected.

**Tiers:**

| Tier | Behavior | Default |
|------|----------|---------|
| Suggest | AI recommends "Block this IP", user clicks to apply | All users |
| One-click approve | Notification with "Approve / Deny" — human gates each action | Opt-in |
| Conditional auto | Auto-block ONLY if: AI confidence > 0.95 AND IP not in allowlist AND under N blocks/hour AND TTL ≤ 1h AND target not in protected-asset list | Opt-in, advanced |
| Full autonomy | — | **Deferred** |

**Alternatives considered:**
- Ship full autonomy with a setting toggle — rejected for current version. CrowdStrike's 2026 Global Threat Report documented adversaries compromising AI tools at 90+ organizations in 2025, with the next wave shipping with write access to firewalls. The Saviynt/Cybersecurity Insiders 2026 CISO survey found 47% of CISOs had observed AI agents exhibiting unintended behavior, and only 5% felt confident they could contain a compromised one. OWASP's Agentic AI Top 10 (Dec 2025) lists Agent Goal Hijacking, Tool Misuse, and Identity/Privilege Abuse as top risks. FireWatch's specific exposure: WAF/IDS logs literally contain attacker payloads, making prompt injection a realistic threat against the LLM that would issue block decisions.
- Suggest-only forever — rejected because "Conditional auto" with strict guardrails is a real productivity gain for daily use (auto-block obvious scanners while user is away from keyboard) and is differentiated from competitors who either skip auto-action or do it without guardrails.
- Permanently reject full autonomy — rejected because the threat landscape and AI safety techniques are evolving fast. A future combination of confidence calibration improvements, sandboxed agent execution, and external policy enforcement may make full autonomy responsibly shippable.

**Reasoning:** The 2026 industry consensus is that autonomous AI action without guardrails is unacceptably risky, but suggest-only leaves real value on the table. The tiered model captures the benefits while keeping safe defaults. Conditional auto is also a marketable differentiator: "tunable autonomy with safe defaults" positions FireWatch as the responsible alternative to "trust the AI" platforms.

**Future reconsideration triggers:** Reopen this ADR if any of the following becomes true:
- LLM confidence calibration matures to the point where a 95%+ confidence score correlates reliably with correctness
- Sandboxed agent execution patterns become standard (e.g., MCP-style policy enforcement layers)
- A specific customer use case justifies the risk and is willing to accept the liability
- A safer architectural pattern emerges (e.g., AI proposes, second independent model validates, only then auto-acts)
