# ADR-012: IDS Action Mapping — ALERT Badge

**Date:** April 2026
**Status:** Accepted

**Decision:** Suricata IDS alerts display as orange "ALERT" badge. WAF blocks display as red "BLOCK". No rewriting IDS actions to BLOCK.

**Reasoning:** Suricata in IDS mode detects but does not block. Showing "BLOCK" for IDS events was misleading. "ALERT" honestly represents "detected but not stopped."
