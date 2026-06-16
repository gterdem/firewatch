"""Severity derivation for the Azure WAF plugin.

Two complementary signals (azure-waf-log-standard.md §2d):
  1. Primary: CRS category (from the static table in crs.py).
  2. Refinement: anomaly score in the event message.

Always returns a ``SeverityLiteral`` — never ``None``.

Severity mapping follows OCSF severity_id alignment (ADR-0020):
  info=1, low=2, medium=3, high=4, critical=5

CRS inbound anomaly threshold default is 5; scores >= threshold are
escalated.  Very high scores (>= 30) are escalated to critical.
Source: https://coreruleset.org/docs/2-how-crs-works/2-1-paranoia-levels/#anomaly-scoring
"""
from __future__ import annotations

import re

from firewatch_sdk.models import SeverityLiteral

# ---------------------------------------------------------------------------
# Category → base severity
# ---------------------------------------------------------------------------

# Map category string (from crs.CRSEntry.category) → SeverityLiteral.
# Covers every category the CRS table emits; no "Other" fall-through needed
# because crs.lookup never returns an "Other" entry.
_CATEGORY_SEVERITY: dict[str, SeverityLiteral] = {
    "Scanner / Recon Detection":    "low",
    "Protocol Enforcement":         "low",
    "Protocol Attack":              "medium",
    "Local File Inclusion":         "high",
    "Remote File Inclusion":        "high",
    "Remote Code Execution":        "critical",
    "PHP Injection":                "high",
    "Cross-Site Scripting (XSS)":   "high",
    "SQL Injection":                "high",
    "Session Fixation":             "medium",
    "Java / Log4j Exploit":         "critical",
    "Anomaly Score Threshold":      "medium",  # refined by anomaly score below
    # Azure custom rule categories
    "Rate Limit":                   "low",
    "Geo Block":                    "low",
    "IP Reputation":                "medium",
    "Bot Detection":                "low",
}

# Default when category is unrecognized (should not happen with full CRS coverage,
# but guards against unexpected future categories).
_DEFAULT_SEVERITY: SeverityLiteral = "medium"

# ---------------------------------------------------------------------------
# Anomaly score thresholds (CRS defaults)
# ---------------------------------------------------------------------------

_ANOMALY_THRESHOLD_HIGH: int = 5     # CRS default inbound threshold — treat as high
_ANOMALY_THRESHOLD_CRITICAL: int = 30  # large score → critical


def _parse_anomaly_score(message: str | None) -> int | None:
    """Extract the anomaly score integer from a CRS anomaly message, or None.

    Patterns observed (from MS Learn / CRS docs):
      - "Inbound Anomaly Score Exceeded (Total Score: 15)"
      - "Anomaly Score Exceeded (Score: 7)"
    Returns the integer score, or None if the message does not carry one.
    """
    if not message:
        return None
    # Match "Total Score: N" or "Score: N"
    m = re.search(r"(?:Total\s+)?Score:\s*(\d+)", message[:1024], re.IGNORECASE)
    if m:
        return int(m.group(1))
    return None


def severity_from_category(
    category: str | None,
    message: str | None = None,
) -> SeverityLiteral:
    """Return a ``SeverityLiteral`` for an Azure WAF event.

    Args:
        category: The CRS category string derived from ``crs.lookup()``.
                  May be None for unmapped events (yields _DEFAULT_SEVERITY).
        message:  The raw event message; may carry an anomaly score for refinement.

    Returns:
        A ``SeverityLiteral`` — never ``None``.

    Severity derivation (azure-waf-log-standard.md §2d):
      1. Derive base severity from the category table.
      2. If an anomaly score is present in the message, escalate:
         - score >= _ANOMALY_THRESHOLD_CRITICAL → "critical"
         - score >= _ANOMALY_THRESHOLD_HIGH     → "high" (if currently < high)
    """
    base: SeverityLiteral = _CATEGORY_SEVERITY.get(category or "", _DEFAULT_SEVERITY)

    # Anomaly-score refinement
    score = _parse_anomaly_score(message)
    if score is not None:
        if score >= _ANOMALY_THRESHOLD_CRITICAL:
            return "critical"
        if score >= _ANOMALY_THRESHOLD_HIGH:
            # Escalate to high, but never downgrade something already higher
            if base in ("info", "low", "medium"):
                return "high"

    return base
