"""ClamAV FOUND-line → SecurityEvent normalization (pure mapping).

``collector.py`` owns turning journald/file-tail text into ``RawEvent``s; this module
owns the single, pure ``raw → SecurityEvent`` mapping (PLUGIN_CONTRACT.md — the plugin
owns its mapping). ``raw.data`` always carries ``{"path": str, "signature": str,
"outcome": "removed" | "moved" | None, "line": str}`` — see ``collector.py`` for how it's
built from ClamAV's ``<path>: <signature> FOUND`` detection line.

Action mapping (ADR-0012 semantics, applied honestly per issue #2's acceptance criteria):
  - Detection only (no companion remove/quarantine outcome observed) → ``ALERT``.
  - A configured remove/quarantine outcome, when present in the log stream for this
    detection → ``BLOCK`` (ClamAV, not FireWatch, performed the enforcement — ``BLOCK``
    here means "an enforcement action happened", matching ADR-0012's WAF/IPS-block
    semantics, not a FireWatch-side action).

Severity (ADR-0067 D4 / ADR-0069, maintainer-ruled): ``FOUND`` → ``high``, always. Malware
present on disk is a genuine assertion — "requires a prompt review" — not ``critical``,
because a signature match alone does not "border certainty" (a healthy machine produces
~zero FOUND events, so this is not an ambient-noise concern).

MITRE ATT&CK / CAPEC (ADR-0014): ADR-0014 extracts technique/tactic from *source-specific
metadata* (Suricata's ET Open ``mitre_*`` tags, OWASP CRS CAPEC tags). A ClamAV signature
name (e.g. "Win.Test.EICAR_HDB-1") carries no such metadata — there is nothing here to
derive a technique/tactic from without fabricating one, so ``attack_technique`` /
``attack_tactic`` / ``kill_chain_phase`` / ``capec_id`` are left unset (``None``), per
PLUGIN_CONTRACT.md's "MITRE/CAPEC … where derivable" and "never fabricate" discipline.

OCSF alignment (ADR-0020, lightweight): a ClamAV FOUND event is a detection finding, not a
network/HTTP/DNS activity record. OCSF 1.8.0 models this as class_uid 2004 "Detection
Finding" under category_uid 2 "Findings" (https://schema.ocsf.io/1.8.0/classes/detection_finding
— the same class ADR-0055's File-IOC group anchors to for file-based findings).
"""
from __future__ import annotations

import posixpath

from firewatch_sdk import ActionLiteral, RawEvent, SecurityEvent

# Constant source_type — this plugin declares "clamav" as its type key.
SOURCE_TYPE: str = "clamav"

# OCSF 1.8.0: category_uid 2 = Findings, class_uid 2004 = Detection Finding.
# https://schema.ocsf.io/1.8.0/classes/detection_finding
_OCSF_CLASS_DETECTION_FINDING = 2004
_OCSF_CATEGORY_FINDINGS = 2


def normalize(raw: RawEvent, source_id: str) -> SecurityEvent:
    """Map a ClamAV FOUND-detection ``RawEvent`` to a ``SecurityEvent``.

    ``source_type`` is always ``"clamav"`` (this plugin's constant). ``source_id`` is the
    caller's instance name, passed through as-is; this function never branches on it
    (Flag B, PLUGIN_CONTRACT.md).
    """
    d = raw.data
    path: str = d.get("path") or ""
    signature: str = d.get("signature") or ""
    outcome: str | None = d.get("outcome")

    action: ActionLiteral = "BLOCK" if outcome is not None else "ALERT"

    # ClamAV has no separate numeric rule ID distinct from the signature name (unlike
    # Suricata's SID vs. msg) — the signature IS the identifier, so rule_id and
    # rule_name are deliberately the same value.
    signature_or_none = signature or None

    return SecurityEvent(
        source_type=SOURCE_TYPE,
        source_id=source_id,
        timestamp=raw.received_at,
        # Host-based detection: malware on THIS machine's disk, not network traffic.
        # No source IP exists to report — left as "" (never fabricated), matching the
        # established fallback convention (firewatch_suricata / firewatch_aws_nfw
        # `d.get("src_ip") or ""`) rather than inventing a loopback/placeholder value.
        source_ip="",
        action=action,
        category="malware",
        severity="high",  # ADR-0067 D4 / ADR-0069 — load-bearing, not cosmetic.
        rule_id=signature_or_none,
        rule_name=signature_or_none,
        payload_snippet=path[:500] if path else None,
        file_name=_basename(path) if path else None,
        ocsf_class=_OCSF_CLASS_DETECTION_FINDING,
        ocsf_category=_OCSF_CATEGORY_FINDINGS,
        raw_log=d,
    )


def _basename(path: str) -> str:
    """Return the file name component of *path*.

    ClamAV always reports POSIX paths (Linux-only source) — ``posixpath`` is used
    explicitly rather than ``pathlib.Path`` so behavior doesn't drift if this ever runs
    on a non-POSIX host.
    """
    return posixpath.basename(path.rstrip("/")) or path
