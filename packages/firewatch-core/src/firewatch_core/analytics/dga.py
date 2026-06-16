"""DGA (Domain Generation Algorithm) detection — ML-12, issue #440.

Detects algorithmically-generated domain names used by malware for C2 beaconing.
This module is **zero-egress**: no DNS lookups, no external reputation services.
All scoring is purely local, deterministic, and operates on the domain string alone.

Heuristic basis
---------------
The following well-cited signals are combined into a weighted composite score.
Each signal is normalized to [0.0, 1.0] before weighting.

1. **Shannon entropy** (Plohmann et al., 2016 "A Comprehensive Measurement
   Study of Domain Generating Malware", USENIX Security):
   High entropy in the leftmost label (the randomized part) is a strong DGA
   indicator.  Benign domains tend toward pronounceable, lower-entropy strings.
   Theoretical max for lowercase alpha: log2(26) ≈ 4.70 bits/char.

2. **Consonant cluster ratio** (Schiavoni et al., 2014 "Phoenix: DGA-based
   Botnet Tracking and Intelligence", DIMVA):
   DGA labels are typically unpronounceable — they lack vowel-consonant
   alternation.  The ratio of non-vowel alpha chars to total alpha chars in
   the longest label is computed.  English text: ~55% consonants; DGA labels
   often exceed 75%.

3. **Digit ratio** (inspired by Biau et al., 2011):
   Hash-derived DGA domains often include digit-hex characters.  Ratio of
   digit chars to total chars in the longest label.

4. **Label length** (Antonakakis et al., 2012 "From Throw-Away Traffic to
   Bots: Detecting the Rise of DGA-Based Malware", USENIX Security):
   The randomized label is typically long (15–40 chars).  Labels < 6 chars or
   > 50 chars are filtered as not typical DGA (extremely short = legit; very
   long = CDN CName hash, not classical DGA).  Length signal is raised when
   the label length falls in the 12–32 range typical of hash/PRNG outputs.

5. **Unique-character ratio** (novel):
   DGA strings rarely repeat characters (high character diversity).
   Ratio of distinct chars to label length.

Scoring: each sub-score is weighted and clamped to [0.0, 1.0].  The final
score is the weighted average.  FLAG_THRESHOLD is calibrated so that the
well-known DGA fixtures (consonant-heavy, high-entropy, digit-interspersed)
score above it and known benign domains (English word + TLD patterns) score
below it.

Zero-egress guarantee
---------------------
No DNS queries, HTTP calls, or file I/O are performed.  The scorer is a
pure function over a domain string — safe to call in hot-path event
normalization.

Imports only stdlib and firewatch-sdk; never firewatch-core internal stores
directly (the store-level aggregation function ``get_dga_suspects`` receives
a store instance injected by the caller, not imported here as a singleton).
"""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    # Avoid a hard runtime import; accepts any EventStore-conforming object
    # that exposes ``_read_conn``.
    from firewatch_core.adapters.sqlite_store import SQLiteEventStore

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

#: Composite DGA score at or above which a domain is flagged as "possible DGA".
#: Calibrated against the heuristic fixture sets in test_dga.py.
#: Threshold 0.60 gives > 0.17 gap: benign max ≈ 0.54 ("cloudflare"),
#: DGA min ≈ 0.72 ("2f4a8b1c9d3e7f.xyz" hex-pattern).
#: Provenance: RULE (deterministic, no AI).
FLAG_THRESHOLD: float = 0.60

#: Default number of suspect rows returned by get_dga_suspects.
DEFAULT_TOP_N: int = 50

#: Hard ceiling on top_n for get_dga_suspects (mirrors ML-3/ML-8 le-cap pattern).
MAX_TOP_N: int = 1000

# ---------------------------------------------------------------------------
# Heuristic weights — must sum to 1.0
# ---------------------------------------------------------------------------

#
# Calibration note:
#   Consonant ratio is the strongest DGA discriminator: real DGA generators
#   (Conficker, DGA.Mirai, etc.) produce labels with 90-100% consonants, while
#   brand names like "microsoft" peak at ~67% and "cloudflare" at ~60%.
#   The no-vowel bonus (_W_NOVOWEL) captures the extreme case (cons_ratio >= 0.90)
#   with a binary boost, cleanly separating the two populations.
#   Threshold 0.60 gives a > 0.17 gap: benign max ~0.54 ("cloudflare"),
#   DGA min ~0.72 ("2f4a8b1c9d3e7f" hex-pattern domain).
_W_ENTROPY: float = 0.30       # Shannon entropy of the randomized label
_W_CONSONANT: float = 0.30     # consonant cluster ratio
_W_DIGIT: float = 0.15         # digit ratio
_W_LENGTH: float = 0.10        # label length signal (12-32 range)
_W_UNIQ_CHAR: float = 0.10     # unique-character ratio
_W_NOVOWEL: float = 0.05       # binary bonus: cons_ratio >= 0.90 (near-zero vowels)

assert abs((_W_ENTROPY + _W_CONSONANT + _W_DIGIT + _W_LENGTH + _W_UNIQ_CHAR + _W_NOVOWEL) - 1.0) < 1e-9, (
    "Heuristic weights must sum to 1.0"
)

# ---------------------------------------------------------------------------
# Known vowels (ASCII lowercase + uppercase, for normalization)
# ---------------------------------------------------------------------------
_VOWELS: frozenset[str] = frozenset("aeiouAEIOU")

# Typical DGA label length range (Antonakakis et al., 2012 empirical findings)
_DGA_LEN_MIN: int = 12
_DGA_LEN_MAX: int = 32


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DomainScore:
    """Result of scoring a single domain string.

    Attributes
    ----------
    domain:
        The input domain string (preserved verbatim).
    score:
        Composite DGA likelihood in [0.0, 1.0].  Higher = more DGA-like.
    flagged:
        ``True`` iff ``score >= FLAG_THRESHOLD``.  Always consistent with score.
    entropy:
        Shannon entropy of the longest non-TLD label (bits/char), [0.0, 1.0]
        normalized.  Included for glass-box honesty / explain-ability.
    consonant_ratio:
        Ratio of consonant chars to total alpha chars in the scored label.
    digit_ratio:
        Ratio of digit chars to total chars in the scored label.
    label_length:
        Character count of the scored label.
    """

    domain: str
    score: float
    flagged: bool
    entropy: float
    consonant_ratio: float
    digit_ratio: float
    label_length: int


# ---------------------------------------------------------------------------
# Sub-signal helpers (intentionally public for unit-testing)
# ---------------------------------------------------------------------------


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy (bits/char, base-2) for string *s*.

    Returns 0.0 for empty or single-character strings.

    Reference: Shannon, C.E. (1948). "A Mathematical Theory of Communication".
    Bell System Technical Journal.
    """
    if len(s) <= 1:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum(
        (c / total) * math.log2(c / total)
        for c in counts.values()
    )


def _consonant_ratio(label: str) -> float:
    """Return the ratio of consonant chars to total alpha chars in *label*.

    Consonants = alpha chars that are not vowels (a/e/i/o/u, case-insensitive).
    Returns 0.0 when *label* has no alpha characters.
    """
    alpha_chars = [ch for ch in label if ch.isalpha()]
    if not alpha_chars:
        return 0.0
    consonants = sum(1 for ch in alpha_chars if ch not in _VOWELS)
    return consonants / len(alpha_chars)


def _digit_ratio(label: str) -> float:
    """Return the ratio of digit chars to total chars in *label*.

    Returns 0.0 for an empty label.
    """
    if not label:
        return 0.0
    return sum(1 for ch in label if ch.isdigit()) / len(label)


def _length_score(length: int) -> float:
    """Map label *length* to a [0.0, 1.0] signal.

    Peak signal (1.0) for the empirically DGA-typical 12–32 char range.
    Ramps linearly from 0→1 between 6–12 and from 1→0 between 32–50.
    Labels < 6 or > 50 yield 0.0 (not typical DGA; see module docstring).
    """
    if length < 6 or length > 50:
        return 0.0
    if _DGA_LEN_MIN <= length <= _DGA_LEN_MAX:
        return 1.0
    if length < _DGA_LEN_MIN:
        # ramp 0→1 over [6, _DGA_LEN_MIN)
        return (length - 6) / (_DGA_LEN_MIN - 6)
    # length > _DGA_LEN_MAX: ramp 1→0 over (_DGA_LEN_MAX, 50]
    return 1.0 - (length - _DGA_LEN_MAX) / (50 - _DGA_LEN_MAX)


def _unique_char_ratio(label: str) -> float:
    """Return ratio of distinct chars to total chars in *label*.

    High ratio (near 1.0) = no repeated characters = typical DGA.
    Returns 0.0 for empty label.
    """
    if not label:
        return 0.0
    return len(set(label)) / len(label)


def _extract_scored_label(domain: str) -> str:
    """Extract the randomized left-most label from a domain FQDN.

    For "xkzqvbmnwjr.example.com", returns "xkzqvbmnwjr" (the part that
    the DGA algorithm generates).  For a single-part label like "localhost",
    returns "localhost" unchanged.

    The TLD (rightmost label) and second-level domain are stripped when there
    are >= 2 dots, leaving only the leftmost label.  When there is exactly one
    dot (e.g. "xkzqvbmnwjr.example"), the leftmost part is returned.
    """
    if not domain:
        return ""
    parts = domain.rstrip(".").split(".")
    # Return the leftmost label — the DGA-generated part
    return parts[0] if parts else ""


# ---------------------------------------------------------------------------
# Public API — scorer
# ---------------------------------------------------------------------------


def score_domain(domain: str) -> DomainScore:
    """Score a single domain string for DGA likelihood.

    Parameters
    ----------
    domain:
        Fully-qualified domain name (or bare label) to evaluate.  Pass ``""``
        when ``dns_query`` is absent (yields score=0.0, flagged=False).

    Returns
    -------
    DomainScore
        Composite score in [0.0, 1.0] with per-signal breakdown for
        glass-box honesty.  ``flagged=True`` iff ``score >= FLAG_THRESHOLD``.

    Zero-egress
    -----------
    No network calls are made.  This function is safe to call from anywhere
    in the pipeline without risking DNS amplification or external lookups.
    """
    if not domain:
        return DomainScore(
            domain=domain,
            score=0.0,
            flagged=False,
            entropy=0.0,
            consonant_ratio=0.0,
            digit_ratio=0.0,
            label_length=0,
        )

    label = _extract_scored_label(domain)
    if not label:
        return DomainScore(
            domain=domain,
            score=0.0,
            flagged=False,
            entropy=0.0,
            consonant_ratio=0.0,
            digit_ratio=0.0,
            label_length=0,
        )

    # --- Compute each sub-signal normalized to [0.0, 1.0] ---

    # Entropy: max theoretical for 26-char alpha alphabet is log2(26) ≈ 4.70
    raw_entropy = _shannon_entropy(label.lower())
    _ENTROPY_MAX = math.log2(26)  # ≈ 4.70 bits/char
    norm_entropy = min(raw_entropy / _ENTROPY_MAX, 1.0)

    # Consonant ratio: 1.0 = fully consonant, 0.0 = fully vowel
    cons_ratio = _consonant_ratio(label)

    # Digit ratio: direct [0.0, 1.0]
    dig_ratio = _digit_ratio(label)

    # Length signal: [0.0, 1.0] based on empirical DGA length range
    len_sig = _length_score(len(label))

    # Unique-char ratio: [0.0, 1.0]
    uniq_sig = _unique_char_ratio(label)

    # No-vowel bonus: 1.0 when cons_ratio >= 0.90 (label is almost entirely consonants),
    # 0.0 otherwise.  This binary signal cleanly separates pure-consonant DGA labels
    # (cons_ratio == 1.0 for Conficker/DGA.Mirai patterns) from high-consonant brand
    # names like "microsoft" (cons_ratio 0.67) or "cloudflare" (cons_ratio 0.60).
    no_vowel_bonus = 1.0 if cons_ratio >= 0.90 else 0.0

    # Weighted composite
    composite = (
        _W_ENTROPY    * norm_entropy
        + _W_CONSONANT  * cons_ratio
        + _W_DIGIT      * dig_ratio
        + _W_LENGTH     * len_sig
        + _W_UNIQ_CHAR  * uniq_sig
        + _W_NOVOWEL    * no_vowel_bonus
    )
    # Clamp to [0.0, 1.0] (floating-point safety)
    score = max(0.0, min(1.0, composite))

    return DomainScore(
        domain=domain,
        score=round(score, 4),
        flagged=score >= FLAG_THRESHOLD,
        entropy=round(norm_entropy, 4),
        consonant_ratio=round(cons_ratio, 4),
        digit_ratio=round(dig_ratio, 4),
        label_length=len(label),
    )


# ---------------------------------------------------------------------------
# Store-level aggregation
# ---------------------------------------------------------------------------


async def get_dga_suspects(
    store: "SQLiteEventStore",
    top_n: int = DEFAULT_TOP_N,
) -> list[dict[str, Any]]:
    """Return the top ``top_n`` DNS rows whose ``dns_query`` is DGA-suspected.

    Algorithm
    ---------
    1. Fetch all distinct (dns_query, source_ip, timestamp) rows from the logs
       table where ``dns_query`` IS NOT NULL AND dns_query != ''.
       Parameterized SQL only — ``top_n`` is bound via ``?`` placeholder.
    2. Score each distinct domain with ``score_domain()``.
    3. Discard rows where ``score < FLAG_THRESHOLD`` (not flagged).
    4. Sort descending by dga_score; slice to ``top_n``.

    Returns
    -------
    list[dict]
        Each dict has keys: ``dns_query``, ``source_ip``, ``timestamp``,
        ``dga_score``, plus the per-signal breakdown fields for glass-box
        honesty (entropy, consonant_ratio, digit_ratio, label_length).
        Rows are ordered by ``dga_score`` descending.

    Zero-egress
    -----------
    No DNS or HTTP calls.  Scoring is pure local computation.

    Security (ADR-0029 D3)
    ----------------------
    ``dns_query`` and ``source_ip`` are attacker-controlled telemetry — callers
    MUST render them as text nodes only.

    Parameters
    ----------
    store:
        An EventStore-conforming instance exposing ``_read_conn()``.
    top_n:
        Maximum number of suspect rows to return.  Bound via SQL ``?``
        placeholder — never f-string interpolated.
    """
    # Clamp top_n defensively (mirrors ML-3/ML-8 le-cap pattern)
    top_n = max(1, min(top_n, MAX_TOP_N))

    db = await store._read_conn()  # type: ignore[union-attr]
    # Fetch candidate rows: only rows with non-null, non-empty dns_query.
    # We over-fetch by capping at MAX_TOP_N * 4 to leave room for
    # post-scoring filtering (most rows will not be flagged).
    fetch_limit = min(top_n * 20, MAX_TOP_N * 4)
    cursor = await db.execute(
        """
        SELECT dns_query, source_ip, timestamp
        FROM logs
        WHERE dns_query IS NOT NULL
          AND dns_query != ''
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (fetch_limit,),
    )
    rows = await cursor.fetchall()

    # Score and filter in Python (zero-egress: pure local computation)
    scored: list[dict[str, Any]] = []
    for row in rows:
        dns_query: str = row[0]
        source_ip: str = row[1]
        timestamp: str = row[2]

        ds = score_domain(dns_query)
        if not ds.flagged:
            continue

        scored.append({
            "dns_query": dns_query,
            "source_ip": source_ip,
            "timestamp": timestamp,
            "dga_score": ds.score,
            "entropy": ds.entropy,
            "consonant_ratio": ds.consonant_ratio,
            "digit_ratio": ds.digit_ratio,
            "label_length": ds.label_length,
        })

    # Sort by dga_score descending; take top_n
    scored.sort(key=lambda r: r["dga_score"], reverse=True)
    return scored[:top_n]
