/**
 * escalationCopy — the SINGLE SOURCE OF TRUTH for the escalation-tier display
 * labels shown across the dashboard (issue #6 / ADR-0058 / ADR-0059 / ADR-0067).
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * ADR-0058 draws a hard line: "labels may change, semantics may NOT." Tier
 * number, disposition key, and block_status key are facts computed by the
 * backend decider (`escalation/decider.py`) from the perimeter's `action`
 * field — this file never touches those. It owns ONLY the human-readable
 * wording layered on top, so a future rewording is a one-file edit instead of
 * a hunt across TriageBanner, tooltips, popovers, and the legend.
 *
 * Every surface that renders a tier label, a block-status badge, or a
 * tier-group header imports from here — no surface defines its own copy.
 *
 * NAMING NOTE (issue #6): Tier 1/3/4 wording is the maintainer-approved final
 * copy (Galip, via the product-strategist's recommendation) — see PR #38 for
 * the alternatives considered and the reasoning.
 *
 * TIER 2 — REBASED FOR ADR-0067 (issue #6 PR, post-#42/#51):
 * PR #38's original Tier-2 proposal, "Unconfirmed — may have got through", is
 * falsified by ADR-0067 D1: reaching Tier 2 now REQUIRES a qualifying
 * assertion (a correlation rule, or a source-declared high/critical
 * severity) — it is no longer bare, unconfirmed telemetry. "Unconfirmed" as
 * the leading word undersells that; and "may have got through" is flatly
 * false whenever the qualifying signal is a LOG-only correlation (e.g. a
 * brute-force rule built from failed, *attested* logins — ADR-0067 RC3, the
 * "a failed-login LOG line ... the login failed" example).
 *
 * CORRECTION (superseded): a subsequent pass on this PR claimed ADR-0067 had
 * no "D6" and that citing it was a fabrication. That claim was itself wrong —
 * the grep pattern used (`^\*\*?D[0-9]`) did not match the actual `### D6`
 * markdown heading. ADR-0067 D6 ("Enforcement posture: plugin-declared
 * default, core-owned per-instance override") exists (docs/adr/0067-*.md,
 * "### D6") and directly governs `block_status_unknown` today: D6 states
 * "`enforce` or undeclared → `block_status_unknown`" — every instance before
 * issue #75 was posture-undeclared, so this key was D6's correct label over
 * an empty posture map, not drift. What RC3 falsified was the popover
 * SENTENCE built on top of the key (prose implying an OCSF non-terminating
 * mapping), never the disposition key itself. See the architect's ruling on
 * PR #38 for the settled account.
 *
 * D6's "rare and genuinely meaningful" distribution claim for the residual
 * `block_status_unknown` cell is CORRECTED by ADR-0067 Amendment 1: the
 * `enforce` + zero-BLOCK/DROP cell is a *routine* M1 population (aws_nfw
 * declares `enforce` and maps every non-blocked stateful event to ALERT), not
 * rare — Amendment 1 A1.3. This file's PostureCopy rows below implement A1.1's
 * fix for that cell.
 *
 * TIER 2 LABEL — RATIFIED (architect ruling, PR #38): "Flagged — needs
 * review" below is the settled interim Tier-2 label for the (now narrower)
 * `block_status_unknown` cell, not an open proposal. It names what IS known
 * (a qualifying detection/assertion exists per D1) and makes no claim about
 * whether the traffic was blocked.
 *
 * POSTURE LABELS — issue #75 (ADR-0067 D6 + Amendment 1): a qualified Tier-2
 * verdict whose contributing instance(s) declare a SINGLE, uniform
 * `enforcement` posture gets one of three additive, posture-specific labels
 * instead of the generic `block_status_unknown` — see `POSTURE_COPY` below.
 * Modeled on the same "kept out of `TIER_COPY`, merged in the lookup helpers"
 * pattern as `OBSERVED_COPY`: these are Tier-2 *variants*, not new tiers.
 *
 * OBSERVED STRATUM (ADR-0067 D2): an additive, deliberately NOT-a-fifth-tier
 * row — `tier: null`, `disposition: "observed"`. An observed actor carries no
 * escalation claim at all and must never read as an alert; it is exported
 * separately from `TIER_COPY` (which stays the fixed 1-4 tier ladder) and
 * merged into the lookup helpers below.
 */

/** Machine-readable disposition key for a ranked tier — from `EscalationVerdict.disposition` (fixed, ADR-0058). */
export type DispositionKey =
  | 'allowed_through'
  | 'block_status_unknown'
  | 'blocked_persistent'
  | 'blocked_one_off'

/** The ADR-0067 D2 observed-stratum disposition key — always paired with `tier: null`. */
export type ObservedDispositionKey = 'observed'

/**
 * The ADR-0067 D6 + Amendment 1 posture-derived Tier-2 disposition keys
 * (issue #75) — additive to `DispositionKey`, always paired with `tier: 2`.
 * Emitted instead of the generic `block_status_unknown` when a qualified
 * Tier-2 verdict's contributing instance(s) declare a single, uniform
 * `enforcement` posture (`SourceMetadata.enforcement`, resolved core-side).
 */
export type PostureDispositionKey =
  | 'not_blocked_passive'
  | 'detected_no_action'
  | 'not_blocked_enforcing'

/** Machine-readable block_status key — from `EscalationVerdict.block_status` (fixed, ADR-0058 Amendment 1). */
export type BlockStatusKey = 'allowed' | 'blocked' | 'unknown' | 'partial'

/** Per-class event count breakdown — mirrors `EscalationVerdict.disposition_counts`. */
export interface DispositionCountsLike {
  blocked: number
  alert_unknown: number
  allowed: number
}

/** One row of the fixed 4-tier model, with its display copy attached. */
export interface TierCopy {
  /** 1-4; lower = louder (ADR-0058 tier priority — semantics fixed). */
  tier: 1 | 2 | 3 | 4
  /** The machine disposition key this row corresponds to. */
  disposition: DispositionKey
  /** The single-class block_status key this row corresponds to. */
  blockStatus: Exclude<BlockStatusKey, 'partial'>
  /**
   * Full label shown on the actor chip, the popover trigger, and the legend
   * row title — a short plain-language verdict, not SOC jargon.
   */
  label: string
  /**
   * Short label for compact surfaces (tier-group headers) where the full
   * `label` sentence would be too long for a one-line header.
   */
  shortLabel: string
  /** One-sentence plain-language explanation shown in the legend row body. */
  description: string
  /** CSS color token (ADR-0028 D6 — --fw-* tokens only). */
  color: string
}

// ---------------------------------------------------------------------------
// The 4-tier copy table (issue #6 — maintainer-approved wording; Tier 2
// re-derived for ADR-0067, see the module doc above)
//
// Tiers 3 and 4 differ on exactly one fact — persistence — so their labels
// differ on exactly that word ("kept trying" / "didn't keep trying"). Reading
// both legend rows together teaches the whole lower half of the ladder with
// no tooltip needed. Both are count-agnostic and threshold-proof: they stay
// true regardless of where _PERSISTENCE_THRESHOLD (decider.py) is set.
// ---------------------------------------------------------------------------

export const TIER_COPY: readonly TierCopy[] = [
  {
    tier: 1,
    disposition: 'allowed_through',
    blockStatus: 'allowed',
    label: 'Got through — possible breach',
    shortLabel: 'Got through',
    description:
      'A confirmed attack pattern matched, and the traffic got past your defenses. It may have reached your system — highest priority.',
    color: 'var(--fw-red)',
  },
  {
    tier: 2,
    disposition: 'block_status_unknown',
    blockStatus: 'unknown',
    label: 'Flagged — needs review',
    shortLabel: 'Flagged',
    description:
      'A correlation rule fired, or a source-declared high/critical severity was present, flagging this actor as hostile. This label makes no claim about whether the traffic was actually blocked.',
    color: 'var(--fw-amber)',
  },
  {
    tier: 3,
    disposition: 'blocked_persistent',
    blockStatus: 'blocked',
    label: 'Blocked — kept trying',
    shortLabel: 'Blocked, repeated',
    description:
      'Your defenses stopped every attempt, but this attacker keeps coming back. Consider a longer-term block.',
    // NOTE: --fw-t2/--fw-t3 are a text-emphasis scale (secondary/muted text),
    // not a tier-numbered token family — the shared "t2"/"t3" naming with
    // Tier 2/Tier 3 is coincidental. Tiers 3 and 4 are both "informational,
    // lower urgency" so they intentionally step down through this grey scale
    // rather than getting their own hue (reserved for Tier 1 red / Tier 2 amber).
    color: 'var(--fw-t2)',
  },
  {
    tier: 4,
    disposition: 'blocked_one_off',
    blockStatus: 'blocked',
    label: "Blocked — didn't keep trying",
    shortLabel: "Didn't keep trying",
    description:
      "Your defenses stopped every attempt, and this one didn't keep coming back. No action needed.",
    color: 'var(--fw-t3)',
  },
] as const

const TIER_COPY_BY_DISPOSITION: Record<DispositionKey, TierCopy> = Object.fromEntries(
  TIER_COPY.map((row) => [row.disposition, row]),
) as Record<DispositionKey, TierCopy>

/**
 * The ADR-0067 D2 observed-stratum copy row. Deliberately separate from
 * `TIER_COPY`: it has no tier number (not a fifth tier — see the module doc)
 * and no fixed `block_status` (an observed verdict's block_status reflects
 * whichever truthful state applies — "unknown" for an unqualified ALERT/LOG
 * population, "allowed" for an ALLOW-only actor with no detection).
 */
export const OBSERVED_COPY = {
  disposition: 'observed' as const,
  label: 'On the record — no escalation claim',
  shortLabel: 'Observed',
  description:
    'Nothing asserted this actor is hostile — no qualifying detection, no declared high/critical severity. Not dropped: still scored on the severity-band axis and fully visible in Network Logs.',
  color: 'var(--fw-t3)',
}

/** One row of the ADR-0067 D6 + Amendment 1 posture-derived Tier-2 label set (issue #75). */
export interface PostureCopy {
  disposition: PostureDispositionKey
  /** Always 2 — these are Tier-2 variants, never a new tier (see the module doc). */
  tier: 2
  /** Always 'unknown' — posture only relabels the disposition, never block_status (the #75 safety property). */
  blockStatus: 'unknown'
  label: string
  shortLabel: string
  description: string
  color: string
}

// ---------------------------------------------------------------------------
// The posture-derived Tier-2 copy rows (issue #75, ADR-0067 D6 + Amendment 1).
// Kept OUT of TIER_COPY (same pattern as OBSERVED_COPY): these are honest
// per-sensor VARIANTS of the generic Tier-2 label, not new tiers. Exact
// wording per D6 / Amendment 1 A1.1.
// ---------------------------------------------------------------------------

export const POSTURE_COPY: readonly PostureCopy[] = [
  {
    disposition: 'not_blocked_passive',
    tier: 2,
    blockStatus: 'unknown',
    label: 'Not blocked — watch-only sensor',
    shortLabel: 'Not blocked (watch-only)',
    description:
      'This sensor observes traffic but cannot block it. A qualifying detection or declared high/critical severity flagged this actor — the traffic was not stopped by this control.',
    color: 'var(--fw-amber)',
  },
  {
    disposition: 'detected_no_action',
    tier: 2,
    blockStatus: 'unknown',
    label: 'Detected — no action taken; file present',
    shortLabel: 'Detected, no action',
    description:
      'A host-based detector found this on disk but does not remove or quarantine it automatically. The file is still present — this needs manual cleanup.',
    color: 'var(--fw-amber)',
  },
  {
    disposition: 'not_blocked_enforcing',
    tier: 2,
    blockStatus: 'unknown',
    label: 'Not blocked — this control was enforcing and did not block it',
    shortLabel: 'Not blocked (enforcing)',
    description:
      'This control is configured to block traffic, but it let this specific activity through — it alerted without stopping it. Worth a closer look.',
    color: 'var(--fw-amber)',
  },
] as const

const POSTURE_COPY_BY_DISPOSITION: Record<PostureDispositionKey, PostureCopy> = Object.fromEntries(
  POSTURE_COPY.map((row) => [row.disposition, row]),
) as Record<PostureDispositionKey, PostureCopy>

// ---------------------------------------------------------------------------
// Lookup helpers — every surface goes through these, never a switch of its own
// ---------------------------------------------------------------------------

/**
 * Full disposition label for a chip / popover trigger / legend title.
 * Handles the four ranked tiers, the ADR-0067 observed stratum, and the
 * issue #75 posture-derived Tier-2 labels. Falls back to the raw key for a
 * disposition the copy table doesn't know about yet (forward-compat — never
 * throws on an unrecognized value).
 */
export function dispositionLabel(disposition: string): string {
  if (disposition === OBSERVED_COPY.disposition) return OBSERVED_COPY.label
  const postureRow = POSTURE_COPY_BY_DISPOSITION[disposition as PostureDispositionKey]
  if (postureRow != null) return postureRow.label
  return TIER_COPY_BY_DISPOSITION[disposition as DispositionKey]?.label ?? disposition
}

/**
 * Short label for a tier-group header (e.g. "Tier 2 — Flagged (84)").
 * `tier === null` covers the observed stratum (ADR-0067 D2): returns the
 * observed short label when the disposition says so, or a defensive
 * "No escalation verdict" fallback for a null tier with no disposition.
 * A posture-derived disposition (issue #75) resolves through the same
 * `Tier ${tier} — ${shortLabel}` shape as the four ranked tiers.
 */
export function tierGroupLabel(tier: number | null, disposition: string | undefined): string {
  if (tier == null) {
    if (disposition === OBSERVED_COPY.disposition) return OBSERVED_COPY.shortLabel
    return 'No escalation verdict'
  }
  const postureRow =
    disposition != null ? POSTURE_COPY_BY_DISPOSITION[disposition as PostureDispositionKey] : undefined
  if (postureRow != null) return `Tier ${tier} — ${postureRow.shortLabel}`
  const row = disposition != null ? TIER_COPY_BY_DISPOSITION[disposition as DispositionKey] : undefined
  return row != null ? `Tier ${tier} — ${row.shortLabel}` : `Tier ${tier}`
}

/**
 * Short human-readable label for the block_status badge.
 *
 * When block_status === "partial", formats a counts-derived label
 * (e.g. "9 blocked · 298 unconfirmed") from the disposition_counts
 * breakdown. Gracefully degrades to "Partial" when counts are absent.
 *
 * Unaffected by the Tier-2 relabel above: block_status's meaning is
 * unchanged by ADR-0067 (an observed verdict still carries its truthful
 * block_status — "unknown" or "allowed").
 */
export function blockStatusLabel(blockStatus: string, counts?: DispositionCountsLike): string {
  switch (blockStatus) {
    case 'allowed':
      return 'Got through'
    case 'blocked':
      return 'Blocked'
    case 'unknown':
      return 'Unconfirmed'
    case 'partial':
      if (counts != null) {
        return `${counts.blocked} blocked · ${counts.alert_unknown} unconfirmed`
      }
      return 'Partial'
    default:
      return blockStatus
  }
}

/**
 * CSS color token for a disposition.
 * Tier 1 (allowed-through) uses --fw-red (highest urgency).
 * Tier 2 (block_status_unknown) uses --fw-amber; the issue #75 posture-derived
 * Tier-2 labels use the same --fw-amber (they are Tier-2 variants).
 * Observed uses its own (muted) token. Others use the tier's own copy-table
 * color, or --fw-t2 for an unrecognized key.
 */
export function dispositionColor(disposition: string): string {
  if (disposition === OBSERVED_COPY.disposition) return OBSERVED_COPY.color
  const postureRow = POSTURE_COPY_BY_DISPOSITION[disposition as PostureDispositionKey]
  if (postureRow != null) return postureRow.color
  return TIER_COPY_BY_DISPOSITION[disposition as DispositionKey]?.color ?? 'var(--fw-t2)'
}

// ---------------------------------------------------------------------------
// Attempts headline copy (issue #55, ADR-0070) — the single place the
// "N hostile attempts from M actors — S succeeded · K need review" sentence
// is assembled, so TriageBanner/AttemptsHeadline own zero copy of their own
// (issue #6 discipline, extended to this new headline).
//
// Every number here MUST be rendered verbatim from GET /banner/summary
// (firewatch_api.banner_assembler) — this module only pluralizes words
// around already-computed engine integers. It NEVER counts, sums, or
// re-derives "succeeded"/"need review" itself (issue #55 hard constraint —
// the banner must never count differently than the escalation engine).
// ---------------------------------------------------------------------------

/** The subset of `BannerAttemptSummary` the headline sentence needs. */
export interface AttemptsHeadlineCounts {
  attempt_count: number
  actor_count: number
  succeeded_count: number
  queue_size: number
}

/**
 * Build the attempts headline sentence, e.g.:
 *   "412 hostile attempts from 87 actors — 0 succeeded · 2 need review"
 *
 * Pure string formatting over server-provided integers — no client-side
 * derivation of any count (ADR-0070 D3 / issue #55).
 */
export function attemptsHeadlineText(counts: AttemptsHeadlineCounts): string {
  const { attempt_count, actor_count, succeeded_count, queue_size } = counts
  const attemptWord = attempt_count === 1 ? 'attempt' : 'attempts'
  const actorWord = actor_count === 1 ? 'actor' : 'actors'
  const needWord = queue_size === 1 ? 'needs' : 'need'
  return (
    `${attempt_count} hostile ${attemptWord} from ${actor_count} ${actorWord}` +
    ` — ${succeeded_count} succeeded · ${queue_size} ${needWord} review`
  )
}

/**
 * Plain-text pressure-row description — "N attempts over M min" (or the
 * singular "1 attempt" when only one qualifying event exists for this actor).
 *
 * Strategist condition (issue #55, ADR-0070/ADR-0069 conditions, 2026-07-16):
 * the pressure strip's minimal "show me the math" slice is plain integers —
 * attempt_count + span_minutes — text, never hover-only (WCAG). The fuller
 * "peak pressure X of Y" (peak decayed intensity vs. the HIGH ALERT
 * threshold) is NOT in `GET /banner/summary` today (the endpoint exposes
 * only attempt_count/span_minutes per row, ADR-0035 — engine integers, never
 * the raw decayed-intensity float) — this function renders what IS
 * available and never recomputes or estimates the missing peak/threshold
 * pair client-side.
 */
export function pressureRowText(attemptCount: number, spanMinutes: number): string {
  if (attemptCount === 1) return '1 attempt'
  if (spanMinutes > 0) return `${attemptCount} attempts over ${spanMinutes} min`
  return `${attemptCount} attempts`
}
