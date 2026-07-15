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
 * CORRECTION: an earlier version of this label used "block status unknown"
 * as the replacement — that is WRONG. ADR-0067 does not sanction that phrase;
 * it is the ADR's central falsified premise (line 4: "...the ALERT/LOG
 * 'block status unknown' label"; RC3's own title: "the OCSF premise behind
 * 'block status unknown' is factually false" — verified live against OCSF
 * 1.8.0 `disposition_id=19 Alert`: "...resulted in a notification but request
 * was **not blocked**," which asserts NOT-blocked, not unknown). There is no
 * "D6" in ADR-0067 (it has no lettered decision sections past D... verify
 * with `grep -nE "^### D[0-9]" docs/adr/0067-*.md` before ever citing one) —
 * the posture-aware replacement vocabulary belongs to issues #44/#45 (M3, not
 * started), not this ADR.
 *
 * ADR-0067 does NOT hand over replacement UI copy for Tier 2 — the only thing
 * it settles is the *mechanism* (D1: "Tier 2 requires a qualifying assertion
 * ... An actor's ALERT/LOG population reaches Tier 2 only when a qualifying
 * signal is present"). The label below is this implementer's PROPOSAL, built
 * from that one settled fact and nothing else: it names what IS known (a
 * qualifying detection/assertion exists) and makes NO claim about whether the
 * traffic was blocked. Flagged here as an OPEN QUESTION for the
 * architect/maintainer to redline, same as Tier 1/3/4 originally were in
 * PR #38 — this wording is not architect- or maintainer-sourced.
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

// ---------------------------------------------------------------------------
// Lookup helpers — every surface goes through these, never a switch of its own
// ---------------------------------------------------------------------------

/**
 * Full disposition label for a chip / popover trigger / legend title.
 * Handles the four ranked tiers plus the ADR-0067 observed stratum. Falls
 * back to the raw key for a disposition the copy table doesn't know about
 * yet (forward-compat — never throws on an unrecognized value).
 */
export function dispositionLabel(disposition: string): string {
  if (disposition === OBSERVED_COPY.disposition) return OBSERVED_COPY.label
  return TIER_COPY_BY_DISPOSITION[disposition as DispositionKey]?.label ?? disposition
}

/**
 * Short label for a tier-group header (e.g. "Tier 2 — Flagged (84)").
 * `tier === null` covers the observed stratum (ADR-0067 D2): returns the
 * observed short label when the disposition says so, or a defensive
 * "No escalation verdict" fallback for a null tier with no disposition.
 */
export function tierGroupLabel(tier: number | null, disposition: string | undefined): string {
  if (tier == null) {
    if (disposition === OBSERVED_COPY.disposition) return OBSERVED_COPY.shortLabel
    return 'No escalation verdict'
  }
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
 * Tier 2 (block_status_unknown) uses --fw-amber.
 * Observed uses its own (muted) token. Others use the tier's own copy-table
 * color, or --fw-t2 for an unrecognized key.
 */
export function dispositionColor(disposition: string): string {
  if (disposition === OBSERVED_COPY.disposition) return OBSERVED_COPY.color
  return TIER_COPY_BY_DISPOSITION[disposition as DispositionKey]?.color ?? 'var(--fw-t2)'
}
