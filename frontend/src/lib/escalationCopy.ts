/**
 * escalationCopy — the SINGLE SOURCE OF TRUTH for the four escalation-tier
 * display labels shown across the dashboard (issue #6 / ADR-0058 / ADR-0059).
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
 * NAMING NOTE (maintainer sign-off pending, issue #6): the `label` /
 * `description` / `blockStatusLabel` strings below are a PROPOSAL. See the
 * PR description for the alternatives considered; final wording is the
 * maintainer's call before merge.
 */

/** Machine-readable disposition key — from `EscalationVerdict.disposition` (fixed, ADR-0058). */
export type DispositionKey =
  | 'allowed_through'
  | 'block_status_unknown'
  | 'blocked_persistent'
  | 'blocked_one_off'

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
// The 4-tier copy table (issue #6 proposal — see PR description for alternatives)
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
    label: 'Unconfirmed — may have gotten in',
    shortLabel: 'Unconfirmed',
    description:
      'Something suspicious was flagged, but nothing confirms whether it was actually stopped. Treat it as unresolved.',
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
    color: 'var(--fw-t2)',
  },
  {
    tier: 4,
    disposition: 'blocked_one_off',
    blockStatus: 'blocked',
    label: 'Blocked — single attempt',
    shortLabel: 'Blocked, one-off',
    description:
      'Your defenses stopped this attempt. A single try only — informational, no action needed.',
    color: 'var(--fw-t3)',
  },
] as const

const TIER_COPY_BY_DISPOSITION: Record<DispositionKey, TierCopy> = Object.fromEntries(
  TIER_COPY.map((row) => [row.disposition, row]),
) as Record<DispositionKey, TierCopy>

// ---------------------------------------------------------------------------
// Lookup helpers — every surface goes through these, never a switch of its own
// ---------------------------------------------------------------------------

/**
 * Full disposition label for a chip / popover trigger / legend title.
 * Falls back to the raw key for a disposition the copy table doesn't know
 * about yet (forward-compat — never throws on an unrecognized value).
 */
export function dispositionLabel(disposition: string): string {
  return TIER_COPY_BY_DISPOSITION[disposition as DispositionKey]?.label ?? disposition
}

/**
 * Short label for a tier-group header (e.g. "Tier 2 — Unconfirmed (84)").
 * Falls back to a bare "Tier N" when the disposition is unrecognized.
 */
export function tierGroupLabel(tier: number | null, disposition: string | undefined): string {
  if (tier == null) return 'No escalation verdict'
  const row = disposition != null ? TIER_COPY_BY_DISPOSITION[disposition as DispositionKey] : undefined
  return row != null ? `Tier ${tier} — ${row.shortLabel}` : `Tier ${tier}`
}

/**
 * Short human-readable label for the block_status badge.
 *
 * When block_status === "partial", formats a counts-derived label
 * (e.g. "9 blocked · 298 unconfirmed") from the disposition_counts
 * breakdown. Gracefully degrades to "Partial" when counts are absent.
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
 * Others use the tier's own copy-table color, or --fw-t2 for an unknown key.
 */
export function dispositionColor(disposition: string): string {
  return TIER_COPY_BY_DISPOSITION[disposition as DispositionKey]?.color ?? 'var(--fw-t2)'
}
