/**
 * Tests for lib/escalationCopy.ts — the centralized escalation-tier copy
 * table (issue #6 / ADR-0058 / ADR-0059 / ADR-0067).
 *
 * EARS criteria → test mapping:
 *   - WHEN a tier badge/chip/legend row/popover renders, THE SYSTEM SHALL use
 *     the new self-explanatory label set, consistently across every lookup
 *     helper (dispositionLabel / tierGroupLabel / blockStatusLabel).
 *     → describe('TIER_COPY table'), describe('dispositionLabel'), etc.
 *   - Tier semantics (tier number, disposition key, block_status key) SHALL
 *     be unchanged — only wording changes.
 *     → describe('TIER_COPY table — semantics unchanged')
 *   - The four labels SHALL be centralized in exactly one module.
 *     → this file existing + TriageBanner importing from it (see
 *       TriageBanner.test.tsx for the render-level assertions).
 *   - WHEN a verdict is the ADR-0067 D2 observed stratum (tier=null,
 *     disposition="observed"), THE SYSTEM SHALL label it as a non-claim
 *     (never as an alert) via the same lookup helpers.
 *     → describe('OBSERVED_COPY (ADR-0067 D2)')
 */
import { describe, it, expect } from 'vitest'
import {
  TIER_COPY,
  OBSERVED_COPY,
  POSTURE_COPY,
  dispositionLabel,
  tierGroupLabel,
  blockStatusLabel,
  dispositionColor,
} from '../lib/escalationCopy'

describe('TIER_COPY table — semantics unchanged (ADR-0058)', () => {
  it('has exactly 4 rows (the fixed 4-tier model)', () => {
    expect(TIER_COPY).toHaveLength(4)
  })

  it('tier numbers are 1-4 in order (lower = louder, priority unchanged)', () => {
    expect(TIER_COPY.map((r) => r.tier)).toEqual([1, 2, 3, 4])
  })

  it('disposition keys match the fixed EscalationVerdict.disposition vocabulary', () => {
    expect(TIER_COPY.map((r) => r.disposition)).toEqual([
      'allowed_through',
      'block_status_unknown',
      'blocked_persistent',
      'blocked_one_off',
    ])
  })

  it('block_status keys match the fixed EscalationVerdict.block_status vocabulary', () => {
    expect(TIER_COPY.map((r) => r.blockStatus)).toEqual([
      'allowed',
      'unknown',
      'blocked',
      'blocked',
    ])
  })

  it('every row has a non-empty label, shortLabel, description, and color', () => {
    for (const row of TIER_COPY) {
      expect(row.label.length).toBeGreaterThan(0)
      expect(row.shortLabel.length).toBeGreaterThan(0)
      expect(row.description.length).toBeGreaterThan(0)
      expect(row.color.length).toBeGreaterThan(0)
    }
  })

  it('colors are --fw-* CSS variable tokens only (ADR-0028 D6)', () => {
    for (const row of TIER_COPY) {
      expect(row.color).toMatch(/^var\(--fw-/)
    }
  })
})

describe('dispositionLabel', () => {
  it('returns the full label for each known disposition', () => {
    expect(dispositionLabel('allowed_through')).toBe(TIER_COPY[0].label)
    expect(dispositionLabel('block_status_unknown')).toBe(TIER_COPY[1].label)
    expect(dispositionLabel('blocked_persistent')).toBe(TIER_COPY[2].label)
    expect(dispositionLabel('blocked_one_off')).toBe(TIER_COPY[3].label)
  })

  it('falls back to the raw key for an unrecognized disposition (forward-compat)', () => {
    expect(dispositionLabel('some_future_disposition')).toBe('some_future_disposition')
  })
})

describe('tierGroupLabel', () => {
  it('builds "Tier N — shortLabel" for each known tier/disposition pair', () => {
    expect(tierGroupLabel(1, 'allowed_through')).toBe(`Tier 1 — ${TIER_COPY[0].shortLabel}`)
    expect(tierGroupLabel(2, 'block_status_unknown')).toBe(`Tier 2 — ${TIER_COPY[1].shortLabel}`)
    expect(tierGroupLabel(3, 'blocked_persistent')).toBe(`Tier 3 — ${TIER_COPY[2].shortLabel}`)
    expect(tierGroupLabel(4, 'blocked_one_off')).toBe(`Tier 4 — ${TIER_COPY[3].shortLabel}`)
  })

  it('returns "No escalation verdict" when tier is null', () => {
    expect(tierGroupLabel(null, undefined)).toBe('No escalation verdict')
  })

  it('falls back to a bare "Tier N" for an unrecognized disposition', () => {
    expect(tierGroupLabel(9, 'unknown_future_disposition')).toBe('Tier 9')
  })
})

describe('blockStatusLabel', () => {
  it('maps single-class block_status keys to their short label', () => {
    expect(blockStatusLabel('allowed')).toBe('Got through')
    expect(blockStatusLabel('blocked')).toBe('Blocked')
    expect(blockStatusLabel('unknown')).toBe('Unconfirmed')
  })

  it('formats a partial label from disposition_counts', () => {
    expect(
      blockStatusLabel('partial', { blocked: 9, alert_unknown: 298, allowed: 0 }),
    ).toBe('9 blocked · 298 unconfirmed')
  })

  it('falls back to "Partial" when counts are absent (graceful degradation)', () => {
    expect(blockStatusLabel('partial')).toBe('Partial')
  })

  it('does not surface the raw "partial" key when counts are present', () => {
    const label = blockStatusLabel('partial', { blocked: 1, alert_unknown: 2, allowed: 0 })
    expect(label).not.toMatch(/\bpartial\b/i)
  })
})

describe('dispositionColor', () => {
  it('returns the color token for each known disposition', () => {
    expect(dispositionColor('allowed_through')).toBe(TIER_COPY[0].color)
    expect(dispositionColor('block_status_unknown')).toBe(TIER_COPY[1].color)
  })

  it('falls back to --fw-t2 for an unrecognized disposition', () => {
    expect(dispositionColor('nonsense')).toBe('var(--fw-t2)')
  })
})

// ---------------------------------------------------------------------------
// ADR-0067 D2 — the observed stratum (tier=null, disposition="observed")
// ---------------------------------------------------------------------------

describe('OBSERVED_COPY (ADR-0067 D2)', () => {
  it('is not one of the 4 ranked tiers (deliberately not a fifth tier)', () => {
    expect(TIER_COPY.map((r) => r.disposition)).not.toContain('observed')
  })

  it('has a non-empty label, shortLabel, description, and a --fw-* color token', () => {
    expect(OBSERVED_COPY.label.length).toBeGreaterThan(0)
    expect(OBSERVED_COPY.shortLabel.length).toBeGreaterThan(0)
    expect(OBSERVED_COPY.description.length).toBeGreaterThan(0)
    expect(OBSERVED_COPY.color).toMatch(/^var\(--fw-/)
  })

  it('makes no escalation/urgency claim — must not read as an alert', () => {
    // EARS: an observed actor is NOT queued and must not read as an alert.
    expect(OBSERVED_COPY.label.toLowerCase()).not.toMatch(/alert|breach|block status unknown/)
    expect(OBSERVED_COPY.label.toLowerCase()).toContain('no escalation claim')
  })

  it('dispositionLabel("observed") returns the observed label', () => {
    expect(dispositionLabel('observed')).toBe(OBSERVED_COPY.label)
  })

  it('dispositionColor("observed") returns the observed color token', () => {
    expect(dispositionColor('observed')).toBe(OBSERVED_COPY.color)
  })

  it('tierGroupLabel(null, "observed") returns the observed short label, not "No escalation verdict"', () => {
    expect(tierGroupLabel(null, 'observed')).toBe(OBSERVED_COPY.shortLabel)
  })

  it('tierGroupLabel(null, undefined) still falls back to "No escalation verdict" (defensive default)', () => {
    expect(tierGroupLabel(null, undefined)).toBe('No escalation verdict')
  })
})

// ---------------------------------------------------------------------------
// ADR-0067 D6 + Amendment 1 — posture-derived Tier-2 labels (issue #75)
// ---------------------------------------------------------------------------

describe('POSTURE_COPY (ADR-0067 D6 + Amendment 1, issue #75)', () => {
  it('has exactly 3 rows (observe / detect_only / enforce+zero-blocks)', () => {
    expect(POSTURE_COPY).toHaveLength(3)
  })

  it('is not one of the 4 ranked tiers (kept out of TIER_COPY, like OBSERVED_COPY)', () => {
    expect(TIER_COPY.map((r) => r.disposition)).not.toContain('not_blocked_passive')
    expect(TIER_COPY.map((r) => r.disposition)).not.toContain('detected_no_action')
    expect(TIER_COPY.map((r) => r.disposition)).not.toContain('not_blocked_enforcing')
  })

  it('every row is tier 2 with blockStatus "unknown" (posture relabels disposition only)', () => {
    for (const row of POSTURE_COPY) {
      expect(row.tier).toBe(2)
      expect(row.blockStatus).toBe('unknown')
    }
  })

  it('every row has a non-empty label, shortLabel, description, and --fw-* color token', () => {
    for (const row of POSTURE_COPY) {
      expect(row.label.length).toBeGreaterThan(0)
      expect(row.shortLabel.length).toBeGreaterThan(0)
      expect(row.description.length).toBeGreaterThan(0)
      expect(row.color).toMatch(/^var\(--fw-/)
    }
  })

  it('not_blocked_passive label matches the D6 wording exactly', () => {
    const row = POSTURE_COPY.find((r) => r.disposition === 'not_blocked_passive')
    expect(row?.label).toBe('Not blocked — watch-only sensor')
  })

  it('detected_no_action label matches the D6 wording exactly', () => {
    const row = POSTURE_COPY.find((r) => r.disposition === 'detected_no_action')
    expect(row?.label).toBe('Detected — no action taken; file present')
  })

  it('not_blocked_enforcing label matches the Amendment 1 A1.1 wording exactly', () => {
    const row = POSTURE_COPY.find((r) => r.disposition === 'not_blocked_enforcing')
    expect(row?.label).toBe('Not blocked — this control was enforcing and did not block it')
  })

  it('not_blocked_enforcing label MUST NOT claim "breach" (A1.1 honest-state discipline)', () => {
    const row = POSTURE_COPY.find((r) => r.disposition === 'not_blocked_enforcing')
    expect(row?.label.toLowerCase()).not.toContain('breach')
    expect(row?.description.toLowerCase()).not.toContain('breach')
  })

  it('dispositionLabel resolves each posture key to its POSTURE_COPY label', () => {
    for (const row of POSTURE_COPY) {
      expect(dispositionLabel(row.disposition)).toBe(row.label)
    }
  })

  it('dispositionColor resolves each posture key to its POSTURE_COPY color', () => {
    for (const row of POSTURE_COPY) {
      expect(dispositionColor(row.disposition)).toBe(row.color)
    }
  })

  it('tierGroupLabel(2, postureKey) builds "Tier 2 — shortLabel" for each posture row', () => {
    for (const row of POSTURE_COPY) {
      expect(tierGroupLabel(2, row.disposition)).toBe(`Tier 2 — ${row.shortLabel}`)
    }
  })
})

describe('Tier 2 label — rebased for ADR-0067 (issue #6 PR)', () => {
  it('does not claim the traffic "may have got through" (false for LOG-only qualifying signals)', () => {
    expect(TIER_COPY[1].label.toLowerCase()).not.toMatch(/may have got(ten)? (in|through)/)
  })

  it('does not open with "Unconfirmed" (undersells that a qualifying assertion was made)', () => {
    expect(TIER_COPY[1].label.toLowerCase().startsWith('unconfirmed')).toBe(false)
  })

  it('does not claim "block status unknown" — ADR-0067 RC3 falsifies that as a Tier-2 premise, not authorizes it', () => {
    // ADR-0067 line 4 + RC3's own title: "the OCSF premise behind 'block
    // status unknown' is factually false" (OCSF disposition_id=19 Alert
    // asserts NOT-blocked, not unknown). This phrase must never reappear
    // as the general Tier-2 label.
    expect(TIER_COPY[1].label.toLowerCase()).not.toContain('block status unknown')
    expect(TIER_COPY[1].description.toLowerCase()).not.toContain('block status unknown')
  })

  it('states only what ADR-0067 D1 settles: a qualifying assertion/detection exists', () => {
    expect(TIER_COPY[1].label.toLowerCase()).toMatch(/flag/)
  })
})
