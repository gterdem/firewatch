/**
 * Tests for lib/escalationCopy.ts — the centralized escalation-tier copy
 * table (issue #6 / ADR-0058 / ADR-0059).
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
 */
import { describe, it, expect } from 'vitest'
import {
  TIER_COPY,
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
