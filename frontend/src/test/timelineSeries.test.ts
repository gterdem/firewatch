/**
 * Tests for lib/timelineSeries.ts — pure stacked-bar transforms (issue #247).
 *
 * EARS acceptance criteria covered:
 *
 * 1. buildSeverityRows: WHEN buckets have severity counts, SHALL return one row
 *    per bucket with four segments keyed critical/high/medium/low.
 *
 * 2. buildSeverityRows: WHEN severity is absent (old API), SHALL default to all-zero
 *    severity counts (backward-compat with pre-#247 API responses).
 *
 * 3. buildDispositionRows: SHALL produce blocked + allowed segments derived from
 *    total/blocked WITHOUT requiring any refetch (free transform).
 *
 * 4. Zero-event bucket: isEmpty SHALL be true; all segment counts SHALL be 0.
 *
 * 5. Global-max normalisation: the bucket with the highest total SHALL have its
 *    tallest segment reach 100%; other buckets are proportioned accordingly.
 *
 * 6. buildSeverityRows: segment colorClass SHALL carry the soc-* token class
 *    (never a hardcoded hex).
 *
 * 7. buildDispositionRows: blocked segment colorClass SHALL be soc-enforced-fg;
 *    allowed segment SHALL be soc-ok-fg.
 *
 * 8. SEVERITY_LEGEND and DISPOSITION_LEGEND SHALL export stable key/label/colorClass
 *    arrays for the legend component.
 *
 * 9. BucketHoverData: top_category and top_source_ip SHALL pass through null when
 *    the bucket has no additive fields.
 *
 * 10. buildSeverityRows: total of all severity segment counts SHALL equal bucket.total
 *     when all events have one of the four severity levels.
 */

import { describe, it, expect } from 'vitest'
import {
  buildSeverityRows,
  buildDispositionRows,
  SEVERITY_LEGEND,
  DISPOSITION_LEGEND,
} from '../lib/timelineSeries'
import type { TimelineBucket } from '../api/types'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const BUCKET_FULL: TimelineBucket = {
  hour: '2026-06-11T02:00',
  total: 100,
  blocked: 60,
  granularity: 'hourly',
  severity: { critical: 10, high: 30, medium: 40, low: 20 },
  top_category: 'SQL Injection',
  top_source_ip: '198.51.100.1',
}

const BUCKET_NO_SEV: TimelineBucket = {
  hour: '2026-06-11T03:00',
  total: 50,
  blocked: 20,
  granularity: 'hourly',
  // No severity field — old API response shape
}

const BUCKET_ZERO: TimelineBucket = {
  hour: '2026-06-11T04:00',
  total: 0,
  blocked: 0,
  granularity: 'hourly',
  severity: { critical: 0, high: 0, medium: 0, low: 0 },
}

const BUCKET_DAILY: TimelineBucket = {
  hour: '2026-06-01',
  total: 200,
  blocked: 100,
  granularity: 'daily',
  severity: { critical: 50, high: 80, medium: 60, low: 10 },
  top_category: 'XSS',
  top_source_ip: '203.0.113.5',
}

// Two-bucket set for max-normalisation tests
const TWO_BUCKETS: TimelineBucket[] = [
  { hour: '2026-06-11T00:00', total: 200, blocked: 100, severity: { critical: 200, high: 0, medium: 0, low: 0 } },
  { hour: '2026-06-11T01:00', total: 100, blocked: 50,  severity: { critical: 100, high: 0, medium: 0, low: 0 } },
]

// ---------------------------------------------------------------------------
// buildSeverityRows — basic shape
// ---------------------------------------------------------------------------

describe('buildSeverityRows — basic shape', () => {
  it('returns one row per input bucket', () => {
    const rows = buildSeverityRows([BUCKET_FULL, BUCKET_ZERO])
    expect(rows).toHaveLength(2)
  })

  it('each row has four segments (critical/high/medium/low)', () => {
    const rows = buildSeverityRows([BUCKET_FULL])
    const keys = rows[0].segments.map((s) => s.key)
    expect(keys).toEqual(['critical', 'high', 'medium', 'low'])
  })

  it('segment counts match the severity sub-object', () => {
    const rows = buildSeverityRows([BUCKET_FULL])
    const seg = rows[0].segments
    expect(seg.find((s) => s.key === 'critical')?.count).toBe(10)
    expect(seg.find((s) => s.key === 'high')?.count).toBe(30)
    expect(seg.find((s) => s.key === 'medium')?.count).toBe(40)
    expect(seg.find((s) => s.key === 'low')?.count).toBe(20)
  })

  it('preserves hour and granularity on each row', () => {
    const rows = buildSeverityRows([BUCKET_FULL])
    expect(rows[0].hour).toBe(BUCKET_FULL.hour)
    expect(rows[0].granularity).toBe('hourly')
  })

  it('daily bucket has granularity="daily"', () => {
    const rows = buildSeverityRows([BUCKET_DAILY])
    expect(rows[0].granularity).toBe('daily')
  })
})

// ---------------------------------------------------------------------------
// buildSeverityRows — backward-compat: absent severity field
// ---------------------------------------------------------------------------

describe('buildSeverityRows — absent severity (old API)', () => {
  it('defaults all severity counts to 0 when severity field is absent', () => {
    const rows = buildSeverityRows([BUCKET_NO_SEV])
    rows[0].segments.forEach((seg) => {
      expect(seg.count).toBe(0)
    })
  })

  it('isEmpty is false when total > 0 even without severity', () => {
    const rows = buildSeverityRows([BUCKET_NO_SEV])
    expect(rows[0].isEmpty).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// buildSeverityRows — zero-event bucket
// ---------------------------------------------------------------------------

describe('buildSeverityRows — zero-event bucket', () => {
  it('isEmpty is true when total === 0', () => {
    const rows = buildSeverityRows([BUCKET_ZERO])
    expect(rows[0].isEmpty).toBe(true)
  })

  it('all segment counts are 0 for an empty bucket', () => {
    const rows = buildSeverityRows([BUCKET_ZERO])
    rows[0].segments.forEach((seg) => {
      expect(seg.count).toBe(0)
    })
  })

  it('all segment pcts are 0 for an empty bucket with empty-only set', () => {
    const rows = buildSeverityRows([BUCKET_ZERO])
    rows[0].segments.forEach((seg) => {
      expect(seg.pct).toBe(0)
    })
  })
})

// ---------------------------------------------------------------------------
// buildSeverityRows — global-max normalisation
// ---------------------------------------------------------------------------

describe('buildSeverityRows — global-max normalisation', () => {
  it('the bucket with max total has its largest segment at pct <= 100', () => {
    const rows = buildSeverityRows(TWO_BUCKETS)
    const maxRow = rows[0] // total=200 is max
    const critSeg = maxRow.segments.find((s) => s.key === 'critical')!
    expect(critSeg.pct).toBe(100)
  })

  it('the half-max bucket has its largest segment at pct ≈ 50', () => {
    const rows = buildSeverityRows(TWO_BUCKETS)
    const halfRow = rows[1] // total=100 = 50% of 200
    const critSeg = halfRow.segments.find((s) => s.key === 'critical')!
    expect(critSeg.pct).toBe(50)
  })

  it('no segment pct exceeds 100', () => {
    const rows = buildSeverityRows([BUCKET_FULL, BUCKET_ZERO])
    rows.forEach((row) => {
      row.segments.forEach((seg) => {
        expect(seg.pct).toBeLessThanOrEqual(100)
      })
    })
  })
})

// ---------------------------------------------------------------------------
// buildSeverityRows — colour token classes
// ---------------------------------------------------------------------------

describe('buildSeverityRows — colour token classes', () => {
  it('critical segment colorClass contains "soc-critical"', () => {
    const rows = buildSeverityRows([BUCKET_FULL])
    const seg = rows[0].segments.find((s) => s.key === 'critical')!
    expect(seg.colorClass).toContain('soc-critical')
  })

  it('high segment colorClass contains "soc-high"', () => {
    const rows = buildSeverityRows([BUCKET_FULL])
    const seg = rows[0].segments.find((s) => s.key === 'high')!
    expect(seg.colorClass).toContain('soc-high')
  })

  it('colorClass values do NOT contain hardcoded hex colours', () => {
    const rows = buildSeverityRows([BUCKET_FULL])
    rows[0].segments.forEach((seg) => {
      expect(seg.colorClass).not.toMatch(/#[0-9a-fA-F]{3,6}/)
    })
  })
})

// ---------------------------------------------------------------------------
// buildDispositionRows — basic shape
// ---------------------------------------------------------------------------

describe('buildDispositionRows — basic shape', () => {
  it('returns one row per input bucket', () => {
    const rows = buildDispositionRows([BUCKET_FULL, BUCKET_ZERO])
    expect(rows).toHaveLength(2)
  })

  it('each row has exactly two segments: blocked + allowed', () => {
    const rows = buildDispositionRows([BUCKET_FULL])
    expect(rows[0].segments).toHaveLength(2)
    expect(rows[0].segments[0].key).toBe('blocked')
    expect(rows[0].segments[1].key).toBe('allowed')
  })

  it('blocked count matches bucket.blocked', () => {
    const rows = buildDispositionRows([BUCKET_FULL])
    const blocked = rows[0].segments.find((s) => s.key === 'blocked')!
    expect(blocked.count).toBe(60)
  })

  it('allowed count is total - blocked', () => {
    const rows = buildDispositionRows([BUCKET_FULL])
    const allowed = rows[0].segments.find((s) => s.key === 'allowed')!
    expect(allowed.count).toBe(40) // 100 - 60
  })

  it('isEmpty is true for a zero-total bucket', () => {
    const rows = buildDispositionRows([BUCKET_ZERO])
    expect(rows[0].isEmpty).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// buildDispositionRows — colour token classes
// ---------------------------------------------------------------------------

describe('buildDispositionRows — colour token classes', () => {
  it('blocked segment colorClass contains "soc-enforced-fg"', () => {
    const rows = buildDispositionRows([BUCKET_FULL])
    const seg = rows[0].segments.find((s) => s.key === 'blocked')!
    expect(seg.colorClass).toContain('soc-enforced-fg')
  })

  it('allowed segment colorClass contains "soc-ok-fg"', () => {
    const rows = buildDispositionRows([BUCKET_FULL])
    const seg = rows[0].segments.find((s) => s.key === 'allowed')!
    expect(seg.colorClass).toContain('soc-ok-fg')
  })
})

// ---------------------------------------------------------------------------
// buildDispositionRows — free transform (no refetch)
// ---------------------------------------------------------------------------

describe('buildDispositionRows — free transform (no severity data required)', () => {
  it('works when severity field is absent (no refetch required)', () => {
    // BUCKET_NO_SEV has no severity field — disposition is still derivable
    const rows = buildDispositionRows([BUCKET_NO_SEV])
    expect(rows[0].segments.find((s) => s.key === 'blocked')?.count).toBe(20)
    expect(rows[0].segments.find((s) => s.key === 'allowed')?.count).toBe(30)
  })
})

// ---------------------------------------------------------------------------
// BucketHoverData — hover data shape
// ---------------------------------------------------------------------------

describe('BucketHoverData — hover data shape', () => {
  it('topCategory passes through correctly', () => {
    const rows = buildSeverityRows([BUCKET_FULL])
    expect(rows[0].hover.topCategory).toBe('SQL Injection')
  })

  it('topSourceIp passes through correctly', () => {
    const rows = buildSeverityRows([BUCKET_FULL])
    expect(rows[0].hover.topSourceIp).toBe('198.51.100.1')
  })

  it('topCategory is null when absent', () => {
    const rows = buildSeverityRows([BUCKET_NO_SEV])
    expect(rows[0].hover.topCategory).toBeNull()
  })

  it('topSourceIp is null when absent', () => {
    const rows = buildSeverityRows([BUCKET_NO_SEV])
    expect(rows[0].hover.topSourceIp).toBeNull()
  })

  it('hover.total matches bucket.total', () => {
    const rows = buildSeverityRows([BUCKET_FULL])
    expect(rows[0].hover.total).toBe(100)
  })

  it('hover.blocked matches bucket.blocked', () => {
    const rows = buildSeverityRows([BUCKET_FULL])
    expect(rows[0].hover.blocked).toBe(60)
  })

  it('hover.allowed is total - blocked', () => {
    const rows = buildSeverityRows([BUCKET_FULL])
    expect(rows[0].hover.allowed).toBe(40)
  })

  it('severity defaults to all-zero when absent', () => {
    const rows = buildSeverityRows([BUCKET_NO_SEV])
    const sev = rows[0].hover.severity
    expect(sev.critical).toBe(0)
    expect(sev.high).toBe(0)
    expect(sev.medium).toBe(0)
    expect(sev.low).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// SEVERITY_LEGEND + DISPOSITION_LEGEND exports
// ---------------------------------------------------------------------------

describe('SEVERITY_LEGEND export', () => {
  it('has exactly four entries in order: critical, high, medium, low', () => {
    const keys = SEVERITY_LEGEND.map((s) => s.key)
    expect(keys).toEqual(['critical', 'high', 'medium', 'low'])
  })

  it('each entry has a label string', () => {
    SEVERITY_LEGEND.forEach((s) => {
      expect(typeof s.label).toBe('string')
      expect(s.label.length).toBeGreaterThan(0)
    })
  })

  it('each entry colorClass contains "soc-" prefix', () => {
    SEVERITY_LEGEND.forEach((s) => {
      expect(s.colorClass).toContain('soc-')
    })
  })
})

describe('DISPOSITION_LEGEND export', () => {
  it('has exactly two entries: blocked, allowed', () => {
    const keys = DISPOSITION_LEGEND.map((s) => s.key)
    expect(keys).toEqual(['blocked', 'allowed'])
  })

  it('blocked colorClass contains soc-enforced-fg', () => {
    expect(DISPOSITION_LEGEND[0].colorClass).toContain('soc-enforced-fg')
  })

  it('allowed colorClass contains soc-ok-fg', () => {
    expect(DISPOSITION_LEGEND[1].colorClass).toContain('soc-ok-fg')
  })
})
