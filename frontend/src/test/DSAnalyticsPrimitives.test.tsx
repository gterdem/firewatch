/**
 * Unit tests for the MH-foundation DS analytic primitives (issue #200).
 *
 * Implements ADR-0035 (provenance tagging) + ADR-0036 (score/confidence
 * presentation) EARS acceptance criteria:
 *
 *   EARS 1 — Every risk score renders with a canonical band label; band
 *             boundaries come from threat_level / shared mapping (never
 *             component-local thresholds).
 *   EARS 2 — AI confidence is a word band; percentage NEVER rendered.
 *   EARS 3 — ProvenanceChip renders RULE / AI / AI+RULE with distinct,
 *             token-based styling (--fw-* tokens only).
 *   EARS 4 — IF no AI ran (null/undefined confidence), ConfidenceLabel
 *             SHALL render "n/a (AI off)".
 *   EARS 5 — Components render attacker-controlled values as text nodes
 *             only (XSS-safe); keyboard accessible where interactive.
 *   EARS 6 — Unit tests cover all three derivations, all confidence bands
 *             incl. boundary values (0.4, 0.7), and the n/a path.
 *
 * Also covers:
 *   - provenance.ts helpers (normaliseDerivation, confidenceToWord,
 *     scoreToSeverityBand, normaliseThreatLevel, token helpers).
 *   - RULES_ONLY_DEGRADED_WORDING constant export.
 *   - DS barrel export of all three components.
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import {
  ProvenanceChip,
  ScoreBadge,
  ConfidenceLabel,
} from '../components/ds'
import {
  normaliseDerivation,
  confidenceToWord,
  scoreToSeverityBand,
  normaliseThreatLevel,
  severityFgToken,
  severityBgToken,
  severityBorderToken,
  PROVENANCE_LABEL,
  SEVERITY_THRESHOLDS,
  CONFIDENCE_HIGH_THRESHOLD,
  CONFIDENCE_MEDIUM_THRESHOLD,
  RULES_ONLY_DEGRADED_WORDING,
} from '../lib/provenance'

// =============================================================================
// provenance.ts — library helpers
// =============================================================================

describe('provenance lib — normaliseDerivation', () => {
  it('returns "rule" for "rule"', () => {
    expect(normaliseDerivation('rule')).toBe('rule')
  })

  it('returns "ai" for "ai"', () => {
    expect(normaliseDerivation('ai')).toBe('ai')
  })

  it('returns "ai+rule" for "ai+rule"', () => {
    expect(normaliseDerivation('ai+rule')).toBe('ai+rule')
  })

  it('falls back to "rule" for unknown string', () => {
    expect(normaliseDerivation('unknown')).toBe('rule')
  })

  it('falls back to "rule" for null', () => {
    expect(normaliseDerivation(null)).toBe('rule')
  })

  it('falls back to "rule" for undefined', () => {
    expect(normaliseDerivation(undefined)).toBe('rule')
  })

  it('falls back to "rule" for empty string', () => {
    expect(normaliseDerivation('')).toBe('rule')
  })
})

describe('provenance lib — PROVENANCE_LABEL mapping', () => {
  it('maps rule → "RULE"', () => {
    expect(PROVENANCE_LABEL['rule']).toBe('RULE')
  })

  it('maps ai → "AI"', () => {
    expect(PROVENANCE_LABEL['ai']).toBe('AI')
  })

  it('maps ai+rule → "AI+RULE"', () => {
    expect(PROVENANCE_LABEL['ai+rule']).toBe('AI+RULE')
  })
})

describe('provenance lib — SEVERITY_THRESHOLDS (canonical engine bands)', () => {
  it('CRITICAL threshold is 76', () => {
    expect(SEVERITY_THRESHOLDS.CRITICAL).toBe(76)
  })

  it('HIGH threshold is 51', () => {
    expect(SEVERITY_THRESHOLDS.HIGH).toBe(51)
  })

  it('MEDIUM threshold is 26', () => {
    expect(SEVERITY_THRESHOLDS.MEDIUM).toBe(26)
  })

  it('LOW threshold is 0', () => {
    expect(SEVERITY_THRESHOLDS.LOW).toBe(0)
  })
})

describe('provenance lib — scoreToSeverityBand', () => {
  it('100 → CRITICAL', () => {
    expect(scoreToSeverityBand(100)).toBe('CRITICAL')
  })

  it('76 → CRITICAL (at boundary)', () => {
    expect(scoreToSeverityBand(76)).toBe('CRITICAL')
  })

  it('75 → HIGH (just below CRITICAL boundary)', () => {
    expect(scoreToSeverityBand(75)).toBe('HIGH')
  })

  it('51 → HIGH (at boundary)', () => {
    expect(scoreToSeverityBand(51)).toBe('HIGH')
  })

  it('50 → MEDIUM (just below HIGH boundary)', () => {
    expect(scoreToSeverityBand(50)).toBe('MEDIUM')
  })

  it('26 → MEDIUM (at boundary)', () => {
    expect(scoreToSeverityBand(26)).toBe('MEDIUM')
  })

  it('25 → LOW (just below MEDIUM boundary)', () => {
    expect(scoreToSeverityBand(25)).toBe('LOW')
  })

  it('0 → LOW', () => {
    expect(scoreToSeverityBand(0)).toBe('LOW')
  })
})

describe('provenance lib — normaliseThreatLevel', () => {
  it('CRITICAL → CRITICAL', () => {
    expect(normaliseThreatLevel('CRITICAL')).toBe('CRITICAL')
  })

  it('high (lowercase) → HIGH', () => {
    expect(normaliseThreatLevel('high')).toBe('HIGH')
  })

  it('Medium (mixed case) → MEDIUM', () => {
    expect(normaliseThreatLevel('Medium')).toBe('MEDIUM')
  })

  it('low → LOW', () => {
    expect(normaliseThreatLevel('low')).toBe('LOW')
  })

  it('unknown → LOW (safe under-state)', () => {
    expect(normaliseThreatLevel('unknown')).toBe('LOW')
  })

  it('null → LOW', () => {
    expect(normaliseThreatLevel(null)).toBe('LOW')
  })

  it('undefined → LOW', () => {
    expect(normaliseThreatLevel(undefined)).toBe('LOW')
  })
})

describe('provenance lib — severity token helpers (token-based, no raw hex)', () => {
  it.each(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const)(
    'severityFgToken(%s) returns a var(--fw-*) reference',
    (band) => {
      expect(severityFgToken(band)).toMatch(/^var\(--fw-/)
    },
  )

  it.each(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const)(
    'severityBgToken(%s) returns a var(--fw-tint-*) or rgba reference',
    (band) => {
      const result = severityBgToken(band)
      // Either a CSS var reference or an rgba() value from the tint set
      expect(result).toMatch(/^(var\(--fw-tint-|rgba\()/)
    },
  )

  it.each(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const)(
    'severityBorderToken(%s) returns a var(--fw-tint-*-bd) or rgba reference',
    (band) => {
      const result = severityBorderToken(band)
      expect(result).toMatch(/^(var\(--fw-tint-|rgba\()/)
    },
  )

  it('CRITICAL fg is var(--fw-red)', () => {
    expect(severityFgToken('CRITICAL')).toBe('var(--fw-red)')
  })

  it('HIGH fg is var(--fw-orange)', () => {
    expect(severityFgToken('HIGH')).toBe('var(--fw-orange)')
  })

  it('MEDIUM fg is var(--fw-blue)', () => {
    expect(severityFgToken('MEDIUM')).toBe('var(--fw-blue)')
  })

  it('LOW fg is var(--fw-green)', () => {
    expect(severityFgToken('LOW')).toBe('var(--fw-green)')
  })
})

describe('provenance lib — confidenceToWord', () => {
  it('null → "n/a (AI off)"', () => {
    expect(confidenceToWord(null)).toBe('n/a (AI off)')
  })

  it('undefined → "n/a (AI off)"', () => {
    expect(confidenceToWord(undefined)).toBe('n/a (AI off)')
  })

  it('0.7 (boundary) → "High"', () => {
    expect(confidenceToWord(0.7)).toBe('High')
  })

  it('0.71 → "High"', () => {
    expect(confidenceToWord(0.71)).toBe('High')
  })

  it('1.0 → "High"', () => {
    expect(confidenceToWord(1.0)).toBe('High')
  })

  it('0.69 → "Medium" (just below High boundary)', () => {
    expect(confidenceToWord(0.69)).toBe('Medium')
  })

  it('0.4 (boundary) → "Medium"', () => {
    expect(confidenceToWord(0.4)).toBe('Medium')
  })

  it('0.5 → "Medium"', () => {
    expect(confidenceToWord(0.5)).toBe('Medium')
  })

  it('0.39 → "Low" (just below Medium boundary)', () => {
    expect(confidenceToWord(0.39)).toBe('Low')
  })

  it('0.0 → "Low"', () => {
    expect(confidenceToWord(0.0)).toBe('Low')
  })
})

describe('provenance lib — CONFIDENCE thresholds', () => {
  it('CONFIDENCE_HIGH_THRESHOLD is 0.7 (aligned with AI boost gate)', () => {
    expect(CONFIDENCE_HIGH_THRESHOLD).toBe(0.7)
  })

  it('CONFIDENCE_MEDIUM_THRESHOLD is 0.4', () => {
    expect(CONFIDENCE_MEDIUM_THRESHOLD).toBe(0.4)
  })
})

describe('provenance lib — RULES_ONLY_DEGRADED_WORDING', () => {
  it('exports the standard degraded-state wording (ADR-0035 §4)', () => {
    expect(RULES_ONLY_DEGRADED_WORDING).toBe('Rules-only mode · AI engine offline')
  })
})

// =============================================================================
// ProvenanceChip component
// =============================================================================

describe('ProvenanceChip — ADR-0035 derivation rendering (EARS 3)', () => {
  it('renders "RULE" label for derivation="rule"', () => {
    render(<ProvenanceChip derivation="rule" />)
    expect(screen.getByText('RULE')).toBeInTheDocument()
  })

  it('renders "AI" label for derivation="ai"', () => {
    render(<ProvenanceChip derivation="ai" />)
    expect(screen.getByText('AI')).toBeInTheDocument()
  })

  it('renders "AI+RULE" label for derivation="ai+rule"', () => {
    render(<ProvenanceChip derivation="ai+rule" />)
    expect(screen.getByText('AI+RULE')).toBeInTheDocument()
  })

  it('sets data-derivation="rule" for "rule"', () => {
    render(<ProvenanceChip derivation="rule" data-testid="chip" />)
    expect(screen.getByTestId('chip').getAttribute('data-derivation')).toBe('rule')
  })

  it('sets data-derivation="ai" for "ai"', () => {
    render(<ProvenanceChip derivation="ai" data-testid="chip" />)
    expect(screen.getByTestId('chip').getAttribute('data-derivation')).toBe('ai')
  })

  it('sets data-derivation="ai+rule" for "ai+rule"', () => {
    render(<ProvenanceChip derivation="ai+rule" data-testid="chip" />)
    expect(screen.getByTestId('chip').getAttribute('data-derivation')).toBe('ai+rule')
  })

  it('unknown derivation falls back to "rule" (does not crash)', () => {
    // eslint-disable-next-line no-restricted-syntax -- intentional out-of-whitelist value for fallback test
    render(<ProvenanceChip derivation="mystery" data-testid="chip" />)
    const el = screen.getByTestId('chip')
    expect(el).toBeInTheDocument()
    expect(el.textContent).toBe('RULE')
    expect(el.getAttribute('data-derivation')).toBe('rule')
  })

  it('RULE chip uses muted/neutral styling (token-based, no raw hex)', () => {
    const { container } = render(<ProvenanceChip derivation="rule" />)
    const el = container.querySelector('.fw-provenance-chip') as HTMLElement
    // RULE uses --fw-bg-input background and --fw-t2 color
    expect(el.style.background).toContain('var(--fw-bg-input)')
    expect(el.style.color).toContain('var(--fw-t2)')
  })

  it('AI chip uses amber accent token (visually distinct from RULE)', () => {
    const { container } = render(<ProvenanceChip derivation="ai" />)
    const el = container.querySelector('.fw-provenance-chip') as HTMLElement
    expect(el.style.color).toContain('var(--fw-accent)')
  })

  it('AI+RULE chip uses amber accent token', () => {
    const { container } = render(<ProvenanceChip derivation="ai+rule" />)
    const el = container.querySelector('.fw-provenance-chip') as HTMLElement
    expect(el.style.color).toContain('var(--fw-accent)')
  })

  it('RULE and AI chips have visually distinct backgrounds', () => {
    const { container: c1 } = render(<ProvenanceChip derivation="rule" />)
    const { container: c2 } = render(<ProvenanceChip derivation="ai" />)
    const rule = (c1.querySelector('.fw-provenance-chip') as HTMLElement).style.background
    const ai = (c2.querySelector('.fw-provenance-chip') as HTMLElement).style.background
    expect(rule).not.toBe(ai)
  })

  it('has role="status" (accessibility)', () => {
    render(<ProvenanceChip derivation="rule" />)
    expect(screen.getByRole('status')).toBeInTheDocument()
  })

  it('has aria-label describing the derivation', () => {
    render(<ProvenanceChip derivation="ai" data-testid="chip" />)
    const el = screen.getByTestId('chip')
    expect(el.getAttribute('aria-label')).toContain('AI')
  })

  it('accepts and forwards extra HTML attributes', () => {
    render(<ProvenanceChip derivation="rule" data-testid="fwd" />)
    expect(screen.getByTestId('fwd')).toBeInTheDocument()
  })

  it('accepts extra className', () => {
    const { container } = render(<ProvenanceChip derivation="ai" className="my-class" />)
    expect(container.querySelector('.my-class')).toBeInTheDocument()
  })
})

// DS barrel export check
describe('DS barrel — ProvenanceChip exported', () => {
  it('ProvenanceChip is a function (exported from ds barrel)', () => {
    expect(typeof ProvenanceChip).toBe('function')
  })
})

// =============================================================================
// ScoreBadge component
// =============================================================================

describe('ScoreBadge — ADR-0036 D1 band label + score (EARS 1)', () => {
  it('renders score value as text', () => {
    render(<ScoreBadge score={100} threatLevel="CRITICAL" />)
    // The score is rendered inside the badge
    expect(screen.getByRole('img')).toBeInTheDocument()
    const badge = screen.getByRole('img')
    expect(badge.textContent).toContain('100')
  })

  it('renders CRITICAL band label', () => {
    render(<ScoreBadge score={100} threatLevel="CRITICAL" />)
    expect(screen.getByRole('img').textContent).toContain('CRITICAL')
  })

  it('renders HIGH band label', () => {
    render(<ScoreBadge score={72} threatLevel="HIGH" />)
    expect(screen.getByRole('img').textContent).toContain('HIGH')
  })

  it('renders MEDIUM band label', () => {
    render(<ScoreBadge score={40} threatLevel="MEDIUM" />)
    expect(screen.getByRole('img').textContent).toContain('MEDIUM')
  })

  it('renders LOW band label', () => {
    render(<ScoreBadge score={10} threatLevel="LOW" />)
    expect(screen.getByRole('img').textContent).toContain('LOW')
  })

  it('renders "Risk" prefix in the badge text', () => {
    render(<ScoreBadge score={80} threatLevel="CRITICAL" />)
    expect(screen.getByRole('img').textContent).toContain('Risk')
  })

  it('sets data-band attribute to the normalised band', () => {
    render(<ScoreBadge score={90} threatLevel="CRITICAL" data-testid="badge" />)
    expect(screen.getByTestId('badge').getAttribute('data-band')).toBe('CRITICAL')
  })

  it('sets data-score attribute to the score value', () => {
    render(<ScoreBadge score={55} threatLevel="HIGH" data-testid="badge" />)
    expect(screen.getByTestId('badge').getAttribute('data-score')).toBe('55')
  })

  it('normalises lowercase threat_level (case-insensitive)', () => {
    render(<ScoreBadge score={80} threatLevel="critical" data-testid="badge" />)
    expect(screen.getByTestId('badge').getAttribute('data-band')).toBe('CRITICAL')
    expect(screen.getByTestId('badge').textContent).toContain('CRITICAL')
  })

  it('unknown threat_level falls back to LOW without crashing', () => {
    render(<ScoreBadge score={100} threatLevel="unknown" data-testid="badge" />)
    const el = screen.getByTestId('badge')
    expect(el).toBeInTheDocument()
    expect(el.getAttribute('data-band')).toBe('LOW')
  })

  it('CRITICAL band uses red color token (--fw-red)', () => {
    const { container } = render(<ScoreBadge score={100} threatLevel="CRITICAL" />)
    const el = container.querySelector('.fw-score-badge') as HTMLElement
    expect(el.style.color).toContain('var(--fw-red)')
  })

  it('HIGH band uses orange color token (--fw-orange)', () => {
    const { container } = render(<ScoreBadge score={60} threatLevel="HIGH" />)
    const el = container.querySelector('.fw-score-badge') as HTMLElement
    expect(el.style.color).toContain('var(--fw-orange)')
  })

  it('MEDIUM band uses blue color token (--fw-blue)', () => {
    const { container } = render(<ScoreBadge score={40} threatLevel="MEDIUM" />)
    const el = container.querySelector('.fw-score-badge') as HTMLElement
    expect(el.style.color).toContain('var(--fw-blue)')
  })

  it('LOW band uses green color token (--fw-green)', () => {
    const { container } = render(<ScoreBadge score={10} threatLevel="LOW" />)
    const el = container.querySelector('.fw-score-badge') as HTMLElement
    expect(el.style.color).toContain('var(--fw-green)')
  })

  it('has role="img" with aria-label describing score and band', () => {
    render(<ScoreBadge score={82} threatLevel="CRITICAL" />)
    const el = screen.getByRole('img')
    const label = el.getAttribute('aria-label') ?? ''
    expect(label).toContain('82')
    expect(label).toContain('CRITICAL')
  })

  it('score rendered in mono font (--fw-font-mono)', () => {
    const { container } = render(<ScoreBadge score={77} threatLevel="CRITICAL" />)
    const monoSpan = container.querySelector('span[style*="fw-font-mono"]')
    expect(monoSpan).not.toBeNull()
    expect(monoSpan?.textContent).toContain('77')
  })

  it('does NOT render a "?" trigger without onBreakdownClick', () => {
    render(<ScoreBadge score={100} threatLevel="CRITICAL" />)
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })

  it('renders a "?" trigger button when onBreakdownClick is provided', () => {
    render(
      <ScoreBadge score={100} threatLevel="CRITICAL" onBreakdownClick={() => {}} />,
    )
    expect(screen.getByRole('button', { name: 'Why this score?' })).toBeInTheDocument()
  })

  it('"?" trigger is keyboard-accessible (fires click handler)', () => {
    const handler = vi.fn()
    render(<ScoreBadge score={100} threatLevel="CRITICAL" onBreakdownClick={handler} />)
    const btn = screen.getByRole('button', { name: 'Why this score?' })
    fireEvent.click(btn)
    expect(handler).toHaveBeenCalledOnce()
  })

  it('accepts extra className', () => {
    const { container } = render(<ScoreBadge score={50} threatLevel="MEDIUM" className="extra" />)
    expect(container.querySelector('.extra')).toBeInTheDocument()
  })

  it('DOES NOT render a raw percentage anywhere (ADR-0036 D2 — no naked number)', () => {
    // The badge content should show label text, not "%" character
    render(<ScoreBadge score={72} threatLevel="HIGH" />)
    const badgeText = screen.getByRole('img').textContent ?? ''
    expect(badgeText).not.toContain('%')
  })
})

// DS barrel export check
describe('DS barrel — ScoreBadge exported', () => {
  it('ScoreBadge is a function (exported from ds barrel)', () => {
    expect(typeof ScoreBadge).toBe('function')
  })
})

// =============================================================================
// ConfidenceLabel component
// =============================================================================

describe('ConfidenceLabel — ADR-0036 D2 word confidence (EARS 2, EARS 4)', () => {
  it('renders "n/a (AI off)" when confidence is null (EARS 4)', () => {
    render(<ConfidenceLabel confidence={null} />)
    expect(screen.getByText('n/a (AI off)')).toBeInTheDocument()
  })

  it('renders "n/a (AI off)" when confidence is undefined (EARS 4)', () => {
    render(<ConfidenceLabel confidence={undefined} />)
    expect(screen.getByText('n/a (AI off)')).toBeInTheDocument()
  })

  it('renders "High" for confidence 0.7 (boundary value)', () => {
    render(<ConfidenceLabel confidence={0.7} />)
    expect(screen.getByText('High')).toBeInTheDocument()
  })

  it('renders "High" for confidence 0.9', () => {
    render(<ConfidenceLabel confidence={0.9} />)
    expect(screen.getByText('High')).toBeInTheDocument()
  })

  it('renders "High" for confidence 1.0', () => {
    render(<ConfidenceLabel confidence={1.0} />)
    expect(screen.getByText('High')).toBeInTheDocument()
  })

  it('renders "Medium" for confidence 0.69 (just below High boundary)', () => {
    render(<ConfidenceLabel confidence={0.69} />)
    expect(screen.getByText('Medium')).toBeInTheDocument()
  })

  it('renders "Medium" for confidence 0.4 (boundary value)', () => {
    render(<ConfidenceLabel confidence={0.4} />)
    expect(screen.getByText('Medium')).toBeInTheDocument()
  })

  it('renders "Medium" for confidence 0.5', () => {
    render(<ConfidenceLabel confidence={0.5} />)
    expect(screen.getByText('Medium')).toBeInTheDocument()
  })

  it('renders "Low" for confidence 0.39 (just below Medium boundary)', () => {
    render(<ConfidenceLabel confidence={0.39} />)
    expect(screen.getByText('Low')).toBeInTheDocument()
  })

  it('renders "Low" for confidence 0.0', () => {
    render(<ConfidenceLabel confidence={0.0} />)
    expect(screen.getByText('Low')).toBeInTheDocument()
  })

  it('NEVER renders a percentage (EARS 2)', () => {
    // Confidence 0.85 should render "High", not "85%"
    render(<ConfidenceLabel confidence={0.85} />)
    const el = screen.getByRole('status')
    expect(el.textContent).not.toContain('%')
    expect(el.textContent).toBe('High')
  })

  it('NEVER renders "0%" even when confidence is 0 (EARS 2)', () => {
    render(<ConfidenceLabel confidence={0} />)
    const el = screen.getByRole('status')
    expect(el.textContent).not.toContain('%')
    expect(el.textContent).toBe('Low')
  })

  it('sets data-confidence-word attribute', () => {
    render(<ConfidenceLabel confidence={0.8} data-testid="cl" />)
    expect(screen.getByTestId('cl').getAttribute('data-confidence-word')).toBe('High')
  })

  it('sets data-confidence-word="n/a (AI off)" when null', () => {
    render(<ConfidenceLabel confidence={null} data-testid="cl" />)
    expect(screen.getByTestId('cl').getAttribute('data-confidence-word')).toBe('n/a (AI off)')
  })

  it('has role="status" (accessibility)', () => {
    render(<ConfidenceLabel confidence={0.8} />)
    expect(screen.getByRole('status')).toBeInTheDocument()
  })

  it('has aria-label mentioning "High" for High confidence', () => {
    render(<ConfidenceLabel confidence={0.8} data-testid="cl" />)
    const label = screen.getByTestId('cl').getAttribute('aria-label') ?? ''
    expect(label.toLowerCase()).toContain('high')
  })

  it('has aria-label mentioning "AI engine did not run" for null confidence', () => {
    render(<ConfidenceLabel confidence={null} data-testid="cl" />)
    const label = screen.getByTestId('cl').getAttribute('aria-label') ?? ''
    expect(label.toLowerCase()).toContain('did not run')
  })

  it('High confidence uses green color token (--fw-green)', () => {
    const { container } = render(<ConfidenceLabel confidence={0.8} />)
    const el = container.querySelector('.fw-confidence-label') as HTMLElement
    expect(el.style.color).toContain('var(--fw-green)')
  })

  it('Medium confidence uses amber accent token (--fw-accent)', () => {
    const { container } = render(<ConfidenceLabel confidence={0.5} />)
    const el = container.querySelector('.fw-confidence-label') as HTMLElement
    expect(el.style.color).toContain('var(--fw-accent)')
  })

  it('Low confidence uses red color token (--fw-red)', () => {
    const { container } = render(<ConfidenceLabel confidence={0.1} />)
    const el = container.querySelector('.fw-confidence-label') as HTMLElement
    expect(el.style.color).toContain('var(--fw-red)')
  })

  it('"n/a (AI off)" uses muted faint text token (--fw-t3)', () => {
    const { container } = render(<ConfidenceLabel confidence={null} />)
    const el = container.querySelector('.fw-confidence-label') as HTMLElement
    expect(el.style.color).toContain('var(--fw-t3)')
  })

  it('"n/a (AI off)" has no badge background (transparent)', () => {
    const { container } = render(<ConfidenceLabel confidence={null} />)
    const el = container.querySelector('.fw-confidence-label') as HTMLElement
    expect(el.style.background).toBe('transparent')
  })

  it('accepts extra className', () => {
    const { container } = render(<ConfidenceLabel confidence={0.5} className="custom" />)
    expect(container.querySelector('.custom')).toBeInTheDocument()
  })
})

// DS barrel export check
describe('DS barrel — ConfidenceLabel exported', () => {
  it('ConfidenceLabel is a function (exported from ds barrel)', () => {
    expect(typeof ConfidenceLabel).toBe('function')
  })
})

// =============================================================================
// XSS safety (EARS 5 / ADR-0029 D3)
// =============================================================================

describe('XSS safety — attacker-controlled values render as text nodes (EARS 5)', () => {
  it('ProvenanceChip does not interpolate derivation into innerHTML', () => {
    // Inject a mock XSS payload as derivation — should render as "RULE" (fallback)
    const payload = '<img src=x onerror=alert(1)>'
    const { container } = render(
      <ProvenanceChip derivation={payload} data-testid="xss" />,
    )
    // The injected string should NOT appear in the DOM as a raw element
    expect(container.querySelector('img[src="x"]')).toBeNull()
    // Should fall back to RULE label safely
    expect(screen.getByTestId('xss').textContent).toBe('RULE')
  })

  it('ScoreBadge score renders as numeric text node, not raw HTML', () => {
    // Score is a number — React renders it as text automatically
    render(<ScoreBadge score={100} threatLevel="CRITICAL" data-testid="badge" />)
    // The badge text should contain the number but no HTML injection
    const text = screen.getByTestId('badge').textContent ?? ''
    expect(text).not.toContain('<')
    expect(text).not.toContain('>')
  })

  it('ScoreBadge with XSS threat_level falls back safely to LOW band', () => {
    render(
      <ScoreBadge score={100} threatLevel='<script>alert(1)</script>' data-testid="badge" />,
    )
    const el = screen.getByTestId('badge')
    expect(el.getAttribute('data-band')).toBe('LOW')
    expect(el.querySelector('script')).toBeNull()
  })
})

// =============================================================================
// Integration: combined usage
// =============================================================================

describe('Combined usage — primitives compose without conflict', () => {
  it('renders ProvenanceChip + ScoreBadge + ConfidenceLabel side-by-side', () => {
    render(
      <div>
        <ProvenanceChip derivation="ai+rule" data-testid="prov" />
        <ScoreBadge score={80} threatLevel="CRITICAL" data-testid="score" />
        <ConfidenceLabel confidence={0.8} data-testid="conf" />
      </div>,
    )
    expect(screen.getByTestId('prov').textContent).toBe('AI+RULE')
    expect(screen.getByTestId('score').textContent).toContain('CRITICAL')
    expect(screen.getByTestId('conf').textContent).toBe('High')
  })

  it('rules-only scenario: RULE chip + CRITICAL score + n/a confidence', () => {
    render(
      <div>
        <ProvenanceChip derivation="rule" data-testid="prov" />
        <ScoreBadge score={100} threatLevel="CRITICAL" data-testid="score" />
        <ConfidenceLabel confidence={null} data-testid="conf" />
      </div>,
    )
    expect(screen.getByTestId('prov').textContent).toBe('RULE')
    expect(screen.getByTestId('score').textContent).toContain('CRITICAL')
    expect(screen.getByTestId('conf').textContent).toBe('n/a (AI off)')
  })
})
