/**
 * Tests for src/components/threats/SourceProvenanceBadges.tsx
 *
 * EARS criteria (issue #88 MC.3):
 *   - Two source_types → two badges with correct human labels (correlation case).
 *   - One source_type → one badge, no "correlated" label.
 *   - Empty array → nothing rendered (no crash, no empty chip).
 *   - undefined / null → nothing rendered (no crash).
 *   - Unknown source_type key → graceful generic label (title-case fallback).
 *   - Security: source_types values rendered as text nodes, never innerHTML.
 *
 * ADR-0024 modular-UI principle: no per-source code. Tests verify that the
 * component renders generically from whatever source_types the server returns.
 */

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import SourceProvenanceBadges from '../components/threats/SourceProvenanceBadges'
import { sourceTypeLabel } from '../components/threats/sourceTypeLabel'

// ---------------------------------------------------------------------------
// sourceTypeLabel unit tests
// ---------------------------------------------------------------------------

describe('sourceTypeLabel()', () => {
  it('maps "suricata" → "Suricata"', () => {
    expect(sourceTypeLabel('suricata')).toBe('Suricata')
  })

  it('maps "azure_waf" → "Azure WAF"', () => {
    expect(sourceTypeLabel('azure_waf')).toBe('Azure WAF')
  })

  it('maps "syslog" → "Syslog"', () => {
    expect(sourceTypeLabel('syslog')).toBe('Syslog')
  })

  it('returns title-cased fallback for unknown key with underscores', () => {
    expect(sourceTypeLabel('my_custom_source')).toBe('My Custom Source')
  })

  it('returns title-cased fallback for unknown key with hyphens', () => {
    expect(sourceTypeLabel('cloud-waf-v2')).toBe('Cloud Waf V2')
  })

  it('returns title-cased fallback for plain unknown key', () => {
    expect(sourceTypeLabel('crowdstrike')).toBe('Crowdstrike')
  })

  it('returns "?" for empty string', () => {
    expect(sourceTypeLabel('')).toBe('?')
  })
})

// ---------------------------------------------------------------------------
// SourceProvenanceBadges component tests
// ---------------------------------------------------------------------------

describe('SourceProvenanceBadges', () => {
  // EARS: two source_types → two badges with correct labels (correlation case)
  it('renders two badges with correct labels when two source_types are given', () => {
    render(<SourceProvenanceBadges sourceTypes={['azure_waf', 'suricata']} />)

    const badges = screen.getAllByTestId('source-provenance-badge')
    expect(badges).toHaveLength(2)
    expect(badges[0]).toHaveTextContent('Azure WAF')
    expect(badges[1]).toHaveTextContent('Suricata')
  })

  // EARS: two source_types → "correlated" label visible
  it('shows "correlated" label when more than one source_type is present', () => {
    render(<SourceProvenanceBadges sourceTypes={['azure_waf', 'suricata']} />)

    expect(screen.getByTestId('source-correlated-label')).toBeInTheDocument()
    expect(screen.getByTestId('source-correlated-label')).toHaveTextContent('correlated')
  })

  // EARS: container has accessible aria-label describing correlation
  it('has aria-label describing correlation when multiple sources', () => {
    render(<SourceProvenanceBadges sourceTypes={['azure_waf', 'suricata']} />)

    const container = screen.getByTestId('source-provenance-badges')
    expect(container).toHaveAttribute('aria-label', expect.stringContaining('Correlated'))
    expect(container).toHaveAttribute('aria-label', expect.stringContaining('Azure WAF'))
    expect(container).toHaveAttribute('aria-label', expect.stringContaining('Suricata'))
  })

  // EARS: one source_type → one badge, no "correlated" label
  it('renders one badge and no correlated label when only one source_type', () => {
    render(<SourceProvenanceBadges sourceTypes={['suricata']} />)

    const badges = screen.getAllByTestId('source-provenance-badge')
    expect(badges).toHaveLength(1)
    expect(badges[0]).toHaveTextContent('Suricata')
    expect(screen.queryByTestId('source-correlated-label')).toBeNull()
  })

  // EARS: one source_type → aria-label describes the single source
  it('has aria-label describing single source when one source_type', () => {
    render(<SourceProvenanceBadges sourceTypes={['suricata']} />)

    const container = screen.getByTestId('source-provenance-badges')
    expect(container).toHaveAttribute('aria-label', 'Source: Suricata')
  })

  // EARS: empty array → nothing rendered (no crash, no chip)
  it('renders nothing when sourceTypes is empty array', () => {
    const { container } = render(<SourceProvenanceBadges sourceTypes={[]} />)
    expect(container.firstChild).toBeNull()
  })

  // EARS: undefined → nothing rendered (no crash)
  it('renders nothing when sourceTypes is undefined', () => {
    const { container } = render(<SourceProvenanceBadges sourceTypes={undefined} />)
    expect(container.firstChild).toBeNull()
  })

  // EARS: null → nothing rendered (no crash)
  it('renders nothing when sourceTypes is null', () => {
    const { container } = render(<SourceProvenanceBadges sourceTypes={null} />)
    expect(container.firstChild).toBeNull()
  })

  // EARS: unknown source_type key → graceful generic label (title-case fallback)
  it('renders a graceful generic label for unknown source_type key', () => {
    render(<SourceProvenanceBadges sourceTypes={['my_new_source']} />)

    const badges = screen.getAllByTestId('source-provenance-badge')
    expect(badges).toHaveLength(1)
    // Generic fallback: title-case the key
    expect(badges[0]).toHaveTextContent('My New Source')
  })

  // EARS: unknown source_type in multi-source set → still renders correctly
  it('renders unknown source_type alongside known sources without crashing', () => {
    render(<SourceProvenanceBadges sourceTypes={['suricata', 'future_source']} />)

    const badges = screen.getAllByTestId('source-provenance-badge')
    expect(badges).toHaveLength(2)
    expect(badges[0]).toHaveTextContent('Suricata')
    expect(badges[1]).toHaveTextContent('Future Source')
    // Still shows "correlated" because there are 2 sources
    expect(screen.getByTestId('source-correlated-label')).toBeInTheDocument()
  })

  // Security: source_types values rendered as text — not innerHTML
  it('renders source_type values as text nodes, not innerHTML', () => {
    // Even if source_type looks like an XSS payload, it must be inert text.
    // The sourceTypeLabel fallback title-cases the key, so the rendered text
    // will be a transformed version — but it must never execute as a script.
    render(<SourceProvenanceBadges sourceTypes={['<script>alert("xss")</script>']} />)

    const badges = screen.getAllByTestId('source-provenance-badge')
    expect(badges).toHaveLength(1)

    // The badge renders *something* as text content (the transformed label)
    expect(badges[0].textContent).toBeTruthy()

    // No live <script> element injected by the badge should contain xss payload
    document.querySelectorAll('script').forEach((el) => {
      expect(el.textContent).not.toContain('xss')
    })

    // No <img> with onerror (guards against img-based XSS injection)
    expect(document.querySelectorAll('img[onerror]').length).toBe(0)
  })

  // Three sources — all three badges render, all correlated
  it('renders three badges when three source_types are given', () => {
    render(<SourceProvenanceBadges sourceTypes={['suricata', 'azure_waf', 'syslog']} />)

    const badges = screen.getAllByTestId('source-provenance-badge')
    expect(badges).toHaveLength(3)
    expect(screen.getByTestId('source-correlated-label')).toBeInTheDocument()
  })
})
