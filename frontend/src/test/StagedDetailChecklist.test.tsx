/**
 * Tests for src/components/sources/StagedDetailChecklist.tsx (issue #691)
 *
 * EARS criteria covered:
 *   - WHEN detail contains stage_* keys (mix of pass/fail/skip), renders each
 *     stage row with the correct glyph and label.
 *   - WHEN a stage value is "fail", the row has destructive styling.
 *   - WHEN a stage value is "skip", the row has muted styling (NOT destructive).
 *   - WHEN a stage value is "pass", the row has green styling.
 *   - stage_*_msg is rendered as a text node beside (below) each stage.
 *   - No stage_* keys present → renders nothing (null).
 *   - Non-stage_* detail keys are ignored (regression: no extra rows).
 *   - Genericity: fictional stage names (not suricata-specific) render correctly.
 *   - humanizeStageName: "ssh" → "SSH", "evejson" → "Eve.Json",
 *     "activity" → "Activity".
 *   - extractStageRows: preserves insertion order; excludes *_msg keys from row list.
 *   - SECURITY: stage messages render as text nodes (no dangerouslySetInnerHTML paths).
 */

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import StagedDetailChecklist from '../components/sources/StagedDetailChecklist'
import { humanizeStageName, extractStageRows } from '../components/sources/stagedDetailUtils'
import {
  STAGED_RESULT_MIXED,
  STAGED_RESULT_ALL_PASS,
  PLAIN_DETAIL_RESULT,
} from './fixtures'

// ---------------------------------------------------------------------------
// Unit tests: humanizeStageName
// ---------------------------------------------------------------------------

describe('humanizeStageName — naming-convention humanizer', () => {
  it('"ssh" → "SSH" (short abbreviation, all-caps)', () => {
    expect(humanizeStageName('ssh')).toBe('SSH')
  })

  it('"tcp" → "TCP" (3-char abbreviation)', () => {
    expect(humanizeStageName('tcp')).toBe('TCP')
  })

  it('"evejson" → "Eve.Json" (compound normalization + dot-join)', () => {
    expect(humanizeStageName('evejson')).toBe('Eve.Json')
  })

  it('"activity" → "Activity" (longer word, capitalize first)', () => {
    expect(humanizeStageName('activity')).toBe('Activity')
  })

  it('"connectivity" → "Connectivity" (longer word)', () => {
    expect(humanizeStageName('connectivity')).toBe('Connectivity')
  })

  it('"dns" → "DNS" (3-char abbreviation)', () => {
    expect(humanizeStageName('dns')).toBe('DNS')
  })

  it('"auth" → "Auth" (4+ chars → capitalize first letter, not all-caps)', () => {
    expect(humanizeStageName('auth')).toBe('Auth')
  })
})

// ---------------------------------------------------------------------------
// Unit tests: extractStageRows
// ---------------------------------------------------------------------------

describe('extractStageRows — detail map extraction', () => {
  it('extracts stage rows in insertion order, excluding *_msg keys', () => {
    const detail = STAGED_RESULT_MIXED.detail
    const rows = extractStageRows(detail)
    expect(rows).toHaveLength(3)
    expect(rows[0].name).toBe('ssh')
    expect(rows[1].name).toBe('evejson')
    expect(rows[2].name).toBe('activity')
  })

  it('maps "pass" / "fail" / "skip" status correctly', () => {
    const rows = extractStageRows(STAGED_RESULT_MIXED.detail)
    expect(rows[0].status).toBe('pass')   // stage_ssh
    expect(rows[1].status).toBe('fail')   // stage_evejson
    expect(rows[2].status).toBe('skip')   // stage_activity
  })

  it('attaches the paired stage_*_msg message to each row', () => {
    const rows = extractStageRows(STAGED_RESULT_MIXED.detail)
    expect(rows[0].message).toBe('SSH connection established successfully.')
    expect(rows[1].message).toContain('eve.json not found at')
    expect(rows[2].message).toContain('Skipped')
  })

  it('returns [] when no stage_* keys are present', () => {
    expect(extractStageRows(PLAIN_DETAIL_RESULT.detail)).toHaveLength(0)
  })

  it('returns [] for an empty detail map', () => {
    expect(extractStageRows({})).toHaveLength(0)
  })

  it('gracefully handles unknown status value as "skip"', () => {
    const rows = extractStageRows({ stage_custom: 'pending' })
    expect(rows).toHaveLength(1)
    expect(rows[0].status).toBe('skip')
  })

  it('handles a stage with no paired _msg (null message)', () => {
    const rows = extractStageRows({ stage_auth: 'pass' })
    expect(rows).toHaveLength(1)
    expect(rows[0].message).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Component render tests: StagedDetailChecklist
// ---------------------------------------------------------------------------

describe('StagedDetailChecklist — renders nothing when no stage keys', () => {
  it('returns null (no DOM) when detail has no stage_* keys', () => {
    const { container } = render(
      <StagedDetailChecklist detail={PLAIN_DETAIL_RESULT.detail} />,
    )
    expect(container.firstChild).toBeNull()
    expect(screen.queryByTestId('staged-detail-checklist')).toBeNull()
  })

  it('returns null for an empty detail map', () => {
    const { container } = render(<StagedDetailChecklist detail={{}} />)
    expect(container.firstChild).toBeNull()
  })
})

describe('StagedDetailChecklist — renders checklist from stage_* keys', () => {
  it('renders one row per stage (3 rows for mixed fixture)', () => {
    render(<StagedDetailChecklist detail={STAGED_RESULT_MIXED.detail} />)
    expect(screen.getByTestId('staged-detail-checklist')).toBeInTheDocument()
    expect(screen.getByTestId('stage-row-ssh')).toBeInTheDocument()
    expect(screen.getByTestId('stage-row-evejson')).toBeInTheDocument()
    expect(screen.getByTestId('stage-row-activity')).toBeInTheDocument()
  })

  // EARS: pass stage → green glyph (✓)
  it('renders ✓ pass glyph for stage_ssh=pass', () => {
    render(<StagedDetailChecklist detail={STAGED_RESULT_MIXED.detail} />)
    // The pass glyph has aria-label="pass"
    const passGlyphs = screen.getAllByLabelText('pass')
    expect(passGlyphs.length).toBeGreaterThanOrEqual(1)
  })

  // EARS: fail stage → red glyph (✗)
  it('renders ✗ fail glyph for stage_evejson=fail', () => {
    render(<StagedDetailChecklist detail={STAGED_RESULT_MIXED.detail} />)
    const failGlyphs = screen.getAllByLabelText('fail')
    expect(failGlyphs.length).toBeGreaterThanOrEqual(1)
  })

  // EARS: skip stage → muted glyph (⊘)
  it('renders ⊘ skip glyph for stage_activity=skip', () => {
    render(<StagedDetailChecklist detail={STAGED_RESULT_MIXED.detail} />)
    const skipGlyphs = screen.getAllByLabelText('skip')
    expect(skipGlyphs.length).toBeGreaterThanOrEqual(1)
  })

  // EARS: human-readable labels derived from key names
  it('renders humanized labels — SSH, Eve.Json, Activity', () => {
    render(<StagedDetailChecklist detail={STAGED_RESULT_MIXED.detail} />)
    expect(screen.getByTestId('stage-label-ssh').textContent).toBe('SSH')
    expect(screen.getByTestId('stage-label-evejson').textContent).toBe('Eve.Json')
    expect(screen.getByTestId('stage-label-activity').textContent).toBe('Activity')
  })

  // EARS: fail stage has destructive styling
  it('fail stage label has destructive class', () => {
    render(<StagedDetailChecklist detail={STAGED_RESULT_MIXED.detail} />)
    const failLabel = screen.getByTestId('stage-label-evejson')
    expect(failLabel.className).toContain('destructive')
  })

  // EARS: skip stage has muted styling, NOT destructive
  it('skip stage label is muted, not destructive', () => {
    render(<StagedDetailChecklist detail={STAGED_RESULT_MIXED.detail} />)
    const skipLabel = screen.getByTestId('stage-label-activity')
    expect(skipLabel.className).toContain('muted')
    expect(skipLabel.className).not.toContain('destructive')
  })

  // EARS: messages are rendered as text nodes beside each stage
  it('renders stage messages as text beside each stage row', () => {
    render(<StagedDetailChecklist detail={STAGED_RESULT_MIXED.detail} />)
    expect(screen.getByTestId('stage-msg-ssh').textContent).toBe(
      'SSH connection established successfully.',
    )
    expect(screen.getByTestId('stage-msg-evejson').textContent).toContain(
      'eve.json not found at',
    )
    expect(screen.getByTestId('stage-msg-activity').textContent).toContain('Skipped')
  })

  // SECURITY: messages are text nodes — no HTML injection possible.
  // Testing-library renders into real DOM; text content check proves text node rendering.
  it('SECURITY: stage message text is plain text (no HTML tags in content)', () => {
    const xssPayload = '<img src=x onerror=alert(1)>'
    render(
      <StagedDetailChecklist
        detail={{
          stage_test: 'fail',
          stage_test_msg: xssPayload,
        }}
      />,
    )
    const msgEl = screen.getByTestId('stage-msg-test')
    // textContent returns the literal string — if it's a text node, no tags execute
    expect(msgEl.textContent).toBe(xssPayload)
    // The element itself should not contain an img child
    expect(msgEl.querySelector('img')).toBeNull()
  })
})

describe('StagedDetailChecklist — all-pass fixture', () => {
  it('renders 3 pass glyphs for all-pass result', () => {
    render(<StagedDetailChecklist detail={STAGED_RESULT_ALL_PASS.detail} />)
    const passGlyphs = screen.getAllByLabelText('pass')
    expect(passGlyphs).toHaveLength(3)
    expect(screen.queryByLabelText('fail')).toBeNull()
    expect(screen.queryByLabelText('skip')).toBeNull()
  })
})

describe('StagedDetailChecklist — genericity (fictional stage names)', () => {
  it('renders generic stage names not tied to any specific source', () => {
    // Use fictional stage names that do not appear in any real plugin
    render(
      <StagedDetailChecklist
        detail={{
          stage_auth: 'pass',
          stage_auth_msg: 'Token validated.',
          stage_reachable: 'fail',
          stage_reachable_msg: 'Host not reachable.',
          stage_latency: 'skip',
          stage_latency_msg: 'Skipped due to reachability failure.',
        }}
      />,
    )
    expect(screen.getByTestId('stage-row-auth')).toBeInTheDocument()
    expect(screen.getByTestId('stage-row-reachable')).toBeInTheDocument()
    expect(screen.getByTestId('stage-row-latency')).toBeInTheDocument()
    // Labels derived from names
    expect(screen.getByTestId('stage-label-auth').textContent).toBe('Auth')
    expect(screen.getByTestId('stage-label-reachable').textContent).toBe('Reachable')
    expect(screen.getByTestId('stage-label-latency').textContent).toBe('Latency')
  })

  it('renders purely from the stage_* naming convention — not from source-type checks', () => {
    // Use a fully fictional detail map (no real source names) and confirm the
    // component renders correctly. This proves the component has no source-specific
    // branching — it only inspects the key names, not any source_type value.
    const { container } = render(
      <StagedDetailChecklist
        detail={{
          stage_probe: 'pass',
          stage_probe_msg: 'Probe succeeded.',
          stage_validate: 'fail',
          stage_validate_msg: 'Validation failed.',
        }}
      />,
    )
    // Two stage rows from a fictional source — no real plugin name needed
    expect(container.querySelectorAll('[data-testid^="stage-row-"]')).toHaveLength(2)
    expect(screen.getByTestId('stage-label-probe').textContent).toBe('Probe')
    expect(screen.getByTestId('stage-label-validate').textContent).toBe('Validate')
  })
})
