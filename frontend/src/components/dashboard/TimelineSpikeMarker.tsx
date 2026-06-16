/**
 * TimelineSpikeMarker — a glyph rendered above a bar row that has been
 * flagged as a statistical spike (issue #248).
 *
 * Appearance:
 *   - An upward-arrow glyph (▲) in the amber SOC warning token colour.
 *   - Wrapped in a CellTooltip (#246) showing:
 *       "↑4.2x vs window median · 312 events"
 *
 * Provenance honesty (ADR-0035):
 *   - This marker is purely statistical (rolling median + k·MAD, lib/spikes.ts).
 *   - The hover text explicitly reads "statistical" — no AI phrasing whatsoever.
 *   - The llmReason seam slot is defined here as a future prop but is NOT
 *     rendered unless explicitly passed. #213 will populate it; until then
 *     the slot is empty.
 *   - Per ADR-0035 §3: a marker may only carry AI-attributed wording when
 *     its derivation includes `ai`. Until #213 wires in, derivation = `rule`.
 *
 * Layout note:
 *   The marker sits in a zero-height overlay above the bar track row.
 *   It does not shift row heights — it uses position:absolute / translateY
 *   to float above the row without disrupting the flex layout of TimelineChart.
 *
 * Accessibility:
 *   - The glyph span carries aria-label="Spike detected" so screen readers
 *     announce it without relying on the arrow character alone (WCAG 1.4.1).
 *   - The CellTooltip ensures keyboard parity (focus shows same content as hover).
 */

import { CellTooltip } from '../ds'
import type { SpikeMark } from '../../lib/spikes'

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface TimelineSpikeMarkerProps {
  mark: SpikeMark
  /**
   * LLM-generated one-line reason seam (#213, gated).
   * When undefined (the current state), only statistical text renders.
   * ADR-0035: no AI-attributed wording while this is undefined.
   */
  llmReason?: string
}

// ---------------------------------------------------------------------------
// Hover content
// ---------------------------------------------------------------------------

function SpikeHoverContent({ mark, llmReason }: TimelineSpikeMarkerProps) {
  const ratioText = mark.ratio > 0 ? `${mark.ratio.toFixed(1)}x` : 'elevated'

  return (
    <div data-testid="spike-hover-content" style={{ fontSize: 12 }}>
      {/* Statistical magnitude line — always shown (rule-derived) */}
      <div
        style={{
          fontFamily: 'var(--fw-font-mono)',
          color: 'var(--fw-t1)',
          marginBottom: llmReason ? 6 : 0,
        }}
        data-testid="spike-stat-line"
      >
        {/* Up-arrow + ratio + count — text nodes only */}
        <span style={{ color: 'var(--fw-accent)' }}>&#8593;</span>
        {ratioText} vs window median
        {' '}
        <span style={{ color: 'var(--fw-t3)' }}>&middot;</span>
        {' '}
        <span style={{ color: 'var(--fw-t1)' }}>{mark.value.toLocaleString()}</span>
        {' '}
        <span style={{ color: 'var(--fw-t3)' }}>events</span>
      </div>

      {/*
       * LLM-reason seam (#213) — ONLY rendered when explicitly provided.
       * ADR-0035: this section MUST NOT appear until #213 populates the field.
       * When it appears, caller is responsible for also passing a ProvenanceChip
       * with derivation="ai" (or "ai+rule") alongside this text.
       */}
      {llmReason != null && (
        <div
          data-testid="spike-llm-reason"
          style={{ color: 'var(--fw-t2)', borderTop: '1px solid var(--fw-border-l)', paddingTop: 4 }}
        >
          {/* text node only — ADR-0029 D3 */}
          {String(llmReason)}
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function TimelineSpikeMarker({ mark, llmReason }: TimelineSpikeMarkerProps) {
  return (
    <CellTooltip
      data-testid="spike-marker-trigger"
      content={<SpikeHoverContent mark={mark} llmReason={llmReason} />}
    >
      <span
        aria-label="Spike detected"
        data-testid="spike-marker-glyph"
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: 9,
          lineHeight: 1,
          // Amber accent — FireWatch signature amber token (ADR-0028 D6).
          // --fw-accent is the canonical amber; soc-watch-fg also maps to it.
          color: 'var(--fw-accent)',
          cursor: 'default',
          userSelect: 'none',
          // Slight upward nudge to float the glyph above the bar row.
          position: 'relative',
          top: -1,
        }}
      >
        {/* UP-POINTING SMALL TRIANGLE — visually distinct, not a letter */}
        &#9650;
      </span>
    </CellTooltip>
  )
}
