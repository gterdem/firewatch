/**
 * DriftDiffRow — collapsed row for one changed scenario (MK-9, issue #414).
 *
 * Shows a one-line summary of a drift diff entry; keyboard-expandable to
 * reveal DriftDiffDetail (side-by-side baseline-vs-candidate).
 *
 * issue #477 — directional / de-escalation-emphasis polish:
 *   - Each row shows a concrete story sentence, not a bare badge pair.
 *   - Direction (escalation vs de-escalation) is visually distinguished.
 *   - De-escalations (model became LESS alarmed about a known attack) receive
 *     a "Review this" treatment using the existing red tint tokens — this is
 *     the dangerous case that the analyst must scrutinise.
 *
 * WCAG:
 *   - row is a <button> (keyboard focusable, role="button").
 *   - aria-expanded reflects open/closed state.
 *   - Focus ring via :focus-visible (token-based, not raw hex).
 *
 * ADR-0029 D3: scenario, verdict strings, model names rendered as text nodes.
 * ADR-0043: bounded pane — this row expands inline; no inner scrollbar.
 */

import { useState } from 'react'
import type { DriftDiff } from '../../../api/types'
import { DriftDiffDetail } from './DriftDiffDetail'
import { driftDirection, diffStorySentence } from './driftUtils'

export interface DriftDiffRowProps {
  /** The changed-scenario diff entry. */
  diff: DriftDiff
  /** Model ID of the baseline run (forwarded to DriftDiffDetail). */
  baselineModel: string
  /** Model ID of the candidate run (forwarded to DriftDiffDetail). */
  candidateModel: string
  /** 1-based row index for labelling purposes. */
  index: number
}

/** Badge colour for a verdict level (CRITICAL/HIGH/MEDIUM/LOW). */
function verdictColor(verdict: string): string {
  switch (verdict.toUpperCase()) {
    case 'CRITICAL': return 'var(--fw-red)'
    case 'HIGH': return 'var(--fw-accent)'
    case 'MEDIUM': return 'var(--fw-yellow, var(--fw-accent))'
    case 'LOW': return 'var(--fw-green)'
    default: return 'var(--fw-t2)'
  }
}

/** Arrow character for escalation vs de-escalation direction. */
function driftArrow(baseline: string, candidate: string): { label: string; color: string } {
  const SEVERITY_ORDER: Record<string, number> = {
    CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0,
  }
  const baseRank = SEVERITY_ORDER[baseline.toUpperCase()] ?? 0
  const candRank = SEVERITY_ORDER[candidate.toUpperCase()] ?? 0

  if (candRank > baseRank) return { label: '↑', color: 'var(--fw-red)' }
  if (candRank < baseRank) return { label: '↓', color: 'var(--fw-green)' }
  return { label: '~', color: 'var(--fw-t3)' }
}

/**
 * One collapsed drift row — click/Enter/Space to expand side-by-side detail.
 *
 * De-escalations (new model less alarmed) receive:
 *   - A "Review this" badge with red tint background (fw-tint-red / fw-tint-red-bd).
 *   - A "de-escalation" direction label in red text.
 *   - A left-border accent and tinted row background for at-a-glance scanning.
 *
 * Escalations (new model more cautious) receive:
 *   - An "escalation" direction label in muted text (notable but not the risk).
 *
 * Both use existing token colors only — no raw hex (adherence lint compliance).
 */
export function DriftDiffRow({ diff, baselineModel, candidateModel, index }: DriftDiffRowProps) {
  const [expanded, setExpanded] = useState(false)
  const arrow = driftArrow(diff.baseline_verdict, diff.candidate_verdict)
  const direction = driftDirection(diff.baseline_verdict, diff.candidate_verdict)
  const isDeescalation = direction === 'deescalation'
  const storySentence = diffStorySentence(
    diff.scenario,
    diff.baseline_verdict,
    diff.candidate_verdict,
  )

  return (
    <div
      data-testid="drift-diff-row"
      data-direction={direction}
      style={{
        borderBottom: '1px solid var(--fw-border)',
        // De-escalation rows get a subtle red tint background — the risk signal
        background: isDeescalation ? 'var(--fw-tint-red)' : 'transparent',
        borderLeft: isDeescalation
          ? '3px solid var(--fw-tint-red-bd)'
          : '3px solid transparent',
      }}
    >
      {/* Collapsed header row — acts as a button */}
      <button
        type="button"
        aria-expanded={expanded}
        aria-controls={`drift-diff-detail-${index}`}
        onClick={() => setExpanded((v) => !v)}
        data-testid="drift-diff-toggle"
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          width: '100%',
          padding: '8px 0 4px',
          background: 'none',
          border: 'none',
          cursor: 'pointer',
          textAlign: 'left' as const,
          fontFamily: 'var(--fw-font-ui)',
          color: 'var(--fw-t1)',
        }}
      >
        {/* Chevron indicator */}
        <span
          aria-hidden="true"
          style={{
            fontSize: 'var(--fw-fs-xs)',
            color: 'var(--fw-t3)',
            transform: expanded ? 'rotate(90deg)' : 'rotate(0deg)',
            display: 'inline-block',
            transition: 'transform 0.15s',
            flexShrink: 0,
          }}
        >
          ▶
        </span>

        {/* Scenario name — synthetic fixture key (ADR-0029 D3: text node) */}
        <span
          style={{
            flex: 1,
            fontSize: 'var(--fw-fs-xs)',
            fontFamily: 'var(--fw-font-mono)',
            color: 'var(--fw-t2)',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap' as const,
          }}
          data-testid="drift-diff-scenario"
        >
          {String(diff.scenario)}
        </span>

        {/* Baseline verdict */}
        <span
          style={{
            fontSize: 'var(--fw-fs-xs)',
            color: verdictColor(diff.baseline_verdict),
            fontWeight: 'var(--fw-fw-medium)',
            flexShrink: 0,
          }}
          data-testid="drift-diff-baseline-badge"
        >
          {String(diff.baseline_verdict)}
        </span>

        {/* Arrow direction — escalation or de-escalation */}
        <span
          aria-hidden="true"
          style={{ color: arrow.color, fontWeight: 'bold', flexShrink: 0 }}
          data-testid="drift-diff-arrow"
        >
          {arrow.label}
        </span>

        {/* Candidate verdict */}
        <span
          style={{
            fontSize: 'var(--fw-fs-xs)',
            color: verdictColor(diff.candidate_verdict),
            fontWeight: 'var(--fw-fw-medium)',
            flexShrink: 0,
          }}
          data-testid="drift-diff-candidate-badge"
        >
          {String(diff.candidate_verdict)}
        </span>

        {/* Direction label — "de-escalation" or "escalation" (text node, ADR-0029 D3) */}
        <span
          style={{
            fontSize: 'var(--fw-fs-2xs)',
            fontFamily: 'var(--fw-font-ui)',
            color: isDeescalation ? 'var(--fw-red)' : 'var(--fw-t3)',
            flexShrink: 0,
          }}
          data-testid="drift-diff-direction-label"
        >
          {direction === 'deescalation'
            ? 'de-escalation'
            : direction === 'escalation'
              ? 'escalation'
              : ''}
        </span>

        {/*
          * "Review this" badge — de-escalation only (new model less alarmed = risky).
          * Uses only existing token colors (adherence lint: no raw hex).
          * ADR-0029 D3: label text is a literal string constant — safe text node.
          */}
        {isDeescalation && (
          <span
            style={{
              fontSize: 'var(--fw-fs-2xs)',
              fontFamily: 'var(--fw-font-ui)',
              fontWeight: 'var(--fw-fw-medium)',
              color: 'var(--fw-red)',
              background: 'var(--fw-tint-red)',
              border: '1px solid var(--fw-tint-red-bd)',
              borderRadius: 'var(--fw-r-xs)',
              padding: '1px 6px',
              flexShrink: 0,
              letterSpacing: 'var(--fw-ls-label)',
              textTransform: 'uppercase' as const,
            }}
            data-testid="drift-diff-review-badge"
          >
            Review this
          </span>
        )}
      </button>

      {/*
        * Story sentence — concrete framing of the verdict change.
        * e.g. "On a WAF attack probe, your old model called this HIGH;
        *        the new model calls it MEDIUM — the new model is less alarmed."
        * ADR-0029 D3: all values interpolated as text (no dangerouslySetInnerHTML).
        */}
      <div
        style={{
          paddingLeft: 28,
          paddingBottom: 8,
          paddingRight: 4,
          fontSize: 'var(--fw-fs-2xs)',
          color: isDeescalation ? 'var(--fw-t2)' : 'var(--fw-t3)',
          fontFamily: 'var(--fw-font-ui)',
          fontStyle: 'italic',
          lineHeight: 1.4,
        }}
        data-testid="drift-diff-story"
      >
        {/* Plain text node — storySentence constructed from server-validated strings */}
        {storySentence}
      </div>

      {/* Expanded detail — side-by-side baseline-vs-candidate */}
      {expanded && (
        <div
          id={`drift-diff-detail-${index}`}
          role="region"
          aria-label={`Drift detail for scenario ${String(diff.scenario)}`}
          style={{ paddingBottom: 12, paddingLeft: 4 }}
        >
          <DriftDiffDetail
            diff={diff}
            baselineModel={baselineModel}
            candidateModel={candidateModel}
          />
        </div>
      )}
    </div>
  )
}
