/**
 * DriftDiffDetail — side-by-side baseline-vs-candidate comparison pane (MK-9).
 *
 * Renders the expanded detail for one changed scenario in the drift report.
 * Both sides carry an AI ProvenanceChip with the authoring model named
 * (ADR-0035 — model identity is part of honest provenance).
 *
 * Layout: two columns (flex, wraps on narrow screens):
 *   Left  — Baseline verdict (model name, verdict, ConfidenceLabel, summary prose)
 *   Right — Candidate verdict (same structure, different model name)
 *
 * SECURITY (ADR-0029 D3):
 *   - baseline_summary / candidate_summary are model-authored synthetic scenario
 *     outputs — rendered as text nodes only (never dangerouslySetInnerHTML).
 *   - scenario name is a synthetic fixture key — text node only.
 *   - model names are server-validated strings — text node only.
 *
 * ADR-0035: Both sides carry an AI ProvenanceChip. The chip label names the
 * authoring model so the analyst sees exactly which model produced each verdict.
 * Drift is a comparison between two AI verdicts — never RULE-chipped.
 *
 * ADR-0036: ConfidenceLabel provides word-banded confidence (never a raw %).
 * ADR-0043 D1: all numbers/text come from the drift report — never fabricated.
 */

import type { DriftDiff } from '../../../api/types'
import { ProvenanceChip, ConfidenceLabel } from '../../ds'

export interface DriftDiffDetailProps {
  /** The changed-scenario diff entry from the drift report. */
  diff: DriftDiff
  /** Model ID of the baseline run (named on the left chip, ADR-0035). */
  baselineModel: string
  /** Model ID of the candidate run (named on the right chip, ADR-0035). */
  candidateModel: string
}

/** Inline style for one side column. */
const SIDE_STYLE: React.CSSProperties = {
  flex: '1 1 200px',
  minWidth: 0,
  display: 'flex',
  flexDirection: 'column',
  gap: 6,
  padding: '10px 12px',
  background: 'var(--fw-bg-input)',
  border: '1px solid var(--fw-border)',
  borderRadius: 'var(--fw-r-xs)',
}

/** Label style for the small field labels. */
const LABEL_STYLE: React.CSSProperties = {
  fontSize: 'var(--fw-fs-2xs)',
  color: 'var(--fw-t3)',
  textTransform: 'uppercase' as const,
  letterSpacing: 'var(--fw-ls-label)',
  fontFamily: 'var(--fw-font-ui)',
}

/** Value style for the main verdict level text. */
const VALUE_STYLE: React.CSSProperties = {
  fontSize: 'var(--fw-fs-body)',
  fontWeight: 'var(--fw-fw-medium)',
  color: 'var(--fw-t1)',
  fontFamily: 'var(--fw-font-ui)',
}

/** Summary prose style — model-authored, text node only (ADR-0029 D3). */
const PROSE_STYLE: React.CSSProperties = {
  fontSize: 'var(--fw-fs-xs)',
  color: 'var(--fw-t2)',
  fontFamily: 'var(--fw-font-ui)',
  fontStyle: 'italic',
}

/**
 * One side column (baseline or candidate).
 * `modelName` is shown inside the AI chip label for ADR-0035 model identity.
 */
function SideColumn({
  side,
  verdict,
  confidence,
  summary,
  modelName,
}: {
  side: 'baseline' | 'candidate'
  verdict: string
  confidence: number
  summary: string
  modelName: string
}) {
  const sideLabel = side === 'baseline' ? 'Baseline' : 'Candidate'
  return (
    <div
      style={SIDE_STYLE}
      data-testid={`drift-diff-${side}`}
      aria-label={`${sideLabel} verdict: ${verdict}, model ${modelName}`}
    >
      {/* ADR-0035: AI chip with model name — both sides are AI-authored verdicts */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
        <span style={LABEL_STYLE}>{sideLabel}</span>
        {/*
         * ProvenanceChip derivation='ai' — both sides are AI model output.
         * Model name is shown in adjacent text per ADR-0035 (model identity is
         * part of honest provenance; it is NOT inside the chip's text content
         * because ProvenanceChip only renders the derivation label).
         */}
        <ProvenanceChip
          derivation="ai"
          data-testid={`drift-diff-${side}-chip`}
          aria-label={`Derivation: AI (LLM-authored) — authored by ${modelName}`}
        />
        {/* Model name — text node (ADR-0029 D3, server-validated model ID) */}
        <span
          style={{
            fontSize: 'var(--fw-fs-2xs)',
            color: 'var(--fw-t3)',
            fontFamily: 'var(--fw-font-mono)',
          }}
          data-testid={`drift-diff-${side}-model`}
        >
          {String(modelName)}
        </span>
      </div>

      {/* Verdict level — text node */}
      <div>
        <div style={LABEL_STYLE}>Verdict</div>
        <div
          style={VALUE_STYLE}
          data-testid={`drift-diff-${side}-verdict`}
        >
          {/* ADR-0029 D3: model-validated verdict string — text node */}
          {String(verdict)}
        </div>
      </div>

      {/* Confidence — ADR-0036 word-banded (never a raw %) */}
      <div>
        <div style={LABEL_STYLE}>Confidence</div>
        <ConfidenceLabel
          confidence={confidence}
          data-testid={`drift-diff-${side}-confidence`}
        />
      </div>

      {/* Summary prose — model-authored, text node only (ADR-0029 D3) */}
      <div>
        <div style={LABEL_STYLE}>Action</div>
        <div
          style={PROSE_STYLE}
          data-testid={`drift-diff-${side}-summary`}
        >
          {/* model-authored synthetic output — text node; never dangerouslySetInnerHTML */}
          {String(summary)}
        </div>
      </div>
    </div>
  )
}

/**
 * Side-by-side expanded detail for one changed scenario.
 *
 * Both sides carry AI chips (ADR-0035 — both are AI model outputs).
 * The authoring model name is displayed next to each chip so the analyst
 * knows exactly which model produced each verdict.
 */
export function DriftDiffDetail({ diff, baselineModel, candidateModel }: DriftDiffDetailProps) {
  return (
    <div
      data-testid="drift-diff-detail"
      style={{
        display: 'flex',
        gap: 8,
        flexWrap: 'wrap',
        paddingTop: 8,
      }}
    >
      <SideColumn
        side="baseline"
        verdict={diff.baseline_verdict}
        confidence={diff.baseline_confidence}
        summary={diff.baseline_summary}
        modelName={baselineModel}
      />
      <SideColumn
        side="candidate"
        verdict={diff.candidate_verdict}
        confidence={diff.candidate_confidence}
        summary={diff.candidate_summary}
        modelName={candidateModel}
      />
    </div>
  )
}
