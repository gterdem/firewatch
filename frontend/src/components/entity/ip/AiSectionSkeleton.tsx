/**
 * AiSectionSkeleton — shaped skeleton placeholder for the AI analysis section.
 *
 * Rendered while the LLM call is in flight (phase='analyzing'). Shaped like the
 * final AI box (score bar, summary block, insight list) so the layout doesn't
 * shift when content arrives. Shows a staged status line instead of a bare spinner.
 *
 * SECURITY (ADR-0029 D3): no attacker-controlled values are rendered here.
 */

import { capModelName } from '../../../lib/modelName'

interface AiSectionSkeletonProps {
  /** Elapsed seconds since the AI call started (client-measured). */
  elapsedSeconds: number
  /** Model name from /health (e.g. "llama3.2"), or null when unknown. */
  modelName: string | null
}

/** A single shimmering placeholder bar. */
function SkeletonBar({ width = '100%', height = 10 }: { width?: string | number; height?: number }) {
  return (
    <span
      aria-hidden="true"
      style={{
        display: 'block',
        width,
        height,
        background: 'var(--fw-bg-card)',
        borderRadius: 4,
        opacity: 0.7,
        animation: 'fw-pulse 1.4s ease-in-out infinite',
      }}
    />
  )
}

export default function AiSectionSkeleton({ elapsedSeconds, modelName }: AiSectionSkeletonProps) {
  const safeModelName = capModelName(modelName)
  const modelLabel = safeModelName ? ` · ${safeModelName}` : ''
  const elapsedLabel = elapsedSeconds > 0 ? ` · ${elapsedSeconds}s` : ''

  return (
    <div
      aria-label="AI analysis in progress"
      data-testid="ai-section-skeleton"
      style={{
        background: 'var(--fw-bg-input)',
        border: '1px solid var(--fw-border-l)',
        borderRadius: 8,
        padding: 14,
        marginBottom: 16,
      }}
    >
      {/* Header row: AI icon + staged status text */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          marginBottom: 10,
          flexWrap: 'wrap',
        }}
      >
        <span aria-hidden="true" style={{ fontSize: 13 }}>🧠</span>
        <span
          style={{ fontSize: 13, color: 'var(--fw-accent)', fontWeight: 600 }}
          data-testid="ai-skeleton-status"
        >
          rule score ✓
        </span>
        <span style={{ fontSize: 12, color: 'var(--fw-t3)' }}>
          {`· local AI analyzing${modelLabel}~15s${elapsedLabel}`}
        </span>
      </div>

      {/* Score bar placeholder */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
        <SkeletonBar width={40} height={6} />
        <SkeletonBar width={60} height={6} />
        <SkeletonBar width={50} height={6} />
      </div>

      {/* Summary text placeholder */}
      <SkeletonBar width="90%" />
      <div style={{ marginTop: 6 }}>
        <SkeletonBar width="75%" />
      </div>
      <div style={{ marginTop: 6 }}>
        <SkeletonBar width="60%" />
      </div>

      {/* Insight list placeholders */}
      <div style={{ marginTop: 12, display: 'flex', flexDirection: 'column', gap: 5 }}>
        <SkeletonBar width="80%" height={8} />
        <SkeletonBar width="65%" height={8} />
        <SkeletonBar width="70%" height={8} />
      </div>
    </div>
  )
}
