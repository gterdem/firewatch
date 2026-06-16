/**
 * SourceProvenanceBadges — renders the source_types provenance for a ThreatScore.
 *
 * EARS (issue #88 MC.3):
 *   - WHEN source_types contains one entry, one badge is shown.
 *   - WHEN source_types contains multiple entries (e.g. ["azure_waf","suricata"]),
 *     all badges are shown — the correlation signal is visually distinct.
 *   - WHEN source_types is empty or undefined, nothing is rendered (no crash).
 *
 * ADR-0024 / modular-UI principle: ZERO per-source code.
 *   The component renders whatever the server returns — a new source appears
 *   automatically; no UI edit is ever needed.
 *
 * SECURITY (ADR-0029 D3): source_types values are server-provided enums but are
 * still rendered as React text nodes — NEVER via dangerouslySetInnerHTML.
 *
 * ADR-0028 D6 / issue #96:
 *   Badge colors derive from the SOC semantic token set (socTokens.ts).
 *   Single-source: token-styled badge for that source.
 *   Correlated (multi-source): each badge uses its source token; a
 *   "correlated" label appears in the medium/watch token color to signal
 *   the multi-source aggregation without inventing a new color.
 *
 * The sourceTypeLabel mapping lives in ./sourceTypeLabel.ts (separated to
 * satisfy the react-refresh/only-export-components lint rule).
 */

import { sourceTypeLabel } from './sourceTypeLabel'
import { sourceTypeBadgeClasses } from '../../lib/socTokens'

interface SourceProvenanceBadgesProps {
  /** source_types field from ThreatScore / DetailedAnalysis DTO. */
  sourceTypes: string[] | undefined | null
  /** Optional extra className on the wrapper span. */
  className?: string
}

/**
 * Renders one badge per source_type. Visually distinguishes the multi-source
 * correlation case (two or more sources) from the single-source case.
 *
 * Returns null when sourceTypes is empty/undefined/null — no empty chip shown.
 */
export default function SourceProvenanceBadges({
  sourceTypes,
  className = '',
}: SourceProvenanceBadgesProps) {
  if (!sourceTypes || sourceTypes.length === 0) return null

  const isCorrelated = sourceTypes.length > 1

  return (
    <span
      className={`inline-flex flex-wrap items-center gap-1 ${className}`}
      data-testid="source-provenance-badges"
      aria-label={
        isCorrelated
          ? `Correlated across ${sourceTypes.length} sources: ${sourceTypes.map(sourceTypeLabel).join(', ')}`
          : `Source: ${sourceTypeLabel(sourceTypes[0])}`
      }
    >
      {sourceTypes.map((key) => (
        <span
          key={key}
          className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium ${sourceTypeBadgeClasses(String(key))}`}
          data-testid="source-provenance-badge"
        >
          {/* Rendered as a React text node — safe (ADR-0029 D3) */}
          {sourceTypeLabel(String(key))}
        </span>
      ))}
      {isCorrelated && (
        <span
          className="text-xs text-soc-medium-fg font-medium"
          data-testid="source-correlated-label"
          aria-hidden="true"
        >
          correlated
        </span>
      )}
    </span>
  )
}
