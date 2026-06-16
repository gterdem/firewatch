/**
 * StagedDetailChecklist — generic pass/fail/skip checklist rendered from
 * stage_* / stage_*_msg keys in an ActionResult.detail map.
 *
 * Implements issue #691 / ADR-0034 generic-action-rendering / ADR-0010 schema-driven UI.
 *
 * The rendering is keyed on the NAMING CONVENTION only:
 *   - Keys matching /^stage_([^_].*)$/ (but NOT /^stage_.*_msg$/) are treated as stages.
 *   - Each stage value is one of "pass" | "fail" | "skip" (any other value falls back
 *     to "skip" styling so we degrade gracefully for future stage values).
 *   - The paired message key is stage_<name>_msg; absent -> no message line.
 *
 * Stage name humanization is handled by stagedDetailUtils.humanizeStageName.
 * Utility functions (humanizeStageName, extractStageRows) live in stagedDetailUtils.ts
 * so this file exports only the component (react-refresh/only-export-components).
 *
 * SECURITY (ADR-0029 D3):
 *   All stage values and messages are infra-derived text (SSH error strings,
 *   file paths, etc.) that may contain remote-host-derived content. They are
 *   rendered as React text nodes ONLY — never via innerHTML /
 *   dangerouslySetInnerHTML. All string coercions use String().
 */

import type { StageStatus } from './stagedDetailUtils'
import { extractStageRows } from './stagedDetailUtils'

// ---------------------------------------------------------------------------
// Status icon sub-component (text-only, no SVG to keep deps minimal)
// ---------------------------------------------------------------------------

interface StatusGlyphProps {
  status: StageStatus
}

function StatusGlyph({ status }: StatusGlyphProps) {
  if (status === 'pass') {
    return (
      <span
        aria-label="pass"
        data-testid="stage-glyph-pass"
        className="inline-block w-4 text-center font-bold text-green-600 dark:text-green-400 select-none"
      >
        ✓
      </span>
    )
  }
  if (status === 'fail') {
    return (
      <span
        aria-label="fail"
        data-testid="stage-glyph-fail"
        className="inline-block w-4 text-center font-bold text-destructive select-none"
      >
        ✗
      </span>
    )
  }
  // skip (or any unknown value)
  return (
    <span
      aria-label="skip"
      data-testid="stage-glyph-skip"
      className="inline-block w-4 text-center font-bold text-muted-foreground select-none"
    >
      ⊘
    </span>
  )
}

// ---------------------------------------------------------------------------
// StagedDetailChecklist (exported)
// ---------------------------------------------------------------------------

interface StagedDetailChecklistProps {
  /** The ActionResult.detail map. Renders nothing when no stage_* keys present. */
  detail: Record<string, unknown>
}

/**
 * Renders an ordered pass/fail/skip checklist when `detail` contains stage_* keys.
 *
 * When no stage_* keys are present, renders nothing (null).
 * Non-stage_* keys are ignored here — the caller is responsible for rendering them.
 *
 * SECURITY: all string values are rendered as React text nodes via String() coercion.
 * Never reads innerHTML / dangerouslySetInnerHTML.
 */
export default function StagedDetailChecklist({ detail }: StagedDetailChecklistProps) {
  const rows = extractStageRows(detail)
  if (rows.length === 0) return null

  return (
    <ol
      data-testid="staged-detail-checklist"
      className="mt-1.5 space-y-1 list-none p-0"
    >
      {rows.map((row) => (
        <li
          key={row.name}
          data-testid={`stage-row-${row.name}`}
          className="flex flex-col gap-0.5"
        >
          {/* Status glyph + label row */}
          <div className="flex items-center gap-1.5">
            <StatusGlyph status={row.status} />
            <span
              data-testid={`stage-label-${row.name}`}
              className={
                row.status === 'fail'
                  ? 'font-medium text-destructive'
                  : row.status === 'skip'
                    ? 'text-muted-foreground'
                    : 'font-medium text-green-700 dark:text-green-300'
              }
            >
              {/* label is humanizer-derived from the key — safe text node */}
              {String(row.label)}
            </span>
          </div>

          {/* Message line (infra-derived text — text node only, SECURITY: ADR-0029 D3) */}
          {row.message !== null && (
            <div
              data-testid={`stage-msg-${row.name}`}
              className={`ml-6 text-xs leading-relaxed select-text ${
                row.status === 'fail'
                  ? 'text-destructive'
                  : 'text-muted-foreground'
              }`}
            >
              {/* SECURITY: stage messages are infra-derived (SSH errors, paths) —
                  rendered as a React text node. Never via innerHTML. */}
              {String(row.message)}
            </div>
          )}
        </li>
      ))}
    </ol>
  )
}
