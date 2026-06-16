/**
 * Utility functions for staged-detail checklist rendering (issue #691).
 *
 * Split into a separate module from StagedDetailChecklist.tsx so that
 * the component file exports ONLY the React component (required by the
 * react-refresh/only-export-components ESLint rule for HMR compatibility).
 *
 * These helpers are generic — keyed on naming conventions, not source-specific
 * knowledge. They are exported so tests can exercise them directly.
 *
 * SECURITY (ADR-0029 D3): all values passed to these utilities come from
 * ActionResult.detail (server-sanitized but potentially infra-derived text).
 * Callers must render returned strings as React text nodes only.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Canonical stage outcome values. Any other string falls back to "skip". */
export type StageStatus = 'pass' | 'fail' | 'skip'

/** One resolved stage row ready for rendering. */
export interface StageRow {
  /** The raw key segment after "stage_", e.g. "ssh", "evejson", "activity". */
  name: string
  /** Human-readable label derived from the name, e.g. "SSH", "Eve.Json", "Activity". */
  label: string
  /** Outcome status. */
  status: StageStatus
  /** Optional message text (from stage_<name>_msg). Null when absent. */
  message: string | null
}

// ---------------------------------------------------------------------------
// Compound normalization map
// ---------------------------------------------------------------------------

/**
 * Normalize known compound-word patterns in stage names before humanizing.
 * This is a small set of naming-convention normalizations, NOT per-source knowledge.
 *
 * "evejson" -> "eve.json"  (underscore-free compound file extension convention)
 *
 * Any segment not in this map is left unchanged.
 * Add entries here ONLY when a new naming-convention pattern emerges — not for
 * specific source names.
 */
const COMPOUND_NORMALIZATION: Record<string, string> = {
  evejson: 'eve.json',
}

// ---------------------------------------------------------------------------
// humanizeStageName
// ---------------------------------------------------------------------------

/**
 * Humanize a stage name key segment into a display label.
 *
 * Rules (purely convention-driven, no source-specific knowledge):
 * 1. Apply compound normalizations (e.g. "evejson" -> "eve.json").
 * 2. If the result contains a dot, title-case each dot-separated part.
 * 3. Otherwise, if the whole word is 1-3 characters, uppercase it entirely
 *    (SSH, TCP, DNS, etc. are common infra abbreviations that are all-caps).
 *    4+ char words use title-case to avoid over-capitalizing words like "auth".
 * 4. Otherwise, capitalize the first letter only.
 *
 * Examples:
 *   "ssh"      -> "SSH"       (3 chars -> uppercase)
 *   "evejson"  -> "eve.json"  (compound norm) -> "Eve.Json"
 *   "activity" -> "Activity"  (capitalize first letter)
 *   "tcp"      -> "TCP"       (3 chars -> uppercase)
 *   "auth"     -> "Auth"      (4 chars -> capitalize first only)
 */
export function humanizeStageName(name: string): string {
  const normalized = COMPOUND_NORMALIZATION[name] ?? name

  if (normalized.includes('.')) {
    // Title-case each dot-separated segment.
    return normalized
      .split('.')
      .map((part) =>
        part.length > 0 ? part.charAt(0).toUpperCase() + part.slice(1) : part,
      )
      .join('.')
  }

  if (normalized.length >= 1 && normalized.length <= 3) {
    // Short segments (<=3 chars) are treated as abbreviations -> all uppercase.
    return normalized.toUpperCase()
  }

  // Default: capitalize first letter, leave the rest as-is.
  return normalized.charAt(0).toUpperCase() + normalized.slice(1)
}

// ---------------------------------------------------------------------------
// toStageStatus
// ---------------------------------------------------------------------------

/**
 * Coerce a raw detail value to a StageStatus.
 * Unknown/absent values fall back to "skip" for graceful degradation.
 */
export function toStageStatus(value: unknown): StageStatus {
  if (value === 'pass') return 'pass'
  if (value === 'fail') return 'fail'
  return 'skip'
}

// ---------------------------------------------------------------------------
// extractStageRows
// ---------------------------------------------------------------------------

/**
 * Extract ordered stage rows from a detail map.
 *
 * A stage key is any key matching /^stage_/ that does NOT end in _msg.
 * The paired message is found under <stageKey>_msg.
 * Ordering preserves insertion order (JS object key order is stable for
 * non-integer keys in modern engines — adequate for a small fixed set).
 *
 * Returns [] when no stage keys are present.
 */
export function extractStageRows(detail: Record<string, unknown>): StageRow[] {
  const rows: StageRow[] = []

  for (const key of Object.keys(detail)) {
    // Match "stage_<name>" where name does not end in "_msg"
    if (!key.startsWith('stage_')) continue
    if (key.endsWith('_msg')) continue

    const name = key.slice('stage_'.length) // e.g. "ssh", "evejson", "activity"
    const msgKey = `${key}_msg`
    const rawMsg = detail[msgKey]
    const message = rawMsg != null ? String(rawMsg) : null

    rows.push({
      name,
      label: humanizeStageName(name),
      status: toStageStatus(detail[key]),
      message,
    })
  }

  return rows
}
