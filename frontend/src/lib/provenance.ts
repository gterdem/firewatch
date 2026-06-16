/**
 * provenance — shared analytic-provenance vocabulary and presentation helpers.
 *
 * Implements ADR-0035 (provenance tagging — RULE / AI / AI+RULE) and
 * ADR-0036 (score/confidence presentation — banded labels, word confidence).
 *
 * This module is the single source of truth for:
 *   - The three provenance derivation values (wire → chip label).
 *   - The plain-language gloss for each derivation (MM #451 progressive disclosure).
 *   - The canonical severity-band thresholds from the engine (76/51/26).
 *   - The confidence-word mapping (High ≥ 0.7 / Medium 0.4–0.69 / Low < 0.4).
 *   - The standard degraded-state wording for when AI is offline.
 *
 * IMPORTANT — thresholds MUST NOT be duplicated anywhere else in the UI.
 * The engine's canonical bands (76/51/26) are golden-locked (ADR-0036).
 * Components derive colors from the backend `threat_level` field, not from
 * re-computing thresholds locally.
 *
 * SECURITY: all helpers operate on server-provided enum strings / numbers and
 * produce only CSS variable references or string constants — they never
 * interpolate into innerHTML (ADR-0029 D3).
 */

// ---------------------------------------------------------------------------
// ADR-0035 — Provenance derivation vocabulary
// ---------------------------------------------------------------------------

/**
 * Wire values returned by the backend `score_derivation` field.
 * `"ai"` is not a valid score derivation (scores are rules-base + optional AI
 * boost — never pure AI), but is valid for UI-authored text artifacts.
 */
export type ProvenanceDerivation = 'rule' | 'ai' | 'ai+rule'

/** Human-readable chip labels for each derivation value (ADR-0035 table). */
export const PROVENANCE_LABEL: Record<ProvenanceDerivation, string> = {
  rule: 'RULE',
  ai: 'AI',
  'ai+rule': 'AI+RULE',
} as const

/**
 * Plain-language gloss for each derivation value (MM #451).
 *
 * Shown on hover/focus via ProvenanceChip's CellTooltip — progressive
 * disclosure for SOC analysts encountering these terms for the first time.
 * Defined here (the provenance single-source-of-truth module) so the copy is
 * consistent across every panel that renders a ProvenanceChip: Threat summary,
 * coverage table, verdict cards, agreement stat.
 *
 * Copy is the EARS-specified wording from issue #451.
 */
export const PROVENANCE_GLOSS: Record<ProvenanceDerivation, string> = {
  rule: 'This number came from deterministic detection rules — no AI involved.',
  ai: 'A local AI model wrote this verdict.',
  'ai+rule': 'AI and rules both contributed to this score.',
} as const

/**
 * Normalise a raw wire string to a valid ProvenanceDerivation.
 * Unknown / missing values fall back to `'rule'` (most conservative honesty
 * stance: if we don't know, claim deterministic so we never accidentally label
 * rules output as AI).
 */
export function normaliseDerivation(raw: string | undefined | null): ProvenanceDerivation {
  if (raw === 'ai' || raw === 'ai+rule') return raw
  return 'rule'
}

// ---------------------------------------------------------------------------
// ADR-0036 D1 — Canonical severity bands (engine's merge_score thresholds)
// ---------------------------------------------------------------------------

/**
 * Severity band labels (uppercase — matches backend `threat_level` field).
 * Boundaries are golden-locked in the engine scoring module.
 */
export type SeverityBand = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

/**
 * Engine canonical thresholds (ADR-0036 / merge_score):
 *   CRITICAL ≥ 76 | HIGH 51–75 | MEDIUM 26–50 | LOW < 26
 *
 * Exported for documentation / test assertions. Components that receive a
 * `threat_level` from the backend MUST use that field, not re-derive from
 * the score number. This constant exists solely so tests can verify the
 * mapping without hard-coding the numbers in multiple places.
 */
export const SEVERITY_THRESHOLDS = {
  CRITICAL: 76,
  HIGH: 51,
  MEDIUM: 26,
  LOW: 0,
} as const

/**
 * Derive the severity band from a numeric score.
 *
 * Components SHOULD use the backend `threat_level` field (canonical source of
 * truth). Use this function ONLY when `threat_level` is unavailable and you
 * must derive locally — that is a degraded-data case, not the normal path.
 */
export function scoreToSeverityBand(score: number): SeverityBand {
  if (score >= SEVERITY_THRESHOLDS.CRITICAL) return 'CRITICAL'
  if (score >= SEVERITY_THRESHOLDS.HIGH) return 'HIGH'
  if (score >= SEVERITY_THRESHOLDS.MEDIUM) return 'MEDIUM'
  return 'LOW'
}

/**
 * Normalise a raw threat_level string to a SeverityBand.
 * Unknown values fall back to 'LOW' (safe under-state).
 */
export function normaliseThreatLevel(raw: string | undefined | null): SeverityBand {
  const upper = (raw ?? '').toUpperCase()
  if (upper === 'CRITICAL' || upper === 'HIGH' || upper === 'MEDIUM' || upper === 'LOW') {
    return upper as SeverityBand
  }
  return 'LOW'
}

/**
 * CSS token color for a severity band (used in inline styles via var()).
 * Color derives from the band, never from a raw score — ADR-0036 D1.
 */
export function severityFgToken(band: SeverityBand): string {
  switch (band) {
    case 'CRITICAL': return 'var(--fw-red)'
    case 'HIGH':     return 'var(--fw-orange)'
    case 'MEDIUM':   return 'var(--fw-blue)'
    case 'LOW':      return 'var(--fw-green)'
  }
}

/**
 * CSS tint-background token for a severity band (badge fill).
 */
export function severityBgToken(band: SeverityBand): string {
  switch (band) {
    case 'CRITICAL': return 'var(--fw-tint-red)'
    case 'HIGH':     return 'var(--fw-tint-orange)'
    case 'MEDIUM':   return 'var(--fw-tint-blue)'
    case 'LOW':      return 'var(--fw-tint-green)'
  }
}

/**
 * CSS tint-border token for a severity band.
 */
export function severityBorderToken(band: SeverityBand): string {
  switch (band) {
    case 'CRITICAL': return 'var(--fw-tint-red-bd)'
    case 'HIGH':     return 'var(--fw-tint-orange-bd)'
    case 'MEDIUM':   return 'var(--fw-tint-blue-bd)'
    case 'LOW':      return 'var(--fw-tint-green-bd)'
  }
}

// ---------------------------------------------------------------------------
// ADR-0036 D2 — Confidence word bands
// ---------------------------------------------------------------------------

/** Confidence word values (ADR-0036 D2). */
export type ConfidenceWord = 'High' | 'Medium' | 'Low' | 'n/a (AI off)'

/**
 * 0.7 cut is the same threshold that merge_score uses to gate the AI boost
 * (ADR-0036 D2): "High" in the UI means exactly "confident enough to move the
 * score". This alignment is intentional and must not be changed independently.
 */
export const CONFIDENCE_HIGH_THRESHOLD = 0.7
export const CONFIDENCE_MEDIUM_THRESHOLD = 0.4

/**
 * Map a 0–1 confidence float to the word band.
 *
 * @param confidence - null / undefined means AI did not run → "n/a (AI off)".
 */
export function confidenceToWord(confidence: number | null | undefined): ConfidenceWord {
  if (confidence === null || confidence === undefined) return 'n/a (AI off)'
  if (confidence >= CONFIDENCE_HIGH_THRESHOLD)   return 'High'
  if (confidence >= CONFIDENCE_MEDIUM_THRESHOLD) return 'Medium'
  return 'Low'
}

// ---------------------------------------------------------------------------
// ADR-0035 §4 — Standard degraded-state wording
// ---------------------------------------------------------------------------

/**
 * Standard wording for rules-only / AI-engine-offline degraded state.
 * Used by the queue header and pane badges (ADR-0035 §4).
 * ONE constant — never copy this string literally into a component.
 */
export const RULES_ONLY_DEGRADED_WORDING = 'Rules-only mode · AI engine offline' as const
