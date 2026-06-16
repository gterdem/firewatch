/**
 * capModelName — guard against layout-breaking pathological model name strings.
 *
 * NB-2 (issue #306): `ollama_model` comes from a trusted local /health endpoint
 * (ADR-0004 local-only inference) and is rendered as text nodes, so this is NOT
 * an XSS vector.  The cap exists solely to protect layouts from arbitrarily long
 * model name strings (e.g. from a local Ollama installation with a 200-char name).
 *
 * Applied at the seam — once per interpolation site — rather than at the API
 * fetch layer, so raw health data stays intact for any non-UI consumers.
 */

/** Maximum characters to show for a model name in any UI label. */
export const MODEL_NAME_MAX_LEN = 64

/**
 * Return the model name capped to MODEL_NAME_MAX_LEN chars, or null when absent.
 *
 * @param name - Raw model name from /health (may be null/undefined/empty).
 * @returns Capped name, or null when the input is null/undefined/empty.
 */
export function capModelName(name: string | null | undefined): string | null {
  if (!name) return null
  const capped = String(name).slice(0, MODEL_NAME_MAX_LEN)
  return capped || null
}
