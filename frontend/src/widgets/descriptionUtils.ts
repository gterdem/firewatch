/**
 * Utilities for DescriptionFieldTemplate — extracted so the component file only
 * exports the React component (satisfies react-refresh/only-export-components).
 *
 * ADR-0028: part of the project-local widget/template registry.
 */

/** Maximum character length for the clamped lead sentence. */
export const LEAD_MAX_CHARS = 90

/**
 * Derive a short lead sentence from a full description string.
 *
 * Algorithm:
 *  1. Find the first sentence boundary (`. `, `! `, `? `) inside the string.
 *  2. Take the text up to and including the punctuation mark (exclude the
 *     trailing space so there is no dangling whitespace).
 *  3. If the sentence exceeds LEAD_MAX_CHARS, truncate at the last space
 *     before the limit and append `…`.
 *  4. If the entire description is shorter than LEAD_MAX_CHARS and has no
 *     sentence boundary, return it as-is (it is already a short hint).
 */
export function deriveLeadSentence(description: string): string {
  const trimmed = description.trim()
  if (!trimmed) return ''

  // Match first sentence-ending punctuation followed by a space or end-of-string
  const sentenceMatch = trimmed.match(/^(.*?[.!?])(?:\s|$)/)
  const sentence = sentenceMatch ? sentenceMatch[1] : trimmed

  if (sentence.length <= LEAD_MAX_CHARS) return sentence

  // Truncate at last word boundary before limit
  const truncated = sentence.slice(0, LEAD_MAX_CHARS)
  const lastSpace = truncated.lastIndexOf(' ')
  return (lastSpace > 0 ? truncated.slice(0, lastSpace) : truncated) + '…'
}

/**
 * Whether the full text is meaningfully different from the lead sentence.
 * Returns true when we should show the Details disclosure.
 */
export function shouldShowDisclosure(lead: string, full: string): boolean {
  return full.trim().length > lead.length + 1
}
