/**
 * promptSections — pure splitter for AI analysis prompt_text.
 *
 * Splits the stored prompt_text (from GET /ai/analyses/{id}) into
 * human-readable sections based on the real prompt structure from
 * packages/firewatch-core/src/firewatch_core/ai/prompts.py:
 *
 *   1. Instructions   — the system header and IP profile fields
 *   2. Samples        — the "## Attack Samples" block containing sentinel-wrapped
 *                       attacker payloads (<untrusted_data>…</untrusted_data>)
 *   3. Schema         — the "## Your Task" JSON output schema block at the end
 *
 * Sentinel constants (NB-1 / ADR-0015):
 *   SENTINEL_OPEN  = "<untrusted_data>"
 *   SENTINEL_CLOSE = "</untrusted_data>"
 *
 * SECURITY: this module is PURE TEXT MANIPULATION — it never interprets
 * the text as HTML. Callers MUST render each section as a text node only
 * (never via dangerouslySetInnerHTML — ADR-0029 D3 / OWASP LLM05).
 *
 * Unit-testable: no React, no DOM, no side effects. Import in isolation.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PromptSections {
  /**
   * The system instructions + IP profile header.
   * Everything before the Attack Samples / All Triggered Rules section.
   */
  instructions: string

  /**
   * The attack samples block: contains rule IDs, categories, counts,
   * and sentinel-wrapped payloads (<untrusted_data>…</untrusted_data>).
   * Null when the section marker is not found in the prompt.
   */
  samples: string | null

  /**
   * The "## Your Task" JSON output schema block.
   * Null when the section marker is not found.
   */
  schema: string | null
}

// ---------------------------------------------------------------------------
// Section heading constants (must match prompts.py template headings exactly)
// ---------------------------------------------------------------------------

/** Heading used in concise prompts (IP_SUMMARY_PROMPT). */
const SAMPLES_HEADING_CONCISE = '## Attack Samples'

/** Heading used in detailed prompts (IP_DETAILED_PROMPT). */
const SAMPLES_HEADING_DETAILED = '## All Triggered Rules'

/** Heading that starts the JSON output schema block. */
const SCHEMA_HEADING = '## Your Task'

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Split a stored prompt_text into its three display sections.
 *
 * Handles both concise (IP_SUMMARY_PROMPT) and detailed (IP_DETAILED_PROMPT)
 * variants by checking for both sample-section headings.
 *
 * All three sections are plain strings — the caller is responsible for
 * rendering them as text nodes (ADR-0029 D3).
 *
 * @param promptText  The raw prompt_text from GET /ai/analyses/{id}.
 * @returns           Object with instructions, samples, and schema sections.
 *                    samples and schema are null if the headings are absent.
 */
export function splitPromptSections(promptText: string): PromptSections {
  // Determine which samples heading is present (concise vs detailed prompt).
  let samplesHeading: string | null = null
  if (promptText.includes(SAMPLES_HEADING_CONCISE)) {
    samplesHeading = SAMPLES_HEADING_CONCISE
  } else if (promptText.includes(SAMPLES_HEADING_DETAILED)) {
    samplesHeading = SAMPLES_HEADING_DETAILED
  }

  // Locate the schema heading.
  const schemaIndex = promptText.indexOf(SCHEMA_HEADING)

  // -------------------------------------------------------------------------
  // Case 1: Both sections found — split into three parts.
  // -------------------------------------------------------------------------
  if (samplesHeading !== null && schemaIndex !== -1) {
    const samplesIndex = promptText.indexOf(samplesHeading)

    // Guard: headings must appear in order (instructions → samples → schema).
    if (samplesIndex < schemaIndex) {
      return {
        instructions: promptText.slice(0, samplesIndex).trim(),
        samples: promptText.slice(samplesIndex, schemaIndex).trim(),
        schema: promptText.slice(schemaIndex).trim(),
      }
    }
  }

  // -------------------------------------------------------------------------
  // Case 2: Only samples heading found (no schema heading).
  // -------------------------------------------------------------------------
  if (samplesHeading !== null) {
    const samplesIndex = promptText.indexOf(samplesHeading)
    return {
      instructions: promptText.slice(0, samplesIndex).trim(),
      samples: promptText.slice(samplesIndex).trim(),
      schema: null,
    }
  }

  // -------------------------------------------------------------------------
  // Case 3: Only schema heading found (no samples heading).
  // -------------------------------------------------------------------------
  if (schemaIndex !== -1) {
    return {
      instructions: promptText.slice(0, schemaIndex).trim(),
      samples: null,
      schema: promptText.slice(schemaIndex).trim(),
    }
  }

  // -------------------------------------------------------------------------
  // Case 4: No section markers found — entire text is instructions.
  // -------------------------------------------------------------------------
  return {
    instructions: promptText.trim(),
    samples: null,
    schema: null,
  }
}
