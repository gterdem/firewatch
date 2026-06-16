/**
 * Tests for promptSections.ts — pure splitter for AI prompt_text.
 *
 * EARS criteria covered:
 *
 *   EARS-1 (section split — concise prompt):
 *     WHEN a concise prompt_text is given, the splitter SHALL return
 *     instructions, samples ("## Attack Samples" section), and schema
 *     ("## Your Task" section) as separate strings.
 *
 *   EARS-2 (section split — detailed prompt):
 *     WHEN a detailed prompt_text is given ("## All Triggered Rules" heading),
 *     the splitter SHALL return the three sections with the correct headings.
 *
 *   EARS-3 (missing samples section):
 *     WHEN prompt_text has no "## Attack Samples" or "## All Triggered Rules"
 *     heading, samples SHALL be null.
 *
 *   EARS-4 (missing schema section):
 *     WHEN prompt_text has no "## Your Task" heading, schema SHALL be null.
 *
 *   EARS-5 (no markers — falls through to instructions-only):
 *     WHEN prompt_text has no section markers at all, only instructions is
 *     populated; samples and schema are null.
 *
 *   EARS-6 (sentinel preservation):
 *     WHEN the samples section contains <untrusted_data>…</untrusted_data>
 *     sentinel-wrapped payloads, the splitter SHALL preserve them unchanged
 *     in the samples string (it does NOT strip or transform them).
 *
 *   EARS-7 (hostile content — no execution):
 *     WHEN the prompt contains hostile strings (<img onerror>, markdown links,
 *     ANSI escapes), the splitter SHALL return them as literal text in the
 *     appropriate sections without modification. (The render layer is
 *     responsible for text-node rendering; the splitter only splits.)
 */

import { describe, it, expect } from 'vitest'
import { splitPromptSections } from '../components/ai/ledger/promptSections'

// ---------------------------------------------------------------------------
// Fixtures — mirrors real prompt format from packages/firewatch-core/.../prompts.py
// ---------------------------------------------------------------------------

const CONCISE_PROMPT_FIXTURE = `You are a SOC (Security Operations Center) analyst AI assistant.
Analyze this threat actor based on WAF (Web Application Firewall) log data.
Be concise. Keep each insight under 30 words.

## Threat Actor Profile
- **IP Address:** 192.0.2.1
- **Total Events:** 120
- **Blocked Events:** 95
- **Block Rate:** 79.2%
- **Unique Rules Triggered:** 3
- **Activity Window:** 2026-06-01T08:00:00Z to 2026-06-04T09:55:00Z

## Attack Samples (top rules by frequency)
  1. Rule: 942100 (SQL Injection) — triggered 30x
     Sample payload: <untrusted_data>id=1 OR 1=1</untrusted_data>
  2. Rule: 941100 (XSS) — triggered 15x
     Sample payload: <untrusted_data><script>alert(1)</script></untrusted_data>

## Your Task
Provide a threat assessment in JSON format only, no other text:
{
  "threat_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": 0.0-1.0
}`

const DETAILED_PROMPT_FIXTURE = `You are a senior SOC (Security Operations Center) analyst.
Provide a thorough, detailed threat assessment based on WAF log data.

## Threat Actor Profile
- **IP Address:** 192.0.2.1

## All Triggered Rules (with timestamps and descriptions)
  1. Rule: 942100 (SQL Injection) — triggered 30x
     Description: <untrusted_data>SQL injection detection rule</untrusted_data>
     Sample payload: <untrusted_data>id=1 OR 1=1</untrusted_data>

## Your Task
Provide a comprehensive threat assessment in JSON format only, no other text:
{
  "threat_level": "CRITICAL|HIGH|MEDIUM|LOW"
}`

const NO_SAMPLES_PROMPT = `You are a SOC analyst.
## Your Task
Respond with JSON.`

const NO_SCHEMA_PROMPT = `You are a SOC analyst.
## Attack Samples (top rules by frequency)
  1. Rule: 942100 — triggered 5x`

const NO_MARKERS_PROMPT = `You are a SOC analyst.
Analyze this IP address.
Just return JSON.`

const HOSTILE_PROMPT = `You are a SOC analyst.
## Attack Samples (top rules by frequency)
  1. Rule: 942100 — triggered 5x
     Sample payload: <untrusted_data><img src=x onerror=alert(1)></untrusted_data>
     Note: [x](javascript:alert(2))
     ANSI: [31mRED[0m

## Your Task
Return JSON.`

// ---------------------------------------------------------------------------
// EARS-1: concise prompt — three sections found
// ---------------------------------------------------------------------------

describe('splitPromptSections — concise prompt (EARS-1)', () => {
  it('returns non-empty instructions for the system header and profile', () => {
    const result = splitPromptSections(CONCISE_PROMPT_FIXTURE)
    expect(result.instructions).toBeTruthy()
    expect(result.instructions).toContain('SOC')
    expect(result.instructions).toContain('192.0.2.1')
  })

  it('returns samples section starting with the "## Attack Samples" heading', () => {
    const result = splitPromptSections(CONCISE_PROMPT_FIXTURE)
    expect(result.samples).not.toBeNull()
    expect(result.samples!).toContain('## Attack Samples')
  })

  it('returns schema section starting with the "## Your Task" heading', () => {
    const result = splitPromptSections(CONCISE_PROMPT_FIXTURE)
    expect(result.schema).not.toBeNull()
    expect(result.schema!).toContain('## Your Task')
  })

  it('does NOT include "## Attack Samples" in instructions', () => {
    const result = splitPromptSections(CONCISE_PROMPT_FIXTURE)
    expect(result.instructions).not.toContain('## Attack Samples')
  })

  it('does NOT include "## Your Task" in samples section', () => {
    const result = splitPromptSections(CONCISE_PROMPT_FIXTURE)
    expect(result.samples!).not.toContain('## Your Task')
  })

  it('samples section does NOT appear in schema', () => {
    const result = splitPromptSections(CONCISE_PROMPT_FIXTURE)
    expect(result.schema!).not.toContain('## Attack Samples')
  })
})

// ---------------------------------------------------------------------------
// EARS-2: detailed prompt — uses "## All Triggered Rules" heading
// ---------------------------------------------------------------------------

describe('splitPromptSections — detailed prompt (EARS-2)', () => {
  it('returns samples section for "## All Triggered Rules" heading', () => {
    const result = splitPromptSections(DETAILED_PROMPT_FIXTURE)
    expect(result.samples).not.toBeNull()
    expect(result.samples!).toContain('## All Triggered Rules')
  })

  it('returns schema section for detailed prompt', () => {
    const result = splitPromptSections(DETAILED_PROMPT_FIXTURE)
    expect(result.schema).not.toBeNull()
    expect(result.schema!).toContain('## Your Task')
  })

  it('instructions section does NOT contain the triggered rules heading', () => {
    const result = splitPromptSections(DETAILED_PROMPT_FIXTURE)
    expect(result.instructions).not.toContain('## All Triggered Rules')
  })
})

// ---------------------------------------------------------------------------
// EARS-3: missing samples section
// ---------------------------------------------------------------------------

describe('splitPromptSections — missing samples section (EARS-3)', () => {
  it('returns null for samples when no attack-samples heading is present', () => {
    const result = splitPromptSections(NO_SAMPLES_PROMPT)
    expect(result.samples).toBeNull()
  })

  it('still returns schema when samples is absent', () => {
    const result = splitPromptSections(NO_SAMPLES_PROMPT)
    expect(result.schema).not.toBeNull()
    expect(result.schema!).toContain('## Your Task')
  })
})

// ---------------------------------------------------------------------------
// EARS-4: missing schema section
// ---------------------------------------------------------------------------

describe('splitPromptSections — missing schema section (EARS-4)', () => {
  it('returns null for schema when "## Your Task" heading is absent', () => {
    const result = splitPromptSections(NO_SCHEMA_PROMPT)
    expect(result.schema).toBeNull()
  })

  it('still returns samples when schema is absent', () => {
    const result = splitPromptSections(NO_SCHEMA_PROMPT)
    expect(result.samples).not.toBeNull()
    expect(result.samples!).toContain('## Attack Samples')
  })
})

// ---------------------------------------------------------------------------
// EARS-5: no section markers
// ---------------------------------------------------------------------------

describe('splitPromptSections — no section markers (EARS-5)', () => {
  it('returns the entire text as instructions when no markers found', () => {
    const result = splitPromptSections(NO_MARKERS_PROMPT)
    expect(result.instructions).toBeTruthy()
    expect(result.instructions).toContain('SOC analyst')
  })

  it('returns null for both samples and schema', () => {
    const result = splitPromptSections(NO_MARKERS_PROMPT)
    expect(result.samples).toBeNull()
    expect(result.schema).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// EARS-6: sentinel preservation
// ---------------------------------------------------------------------------

describe('splitPromptSections — sentinel preservation (EARS-6)', () => {
  it('preserves <untrusted_data> sentinel tags in the samples section', () => {
    const result = splitPromptSections(CONCISE_PROMPT_FIXTURE)
    expect(result.samples).toContain('<untrusted_data>')
    expect(result.samples).toContain('</untrusted_data>')
  })

  it('does NOT strip or modify sentinel-wrapped payloads', () => {
    const result = splitPromptSections(CONCISE_PROMPT_FIXTURE)
    expect(result.samples).toContain('<untrusted_data>id=1 OR 1=1</untrusted_data>')
  })

  it('preserves nested sentinel content unchanged', () => {
    const result = splitPromptSections(CONCISE_PROMPT_FIXTURE)
    // The XSS payload inside the sentinel must be preserved verbatim.
    expect(result.samples).toContain('<untrusted_data><script>alert(1)</script></untrusted_data>')
  })
})

// ---------------------------------------------------------------------------
// EARS-7: hostile content — literal text in sections (no execution by splitter)
// ---------------------------------------------------------------------------

describe('splitPromptSections — hostile content returns literal text (EARS-7)', () => {
  it('returns <img onerror> as a literal string in samples', () => {
    const result = splitPromptSections(HOSTILE_PROMPT)
    expect(result.samples).toContain('<img src=x onerror=alert(1)>')
  })

  it('returns markdown link as a literal string in samples', () => {
    const result = splitPromptSections(HOSTILE_PROMPT)
    expect(result.samples).toContain('[x](javascript:alert(2))')
  })

  it('returns ANSI escape as a literal string in samples', () => {
    const result = splitPromptSections(HOSTILE_PROMPT)
    expect(result.samples).toContain('[31mRED[0m')
  })

  it('returns schema section intact even with hostile samples present', () => {
    const result = splitPromptSections(HOSTILE_PROMPT)
    expect(result.schema).not.toBeNull()
    expect(result.schema!).toContain('## Your Task')
    // Schema section must NOT contain the hostile samples content.
    expect(result.schema!).not.toContain('<img src=x onerror=alert(1)>')
  })
})

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

describe('splitPromptSections — edge cases', () => {
  it('handles an empty string without throwing', () => {
    expect(() => splitPromptSections('')).not.toThrow()
    const result = splitPromptSections('')
    expect(result.instructions).toBe('')
    expect(result.samples).toBeNull()
    expect(result.schema).toBeNull()
  })

  it('handles a prompt with only whitespace without throwing', () => {
    expect(() => splitPromptSections('   \n   ')).not.toThrow()
  })

  it('sections are trimmed of leading/trailing whitespace', () => {
    const result = splitPromptSections(CONCISE_PROMPT_FIXTURE)
    expect(result.instructions).toBe(result.instructions.trim())
    expect(result.samples!).toBe(result.samples!.trim())
    expect(result.schema!).toBe(result.schema!.trim())
  })
})
