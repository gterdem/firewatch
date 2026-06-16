/**
 * stages.ts — Closed stage-type vocabulary + pure SSE frame parser.
 *
 * ADR-0046 D3: the closed stage vocabulary is wire-stable — names match
 * the backend's StageName constants in firewatch_core/ai/stage_events.py.
 * Unknown event types are silently dropped (forward-compatible).
 *
 * SECURITY (ADR-0029 D3 / ADR-0046 D3): NO model-authored text appears in
 * any stage event. Prose arrives only in the terminal `result` event,
 * after the full gauntlet, through the existing rendering path.
 */

// ---------------------------------------------------------------------------
// Closed stage-name constants (wire-stable — matches backend StageName)
// ---------------------------------------------------------------------------

export const StageName = {
  PROMPT_BUILT: 'prompt_built',
  REQUEST_SENT: 'request_sent',
  GENERATING: 'generating',
  RECEIVED: 'received',
  VALIDATED: 'validated',
  PROJECTED: 'projected',
  FAILED: 'failed',
} as const

export type StageNameValue = (typeof StageName)[keyof typeof StageName]

// ---------------------------------------------------------------------------
// Closed fail-reason constants (matches backend FailReason)
// ---------------------------------------------------------------------------

export const FailReason = {
  VALIDATION_ERROR: 'validation_error',
  ENGINE_ERROR: 'engine_error',
  ENGINE_UNAVAILABLE: 'engine_unavailable',
  TIMEOUT: 'timeout',
  CANCELLED: 'cancelled',
} as const

export type FailReasonValue = (typeof FailReason)[keyof typeof FailReason]

// ---------------------------------------------------------------------------
// Typed stage-fact shapes (discriminated union)
// ---------------------------------------------------------------------------

export interface PromptBuiltStage {
  stage: 'prompt_built'
  sample_count: number
}

export interface RequestSentStage {
  stage: 'request_sent'
  model: string
  endpoint_host: string
}

export interface GeneratingStage {
  stage: 'generating'
  elapsed_ms: number
}

export interface ReceivedStage {
  stage: 'received'
  latency_ms: number
  completion_tokens?: number
}

export interface ValidatedStage {
  stage: 'validated'
}

export interface ProjectedStage {
  stage: 'projected'
  field_count: number
}

export interface FailedStage {
  stage: 'failed'
  at_stage: string
  reason_code: string
}

/** A known, typed stage fact. Unknown stages are filtered before this union. */
export type StageFact =
  | PromptBuiltStage
  | RequestSentStage
  | GeneratingStage
  | ReceivedStage
  | ValidatedStage
  | ProjectedStage
  | FailedStage

// ---------------------------------------------------------------------------
// SSE wire-frame shape
// ---------------------------------------------------------------------------

/** Raw SSE frame from the server (event name + raw JSON string). */
export interface RawSseFrame {
  event: string
  data: string
}

// ---------------------------------------------------------------------------
// Pure SSE frame parser (no side effects — fully unit-testable)
// ---------------------------------------------------------------------------

/**
 * Parse one SSE message block (the text between blank lines) into a RawSseFrame.
 *
 * WHATWG HTML §9.2 SSE field grammar:
 *   Each line is `field: value\n` or `\n` (blank line = message boundary).
 *   We parse `event:` and `data:` fields; others are ignored.
 *   Multiple `data:` lines are concatenated with `\n` between them.
 */
export function parseSseBlock(block: string): RawSseFrame | null {
  let event = 'message'
  const dataParts: string[] = []

  for (const line of block.split('\n')) {
    if (line.startsWith('event:')) {
      event = line.slice('event:'.length).trim()
    } else if (line.startsWith('data:')) {
      dataParts.push(line.slice('data:'.length).trim())
    }
    // Other fields (id:, retry:) are ignored per WHATWG spec.
  }

  if (dataParts.length === 0) return null
  return { event, data: dataParts.join('\n') }
}

/**
 * Parse a raw SSE frame into a typed StageFact, or null if:
 * - the event is not 'stage' (terminal `result` and `error` handled by the hook)
 * - the data is malformed JSON
 * - the stage name is unknown (forward-compat drop)
 *
 * ADR-0046: unknown event types are silently dropped.
 */
export function parseStageFact(frame: RawSseFrame): StageFact | null {
  if (frame.event !== 'stage') return null

  let parsed: unknown
  try {
    parsed = JSON.parse(frame.data)
  } catch {
    // Malformed JSON — drop silently.
    return null
  }

  if (typeof parsed !== 'object' || parsed === null) return null
  const obj = parsed as Record<string, unknown>
  const stage = obj.stage

  switch (stage) {
    case StageName.PROMPT_BUILT:
      return { stage: 'prompt_built', sample_count: Number(obj.sample_count ?? 0) }

    case StageName.REQUEST_SENT:
      return {
        stage: 'request_sent',
        model: String(obj.model ?? ''),
        endpoint_host: String(obj.endpoint_host ?? ''),
      }

    case StageName.GENERATING:
      return { stage: 'generating', elapsed_ms: Number(obj.elapsed_ms ?? 0) }

    case StageName.RECEIVED: {
      const fact: ReceivedStage = {
        stage: 'received',
        latency_ms: Number(obj.latency_ms ?? 0),
      }
      if (obj.completion_tokens !== undefined && obj.completion_tokens !== null) {
        fact.completion_tokens = Number(obj.completion_tokens)
      }
      return fact
    }

    case StageName.VALIDATED:
      return { stage: 'validated' }

    case StageName.PROJECTED:
      return { stage: 'projected', field_count: Number(obj.field_count ?? 0) }

    case StageName.FAILED:
      return {
        stage: 'failed',
        at_stage: String(obj.at_stage ?? ''),
        reason_code: String(obj.reason_code ?? FailReason.ENGINE_ERROR),
      }

    default:
      // Unknown stage name — drop silently (ADR-0046 forward-compat).
      return null
  }
}

// ---------------------------------------------------------------------------
// Human-readable stage label (for the ticker UI)
// ---------------------------------------------------------------------------

/**
 * Format a stage fact as a human-readable ticker line.
 * Returns a concise status string matching the ADR-0046 example labels.
 *
 * SECURITY: All values are numbers or strings from closed enums / configs —
 * never model-authored text.
 */
export function formatStageLabel(fact: StageFact): string {
  switch (fact.stage) {
    case 'prompt_built':
      return `prompt built (${fact.sample_count} samples)`

    case 'request_sent':
      return `sent to ${fact.model} @${fact.endpoint_host}`

    case 'generating': {
      const sec = (fact.elapsed_ms / 1000).toFixed(1)
      return `generating… (${sec}s)`
    }

    case 'received': {
      const sec = (fact.latency_ms / 1000).toFixed(1)
      const tokPart =
        fact.completion_tokens !== undefined ? `${fact.completion_tokens} tok · ` : ''
      return `received (${tokPart}${sec}s)`
    }

    case 'validated':
      return 'schema validated ✓'

    case 'projected':
      return `projected to ${fact.field_count} fields ✓`

    case 'failed':
      return `validation FAILED → rules-only fallback`
  }
}
