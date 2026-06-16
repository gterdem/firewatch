/**
 * pydanticErrors — map Pydantic 422 error objects to rjsf extraErrors.
 *
 * Pydantic v2 returns a 422 body shaped as:
 *   { detail: Array<{ loc: (string | number)[], msg: string, type: string, ... }> }
 *
 * rjsf accepts `extraErrors` typed as `ErrorSchema`, which is a recursive
 * object where `{ fieldName: { __errors: ["message"] } }` attaches a message
 * inline under the named field.
 *
 * This module converts the Pydantic array into:
 *   - `fieldErrors`    — ErrorSchema keyed by the field path for errors whose
 *                        `loc` resolves to a top-level field in the JSON Schema.
 *   - `formErrors`     — string[] of messages for errors that have no resolvable
 *                        field loc (body-level, root, or unrecognised paths).
 *
 * Rules (no per-source branching — ADR-0010 / issue #495):
 *   1. Strip the leading "body" segment if present (FastAPI wraps the Pydantic
 *      model root in a "body" loc segment when the parameter is a request body).
 *   2. If the remaining loc has exactly one string element that names a known
 *      property in the config_schema, treat it as a field error.
 *   3. Everything else goes to formErrors.
 *
 * Only top-level field paths are mapped (Pydantic loc[0] after body strip).
 * Nested paths (e.g. ["address", "port"]) fall through to formErrors —
 * current plugin schemas are flat objects, and rjsf nested extraErrors
 * would require recursive building that's out of scope for this issue.
 */

import type { ErrorSchema } from '@rjsf/utils'

/** One item in the Pydantic v2 422 detail array. */
export interface PydanticErrorItem {
  /** Path segments identifying the field that failed. May be absent in Pydantic v1 compat payloads. */
  loc?: (string | number)[]
  msg?: string
  message?: string
  type?: string
}

/**
 * Result of mapping a Pydantic 422 error list against a JSON Schema.
 */
export interface MappedPydanticErrors {
  /**
   * rjsf ErrorSchema for field-scoped errors.
   * Pass this as the `extraErrors` prop on the rjsf <Form />.
   * Empty object when all errors are form-level.
   */
  fieldErrors: ErrorSchema
  /**
   * Human-readable messages for errors that have no resolvable field location.
   * Show these as the card-level error summary.
   * Empty array when all errors are field-scoped.
   */
  formErrors: string[]
}

/**
 * Extract the scalar message from one Pydantic error item.
 * Prefers `msg` (Pydantic v2) over `message` (Pydantic v1 compat).
 */
function extractMessage(item: PydanticErrorItem): string {
  return item.msg ?? item.message ?? JSON.stringify(item)
}

/**
 * Derive the set of known top-level field names from a JSON Schema object.
 * Collects keys from `properties`, plus conditional branches
 * (`then.properties`, `else.properties`) so that branch-only fields
 * (e.g. Suricata's `remote_host` in the `then` branch) are also recognised.
 */
function knownFields(configSchema: Record<string, unknown>): Set<string> {
  const fields = new Set<string>()

  function collectProps(schema: unknown): void {
    if (typeof schema !== 'object' || schema === null) return
    const s = schema as Record<string, unknown>
    const props = s['properties']
    if (typeof props === 'object' && props !== null) {
      for (const key of Object.keys(props as Record<string, unknown>)) {
        fields.add(key)
      }
    }
    // Recurse into if/then/else branches
    collectProps(s['if'])
    collectProps(s['then'])
    collectProps(s['else'])
  }

  collectProps(configSchema)
  return fields
}

/**
 * Map a Pydantic 422 error detail array to rjsf extraErrors + form-level messages.
 *
 * @param items        - The `detail` array from the 422 response body.
 * @param configSchema - The plugin's JSON Schema (from the discovery response).
 *                       Used to identify which error locs name real fields.
 * @returns { fieldErrors, formErrors }
 */
export function mapPydanticErrors(
  items: PydanticErrorItem[],
  configSchema: Record<string, unknown>,
): MappedPydanticErrors {
  const fields = knownFields(configSchema)
  const fieldErrors: ErrorSchema = {}
  const formErrors: string[] = []

  for (const item of items) {
    const message = extractMessage(item)
    // loc is optional in compat payloads (Pydantic v1, hand-crafted 422s).
    // Treat absent or non-array loc as an empty array → falls to formErrors.
    let loc: (string | number)[] = Array.isArray(item.loc) ? [...item.loc] : []

    // FastAPI wraps request-body Pydantic models under a "body" segment.
    if (loc[0] === 'body') {
      loc = loc.slice(1)
    }

    // A single string segment that matches a known schema field → inline error.
    if (loc.length === 1 && typeof loc[0] === 'string' && fields.has(loc[0])) {
      const fieldName = loc[0]
      const existing = fieldErrors[fieldName] as { __errors?: string[] } | undefined
      const prev: string[] = existing?.__errors ?? []
      // Cast to ErrorSchema to satisfy the recursive type; the shape is valid per rjsf contract.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      fieldErrors[fieldName] = { __errors: [...prev, message] } as ErrorSchema<any>
    } else {
      // Non-field or nested path → card-level summary.
      formErrors.push(message)
    }
  }

  return { fieldErrors, formErrors }
}
