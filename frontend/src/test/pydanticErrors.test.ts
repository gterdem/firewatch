/**
 * Unit tests for src/schema/pydanticErrors.ts — mapPydanticErrors helper.
 *
 * EARS criteria covered:
 *   - A loc that names a known schema field → appears in fieldErrors ErrorSchema.
 *   - A loc wrapped with a leading "body" segment → body is stripped; field is resolved.
 *   - A loc that is empty [] → non-field → appears in formErrors.
 *   - A loc pointing to a field not in the schema → non-field → appears in formErrors.
 *   - Multiple errors → partitioned correctly across fieldErrors and formErrors.
 *   - Multiple messages for the same field → accumulated in __errors array.
 *   - Branch-only fields (then.properties, else.properties) are recognised.
 */

import { describe, it, expect } from 'vitest'
import { mapPydanticErrors } from '../schema/pydanticErrors'

/** Minimal flat config schema with two properties */
const FLAT_SCHEMA = {
  type: 'object',
  title: 'FlatConfig',
  properties: {
    host: { type: 'string', title: 'Host' },
    port: { type: 'integer', title: 'Port' },
  },
} as const

/** Schema that uses if/then/else — SSH fields only in then.properties */
const CONDITIONAL_SCHEMA = {
  type: 'object',
  title: 'ConditionalConfig',
  properties: {
    mode: { type: 'string', enum: ['local', 'remote'] },
    local_path: { type: 'string' },
  },
  if: { properties: { mode: { const: 'remote' } } },
  then: {
    properties: {
      remote_host: { type: 'string' },
      remote_port: { type: 'integer' },
    },
  },
  else: {
    properties: {
      local_path: { type: 'string' },
    },
  },
} as const

describe('mapPydanticErrors', () => {
  it('maps a field-scoped loc to fieldErrors ErrorSchema', () => {
    const { fieldErrors, formErrors } = mapPydanticErrors(
      [{ loc: ['host'], msg: 'host must be an IP literal', type: 'value_error' }],
      FLAT_SCHEMA,
    )

    expect(fieldErrors).toMatchObject({
      host: { __errors: ['host must be an IP literal'] },
    })
    expect(formErrors).toHaveLength(0)
  })

  it('strips a leading "body" segment and resolves the remaining field', () => {
    const { fieldErrors, formErrors } = mapPydanticErrors(
      [{ loc: ['body', 'port'], msg: 'port must be ≥ 1', type: 'value_error' }],
      FLAT_SCHEMA,
    )

    expect(fieldErrors).toMatchObject({
      port: { __errors: ['port must be ≥ 1'] },
    })
    expect(formErrors).toHaveLength(0)
  })

  it('puts empty loc [] errors into formErrors', () => {
    const { fieldErrors, formErrors } = mapPydanticErrors(
      [{ loc: [], msg: 'Authorization failed', type: 'value_error' }],
      FLAT_SCHEMA,
    )

    expect(Object.keys(fieldErrors)).toHaveLength(0)
    expect(formErrors).toEqual(['Authorization failed'])
  })

  it('puts errors whose loc field does not exist in schema into formErrors', () => {
    const { fieldErrors, formErrors } = mapPydanticErrors(
      [{ loc: ['nonexistent'], msg: 'unknown field', type: 'value_error' }],
      FLAT_SCHEMA,
    )

    expect(Object.keys(fieldErrors)).toHaveLength(0)
    expect(formErrors).toEqual(['unknown field'])
  })

  it('partitions a mixed error list across fieldErrors and formErrors', () => {
    const { fieldErrors, formErrors } = mapPydanticErrors(
      [
        { loc: ['host'], msg: 'host must be an IP literal', type: 'value_error' },
        { loc: [], msg: 'form-level error', type: 'value_error' },
        { loc: ['port'], msg: 'port out of range', type: 'value_error' },
      ],
      FLAT_SCHEMA,
    )

    expect(fieldErrors).toMatchObject({
      host: { __errors: ['host must be an IP literal'] },
      port: { __errors: ['port out of range'] },
    })
    expect(formErrors).toEqual(['form-level error'])
  })

  it('accumulates multiple messages for the same field in one __errors array', () => {
    const { fieldErrors, formErrors } = mapPydanticErrors(
      [
        { loc: ['host'], msg: 'too short', type: 'value_error' },
        { loc: ['host'], msg: 'must not contain spaces', type: 'value_error' },
      ],
      FLAT_SCHEMA,
    )

    expect((fieldErrors['host'] as { __errors: string[] }).__errors).toEqual([
      'too short',
      'must not contain spaces',
    ])
    expect(formErrors).toHaveLength(0)
  })

  it('falls back to JSON.stringify when both msg and message are absent', () => {
    const item = { loc: ['host'], type: 'value_error' } as { loc: string[]; type: string }
    const { fieldErrors } = mapPydanticErrors([item as Parameters<typeof mapPydanticErrors>[0][0]], FLAT_SCHEMA)

    // Should still attach something to the field
    const errors = (fieldErrors['host'] as { __errors: string[] }).__errors
    expect(errors).toHaveLength(1)
    expect(typeof errors[0]).toBe('string')
  })

  it('recognises branch-only fields in then.properties', () => {
    const { fieldErrors, formErrors } = mapPydanticErrors(
      [{ loc: ['remote_host'], msg: 'remote_host is required', type: 'value_error' }],
      CONDITIONAL_SCHEMA,
    )

    expect(fieldErrors).toMatchObject({
      remote_host: { __errors: ['remote_host is required'] },
    })
    expect(formErrors).toHaveLength(0)
  })

  it('recognises branch-only fields in else.properties', () => {
    const { fieldErrors, formErrors } = mapPydanticErrors(
      [{ loc: ['local_path'], msg: 'local_path must be absolute', type: 'value_error' }],
      CONDITIONAL_SCHEMA,
    )

    expect(fieldErrors).toMatchObject({
      local_path: { __errors: ['local_path must be absolute'] },
    })
    expect(formErrors).toHaveLength(0)
  })

  it('treats a nested loc (multi-segment after body strip) as form-level', () => {
    // ["address", "port"] — nested path, only top-level field mapping is in scope
    const { fieldErrors, formErrors } = mapPydanticErrors(
      [{ loc: ['address', 'port'], msg: 'port invalid', type: 'value_error' }],
      FLAT_SCHEMA,
    )

    expect(Object.keys(fieldErrors)).toHaveLength(0)
    expect(formErrors).toEqual(['port invalid'])
  })

  it('handles an empty items array gracefully', () => {
    const { fieldErrors, formErrors } = mapPydanticErrors([], FLAT_SCHEMA)
    expect(Object.keys(fieldErrors)).toHaveLength(0)
    expect(formErrors).toHaveLength(0)
  })
})
