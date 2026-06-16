/**
 * Tests for src/schema/uiSchema.ts and src/schema/schemaTransform.ts
 *
 * EARS criteria covered:
 *   - Ubiquitous: secrets (SecretStr / writeOnly / format:password) → PasswordWidget
 *   - D3 (R4 fix): nullable plain strings no longer produce a uiSchema entry;
 *     instead normalizeConfigSchema collapses anyOf[string,null] → type:["string","null"]
 *     so rjsf never sees the anyOf and never renders a discriminator dropdown.
 */

import { describe, it, expect } from 'vitest'
import { buildUiSchema } from '../schema/uiSchema'
import { normalizeConfigSchema } from '../schema/schemaTransform'
import { SURICATA_CONFIG_SCHEMA, MINIMAL_SOURCE_ENTRY } from './fixtures'

describe('buildUiSchema', () => {
  it('assigns PasswordWidget to format:password fields', () => {
    const uiSchema = buildUiSchema(MINIMAL_SOURCE_ENTRY.config_schema)
    expect(uiSchema['api_key']).toEqual({ 'ui:widget': 'PasswordWidget' })
  })

  it('does not assign PasswordWidget to plain string fields', () => {
    const uiSchema = buildUiSchema(MINIMAL_SOURCE_ENTRY.config_schema)
    expect(uiSchema['host']).toBeUndefined()
  })

  it('detects writeOnly inside anyOf for Suricata remote_key (nullable secret → NullablePasswordField)', () => {
    // remote_key is anyOf[{format:password, writeOnly:true, type:string}, {type:null}]
    // This is a nullable secret (SecretStr | None): buildUiSchema must map it to
    // NullablePasswordField + ui:fieldReplacesAnyOrOneOf:true so rjsf skips the
    // anyOf type-selector dropdown and presents the password input directly (#67).
    const uiSchema = buildUiSchema(SURICATA_CONFIG_SCHEMA)
    expect(uiSchema['remote_key']).toEqual({
      'ui:field': 'NullablePasswordField',
      'ui:fieldReplacesAnyOrOneOf': true,
    })
  })

  it('maps a simple (non-nullable) password field to PasswordWidget', () => {
    // A plain SecretStr (not Optional) → {type:string, format:password, writeOnly:true}
    // No anyOf → isNullablePasswordField returns false → isSimplePasswordField returns true
    const schema = {
      type: 'object',
      properties: {
        token: {
          type: 'string',
          format: 'password',
          writeOnly: true,
          title: 'API Token',
        },
      },
    }
    const uiSchema = buildUiSchema(schema)
    expect(uiSchema['token']).toEqual({ 'ui:widget': 'PasswordWidget' })
  })

  it('does not assign PasswordWidget to non-secret Suricata fields', () => {
    const uiSchema = buildUiSchema(SURICATA_CONFIG_SCHEMA)
    expect(uiSchema['mode']).toBeUndefined()
    expect(uiSchema['remote_host']).toBeUndefined()
    expect(uiSchema['local_path']).toBeUndefined()
  })

  it('returns empty object for a schema with no secret fields', () => {
    const schema = {
      type: 'object',
      properties: {
        name: { type: 'string', title: 'Name' },
        port: { type: 'integer', title: 'Port' },
      },
    }
    const uiSchema = buildUiSchema(schema)
    expect(Object.keys(uiSchema)).toHaveLength(0)
  })

  // D3 (R4 fix): buildUiSchema no longer produces a uiSchema entry for nullable plain strings.
  // The discriminator is suppressed at the SCHEMA level by normalizeConfigSchema().
  // After normalization, anyOf:[{type:string},{type:null}] becomes type:["string","null"]
  // so buildUiSchema sees no anyOf on that field and produces no entry.
  it('D3: buildUiSchema produces NO entry for nullable plain string — normalization handles it', () => {
    // Supply the RAW schema (not normalized); after normalization remote_user has no anyOf.
    // When buildUiSchema sees the normalized schema it must not produce a uiSchema entry.
    const normalizedSchema = normalizeConfigSchema(SURICATA_CONFIG_SCHEMA as Record<string, unknown>)
    const uiSchema = buildUiSchema(normalizedSchema)
    // After normalization, remote_user is type:["string","null"] — no anyOf → no uiSchema entry.
    expect(uiSchema['remote_user']).toBeUndefined()
  })

  // D3 regression: nullable password (remote_key) must NOT be collapsed by normalizeConfigSchema.
  it('D3: nullable password field (remote_key) is still mapped to NullablePasswordField after normalization', () => {
    // normalizeConfigSchema leaves anyOf[{password},{null}] intact (password marker present).
    const normalizedSchema = normalizeConfigSchema(SURICATA_CONFIG_SCHEMA as Record<string, unknown>)
    const uiSchema = buildUiSchema(normalizedSchema)
    expect(uiSchema['remote_key']).toEqual({
      'ui:field': 'NullablePasswordField',
      'ui:fieldReplacesAnyOrOneOf': true,
    })
  })

  it('detects writeOnly:true on a top-level property', () => {
    const schema = {
      type: 'object',
      properties: {
        secret_token: { type: 'string', writeOnly: true, title: 'Secret Token' },
      },
    }
    const uiSchema = buildUiSchema(schema)
    expect(uiSchema['secret_token']).toEqual({ 'ui:widget': 'PasswordWidget' })
  })
})

// ---------------------------------------------------------------------------
// normalizeConfigSchema — schema-level transformation tests (R4 / D3)
// ---------------------------------------------------------------------------
describe('normalizeConfigSchema — D3 / R4 fix', () => {
  // Core behaviour: anyOf[{type:string},{type:null}] collapses to type:["string","null"]
  it('collapses anyOf[string,null] into type:["string","null"] for a plain optional field', () => {
    const schema = {
      type: 'object',
      properties: {
        remote_user: {
          anyOf: [{ type: 'string' }, { type: 'null' }],
          default: null,
          title: 'SSH user',
        },
      },
    }
    const normalized = normalizeConfigSchema(schema)
    const prop = (normalized['properties'] as Record<string, unknown>)['remote_user'] as Record<string, unknown>
    expect(prop['type']).toEqual(['string', 'null'])
    expect(prop['anyOf']).toBeUndefined()
    // Original metadata preserved
    expect(prop['default']).toBe(null)
    expect(prop['title']).toBe('SSH user')
  })

  // Does NOT collapse nullable passwords (anyOf with writeOnly/format:password branch)
  it('leaves anyOf with a password branch intact (nullable secret not collapsed)', () => {
    const schema = {
      type: 'object',
      properties: {
        remote_key: {
          anyOf: [{ format: 'password', type: 'string', writeOnly: true }, { type: 'null' }],
          default: null,
          title: 'SSH key',
        },
      },
    }
    const normalized = normalizeConfigSchema(schema)
    const prop = (normalized['properties'] as Record<string, unknown>)['remote_key'] as Record<string, unknown>
    // anyOf must be preserved (for NullablePasswordField to work)
    expect(Array.isArray(prop['anyOf'])).toBe(true)
    expect(prop['type']).toBeUndefined()
  })

  // Collapses remote_user in the real Suricata schema
  it('collapses remote_user in the real SURICATA_CONFIG_SCHEMA', () => {
    const normalized = normalizeConfigSchema(SURICATA_CONFIG_SCHEMA as Record<string, unknown>)
    const props = normalized['properties'] as Record<string, Record<string, unknown>>
    const remoteUser = props['remote_user']
    expect(remoteUser['type']).toEqual(['string', 'null'])
    expect(remoteUser['anyOf']).toBeUndefined()
  })

  // remote_key in real schema is preserved
  it('preserves remote_key anyOf in the real SURICATA_CONFIG_SCHEMA', () => {
    const normalized = normalizeConfigSchema(SURICATA_CONFIG_SCHEMA as Record<string, unknown>)
    const props = normalized['properties'] as Record<string, Record<string, unknown>>
    const remoteKey = props['remote_key']
    expect(Array.isArray(remoteKey['anyOf'])).toBe(true)
    expect(remoteKey['type']).toBeUndefined()
  })

  // Does not mutate the original schema
  it('does not mutate the original schema object', () => {
    const original = {
      type: 'object',
      properties: {
        name: { anyOf: [{ type: 'string' }, { type: 'null' }] },
      },
    }
    normalizeConfigSchema(original)
    // Original is unchanged
    expect((original.properties.name as Record<string, unknown>)['anyOf']).toBeDefined()
    expect((original.properties.name as Record<string, unknown>)['type']).toBeUndefined()
  })

  // oneOf variant also collapsed
  it('collapses oneOf[{type:string},{type:null}] into type:["string","null"]', () => {
    const schema = {
      type: 'object',
      properties: {
        label: {
          oneOf: [{ type: 'string' }, { type: 'null' }],
          title: 'Label',
        },
      },
    }
    const normalized = normalizeConfigSchema(schema)
    const prop = (normalized['properties'] as Record<string, unknown>)['label'] as Record<string, unknown>
    expect(prop['type']).toEqual(['string', 'null'])
    expect(prop['oneOf']).toBeUndefined()
  })

  // Non-2-branch anyOf (e.g. anyOf with 3 branches) is left unchanged
  it('does not collapse anyOf with more than 2 branches', () => {
    const schema = {
      type: 'object',
      properties: {
        multi: {
          anyOf: [{ type: 'string' }, { type: 'number' }, { type: 'null' }],
        },
      },
    }
    const normalized = normalizeConfigSchema(schema)
    const prop = (normalized['properties'] as Record<string, unknown>)['multi'] as Record<string, unknown>
    expect(Array.isArray(prop['anyOf'])).toBe(true)
    expect(prop['type']).toBeUndefined()
  })
})
