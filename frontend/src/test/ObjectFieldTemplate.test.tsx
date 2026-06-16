/**
 * Tests for src/widgets/ObjectFieldTemplate.tsx and src/widgets/partitionFields.ts
 * (R2, #490 — required-first grouping with collapsed Advanced section)
 *
 * EARS acceptance criteria covered:
 *
 *   EARS-1 (Ubiquitous — Essential/Advanced partition):
 *     The object field template SHALL render schema-`required` fields (and fields
 *     lacking a `default`/value) in an always-visible "Essential" group, and fields
 *     with a `default` (plus blank secret/`writeOnly` fields) in a collapsed
 *     "Advanced" group.
 *
 *   EARS-2 (Ubiquitous — schema-metadata-only partition):
 *     The Essential/Advanced partition SHALL be derived from schema metadata only
 *     (`required`, `default`, `writeOnly`) with no field-name allowlists and no
 *     per-source-type branching.
 *
 *   EARS-3 (Event-driven — ui:order):
 *     WHEN a plugin supplies `ui:order`, the template SHALL render fields in that
 *     order within their groups.
 *     (Tested at partitionFields level: order of orderedNames is preserved.)
 *
 *   EARS-4 (Ubiquitous — no inner scroll):
 *     Expanding the "Advanced" group SHALL grow the card height and SHALL NOT
 *     introduce a scroll region inside the card.
 *     (Tested: the details/content containers have no overflow:hidden/scroll style.)
 *
 *   EARS-5 (Ubiquitous a11y):
 *     The "Advanced" group toggle SHALL be keyboard-operable with `aria-expanded`.
 *     (Tested: native <details>/<summary> provides keyboard operability natively;
 *      the summary element is present and data-fw-advanced-toggle is set.)
 *
 * Additional unit tests cover the partition helpers (partitionFields.ts) exhaustively.
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import type {
  ObjectFieldTemplateProps,
  ObjectFieldTemplatePropertyType,
  FieldPathId,
  RJSFSchema,
} from '@rjsf/utils'
import ObjectFieldTemplate from '../widgets/ObjectFieldTemplate'
import {
  partitionFields,
  isWriteOnlyField,
  hasMeaningfulDefault,
  getDiscriminatorFields,
} from '../widgets/partitionFields'

// ---------------------------------------------------------------------------
// partitionFields.ts unit tests (pure logic, no React)
// ---------------------------------------------------------------------------

describe('isWriteOnlyField', () => {
  it('returns true for a direct writeOnly:true property', () => {
    expect(isWriteOnlyField({ type: 'string', writeOnly: true })).toBe(true)
  })

  it('returns true when writeOnly appears in an anyOf branch (nullable secret)', () => {
    expect(
      isWriteOnlyField({
        anyOf: [{ type: 'string', format: 'password', writeOnly: true }, { type: 'null' }],
        default: null,
      } as RJSFSchema),
    ).toBe(true)
  })

  it('returns true when writeOnly appears in a oneOf branch', () => {
    expect(
      isWriteOnlyField({
        oneOf: [{ type: 'string', writeOnly: true }, { type: 'null' }],
        default: null,
      } as RJSFSchema),
    ).toBe(true)
  })

  it('returns false for a plain string field (no writeOnly)', () => {
    expect(isWriteOnlyField({ type: 'string', title: 'Host', default: 'localhost' })).toBe(false)
  })

  it('returns false for an enum field', () => {
    expect(
      isWriteOnlyField({ type: 'string', enum: ['a', 'b'], default: 'a' } as RJSFSchema),
    ).toBe(false)
  })

  it('returns false for an integer field', () => {
    expect(isWriteOnlyField({ type: 'integer', default: 5 })).toBe(false)
  })

  it('returns false for an empty schema', () => {
    expect(isWriteOnlyField({})).toBe(false)
  })
})

describe('hasMeaningfulDefault', () => {
  it('returns false when no default key exists', () => {
    expect(hasMeaningfulDefault({ type: 'string', title: 'Host' })).toBe(false)
  })

  it('returns false when default is null', () => {
    expect(hasMeaningfulDefault({ type: 'string', default: null } as RJSFSchema)).toBe(false)
  })

  it('returns false when default is empty string ""', () => {
    expect(hasMeaningfulDefault({ type: 'string', default: '' })).toBe(false)
  })

  it('returns true when default is a non-empty string', () => {
    expect(hasMeaningfulDefault({ type: 'string', default: 'localhost' })).toBe(true)
    expect(hasMeaningfulDefault({ type: 'string', default: 'resource_specific' })).toBe(true)
  })

  it('returns true when default is a non-zero integer', () => {
    expect(hasMeaningfulDefault({ type: 'integer', default: 5 })).toBe(true)
    expect(hasMeaningfulDefault({ type: 'integer', default: 50000 })).toBe(true)
  })

  it('returns true when default is 0 (zero is an explicit meaningful choice)', () => {
    // 0 is a meaningful integer default (e.g. overlap_minutes = 0 means "no overlap")
    expect(hasMeaningfulDefault({ type: 'integer', default: 0 })).toBe(true)
  })

  it('returns true when default is boolean true', () => {
    expect(hasMeaningfulDefault({ type: 'boolean', default: true })).toBe(true)
  })

  it('returns true when default is boolean false', () => {
    expect(hasMeaningfulDefault({ type: 'boolean', default: false })).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// getDiscriminatorFields() — #696 if/then/else discriminator detection
// ---------------------------------------------------------------------------

describe('getDiscriminatorFields', () => {
  it('returns the keys of schema.if.properties when present', () => {
    const schema: RJSFSchema = {
      type: 'object',
      if: { properties: { mode: { const: 'remote' } } } as RJSFSchema,
      then: { required: ['remote_host'] } as RJSFSchema,
      properties: {
        mode: { type: 'string', enum: ['local', 'remote'], default: 'local' } as RJSFSchema,
        remote_host: { type: 'string', default: '' },
      },
    }
    const fields = getDiscriminatorFields(schema)
    expect(fields.has('mode')).toBe(true)
    expect(fields.size).toBe(1)
  })

  it('returns an empty set when schema has no if clause', () => {
    const schema: RJSFSchema = {
      type: 'object',
      properties: { port: { type: 'integer', default: 514 } },
    }
    expect(getDiscriminatorFields(schema).size).toBe(0)
  })

  it('returns an empty set when schema.if has no properties key', () => {
    const schema: RJSFSchema = {
      type: 'object',
      if: { required: ['mode'] } as RJSFSchema,
      properties: { mode: { type: 'string', default: 'local' } },
    }
    expect(getDiscriminatorFields(schema).size).toBe(0)
  })

  it('supports multiple discriminator keys in schema.if.properties', () => {
    const schema: RJSFSchema = {
      type: 'object',
      if: {
        properties: {
          protocol: { const: 'tcp' },
          tls: { const: true },
        },
      } as RJSFSchema,
      properties: {
        protocol: { type: 'string', default: 'udp' } as RJSFSchema,
        tls: { type: 'boolean', default: false },
      },
    }
    const fields = getDiscriminatorFields(schema)
    expect(fields.has('protocol')).toBe(true)
    expect(fields.has('tls')).toBe(true)
    expect(fields.size).toBe(2)
  })
})

// ---------------------------------------------------------------------------
// partitionFields() — EARS-1 and EARS-2 (core partition logic)
// ---------------------------------------------------------------------------

describe('partitionFields — schema-metadata-only partition (EARS-1, EARS-2)', () => {
  it('puts schema.required fields in Essential regardless of default', () => {
    const schema: RJSFSchema = {
      type: 'object',
      required: ['workspace_id'],
      properties: {
        workspace_id: { type: 'string', default: '' },
        port: { type: 'integer', default: 8080 },
      },
    }
    const { essential, advanced } = partitionFields(['workspace_id', 'port'], schema)
    expect(essential.map((s) => s.name)).toContain('workspace_id')
    expect(advanced.map((s) => s.name)).toContain('port')
  })

  it('puts fields with no default key in Essential', () => {
    const schema: RJSFSchema = {
      type: 'object',
      properties: {
        host: { type: 'string', title: 'Host' }, // no default key
        port: { type: 'integer', default: 514 },
      },
    }
    const { essential, advanced } = partitionFields(['host', 'port'], schema)
    expect(essential.map((s) => s.name)).toContain('host')
    expect(advanced.map((s) => s.name)).toContain('port')
  })

  it('puts fields with default:null in Essential (they have no meaningful value)', () => {
    const schema: RJSFSchema = {
      type: 'object',
      properties: {
        label: { type: 'string', default: null } as RJSFSchema,
        timeout: { type: 'integer', default: 30 },
      },
    }
    const { essential, advanced } = partitionFields(['label', 'timeout'], schema)
    expect(essential.map((s) => s.name)).toContain('label')
    expect(advanced.map((s) => s.name)).toContain('timeout')
  })

  it('puts fields with default:"" in Essential (empty string signals must-fill)', () => {
    const schema: RJSFSchema = {
      type: 'object',
      properties: {
        workspace_id: { type: 'string', default: '' },  // Azure WAF workspace_id case
        overlap_minutes: { type: 'integer', default: 5 },
      },
    }
    const { essential, advanced } = partitionFields(['workspace_id', 'overlap_minutes'], schema)
    expect(essential.map((s) => s.name)).toContain('workspace_id')
    expect(advanced.map((s) => s.name)).toContain('overlap_minutes')
  })

  it('puts writeOnly fields in Advanced (they are optional credentials)', () => {
    const schema: RJSFSchema = {
      type: 'object',
      properties: {
        // Azure-style SP secret: anyOf[{password},{null}] with default:null
        client_secret: {
          anyOf: [{ type: 'string', format: 'password', writeOnly: true }, { type: 'null' }],
          default: null,
        } as RJSFSchema,
        workspace_id: { type: 'string', default: '' },
      },
    }
    const { essential, advanced } = partitionFields(['client_secret', 'workspace_id'], schema)
    expect(advanced.map((s) => s.name)).toContain('client_secret')
    expect(essential.map((s) => s.name)).toContain('workspace_id')
  })

  it('preserves relative order within Essential and Advanced groups (EARS-3 / ui:order)', () => {
    // orderedNames is the pre-sorted list (ui:order already applied by rjsf)
    const schema: RJSFSchema = {
      type: 'object',
      properties: {
        alpha: { type: 'string', default: '' },   // Essential
        beta: { type: 'integer', default: 5 },    // Advanced
        gamma: { type: 'string', default: '' },   // Essential
        delta: { type: 'integer', default: 10 },  // Advanced
      },
    }
    const { essential, advanced } = partitionFields(['alpha', 'beta', 'gamma', 'delta'], schema)
    expect(essential.map((s) => s.name)).toEqual(['alpha', 'gamma'])
    expect(advanced.map((s) => s.name)).toEqual(['beta', 'delta'])
  })

  it('produces empty Advanced when all fields are Essential (all have no/null/"" default)', () => {
    const schema: RJSFSchema = {
      type: 'object',
      properties: {
        a: { type: 'string' },
        b: { type: 'string', default: null } as RJSFSchema,
        c: { type: 'string', default: '' },
      },
    }
    const { essential, advanced } = partitionFields(['a', 'b', 'c'], schema)
    expect(essential).toHaveLength(3)
    expect(advanced).toHaveLength(0)
  })

  // #574 empty-card guard: when ALL non-writeOnly fields have meaningful defaults
  // (and none are required), they would all go to Advanced, leaving an empty-
  // looking card.  The guard promotes them all back to Essential so the card
  // always shows at least one visible field.
  it('#574: promotes all Advanced fields to Essential when Essential would be empty (empty-card guard)', () => {
    const schema: RJSFSchema = {
      type: 'object',
      properties: {
        timeout: { type: 'integer', default: 30 },
        retries: { type: 'integer', default: 3 },
      },
    }
    const { essential, advanced } = partitionFields(['timeout', 'retries'], schema)
    // Both fields are promoted to Essential — the card shows them up-front.
    expect(essential).toHaveLength(2)
    expect(essential.map((s) => s.name)).toContain('timeout')
    expect(essential.map((s) => s.name)).toContain('retries')
    // Advanced is empty after promotion.
    expect(advanced).toHaveLength(0)
  })

  // When ALL non-writeOnly fields have meaningful defaults AND there are also
  // writeOnly fields, only the non-writeOnly ones are promoted; writeOnly stays
  // in Advanced (they are optional credentials, not operationally-critical config).
  it('#574: writeOnly fields stay in Advanced even after empty-card guard promotion', () => {
    const schema: RJSFSchema = {
      type: 'object',
      properties: {
        bind_address: { type: 'string', default: '0.0.0.0' },
        port: { type: 'integer', default: 514 },
        secret_key: {
          anyOf: [{ type: 'string', writeOnly: true }, { type: 'null' }],
          default: null,
        } as RJSFSchema,
      },
    }
    const { essential, advanced } = partitionFields(['bind_address', 'port', 'secret_key'], schema)
    // Non-writeOnly fields promoted to Essential (empty-card guard)
    expect(essential.map((s) => s.name)).toContain('bind_address')
    expect(essential.map((s) => s.name)).toContain('port')
    // writeOnly credential stays in Advanced
    expect(advanced.map((s) => s.name)).toContain('secret_key')
  })

  it('handles an empty schema (no properties, no required) without throwing', () => {
    const schema: RJSFSchema = { type: 'object' }
    const { essential, advanced } = partitionFields(['orphan'], schema)
    // Unknown field has no propSchema → no default → Essential
    expect(essential.map((s) => s.name)).toContain('orphan')
    expect(advanced).toHaveLength(0)
  })

  // EARS-2: no field-name allowlists — the exact same rules apply to ANY plugin schema.
  // This test uses a schema WITHOUT an if/then/else clause; mode is a plain defaulted
  // field and should go to Advanced (no discriminator exemption applies here).
  it('EARS-2: schema-metadata-only — plain defaulted field without if clause goes to Advanced', () => {
    const schema: RJSFSchema = {
      type: 'object',
      required: ['remote_host'],
      properties: {
        mode: { type: 'string', enum: ['local', 'remote'], default: 'local' } as RJSFSchema,
        remote_host: { type: 'string', default: '' },
        remote_key: {
          anyOf: [{ type: 'string', writeOnly: true }, { type: 'null' }],
          default: null,
        } as RJSFSchema,
      },
    }
    const { essential, advanced } = partitionFields(['mode', 'remote_host', 'remote_key'], schema)
    // mode has meaningful default and NO if clause → Advanced (no discriminator exemption)
    expect(advanced.map((s) => s.name)).toContain('mode')
    // remote_host is required → Essential
    expect(essential.map((s) => s.name)).toContain('remote_host')
    // remote_key is writeOnly → Advanced
    expect(advanced.map((s) => s.name)).toContain('remote_key')
  })

  // #696 — if/then/else discriminator fields MUST be Essential regardless of default.
  // EARS criterion: WHEN a field appears in schema.if.properties (it is the
  // conditional discriminator), the partition SHALL classify it as Essential even
  // when it has a meaningful default.
  it('#696: discriminator field in schema.if.properties lands in Essential despite having a default', () => {
    // Real Suricata-like schema: mode drives the if/then/else (remote SSH field group).
    // mode has default="local" which normally pushes it to Advanced.
    const schema: RJSFSchema = {
      type: 'object',
      properties: {
        mode: { type: 'string', enum: ['local', 'remote'], default: 'local' } as RJSFSchema,
        remote_host: { type: 'string', default: '' },
        timeout: { type: 'integer', default: 30 },
      },
      // mode is the discriminator: schema.if.properties contains "mode"
      if: { properties: { mode: { const: 'remote' } } } as RJSFSchema,
      then: { required: ['remote_host'] } as RJSFSchema,
    }
    const { essential, advanced } = partitionFields(
      ['mode', 'remote_host', 'timeout'],
      schema,
    )
    // mode is the discriminator → Essential (even with default="local")
    expect(essential.map((s) => s.name)).toContain('mode')
    expect(advanced.map((s) => s.name)).not.toContain('mode')
    // remote_host has default="" → Essential (no-default rule still applies)
    expect(essential.map((s) => s.name)).toContain('remote_host')
    // timeout has a meaningful default and is NOT a discriminator → Advanced
    expect(advanced.map((s) => s.name)).toContain('timeout')
  })

  // #696 — a non-discriminator defaulted field is still classified as Advanced.
  // This confirms the discriminator exemption is targeted, not broad.
  it('#696: non-discriminator defaulted field still goes to Advanced when schema has an if clause', () => {
    const schema: RJSFSchema = {
      type: 'object',
      properties: {
        mode: { type: 'string', enum: ['local', 'remote'], default: 'local' } as RJSFSchema,
        overlap_minutes: { type: 'integer', default: 5 }, // NOT a discriminator
        timeout: { type: 'integer', default: 30 },        // NOT a discriminator
      },
      if: { properties: { mode: { const: 'remote' } } } as RJSFSchema,
      then: { required: [] } as RJSFSchema,
    }
    const { essential, advanced } = partitionFields(
      ['mode', 'overlap_minutes', 'timeout'],
      schema,
    )
    // mode is the discriminator → Essential
    expect(essential.map((s) => s.name)).toContain('mode')
    // overlap_minutes and timeout are NOT discriminators → Advanced (meaningful defaults)
    expect(advanced.map((s) => s.name)).toContain('overlap_minutes')
    expect(advanced.map((s) => s.name)).toContain('timeout')
  })

  // Azure WAF full schema partition — validates the expected first-run UX
  it('Azure WAF schema: workspace_id Essential, SP secrets and tuning ints Advanced', () => {
    // Actual Azure WAF JSON Schema (from AzureWAFConfig.model_json_schema())
    const azureSchema: RJSFSchema = {
      type: 'object',
      properties: {
        workspace_id: { type: 'string', default: '' },
        table_regime: {
          type: 'string',
          enum: ['resource_specific', 'azure_diagnostics'],
          default: 'resource_specific',
        } as RJSFSchema,
        product: {
          type: 'string',
          enum: ['app_gateway', 'front_door', 'both'],
          default: 'both',
        } as RJSFSchema,
        tenant_id: {
          anyOf: [{ type: 'string', format: 'password', writeOnly: true }, { type: 'null' }],
          default: null,
        } as RJSFSchema,
        client_id: {
          anyOf: [{ type: 'string', format: 'password', writeOnly: true }, { type: 'null' }],
          default: null,
        } as RJSFSchema,
        client_secret: {
          anyOf: [{ type: 'string', format: 'password', writeOnly: true }, { type: 'null' }],
          default: null,
        } as RJSFSchema,
        overlap_minutes: { type: 'integer', default: 5 },
        max_events_per_collect: { type: 'integer', default: 50000 },
      },
    }
    const fields = [
      'workspace_id',
      'table_regime',
      'product',
      'tenant_id',
      'client_id',
      'client_secret',
      'overlap_minutes',
      'max_events_per_collect',
    ]
    const { essential, advanced } = partitionFields(fields, azureSchema)

    // workspace_id has default:"" → Essential (operator must fill it in)
    expect(essential.map((s) => s.name)).toContain('workspace_id')

    // SP secrets (writeOnly) → Advanced
    expect(advanced.map((s) => s.name)).toContain('tenant_id')
    expect(advanced.map((s) => s.name)).toContain('client_id')
    expect(advanced.map((s) => s.name)).toContain('client_secret')

    // Tuning ints with meaningful defaults → Advanced
    expect(advanced.map((s) => s.name)).toContain('overlap_minutes')
    expect(advanced.map((s) => s.name)).toContain('max_events_per_collect')

    // workspace_id NOT in Advanced
    expect(advanced.map((s) => s.name)).not.toContain('workspace_id')
  })
})

// ---------------------------------------------------------------------------
// ObjectFieldTemplate component rendering tests
// ---------------------------------------------------------------------------

/**
 * Minimal stub registry that satisfies getTemplate() and getUiOptions().
 * The templates needed are TitleFieldTemplate, DescriptionFieldTemplate,
 * AddButton — we provide no-op stubs since we're testing grouping logic.
 */
function makeRegistry(): ObjectFieldTemplateProps['registry'] {
  const noopComponent = () => null
  return {
    formContext: {},
    widgets: {},
    fields: {},
    templates: {
      TitleFieldTemplate: noopComponent,
      DescriptionFieldTemplate: noopComponent,
      ButtonTemplates: {
        AddButton: noopComponent,
      },
    } as unknown as ObjectFieldTemplateProps['registry']['templates'],
    rootSchema: {},
    schemaUtils: {} as ObjectFieldTemplateProps['registry']['schemaUtils'],
    translateString: (s: string) => s,
    globalUiOptions: {},
  } as unknown as ObjectFieldTemplateProps['registry']
}

/** Build a minimal property slot from a field name and content JSX. */
function makeProp(name: string, content: React.ReactElement): ObjectFieldTemplatePropertyType {
  return { name, content, hidden: false }
}

/** Minimal ObjectFieldTemplateProps stub. */
function makeTemplateProps(
  overrides: Partial<ObjectFieldTemplateProps> = {},
): ObjectFieldTemplateProps {
  return {
    title: '',
    description: '',
    properties: [],
    required: false,
    uiSchema: {},
    fieldPathId: { $id: 'root', path: [] } as FieldPathId,
    schema: { type: 'object', properties: {} } as RJSFSchema,
    formData: {},
    onAddProperty: vi.fn(),
    disabled: false,
    readonly: false,
    hideError: false,
    registry: makeRegistry(),
    ...overrides,
  } as ObjectFieldTemplateProps
}

describe('ObjectFieldTemplate — component rendering (EARS-1, EARS-4, EARS-5)', () => {
  // EARS-1: Essential fields are visible; Advanced fields are in a collapsed group.
  it('EARS-1: renders Essential fields in the main section (always visible)', () => {
    const props = makeTemplateProps({
      schema: {
        type: 'object',
        properties: {
          workspace_id: { type: 'string', default: '' },  // Essential (empty default)
          overlap: { type: 'integer', default: 5 },       // Advanced (meaningful default)
        },
      } as RJSFSchema,
      properties: [
        makeProp('workspace_id', <input data-testid="workspace-input" />),
        makeProp('overlap', <input data-testid="overlap-input" />),
      ],
    })
    render(<ObjectFieldTemplate {...props} />)

    // workspace_id (Essential) is visible directly — not inside <details>
    const workspaceInput = screen.getByTestId('workspace-input')
    expect(workspaceInput).toBeInTheDocument()

    // overlap (Advanced) is inside the <details> disclosure
    const advancedDetails = document.querySelector('[data-fw-advanced-group]')
    expect(advancedDetails).toBeInTheDocument()
    const overlapInput = screen.getByTestId('overlap-input')
    expect(overlapInput).toBeInTheDocument() // present in DOM (may be collapsed)
  })

  // EARS-1: Advanced group is rendered when there are Advanced fields.
  it('EARS-1: renders the Advanced disclosure group when there are Advanced fields', () => {
    const props = makeTemplateProps({
      schema: {
        type: 'object',
        properties: {
          workspace_id: { type: 'string', default: '' },
          timeout: { type: 'integer', default: 30 },
        },
      } as RJSFSchema,
      properties: [
        makeProp('workspace_id', <span>ws</span>),
        makeProp('timeout', <span>timeout</span>),
      ],
    })
    render(<ObjectFieldTemplate {...props} />)
    expect(document.querySelector('[data-fw-advanced-group]')).toBeInTheDocument()
    expect(document.querySelector('[data-fw-advanced-toggle]')).toBeInTheDocument()
  })

  // EARS-1: No Advanced group when all fields are Essential.
  it('EARS-1: does NOT render the Advanced group when all fields are Essential', () => {
    const props = makeTemplateProps({
      schema: {
        type: 'object',
        properties: {
          a: { type: 'string' },          // no default → Essential
          b: { type: 'string', default: '' },  // empty default → Essential
        },
      } as RJSFSchema,
      properties: [
        makeProp('a', <span>a</span>),
        makeProp('b', <span>b</span>),
      ],
    })
    render(<ObjectFieldTemplate {...props} />)
    expect(document.querySelector('[data-fw-advanced-group]')).toBeNull()
  })

  // EARS-5 (a11y): native <details>/<summary> for keyboard operability.
  it('EARS-5: Advanced toggle uses native <details>/<summary> (keyboard-operable)', () => {
    const props = makeTemplateProps({
      schema: {
        type: 'object',
        properties: {
          x: { type: 'string', default: '' },
          y: { type: 'integer', default: 99 },
        },
      } as RJSFSchema,
      properties: [
        makeProp('x', <span>x</span>),
        makeProp('y', <span>y</span>),
      ],
    })
    render(<ObjectFieldTemplate {...props} />)

    const details = document.querySelector('[data-fw-advanced-group]')
    expect(details?.tagName.toLowerCase()).toBe('details')

    const summary = document.querySelector('[data-fw-advanced-toggle]')
    expect(summary?.tagName.toLowerCase()).toBe('summary')
  })

  // EARS-5: The summary label is "Advanced / Optional".
  // Schema must have both an Essential field and an Advanced field; a single-field
  // all-Advanced schema triggers the #574 empty-card guard and promotes it to Essential.
  it('EARS-5: Advanced toggle text is "Advanced / Optional"', () => {
    const props = makeTemplateProps({
      schema: {
        type: 'object',
        properties: {
          // Essential: empty-string default signals "must fill"
          host: { type: 'string', default: '' },
          // Advanced: meaningful integer default
          f: { type: 'integer', default: 5 },
        },
      } as RJSFSchema,
      properties: [
        makeProp('host', <span>host</span>),
        makeProp('f', <span>f</span>),
      ],
    })
    render(<ObjectFieldTemplate {...props} />)
    expect(screen.getByText('Advanced / Optional')).toBeInTheDocument()
  })

  // EARS-4: no overflow:hidden/auto/scroll in the Advanced content container (no inner scroll).
  // Schema must have both an Essential and an Advanced field; a single-field all-Advanced
  // schema triggers the #574 empty-card guard (no Advanced group rendered).
  it('EARS-4: Advanced content container has no overflow:hidden/scroll (no inner scroll region)', () => {
    const props = makeTemplateProps({
      schema: {
        type: 'object',
        properties: {
          // Essential: empty-string default
          host: { type: 'string', default: '' },
          // Advanced: meaningful integer default
          g: { type: 'integer', default: 1 },
        },
      } as RJSFSchema,
      properties: [
        makeProp('host', <span>host</span>),
        makeProp('g', <span>g</span>),
      ],
    })
    render(<ObjectFieldTemplate {...props} />)
    const content = document.querySelector('[data-fw-advanced-content]') as HTMLElement | null
    expect(content).not.toBeNull()
    const overflow = content!.style.overflow
    expect(overflow).not.toMatch(/hidden|auto|scroll/)
  })

  // #573: Advanced toggle has a chevron SVG affordance indicating expand/collapse.
  it('#573: Advanced toggle contains a chevron SVG element for expand/collapse affordance', () => {
    const props = makeTemplateProps({
      schema: {
        type: 'object',
        properties: {
          host: { type: 'string', default: '' },     // Essential
          timeout: { type: 'integer', default: 30 }, // Advanced
        },
      } as RJSFSchema,
      properties: [
        makeProp('host', <span>host</span>),
        makeProp('timeout', <span>timeout</span>),
      ],
    })
    render(<ObjectFieldTemplate {...props} />)

    const summary = document.querySelector('[data-fw-advanced-toggle]')
    expect(summary).not.toBeNull()
    // Chevron SVG is inside the summary element
    const chevron = summary!.querySelector('svg.fw-chevron')
    expect(chevron).not.toBeNull()
  })

  // #574 Syslog-like: all non-writeOnly fields have defaults → empty-card guard
  // promotes them to Essential so the card body shows visible fields.
  it('#574: Syslog-like schema (all fields have defaults) shows all fields in Essential — no empty card', () => {
    const props = makeTemplateProps({
      schema: {
        type: 'object',
        // No required array — all fields have meaningful defaults (typical Syslog shape)
        properties: {
          bind_address: { type: 'string', default: '0.0.0.0' },
          port: { type: 'integer', default: 514 },
          protocol: { type: 'string', enum: ['udp', 'tcp'], default: 'udp' },
        },
      } as RJSFSchema,
      properties: [
        makeProp('bind_address', <input data-testid="bind-address" />),
        makeProp('port', <input data-testid="port" />),
        makeProp('protocol', <select data-testid="protocol" />),
      ],
    })
    render(<ObjectFieldTemplate {...props} />)

    // All three fields are visible — not collapsed under Advanced
    expect(screen.getByTestId('bind-address')).toBeInTheDocument()
    expect(screen.getByTestId('port')).toBeInTheDocument()
    expect(screen.getByTestId('protocol')).toBeInTheDocument()

    // No Advanced group — all fields promoted to Essential
    expect(document.querySelector('[data-fw-advanced-group]')).toBeNull()
  })

  // writeOnly fields are placed in Advanced (Azure SP fields case).
  it('writeOnly/secret fields are rendered inside the Advanced group', () => {
    const props = makeTemplateProps({
      schema: {
        type: 'object',
        properties: {
          workspace_id: { type: 'string', default: '' },
          client_secret: {
            anyOf: [{ type: 'string', writeOnly: true }, { type: 'null' }],
            default: null,
          } as RJSFSchema,
        },
      } as RJSFSchema,
      properties: [
        makeProp('workspace_id', <span data-testid="ws">ws</span>),
        makeProp('client_secret', <span data-testid="secret">secret</span>),
      ],
    })
    render(<ObjectFieldTemplate {...props} />)

    // Both fields present in DOM
    expect(screen.getByTestId('ws')).toBeInTheDocument()
    expect(screen.getByTestId('secret')).toBeInTheDocument()

    // secret is inside the Advanced group
    const advancedContent = document.querySelector('[data-fw-advanced-content]')
    expect(advancedContent).toBeInTheDocument()
    expect(advancedContent).toContainElement(screen.getByTestId('secret'))

    // workspace_id is NOT inside Advanced group
    expect(advancedContent).not.toContainElement(screen.getByTestId('ws'))
  })

  // EARS-2: No per-source branching — same template applies to all source types.
  it('EARS-2: renders correctly for a minimal single-field schema (any source type)', () => {
    const props = makeTemplateProps({
      schema: {
        type: 'object',
        properties: {
          host: { type: 'string', title: 'Host' }, // no default → Essential
        },
      } as RJSFSchema,
      properties: [makeProp('host', <label>Host field</label>)],
    })
    render(<ObjectFieldTemplate {...props} />)
    expect(screen.getByText('Host field')).toBeInTheDocument()
    // No Advanced group for a single Essential field
    expect(document.querySelector('[data-fw-advanced-group]')).toBeNull()
  })

  // Hidden fields are excluded regardless of group.
  it('skips hidden properties (rjsf marks them hidden:true)', () => {
    const props = makeTemplateProps({
      schema: {
        type: 'object',
        properties: {
          a: { type: 'string', default: '' },
          b: { type: 'integer', default: 5 },
        },
      } as RJSFSchema,
      properties: [
        { name: 'a', content: <span data-testid="visible">a</span>, hidden: false },
        { name: 'b', content: <span data-testid="hidden-field">b</span>, hidden: true },
      ],
    })
    render(<ObjectFieldTemplate {...props} />)
    expect(screen.getByTestId('visible')).toBeInTheDocument()
    // hidden field is not rendered
    expect(screen.queryByTestId('hidden-field')).toBeNull()
  })

  // Regression test for #526: rjsf passes schema.title ("AzureWAFConfig") as the
  // `title` prop for the root object — NOT an empty string. The previous
  // `isTopLevel = !title` check treated this as a nested object and rendered
  // all fields flat.  The fix uses `fieldPathId.path.length === 0` instead.
  it('#526 regression: Advanced group renders even when title is the schema class name (real Azure WAF shape)', () => {
    // Real Azure WAF schema — matches GET /sources/types response for azure_waf.
    // title="AzureWAFConfig" is passed by rjsf as the ObjectFieldTemplate `title` prop.
    const azureWAFSchema: RJSFSchema = {
      title: 'AzureWAFConfig',
      type: 'object',
      properties: {
        workspace_id: { type: 'string', default: '' },       // Essential: empty-string default
        table_regime: {
          type: 'string',
          enum: ['resource_specific', 'azure_diagnostics'],
          default: 'resource_specific',
        } as RJSFSchema,                                     // Advanced: meaningful default
        product: {
          type: 'string',
          enum: ['app_gateway', 'front_door', 'both'],
          default: 'both',
        } as RJSFSchema,                                     // Advanced: meaningful default
        tenant_id: {
          anyOf: [{ type: 'string', format: 'password', writeOnly: true }, { type: 'null' }],
          default: null,
        } as RJSFSchema,                                     // Advanced: writeOnly/secret
        overlap_minutes: { type: 'integer', default: 5 },   // Advanced: meaningful int default
      },
    }
    const props = makeTemplateProps({
      // rjsf passes schema.title as title prop for the root object (#526 root cause)
      title: 'AzureWAFConfig',
      // root object: path is always [] at form root
      fieldPathId: { $id: 'root', path: [] } as FieldPathId,
      schema: azureWAFSchema,
      properties: [
        makeProp('workspace_id', <input data-testid="workspace" />),
        makeProp('table_regime', <select data-testid="regime" />),
        makeProp('product', <select data-testid="product" />),
        makeProp('tenant_id', <input data-testid="tenant" type="password" />),
        makeProp('overlap_minutes', <input data-testid="overlap" type="number" />),
      ],
    })
    render(<ObjectFieldTemplate {...props} />)

    // workspace_id (empty default) must be in the visible Essential section
    expect(screen.getByTestId('workspace')).toBeInTheDocument()

    // Advanced group MUST be present — this is the regression assertion
    const advancedGroup = document.querySelector('[data-fw-advanced-group]')
    expect(advancedGroup).toBeInTheDocument()
    expect(document.querySelector('[data-fw-advanced-toggle]')).toBeInTheDocument()

    // Advanced fields must be inside the group
    const advancedContent = document.querySelector('[data-fw-advanced-content]')
    expect(advancedContent).toBeInTheDocument()
    expect(advancedContent).toContainElement(screen.getByTestId('regime'))
    expect(advancedContent).toContainElement(screen.getByTestId('product'))
    expect(advancedContent).toContainElement(screen.getByTestId('tenant'))
    expect(advancedContent).toContainElement(screen.getByTestId('overlap'))

    // workspace_id must NOT be inside the Advanced group
    expect(advancedContent).not.toContainElement(screen.getByTestId('workspace'))
  })

  // A nested object (non-empty path) should render flat — no double-grouping.
  it('nested object (non-empty fieldPathId.path) renders flat without Advanced grouping', () => {
    const props = makeTemplateProps({
      title: 'SSH Options',
      // Non-empty path signals a nested object, not the root
      fieldPathId: { $id: 'root_ssh_options', path: ['ssh_options'] } as FieldPathId,
      schema: {
        type: 'object',
        title: 'SSH Options',
        properties: {
          port: { type: 'integer', default: 22 },
          host: { type: 'string', default: '' },
        },
      } as RJSFSchema,
      properties: [
        makeProp('port', <input data-testid="port" />),
        makeProp('host', <input data-testid="host" />),
      ],
    })
    render(<ObjectFieldTemplate {...props} />)
    // Both fields visible (flat render, no partitioning)
    expect(screen.getByTestId('port')).toBeInTheDocument()
    expect(screen.getByTestId('host')).toBeInTheDocument()
    // No Advanced group for nested objects
    expect(document.querySelector('[data-fw-advanced-group]')).toBeNull()
  })
})
