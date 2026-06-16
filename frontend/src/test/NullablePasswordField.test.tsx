/**
 * Tests for src/widgets/NullablePasswordField.tsx
 *
 * EARS criteria covered (#67 — nullable-secret entry UX):
 *   - Event-driven: NullablePasswordField renders a password input directly,
 *     without an anyOf type-selector dropdown.
 *   - Ubiquitous: masking contract preserved — null value shows masked placeholder.
 *   - Ubiquitous: typed value propagated via onChange.
 *   - A11y: aria-invalid set on the input when rawErrors is non-empty.
 *
 * Also covers buildPutPayload PUT-strip fix (#523):
 *   - Empty string for a NullablePasswordField entry MUST be stripped from the PUT
 *     payload (same as PasswordWidget), so an unchanged nullable secret is not
 *     overwritten with '' on the server.
 *
 * Also covers label regression (#695):
 *   - NullablePasswordField must render the field's schema.title as a visible label,
 *     since rjsf suppresses FieldTemplate's label when ui:field is set.
 *   - The label must be linked to the input via htmlFor/id.
 *   - A required field must show the required indicator (*).
 *
 * The field is used when buildUiSchema detects anyOf[{password}, {null}] —
 * i.e. Pydantic SecretStr | None. It bypasses the AnyOfField selector so
 * users see the password input directly.
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import NullablePasswordField from '../widgets/NullablePasswordField'
import { buildPutPayload } from '../schema/configPayload'
import type { FieldProps } from '@rjsf/utils'

/** Minimal FieldProps stub for testing NullablePasswordField in isolation. */
function makeFieldProps(overrides: Partial<FieldProps> = {}): FieldProps {
  return {
    id: 'root_remote_key',
    name: 'remote_key',
    formData: undefined,
    schema: {
      anyOf: [
        { type: 'string', format: 'password', writeOnly: true },
        { type: 'null' },
      ],
      title: 'SSH private key path',
    },
    uiSchema: {},
    required: false,
    disabled: false,
    readonly: false,
    autofocus: false,
    rawErrors: [],
    errorSchema: {},
    onChange: vi.fn(),
    onBlur: vi.fn(),
    onFocus: vi.fn(),
    // fieldPathId is a rjsf internal type — provide minimal shape for tests
    fieldPathId: { $id: 'root_remote_key', $idPrefix: 'root', path: ['remote_key'] } as FieldProps['fieldPathId'],
    registry: {
      formContext: {},
      widgets: {},
      fields: {},
      templates: {} as FieldProps['registry']['templates'],
      rootSchema: {},
      schemaUtils: {} as FieldProps['registry']['schemaUtils'],
      translateString: (s: string) => s,
      globalUiOptions: {},
    } as FieldProps['registry'],
    ...overrides,
  } as FieldProps
}

describe('NullablePasswordField', () => {
  it('renders a password input (not a type-selector dropdown)', () => {
    render(<NullablePasswordField {...makeFieldProps()} />)
    // Must render a password input, not a select element
    const pwInput = document.querySelector('input[type="password"]')
    expect(pwInput).not.toBeNull()
    // Must NOT render a select (the anyOf type-selector)
    const select = screen.queryByRole('combobox')
    expect(select).toBeNull()
  })

  it('shows masked placeholder when formData is null (server-masked secret)', () => {
    render(<NullablePasswordField {...makeFieldProps({ formData: null })} />)
    const pwInput = document.querySelector('input[type="password"]') as HTMLInputElement
    expect(pwInput.value).toBe('')
    expect(pwInput.placeholder).toMatch(/set/i)
  })

  it('shows masked placeholder when formData is undefined (no value set)', () => {
    render(<NullablePasswordField {...makeFieldProps({ formData: undefined })} />)
    const pwInput = document.querySelector('input[type="password"]') as HTMLInputElement
    expect(pwInput.value).toBe('')
  })

  it('calls onChange when user types a new value', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<NullablePasswordField {...makeFieldProps({ onChange })} />)
    const pwInput = document.querySelector('input[type="password"]') as HTMLInputElement
    await user.type(pwInput, 'newkey')
    expect(onChange).toHaveBeenCalled()
    // Last call should have the typed value as first arg (via field onChange adapter)
    const lastCall = onChange.mock.calls[onChange.mock.calls.length - 1] as unknown[]
    expect(lastCall[0]).toBe('newkey')
  })

  it('sets aria-invalid when rawErrors is non-empty (#67 a11y)', () => {
    render(
      <NullablePasswordField
        {...makeFieldProps({ rawErrors: ['Value is required'] })}
      />,
    )
    const pwInput = document.querySelector('input[type="password"]') as HTMLInputElement
    expect(pwInput.getAttribute('aria-invalid')).toBe('true')
  })

  it('does not set aria-invalid when rawErrors is empty (#67 a11y)', () => {
    render(<NullablePasswordField {...makeFieldProps({ rawErrors: [] })} />)
    const pwInput = document.querySelector('input[type="password"]') as HTMLInputElement
    expect(pwInput.getAttribute('aria-invalid')).toBeNull()
  })

  // Label rendering regression (#695): rjsf suppresses FieldTemplate's label when
  // ui:field is set. NullablePasswordField must render the label itself so operators
  // see the field title (e.g. "SSH private key path") above the masked input.
  it('renders the schema title as a visible label (#695)', () => {
    render(<NullablePasswordField {...makeFieldProps()} />)
    // The title from the schema must appear as visible text in the DOM.
    expect(screen.getByText('SSH private key path')).toBeInTheDocument()
  })

  it('links the label to the input via htmlFor (#695)', () => {
    render(<NullablePasswordField {...makeFieldProps()} />)
    // The label element must have htmlFor matching the input's id.
    const label = document.querySelector('label[data-fw-field-label]') as HTMLLabelElement
    expect(label).not.toBeNull()
    const inputId = (document.querySelector('input[type="password"]') as HTMLInputElement).id
    expect(label.htmlFor).toBe(inputId)
  })

  it('shows a required indicator when required=true (#695)', () => {
    render(<NullablePasswordField {...makeFieldProps({ required: true })} />)
    const label = document.querySelector('label[data-fw-field-label]') as HTMLLabelElement
    expect(label).not.toBeNull()
    // Required indicator (*) must be present in label text
    expect(label.textContent).toContain('*')
  })

  it('does not show a required indicator when required=false (#695)', () => {
    render(<NullablePasswordField {...makeFieldProps({ required: false })} />)
    const label = document.querySelector('label[data-fw-field-label]') as HTMLLabelElement
    expect(label).not.toBeNull()
    expect(label.textContent).not.toContain('*')
  })

  // DEFECT 2 fix (#85): onChange must be called with fieldPathId.path, NOT an empty
  // array []. Calling onChange(value, [], ...) makes rjsf Form treat path=[] as the
  // root path and replaces the ENTIRE formData object with the string value, causing
  // a top-level "SuricataConfig must be object" AJV error on next submit.
  it('calls FieldProps onChange with fieldPathId.path — not empty [] (#85 D2 fix)', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(
      <NullablePasswordField
        {...makeFieldProps({
          onChange,
          fieldPathId: {
            $id: 'root_remote_key',
            $idPrefix: 'root',
            path: ['remote_key'],
          } as FieldProps['fieldPathId'],
        })}
      />,
    )
    const pwInput = document.querySelector('input[type="password"]') as HTMLInputElement
    await user.type(pwInput, 's')

    expect(onChange).toHaveBeenCalled()
    const lastCall = onChange.mock.calls[onChange.mock.calls.length - 1] as unknown[]
    // path argument must be ['remote_key'] (fieldPathId.path), NOT []
    // An empty path [] causes the Form to replace the root formData with the string value.
    expect(lastCall[1]).toEqual(['remote_key'])
  })
})

// ---------------------------------------------------------------------------
// buildPutPayload — NullablePasswordField empty-string strip (#523)
// ---------------------------------------------------------------------------
// Issue #523 fix: buildPutPayload previously only stripped '' for PasswordWidget
// (ui:widget check). NullablePasswordField fields (ui:field check) were not covered.
// After the fix, both secret field types have their empty-string values stripped.

describe('buildPutPayload — NullablePasswordField empty-string strip (#523)', () => {
  // uiSchema as produced by buildUiSchema for a SecretStr | None field
  const uiSchemaWithNullablePassword = {
    remote_key: {
      'ui:field': 'NullablePasswordField',
      'ui:fieldReplacesAnyOrOneOf': true,
    },
  }

  it('strips empty string for a NullablePasswordField entry', () => {
    const formData = { host: 'myhost', remote_key: '' }
    const result = buildPutPayload(formData, uiSchemaWithNullablePassword)
    // remote_key = '' means the user has not typed a new value — must be omitted
    expect(result).not.toHaveProperty('remote_key')
    // Non-secret field must be preserved
    expect(result).toHaveProperty('host', 'myhost')
  })

  it('preserves a typed (non-empty) value for a NullablePasswordField entry', () => {
    const formData = { host: 'myhost', remote_key: '/path/to/key' }
    const result = buildPutPayload(formData, uiSchemaWithNullablePassword)
    // User typed a real value — must be included in PUT
    expect(result).toHaveProperty('remote_key', '/path/to/key')
    expect(result).toHaveProperty('host', 'myhost')
  })

  it('strips empty string for a PasswordWidget entry (pre-existing behaviour)', () => {
    const uiSchema = { token: { 'ui:widget': 'PasswordWidget' } }
    const formData = { host: 'myhost', token: '' }
    const result = buildPutPayload(formData, uiSchema)
    expect(result).not.toHaveProperty('token')
    expect(result).toHaveProperty('host', 'myhost')
  })

  it('preserves empty string for non-secret fields (e.g. remote_host = "")', () => {
    // remote_host is a plain string, not in uiSchema as a secret field
    const formData = { remote_host: '', port: 22 }
    const result = buildPutPayload(formData, {})
    // Empty remote_host must be sent — it is a valid clear operation
    expect(result).toHaveProperty('remote_host', '')
    expect(result).toHaveProperty('port', 22)
  })
})
