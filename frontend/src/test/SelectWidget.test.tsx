/**
 * Tests for src/widgets/SelectWidget.tsx (F4, #110)
 *
 * EARS criteria covered:
 *   - Ubiquitous: enum fields render as a native <select> (not shadcn FancySelect).
 *   - Ubiquitous: options rendered from enumOptions prop.
 *   - State-driven: selected value reflected in the select.
 *   - Event-driven: onChange called with the selected enum value when changed.
 *   - Ubiquitous: aria-invalid="true" DOM attribute when rawErrors non-empty (ARIA 1.1 §6.6.5).
 *   - Ubiquitous: disabled, required forwarded.
 *   - DS re-skin (#110): renders with DS token styles (--fw-bg-input, --fw-font-mono).
 *   - DS re-skin (#110): --fw-red border on error (not shadcn border-destructive).
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import SelectWidget from '../widgets/SelectWidget'
import type { WidgetProps } from '@rjsf/utils'

const ENUM_OPTIONS = [
  { value: 'local', label: 'Local' },
  { value: 'remote', label: 'Remote' },
]

/** Minimal WidgetProps stub for testing SelectWidget in isolation. */
function makeProps(overrides: Partial<WidgetProps> = {}): WidgetProps {
  return {
    id: 'test-select',
    name: 'test-select',
    value: 'local',
    required: false,
    disabled: false,
    readonly: false,
    autofocus: false,
    multiple: false,
    onChange: vi.fn(),
    onBlur: vi.fn(),
    onFocus: vi.fn(),
    schema: { type: 'string', enum: ['local', 'remote'] },
    uiSchema: {},
    options: {
      enumOptions: ENUM_OPTIONS,
      enumDisabled: [],
    },
    formContext: {},
    registry: {} as WidgetProps['registry'],
    label: 'Mode',
    hideLabel: false,
    hideError: false,
    rawErrors: [],
    placeholder: '',
    ...overrides,
  } as WidgetProps
}

describe('SelectWidget', () => {
  it('renders a native <select> element (not a combobox overlay)', () => {
    render(<SelectWidget {...makeProps()} />)
    // Must be a native <select>, not a div-based combobox
    const select = document.querySelector('select')
    expect(select).not.toBeNull()
  })

  it('renders all enum options as <option> elements', () => {
    render(<SelectWidget {...makeProps()} />)
    expect(screen.getByRole('option', { name: 'Local' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'Remote' })).toBeInTheDocument()
  })

  it('reflects the current value as the selected option', () => {
    render(<SelectWidget {...makeProps({ value: 'remote' })} />)
    const select = document.querySelector('select') as HTMLSelectElement
    expect(select.value).toBe('remote')
  })

  it('calls onChange with the enum value when selection changes', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<SelectWidget {...makeProps({ onChange })} />)
    const select = document.querySelector('select') as HTMLSelectElement
    await user.selectOptions(select, 'Remote')
    expect(onChange).toHaveBeenCalled()
    const lastCall = onChange.mock.calls[onChange.mock.calls.length - 1] as [unknown]
    expect(lastCall[0]).toBe('remote')
  })

  it('is disabled when disabled prop is true', () => {
    render(<SelectWidget {...makeProps({ disabled: true })} />)
    const select = document.querySelector('select') as HTMLSelectElement
    expect(select.disabled).toBe(true)
  })

  it('has required attribute when required prop is true', () => {
    render(<SelectWidget {...makeProps({ required: true })} />)
    const select = document.querySelector('select') as HTMLSelectElement
    expect(select.required).toBe(true)
  })

  // A11y: aria-invalid="true" DOM attribute when rawErrors is non-empty.
  it('sets aria-invalid="true" when rawErrors is non-empty (a11y)', () => {
    render(<SelectWidget {...makeProps({ rawErrors: ['Invalid selection'] })} />)
    const select = document.querySelector('select') as HTMLSelectElement
    expect(select).toHaveAttribute('aria-invalid', 'true')
  })

  it('does NOT set aria-invalid when rawErrors is empty (a11y)', () => {
    render(<SelectWidget {...makeProps({ rawErrors: [] })} />)
    const select = document.querySelector('select') as HTMLSelectElement
    expect(select).not.toHaveAttribute('aria-invalid')
  })

  // DS re-skin (#110): select renders on --fw-bg-input inset well.
  it('renders with DS inset well background (--fw-bg-input) [F4 re-skin]', () => {
    render(<SelectWidget {...makeProps()} />)
    const select = document.querySelector('select') as HTMLSelectElement
    expect(select.style.background).toBe('var(--fw-bg-input)')
  })

  // DS re-skin (#110): select uses monospace font.
  it('renders with DS monospace font (--fw-font-mono) [F4 re-skin]', () => {
    render(<SelectWidget {...makeProps()} />)
    const select = document.querySelector('select') as HTMLSelectElement
    expect(select.style.fontFamily).toBe('var(--fw-font-mono)')
  })

  // DS re-skin (#110): error state applies --fw-red border.
  it('applies --fw-red border color when rawErrors is non-empty [F4 re-skin]', () => {
    render(<SelectWidget {...makeProps({ rawErrors: ['Required'] })} />)
    const select = document.querySelector('select') as HTMLSelectElement
    expect(select.style.borderColor).toBe('var(--fw-red)')
  })

  // DS re-skin (#110): data-fw-select marks the select as DS-styled.
  it('has data-fw-select attribute on the select element [F4 re-skin]', () => {
    render(<SelectWidget {...makeProps()} />)
    const select = document.querySelector('[data-fw-select]')
    expect(select).not.toBeNull()
  })

  // Non-required select has an empty option to allow clearing.
  it('renders an empty option for non-required selects', () => {
    render(<SelectWidget {...makeProps({ required: false })} />)
    const options = document.querySelectorAll('option')
    // First option should be the empty one (value='')
    const emptyOpt = Array.from(options).find((o) => o.value === '')
    expect(emptyOpt).not.toBeUndefined()
  })

  // Required select does NOT have the empty option (to avoid accidental empty submission).
  it('does NOT render an empty option for required selects', () => {
    render(<SelectWidget {...makeProps({ required: true })} />)
    const options = document.querySelectorAll('option')
    const emptyOpt = Array.from(options).find((o) => o.value === '')
    expect(emptyOpt).toBeUndefined()
  })
})
