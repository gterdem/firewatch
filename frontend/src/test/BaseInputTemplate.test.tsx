/**
 * Tests for src/widgets/BaseInputTemplate.tsx (F4 re-skin, #110)
 *
 * EARS criteria covered:
 *   - Ubiquitous: invalid field has aria-invalid="true" DOM attribute (ARIA 1.1 §6.6.5 / WCAG 4.1.3).
 *   - Ubiquitous: valid field does NOT have aria-invalid.
 *   - Ubiquitous: id, type, disabled, required forwarded to the <input>.
 *   - Ubiquitous (DS re-skin): renders with DS token styles (--fw-bg-input, --fw-font-mono,
 *     --fw-border-l border, --fw-red on error).
 *   - Event-driven: onChange called when user types.
 *
 * The primary a11y assertion is toHaveAttribute('aria-invalid', 'true') — the DOM
 * attribute, not a CSS class (per ARIA 1.1 §6.6.5 / WCAG 4.1.3).
 *
 * DS style assertions check inline style properties (the widget uses --fw-* tokens
 * via inline styles, not Tailwind classes, matching DS Input recipe).
 */

import { describe, it, expect, vi } from 'vitest'
import { render } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { BaseInputTemplateProps } from '@rjsf/utils'
import BaseInputTemplate from '../widgets/BaseInputTemplate'

/** Minimal BaseInputTemplateProps stub for isolated testing. */
function makeProps(overrides: Partial<BaseInputTemplateProps> = {}): BaseInputTemplateProps {
  return {
    id: 'test-input',
    htmlName: 'test-input',
    type: 'text',
    value: '',
    required: false,
    disabled: false,
    readonly: false,
    autofocus: false,
    placeholder: '',
    label: 'Test Field',
    hideLabel: false,
    hideError: false,
    schema: { type: 'string' },
    uiSchema: {},
    options: {},
    rawErrors: [],
    onChange: vi.fn(),
    onBlur: vi.fn(),
    onFocus: vi.fn(),
    registry: {
      templates: {
        ButtonTemplates: {
          ClearButton: () => null,
        },
      },
    } as unknown as BaseInputTemplateProps['registry'],
    ...overrides,
  } as BaseInputTemplateProps
}

describe('BaseInputTemplate', () => {
  it('renders an <input> element', () => {
    render(<BaseInputTemplate {...makeProps()} />)
    const input = document.querySelector('input')
    expect(input).not.toBeNull()
  })

  it('forwards id, type to the input', () => {
    render(<BaseInputTemplate {...makeProps({ id: 'my-field', type: 'number' })} />)
    const input = document.querySelector('input') as HTMLInputElement
    expect(input.id).toBe('my-field')
    expect(input.type).toBe('number')
  })

  it('forwards disabled to the input', () => {
    render(<BaseInputTemplate {...makeProps({ disabled: true })} />)
    const input = document.querySelector('input') as HTMLInputElement
    expect(input.disabled).toBe(true)
  })

  it('forwards required to the input', () => {
    render(<BaseInputTemplate {...makeProps({ required: true })} />)
    const input = document.querySelector('input') as HTMLInputElement
    expect(input.required).toBe(true)
  })

  // DEFECT 1 (Blocker #85): invalid field must have aria-invalid="true" as a real
  // DOM attribute so screen readers announce invalid state (ARIA 1.1 §6.6.5 / WCAG 4.1.3).
  it('sets aria-invalid="true" attribute when rawErrors is non-empty (#85 D1 a11y)', () => {
    render(
      <BaseInputTemplate
        {...makeProps({ rawErrors: ['Must be between 1 and 65535'] })}
      />,
    )
    const input = document.querySelector('input') as HTMLInputElement
    // This MUST be the real DOM attribute, not just a CSS class
    expect(input).toHaveAttribute('aria-invalid', 'true')
  })

  // The other side: valid field must NOT have aria-invalid (per ARIA 1.1 best practice:
  // do not set aria-invalid="false" explicitly — absence is correct).
  it('does NOT set aria-invalid when rawErrors is empty (#85 D1 a11y)', () => {
    render(<BaseInputTemplate {...makeProps({ rawErrors: [] })} />)
    const input = document.querySelector('input') as HTMLInputElement
    expect(input).not.toHaveAttribute('aria-invalid')
  })

  it('calls onChange when user types', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<BaseInputTemplate {...makeProps({ onChange })} />)
    const input = document.querySelector('input') as HTMLInputElement
    await user.type(input, 'hello')
    expect(onChange).toHaveBeenCalled()
  })

  // DS re-skin (#110): input renders on the DS inset well (--fw-bg-input background).
  it('renders with DS inset well background (--fw-bg-input) [F4 re-skin]', () => {
    render(<BaseInputTemplate {...makeProps()} />)
    const input = document.querySelector('input') as HTMLInputElement
    // The DS Input uses inline style with --fw-bg-input
    expect(input.style.background).toBe('var(--fw-bg-input)')
  })

  // DS re-skin (#110): input uses monospace font (--fw-font-mono) for data fields.
  it('renders with DS monospace font (--fw-font-mono) [F4 re-skin]', () => {
    render(<BaseInputTemplate {...makeProps()} />)
    const input = document.querySelector('input') as HTMLInputElement
    expect(input.style.fontFamily).toBe('var(--fw-font-mono)')
  })

  // DS re-skin (#110): error state uses --fw-red border color instead of shadcn border-destructive.
  it('applies --fw-red border color when rawErrors is non-empty [F4 re-skin]', () => {
    render(
      <BaseInputTemplate
        {...makeProps({ rawErrors: ['Error message'] })}
      />,
    )
    const input = document.querySelector('input') as HTMLInputElement
    // DS error style: --fw-red via inline borderColor (not shadcn border-destructive class)
    expect(input.style.borderColor).toBe('var(--fw-red)')
  })

  // DS re-skin (#110): data-fw-input attribute marks the input as DS-styled for targeting.
  it('has data-fw-input attribute on the input element [F4 re-skin]', () => {
    render(<BaseInputTemplate {...makeProps()} />)
    const input = document.querySelector('[data-fw-input]')
    expect(input).not.toBeNull()
  })
})
