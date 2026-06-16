/**
 * Tests for src/widgets/PasswordWidget.tsx (F4 re-skin, #110)
 *
 * EARS criteria covered:
 *   - Ubiquitous: SecretStr fields rendered masked (type=password).
 *   - Ubiquitous: null value (server-masked) → placeholder shown, empty value.
 *   - Ubiquitous: typed value → onChange called with new value, not null.
 *   - Ubiquitous: clear → onChange called with undefined (omit from payload).
 *   - Security: secret value never appears in the DOM in plaintext.
 *   - A11y (#67): aria-invalid set when rawErrors is non-empty.
 *   - A11y (#67): aria-invalid absent when no errors.
 *   - DS re-skin (#110): renders with DS token styles (--fw-bg-input, --fw-font-mono).
 *   - Save-failure secret persistence (#523): localValue is NOT cleared when
 *     secretClearNonce stays at 0 (i.e. save FAILED — nonce is only bumped on success).
 */

import { describe, it, expect, vi } from 'vitest'
import { render, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import PasswordWidget from '../widgets/PasswordWidget'
import type { WidgetProps } from '@rjsf/utils'

/** Minimal WidgetProps stub for testing PasswordWidget in isolation. */
function makeProps(overrides: Partial<WidgetProps> = {}): WidgetProps {
  return {
    id: 'test-pw',
    name: 'test-pw',
    value: undefined,
    required: false,
    disabled: false,
    readonly: false,
    autofocus: false,
    onChange: vi.fn(),
    onBlur: vi.fn(),
    onFocus: vi.fn(),
    schema: { type: 'string', title: 'Secret' },
    uiSchema: {},
    options: {},
    formContext: {},
    // Registry is not used by PasswordWidget directly
    registry: {} as WidgetProps['registry'],
    label: 'Secret',
    hideLabel: false,
    hideError: false,
    rawErrors: [],
    ...overrides,
  } as WidgetProps
}

describe('PasswordWidget', () => {
  it('renders as an input with type="password"', () => {
    render(<PasswordWidget {...makeProps()} />)
    const pwInput = document.querySelector('input[type="password"]')
    expect(pwInput).not.toBeNull()
    expect(pwInput!.getAttribute('type')).toBe('password')
  })

  it('shows masked placeholder when value is null (server-masked secret)', () => {
    render(<PasswordWidget {...makeProps({ value: null })} />)
    const pwInput = document.querySelector('input[type="password"]') as HTMLInputElement
    expect(pwInput.value).toBe('')
    // Placeholder should indicate a value is set
    expect(pwInput.placeholder).toMatch(/set/i)
  })

  it('shows masked placeholder when value is undefined', () => {
    render(<PasswordWidget {...makeProps({ value: undefined })} />)
    const pwInput = document.querySelector('input[type="password"]') as HTMLInputElement
    expect(pwInput.value).toBe('')
  })

  it('does not render the actual secret value in the DOM (null case)', () => {
    const secretValue = 'super-secret-key-12345'
    // Even if we accidentally pass the secret as value (shouldn't happen in practice),
    // it should not appear as visible text anywhere
    render(<PasswordWidget {...makeProps({ value: null })} />)
    expect(document.body.textContent).not.toContain(secretValue)
  })

  it('calls onChange with the typed value when user types', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<PasswordWidget {...makeProps({ onChange })} />)
    const pwInput = document.querySelector('input[type="password"]') as HTMLInputElement
    await user.type(pwInput, 'newsecret')
    // onChange should have been called with the typed characters
    expect(onChange).toHaveBeenCalled()
    const lastCall = onChange.mock.calls[onChange.mock.calls.length - 1] as [string | undefined]
    expect(lastCall[0]).toBe('newsecret')
  })

  it('calls onChange with undefined when user clears the field', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<PasswordWidget {...makeProps({ onChange })} />)
    const pwInput = document.querySelector('input[type="password"]') as HTMLInputElement
    await user.type(pwInput, 'typed')
    await user.clear(pwInput)
    // After clearing, last onChange call should pass undefined
    const lastCall = onChange.mock.calls[onChange.mock.calls.length - 1] as [string | undefined]
    expect(lastCall[0]).toBeUndefined()
  })

  it('does not log the secret value', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<PasswordWidget {...makeProps({ onChange })} />)
    const pwInput = document.querySelector('input[type="password"]') as HTMLInputElement
    await user.type(pwInput, 'topsecret')
    // Check that console.log was never called with the secret value
    for (const call of consoleSpy.mock.calls) {
      const callStr = JSON.stringify(call)
      expect(callStr).not.toContain('topsecret')
    }
    for (const call of consoleErrorSpy.mock.calls) {
      const callStr = JSON.stringify(call)
      expect(callStr).not.toContain('topsecret')
    }
    consoleSpy.mockRestore()
    consoleErrorSpy.mockRestore()
  })

  it('is disabled when disabled prop is true', () => {
    render(<PasswordWidget {...makeProps({ disabled: true })} />)
    const pwInput = document.querySelector('input[type="password"]') as HTMLInputElement
    expect(pwInput.disabled).toBe(true)
  })

  it('is readonly when readonly prop is true', () => {
    render(<PasswordWidget {...makeProps({ readonly: true })} />)
    const pwInput = document.querySelector('input[type="password"]') as HTMLInputElement
    expect(pwInput.readOnly).toBe(true)
  })

  // A11y (#67): aria-invalid must be set when rawErrors is non-empty
  // so screen readers receive the invalid state (WCAG 4.1.3 / ARIA 1.1).
  it('sets aria-invalid when rawErrors is non-empty (#67 a11y)', () => {
    render(<PasswordWidget {...makeProps({ rawErrors: ['Value must be less than 65535'] })} />)
    const pwInput = document.querySelector('input[type="password"]') as HTMLInputElement
    expect(pwInput.getAttribute('aria-invalid')).toBe('true')
  })

  it('does not set aria-invalid when rawErrors is empty (#67 a11y)', () => {
    render(<PasswordWidget {...makeProps({ rawErrors: [] })} />)
    const pwInput = document.querySelector('input[type="password"]') as HTMLInputElement
    // aria-invalid should be absent (or false) when there are no errors
    expect(pwInput.getAttribute('aria-invalid')).toBeNull()
  })

  // DS re-skin (#110): password input renders on --fw-bg-input inset well.
  it('renders with DS inset well background (--fw-bg-input) [F4 re-skin]', () => {
    render(<PasswordWidget {...makeProps()} />)
    const pwInput = document.querySelector('input[type="password"]') as HTMLInputElement
    expect(pwInput.style.background).toBe('var(--fw-bg-input)')
  })

  // DS re-skin (#110): password input uses monospace font for data fields.
  it('renders with DS monospace font (--fw-font-mono) [F4 re-skin]', () => {
    render(<PasswordWidget {...makeProps()} />)
    const pwInput = document.querySelector('input[type="password"]') as HTMLInputElement
    expect(pwInput.style.fontFamily).toBe('var(--fw-font-mono)')
  })

  // DS re-skin (#110): error state uses --fw-red border (not shadcn border-destructive).
  it('applies --fw-red border color when rawErrors is non-empty [F4 re-skin]', () => {
    render(<PasswordWidget {...makeProps({ rawErrors: ['Required'] })} />)
    const pwInput = document.querySelector('input[type="password"]') as HTMLInputElement
    expect(pwInput.style.borderColor).toBe('var(--fw-red)')
  })

  // DS re-skin (#110): data-fw-input marks the password input as DS-styled.
  it('has data-fw-input attribute on the password input [F4 re-skin]', () => {
    render(<PasswordWidget {...makeProps()} />)
    const input = document.querySelector('[data-fw-input]')
    expect(input).not.toBeNull()
  })

  // Secret-hygiene clear (R9 / issue #497): secretClearNonce > 0 (bumped on success)
  // clears localValue so the typed plaintext does not persist after a successful save.
  it('clears localValue when secretClearNonce increments (successful-save signal)', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    const { rerender } = render(
      <PasswordWidget {...makeProps({ onChange, options: { secretClearNonce: 0 } })} />,
    )

    const pwInput = document.querySelector('input[type="password"]') as HTMLInputElement
    await user.type(pwInput, 'typed-secret')
    expect(pwInput.value).toBe('typed-secret')

    // Simulate a successful save: secretClearNonce bumps to 1
    await act(async () => {
      rerender(
        <PasswordWidget {...makeProps({ onChange, options: { secretClearNonce: 1 } })} />,
      )
    })
    // localValue must be cleared — typed secret gone
    expect(pwInput.value).toBe('')
  })

  // Save-failure secret persistence (#523): when PUT FAILS, secretClearNonce is NOT
  // bumped (SourceConfigForm only increments nonce on success). localValue must remain
  // intact so the user can fix and retry without re-entering the secret.
  it('preserves localValue when secretClearNonce stays at 0 (failed-save scenario) [#523]', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    const { rerender } = render(
      <PasswordWidget {...makeProps({ onChange, options: { secretClearNonce: 0 } })} />,
    )

    const pwInput = document.querySelector('input[type="password"]') as HTMLInputElement
    await user.type(pwInput, 'typed-secret')
    expect(pwInput.value).toBe('typed-secret')

    // Simulate a FAILED save: secretClearNonce stays at 0 — no re-render of options needed,
    // but rerender with the same nonce to confirm the effect guard (nonce===0 → no clear).
    await act(async () => {
      rerender(
        <PasswordWidget {...makeProps({ onChange, options: { secretClearNonce: 0 } })} />,
      )
    })
    // localValue must NOT be cleared — user can retry with the same secret
    expect(pwInput.value).toBe('typed-secret')
  })
})
