/**
 * Widgets test file — #489 (DescriptionFieldTemplate) + #498 (PasswordWidget reveal toggle)
 *
 * EARS criteria mapped to tests:
 *
 * #489 — Two-tier field help (DescriptionFieldTemplate):
 *   [489-A] Every field SHALL display its description as a single clamped lead line.
 *   [489-B] Full description SHALL remain reachable behind a keyboard-operable "Details"
 *           disclosure (aria-expanded / native <details>) — hover is NOT the sole path.
 *   [489-C] WHERE description exceeds the lead sentence, the full text SHALL be present
 *           (not truncated away) when the disclosure is expanded.
 *   [489-D] The PasswordWidget SHALL NOT use schema.description as its input placeholder.
 *   [489-E] When a schema provides ui:help, the template SHALL prefer it over the
 *           derived first sentence.
 *   [489-F] Zero per-source branching — template is generic.
 *
 * #498 — Working secret reveal toggle (PasswordWidget):
 *   [498-A] WHEN the user activates the reveal toggle on a field with a typed value,
 *           the input SHALL switch from type="password" to type="text".
 *   [498-B] WHEN the user activates the toggle again, the field SHALL return to
 *           type="password".
 *   [498-C] WHILE server-masked (null value, nothing typed), the reveal toggle SHALL
 *           NOT reveal any value — the masked placeholder stays; no stored secret echoed.
 *   [498-D] The reveal toggle SHALL be a keyboard-operable <button> with aria-pressed and
 *           accessible aria-label reflecting its state ("Show value" / "Hide value").
 *   [498-E] The secret value SHALL NEVER be written to logs under any reveal path (ADR-0006).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, cleanup } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { WidgetProps, DescriptionFieldProps } from '@rjsf/utils'

import DescriptionFieldTemplate from '../widgets/DescriptionFieldTemplate'
import { deriveLeadSentence } from '../widgets/descriptionUtils'
import PasswordWidget from '../widgets/PasswordWidget'

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

beforeEach(() => {
  cleanup()
})

// ---------------------------------------------------------------------------
// DescriptionFieldTemplate unit helpers
// ---------------------------------------------------------------------------

describe('deriveLeadSentence (unit)', () => {
  it('returns the first sentence when text ends with ". "', () => {
    const result = deriveLeadSentence('Short first sentence. Then more details about the setting.')
    expect(result).toBe('Short first sentence.')
  })

  it('returns the whole string if no sentence boundary found and under 90 chars', () => {
    const result = deriveLeadSentence('A short hint with no period')
    expect(result).toBe('A short hint with no period')
  })

  it('truncates at last word boundary and appends ellipsis when first sentence > 90 chars', () => {
    const long = 'This is a very long sentence that has far more than ninety characters in it without any break.'
    const result = deriveLeadSentence(long)
    expect(result.length).toBeLessThanOrEqual(90 + 1) // +1 for the ellipsis char
    expect(result.endsWith('…')).toBe(true)
  })

  it('handles text that ends with "! " (exclamation boundary)', () => {
    const result = deriveLeadSentence('Warning! The bind address must be an IP literal.')
    expect(result).toBe('Warning!')
  })

  it('handles text that ends with "? " (question boundary)', () => {
    const result = deriveLeadSentence('Need help? Read the docs. More info here.')
    expect(result).toBe('Need help?')
  })

  it('returns empty string for empty/whitespace input', () => {
    expect(deriveLeadSentence('')).toBe('')
    expect(deriveLeadSentence('   ')).toBe('')
  })
})

// ---------------------------------------------------------------------------
// DescriptionFieldTemplate rendering tests (#489)
// ---------------------------------------------------------------------------

/** Minimal DescriptionFieldProps stub. */
function makeDescriptionProps(
  overrides: Partial<DescriptionFieldProps> = {},
): DescriptionFieldProps {
  return {
    id: 'desc-test',
    description: '',
    schema: {},
    uiSchema: {},
    registry: {} as DescriptionFieldProps['registry'],
    ...overrides,
  } as DescriptionFieldProps
}

describe('DescriptionFieldTemplate', () => {
  // [489-A] Lead line always visible
  it('[489-A] renders the lead sentence as visible text', () => {
    const description = 'The workspace ID for your Azure Log Analytics. More detail follows here in the docs paragraph.'
    render(<DescriptionFieldTemplate {...makeDescriptionProps({ description })} />)
    // The lead sentence "The workspace ID for your Azure Log Analytics." should be in the DOM
    expect(document.body.textContent).toContain('The workspace ID for your Azure Log Analytics.')
  })

  // [489-B] Full text reachable behind a <details> disclosure — not hover-only
  it('[489-B] renders a <details> disclosure element when description has more than the lead', () => {
    const description =
      'Short lead. Much longer second sentence that explains everything in detail about the network binding address and DNS resolution vectors at bind time.'
    render(<DescriptionFieldTemplate {...makeDescriptionProps({ description })} />)
    // The native <details> element exposes content without hover (WCAG 1.4.13)
    const details = document.querySelector('details[data-fw-description-details]')
    expect(details).not.toBeNull()
  })

  // [489-B] Keyboard-operable: <summary> is the disclosure trigger
  it('[489-B] disclosure is a native <details> with a <summary> (keyboard-accessible, no hover required)', () => {
    const description =
      'First sentence. Second sentence that makes the full text much longer than the lead alone.'
    render(<DescriptionFieldTemplate {...makeDescriptionProps({ description })} />)
    const summary = document.querySelector('summary')
    expect(summary).not.toBeNull()
    expect(summary!.textContent).toContain('Details')
  })

  // [489-C] Full text present in DOM when disclosure is opened
  it('[489-C] the full description text is present in the DOM (reachable, not truncated away)', () => {
    const description =
      'Lead sentence. The full text is much longer and contains all the important details about this field and its security implications for DNS resolution.'
    render(<DescriptionFieldTemplate {...makeDescriptionProps({ description })} />)
    const fullEl = document.querySelector('[data-fw-description-full]')
    expect(fullEl).not.toBeNull()
    expect(fullEl!.textContent).toContain(description.trim())
  })

  // [489-C] Clicking the <details> summary opens it (user-event test)
  it('[489-C] clicking the Details summary opens the disclosure', async () => {
    const user = userEvent.setup()
    const description =
      'Short. Much longer details that follow after the period and explain everything at length.'
    render(<DescriptionFieldTemplate {...makeDescriptionProps({ description })} />)
    const details = document.querySelector('details') as HTMLDetailsElement
    expect(details.open).toBe(false)
    const summary = details.querySelector('summary')!
    await user.click(summary)
    expect(details.open).toBe(true)
  })

  // [489-E] ui:help takes precedence over derived lead sentence
  it('[489-E] prefers ui:help over derived first sentence when provided', () => {
    const description = 'Full long description with many details. More info on everything.'
    const uiHelp = 'Short hint for operators'
    render(
      <DescriptionFieldTemplate
        {...makeDescriptionProps({
          description,
          uiSchema: { 'ui:help': uiHelp },
        })}
      />,
    )
    // The ui:help text should appear as the lead
    const wrapper = document.querySelector('[data-fw-description]')
    expect(wrapper!.textContent).toContain(uiHelp)
  })

  // [489-F] Generic — renders for any description without source-specific branching
  it('[489-F] renders generically for any description string (no per-source code)', () => {
    const descriptions = [
      'Azure client secret for service principal authentication. More info.',
      'Syslog bind address. Must be an IP literal to avoid DNS-resolution-at-bind vector.',
      'Collection mode determines whether Suricata logs are read locally or via SSH.',
    ]
    for (const description of descriptions) {
      cleanup()
      render(<DescriptionFieldTemplate {...makeDescriptionProps({ description })} />)
      // Each should render a lead sentence without throwing
      expect(document.querySelector('[data-fw-description]')).not.toBeNull()
    }
  })

  // Edge: renders nothing when description is empty
  it('renders nothing when description is empty', () => {
    const { container } = render(
      <DescriptionFieldTemplate {...makeDescriptionProps({ description: '' })} />,
    )
    expect(container.firstChild).toBeNull()
  })

  // Edge: does not show disclosure when description is just one sentence
  it('does NOT show a Details disclosure when description is a single short sentence', () => {
    const description = 'Short single-sentence description.'
    render(<DescriptionFieldTemplate {...makeDescriptionProps({ description })} />)
    expect(document.querySelector('details')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// PasswordWidget — reveal toggle tests (#498)
// ---------------------------------------------------------------------------

/** Minimal WidgetProps stub for PasswordWidget. */
function makePwProps(overrides: Partial<WidgetProps> = {}): WidgetProps {
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
    registry: {} as WidgetProps['registry'],
    label: 'Secret',
    hideLabel: false,
    hideError: false,
    rawErrors: [],
    ...overrides,
  } as WidgetProps
}

describe('PasswordWidget — reveal toggle (#498)', () => {
  // [498-A] Toggle changes type from password to text when a value has been typed
  it('[498-A] clicking reveal toggle switches input to type="text" after user types a value', async () => {
    const user = userEvent.setup()
    render(<PasswordWidget {...makePwProps()} />)

    const input = document.querySelector('input') as HTMLInputElement
    // Type something first so there is a typed value to reveal
    await user.type(input, 'mysecret')

    // Initially masked
    expect(input.getAttribute('type')).toBe('password')

    const toggle = document.querySelector('[data-fw-reveal-toggle]') as HTMLButtonElement
    await user.click(toggle)

    expect(input.getAttribute('type')).toBe('text')
  })

  // [498-B] Toggle again returns to type="password"
  it('[498-B] clicking reveal toggle a second time returns input to type="password"', async () => {
    const user = userEvent.setup()
    render(<PasswordWidget {...makePwProps()} />)

    const input = document.querySelector('input') as HTMLInputElement
    await user.type(input, 'mysecret')

    const toggle = document.querySelector('[data-fw-reveal-toggle]') as HTMLButtonElement
    // First click — reveal
    await user.click(toggle)
    expect(input.getAttribute('type')).toBe('text')
    // Second click — mask again
    await user.click(toggle)
    expect(input.getAttribute('type')).toBe('password')
  })

  // [498-C] Server-masked (null value, nothing typed) — reveal does NOT show stored secret
  it('[498-C] reveal toggle does NOT change type to text when server-masked and nothing typed', async () => {
    const user = userEvent.setup()
    // null = server has a secret but returns null (ADR-0006 mask-on-GET)
    render(<PasswordWidget {...makePwProps({ value: null })} />)

    const input = document.querySelector('input') as HTMLInputElement
    expect(input.getAttribute('type')).toBe('password')

    const toggle = document.querySelector('[data-fw-reveal-toggle]') as HTMLButtonElement
    await user.click(toggle)

    // Should remain password — there is nothing to show (stored secret never echoed)
    expect(input.getAttribute('type')).toBe('password')
  })

  // [498-D] aria-pressed reflects current state
  it('[498-D] toggle button has aria-pressed=false when masked', () => {
    render(<PasswordWidget {...makePwProps()} />)
    const toggle = document.querySelector('[data-fw-reveal-toggle]') as HTMLButtonElement
    expect(toggle.getAttribute('aria-pressed')).toBe('false')
  })

  it('[498-D] toggle button has aria-pressed=true when revealed', async () => {
    const user = userEvent.setup()
    render(<PasswordWidget {...makePwProps()} />)

    const input = document.querySelector('input') as HTMLInputElement
    await user.type(input, 'secret')

    const toggle = document.querySelector('[data-fw-reveal-toggle]') as HTMLButtonElement
    await user.click(toggle)
    expect(toggle.getAttribute('aria-pressed')).toBe('true')
  })

  // [498-D] aria-label reflects current action
  it('[498-D] toggle button has aria-label="Show value" when masked', () => {
    render(<PasswordWidget {...makePwProps()} />)
    const toggle = document.querySelector('[data-fw-reveal-toggle]') as HTMLButtonElement
    expect(toggle.getAttribute('aria-label')).toBe('Show value')
  })

  it('[498-D] toggle button has aria-label="Hide value" when revealed', async () => {
    const user = userEvent.setup()
    render(<PasswordWidget {...makePwProps()} />)

    const input = document.querySelector('input') as HTMLInputElement
    await user.type(input, 'secret')

    const toggle = document.querySelector('[data-fw-reveal-toggle]') as HTMLButtonElement
    await user.click(toggle)
    expect(toggle.getAttribute('aria-label')).toBe('Hide value')
  })

  // [498-D] Toggle is a <button> element (keyboard-operable)
  it('[498-D] reveal toggle is a <button> element (keyboard-operable)', () => {
    render(<PasswordWidget {...makePwProps()} />)
    const toggle = document.querySelector('[data-fw-reveal-toggle]')
    expect(toggle?.tagName.toLowerCase()).toBe('button')
  })

  // [498-E] Secret value never logged (ADR-0006)
  it('[498-E] secret value is never written to console.log or console.error under reveal path', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const user = userEvent.setup()

    render(<PasswordWidget {...makePwProps()} />)
    const input = document.querySelector('input') as HTMLInputElement
    await user.type(input, 'topsecretvalue')

    const toggle = document.querySelector('[data-fw-reveal-toggle]') as HTMLButtonElement
    await user.click(toggle) // reveal
    await user.click(toggle) // hide again

    for (const call of consoleSpy.mock.calls) {
      expect(JSON.stringify(call)).not.toContain('topsecretvalue')
    }
    for (const call of consoleErrorSpy.mock.calls) {
      expect(JSON.stringify(call)).not.toContain('topsecretvalue')
    }

    consoleSpy.mockRestore()
    consoleErrorSpy.mockRestore()
  })

  // Regression — existing tests still pass after changes
  it('[regression] renders as type="password" by default', () => {
    render(<PasswordWidget {...makePwProps()} />)
    const input = document.querySelector('input') as HTMLInputElement
    expect(input.getAttribute('type')).toBe('password')
  })

  it('[regression] shows masked placeholder when value is null (server-masked secret)', () => {
    render(<PasswordWidget {...makePwProps({ value: null })} />)
    const input = document.querySelector('input') as HTMLInputElement
    expect(input.value).toBe('')
    expect(input.placeholder).toMatch(/set/i)
  })

  // [489-D] Placeholder does NOT use schema.description
  it('[489-D] placeholder is NOT schema.description when value is unset', () => {
    const description = 'Very long security description paragraph that should never be a placeholder.'
    render(<PasswordWidget {...makePwProps({ schema: { type: 'string', description } })} />)
    const input = document.querySelector('input') as HTMLInputElement
    expect(input.placeholder).not.toBe(description)
    expect(input.placeholder).not.toContain('security description')
  })

  it('[489-D] placeholder is NEUTRAL (not schema.description) when value is empty string (not masked)', () => {
    // Empty string = user cleared the field; not server-masked → neutral placeholder
    render(<PasswordWidget {...makePwProps({ value: '' })} />)
    const input = document.querySelector('input') as HTMLInputElement
    // Should NOT contain description text
    expect(input.placeholder).toBe('Enter value')
  })

  it('[regression] calls onChange with typed value', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<PasswordWidget {...makePwProps({ onChange })} />)
    const input = document.querySelector('input') as HTMLInputElement
    await user.type(input, 'newval')
    expect(onChange).toHaveBeenCalled()
    const lastCall = onChange.mock.calls[onChange.mock.calls.length - 1] as [string | undefined]
    expect(lastCall[0]).toBe('newval')
  })

  it('[regression] sets aria-invalid when rawErrors is non-empty', () => {
    render(<PasswordWidget {...makePwProps({ rawErrors: ['Required'] })} />)
    const input = document.querySelector('input') as HTMLInputElement
    expect(input.getAttribute('aria-invalid')).toBe('true')
  })

  it('[regression] renders data-fw-input attribute on the input', () => {
    render(<PasswordWidget {...makePwProps()} />)
    expect(document.querySelector('[data-fw-input]')).not.toBeNull()
  })
})
