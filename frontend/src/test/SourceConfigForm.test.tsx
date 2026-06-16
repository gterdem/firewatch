/**
 * Tests for SourceConfigForm.tsx — R8 inline 422 field errors (issue #495).
 *
 * EARS criteria covered:
 *   - Event-driven: WHEN the backend returns a 422 with field-scoped errors,
 *     the form SHALL render each field-scoped message inline beneath its
 *     corresponding field (via rjsf extraErrors).
 *   - Event-driven: WHEN a 422 error has no resolvable field location, the form
 *     SHALL show it in the existing card-level error summary.
 *   - Ubiquitous: Mapping SHALL use the Pydantic error loc path; no per-source
 *     special-casing.
 *
 * These tests exercise SourceConfigForm directly (not wrapped in SourceCard) so
 * we own the error display (onServerErrors not provided → standalone mode).
 *
 * DOM structure note: rjsf renders extraErrors in TWO places by default:
 *   1. An ErrorList panel at the top of the form (all errors combined).
 *   2. Inline [data-fw-error] spans near the field (via project FieldErrorTemplate).
 * Field-scoped errors → exist in both places (rendered via extraErrors prop).
 * Non-field errors → only in the component's own <p role="alert"> (no field to attach to).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import SourceConfigForm from '../components/SourceConfigForm'
import { MINIMAL_SOURCE_ENTRY } from './fixtures'

// vi.hoisted so mock constructors are captured before vi.mock factory runs
const { mockFetchSourceConfig, mockPutSourceConfig, MockApiError } = vi.hoisted(() => {
  // Define ApiError inside vi.hoisted so the same constructor is used by both
  // the mock module and the test helper functions. Using the same class guarantees
  // `err instanceof ApiError` in handleSubmit correctly identifies our test errors.
  class MockApiError extends Error {
    status: number
    detail: unknown
    constructor(status: number, detail: unknown, message?: string) {
      super(message ?? `API error ${status}`)
      this.status = status
      this.detail = detail
    }
  }
  return {
    mockFetchSourceConfig: vi.fn(),
    mockPutSourceConfig: vi.fn(),
    MockApiError,
  }
})

vi.mock('../api/client', () => {
  return {
    fetchSourceConfig: mockFetchSourceConfig,
    putSourceConfig: mockPutSourceConfig,
    // Export MockApiError as ApiError — same constructor that test helpers use.
    ApiError: MockApiError,
    resolveBaseUrl: () => '',
    assertLoopbackBase: () => undefined,
  }
})

// ---------------------------------------------------------------------------
// 422 error fixture helpers — use MockApiError so instanceof checks pass
// ---------------------------------------------------------------------------

/** 422 with a single field-scoped error: loc = [fieldName]. */
function make422FieldError(fieldName: string, msg: string) {
  return new MockApiError(422, {
    detail: [{ loc: [fieldName], msg, type: 'value_error' }],
  })
}

/** 422 with a FastAPI "body"-prefixed field loc: loc = ['body', fieldName]. */
function make422BodyFieldError(fieldName: string, msg: string) {
  return new MockApiError(422, {
    detail: [{ loc: ['body', fieldName], msg, type: 'value_error' }],
  })
}

/** 422 with a form-level (non-field) error: loc = []. */
function make422FormLevelError(msg: string) {
  return new MockApiError(422, {
    detail: [{ loc: [], msg, type: 'value_error' }],
  })
}

/** 422 with both a field error and a form-level error. */
function make422MixedErrors(fieldName: string, fieldMsg: string, formMsg: string) {
  return new MockApiError(422, {
    detail: [
      { loc: [fieldName], msg: fieldMsg, type: 'value_error' },
      { loc: [], msg: formMsg, type: 'value_error' },
    ],
  })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Click the Save button (rjsf shadcn theme labels it "Save", not "Submit"). */
async function clickSave(user: ReturnType<typeof userEvent.setup>) {
  const btn = screen.getByRole('button', { name: /save/i })
  await user.click(btn)
}

/**
 * Query all inline field-error spans rendered by the project's FieldErrorTemplate.
 * These carry `data-fw-error` and appear near their field, not in the card-level alert.
 * Returns true if any span contains text matching the pattern.
 */
function inlineFieldErrorContains(pattern: RegExp): boolean {
  const spans = document.querySelectorAll('[data-fw-error]')
  return Array.from(spans).some((el) => pattern.test(el.textContent ?? ''))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('SourceConfigForm — R8 inline 422 field errors (issue #495)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Default: server returns a basic config
    mockFetchSourceConfig.mockResolvedValue({ host: 'localhost' })
    // Default: PUT succeeds
    mockPutSourceConfig.mockResolvedValue(undefined)
  })

  // EARS — field-scoped 422 renders inline under the field via rjsf extraErrors.
  // When the 422 loc names "host" and MINIMAL_SOURCE_ENTRY has "host" in properties,
  // the error message appears in a [data-fw-error] span near the host input.
  it('renders field-scoped 422 error inline under the matching field via extraErrors', async () => {
    mockPutSourceConfig.mockRejectedValue(
      make422FieldError('host', 'host must be an IP literal'),
    )

    const user = userEvent.setup()
    render(<SourceConfigForm source={MINIMAL_SOURCE_ENTRY} />)

    // Wait for initial config load and form to render
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /save/i })).toBeInTheDocument()
    })

    await act(async () => {
      await clickSave(user)
    })

    // The error must appear in an inline [data-fw-error] span (field-level placement)
    await waitFor(() => {
      expect(inlineFieldErrorContains(/host must be an IP literal/i)).toBe(true)
    })

    // The card-level <p role="alert"> from this component MUST NOT contain the message.
    // (SourceConfigForm only puts formErrors into its own <p role="alert">.)
    const cardAlert = document.querySelector('p[role="alert"]')
    // No card-level alert when all errors are field-scoped
    expect(cardAlert).toBeNull()
  })

  // EARS — FastAPI body prefix: loc = ['body', 'host'] → strip 'body' → field 'host'.
  // The stripped loc should still resolve to the "host" field inline.
  it('strips the leading "body" loc segment and attaches the error inline to the field', async () => {
    mockPutSourceConfig.mockRejectedValue(
      make422BodyFieldError('host', 'host is invalid'),
    )

    const user = userEvent.setup()
    render(<SourceConfigForm source={MINIMAL_SOURCE_ENTRY} />)

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /save/i })).toBeInTheDocument()
    })

    await act(async () => {
      await clickSave(user)
    })

    // Error must appear in an inline [data-fw-error] span
    await waitFor(() => {
      expect(inlineFieldErrorContains(/host is invalid/i)).toBe(true)
    })

    // No card-level alert for field-only errors
    const cardAlert = document.querySelector('p[role="alert"]')
    expect(cardAlert).toBeNull()
  })

  // EARS — form-level / non-field errors appear in the card-level alert paragraph.
  // When loc = [] there is no field to attach to — the error falls to formErrors
  // and is shown in the standalone component's own <p role="alert">.
  it('shows form-level (non-field) 422 errors in the card-level alert', async () => {
    mockPutSourceConfig.mockRejectedValue(
      make422FormLevelError('Request payload is malformed'),
    )

    const user = userEvent.setup()
    render(<SourceConfigForm source={MINIMAL_SOURCE_ENTRY} />)

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /save/i })).toBeInTheDocument()
    })

    await act(async () => {
      await clickSave(user)
    })

    // The card-level <p role="alert"> must contain the message
    await waitFor(() => {
      const cardAlert = document.querySelector('p[role="alert"]')
      expect(cardAlert).not.toBeNull()
      expect(cardAlert!.textContent).toMatch(/Request payload is malformed/i)
    })

    // No inline field-error span for a non-field error
    expect(inlineFieldErrorContains(/Request payload is malformed/i)).toBe(false)
  })

  // EARS — mixed: field error goes inline; form-level error goes to card-level alert.
  it('routes field errors inline and form-level errors to card-level alert separately', async () => {
    mockPutSourceConfig.mockRejectedValue(
      make422MixedErrors('host', 'host must be an IP literal', 'Authorization failed'),
    )

    const user = userEvent.setup()
    render(<SourceConfigForm source={MINIMAL_SOURCE_ENTRY} />)

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /save/i })).toBeInTheDocument()
    })

    await act(async () => {
      await clickSave(user)
    })

    // Field error must appear inline via [data-fw-error]
    await waitFor(() => {
      expect(inlineFieldErrorContains(/host must be an IP literal/i)).toBe(true)
    })

    // Form-level error must appear in card-level <p role="alert">
    const cardAlert = document.querySelector('p[role="alert"]')
    expect(cardAlert).not.toBeNull()
    expect(cardAlert!.textContent).toMatch(/Authorization failed/i)

    // Card-level alert must NOT carry the field-scoped message
    expect(cardAlert!.textContent).not.toMatch(/host must be an IP literal/i)
  })

  // EARS — unknown field loc falls through to card-level summary.
  // "nonexistent_field" is not in MINIMAL_SOURCE_ENTRY.config_schema.properties,
  // so the error cannot be attached to any field.
  it('falls through to card-level alert when loc field is not in the schema', async () => {
    mockPutSourceConfig.mockRejectedValue(
      new MockApiError(422, {
        detail: [{ loc: ['nonexistent_field'], msg: 'unknown field error', type: 'value_error' }],
      }),
    )

    const user = userEvent.setup()
    render(<SourceConfigForm source={MINIMAL_SOURCE_ENTRY} />)

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /save/i })).toBeInTheDocument()
    })

    await act(async () => {
      await clickSave(user)
    })

    // Must appear in card-level alert (fallthrough — field not in schema)
    await waitFor(() => {
      const cardAlert = document.querySelector('p[role="alert"]')
      expect(cardAlert).not.toBeNull()
      expect(cardAlert!.textContent).toMatch(/unknown field error/i)
    })

    // Must NOT appear in any inline [data-fw-error] span
    expect(inlineFieldErrorContains(/unknown field error/i)).toBe(false)
  })

  // Subsequent successful save clears field errors.
  // After a failed PUT shows a field error, a second successful PUT must clear it.
  it('clears inline field errors after a subsequent successful save', async () => {
    // First call fails, second call succeeds.
    mockPutSourceConfig
      .mockRejectedValueOnce(make422FieldError('host', 'host must be an IP literal'))
      .mockResolvedValueOnce(undefined)
    // fetchSourceConfig: initial load + post-save reload
    mockFetchSourceConfig
      .mockResolvedValueOnce({ host: 'localhost' })
      .mockResolvedValueOnce({ host: '10.0.0.1' })

    const user = userEvent.setup()
    render(<SourceConfigForm source={MINIMAL_SOURCE_ENTRY} />)

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /save/i })).toBeInTheDocument()
    })

    // First submit → inline field error appears
    await act(async () => {
      await clickSave(user)
    })
    await waitFor(() => {
      expect(inlineFieldErrorContains(/host must be an IP literal/i)).toBe(true)
    })

    // Second submit → success; inline error must be gone
    await act(async () => {
      await clickSave(user)
    })
    await waitFor(() => {
      expect(inlineFieldErrorContains(/host must be an IP literal/i)).toBe(false)
    })
  })

  // Save-failure secret persistence (#523):
  // WHEN a PUT fails, THEN secretClearNonce is NOT incremented by SourceConfigForm,
  // so each PasswordWidget's localValue is NOT cleared.
  // The user can retry the save without re-entering the secret.
  //
  // MINIMAL_SOURCE_ENTRY has an api_key field (format:password / writeOnly).
  // We type a value, submit (fails), then verify the PasswordWidget input still
  // contains the typed value — proving nonce was NOT bumped on failure.
  it('preserves typed secret in PasswordWidget after a FAILED save (no nonce bump) [#523]', async () => {
    // PUT always fails with a generic error
    mockPutSourceConfig.mockRejectedValue(
      new MockApiError(500, { detail: 'Internal server error' }),
    )
    // fetchSourceConfig: initial load only (no post-save reload on failure)
    mockFetchSourceConfig.mockResolvedValue({ host: 'localhost' })

    const user = userEvent.setup()
    render(<SourceConfigForm source={MINIMAL_SOURCE_ENTRY} />)

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /save/i })).toBeInTheDocument()
    })

    // Type a secret into the password field
    const pwInput = document.querySelector('input[type="password"]') as HTMLInputElement
    expect(pwInput).not.toBeNull()
    await user.click(pwInput)
    await user.type(pwInput, 'my-secret-key')
    expect(pwInput.value).toBe('my-secret-key')

    // Submit → fails
    await act(async () => {
      await clickSave(user)
    })

    // After the failed save, the typed secret must still be in the input.
    // secretClearNonce was NOT bumped (that only happens on success), so
    // PasswordWidget's localValue remains 'my-secret-key'.
    await waitFor(() => {
      expect(document.querySelector('p[role="alert"]')).not.toBeNull()
    })
    expect(pwInput.value).toBe('my-secret-key')
  })
})
