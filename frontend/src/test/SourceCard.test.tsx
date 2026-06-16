/**
 * Tests for src/components/SourceCard.tsx
 *
 * EARS criteria covered:
 *   - Ubiquitous: card rendered from JSON Schema with zero card-specific code.
 *   - Ubiquitous: SecretStr → password widget, never echoed in DOM.
 *   - State-driven: mode=local → SSH fields hidden; mode=remote → SSH fields visible.
 *   - Event-driven: save → PUT called with correct payload.
 *   - Event-driven: server 422 errors are surfaced.
 *
 * ADR-0062 additions (#701–#704):
 *   - §A: Cards collapse by default; Active cards start expanded.
 *   - §B: Active toggle in card header (WAI-ARIA switch).
 *   - §C: Real source_id (not "default") displayed in header.
 *   - §D: "Off" (not "Stale") when source is inactive; Test/Sync disabled when inactive.
 *   - §E: "Not configured" path only reachable when serverHealth='not_configured' AND active.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, act, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import SourceCard from '../components/SourceCard'
import type { SourceHealthItem } from '../lib/sourceHealth'
import {
  SURICATA_SOURCE_ENTRY,
  SURICATA_REVEAL_SOURCE_ENTRY,
  MINIMAL_SOURCE_ENTRY,
  SIMPLE_SECRET_SOURCE_ENTRY,
} from './fixtures'
import type { SourceTypeEntry } from '../schema/types'
import type { SourceInstance } from '../api/types'

// vi.hoisted ensures these are initialized before the vi.mock factory runs
const {
  mockFetchSourceConfig,
  mockPutSourceConfig,
  mockFetchSources,
  mockGetAutoSync,
  mockFetchSourceActions,
} = vi.hoisted(() => ({
  mockFetchSourceConfig: vi.fn(),
  mockPutSourceConfig: vi.fn(),
  mockFetchSources: vi.fn(),
  mockGetAutoSync: vi.fn(),
  mockFetchSourceActions: vi.fn(),
}))

vi.mock('../api/client', () => {
  class ApiError extends Error {
    status: number
    detail: unknown
    constructor(status: number, detail: unknown, message?: string) {
      super(message ?? `API error ${status}`)
      this.status = status
      this.detail = detail
    }
  }
  return {
    fetchSourceConfig: mockFetchSourceConfig,
    putSourceConfig: mockPutSourceConfig,
    ApiError,
    // Required by sourceActions.ts (imported transitively via SourceActions)
    resolveBaseUrl: () => '',
    assertLoopbackBase: () => undefined,
  }
})

// Mock sources API so SourceCard's fetchSources call (for CollectControls) is isolated.
// getAutoSync is called by CollectControls on mount for pull sources — mock it too.
vi.mock('../api/sources', () => ({
  fetchSources: mockFetchSources,
  testSource: vi.fn(),
  syncSource: vi.fn(),
  getAutoSync: mockGetAutoSync,
  setAutoSync: vi.fn(),
}))

// Mock sourceActions API — SourceActions is mounted for sources with declared actions.
// Default: return empty array so the status fetch doesn't interfere with other tests.
vi.mock('../api/sourceActions', () => ({
  fetchSourceActions: mockFetchSourceActions,
  runSourceAction: vi.fn(),
}))

// ---------------------------------------------------------------------------
// Shared instance fixtures (ADR-0062: card starts expanded only when Active)
//
// To test form body (rjsf inputs, save button, etc.), the card must be Active
// (i.e., an instance must exist in GET /sources). These fixtures provide a
// matching active instance for each source type.
// ---------------------------------------------------------------------------

// ADR-0062 Amendment 1 §1 (issue #737): active instances must carry auto_sync_enabled=true.
// SourceCard now derives isActive from auto_sync_enabled, not instance-presence.
// All "active" test fixtures must include this field so the card renders expanded.
const SURICATA_ACTIVE_INSTANCE: SourceInstance = {
  source_type: 'suricata',
  source_id: 'suricata',
  flavor: 'pull',
  state: 'running',
  attempt: 0,
  total_crashes: 0,
  total_dlq: 0,
  dropped_count: 0,
  last_success_at: '2026-06-04T10:00:00Z',
  event_count: 100,
  auto_sync_enabled: true,
}

const SIMPLE_ACTIVE_INSTANCE: SourceInstance = {
  source_type: 'simple_source',
  source_id: 'simple_source',
  flavor: 'push',
  state: 'running',
  attempt: 0,
  total_crashes: 0,
  total_dlq: 0,
  dropped_count: 0,
  last_success_at: '2026-06-04T10:00:00Z',
  event_count: 0,
  auto_sync_enabled: true,
}

const MINIMAL_ACTIVE_INSTANCE: SourceInstance = {
  source_type: 'test_source',
  source_id: 'test_source',
  flavor: 'push',
  state: 'running',
  attempt: 0,
  total_crashes: 0,
  total_dlq: 0,
  dropped_count: 0,
  last_success_at: '2026-06-04T10:00:00Z',
  event_count: 0,
  auto_sync_enabled: true,
}

// ---------------------------------------------------------------------------
// Helper: expand a card that starts collapsed (when testing inactive state).
// Clicks the ds-source-card-chevron to expand the body.
// ---------------------------------------------------------------------------
async function expandCard(): Promise<void> {
  const chevron = screen.getByTestId('ds-source-card-chevron')
  await act(async () => {
    chevron.click()
  })
}

describe('SourceCard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchSourceConfig.mockResolvedValue({
      mode: 'local',
      local_path: '/var/log/suricata/eve.json',
      remote_host: '',
      remote_port: 22,
      remote_user: null,
      remote_key: null,   // server-masked SecretStr
      remote_path: '/var/log/suricata/eve.json',
      verify_host_key: true,
    })
    mockPutSourceConfig.mockResolvedValue(undefined)
    // ADR-0062: card starts expanded only when Active (instance present).
    // Return a suricata instance so card body is visible for form-related tests.
    mockFetchSources.mockResolvedValue([SURICATA_ACTIVE_INSTANCE])
    // Default: getAutoSync returns disabled state (pull sources call this on mount)
    mockGetAutoSync.mockResolvedValue({
      enabled: false,
      interval_seconds: 300,
      source_id: 'suricata',
      last_sync: { last_sync_at: null, last_sync_ingested: 0, last_sync_status: null, last_error: null },
    })
    // Default: no declared actions — SourceActions fetches nothing for sources without actions.
    mockFetchSourceActions.mockResolvedValue([])
  })

  // EARS ubiquitous: card renders from schema with display_name shown
  it('renders the card with the source display_name', async () => {
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    expect(screen.getByLabelText('Suricata IDS/IPS settings')).toBeInTheDocument()
    expect(screen.getByText('Suricata IDS/IPS')).toBeInTheDocument()
  })

  // EARS ubiquitous: card renders from minimal fixture schema
  it('renders a card from a minimal fixture schema (schema-driven, no per-source code)', async () => {
    mockFetchSourceConfig.mockResolvedValue({ host: 'localhost', api_key: null })
    mockFetchSources.mockResolvedValue([MINIMAL_ACTIVE_INSTANCE])
    render(<SourceCard source={MINIMAL_SOURCE_ENTRY} />)
    expect(screen.getByTestId('source-card-test_source')).toBeInTheDocument()
    // Field from schema appears
    await waitFor(() => {
      expect(screen.getByLabelText(/host/i)).toBeInTheDocument()
    })
  })

  // EARS ubiquitous: SecretStr → password input (never plaintext in DOM)
  it('renders secret fields as password inputs', async () => {
    mockFetchSourceConfig.mockResolvedValue({ host: 'localhost', api_key: '' })
    mockFetchSources.mockResolvedValue([MINIMAL_ACTIVE_INSTANCE])
    render(<SourceCard source={MINIMAL_SOURCE_ENTRY} />)
    await waitFor(() => {
      const pwInputs = document.querySelectorAll('input[type="password"]')
      expect(pwInputs.length).toBeGreaterThan(0)
    })
  })

  // EARS ubiquitous: SecretStr field never shows raw value in DOM
  // When the server masks a secret (returns null), the PasswordWidget shows '' with a
  // "•••• set" placeholder — the plaintext secret is never echoed into the DOM.
  it('does not echo the secret value in the DOM for a server-masked field', async () => {
    // The server returns null for a masked secret; after stripNullValues, api_key is absent
    // from formData, so PasswordWidget receives value=undefined (empty).
    mockFetchSourceConfig.mockResolvedValue({ host: 'localhost', api_key: null })
    mockFetchSources.mockResolvedValue([MINIMAL_ACTIVE_INSTANCE])
    render(<SourceCard source={MINIMAL_SOURCE_ENTRY} />)
    await waitFor(() => {
      const pwInput = document.getElementById('root_api_key') as HTMLInputElement | null
      expect(pwInput).not.toBeNull()
      expect(pwInput!.getAttribute('type')).toBe('password')
      // The displayed value must be empty (server secret not echoed into DOM)
      expect(pwInput!.value).toBe('')
    })
  })

  // EARS state-driven (D5 if/then/else reveal): mode=local → SSH fields hidden.
  // Uses the "reveal not require" schema fixture (SURICATA_REVEAL_SCHEMA):
  // SSH fields are ONLY in the then.properties branch; local_path is ONLY in
  // else.properties. rjsf hides the inactive branch's fields.
  //
  // Note: when branch fields don't carry their schema metadata through the merge,
  // rjsf renders them with empty labels. We check by element id (rjsf convention:
  // root_<fieldname>) rather than by label text.
  it('hides SSH fields when mode is local (if/then/else reveal)', async () => {
    mockFetchSourceConfig.mockResolvedValue({ mode: 'local' })
    mockFetchSources.mockResolvedValue([{
      ...SURICATA_ACTIVE_INSTANCE,
      source_type: 'suricata_reveal',
      source_id: 'suricata_reveal',
    }])
    render(<SourceCard source={SURICATA_REVEAL_SOURCE_ENTRY} />)
    // local_path (else branch) should be in DOM for local mode
    await waitFor(() => {
      expect(document.getElementById('root_local_path')).toBeInTheDocument()
    })
    // SSH fields (then branch) must NOT be in DOM when mode=local
    expect(document.getElementById('root_remote_host')).not.toBeInTheDocument()
    expect(document.getElementById('root_remote_port')).not.toBeInTheDocument()
  })

  // EARS state-driven (D5 if/then/else reveal): mode=remote → SSH fields visible.
  // With the reveal schema: SSH fields appear when mode=remote, local_path disappears.
  it('shows SSH fields and hides local_path when mode is remote (if/then/else reveal)', async () => {
    mockFetchSourceConfig.mockResolvedValue({ mode: 'remote', remote_host: '10.0.0.1' })
    mockFetchSources.mockResolvedValue([{
      ...SURICATA_ACTIVE_INSTANCE,
      source_type: 'suricata_reveal',
      source_id: 'suricata_reveal',
    }])
    render(<SourceCard source={SURICATA_REVEAL_SOURCE_ENTRY} />)

    // SSH fields (then branch) should be visible because mode=remote
    await waitFor(() => {
      expect(document.getElementById('root_remote_host')).toBeInTheDocument()
    })
    expect(document.getElementById('root_remote_port')).toBeInTheDocument()
    // local_path (else branch) must NOT be in DOM when mode=remote
    expect(document.getElementById('root_local_path')).not.toBeInTheDocument()
  })

  // EARS event-driven: save → PUT with correct payload
  // MF-6 F10: button now labelled "Save" (not "Submit")
  it('calls putSourceConfig on form submit', async () => {
    const user = userEvent.setup()
    mockFetchSourceConfig.mockResolvedValue({ host: 'localhost', token: '' })
    mockFetchSources.mockResolvedValue([SIMPLE_ACTIVE_INSTANCE])
    render(<SourceCard source={SIMPLE_SECRET_SOURCE_ENTRY} />)

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /save/i })).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByRole('button', { name: /save/i }))
    })

    await waitFor(() => {
      expect(mockPutSourceConfig).toHaveBeenCalledWith(
        'simple_source',
        expect.objectContaining({ host: 'localhost' }),
      )
    })
  })

  // EARS event-driven: null (server-masked) secrets are stripped from the PUT payload
  it('omits null-valued (server-masked) secret from PUT payload', async () => {
    const user = userEvent.setup()
    // token is null (server-masked); host has a real value
    mockFetchSourceConfig.mockResolvedValue({ host: 'myhost', token: null })
    mockFetchSources.mockResolvedValue([SIMPLE_ACTIVE_INSTANCE])
    render(<SourceCard source={SIMPLE_SECRET_SOURCE_ENTRY} />)

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /save/i })).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByRole('button', { name: /save/i }))
    })

    await waitFor(() => {
      expect(mockPutSourceConfig).toHaveBeenCalled()
      const [, payload] = mockPutSourceConfig.mock.calls[0] as [string, Record<string, unknown>]
      // token was null (masked) and user didn't type → must be omitted from PUT
      expect(payload).not.toHaveProperty('token')
    })
  })


  // NB-1 (ADR-0006, R9 / #497): after a successful save, the password input shows
  // the masked placeholder, not the previously-typed value.
  // The Form is NOT remounted — PasswordWidget's localValue is cleared via
  // secretClearNonce in formContext (targeted per-widget state reset).
  it('resets password field to masked placeholder after a successful save (NB-1)', async () => {
    const user = userEvent.setup()
    // First fetch: token is null (server-masked)
    mockFetchSourceConfig
      .mockResolvedValueOnce({ host: 'myhost', token: null })
      // Second fetch (after save): server still masks the secret as null
      .mockResolvedValueOnce({ host: 'myhost', token: null })
    mockPutSourceConfig.mockResolvedValue(undefined)
    mockFetchSources.mockResolvedValue([SIMPLE_ACTIVE_INSTANCE])
    render(<SourceCard source={SIMPLE_SECRET_SOURCE_ENTRY} />)

    // Wait for form to load
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /save/i })).toBeInTheDocument()
    })

    // Find the password input and type a new secret
    const pwInput = document.getElementById('root_token') as HTMLInputElement
    expect(pwInput).not.toBeNull()
    await user.type(pwInput, 'my-new-secret')
    // The typed value should be in the input
    expect(pwInput.value).toBe('my-new-secret')

    // Submit the form
    await act(async () => {
      await user.click(screen.getByRole('button', { name: /save/i }))
    })

    // After save, secretClearNonce increments → PasswordWidget resets localValue.
    // The Form is NOT remounted (R9 #497 — no full-card flash/scroll reset).
    // The password input must be empty with the "•••• set" placeholder (secret cleared).
    await waitFor(() => {
      const freshPwInput = document.getElementById('root_token') as HTMLInputElement
      expect(freshPwInput).not.toBeNull()
      // Value must be empty — typed secret must not persist after save (ADR-0006)
      expect(freshPwInput.value).toBe('')
      // Placeholder must show the masked indicator (server still returns null)
      expect(freshPwInput.placeholder).toMatch(/set/i)
    })
  })

  // EARS event-driven: 422 server errors are surfaced
  it('shows server validation errors on 422 response', async () => {
    const user = userEvent.setup()
    const { ApiError } = await import('../api/client')
    mockFetchSourceConfig.mockResolvedValue({ host: 'localhost', token: '' })
    mockFetchSources.mockResolvedValue([SIMPLE_ACTIVE_INSTANCE])
    mockPutSourceConfig.mockRejectedValue(
      new ApiError(422, { detail: [{ msg: 'value is not a valid string' }] }),
    )
    render(<SourceCard source={SIMPLE_SECRET_SOURCE_ENTRY} />)

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /save/i })).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByRole('button', { name: /save/i }))
    })

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('value is not a valid string')
    })
  })
})

// #67 a11y: noHtml5Validate causes the rjsf Form to set the HTML noValidate attr
// so the browser's native constraint validation is disabled and rjsf/AJV owns errors.
describe('SourceCard validation a11y (#67)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchSourceConfig.mockResolvedValue({ host: 'localhost', token: '' })
    mockPutSourceConfig.mockResolvedValue(undefined)
    // ADR-0062: card must be Active (expanded) for form tests
    mockFetchSources.mockResolvedValue([SIMPLE_ACTIVE_INSTANCE])
    mockGetAutoSync.mockResolvedValue({
      enabled: false, interval_seconds: 300, source_id: 'simple_source',
      last_sync: { last_sync_at: null, last_sync_ingested: 0, last_sync_status: null, last_error: null },
    })
  })

  // The rjsf Form element must have the HTML noValidate attribute set (from
  // noHtml5Validate prop) so rjsf/AJV handles validation instead of the browser.
  it('renders the form with noValidate so rjsf/AJV surfaces errors (#67 a11y)', async () => {
    render(<SourceCard source={SIMPLE_SECRET_SOURCE_ENTRY} />)
    await waitFor(() => {
      // MF-6 F10: button now labelled "Save" (not "Submit")
      expect(screen.getByRole('button', { name: /save/i })).toBeInTheDocument()
    })
    // The <form> element must have the noValidate attribute
    const formEl = document.querySelector('form')
    expect(formEl).not.toBeNull()
    expect(formEl!.hasAttribute('novalidate')).toBe(true)
  })

  // DEFECT 1 fix (#85): the <input> for an invalid field must have the real
  // aria-invalid="true" DOM attribute set (not just a CSS class), so screen
  // readers announce it as invalid (ARIA 1.1 §6.6.5 / WCAG 4.1.3).
  // The @rjsf/shadcn BaseInputTemplate only added CSS classes — our override adds
  // the attribute. We trigger validation by submitting with an invalid port value.
  it('sets aria-invalid="true" attribute on invalid number input after submit (#85 D1 a11y)', async () => {
    vi.clearAllMocks()
    mockFetchSources.mockResolvedValue([SURICATA_ACTIVE_INSTANCE])
    mockPutSourceConfig.mockResolvedValue(undefined)
    mockGetAutoSync.mockResolvedValue({
      enabled: false, interval_seconds: 300, source_id: 'suricata',
      last_sync: { last_sync_at: null, last_sync_ingested: 0, last_sync_status: null, last_error: null },
    })
    mockFetchSourceActions.mockResolvedValue([])

    // Use Suricata schema which has remote_port (integer, min:1, max:65535).
    // Load with an out-of-range port so the field is invalid from the start.
    mockFetchSourceConfig.mockResolvedValue({
      mode: 'remote',
      remote_host: 'server.example.com',
      remote_port: 99999, // invalid: exceeds maximum 65535
      remote_path: '/var/log/suricata/eve.json',
      verify_host_key: true,
    })

    const user = userEvent.setup()
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)

    await waitFor(() => {
      // MF-6 F10: button now labelled "Save" (not "Submit")
      expect(screen.getByRole('button', { name: /save/i })).toBeInTheDocument()
    })

    // Submit to trigger rjsf/AJV validation
    await act(async () => {
      await user.click(screen.getByRole('button', { name: /save/i }))
    })

    // The remote_port input must have the real aria-invalid="true" DOM attribute
    await waitFor(() => {
      const portInput = document.getElementById('root_remote_port') as HTMLInputElement | null
      expect(portInput).not.toBeNull()
      // This is the KEY assertion: the DOM attribute must be set, not just a CSS class
      expect(portInput).toHaveAttribute('aria-invalid', 'true')
    })
  })
})

// #67: nullable-secret entry UX — remote_key (SecretStr | None) renders
// the password input directly, without an anyOf type-selector dropdown.
describe('SourceCard nullable-secret UX (#67)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockPutSourceConfig.mockResolvedValue(undefined)
    // ADR-0062: card must be Active (expanded) for form tests
    mockFetchSources.mockResolvedValue([SURICATA_ACTIVE_INSTANCE])
    mockGetAutoSync.mockResolvedValue({
      enabled: false, interval_seconds: 300, source_id: 'suricata',
      last_sync: { last_sync_at: null, last_sync_ingested: 0, last_sync_status: null, last_error: null },
    })
  })

  it('renders remote_key as a password input directly (no anyOf selector) for Suricata remote mode', async () => {
    mockFetchSourceConfig.mockResolvedValue({
      mode: 'remote',
      remote_host: '10.0.0.1',
      remote_port: 22,
      remote_user: 'ubuntu',
      remote_key: null, // server-masked SecretStr | None
      remote_path: '/var/log/suricata/eve.json',
      verify_host_key: true,
    })
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)

    // Wait for the remote_key password input — it should appear without the user
    // having to pick a type from an anyOf selector dropdown first.
    await waitFor(() => {
      const remoteKeyInput = document.getElementById('root_remote_key') as HTMLInputElement | null
      expect(remoteKeyInput).not.toBeNull()
      expect(remoteKeyInput!.getAttribute('type')).toBe('password')
    })

    // The anyOf type-selector must NOT be present for remote_key
    const anyofSelect = document.getElementById('root_remote_key__anyof_select')
    expect(anyofSelect).toBeNull()
  })

  // R4 fix (D3, #195): remote_user is anyOf[{type:string},{type:null}] in the Suricata schema.
  // rjsf v6 renders a discriminator dropdown (select#root_remote_user__anyof_select) for these
  // by default. The fix collapses anyOf[string,null] into type:["string","null"] at the schema
  // level (normalizeConfigSchema), so rjsf never sees anyOf and never renders the dropdown.
  // This test renders the REAL Suricata schema through the REAL form component and asserts
  // the rendered DOM: no __anyof_select element for remote_user, but the text input is present.
  it('R4: no anyOf discriminator dropdown for remote_user — DOM assertion on real Suricata schema', async () => {
    mockFetchSourceConfig.mockResolvedValue({
      mode: 'remote',
      remote_host: '10.0.0.1',
      remote_port: 22,
      remote_user: 'ubuntu',
      remote_key: null,
      remote_path: '/var/log/suricata/eve.json',
      verify_host_key: true,
    })
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)

    // Wait for the form to load (remote_host should appear since mode=remote)
    await waitFor(() => {
      expect(document.getElementById('root_remote_host')).not.toBeNull()
    })

    // The anyOf type-selector for remote_user must NOT be present in the DOM
    const anyofSelectRemoteUser = document.getElementById('root_remote_user__anyof_select')
    expect(anyofSelectRemoteUser).toBeNull()

    // The remote_user text input should be present (as a regular text field)
    const remoteUserInput = document.getElementById('root_remote_user') as HTMLInputElement | null
    expect(remoteUserInput).not.toBeNull()
    // Must be a text input, not a select
    expect(remoteUserInput!.tagName).toBe('INPUT')

    // Verify the remote_key anyOf selector is also absent (existing #67 behavior preserved)
    const anyofSelectRemoteKey = document.getElementById('root_remote_key__anyof_select')
    expect(anyofSelectRemoteKey).toBeNull()

    // The remote_key password input must still be present (NullablePasswordField intact)
    const remoteKeyInput = document.getElementById('root_remote_key') as HTMLInputElement | null
    expect(remoteKeyInput).not.toBeNull()
    expect(remoteKeyInput!.getAttribute('type')).toBe('password')
  })

  // DEFECT 2 fix (#85): typing in remote_key must NOT corrupt the root formData.
  // Bug: NullablePasswordField called onChange(value, [], ...) which rjsf treated
  // as a root-path replace, setting formData = "typed-value" (a string), causing
  // the next submit to fail AJV "SuricataConfig must be object" validation.
  // Fix: onChange is called with fieldPathId.path instead of [].
  it('typing in remote_key does not corrupt the root formData — PUT payload is an object (#85 D2)', async () => {
    const user = userEvent.setup()
    mockFetchSourceConfig.mockResolvedValue({
      mode: 'remote',
      remote_host: '10.0.0.1',
      remote_port: 22,
      remote_user: 'ubuntu',
      remote_key: null,
      remote_path: '/var/log/suricata/eve.json',
      verify_host_key: true,
    })
    // Second fetch after save:
    mockFetchSourceConfig.mockResolvedValueOnce({
      mode: 'remote',
      remote_host: '10.0.0.1',
      remote_port: 22,
      remote_user: 'ubuntu',
      remote_key: null,
      remote_path: '/var/log/suricata/eve.json',
      verify_host_key: true,
    })

    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)

    // Wait for the password input
    await waitFor(() => {
      expect(document.getElementById('root_remote_key')).not.toBeNull()
    })

    // Type a new key value
    const remoteKeyInput = document.getElementById('root_remote_key') as HTMLInputElement
    await user.type(remoteKeyInput, 'my-ssh-key')

    // Submit — MF-6 F10: button now labelled "Save" (not "Submit")
    await act(async () => {
      await user.click(screen.getByRole('button', { name: /save/i }))
    })

    // PUT must have been called and the payload must be a proper object (not a string)
    await waitFor(() => {
      expect(mockPutSourceConfig).toHaveBeenCalled()
    })

    const [, payload] = mockPutSourceConfig.mock.calls[0] as [string, unknown]
    // If the bug is present, payload would be the string "my-ssh-key" instead of an object
    expect(typeof payload).toBe('object')
    expect(payload).not.toBeNull()
    // The key value should be in the payload (remote_key was typed, not empty)
    expect((payload as Record<string, unknown>)['remote_key']).toBe('my-ssh-key')
    // Other fields must also be present (root formData intact)
    expect((payload as Record<string, unknown>)['mode']).toBe('remote')
    expect((payload as Record<string, unknown>)['remote_host']).toBe('10.0.0.1')
  })
})

// #78: CollectControls wiring — rendered for all sources, flavor-driven.
// Replaces the old SuricataControls-specific test.
// Issue #138: collect controls are now flavor-driven via CollectControls, not type_key-gated.
describe('SourceCard CollectControls wiring (#78 / #138)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchSourceConfig.mockResolvedValue({ mode: 'local' })
    mockPutSourceConfig.mockResolvedValue(undefined)
    mockGetAutoSync.mockResolvedValue({
      enabled: false, interval_seconds: 300, source_id: 'suricata',
      last_sync: { last_sync_at: null, last_sync_ingested: 0, last_sync_status: null, last_error: null },
    })
    mockFetchSourceActions.mockResolvedValue([])
  })

  it('renders CollectControls (pull controls) for the suricata type_key (flavor=pull)', async () => {
    mockFetchSources.mockResolvedValue([
      {
        source_type: 'suricata',
        source_id: 'vm-target',
        flavor: 'pull',
        state: 'running',
        attempt: 0,
        total_crashes: 0,
        total_dlq: 0,
        dropped_count: 0,
        last_success_at: '2026-06-04T10:00:00Z',
        event_count: 100,
        auto_sync_enabled: true,
      },
    ])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      expect(screen.getByTestId('collect-controls')).toBeInTheDocument()
    })
    // Pull flavor → shows Sync-now and Test buttons
    await waitFor(() => {
      expect(screen.getByTestId('btn-test')).toBeInTheDocument()
      expect(screen.getByTestId('btn-sync-now')).toBeInTheDocument()
    })
  })

  it('renders CollectControls for a push source (flavor=push) — listener status only', async () => {
    // Push source: no active instance needed for the CollectControls (push doesn't use Active toggle)
    // However, card still needs to be expanded for the body to show.
    mockFetchSources.mockResolvedValue([MINIMAL_ACTIVE_INSTANCE])
    render(<SourceCard source={MINIMAL_SOURCE_ENTRY} />)
    // MINIMAL_SOURCE_ENTRY has flavor=push — push-status rendered, no pull controls
    await waitFor(() => {
      expect(screen.getByTestId('collect-controls')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('pull-controls')).not.toBeInTheDocument()
  })

  it('renders CollectControls with instance=null when GET /sources returns 503 (no supervisor)', async () => {
    const { ApiError } = await import('../api/client')
    mockFetchSources.mockRejectedValue(new ApiError(503, null, 'Service Unavailable'))
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    // Controls still render — graceful degradation
    // Card will be collapsed (no instance = inactive), expand it
    await waitFor(() => {
      expect(screen.getByTestId('ds-source-card')).toBeInTheDocument()
    })
    await expandCard()
    await waitFor(() => {
      expect(screen.getByTestId('collect-controls')).toBeInTheDocument()
    })
  })

  // D1 regression (#195): GET /sources uses `source_type` (not `type_key`) as the
  // discriminant field. This test uses the EXACT real /sources DTO shape and asserts
  // that SourceActions receives the real source_id ("vm-target"), not the fallback
  // type_key. It will FAIL if anyone re-introduces `i.type_key === typeKey` matching.
  it('D1: instance is matched by source_type and carries the real source_id (real /sources DTO)', async () => {
    // The real GET /sources response shape: source_type (NOT type_key), state (NOT status),
    // last_success_at (NOT last_event_at), no error_message, no display_name.
    mockFetchSources.mockResolvedValue([
      {
        source_type: 'suricata',      // real field — was type_key in old (wrong) interface
        source_id: 'vm-target',        // real instance name from _instances
        flavor: 'pull',
        state: 'running',              // real field — was status in old (wrong) interface
        attempt: 0,
        total_crashes: 0,
        total_dlq: 0,
        dropped_count: 0,
        last_success_at: '2026-06-04T10:00:00Z',  // real field — was last_event_at
        event_count: 42,
        auto_sync_enabled: true, // ADR-0062 Amendment 1: must be true for card to expand
        // NO type_key, NO status, NO last_event_at, NO error_message
      },
    ])
    const mockSourceActions = vi.fn().mockResolvedValue([])
    mockFetchSourceActions.mockImplementation(mockSourceActions)

    // Render Suricata source which has declared actions (so SourceActions is mounted)
    const suricataWithActions: SourceTypeEntry = {
      ...SURICATA_SOURCE_ENTRY,
      actions: [
        {
          id: 'fetch_ruleset',
          label: 'Download rules',
          description: 'Downloads rule descriptions.',
          long_running: true,
          confirm: 'This will download ~40 MB.',
          provides: ['rule_descriptions'],
        },
      ],
    }
    render(<SourceCard source={suricataWithActions} />)

    // Wait for the instance to be fetched and controls to render
    await waitFor(() => {
      expect(screen.getByTestId('collect-controls')).toBeInTheDocument()
    })

    // R1 fix: SourceActions only mounts AFTER the instance fetch resolves.
    // Therefore, fetchSourceActions must be called with "vm-target" (the real instance id).
    // It must NEVER be called with "suricata" (the fallback type_key) because SourceActions
    // does not mount until instanceResolved=true.
    await waitFor(() => {
      const calls = mockSourceActions.mock.calls as [string, string][]
      const calledWithRealId = calls.some(([, sourceId]) => sourceId === 'vm-target')
      expect(calledWithRealId).toBe(true)
    })

    // Assert the type_key fallback was NEVER used — this is the R1 fix assertion.
    const calls = mockSourceActions.mock.calls as [string, string][]
    const calledWithTypeKey = calls.some(([, sourceId]) => sourceId === 'suricata')
    expect(calledWithTypeKey).toBe(false)
  })

  // R1 fix: mock a delayed /sources response → SourceActions must NOT fire with type_key.
  // Simulates the race condition: SourceActions would previously mount immediately with
  // sourceId="suricata" before the instance fetch resolved, causing 404s.
  it('R1: delayed /sources fetch — no request ever fires with type_key as source_id', async () => {
    // Delay the /sources response to simulate a slow network fetch
    let resolveSourcesFetch!: (value: ReturnType<typeof mockFetchSources.mock.results[0]['value']>) => void
    mockFetchSources.mockReturnValue(
      new Promise((resolve) => { resolveSourcesFetch = resolve }),
    )

    const mockSourceActions = vi.fn().mockResolvedValue([])
    mockFetchSourceActions.mockImplementation(mockSourceActions)

    const suricataWithActions: SourceTypeEntry = {
      ...SURICATA_SOURCE_ENTRY,
      actions: [
        {
          id: 'fetch_ruleset',
          label: 'Download rules',
          description: 'Downloads rule descriptions.',
          long_running: true,
          confirm: null,
          provides: [],
        },
      ],
    }
    render(<SourceCard source={suricataWithActions} />)

    // Let React settle initial renders (before /sources resolves)
    await act(async () => {
      await new Promise((r) => setTimeout(r, 50))
    })

    // While /sources is still pending, SourceActions must NOT have fired at all
    // (R1: deferred mount — SourceActions only mounts after instanceResolved=true)
    expect(mockSourceActions).not.toHaveBeenCalled()

    // Now resolve the /sources fetch with a real instance
    await act(async () => {
      resolveSourcesFetch([
        {
          source_type: 'suricata',
          source_id: 'vm-target',
          flavor: 'pull',
          state: 'running',
          attempt: 0,
          total_crashes: 0,
          total_dlq: 0,
          dropped_count: 0,
          last_success_at: '2026-06-04T10:00:00Z',
          event_count: 5,
          auto_sync_enabled: true,
        },
      ])
    })

    // After resolution, SourceActions mounts with the correct id
    await waitFor(() => {
      expect(mockSourceActions).toHaveBeenCalled()
    })
    // No call with the type_key fallback — only "vm-target" was ever used
    const calls = mockSourceActions.mock.calls as [string, string][]
    const calledWithTypeKey = calls.some(([, id]) => id === 'suricata')
    expect(calledWithTypeKey).toBe(false)
    const calledWithRealId = calls.some(([, id]) => id === 'vm-target')
    expect(calledWithRealId).toBe(true)
  })
})

// Separate test: card data-testid presence for SourceCard
describe('SourceCard testid', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchSourceConfig.mockResolvedValue({})
    mockPutSourceConfig.mockResolvedValue(undefined)
    mockFetchSources.mockResolvedValue([])
    mockGetAutoSync.mockResolvedValue({
      enabled: false, interval_seconds: 300, source_id: 'my_plugin',
      last_sync: { last_sync_at: null, last_sync_ingested: 0, last_sync_status: null, last_error: null },
    })
  })

  it('has data-testid matching the type_key', () => {
    const source: SourceTypeEntry = {
      type_key: 'my_plugin',
      display_name: 'My Plugin',
      version: '1.0.0',
      flavor: 'pull',
      config_schema: { type: 'object', properties: {} },
    }
    render(<SourceCard source={source} />)
    expect(screen.getByTestId('source-card-my_plugin')).toBeInTheDocument()
  })
})

// P5 (#116) DS SourceCard shell chrome assertions
// Verifies header/badge/health/version chrome from the DS SourceCard shell.
describe('SourceCard P5 DS shell chrome (#116)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchSourceConfig.mockResolvedValue({ mode: 'local' })
    mockPutSourceConfig.mockResolvedValue(undefined)
    // ADR-0062: card must be Active for form body tests.
    // Header chrome tests (badges, icons, version) work regardless — header always visible.
    mockFetchSources.mockResolvedValue([SURICATA_ACTIVE_INSTANCE])
    mockGetAutoSync.mockResolvedValue({
      enabled: false, interval_seconds: 300, source_id: 'suricata',
      last_sync: { last_sync_at: null, last_sync_ingested: 0, last_sync_status: null, last_error: null },
    })
  })

  // DS SourceCard shell renders (data-testid="ds-source-card")
  it('renders the DS SourceCard shell', () => {
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    expect(screen.getByTestId('ds-source-card')).toBeInTheDocument()
  })

  // SourceBadge is present in the header for the source type_key
  it('renders a SourceBadge for the source type_key', () => {
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    // SourceBadge renders with data-source attribute
    const badge = document.querySelector('[data-source="suricata"]')
    expect(badge).not.toBeNull()
    expect(badge).toBeInTheDocument()
  })

  // SourceHealth dot is present in the header
  it('renders a SourceHealth dot for the source', () => {
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    // SourceHealth renders health-item-{id} data-testid
    expect(screen.getByTestId(`health-item-suricata`)).toBeInTheDocument()
  })

  // Version number is rendered in header
  it('renders the source version in the header', () => {
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    expect(screen.getByText(`v${SURICATA_SOURCE_ENTRY.version}`)).toBeInTheDocument()
  })

  // Source icon (emoji glyph) is rendered: suricata → 🛰️
  it('renders the correct emoji glyph for the suricata source', () => {
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    // DS SourceCard renders icon in an aria-hidden span
    const header = screen.getByTestId('ds-source-card')
    expect(header.textContent).toContain('🛰️')
  })

  // Source icon for unknown type_key → neutral 📦
  it('renders the neutral emoji glyph for an unknown source type', () => {
    mockFetchSourceConfig.mockResolvedValue({})
    mockFetchSources.mockResolvedValue([])
    const source: SourceTypeEntry = {
      type_key: 'my_unknown',
      display_name: 'Unknown Source',
      version: '0.1.0',
      flavor: 'pull',
      config_schema: { type: 'object', properties: {} },
    }
    render(<SourceCard source={source} />)
    expect(screen.getByTestId('ds-source-card').textContent).toContain('📦')
  })

  // rjsf form is still rendered inside the DS shell (schema-driven, ADR-0010)
  it('renders the rjsf form inside the DS SourceCard shell', async () => {
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      expect(screen.getByTestId(`source-config-form-suricata`)).toBeInTheDocument()
    })
  })

  // Modularity: azure_waf → ☁️ glyph
  it('renders ☁️ glyph for azure_waf source', () => {
    mockFetchSourceConfig.mockResolvedValue({})
    mockFetchSources.mockResolvedValue([])
    const wafSource: SourceTypeEntry = {
      type_key: 'azure_waf',
      display_name: 'Azure WAF',
      version: '1.0.0',
      flavor: 'pull',
      config_schema: { type: 'object', properties: {} },
    }
    render(<SourceCard source={wafSource} />)
    expect(screen.getByTestId('ds-source-card').textContent).toContain('☁️')
  })
})

// MF-6 (#163) v2 kit restyle — EARS-driven tests
// Ubiquitous: rjsf submit button MUST read "Save" (not "Submit") per sweep finding F10.
describe('SourceCard MF-6 v2 kit restyle (#163)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchSourceConfig.mockResolvedValue({ host: 'localhost', token: '' })
    mockPutSourceConfig.mockResolvedValue(undefined)
    // ADR-0062: card must be Active for form body to be visible
    mockFetchSources.mockResolvedValue([SIMPLE_ACTIVE_INSTANCE])
    mockGetAutoSync.mockResolvedValue({
      enabled: false,
      interval_seconds: 300,
      source_id: 'simple_source',
      last_sync: { last_sync_at: null, last_sync_ingested: 0, last_sync_status: null, last_error: null },
    })
  })

  // EARS ubiquitous: form submit button MUST be labelled "Save" (sweep finding F10).
  // The SubmitButton template override (MF-6) replaces the rjsf default "Submit" label.
  it('renders the form submit button with label "Save" — not "Submit" (MF-6 F10)', async () => {
    render(<SourceCard source={SIMPLE_SECRET_SOURCE_ENTRY} />)
    await waitFor(() => {
      const btn = screen.getByRole('button', { name: /save/i })
      expect(btn).toBeInTheDocument()
      expect(btn.textContent).toBe('Save')
    })
    // Must NOT have a button named "Submit" (the old default)
    expect(screen.queryByRole('button', { name: /^submit$/i })).toBeNull()
  })

  // EARS state-driven: schema-driven form behaviors (masking/reveal/aria-invalid) MUST
  // survive the restyle — this test confirms the form still renders after the restyle.
  it('still renders schema-driven form with DS shell after restyle (rjsf form present)', async () => {
    render(<SourceCard source={SIMPLE_SECRET_SOURCE_ENTRY} />)
    await waitFor(() => {
      expect(screen.getByTestId('source-config-form-simple_source')).toBeInTheDocument()
    })
    // DS shell still present
    expect(screen.getByTestId('ds-source-card')).toBeInTheDocument()
  })
})

// R9 (issue #497) — soften save flow: no full-form remount, secret hygiene preserved.
// These tests cover the three EARS criteria from issue #497:
//   1. (HARD/security) Secret must not persist in state after save.
//   2. (Event-driven) Form must NOT fully remount on save (non-secret state preserved).
//   3. (Event-driven) Success toast appears after save; no static "Settings saved." text.
describe('SourceConfigForm R9 (#497) — softer save, preserved secret hygiene', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchSourceConfig
      .mockResolvedValueOnce({ host: 'myhost', token: null })
      .mockResolvedValueOnce({ host: 'myhost', token: null })
    mockPutSourceConfig.mockResolvedValue(undefined)
    // ADR-0062: card must be Active for form body to be visible
    mockFetchSources.mockResolvedValue([SIMPLE_ACTIVE_INSTANCE])
    mockGetAutoSync.mockResolvedValue({
      enabled: false,
      interval_seconds: 300,
      source_id: 'simple_source',
      last_sync: { last_sync_at: null, last_sync_ingested: 0, last_sync_status: null, last_error: null },
    })
  })

  // EARS constraint (HARD — security, ADR-0006): typed secret must be gone from
  // component state after a successful save. The PasswordWidget must return to
  // the masked-placeholder state (empty value, '•••• set' placeholder).
  it('typed secret value is NOT present in the password input after a successful save (NB-1/ADR-0006)', async () => {
    const user = userEvent.setup()
    render(<SourceCard source={SIMPLE_SECRET_SOURCE_ENTRY} />)

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /save/i })).toBeInTheDocument()
    })

    const pwInput = document.getElementById('root_token') as HTMLInputElement
    expect(pwInput).not.toBeNull()

    // Type a plaintext secret
    await user.type(pwInput, 'plaintext-secret-must-not-survive')
    expect(pwInput.value).toBe('plaintext-secret-must-not-survive')

    // Save
    await act(async () => {
      await user.click(screen.getByRole('button', { name: /save/i }))
    })

    // The secret must NOT be present in the input value after save
    await waitFor(() => {
      const pwAfterSave = document.getElementById('root_token') as HTMLInputElement
      expect(pwAfterSave).not.toBeNull()
      // CRITICAL: typed secret must not survive in component state
      expect(pwAfterSave.value).toBe('')
      expect(pwAfterSave.value).not.toContain('plaintext-secret-must-not-survive')
    })
  })

  // EARS event-driven: WHEN a save succeeds, the form SHALL NOT fully remount.
  // Verified by checking that a non-secret field's DOM node identity is preserved
  // across the save: if the Form remounted, the element reference would change and
  // a stale reference would be detached from the document.
  it('non-secret field retains its DOM node identity after save (no full-form remount)', async () => {
    const user = userEvent.setup()
    mockFetchSourceConfig
      .mockResolvedValueOnce({ host: 'before-save', token: null })
      .mockResolvedValueOnce({ host: 'before-save', token: null })
    render(<SourceCard source={SIMPLE_SECRET_SOURCE_ENTRY} />)

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /save/i })).toBeInTheDocument()
    })

    // Capture the DOM node for the non-secret 'host' field before save
    const hostInputBefore = document.getElementById('root_host') as HTMLInputElement
    expect(hostInputBefore).not.toBeNull()

    // Save
    await act(async () => {
      await user.click(screen.getByRole('button', { name: /save/i }))
    })

    // Allow the save to complete
    await waitFor(() => {
      expect(mockPutSourceConfig).toHaveBeenCalled()
    })

    // The host field's DOM node must still be the same element (not remounted).
    // If the Form remounted, document.getElementById('root_host') would return
    // a NEW node and the old reference would be detached (not in the document).
    // We re-query by id and verify the field is still present and functional.
    await waitFor(() => {
      const hostInputAfter = document.getElementById('root_host') as HTMLInputElement
      expect(hostInputAfter).not.toBeNull()
      // Both the old and new references must point to nodes in the document.
      // If remounted, the OLD node would be detached (not in document.body).
      expect(document.body.contains(hostInputBefore)).toBe(true)
    })
  })

  // EARS event-driven: WHEN a save succeeds, a clear transient success affordance
  // (DS Toast) SHALL appear. The previous "Settings saved." static text is replaced
  // by a Toast with tone="ok" and role="status" (R9 #497).
  it('shows a success toast (DS Toast, tone=ok) after a successful save', async () => {
    const user = userEvent.setup()
    render(<SourceCard source={SIMPLE_SECRET_SOURCE_ENTRY} />)

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /save/i })).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByRole('button', { name: /save/i }))
    })

    // The DS Toast renders with role="status" and contains the success message
    await waitFor(() => {
      const toast = screen.getByTestId('save-success-toast')
      expect(toast).toBeInTheDocument()
      // The DS Toast inside has role="status"
      const statusEl = toast.querySelector('[role="status"]')
      expect(statusEl).not.toBeNull()
      expect(statusEl!.textContent).toMatch(/saved/i)
    })
  })

  // Regression: the old static role="status" paragraph (saveStatus === 'saved') must
  // NOT appear — it has been replaced by the DS Toast. This ensures the affordance
  // is consistent with the design system (not a plain paragraph).
  it('does not show the old static "Settings saved." paragraph (replaced by Toast)', async () => {
    const user = userEvent.setup()
    render(<SourceCard source={SIMPLE_SECRET_SOURCE_ENTRY} />)

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /save/i })).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByRole('button', { name: /save/i }))
    })

    await waitFor(() => {
      // The toast must be present
      expect(screen.getByTestId('save-success-toast')).toBeInTheDocument()
    })

    // There must be no bare <p role="status"> with "Settings saved." text outside the toast
    const allStatus = document.querySelectorAll('p[role="status"]')
    expect(allStatus.length).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// #573 — "Stale — 29689956m ago" → "Stale — never" for epoch-fallback timestamps
// ---------------------------------------------------------------------------

describe('#573 — toStatusText epoch-fallback guard ("never" instead of huge minute count)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchSourceConfig.mockResolvedValue({
      mode: 'local',
      local_path: '/var/log/suricata/eve.json',
      remote_host: '',
      remote_port: 22,
      remote_user: null,
      remote_key: null,
      remote_path: '/var/log/suricata/eve.json',
      verify_host_key: true,
    })
    mockPutSourceConfig.mockResolvedValue(undefined)
    mockGetAutoSync.mockResolvedValue({
      enabled: false,
      interval_seconds: 300,
      source_id: 'suricata',
      last_sync: { last_sync_at: null, last_sync_ingested: 0, last_sync_status: null, last_error: null },
    })
    mockFetchSourceActions.mockResolvedValue([])
  })

  // WHEN last_success_at is an epoch-like timestamp AND server health is amber,
  // THE SYSTEM SHALL display "Stale — never" (epoch guard fires for the recency suffix).
  // Since ADR-0032, the primary label ("Stale") comes from serverHealth='amber';
  // the recency caption "— never" comes from the epoch-fallback guard (#573).
  // ADR-0062: "Stale" only shows when isActive=true (instance present).
  it('shows "Stale — never" when last_success_at is the Unix epoch (1970-01-01) and server health is amber', async () => {
    // Provide a source instance with a 1970 epoch timestamp (isActive=true)
    mockFetchSources.mockResolvedValue([
      {
        source_id: 'suricata',
        source_type: 'suricata',
        state: 'ok',
        // Unix epoch — the epoch fallback that caused "Stale — 29689956m ago"
        last_success_at: '1970-01-01T00:00:00Z',
        last_error: null,
        auto_sync_enabled: true, // ADR-0062 Amendment 1: isActive=true so "Stale" is reachable
      },
    ])

    // serverHealth='amber' (stale source) — the dot color comes from server, not recency.
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} serverHealth="amber" />)

    await waitFor(() => {
      const statusEl = screen.getByTestId('source-card-suricata')
      // Must contain "Stale" (from server health=amber) and "never" (epoch guard)
      expect(statusEl.textContent).toContain('Stale')
      expect(statusEl.textContent).toContain('never')
      // Must NOT contain a multi-digit minute count like "29689956m"
      expect(statusEl.textContent).not.toMatch(/\d{5,}m ago/)
    })
  })

  // A recent timestamp (<5 min) with server health='ok' renders "Active — Xm ago"
  it('shows "Active — Xm ago" with recent last_success_at and server health=ok', async () => {
    const twoMinutesAgo = new Date(Date.now() - 2 * 60 * 1000).toISOString()
    mockFetchSources.mockResolvedValue([
      {
        source_id: 'suricata',
        source_type: 'suricata',
        state: 'ok',
        last_success_at: twoMinutesAgo,
        last_error: null,
        auto_sync_enabled: true, // ADR-0062 Amendment 1: isActive=true so "Active" is reachable
      },
    ])

    // serverHealth='ok' — active source with recent events
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} serverHealth="ok" />)

    await waitFor(() => {
      const statusEl = screen.getByTestId('source-card-suricata')
      expect(statusEl.textContent).toContain('Active')
    })
  })
})

// ---------------------------------------------------------------------------
// ADR-0032 Decision C — SourceCard health dot uses server health field
//
// Tests for the fix: the Settings card dot is driven by the server-computed
// `health` prop (from GET /stats), NOT from local last_success_at recency.
// This ensures the card dot matches the AppHeader dot for the same source.
//
// Regression: before the fix, azure_waf with epoch last_success_at showed red
// ("Stale — never" / "collector failure") even when the server health was amber.
// ---------------------------------------------------------------------------

describe('SourceCard serverHealth prop — dot driven by server health (ADR-0032 D/C)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchSourceConfig.mockResolvedValue({})
    mockPutSourceConfig.mockResolvedValue(undefined)
    mockGetAutoSync.mockResolvedValue({
      enabled: false,
      interval_seconds: 300,
      source_id: 'suricata',
      last_sync: { last_sync_at: null, last_sync_ingested: 0, last_sync_status: null, last_error: null },
    })
    mockFetchSourceActions.mockResolvedValue([])
  })

  // THE KEY REGRESSION TEST:
  // GIVEN server health='amber' for a source whose last_success_at is epoch/never,
  // THE card dot MUST render warn (amber) — NOT down (red).
  // The status text must say "Stale — never" (amber label + epoch caption), NOT
  // "Stale — never / collector failure" or similar false-failure wording.
  // ADR-0062: instance present (active) so "Stale" is reachable (not "Off").
  it('serverHealth=amber + epoch last_success_at → warn dot and "Stale" text, NOT red/collector-failure', async () => {
    mockFetchSources.mockResolvedValue([
      {
        source_id: 'azure_waf',
        source_type: 'azure_waf',
        state: 'idle',
        // epoch-fallback timestamp — the azure_waf case from the bug report
        last_success_at: '1970-01-01T00:00:00Z',
        last_error: null,
        auto_sync_enabled: true, // ADR-0062 Amendment 1: isActive=true so "Stale" is reachable
      },
    ])

    const wafSource: SourceTypeEntry = {
      type_key: 'azure_waf',
      display_name: 'Azure WAF',
      version: '1.0.0',
      flavor: 'pull',
      config_schema: { type: 'object', properties: {} },
    }

    // serverHealth='amber': server knows the source is stale but not failed
    render(<SourceCard source={wafSource} serverHealth="amber" />)

    await waitFor(() => {
      // The health item must reflect amber (warn), not red (down)
      const healthItem = screen.getByTestId('health-item-azure_waf')
      expect(healthItem).toBeInTheDocument()
      // The dot renders with data-health attribute matching the health string
      // SourceHealth DS component renders data-health on the dot element
      const dotEl = healthItem.querySelector('[data-health]')
      if (dotEl) {
        // Must be 'amber' (warn), NEVER 'red' (down) — the regression guard
        expect(dotEl.getAttribute('data-health')).not.toBe('red')
        expect(dotEl.getAttribute('data-health')).toBe('amber')
      }

      // Status text must say "Stale" (from amber) — not "collector failure" or "Error"
      const card = screen.getByTestId('source-card-azure_waf')
      expect(card.textContent).toContain('Stale')
      expect(card.textContent).not.toContain('collector failure')
      expect(card.textContent).not.toContain('Error')
      // The epoch guard must append "never" (not a huge minute count)
      expect(card.textContent).toContain('never')
      expect(card.textContent).not.toMatch(/\d{5,}m ago/)
    })
  })

  // serverHealth='ok' → green dot + "Active" text
  it('serverHealth=ok → active card status and "Active" status text', async () => {
    const twoMinutesAgo = new Date(Date.now() - 2 * 60 * 1000).toISOString()
    mockFetchSources.mockResolvedValue([
      {
        source_id: 'suricata',
        source_type: 'suricata',
        state: 'running',
        last_success_at: twoMinutesAgo,
        last_error: null,
        auto_sync_enabled: true, // ADR-0062 Amendment 1: isActive=true so "Active" is reachable
      },
    ])

    render(<SourceCard source={SURICATA_SOURCE_ENTRY} serverHealth="ok" />)

    await waitFor(() => {
      const healthItem = screen.getByTestId('health-item-suricata')
      const dotEl = healthItem.querySelector('[data-health]')
      if (dotEl) {
        expect(dotEl.getAttribute('data-health')).toBe('ok')
      }
      const card = screen.getByTestId('source-card-suricata')
      expect(card.textContent).toContain('Active')
    })
  })

  // serverHealth='red' → red dot + "Error" text
  it('serverHealth=red → error card status and "Error" status text', async () => {
    mockFetchSources.mockResolvedValue([
      {
        source_id: 'suricata',
        source_type: 'suricata',
        state: 'error',
        last_success_at: null,
        last_error: 'Connection refused',
        auto_sync_enabled: true, // ADR-0062 Amendment 1: isActive=true so "Error" is reachable
      },
    ])

    render(<SourceCard source={SURICATA_SOURCE_ENTRY} serverHealth="red" />)

    await waitFor(() => {
      const healthItem = screen.getByTestId('health-item-suricata')
      const dotEl = healthItem.querySelector('[data-health]')
      if (dotEl) {
        expect(dotEl.getAttribute('data-health')).toBe('red')
      }
      const card = screen.getByTestId('source-card-suricata')
      expect(card.textContent).toContain('Error')
    })
  })

  // ADR-0062 §E: inactive source (no instance) → "Off" (not "Not configured")
  // When there's no _instances entry, the source is Off (not running at all).
  // "Not configured" is only valid when isActive=true AND serverHealth='not_configured'.
  it('no instance → shows "Off" in status text (ADR-0062 §E)', async () => {
    mockFetchSources.mockResolvedValue([]) // no instance → isActive=false

    render(<SourceCard source={SURICATA_SOURCE_ENTRY} serverHealth="not_configured" />)

    await waitFor(() => {
      const card = screen.getByTestId('source-card-suricata')
      // ADR-0062 §E: "Off" replaces all other labels when isActive=false
      expect(card.textContent).toContain('Off')
      expect(card.textContent).not.toContain('Not configured')
    })
  })

  // serverHealth=null (stats not yet fetched) → neutral dot, no false-red
  it('serverHealth=null (unavailable) → neutral idle state, NOT red', async () => {
    mockFetchSources.mockResolvedValue([
      {
        source_id: 'suricata',
        source_type: 'suricata',
        state: 'idle',
        // epoch-fallback timestamp — what used to cause false-red before the fix
        last_success_at: '1970-01-01T00:00:00Z',
        last_error: null,
      },
    ])

    // No serverHealth prop (null) — stats not yet available
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)

    await waitFor(() => {
      const healthItem = screen.getByTestId('health-item-suricata')
      const dotEl = healthItem.querySelector('[data-health]')
      if (dotEl) {
        // Must NOT be red when server health is unknown — fall back to neutral
        expect(dotEl.getAttribute('data-health')).not.toBe('red')
      }
      const card = screen.getByTestId('source-card-suricata')
      // Must not show "collector failure" or "Error" when server health unknown
      expect(card.textContent).not.toContain('collector failure')
    })
  })
})

// ---------------------------------------------------------------------------
// ADR-0062 §A/§B/§C — Collapse, Active toggle, real source_id
// ---------------------------------------------------------------------------

describe('ADR-0062 — collapse, Active toggle, and source_id (§A/§B/§C)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchSourceConfig.mockResolvedValue({ mode: 'local' })
    mockPutSourceConfig.mockResolvedValue(undefined)
    mockGetAutoSync.mockResolvedValue({
      enabled: false,
      interval_seconds: 300,
      source_id: 'suricata',
      last_sync: { last_sync_at: null, last_sync_ingested: 0, last_sync_status: null, last_error: null },
    })
    mockFetchSourceActions.mockResolvedValue([])
  })

  // §A: card starts collapsed when no instance (inactive)
  it('§A: card body is hidden when source is inactive (collapsed by default)', async () => {
    mockFetchSources.mockResolvedValue([]) // no instance → isActive=false
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      expect(screen.getByTestId('ds-source-card')).toBeInTheDocument()
    })
    // Body (form) must NOT be visible — card is collapsed
    expect(screen.queryByTestId('source-config-form-suricata')).not.toBeInTheDocument()
  })

  // §A: card starts expanded when source is active (instance present)
  it('§A: card body is visible when source is active (expanded by default)', async () => {
    mockFetchSources.mockResolvedValue([SURICATA_ACTIVE_INSTANCE])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      expect(screen.getByTestId('source-config-form-suricata')).toBeInTheDocument()
    })
  })

  // §A: expanding a collapsed card reveals the form body
  it('§A: clicking the collapse toggle expands a collapsed card to reveal the form', async () => {
    mockFetchSources.mockResolvedValue([]) // inactive → collapsed
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      expect(screen.getByTestId('ds-source-card')).toBeInTheDocument()
    })
    // Form not visible before expand
    expect(screen.queryByTestId('source-config-form-suricata')).not.toBeInTheDocument()

    // Expand by clicking the chevron
    await expandCard()

    // Form must be visible after expand
    await waitFor(() => {
      expect(screen.getByTestId('source-config-form-suricata')).toBeInTheDocument()
    })
  })

  // §B: Active toggle is in the card header for pull sources
  it('§B: Active toggle (role=switch) is in the header for pull sources', async () => {
    mockFetchSources.mockResolvedValue([]) // inactive
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      const toggle = screen.getByTestId('active-toggle')
      expect(toggle).toBeInTheDocument()
      expect(toggle).toHaveAttribute('role', 'switch')
      expect(toggle).toHaveAttribute('aria-checked', 'false') // inactive
    })
  })

  // §B: Active toggle reflects active state when instance is present
  it('§B: Active toggle shows aria-checked=true when source is active', async () => {
    mockFetchSources.mockResolvedValue([SURICATA_ACTIVE_INSTANCE])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      const toggle = screen.getByTestId('active-toggle')
      expect(toggle).toHaveAttribute('aria-checked', 'true')
    })
  })

  // §B: "Active" label when toggle is on
  it('§B: toggle label shows "Active" when source is active', async () => {
    mockFetchSources.mockResolvedValue([SURICATA_ACTIVE_INSTANCE])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      const label = screen.getByTestId('active-toggle-label')
      expect(label).toHaveTextContent('Active')
    })
  })

  // §B: "Off" label when toggle is off
  it('§B: toggle label shows "Off" when source is inactive', async () => {
    mockFetchSources.mockResolvedValue([]) // no instance → inactive
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      const label = screen.getByTestId('active-toggle-label')
      expect(label).toHaveTextContent('Off')
    })
  })

  // §C: real source_id in header when instance is present
  it('§C: shows real source_id (not "default") in card header when instance exists', async () => {
    mockFetchSources.mockResolvedValue([{
      ...SURICATA_ACTIVE_INSTANCE,
      source_id: 'my-vm-target',
    }])
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      // source_id span shows the real instance id
      const sourceIdSpan = screen.getByTestId('source-id-suricata')
      expect(sourceIdSpan).toHaveTextContent('my-vm-target')
      expect(sourceIdSpan).not.toHaveTextContent('default')
    })
  })

  // §C: shows type_key as default source_id when no instance
  it('§C: shows type_key as source_id when no instance (defaults to type_key per ADR-0031 §B)', async () => {
    mockFetchSources.mockResolvedValue([]) // no instance
    render(<SourceCard source={SURICATA_SOURCE_ENTRY} />)
    await waitFor(() => {
      const sourceIdSpan = screen.getByTestId('source-id-suricata')
      expect(sourceIdSpan).toHaveTextContent('suricata')
    })
  })
})

// ---------------------------------------------------------------------------
// serverHealthItem prop — "Events" + "Last event" fields in the HealthCard popover
//
// Bug fix: the HealthCard popover's "Events" row was showing 0 (hardcoded) and
// "Last event" was showing "—" (from epoch last_success_at) even when the server
// had real data.  The fix threads serverHealthItem (from GET /stats) into the
// healthItem that feeds the HealthCard popover.
//
// EARS criteria:
//   - State-driven: GIVEN a serverHealthItem with event_count=269 and a recent
//     last_event_at, the HealthCard SHALL render "269" for Events and a formatted
//     timestamp for Last event (not "—" / 0 / "never").
//   - State-driven: GIVEN no serverHealthItem (null), the HealthCard SHALL render
//     "—" for Last event and "—" for Events (graceful fallback, no crash).
//   - Consistency: the card's "Last event" and "Events" MUST match the values
//     the AppHeader shows for the same source type (both read from /stats).
// ---------------------------------------------------------------------------

describe('SourceCard serverHealthItem — Events + Last event match /stats data', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchSourceConfig.mockResolvedValue({})
    mockPutSourceConfig.mockResolvedValue(undefined)
    mockFetchSources.mockResolvedValue([])
    mockGetAutoSync.mockResolvedValue({
      enabled: false,
      interval_seconds: 300,
      source_id: 'azure_waf',
      last_sync: { last_sync_at: null, last_sync_ingested: 0, last_sync_status: null, last_error: null },
    })
    mockFetchSourceActions.mockResolvedValue([])
  })

  it('shows real event_count in HealthCard popover when serverHealthItem is provided', async () => {
    const recentTime = new Date(Date.now() - 11 * 60 * 1000).toISOString() // 11m ago

    const healthItem: SourceHealthItem = {
      id: 'azure_waf',
      label: 'Azure WAF',
      health: 'amber',
      supervisorState: null,
      lastEventAt: recentTime,
      lastError: null,
      eventCount: 269,
      sourceType: 'azure_waf',
    }

    const wafSource = {
      type_key: 'azure_waf',
      display_name: 'Azure WAF',
      version: '1.0.0',
      flavor: 'pull' as const,
      config_schema: { type: 'object', properties: {} },
    }

    render(
      <SourceCard
        source={wafSource}
        serverHealth="amber"
        serverHealthItem={healthItem}
      />,
    )

    // Trigger the HealthCard by focusing the health dot trigger
    await waitFor(() => {
      expect(screen.getByTestId('health-item-azure_waf')).toBeInTheDocument()
    })

    const trigger = screen.getByTestId('health-dot-trigger-azure_waf')
    act(() => { fireEvent.focus(trigger) })

    // The HealthCard popover must be visible with real data
    await waitFor(() => {
      expect(screen.getByTestId('health-card-single')).toBeInTheDocument()
    })

    // "Events" must show 269 (the real count from /stats), NOT 0 or "—"
    const countEl = screen.getByTestId('health-card-event-count')
    expect(countEl.textContent).not.toBe('—')
    expect(countEl.textContent).toContain('269')

    // "Last event" must show a formatted time, NOT "—" or "Never"
    const timeEl = screen.getByTestId('health-card-last-event')
    expect(timeEl.textContent).not.toBe('—')
    expect(timeEl.textContent).not.toBe('Never')
  })

  it('shows "—" for Last event and "—" for Events when serverHealthItem is null (no stats data)', async () => {
    const wafSource = {
      type_key: 'azure_waf',
      display_name: 'Azure WAF',
      version: '1.0.0',
      flavor: 'pull' as const,
      config_schema: { type: 'object', properties: {} },
    }

    // No serverHealthItem — stats fetch pending or unavailable
    render(<SourceCard source={wafSource} serverHealth={null} serverHealthItem={null} />)

    await waitFor(() => {
      expect(screen.getByTestId('health-item-azure_waf')).toBeInTheDocument()
    })

    const trigger = screen.getByTestId('health-dot-trigger-azure_waf')
    act(() => { fireEvent.focus(trigger) })

    await waitFor(() => {
      expect(screen.getByTestId('health-card-single')).toBeInTheDocument()
    })

    // Both should show "—" (graceful fallback, no crash, no false "0 events")
    const timeEl = screen.getByTestId('health-card-last-event')
    expect(timeEl.textContent).toBe('—')

    const countEl = screen.getByTestId('health-card-event-count')
    expect(countEl.textContent).toBe('—')
  })

  it('recency caption uses last_event_at from serverHealthItem when last_success_at is epoch', async () => {
    // Source has epoch last_success_at (the bug case) but serverHealthItem has recent last_event_at
    const elevenMinutesAgo = new Date(Date.now() - 11 * 60 * 1000).toISOString()

    const healthItem: SourceHealthItem = {
      id: 'azure_waf',
      label: 'Azure WAF',
      health: 'amber',
      supervisorState: null,
      lastEventAt: elevenMinutesAgo,
      lastError: null,
      eventCount: 269,
      sourceType: 'azure_waf',
    }

    // Return a source instance with epoch last_success_at (isActive=true so "Stale" is reachable)
    mockFetchSources.mockResolvedValue([
      {
        source_id: 'azure_waf',
        source_type: 'azure_waf',
        state: 'idle',
        last_success_at: '1970-01-01T00:00:00Z', // epoch — pre-bug would cause "never"
        last_error: null,
        auto_sync_enabled: true, // ADR-0062 Amendment 1: isActive=true so "Stale" is reachable
      },
    ])

    const wafSource = {
      type_key: 'azure_waf',
      display_name: 'Azure WAF',
      version: '1.0.0',
      flavor: 'pull' as const,
      config_schema: { type: 'object', properties: {} },
    }

    render(
      <SourceCard
        source={wafSource}
        serverHealth="amber"
        serverHealthItem={healthItem}
      />,
    )

    // The status text (recency caption) should use last_event_at (11m ago), NOT epoch
    await waitFor(() => {
      const card = screen.getByTestId('source-card-azure_waf')
      // Must show "11m ago" (from last_event_at), not "never" (from epoch last_success_at)
      expect(card.textContent).toContain('11m ago')
      expect(card.textContent).not.toContain('never')
    })
  })
})
