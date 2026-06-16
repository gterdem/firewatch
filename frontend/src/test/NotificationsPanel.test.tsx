/**
 * Tests for NotificationsPanel and its sub-components (issue #661, ADR-0059 D3/D4).
 *
 * EARS criteria covered:
 *   Threshold (NotificationThresholdField):
 *   - Rendered: "Notification threshold" label present (NOT "Alert threshold").
 *   - Rendered: subtitle "Send to Discord / Slack / webhook at or above this severity." present.
 *   - State-driven: GET /config/runtime populates threshold.
 *   - Event-driven: threshold change → PUT /config/runtime called with alert_threshold.
 *   - Event-driven: threshold change success → success toast shown.
 *   - Event-driven: threshold change failure → error toast shown.
 *   - State-driven: GET fails → default CRITICAL (no crash).
 *
 *   Webhook (WebhookField):
 *   - Rendered: webhook URL input + Save button present.
 *   - State-driven: webhook_url_set=true → placeholder shows "•••• set — type to replace".
 *   - State-driven: webhook_url_set=false → placeholder shows default hint.
 *   - Constraint (ADR-0006): secret value never echoed; input value always empty.
 *   - Event-driven: Save → PUT /config/runtime called with webhook_url.
 *   - Event-driven: Save success → "Webhook URL saved" toast.
 *   - Event-driven: Save 422 → error toast with sanitized message.
 *   - Event-driven: Save with empty value → PUT with null (clears webhook).
 *
 *   alert_on_sync (WebhookField):
 *   - Rendered: "Notify me when a scheduled pull is blocked" checkbox present.
 *   - State-driven: GET /config/runtime populates alert_on_sync.
 *   - Event-driven: toggle → PUT /config/runtime called with alert_on_sync.
 *   - Event-driven: toggle success → success toast.
 *   - Event-driven: toggle failure → error toast + checkbox rolled back.
 *
 *   NotifyOnAutoEscalateToggle (ADR-0059 D3):
 *   - Rendered: "Also notify on auto-escalating detections" toggle present.
 *   - State-driven: default OFF when GET fails (safe default).
 *   - State-driven: GET /config/runtime populates notify_on_auto_escalate.
 *   - Event-driven: toggle → PUT /config/runtime called with notify_on_auto_escalate.
 *   - Event-driven: toggle success → success toast.
 *   - Event-driven: toggle failure → error toast + toggle rolled back.
 *   - Round-trip: GET sets value false; toggle ON → PUT called with true.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import NotificationsPanel from '../components/notifications/NotificationsPanel'

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const { mockPutRuntimeConfig, mockGetRuntimeConfig } = vi.hoisted(() => ({
  mockPutRuntimeConfig: vi.fn(),
  mockGetRuntimeConfig: vi.fn(),
}))

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    putRuntimeConfig: mockPutRuntimeConfig,
    getRuntimeConfig: mockGetRuntimeConfig,
  }
})

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** Typical GET /config/runtime response for notifications. */
const RUNTIME_CONFIG_BASE = {
  alert_threshold: 'CRITICAL' as const,
  alert_on_sync: true,
  webhook_url: null,
  webhook_url_set: false,
  api_key_set: false,
  ollama_model: 'qwen3:14b',
  ai_enabled: true,
  ollama_base_url: 'http://localhost:11434',
  geo_provider: 'offline' as const,
  notify_on_auto_escalate: false,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderPanel() {
  return render(<NotificationsPanel />)
}

// ---------------------------------------------------------------------------
// Tests — card renders with correct structure
// ---------------------------------------------------------------------------

describe('NotificationsPanel — structure', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockPutRuntimeConfig.mockResolvedValue(undefined)
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_BASE)
  })

  it('renders the Notifications panel heading', async () => {
    renderPanel()
    await waitFor(() => {
      const heading = screen.getByRole('heading', { level: 2 })
      expect(heading.textContent).toContain('Notifications')
    })
  })

  it('renders the Alerts section group', async () => {
    renderPanel()
    await waitFor(() => {
      expect(screen.getByTestId('section-notifications-alerts')).toBeInTheDocument()
    })
  })

  it('renders the Escalation section group', async () => {
    renderPanel()
    await waitFor(() => {
      expect(screen.getByTestId('section-notifications-escalation')).toBeInTheDocument()
    })
  })
})

// ---------------------------------------------------------------------------
// Tests — NotificationThresholdField (relabelled alert_threshold)
// ---------------------------------------------------------------------------

describe('NotificationsPanel — NotificationThresholdField', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockPutRuntimeConfig.mockResolvedValue(undefined)
  })

  // EARS: label must read "Notification threshold" (NOT "Alert threshold")
  it('renders "Notification threshold" label (not "Alert threshold")', async () => {
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_BASE)
    renderPanel()
    await waitFor(() => {
      expect(screen.getByText('Notification threshold')).toBeInTheDocument()
      expect(screen.queryByText('Alert threshold')).not.toBeInTheDocument()
    })
  })

  // EARS: subtitle must be the exact required text
  it('renders the required subtitle for notification threshold', async () => {
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_BASE)
    renderPanel()
    await waitFor(() => {
      expect(
        screen.getByText('Send to Discord / Slack / webhook at or above this severity.'),
      ).toBeInTheDocument()
    })
  })

  // State-driven: GET /config/runtime populates threshold
  it('populates threshold from GET /config/runtime on mount', async () => {
    mockGetRuntimeConfig.mockResolvedValue({ ...RUNTIME_CONFIG_BASE, alert_threshold: 'HIGH' })
    renderPanel()
    await waitFor(() => {
      const select = screen.getByTestId('notification-threshold-select') as HTMLSelectElement
      expect(select.value).toBe('HIGH')
    })
  })

  // State-driven: GET fails → defaults to CRITICAL (no crash)
  it('defaults to CRITICAL when getRuntimeConfig fails', async () => {
    const { ApiError } = await import('../api/client')
    mockGetRuntimeConfig.mockRejectedValue(new ApiError(503, null, 'Service Unavailable'))
    renderPanel()
    await waitFor(() => {
      const select = screen.getByTestId('notification-threshold-select') as HTMLSelectElement
      expect(select).toBeInTheDocument()
      expect(select.value).toBe('CRITICAL')
    })
  })

  // Event-driven: threshold change → PUT /config/runtime called with alert_threshold
  it('calls putRuntimeConfig with alert_threshold when threshold changes', async () => {
    const user = userEvent.setup()
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_BASE)
    renderPanel()

    const select = await screen.findByTestId('notification-threshold-select')
    await user.selectOptions(select, 'LOW')

    await waitFor(() => {
      expect(mockPutRuntimeConfig).toHaveBeenCalledWith({ alert_threshold: 'LOW' })
    })
  })

  // Event-driven: success → toast shown
  it('shows success toast after threshold change', async () => {
    const user = userEvent.setup()
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_BASE)
    renderPanel()

    const select = await screen.findByTestId('notification-threshold-select')
    await user.selectOptions(select, 'MEDIUM')

    await waitFor(() => {
      const toast = screen.getByRole('status')
      expect(toast.textContent).toContain('MEDIUM')
    })
  })

  // Event-driven: failure → error toast
  it('shows error toast when threshold PUT fails', async () => {
    const user = userEvent.setup()
    const { ApiError } = await import('../api/client')
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_BASE)
    mockPutRuntimeConfig.mockRejectedValue(new ApiError(422, [{ msg: 'Invalid threshold' }]))
    renderPanel()

    const select = await screen.findByTestId('notification-threshold-select')
    await user.selectOptions(select, 'LOW')

    await waitFor(() => {
      const toast = screen.getByRole('status')
      expect(toast.textContent).toContain('Invalid threshold')
    })
  })
})

// ---------------------------------------------------------------------------
// Tests — WebhookField (webhook_url + alert_on_sync)
// ---------------------------------------------------------------------------

describe('NotificationsPanel — WebhookField', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockPutRuntimeConfig.mockResolvedValue(undefined)
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_BASE)
  })

  // Rendered: webhook URL input present
  it('renders webhook URL input', async () => {
    renderPanel()
    await waitFor(() => {
      expect(screen.getByTestId('webhook-url-input')).toBeInTheDocument()
    })
  })

  // Rendered: Save button present
  it('renders webhook Save button', async () => {
    renderPanel()
    await waitFor(() => {
      expect(screen.getByTestId('webhook-url-save')).toBeInTheDocument()
    })
  })

  // State-driven: webhook_url_set=true → "•••• set — type to replace" placeholder
  it('shows masked "set" placeholder when webhook_url_set=true', async () => {
    mockGetRuntimeConfig.mockResolvedValue({
      ...RUNTIME_CONFIG_BASE,
      webhook_url: null,
      webhook_url_set: true,
    })
    renderPanel()
    const input = (await screen.findByTestId('webhook-url-input')) as HTMLInputElement
    expect(input.placeholder).toContain('set — type to replace')
  })

  // State-driven: webhook_url_set=false → default hint placeholder
  it('shows default placeholder when webhook_url_set=false', async () => {
    mockGetRuntimeConfig.mockResolvedValue({
      ...RUNTIME_CONFIG_BASE,
      webhook_url: null,
      webhook_url_set: false,
    })
    renderPanel()
    const input = (await screen.findByTestId('webhook-url-input')) as HTMLInputElement
    expect(input.placeholder).not.toContain('set — type to replace')
    expect(input.placeholder).toContain('https://hooks.slack.com/')
  })

  // Constraint (ADR-0006): secret value never echoed — input value always empty
  it('never prefills the input with a secret value; input value always empty', async () => {
    mockGetRuntimeConfig.mockResolvedValue({
      ...RUNTIME_CONFIG_BASE,
      webhook_url: null,
      webhook_url_set: true,
    })
    renderPanel()
    const input = (await screen.findByTestId('webhook-url-input')) as HTMLInputElement
    expect(input.value).toBe('')
  })

  // Ubiquitous (ADR-0006): webhookIsSet derived from server flag across sessions
  it('shows set state from server flag across sessions (no PUT required)', async () => {
    mockGetRuntimeConfig.mockResolvedValue({
      ...RUNTIME_CONFIG_BASE,
      webhook_url: null,
      webhook_url_set: true,
    })
    renderPanel()
    const input = (await screen.findByTestId('webhook-url-input')) as HTMLInputElement
    expect(input.placeholder).toContain('set — type to replace')
    expect(mockPutRuntimeConfig).not.toHaveBeenCalled()
  })

  // Event-driven: Save → PUT /config/runtime called with webhook_url
  it('calls putRuntimeConfig with webhook_url when Save is clicked', async () => {
    const user = userEvent.setup()
    renderPanel()

    const input = await screen.findByTestId('webhook-url-input')
    await user.type(input, 'https://hooks.slack.com/abc')

    const saveBtn = screen.getByTestId('webhook-url-save')
    await user.click(saveBtn)

    await waitFor(() => {
      expect(mockPutRuntimeConfig).toHaveBeenCalledWith({
        webhook_url: 'https://hooks.slack.com/abc',
      })
    })
  })

  // Event-driven: Save success → "Webhook URL saved" toast
  it('shows "Webhook URL saved" toast after successful save', async () => {
    const user = userEvent.setup()
    renderPanel()

    const input = await screen.findByTestId('webhook-url-input')
    await user.type(input, 'https://hooks.slack.com/abc')

    await user.click(screen.getByTestId('webhook-url-save'))

    await waitFor(() => {
      const toast = screen.getByRole('status')
      expect(toast.textContent).toContain('Webhook URL saved')
    })
  })

  // Event-driven: 422 → error toast with sanitized message
  it('surfaces 422 anti-SSRF error from Pydantic detail array', async () => {
    const user = userEvent.setup()
    const { ApiError } = await import('../api/client')
    mockPutRuntimeConfig.mockRejectedValue(
      new ApiError(422, [
        {
          msg: "webhook_url host 'localhost' is blocked (anti-SSRF, ADR-0026).",
          type: 'value_error',
        },
      ]),
    )
    renderPanel()

    const input = await screen.findByTestId('webhook-url-input')
    await user.type(input, 'http://localhost/hook')
    await user.click(screen.getByTestId('webhook-url-save'))

    await waitFor(() => {
      const toast = screen.getByRole('status')
      expect(toast.textContent).toContain('anti-SSRF')
    })
  })

  // Event-driven: Save with empty field → PUT with null (clears webhook)
  it('sends null when Save is clicked with empty URL field', async () => {
    const user = userEvent.setup()
    renderPanel()

    await waitFor(() => expect(screen.getByTestId('webhook-url-save')).toBeInTheDocument())
    await user.click(screen.getByTestId('webhook-url-save'))

    await waitFor(() => {
      expect(mockPutRuntimeConfig).toHaveBeenCalledWith({ webhook_url: null })
    })
  })

  // Rendered: alert_on_sync checkbox with plain-language label
  it('renders "Notify me when a scheduled pull is blocked" checkbox', async () => {
    renderPanel()
    await waitFor(() => {
      expect(screen.getByTestId('alert-on-sync-blocks')).toBeInTheDocument()
      expect(
        screen.getByText(/Notify me when a scheduled pull is blocked/i),
      ).toBeInTheDocument()
    })
  })

  // State-driven: GET populates alert_on_sync (false)
  it('populates alert_on_sync checkbox from GET /config/runtime', async () => {
    mockGetRuntimeConfig.mockResolvedValue({ ...RUNTIME_CONFIG_BASE, alert_on_sync: false })
    renderPanel()
    await waitFor(() => {
      const cb = screen.getByTestId('alert-on-sync-blocks') as HTMLInputElement
      expect(cb.checked).toBe(false)
    })
  })

  // Event-driven: toggle → PUT called with alert_on_sync
  it('calls putRuntimeConfig with alert_on_sync on checkbox toggle', async () => {
    const user = userEvent.setup()
    mockGetRuntimeConfig.mockResolvedValue({ ...RUNTIME_CONFIG_BASE, alert_on_sync: false })
    renderPanel()

    const cb = await screen.findByTestId('alert-on-sync-blocks')
    await user.click(cb)

    await waitFor(() => {
      expect(mockPutRuntimeConfig).toHaveBeenCalledWith({ alert_on_sync: true })
    })
  })

  // Event-driven: toggle success → toast shown
  it('shows success toast after alert_on_sync toggle', async () => {
    const user = userEvent.setup()
    mockGetRuntimeConfig.mockResolvedValue({ ...RUNTIME_CONFIG_BASE, alert_on_sync: false })
    renderPanel()

    const cb = await screen.findByTestId('alert-on-sync-blocks')
    await user.click(cb)

    await waitFor(() => {
      const toast = screen.getByRole('status')
      expect(toast.textContent).toContain('enabled')
    })
  })

  // Event-driven: toggle failure → error toast + checkbox rolled back
  it('rolls back checkbox and shows error toast when alert_on_sync PUT fails', async () => {
    const user = userEvent.setup()
    const { ApiError } = await import('../api/client')
    mockGetRuntimeConfig.mockResolvedValue({ ...RUNTIME_CONFIG_BASE, alert_on_sync: true })
    mockPutRuntimeConfig.mockRejectedValue(new ApiError(500, null, 'Server error'))
    renderPanel()

    await waitFor(() => {
      const cb = screen.getByTestId('alert-on-sync-blocks') as HTMLInputElement
      expect(cb.checked).toBe(true)
    })

    const cb = screen.getByTestId('alert-on-sync-blocks')
    await user.click(cb)

    await waitFor(() => {
      const toast = screen.getByRole('status')
      expect(toast.textContent).toContain('Save failed')
    })

    await waitFor(() => {
      const cbAfter = screen.getByTestId('alert-on-sync-blocks') as HTMLInputElement
      expect(cbAfter.checked).toBe(true)
    })
  })
})

// ---------------------------------------------------------------------------
// Tests — NotifyOnAutoEscalateToggle (ADR-0059 D3)
// ---------------------------------------------------------------------------

describe('NotificationsPanel — NotifyOnAutoEscalateToggle', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockPutRuntimeConfig.mockResolvedValue(undefined)
  })

  // Rendered: toggle present with required label
  it('renders "Also notify on auto-escalating detections" toggle', async () => {
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_BASE)
    renderPanel()
    await waitFor(() => {
      expect(screen.getByTestId('notify-on-auto-escalate-toggle')).toBeInTheDocument()
      expect(
        screen.getByText(/Also notify on auto-escalating detections/i),
      ).toBeInTheDocument()
    })
  })

  // State-driven: default OFF — when GET fails, toggle defaults to false
  it('defaults to OFF (unchecked) when getRuntimeConfig fails', async () => {
    const { ApiError } = await import('../api/client')
    mockGetRuntimeConfig.mockRejectedValue(new ApiError(503, null, 'Service Unavailable'))
    renderPanel()
    await waitFor(() => {
      const toggle = screen.getByTestId('notify-on-auto-escalate-toggle') as HTMLInputElement
      expect(toggle).toBeInTheDocument()
      expect(toggle.checked).toBe(false)
    })
  })

  // State-driven: GET populates notify_on_auto_escalate=false → unchecked
  it('renders toggle as unchecked when config returns notify_on_auto_escalate=false', async () => {
    mockGetRuntimeConfig.mockResolvedValue({
      ...RUNTIME_CONFIG_BASE,
      notify_on_auto_escalate: false,
    })
    renderPanel()
    await waitFor(() => {
      const toggle = screen.getByTestId('notify-on-auto-escalate-toggle') as HTMLInputElement
      expect(toggle.checked).toBe(false)
    })
  })

  // State-driven: GET populates notify_on_auto_escalate=true → checked
  it('renders toggle as checked when config returns notify_on_auto_escalate=true', async () => {
    mockGetRuntimeConfig.mockResolvedValue({
      ...RUNTIME_CONFIG_BASE,
      notify_on_auto_escalate: true,
    })
    renderPanel()
    await waitFor(() => {
      const toggle = screen.getByTestId('notify-on-auto-escalate-toggle') as HTMLInputElement
      expect(toggle.checked).toBe(true)
    })
  })

  // Round-trip: GET sets value false; toggle ON → PUT called with true
  it('round-trips: GET=false, toggle → PUT with notify_on_auto_escalate=true', async () => {
    const user = userEvent.setup()
    mockGetRuntimeConfig.mockResolvedValue({
      ...RUNTIME_CONFIG_BASE,
      notify_on_auto_escalate: false,
    })
    renderPanel()

    await waitFor(() => {
      const toggle = screen.getByTestId('notify-on-auto-escalate-toggle') as HTMLInputElement
      expect(toggle.checked).toBe(false)
    })

    const toggle = screen.getByTestId('notify-on-auto-escalate-toggle')
    await user.click(toggle)

    await waitFor(() => {
      expect(mockPutRuntimeConfig).toHaveBeenCalledWith({ notify_on_auto_escalate: true })
    })
  })

  // Event-driven: toggle ON→ success toast
  it('shows success toast after enabling notify_on_auto_escalate', async () => {
    const user = userEvent.setup()
    mockGetRuntimeConfig.mockResolvedValue({
      ...RUNTIME_CONFIG_BASE,
      notify_on_auto_escalate: false,
    })
    renderPanel()

    const toggle = await screen.findByTestId('notify-on-auto-escalate-toggle')
    await user.click(toggle)

    await waitFor(() => {
      const toast = screen.getByRole('status')
      expect(toast.textContent).toContain('enabled')
    })
  })

  // Event-driven: toggle OFF → success toast
  it('shows success toast after disabling notify_on_auto_escalate', async () => {
    const user = userEvent.setup()
    mockGetRuntimeConfig.mockResolvedValue({
      ...RUNTIME_CONFIG_BASE,
      notify_on_auto_escalate: true,
    })
    renderPanel()

    const toggle = await screen.findByTestId('notify-on-auto-escalate-toggle')
    await user.click(toggle)

    await waitFor(() => {
      const toast = screen.getByRole('status')
      expect(toast.textContent).toContain('disabled')
    })
  })

  // Event-driven: failure → error toast + toggle rolled back
  it('rolls back toggle and shows error toast when PUT fails', async () => {
    const user = userEvent.setup()
    const { ApiError } = await import('../api/client')
    mockGetRuntimeConfig.mockResolvedValue({
      ...RUNTIME_CONFIG_BASE,
      notify_on_auto_escalate: false,
    })
    mockPutRuntimeConfig.mockRejectedValue(new ApiError(500, null, 'Server error'))
    renderPanel()

    await waitFor(() => {
      const toggle = screen.getByTestId('notify-on-auto-escalate-toggle') as HTMLInputElement
      expect(toggle.checked).toBe(false)
    })

    const toggle = screen.getByTestId('notify-on-auto-escalate-toggle')
    await user.click(toggle)

    await waitFor(() => {
      const toast = screen.getByRole('status')
      expect(toast.textContent).toContain('Save failed')
    })

    await waitFor(() => {
      const toggleAfter = screen.getByTestId(
        'notify-on-auto-escalate-toggle',
      ) as HTMLInputElement
      expect(toggleAfter.checked).toBe(false)
    })
  })

  // Subtitle explains the behaviour when ON vs OFF
  it('renders subtitle text explaining the toggle behaviour', async () => {
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_BASE)
    renderPanel()
    await waitFor(() => {
      const escalationSection = screen.getByTestId('section-notifications-escalation')
      expect(escalationSection.textContent).toContain('Notification threshold band')
    })
  })
})
