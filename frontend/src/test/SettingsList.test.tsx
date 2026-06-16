/**
 * Tests for src/components/SettingsList.tsx
 *
 * EARS criteria covered (issue #488 R3 + M-0):
 *   - State-driven: while no source package is installed, FirstRunPanel renders
 *     (not the old dead-end "no sources" message).
 *   - Event-driven: WHEN no sources installed → first-run panel contains:
 *       - "what is a source" explainer
 *       - copyable install command with a copy button
 *       - "installed sources appear below automatically" line
 *       - "one instance per source today, multi-instance coming" line
 *       - "nothing leaves this machine / local-first" line
 *   - Unwanted: IF clipboard write fails, the install command remains selectable
 *     as plain text (the code element stays in the DOM).
 *   - Ubiquitous (instance labeling): each source card wrapper SHALL show an
 *     instance label in the form "Display Name · default" (ADR-0035 honest labeling).
 *   - State-driven: installed source → card is present in the DOM.
 *   - Loading and error states rendered correctly.
 *
 * These tests use a mock for the API client so SourceCard's fetch does not fire.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import SettingsList from '../components/SettingsList'
import type { SourceTypeEntry } from '../schema/types'
import { SURICATA_SOURCE_ENTRY, MINIMAL_SOURCE_ENTRY } from './fixtures'

// Mock the API client so SourceCard doesn't attempt real fetches.
// importOriginal spreads the real module so helpers like resolveBaseUrl and
// assertLoopbackBase (used by sources.ts after fix #81) are available without
// being explicitly listed in every test mock.
vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    fetchSourceConfig: vi.fn().mockResolvedValue({}),
    putSourceConfig: vi.fn().mockResolvedValue(undefined),
    fetchSourceTypes: vi.fn().mockResolvedValue([]),
  }
})

// Mock api/sources so SettingsList's fetchSources call (for active-first sort,
// ADR-0062 §A) is controlled. Also mocks SourceCard's fetchSources call.
vi.mock('../api/sources', () => ({
  fetchSources: vi.fn().mockResolvedValue([]),
  getAutoSync: vi.fn().mockResolvedValue({
    enabled: false,
    interval_seconds: 300,
    source_id: '',
    last_sync: { last_sync_at: null, last_sync_ingested: 0, last_sync_status: null, last_error: null },
  }),
  setAutoSync: vi.fn(),
  syncSource: vi.fn(),
  testSource: vi.fn(),
}))

describe('SettingsList', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  // ---------------------------------------------------------------------------
  // Loading / error states (unchanged from pre-#488)
  // ---------------------------------------------------------------------------

  it('shows loading indicator while loading', () => {
    render(<SettingsList sources={[]} loading={true} error={null} />)
    expect(screen.getByRole('status')).toHaveTextContent('Loading')
    expect(screen.queryByTestId('first-run-panel')).not.toBeInTheDocument()
  })

  it('shows error message when discovery fails', () => {
    render(<SettingsList sources={[]} loading={false} error="Discovery failed: 503" />)
    expect(screen.getByRole('alert')).toHaveTextContent('Discovery failed: 503')
  })

  // ---------------------------------------------------------------------------
  // EARS #488: First-run panel (empty state)
  // ---------------------------------------------------------------------------

  it('renders the first-run panel when no sources are installed', () => {
    render(<SettingsList sources={[]} loading={false} error={null} />)
    expect(screen.getByTestId('first-run-panel')).toBeInTheDocument()
    // Old dead-end message must be gone
    expect(screen.queryByTestId('no-sources')).not.toBeInTheDocument()
  })

  it('first-run panel contains a "what is a source" explainer', () => {
    render(<SettingsList sources={[]} loading={false} error={null} />)
    expect(screen.getByTestId('first-run-panel')).toHaveTextContent('What is a source?')
    // The panel should explain that a source is a plugin
    expect(screen.getByTestId('first-run-panel')).toHaveTextContent(/plugin/i)
  })

  it('first-run panel shows the install command as copyable text', () => {
    render(<SettingsList sources={[]} loading={false} error={null} />)
    const cmd = screen.getByTestId('install-command')
    expect(cmd).toBeInTheDocument()
    // Must be plain text — selectable if clipboard fails (EARS unwanted)
    expect(cmd.tagName).toBe('CODE')
    expect(cmd).toHaveTextContent('pip install firewatch-source-')
  })

  it('first-run panel has a copy button that announces success', async () => {
    const writeTextMock = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: writeTextMock },
      configurable: true,
    })

    render(<SettingsList sources={[]} loading={false} error={null} />)
    const copyBtn = screen.getByTestId('copy-install-cmd')
    expect(copyBtn).toBeInTheDocument()

    fireEvent.click(copyBtn)
    await waitFor(() => {
      expect(writeTextMock).toHaveBeenCalled()
    })
    // "Copied!" label appears on button
    await waitFor(() => {
      expect(screen.getByTestId('copy-install-cmd')).toHaveTextContent('Copied!')
    })
    // Accessible announcement
    expect(screen.getByTestId('copy-announcement')).toHaveTextContent(
      /copied to clipboard/i,
    )
  })

  it('install command stays in DOM when clipboard write fails (EARS unwanted)', async () => {
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: vi.fn().mockRejectedValue(new Error('permission denied')) },
      configurable: true,
    })

    render(<SettingsList sources={[]} loading={false} error={null} />)
    const copyBtn = screen.getByTestId('copy-install-cmd')
    fireEvent.click(copyBtn)

    // Even after failure the command is still in the DOM and selectable
    await waitFor(() => {
      expect(screen.getByTestId('install-command')).toBeInTheDocument()
    })
    // Button should NOT show "Copied!" on failure
    expect(screen.getByTestId('copy-install-cmd')).toHaveTextContent('Copy')
  })

  it('first-run panel states that installed sources appear automatically', () => {
    render(<SettingsList sources={[]} loading={false} error={null} />)
    expect(screen.getByTestId('auto-appear-notice')).toHaveTextContent(
      /appear below automatically/i,
    )
  })

  it('first-run panel states one instance per source today and multi-instance coming', () => {
    render(<SettingsList sources={[]} loading={false} error={null} />)
    const notice = screen.getByTestId('single-instance-notice')
    expect(notice).toHaveTextContent(/one instance per source/i)
    expect(notice).toHaveTextContent(/coming/i)
  })

  it('first-run panel states that nothing leaves the device (local-first)', () => {
    render(<SettingsList sources={[]} loading={false} error={null} />)
    expect(screen.getByTestId('local-first-notice')).toHaveTextContent(
      /nothing leaves the device/i,
    )
  })

  // ---------------------------------------------------------------------------
  // EARS #488: Installed sources → grid + instance labeling
  // ---------------------------------------------------------------------------

  it('renders a SourceCard for each installed source', () => {
    const sources: SourceTypeEntry[] = [SURICATA_SOURCE_ENTRY]
    render(<SettingsList sources={sources} loading={false} error={null} />)
    expect(screen.getByTestId('settings-list')).toBeInTheDocument()
    expect(screen.getByTestId('source-card-suricata')).toBeInTheDocument()
  })

  it('renders one card per source when multiple sources are installed', () => {
    const sources: SourceTypeEntry[] = [SURICATA_SOURCE_ENTRY, MINIMAL_SOURCE_ENTRY]
    render(<SettingsList sources={sources} loading={false} error={null} />)
    expect(screen.getByTestId('source-card-suricata')).toBeInTheDocument()
    expect(screen.getByTestId('source-card-test_source')).toBeInTheDocument()
  })

  it('does not render a card for a source not in the discovery list', () => {
    const sources: SourceTypeEntry[] = [MINIMAL_SOURCE_ENTRY]
    render(<SettingsList sources={sources} loading={false} error={null} />)
    // suricata was "uninstalled" — not in sources
    expect(screen.queryByTestId('source-card-suricata')).not.toBeInTheDocument()
    expect(screen.getByTestId('source-card-test_source')).toBeInTheDocument()
  })

  // ADR-0062 §C / ADR-0035 honest instance labeling (M-0 slice of #488)
  // The label now shows the real source_id (not the old "default" placeholder).
  // When no instance is active, source_id defaults to type_key per ADR-0031 §B.
  it('each source card wrapper shows the display name and type_key as source_id (ADR-0062 §C)', () => {
    const sources: SourceTypeEntry[] = [SURICATA_SOURCE_ENTRY]
    render(<SettingsList sources={sources} loading={false} error={null} />)
    const label = screen.getByTestId('instance-label-suricata')
    expect(label).toBeInTheDocument()
    // Contains the display name
    expect(label).toHaveTextContent('Suricata IDS/IPS')
    // ADR-0062 §C: shows real source_id; without active instance, defaults to type_key
    expect(label).toHaveTextContent('suricata')
    // Must NOT show the old "default" placeholder
    expect(label).not.toHaveTextContent('default')
  })

  it('renders an instance label for every installed source', () => {
    const sources: SourceTypeEntry[] = [SURICATA_SOURCE_ENTRY, MINIMAL_SOURCE_ENTRY]
    render(<SettingsList sources={sources} loading={false} error={null} />)
    expect(screen.getByTestId('instance-label-suricata')).toBeInTheDocument()
    expect(screen.getByTestId('instance-label-test_source')).toBeInTheDocument()
  })
})
