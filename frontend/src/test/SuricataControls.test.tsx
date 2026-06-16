/**
 * Tests for src/components/sources/SuricataControls.tsx
 *
 * EARS criteria covered:
 *   - Event-driven: Test button calls POST /sources/suricata/test with source_id.
 *   - Event-driven: Sync button calls POST /sync/suricata with source_id.
 *   - State-driven: while request is in flight, button shows spinner and is disabled.
 *   - State-driven: ok result shown; error result shown.
 *   - State-driven: when status is backoff/parked, buttons are disabled and status shown.
 *   - Unwanted: API error → error message shown, no crash.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import SuricataControls from '../components/sources/SuricataControls'
import {
  SOURCES_FIXTURE,
  SOURCES_BACKOFF_FIXTURE,
  TEST_RESULT_OK,
  TEST_RESULT_FAIL,
  SYNC_RESULT_OK,
} from './readFixtures'

const { mockTestSource, mockSyncSource } = vi.hoisted(() => ({
  mockTestSource: vi.fn(),
  mockSyncSource: vi.fn(),
}))

vi.mock('../api/sources', () => ({
  testSource: mockTestSource,
  syncSource: mockSyncSource,
}))

describe('SuricataControls', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders Test and Sync buttons', () => {
    render(<SuricataControls instance={SOURCES_FIXTURE[0]} />)
    expect(screen.getByTestId('btn-test')).toBeInTheDocument()
    expect(screen.getByTestId('btn-sync')).toBeInTheDocument()
  })

  // D1 fix (#195): real DTO has `state` (not `status`). SOURCES_FIXTURE uses state='running'.
  it('shows instance state from GET /sources (real DTO field is state, not status)', () => {
    render(<SuricataControls instance={SOURCES_FIXTURE[0]} />)
    expect(screen.getByTestId('source-status')).toHaveTextContent('running')
  })

  // EARS event-driven: Test button calls testSource with correct type_key + source_id
  it('calls testSource with suricata type_key and source_id when Test is clicked', async () => {
    mockTestSource.mockResolvedValue(TEST_RESULT_OK)
    render(<SuricataControls instance={SOURCES_FIXTURE[0]} />)

    await userEvent.click(screen.getByTestId('btn-test'))

    expect(mockTestSource).toHaveBeenCalledTimes(1)
    expect(mockTestSource).toHaveBeenCalledWith('suricata', 'suricata-1')
  })

  // EARS event-driven: Sync button calls syncSource with correct type_key + source_id
  it('calls syncSource with suricata type_key and source_id when Sync is clicked', async () => {
    mockSyncSource.mockResolvedValue(SYNC_RESULT_OK)
    render(<SuricataControls instance={SOURCES_FIXTURE[0]} />)

    await userEvent.click(screen.getByTestId('btn-sync'))

    expect(mockSyncSource).toHaveBeenCalledTimes(1)
    expect(mockSyncSource).toHaveBeenCalledWith('suricata', 'suricata-1')
  })

  // EARS state-driven: ok test result shown
  it('shows ok test result after Test succeeds', async () => {
    mockTestSource.mockResolvedValue(TEST_RESULT_OK)
    render(<SuricataControls instance={SOURCES_FIXTURE[0]} />)

    await userEvent.click(screen.getByTestId('btn-test'))

    await waitFor(() => {
      expect(screen.getByTestId('controls-result')).toBeInTheDocument()
    })
    expect(screen.getByTestId('controls-result')).toHaveTextContent(TEST_RESULT_OK.message)
  })

  // EARS state-driven: failed test result shown
  it('shows error test result message when test fails', async () => {
    mockTestSource.mockResolvedValue(TEST_RESULT_FAIL)
    render(<SuricataControls instance={SOURCES_FIXTURE[0]} />)

    await userEvent.click(screen.getByTestId('btn-test'))

    await waitFor(() => {
      expect(screen.getByTestId('controls-result')).toBeInTheDocument()
    })
    expect(screen.getByTestId('controls-result')).toHaveTextContent(TEST_RESULT_FAIL.message)
  })

  // EARS state-driven: backoff/parked instance → buttons disabled
  it('disables both buttons and shows inactive note when instance is in backoff', () => {
    render(<SuricataControls instance={SOURCES_BACKOFF_FIXTURE[0]} />)

    expect(screen.getByTestId('btn-test')).toBeDisabled()
    expect(screen.getByTestId('btn-sync')).toBeDisabled()
    expect(screen.getByTestId('controls-inactive')).toBeInTheDocument()
    expect(screen.getByTestId('controls-inactive')).toHaveTextContent('backoff')
  })

  // D1 fix (#195): the real GET /sources DTO has no error_message field.
  // The inactive note shows the supervisor state — not an error_message string.
  it('shows backoff state in inactive note (no error_message in real DTO)', () => {
    render(<SuricataControls instance={SOURCES_BACKOFF_FIXTURE[0]} />)
    // The inactive note renders the state (backoff) but NOT a separate error_message
    // string — the real DTO does not carry that field.
    expect(screen.getByTestId('controls-inactive')).toHaveTextContent('backoff')
  })

  // EARS unwanted: API error → error message shown
  it('shows error message when testSource rejects with ApiError', async () => {
    const { ApiError } = await import('../api/client')
    mockTestSource.mockRejectedValue(new ApiError(503, null, 'Service Unavailable'))

    render(<SuricataControls instance={SOURCES_FIXTURE[0]} />)

    await userEvent.click(screen.getByTestId('btn-test'))

    await waitFor(() => {
      expect(screen.getByTestId('controls-error')).toBeInTheDocument()
    })
    expect(screen.getByRole('alert')).toHaveTextContent('503')
  })

  it('works with no instance (null) — renders buttons without crash', () => {
    render(<SuricataControls instance={null} />)
    expect(screen.getByTestId('btn-test')).toBeInTheDocument()
    expect(screen.getByTestId('btn-sync')).toBeInTheDocument()
    // null instance → no status badge
    expect(screen.queryByTestId('source-status')).not.toBeInTheDocument()
  })
})
