/**
 * Tests for src/components/SupervisorOfflineBanner.tsx
 *
 * EARS criteria covered (issue #315):
 *   - WHEN supervisorStatus is "offline", the banner is rendered.
 *   - WHEN supervisorStatus is "online" or "unknown", no banner is rendered.
 *   - WHILE offline, a non-zero retryCountdown shows the countdown text.
 *   - WHEN the "Retry now" button is clicked, onRetryNow callback fires.
 *   - The banner carries role="alert" for screen-reader announcement.
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import SupervisorOfflineBanner from '../components/SupervisorOfflineBanner'
import type { SupervisorStatus } from '../hooks/useSupervisorGate'

describe('SupervisorOfflineBanner', () => {
  // WHEN offline: banner renders with role="alert"
  it('renders the banner when supervisorStatus is "offline"', () => {
    render(
      <SupervisorOfflineBanner
        supervisorStatus="offline"
        retryCountdown={5}
        onRetryNow={vi.fn()}
      />,
    )
    expect(screen.getByTestId('supervisor-offline-banner')).toBeInTheDocument()
    expect(screen.getByRole('alert')).toBeInTheDocument()
  })

  // WHEN online: banner NOT rendered
  it('renders nothing when supervisorStatus is "online"', () => {
    render(
      <SupervisorOfflineBanner
        supervisorStatus="online"
        retryCountdown={0}
        onRetryNow={vi.fn()}
      />,
    )
    expect(screen.queryByTestId('supervisor-offline-banner')).not.toBeInTheDocument()
  })

  // WHEN unknown (initial state): banner NOT rendered
  it('renders nothing when supervisorStatus is "unknown"', () => {
    render(
      <SupervisorOfflineBanner
        supervisorStatus="unknown"
        retryCountdown={0}
        onRetryNow={vi.fn()}
      />,
    )
    expect(screen.queryByTestId('supervisor-offline-banner')).not.toBeInTheDocument()
  })

  // WHILE offline: countdown text shows when retryCountdown > 0
  it('shows the retry countdown text when retryCountdown is > 0', () => {
    render(
      <SupervisorOfflineBanner
        supervisorStatus="offline"
        retryCountdown={12}
        onRetryNow={vi.fn()}
      />,
    )
    const countdown = screen.getByTestId('supervisor-retry-countdown')
    expect(countdown).toBeInTheDocument()
    expect(countdown.textContent).toBe('12s')
  })

  // When countdown is 0: no countdown text shown
  it('does not show countdown text when retryCountdown is 0', () => {
    render(
      <SupervisorOfflineBanner
        supervisorStatus="offline"
        retryCountdown={0}
        onRetryNow={vi.fn()}
      />,
    )
    expect(screen.queryByTestId('supervisor-retry-countdown')).not.toBeInTheDocument()
  })

  // WHEN "Retry now" button is clicked: onRetryNow callback fires
  it('calls onRetryNow when the "Retry now" button is clicked', () => {
    const onRetryNow = vi.fn()
    render(
      <SupervisorOfflineBanner
        supervisorStatus="offline"
        retryCountdown={5}
        onRetryNow={onRetryNow}
      />,
    )
    fireEvent.click(screen.getByTestId('supervisor-retry-now'))
    expect(onRetryNow).toHaveBeenCalledTimes(1)
  })

  // Banner text conveys "Supervisor offline" message (honesty, ADR-0035)
  it('shows "Supervisor offline" text in the banner', () => {
    render(
      <SupervisorOfflineBanner
        supervisorStatus="offline"
        retryCountdown={5}
        onRetryNow={vi.fn()}
      />,
    )
    expect(screen.getByRole('alert').textContent).toMatch(/supervisor offline/i)
  })

  // All three status values covered (type exhaustion check)
  const statuses: SupervisorStatus[] = ['online', 'offline', 'unknown']
  statuses.forEach((status) => {
    it(`does not crash when supervisorStatus="${status}"`, () => {
      expect(() => {
        render(
          <SupervisorOfflineBanner
            supervisorStatus={status}
            retryCountdown={0}
            onRetryNow={vi.fn()}
          />,
        )
      }).not.toThrow()
    })
  })
})
