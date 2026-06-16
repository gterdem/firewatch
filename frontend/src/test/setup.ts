/**
 * Vitest setup file — runs before each test file.
 * Extends jest-dom matchers for @testing-library/react.
 */
import '@testing-library/jest-dom'

// jsdom does not ship ResizeObserver; polyfill it for components that use
// Radix UI primitives (e.g. @rjsf/shadcn uses @radix-ui/react-use-size).
if (typeof window !== 'undefined' && !window.ResizeObserver) {
  window.ResizeObserver = class ResizeObserver {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
}

// ---------------------------------------------------------------------------
// ADR-0064: global stub for useRefreshSignal / RefreshProvider.
//
// Route components (DashboardRoute, AIRoute, AnalyticsRoute) now call
// useRefreshSignal() which throws when rendered outside a <RefreshProvider>.
// Unit tests that render these routes directly (without the app shell) would
// all fail.  A global stub that returns a stable signal with dataVersion=0
// keeps every existing test green with zero per-test boilerplate.
//
// Tests that need to simulate a dataVersion bump (AutoLiveRefresh.test.tsx)
// override this mock within their own file using a VersionBumpWrapper that
// updates versionRef.current and triggers re-renders via React state.
// ---------------------------------------------------------------------------
import { vi } from 'vitest'

vi.mock('../app/refresh/RefreshContext', () => ({
  useRefreshSignal: () => ({
    dataVersion: 0,
    grewSources: new Set<string>(),
    lastDeltaCount: 0,
    healthItems: [],
    isLive: false,
    lastPollAt: null,
    lastSyncDeltaCount: 0,
    syncEventId: 0,
    pulsingSources: new Set<string>(),
    clearSyncDelta: () => {},
    freshnessMinutes: 5,
  }),
  RefreshProvider: ({ children }: { children: import('react').ReactNode }) => children,
}))
