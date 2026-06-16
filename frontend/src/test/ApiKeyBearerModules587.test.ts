/**
 * Bearer attach regression guard — issue #587.
 *
 * EARS criteria covered:
 *   - WHEN an api_key is configured, ALL API client modules SHALL attach
 *     Authorization: Bearer to every outbound request — not just client.ts.
 *   - The five sibling modules (logs, analytics, sources, sourceActions, cases)
 *     MUST route through the central buildHeaders() seam (client.ts) which calls
 *     getApiKey() from apiKeyStore.
 *
 * Strategy: stub global `fetch` to capture the request headers; set a key via
 * setApiKey(); call one representative function from each module; assert the
 * Authorization header is present on the intercepted request.
 *
 * The stub returns a minimal valid response for each call shape so no module
 * throws before we can inspect headers.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { setApiKey, _resetForTest } from '../app/apiKeyStore'

// We call the real functions from each module — they call the real buildHeaders().
// fetch is stubbed globally so no network requests are made.

const TEST_KEY = 'test-bearer-key-587'

/** Build a minimal JSON fetch response. */
function okJson(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

/** Capture the Authorization header from the most recent fetch call. */
function capturedAuthHeader(fetchSpy: ReturnType<typeof vi.fn>): string | undefined {
  const lastCall = fetchSpy.mock.calls[fetchSpy.mock.calls.length - 1]
  if (!lastCall) return undefined
  // fetch(url, init) — init.headers is a plain object (Record<string,string>)
  const init = lastCall[1] as RequestInit | undefined
  if (!init?.headers) return undefined
  const headers = init.headers as Record<string, string>
  return headers['Authorization']
}

beforeEach(() => {
  _resetForTest()
})

afterEach(() => {
  vi.unstubAllGlobals()
  _resetForTest()
})

// ---------------------------------------------------------------------------
// logs.ts — fetchPaginatedLogs
// ---------------------------------------------------------------------------

describe('logs.ts — bearer attach (#587 Defect 1)', () => {
  it('attaches Authorization: Bearer when a key is set', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(
      okJson({ logs: [], next_cursor: null, has_more: false, total_matching: 0 }),
    )
    vi.stubGlobal('fetch', fetchSpy)
    setApiKey(TEST_KEY)

    const { fetchPaginatedLogs } = await import('../api/logs')
    await fetchPaginatedLogs({})

    expect(capturedAuthHeader(fetchSpy)).toBe(`Bearer ${TEST_KEY}`)
  })

  it('omits Authorization when no key is set', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(
      okJson({ logs: [], next_cursor: null, has_more: false, total_matching: 0 }),
    )
    vi.stubGlobal('fetch', fetchSpy)

    const { fetchPaginatedLogs } = await import('../api/logs')
    await fetchPaginatedLogs({})

    expect(capturedAuthHeader(fetchSpy)).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// analytics.ts — fetchGeo
// ---------------------------------------------------------------------------

describe('analytics.ts — bearer attach (#587 Defect 1)', () => {
  it('attaches Authorization: Bearer when a key is set', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(okJson([]))
    vi.stubGlobal('fetch', fetchSpy)
    setApiKey(TEST_KEY)

    const { fetchGeo } = await import('../api/analytics')
    await fetchGeo()

    expect(capturedAuthHeader(fetchSpy)).toBe(`Bearer ${TEST_KEY}`)
  })

  it('omits Authorization when no key is set', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(okJson([]))
    vi.stubGlobal('fetch', fetchSpy)

    const { fetchGeo } = await import('../api/analytics')
    await fetchGeo()

    expect(capturedAuthHeader(fetchSpy)).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// sources.ts — fetchSources
// ---------------------------------------------------------------------------

describe('sources.ts — bearer attach (#587 Defect 1)', () => {
  it('attaches Authorization: Bearer when a key is set', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(okJson([]))
    vi.stubGlobal('fetch', fetchSpy)
    setApiKey(TEST_KEY)

    const { fetchSources } = await import('../api/sources')
    await fetchSources()

    expect(capturedAuthHeader(fetchSpy)).toBe(`Bearer ${TEST_KEY}`)
  })

  it('omits Authorization when no key is set', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(okJson([]))
    vi.stubGlobal('fetch', fetchSpy)

    const { fetchSources } = await import('../api/sources')
    await fetchSources()

    expect(capturedAuthHeader(fetchSpy)).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// sourceActions.ts — fetchSourceActions
// ---------------------------------------------------------------------------

describe('sourceActions.ts — bearer attach (#587 Defect 1)', () => {
  it('attaches Authorization: Bearer when a key is set', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(okJson([]))
    vi.stubGlobal('fetch', fetchSpy)
    setApiKey(TEST_KEY)

    const { fetchSourceActions } = await import('../api/sourceActions')
    await fetchSourceActions('azure_waf', 'default')

    expect(capturedAuthHeader(fetchSpy)).toBe(`Bearer ${TEST_KEY}`)
  })

  it('omits Authorization when no key is set', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(okJson([]))
    vi.stubGlobal('fetch', fetchSpy)

    const { fetchSourceActions } = await import('../api/sourceActions')
    await fetchSourceActions('azure_waf', 'default')

    expect(capturedAuthHeader(fetchSpy)).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// cases.ts — listCases
// ---------------------------------------------------------------------------

describe('cases.ts — bearer attach (#587 Defect 1)', () => {
  it('attaches Authorization: Bearer when a key is set', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(
      okJson({ items: [], next_cursor: null, has_more: false }),
    )
    vi.stubGlobal('fetch', fetchSpy)
    setApiKey(TEST_KEY)

    const { listCases } = await import('../api/cases')
    await listCases()

    expect(capturedAuthHeader(fetchSpy)).toBe(`Bearer ${TEST_KEY}`)
  })

  it('omits Authorization when no key is set', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(
      okJson({ items: [], next_cursor: null, has_more: false }),
    )
    vi.stubGlobal('fetch', fetchSpy)

    const { listCases } = await import('../api/cases')
    await listCases()

    expect(capturedAuthHeader(fetchSpy)).toBeUndefined()
  })
})
