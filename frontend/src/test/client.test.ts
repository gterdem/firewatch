/**
 * Tests for src/api/client.ts
 *
 * NB-2: assertLoopbackBase — loopback URL guard (ADR-0026).
 * Exported as a pure helper so it can be unit-tested without mocking import.meta.env.
 *
 * NB-3: resolveBaseUrl — dev-proxy base URL resolution.
 * Exported as a pure helper so it can be unit-tested without mocking import.meta.env.
 * In dev (DEV=true, no override): returns '' so requests are relative and route
 * through the Vite dev proxy.
 * In prod (no DEV flag, no override): returns 'http://127.0.0.1:8000'.
 * Explicit VITE_API_BASE_URL overrides win in both modes.
 *
 * NB-4 (#81): satellite modules (sources.ts, logs.ts, analytics.ts) route their
 * base-URL resolution through resolveBaseUrl + assertLoopbackBase — the same
 * fail-closed guard as client.ts. These tests exercise the shared helpers directly
 * to cover the contract that ALL satellite modules must enforce.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { assertLoopbackBase, resolveBaseUrl, putSourceConfig, fetchBannerSummary } from '../api/client'

describe('assertLoopbackBase', () => {
  // Valid loopback origins must not throw
  it('accepts http://127.0.0.1:8000', () => {
    expect(() => assertLoopbackBase('http://127.0.0.1:8000')).not.toThrow()
  })

  it('accepts http://localhost:8000', () => {
    expect(() => assertLoopbackBase('http://localhost:8000')).not.toThrow()
  })

  it('accepts http://localhost (no port)', () => {
    expect(() => assertLoopbackBase('http://localhost')).not.toThrow()
  })

  it('accepts http://[::1]:8000 (IPv6 loopback)', () => {
    expect(() => assertLoopbackBase('http://[::1]:8000')).not.toThrow()
  })

  // Non-loopback origins must throw (ADR-0026 fail-closed posture)
  it('throws for a public IP address', () => {
    expect(() => assertLoopbackBase('http://192.168.1.100:8000')).toThrowError(
      /non-loopback/i,
    )
  })

  it('throws for a public hostname', () => {
    expect(() => assertLoopbackBase('https://api.example.com')).toThrowError(
      /non-loopback/i,
    )
  })

  it('throws for a non-loopback hostname with a port', () => {
    expect(() => assertLoopbackBase('http://remote-host:8000')).toThrowError(
      /non-loopback/i,
    )
  })

  // Invalid URLs must also throw (not silently pass)
  it('throws for a completely invalid URL', () => {
    expect(() => assertLoopbackBase('not-a-url')).toThrow()
  })
})

describe('resolveBaseUrl', () => {
  // NB-3a: In dev with no override the base must be relative ('') so requests
  // go through the Vite dev proxy (no CORS, no .env.local needed).
  it('returns empty string in dev with no override (proxy-routed)', () => {
    expect(resolveBaseUrl({ DEV: true })).toBe('')
  })

  // NB-3b: In prod with no override the base must be the absolute loopback URL.
  it('returns absolute loopback URL in prod with no override', () => {
    expect(resolveBaseUrl({ DEV: false })).toBe('http://127.0.0.1:8000')
  })

  it('returns absolute loopback URL when env has no flags set', () => {
    expect(resolveBaseUrl({})).toBe('http://127.0.0.1:8000')
  })

  // NB-3c: An explicit VITE_API_BASE_URL override wins in dev.
  it('explicit override wins over dev relative base', () => {
    expect(
      resolveBaseUrl({ DEV: true, VITE_API_BASE_URL: 'http://127.0.0.1:9000' }),
    ).toBe('http://127.0.0.1:9000')
  })

  // NB-3d: An explicit VITE_API_BASE_URL override wins in prod.
  it('explicit override wins over prod absolute default', () => {
    expect(
      resolveBaseUrl({ DEV: false, VITE_API_BASE_URL: 'http://127.0.0.1:9000' }),
    ).toBe('http://127.0.0.1:9000')
  })

  // NB-3e: Override of '' (explicitly blank) is preserved — the caller set it.
  it('preserves an explicitly blank override (not the same as unset)', () => {
    // An explicitly set empty string override means the caller wants relative URLs;
    // that is valid (e.g. a production same-origin setup).
    expect(resolveBaseUrl({ DEV: false, VITE_API_BASE_URL: '' })).toBe('')
  })
})

// ---------------------------------------------------------------------------
// putSourceConfig — request body must be {"updates": <config>} (#63)
// ---------------------------------------------------------------------------
// The API reads body.get("updates", {}) — a raw config body resolves updates={}
// and nothing is persisted. These tests mock fetch to assert the serialized body
// shape without requiring a live server.

describe('putSourceConfig request body shape', () => {
  let fetchSpy: ReturnType<typeof vi.fn>

  beforeEach(() => {
    fetchSpy = vi.fn().mockResolvedValue(
      new Response(null, { status: 200 }),
    )
    vi.stubGlobal('fetch', fetchSpy)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  // EARS event-driven: putSourceConfig wraps the config in {"updates": ...} (#63)
  it('serializes the body as {"updates": config}, not a raw config object', async () => {
    const config = { host: 'localhost', port: 9200 }
    await putSourceConfig('my_source', config)

    expect(fetchSpy).toHaveBeenCalledOnce()
    const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit]
    const parsed = JSON.parse(init.body as string) as unknown
    expect(parsed).toEqual({ updates: config })
  })

  // Confirm no top-level key leaks outside "updates"
  it('does not send top-level config keys outside the updates wrapper', async () => {
    const config = { host: 'remotehost', port: 514 }
    await putSourceConfig('syslog', config)

    const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit]
    const parsed = JSON.parse(init.body as string) as Record<string, unknown>
    // Only "updates" must be at the top level — no raw key leakage
    expect(Object.keys(parsed)).toEqual(['updates'])
    expect(parsed['updates']).toEqual(config)
  })

  // An empty config dict must still be wrapped (not send an empty raw object)
  it('wraps an empty config as {"updates": {}}', async () => {
    await putSourceConfig('empty_source', {})

    const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit]
    const parsed = JSON.parse(init.body as string) as unknown
    expect(parsed).toEqual({ updates: {} })
  })

  // The typeKey must be URI-encoded in the request URL
  it('URI-encodes the type_key in the request URL', async () => {
    await putSourceConfig('my source/type', { val: 1 })

    const [url] = fetchSpy.mock.calls[0] as [string, RequestInit]
    expect(url).toContain('my%20source%2Ftype')
  })
})

// ---------------------------------------------------------------------------
// fetchBannerSummary — GET /banner/summary (issue #55)
// ---------------------------------------------------------------------------

describe('fetchBannerSummary', () => {
  let fetchSpy: ReturnType<typeof vi.fn>

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('issues a GET request to /banner/summary and returns the parsed JSON verbatim', async () => {
    const body = {
      attempt_count: 412,
      actor_count: 87,
      succeeded_count: 0,
      queue_size: 2,
      top_pressure: [{ source_ip: '192.0.2.10', attempt_count: 42, span_minutes: 18 }],
      generated_at: '2026-06-04T10:00:00Z',
    }
    fetchSpy = vi.fn().mockResolvedValue(new Response(JSON.stringify(body), { status: 200 }))
    vi.stubGlobal('fetch', fetchSpy)

    const result = await fetchBannerSummary()

    expect(fetchSpy).toHaveBeenCalledOnce()
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit]
    expect(url).toContain('/banner/summary')
    expect(init.method).toBe('GET')
    // Result is the parsed JSON verbatim — no client-side recomputation.
    expect(result).toEqual(body)
  })

  it('throws on a non-ok response (surfaced via parseError, not swallowed)', async () => {
    fetchSpy = vi.fn().mockResolvedValue(new Response(null, { status: 503 }))
    vi.stubGlobal('fetch', fetchSpy)

    await expect(fetchBannerSummary()).rejects.toBeTruthy()
  })
})

// ---------------------------------------------------------------------------
// #81 — satellite modules share the loopback-guard contract via the exported
// resolveBaseUrl + assertLoopbackBase helpers. These tests verify that the
// shared helpers behave correctly when called from a satellite module's
// getBase() equivalent — i.e. they ARE the mechanism that each satellite uses.
// ---------------------------------------------------------------------------
describe('#81 satellite module loopback-guard contract (resolveBaseUrl + assertLoopbackBase)', () => {
  // EARS: When PROD and VITE_API_BASE_URL is a non-loopback host, assertLoopbackBase
  // SHALL throw — identical to client.ts module-level guard.

  it('resolveBaseUrl returns the non-loopback override unchanged (satellite)', () => {
    // Satellite calls resolveBaseUrl with the same env shape as client.ts.
    const base = resolveBaseUrl({ VITE_API_BASE_URL: 'http://remote.example.com:8000' })
    expect(base).toBe('http://remote.example.com:8000')
  })

  it('assertLoopbackBase then throws on that non-loopback base (satellite fails-closed)', () => {
    const base = resolveBaseUrl({ VITE_API_BASE_URL: 'http://remote.example.com:8000' })
    // This is exactly what sources.ts / logs.ts / analytics.ts do in prod (#81).
    expect(() => assertLoopbackBase(base)).toThrowError(/non-loopback/i)
  })

  it('resolveBaseUrl returns loopback default in prod when no override set (satellite)', () => {
    // No VITE_API_BASE_URL set, not DEV → prod default.
    const base = resolveBaseUrl({})
    expect(base).toBe('http://127.0.0.1:8000')
    // Guard must pass (loopback is valid).
    expect(() => assertLoopbackBase(base)).not.toThrow()
  })

  it('resolveBaseUrl returns empty string in dev (satellite, proxy mode — no guard needed)', () => {
    const base = resolveBaseUrl({ DEV: true })
    // Dev proxy mode: base is '' — each satellite's guard checks BASE_URL !== ''
    // before calling assertLoopbackBase, so no throw in this case.
    expect(base).toBe('')
  })

  it('resolveBaseUrl + assertLoopbackBase accept http://127.0.0.1 override (satellite)', () => {
    const base = resolveBaseUrl({ VITE_API_BASE_URL: 'http://127.0.0.1:8000' })
    expect(() => assertLoopbackBase(base)).not.toThrow()
  })
})
