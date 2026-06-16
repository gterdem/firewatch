/**
 * Tests for bearer attachment in buildHeaders() (issue #550 / ADR-0026 Amendment 1).
 *
 * EARS criteria covered:
 *   - Event-driven: WHEN an API key is set, THEN buildHeaders() includes
 *     Authorization: Bearer <key> (RFC 6750 §2.1).
 *   - Event-driven: WHEN no API key is set, THEN buildHeaders() omits the
 *     Authorization header entirely (no-key path).
 *   - Event-driven: buildHeaders() still includes Content-Type and Accept.
 *   - State-driven: after key is cleared, bearer is no longer sent.
 *   - Event-driven (401): parseError produces a clear "API key required or invalid"
 *     message for 401 responses — not a generic failure string.
 *
 * NB: buildHeaders is now exported from client.ts so it can be unit-tested.
 * The apiKeyStore is reset between tests via _resetForTest().
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { buildHeaders, ApiError } from '../api/client'
import { setApiKey, _resetForTest } from '../app/apiKeyStore'

beforeEach(() => {
  _resetForTest()
})

describe('buildHeaders — bearer attachment (ADR-0026 Amendment 1)', () => {
  it('omits Authorization header when no key is set', () => {
    const headers = buildHeaders()
    expect(headers).not.toHaveProperty('Authorization')
  })

  it('includes Content-Type and Accept when no key is set', () => {
    const headers = buildHeaders()
    expect(headers['Content-Type']).toBe('application/json')
    expect(headers['Accept']).toBe('application/json')
  })

  it('attaches Authorization: Bearer <key> when a key is set', () => {
    setApiKey('my-api-key-123')
    const headers = buildHeaders()
    expect(headers['Authorization']).toBe('Bearer my-api-key-123')
  })

  it('still includes Content-Type and Accept when a key is set', () => {
    setApiKey('some-key')
    const headers = buildHeaders()
    expect(headers['Content-Type']).toBe('application/json')
    expect(headers['Accept']).toBe('application/json')
  })

  it('omits Authorization after the key is cleared', () => {
    setApiKey('active-key')
    expect(buildHeaders()['Authorization']).toBe('Bearer active-key')
    setApiKey(null)
    expect(buildHeaders()).not.toHaveProperty('Authorization')
  })

  it('does not include Authorization for empty-string key', () => {
    setApiKey('')
    const headers = buildHeaders()
    expect(headers).not.toHaveProperty('Authorization')
  })

  it('merges extra headers without overwriting the bearer', () => {
    setApiKey('token-xyz')
    const headers = buildHeaders({ 'X-Custom': 'val' })
    expect(headers['Authorization']).toBe('Bearer token-xyz')
    expect(headers['X-Custom']).toBe('val')
  })
})

describe('401 response produces a clear error message', () => {
  let fetchSpy: ReturnType<typeof vi.fn>

  beforeEach(() => {
    fetchSpy = vi.fn()
    vi.stubGlobal('fetch', fetchSpy)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('ApiError from 401 has a recognizable API-key message', async () => {
    // Simulate a 401 response — the message must contain "API key" guidance.
    fetchSpy.mockResolvedValue(
      new Response(JSON.stringify({ detail: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    // Import dynamically to get live module state (client.ts has been mutated at import time).
    const { fetchStats } = await import('../api/client')
    await expect(fetchStats()).rejects.toSatisfy(
      (e: unknown) =>
        e instanceof ApiError &&
        e.status === 401 &&
        /api key/i.test(e.message),
    )
  })
})
