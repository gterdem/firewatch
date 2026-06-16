/**
 * apiKeyStore — single client-side location for the API key (ADR-0026 Amendment 1).
 *
 * The key feeds buildHeaders() in client.ts; it is set once from the Settings form
 * when the operator configures it. It is NEVER logged, URL-embedded, or echoed to
 * the DOM in plaintext.
 *
 * Design decisions:
 *   - Module-level variable (not React state): the store must be readable from the
 *     client module at fetch time without a React hook call chain.
 *   - No persistence (sessionStorage / localStorage): the key is held in-memory only.
 *     On reload the operator must re-enter — or the page reads the masked server state
 *     (null) which does NOT reveal the value, only that one is set. This is intentional:
 *     storing a bearer token in browser storage violates OWASP ASVS V3.2.
 *   - "first key set" boolean: tracks whether the operator has set a key in THIS session
 *     so the one-time notice fires exactly once per session (not per load).
 *   - keyVersion counter: a monotonically-increasing integer bumped on every setApiKey
 *     call. React components that need to re-fetch when the key changes subscribe via
 *     subscribeKeyVersion() and key their useEffect deps on the version. This avoids a
 *     render loop because the counter only increments — it never oscillates.
 *     (Issue #589: re-query Settings sources/AI panels on in-session key restore.)
 *
 * ADR-0026 Amendment 1 (2026-06-13): a configured key is enforced on every request
 * including the loopback dashboard. The SPA must attach the bearer or lock itself out.
 */

/** The current API key held in memory. Never logged or persisted. */
let _apiKey: string | null = null

/** Whether a key has been set in the current session (drives one-time notice). */
let _firstKeySetInSession = false

/**
 * Monotonically-increasing version counter. Bumped on every setApiKey() call so React
 * effects can depend on it and re-run only when the key actually changes.
 * Issue #589: panels that 401-ed on mount re-fetch when the key is restored in-session.
 */
let _keyVersion = 0

/** Listeners notified whenever the key version changes. */
const _listeners = new Set<() => void>()

/** Returns the current key (null = unset / no auth header should be sent). */
export function getApiKey(): string | null {
  return _apiKey
}

/** Returns the current key-version counter (increases on every setApiKey call). */
export function getKeyVersion(): number {
  return _keyVersion
}

/**
 * Subscribe to key-version changes. Returns an unsubscribe function.
 * Called by useApiKeyVersion() to drive re-renders on key change.
 */
export function subscribeKeyVersion(listener: () => void): () => void {
  _listeners.add(listener)
  return () => {
    _listeners.delete(listener)
  }
}

/**
 * Set the active API key.
 * On first call with a non-empty value, marks the session as "key just set"
 * so the one-time notice can fire. Subsequent calls do not re-trigger it.
 * Always bumps the keyVersion counter and notifies subscribers (issue #589).
 */
export function setApiKey(key: string | null): void {
  const hadKeyBefore = _apiKey !== null && _apiKey !== ''
  _apiKey = key && key.trim() !== '' ? key.trim() : null
  if (_apiKey !== null && !hadKeyBefore) {
    _firstKeySetInSession = true
  }
  // Bump version on every setApiKey call so dependent effects re-run.
  _keyVersion += 1
  _listeners.forEach((fn) => fn())
}

/**
 * Returns true if an API key was set for the first time in this session.
 * The caller (ApiKeyPanel) reads this to decide whether to show the one-time notice,
 * then calls clearFirstKeySetFlag() to prevent re-showing.
 */
export function isFirstKeySetInSession(): boolean {
  return _firstKeySetInSession
}

/** Clears the first-key-set flag after the notice has been shown. */
export function clearFirstKeySetFlag(): void {
  _firstKeySetInSession = false
}

/**
 * Reset store state — for unit tests only.
 * @internal
 */
export function _resetForTest(): void {
  _apiKey = null
  _firstKeySetInSession = false
  _keyVersion = 0
  _listeners.clear()
}
