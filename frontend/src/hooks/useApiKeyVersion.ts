/**
 * useApiKeyVersion — returns the current apiKeyStore key-version counter and
 * re-renders the caller whenever the key changes (set or cleared).
 *
 * Usage: add the returned value to a useEffect dependency array so the effect
 * re-runs each time the operator sets or changes the API key in-session.
 *
 *   const keyVersion = useApiKeyVersion()
 *   useEffect(() => { ... }, [keyVersion])
 *
 * The version is a monotonically-increasing integer — it never oscillates, so
 * there is no risk of an infinite render loop.
 *
 * Uses useSyncExternalStore (React 18) to subscribe to the apiKeyStore external
 * store without calling setState synchronously inside an effect body — the
 * canonical React pattern for external-store subscriptions.
 *
 * Issue #589: re-query Settings sources/AI panels when the key is restored
 * in-session after a 401 on mount (caused by the key being cleared on reload).
 */

import { useSyncExternalStore } from 'react'
import { getKeyVersion, subscribeKeyVersion } from '../app/apiKeyStore'

export function useApiKeyVersion(): number {
  return useSyncExternalStore(subscribeKeyVersion, getKeyVersion)
}
