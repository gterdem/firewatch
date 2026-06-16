/**
 * analysisCache — session-scoped LRU cache for per-IP detailed analysis results (issue #269).
 *
 * Caches the last N (default 10) completed DetailedAnalysis + RuleDescription arrays
 * keyed by IP address.  Clears automatically on page reload (plain module-scope Map —
 * no localStorage, no IndexedDB, no persistence across sessions).
 *
 * ADR-0035 honesty: callers MUST stamp cached results with the fetch timestamp
 * so the UI can render "cached · <age>" and surface a Re-run affordance.
 *
 * Design: a Map doubles as an LRU when we delete-then-reinsert on every write
 * (Map iteration order is insertion order, so the "oldest" entry is Map.keys().next()).
 * This keeps the implementation ~30 lines with zero dependencies.
 */

import type { DetailedAnalysis, RuleDescription } from '../../api/types'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CachedAnalysis {
  analysis: DetailedAnalysis | null
  rules: RuleDescription[]
  /** Unix-ms timestamp of when the fetch completed. */
  fetchedAt: number
}

// ---------------------------------------------------------------------------
// Module-scope LRU store
// ---------------------------------------------------------------------------

const MAX_ENTRIES = 10

/** The live cache — replaced with a fresh Map on import (each page load). */
const store = new Map<string, CachedAnalysis>()

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Returns the cached analysis for `ip`, or `null` if not present.
 */
export function getCachedAnalysis(ip: string): CachedAnalysis | null {
  return store.get(ip) ?? null
}

/**
 * Stores (or replaces) the analysis for `ip`.
 *
 * LRU eviction: if the cache is full, the oldest entry is removed before
 * inserting the new one.  Updating an existing key moves it to "most recent"
 * (delete-then-set exploits Map insertion-order semantics).
 */
export function setCachedAnalysis(ip: string, entry: CachedAnalysis): void {
  // If the key already exists, remove it so re-insertion brings it to the tail.
  if (store.has(ip)) {
    store.delete(ip)
  } else if (store.size >= MAX_ENTRIES) {
    // Evict the oldest entry (first in insertion order).
    const oldest = store.keys().next().value
    if (oldest !== undefined) {
      store.delete(oldest)
    }
  }
  store.set(ip, entry)
}

/**
 * Removes a single entry from the cache.  Used by the Re-run affordance so
 * the next open triggers a fresh fetch.
 */
export function invalidateCachedAnalysis(ip: string): void {
  store.delete(ip)
}

/**
 * Returns the current cache size (test helper / diagnostics).
 */
export function analysisCacheSize(): number {
  return store.size
}

/**
 * Clears the entire cache (test helper / diagnostics).
 */
export function clearAnalysisCache(): void {
  store.clear()
}
