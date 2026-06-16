/**
 * useStructuralColumns — Option-B structural empty-column hiding (ADR-0060, issue #664).
 *
 * Computes the set of LogsTable column keys that are structurally absent from the
 * current result set — i.e. no source currently present in the filtered scope can
 * produce those fields BY DESIGN (per SourceMetadata.produces).
 *
 * This is structural / value-blind hiding. It NEVER inspects row values — doing so
 * would mistake real falsy values (e.g. Azure WAF destination_port=0) for "empty",
 * and would flicker as you paginate. Capability is a fixed property of the source.
 *
 * Algorithm (ADR-0060 D4):
 *   1. Fetch GET /sources/types once → Map<type_key, Set<canonicalField>>.
 *   2. Receive present_source_types from /logs/stats (the current filtered scope).
 *   3. For each present source, look up its produces set.
 *      - produces is empty or absent → "produces-all" (backward-compatible default, D2).
 *        When any present source produces-all, NO column is hidden.
 *   4. Union the produced-field sets across all present sources.
 *   5. A column key is structurally absent when:
 *        - it has a canonical field mapping (COLUMN_CANONICAL_FIELDS), AND
 *        - that canonical field is NOT in the union, AND
 *        - no present source is produces-all.
 *   6. present_source_types is empty/unknown → hide nothing (fail-open).
 *
 * Source-agnostic: no per-source branching. The decision is driven by the
 * plugin-declared produces set and the column→canonicalField map.
 *
 * SECURITY (ADR-0029 D3):
 *   source type keys are normalised backend values (not raw attacker data).
 *   This hook renders nothing — it only returns a Set<string>.
 */

import { useEffect, useMemo, useState } from 'react'
import { fetchSourceTypes } from '../../api/client'
import type { SourceTypeEntry } from '../../schema/types'
import { COLUMN_CANONICAL_FIELDS } from '../../lib/fieldAvailability'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface StructuralColumnsResult {
  /**
   * Set of column keys (e.g. "destip", "protocol", "tls_ja4", "dns", "destport")
   * that are structurally absent from the current scope.
   *
   * A column key is in this set when NO present source can produce its canonical
   * field AND every present source has a non-empty produces declaration.
   *
   * Empty set = hide nothing (fail-open, including when present_source_types=[]).
   */
  structurallyAbsent: ReadonlySet<string>
  /**
   * True while source-types are loading for the first time.
   * The caller may suppress the chip until loading is resolved.
   */
  loading: boolean
}

// ---------------------------------------------------------------------------
// Module-level cache for GET /sources/types (fetched at most once per session).
// Using a module-level promise avoids fetching once per hook invocation when
// multiple components mount simultaneously.
// ---------------------------------------------------------------------------

type SourceTypeMap = Map<string, Set<string>>   // type_key → producedFields (empty = produces-all)

let cachedFetch: Promise<SourceTypeMap> | null = null

function getSourceTypeMap(): Promise<SourceTypeMap> {
  if (cachedFetch !== null) return cachedFetch
  cachedFetch = fetchSourceTypes().then((entries: SourceTypeEntry[]) => {
    const map = new Map<string, Set<string>>()
    for (const entry of entries) {
      // Empty/absent produces → "produces-all" semantics (ADR-0060 D2).
      // We store an empty Set to distinguish "declared empty" from "not in map".
      map.set(entry.type_key, new Set(entry.produces ?? []))
    }
    return map
  }).catch(() => {
    // On network/parse failure: reset so the next mount can retry.
    cachedFetch = null
    return new Map<string, Set<string>>()
  })
  return cachedFetch
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * @param presentSourceTypes - DISTINCT source_type values in the current filtered
 *   scope, from GET /logs/stats `present_source_types`. Pass an empty array when
 *   not yet known — the hook will hide nothing (fail-open per ADR-0060 D2).
 */
export function useStructuralColumns(presentSourceTypes: string[]): StructuralColumnsResult {
  const [sourceTypeMap, setSourceTypeMap] = useState<SourceTypeMap | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    getSourceTypeMap().then((map) => {
      if (!cancelled) {
        setSourceTypeMap(map)
        setLoading(false)
      }
    })
    return () => {
      cancelled = true
    }
  }, [])

  const structurallyAbsent = useMemo<ReadonlySet<string>>(() => {
    // Fail-open: no hiding while loading, or when no sources are present.
    if (sourceTypeMap === null || presentSourceTypes.length === 0) {
      return new Set<string>()
    }

    // Collect the produces sets for sources actually present.
    // If a source is present but not in the discovery map (e.g. a new plugin
    // whose discovery entry hasn't loaded yet), treat it as produces-all.
    const presentProduces: Array<Set<string>> = []
    let anyProducesAll = false

    for (const typeKey of presentSourceTypes) {
      const producedFields = sourceTypeMap.get(typeKey)
      if (producedFields === undefined || producedFields.size === 0) {
        // Not in map (unknown plugin) or empty produces → produces-all → no hiding.
        anyProducesAll = true
        break
      }
      presentProduces.push(producedFields)
    }

    // Any produces-all source → no column is hidden (ADR-0060 D2).
    if (anyProducesAll || presentProduces.length === 0) {
      return new Set<string>()
    }

    // Union of all produced fields across present sources.
    const unionProduced = new Set<string>()
    for (const fieldSet of presentProduces) {
      for (const field of fieldSet) {
        unionProduced.add(field)
      }
    }

    // A column key is structurally absent when its canonical field is NOT in the union.
    const absent = new Set<string>()
    for (const [colKey, { canonicalField }] of Object.entries(COLUMN_CANONICAL_FIELDS)) {
      if (!unionProduced.has(canonicalField)) {
        absent.add(colKey)
      }
    }
    return absent
  }, [sourceTypeMap, presentSourceTypes])

  return { structurallyAbsent, loading }
}

// ---------------------------------------------------------------------------
// Exported for testing (reset the module-level cache between tests).
// ---------------------------------------------------------------------------

export function _resetSourceTypeMapCache(): void {
  cachedFetch = null
}
