/**
 * useEvidenceChain — fetch + cache the MI-6 evidence chain per actor IP.
 *
 * Fetches GET /threats/{ip}/evidence (ADR-0041) once per ip mount.
 * Returns honest loading / empty / error states — no infinite spinners.
 *
 * Cache: keyed by IP; cleared between panel opens (ip change resets state).
 * No LLM call is triggered — the evidence endpoint enforces that boundary
 * server-side (ai-engine-invariants / ADR-0041).
 *
 * SECURITY (ADR-0029 D3): all EventSummary fields from the evidence chain are
 * attacker-controlled. Consumers MUST render them as text nodes only.
 */

import { useEffect, useReducer } from 'react'
import { fetchEvidenceChain } from '../api/client'
import { ApiError } from '../api/client'
import type { EvidenceChainResponse } from '../api/types'

// ---------------------------------------------------------------------------
// State shape + reducer
// ---------------------------------------------------------------------------

export type EvidenceChainStatus = 'loading' | 'ok' | 'empty' | 'error'

export interface EvidenceChainState {
  status: EvidenceChainStatus
  data: EvidenceChainResponse | null
  /** Human-readable error when status === 'error'. */
  error: string | null
}

type Action =
  | { type: 'RESET' }
  | { type: 'OK'; payload: EvidenceChainResponse }
  | { type: 'EMPTY' }
  | { type: 'ERROR'; payload: string }

const LOADING_STATE: EvidenceChainState = {
  status: 'loading',
  data: null,
  error: null,
}

function reducer(state: EvidenceChainState, action: Action): EvidenceChainState {
  switch (action.type) {
    case 'RESET':
      return LOADING_STATE
    case 'OK':
      return { status: 'ok', data: action.payload, error: null }
    case 'EMPTY':
      return { status: 'empty', data: null, error: null }
    case 'ERROR':
      return { status: 'error', data: null, error: action.payload }
    default:
      return state
  }
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useEvidenceChain(ip: string | null): EvidenceChainState {
  const [state, dispatch] = useReducer(reducer, LOADING_STATE)

  useEffect(() => {
    if (!ip) return

    dispatch({ type: 'RESET' })
    let cancelled = false

    fetchEvidenceChain(ip)
      .then((data) => {
        if (cancelled) return
        if (data === null) {
          // 404 — IP has no stored events; render factors without links.
          dispatch({ type: 'EMPTY' })
        } else {
          dispatch({ type: 'OK', payload: data })
        }
      })
      .catch((err: unknown) => {
        if (cancelled) return
        const msg =
          err instanceof ApiError
            ? `Evidence unavailable (${err.status})`
            : 'Failed to load evidence chain'
        dispatch({ type: 'ERROR', payload: msg })
      })

    return () => {
      cancelled = true
    }
  }, [ip])

  return state
}
