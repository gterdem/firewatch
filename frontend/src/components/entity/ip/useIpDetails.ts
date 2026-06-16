/**
 * useIpDetails — fast-path fetch hook for the IP entity panel (ADR-0037).
 *
 * Encapsulates the score + event-timeline fetches:
 *   1. GET /threats/{ip}         — fast (~5ms). Renders header + m-stats immediately.
 *   2. GET /threats/{ip}/events  — DEF-1 per-event timeline (#118/159); non-fatal.
 *
 * Detailed analysis is handled by useRuleAnalysis (fast rule-only, ?ai=false)
 * and useDeepAnalysis (health-gated LLM call) — issue #268 staged AI loading.
 *
 * Returns score + ipEvents state needed by IpScoreSection and EventTimeline.
 * SECURITY (ADR-0029 D3): callers must render all values as text nodes only.
 */

import { useEffect, useReducer } from 'react'
import {
  fetchThreatScore,
  fetchIpEvents,
} from '../../../api/logs'
import type {
  ThreatScore,
  IpEventTimelineResponse,
} from '../../../api/types'
import { ApiError } from '../../../api/client'

// ---------------------------------------------------------------------------
// State shape + reducer
// ---------------------------------------------------------------------------

export interface IpDetailsState {
  // Fast path
  score: ThreatScore | null | 'loading'
  scoreError: string | null

  // DEF-1 per-event timeline
  ipEvents: IpEventTimelineResponse | null | 'loading'
}

type Action =
  | { type: 'RESET' }
  | { type: 'SCORE_OK'; payload: ThreatScore | null }
  | { type: 'SCORE_ERR'; payload: string }
  | { type: 'EVENTS_OK'; payload: IpEventTimelineResponse | null }
  | { type: 'EVENTS_ERR' }

const LOADING_STATE: IpDetailsState = {
  score: 'loading',
  scoreError: null,
  ipEvents: 'loading',
}

function reducer(state: IpDetailsState, action: Action): IpDetailsState {
  switch (action.type) {
    case 'RESET':
      return LOADING_STATE
    case 'SCORE_OK':
      return { ...state, score: action.payload, scoreError: null }
    case 'SCORE_ERR':
      return { ...state, score: null, scoreError: action.payload }
    case 'EVENTS_OK':
      return { ...state, ipEvents: action.payload }
    case 'EVENTS_ERR':
      return { ...state, ipEvents: null }
    default:
      return state
  }
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useIpDetails(ip: string | null): IpDetailsState {
  const [state, dispatch] = useReducer(reducer, LOADING_STATE)

  useEffect(() => {
    if (!ip) return

    dispatch({ type: 'RESET' })

    let cancelled = false

    // Fast fetch — render header + m-stats + attack badges immediately.
    fetchThreatScore(ip)
      .then((s) => {
        if (!cancelled) dispatch({ type: 'SCORE_OK', payload: s })
      })
      .catch((err: unknown) => {
        if (!cancelled)
          dispatch({
            type: 'SCORE_ERR',
            payload:
              err instanceof ApiError
                ? `Score unavailable (${err.status})`
                : 'Failed to load threat score',
          })
      })

    // DEF-1: per-event timeline — non-fatal; 404 → fall back to coarse (OD-3).
    fetchIpEvents(ip)
      .then((events) => {
        if (!cancelled) dispatch({ type: 'EVENTS_OK', payload: events })
      })
      .catch(() => {
        // Any non-404 error: fall back to coarse build (null = use coarse).
        if (!cancelled) dispatch({ type: 'EVENTS_ERR' })
      })

    return () => {
      cancelled = true
    }
  }, [ip])

  return state
}
