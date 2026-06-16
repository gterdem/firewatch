/**
 * useRuleAnalysis — rule-only fast-path hook for the IP entity panel (issue #268).
 *
 * Called unconditionally when the panel opens. Hits GET /threats/{ip}/detailed?ai=false
 * to retrieve rule-derived fields WITHOUT invoking the LLM. Completes in the same
 * latency class as GET /threats/{ip} (~5ms) so rule sections render immediately.
 *
 * The result always carries ai_status='skipped' (server honesty — ADR-0035). The
 * panel uses this as the fast first-paint while useDeepAnalysis fetches the AI pass.
 *
 * SECURITY (ADR-0029 D3): all attacker-controlled fields must be rendered as text nodes.
 */

import { useEffect, useReducer } from 'react'
import { fetchDetailedAnalysis, fetchRules } from '../../../api/logs'
import type { DetailedAnalysis, RuleDescription } from '../../../api/types'
import { ApiError } from '../../../api/client'

// ---------------------------------------------------------------------------
// State shape + reducer
// ---------------------------------------------------------------------------

export interface RuleAnalysisState {
  /** Rule-only analysis result (ai_status='skipped'). null = not loaded / error. */
  ruleAnalysis: DetailedAnalysis | null | 'loading'
  rules: RuleDescription[]
  error: string | null
}

type RuleAction =
  | { type: 'RESET' }
  | { type: 'OK'; analysis: DetailedAnalysis | null; rules: RuleDescription[] }
  | { type: 'ERR'; payload: string }

const LOADING_STATE: RuleAnalysisState = {
  ruleAnalysis: 'loading',
  rules: [],
  error: null,
}

function reducer(state: RuleAnalysisState, action: RuleAction): RuleAnalysisState {
  switch (action.type) {
    case 'RESET':
      return LOADING_STATE
    case 'OK':
      return { ruleAnalysis: action.analysis, rules: action.rules, error: null }
    case 'ERR':
      return { ruleAnalysis: null, rules: [], error: action.payload }
    default:
      return state
  }
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Fetch rule-only analysis for one IP.
 * Hits GET /threats/{ip}/detailed?ai=false — always completes fast, never blocks on LLM.
 */
export function useRuleAnalysis(ip: string | null): RuleAnalysisState {
  const [state, dispatch] = useReducer(reducer, LOADING_STATE)

  useEffect(() => {
    if (!ip) return

    dispatch({ type: 'RESET' })

    let cancelled = false

    // Fire rule-only fetch and rules catalog in parallel.
    Promise.all([fetchDetailedAnalysis(ip, /* includeAi */ false), fetchRules()])
      .then(([analysis, rules]) => {
        if (!cancelled) dispatch({ type: 'OK', analysis, rules })
      })
      .catch((err: unknown) => {
        if (!cancelled)
          dispatch({
            type: 'ERR',
            payload:
              err instanceof ApiError
                ? `Rule analysis unavailable (${err.status})`
                : 'Failed to load rule analysis',
          })
      })

    return () => {
      cancelled = true
    }
  }, [ip])

  return state
}
