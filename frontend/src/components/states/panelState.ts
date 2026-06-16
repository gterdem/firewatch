/**
 * panelState — thin helper for choosing between Loading / Error / Empty / Ready.
 *
 * A panel calls `resolvePanelState({ loading, error, isEmpty })` and renders
 * the appropriate state component based on the returned discriminant.
 * This keeps the branch logic out of render functions and centralises the
 * priority ordering (loading > error > empty > ready).
 *
 * Usage:
 *   const state = resolvePanelState({ loading, error, isEmpty: data.length === 0 })
 *   if (state === 'loading') return <LoadingState />
 *   if (state === 'error')   return <ErrorState headline={error!} />
 *   if (state === 'empty')   return <EmptyState headline="…" />
 *   // else: state === 'ready' — render the actual panel content
 *
 * Issue #98.
 */

export type PanelStateKind = 'loading' | 'error' | 'empty' | 'ready'

interface PanelStateInput {
  loading: boolean
  error: string | null
  isEmpty: boolean
}

/**
 * Resolves which panel state to show based on the three flags.
 *
 * Priority: loading > error > empty > ready.
 *   - loading: always takes precedence — a spinner before any data is known.
 *   - error: a failed fetch overrides any stale empty/ready state.
 *   - empty: data arrived but the result set is empty.
 *   - ready: data arrived and there is at least one item to show.
 */
export function resolvePanelState({ loading, error, isEmpty }: PanelStateInput): PanelStateKind {
  if (loading) return 'loading'
  if (error !== null) return 'error'
  if (isEmpty) return 'empty'
  return 'ready'
}
