/**
 * slideOverMode — session-scoped pinned-state store for the entity slide-over (issue #269).
 *
 * Exposes a minimal subscribe/publish API so that both SlideOver (read) and
 * EntityPanelProvider (write, via the pin toggle callback) share the same
 * in-memory state without a React context or a heavy state library.
 *
 * Session-scoped: state lives in plain module scope — no localStorage, no
 * sessionStorage.  Cleared automatically on page reload.
 *
 * ARIA note (ADR-0037 addendum):
 *   overlay mode  → role="dialog", aria-modal="true", focus trap, Esc closes.
 *   push mode     → role="complementary", aria-modal absent, focus trap released,
 *                   Esc and overlay-click disabled (close via ✕ or unpin only).
 *   Rationale: WAI-ARIA 1.2 §6.3.5 "dialog" requires a focus-trapping modal;
 *   a pinned push-mode side panel is a non-modal complementary region —
 *   equivalent to VS Code's Activity Bar or Elastic EuiFlyout push mode.
 *   Reference: https://www.w3.org/WAI/ARIA/apg/patterns/dialog-modal/
 *              https://www.w3.org/TR/wai-aria-1.2/#complementary
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SlideOverMode = 'overlay' | 'push'

type Listener = (mode: SlideOverMode) => void

// ---------------------------------------------------------------------------
// Module-scope state
// ---------------------------------------------------------------------------

let _mode: SlideOverMode = 'overlay'
const _listeners = new Set<Listener>()

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/** Returns the current mode. */
export function getSlideOverMode(): SlideOverMode {
  return _mode
}

/** Sets the mode and notifies all subscribers. */
export function setSlideOverMode(mode: SlideOverMode): void {
  if (_mode === mode) return
  _mode = mode
  _listeners.forEach((fn) => fn(mode))
}

/** Subscribes to mode changes. Returns an unsubscribe function. */
export function subscribeSlideOverMode(listener: Listener): () => void {
  _listeners.add(listener)
  return () => _listeners.delete(listener)
}

/** Resets to overlay mode (test helper / page unload). */
export function resetSlideOverMode(): void {
  _mode = 'overlay'
  _listeners.forEach((fn) => fn('overlay'))
}
