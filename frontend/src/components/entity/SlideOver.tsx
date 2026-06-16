/**
 * SlideOver — generic right-anchored panel shell (ADR-0037).
 *
 * Responsibilities:
 *   - Overlay + right-anchored card (clamp(360px,32vw,560px) wide, full height).
 *   - Focus trap: moves focus into the panel on open, restores to trigger on close.
 *   - Esc handling: only the TOP-OF-STACK layer responds (handled by caller via onEsc).
 *   - WAI-ARIA dialog semantics: role="dialog", aria-modal="true" (overlay mode).
 *   - Overlay click closes (onClose).
 *   - Breadcrumb slot in the header.
 *   - Generic headerMeta slot below the breadcrumb row (issue #265).
 *   - Pin toggle: switches between overlay and push mode (issue #269).
 *   - NO data fetching — pure presentation.
 *
 * ADR-0037: dashboard stays visible behind the overlay (page content not unmounted).
 *
 * Issue #269 — two interaction modes:
 *   overlay mode (default, unpinned):
 *     role="dialog", aria-modal="true", focus-trap active, Esc+overlay-click close.
 *   push mode (pinned):
 *     role="complementary", aria-modal absent, focus-trap released,
 *     Esc and overlay-click DISABLED — close via x or unpin only.
 *     The app-shell shrinks by the panel width so main content shifts without overlap.
 *
 * Issue #338 — docked-pin geometry fixes:
 *   - Panel width: clamp(360px, 32vw, 560px) — never exceeds 560px, never below 360px.
 *   - Body reservation: ResizeObserver on the panel measures the actual rendered
 *     width; paddingRight is set to that exact pixel value (no fixed-size gap).
 *   - Auto-degrade: matchMedia('(min-width: 1280px)') — when the viewport shrinks
 *     below 1280px while pinned, the effective mode degrades to overlay so the bento
 *     grid is never crushed; pin state is preserved and restored when space returns.
 *   - data-docked attribute: set on [data-testid="main-content"] while effectively
 *     docked so the dashboard grid CSS can target it for narrow-breakpoint reflow.
 *
 * Issue #361 — shell-shrink fix (why #338's paddingRight-on-main-content failed):
 *   [data-testid="main-content"] is a maxWidth:1400px / margin:0 auto centred block.
 *   DashboardRoute renders its own inner <main> with the same maxWidth/auto-margin,
 *   meaning it could still extend to the full 1400 px regardless of paddingRight on
 *   the outer element.  The fix targets [data-testid="app-shell"] — a full-width
 *   container with no maxWidth — so all children (header, nav, main) re-centre
 *   within the narrowed viewport space, leaving no content under the fixed panel.
 *
 * A11y rationale (ADR-0037 addendum):
 *   WAI-ARIA 1.2 section 6.3.5 "dialog" requires a modal focus trap.
 *   A pinned push-mode side panel is a non-modal complementary region
 *   (analogous to VS Code's Activity Bar / Elastic EuiFlyout push mode).
 *   We follow ARIA 1.2 section 6.3.5 for overlay and section 6.3.6 for complementary push mode.
 *   References:
 *     https://www.w3.org/WAI/ARIA/apg/patterns/dialog-modal/
 *     https://www.w3.org/TR/wai-aria-1.2/#complementary
 *
 * Post-release deferred (issue #339): drag-to-resize edge + Ctrl+P toggle.
 */

import { useEffect, useRef, useState, type ReactNode } from 'react'
import type { SlideOverMode } from './slideOverMode'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface BreadcrumbItem {
  label: string
  onClick?: () => void
}

interface SlideOverProps {
  /** Whether the panel is open. When false, renders nothing. */
  open: boolean
  /** Called when user clicks the close button or (in overlay mode) overlay or Esc. */
  onClose: () => void
  /** The panel's accessible label (e.g. "IP 203.0.113.1 details"). */
  ariaLabel: string
  /** Optional breadcrumb trail rendered in the header. */
  breadcrumbs?: BreadcrumbItem[]
  /**
   * Optional entity-kind-agnostic meta slot rendered below the breadcrumb row.
   * Filled by the entity panel (e.g. IpHeaderMeta for IP entities, a group
   * summary line for GroupPanel). SlideOver itself has zero knowledge of entity kinds.
   * Issue #265.
   */
  headerMeta?: ReactNode
  /** Panel body content. */
  children: ReactNode
  /** The DOM element that triggered the open — focus is restored here on close. */
  triggerRef?: React.RefObject<HTMLElement | null>
  /**
   * Issue #269: interaction mode.
   *   "overlay" (default) — backdrop, modal semantics, focus trap.
   *   "push"             — no backdrop, complementary semantics, page shifts right.
   */
  mode?: SlideOverMode
  /**
   * Issue #269: called when the user clicks the pin toggle in the header.
   * The parent manages the mode state; SlideOver is a controlled component.
   */
  onPinToggle?: () => void
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Panel width — issue #338.
 * clamp(360px, 32vw, 560px):
 *   - Minimum 360px — readable at smallest viewports.
 *   - 32vw — proportional between min/max.
 *   - Maximum 560px — never crushes a 1280px content area.
 * Both the panel CSS width and the ResizeObserver use this token as the CSS value;
 * the actual rendered pixel value is measured via ResizeObserver for paddingRight.
 * Exported for test assertions (JSDOM cannot evaluate CSS clamp() in computed styles).
 */
export const PANEL_WIDTH = 'clamp(360px, 32vw, 560px)'

/**
 * Auto-degrade breakpoint — issue #338.
 * Below this viewport width, push mode degrades to effective overlay so the
 * bento grid can never be crushed, even if the user has pinned the panel.
 */
const DOCK_BREAKPOINT_QUERY = '(min-width: 1280px)'

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function SlideOver({
  open,
  onClose,
  ariaLabel,
  breadcrumbs = [],
  headerMeta,
  children,
  triggerRef,
  mode = 'overlay',
  onPinToggle,
}: SlideOverProps) {
  const panelRef = useRef<HTMLDivElement>(null)
  const firstFocusableRef = useRef<HTMLElement | null>(null)

  /**
   * Viewport-is-wide state — issue #338 auto-degrade.
   *
   * Tracks whether (min-width: 1280px) is matched.  Initialised synchronously
   * from matchMedia so the first render is already correct (no one-frame flicker).
   *
   * This is the ONLY state we need: effectiveMode is a pure derivation —
   *   mode="push" && isWide  -> 'push'
   *   mode="push" && !isWide -> 'overlay'  (auto-degrade)
   *   mode="overlay"         -> 'overlay'  (always)
   */
  const [isWide, setIsWide] = useState<boolean>(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return true
    return window.matchMedia(DOCK_BREAKPOINT_QUERY).matches
  })

  /**
   * Effective mode — derived from mode prop + viewport width.
   * No separate setState needed; any mode or isWide change re-derives this value.
   */
  const effectiveMode: SlideOverMode = mode === 'push' && isWide ? 'push' : 'overlay'

  const isPush = effectiveMode === 'push'

  // ---------------------------------------------------------------------------
  // Effect: subscribe to matchMedia change events to update isWide.
  // Only needed when the requested mode is 'push' — overlay is never degraded.
  // ---------------------------------------------------------------------------
  useEffect(() => {
    // If mode is overlay, we don't need the media query listener at all.
    if (mode !== 'push') return
    if (typeof window === 'undefined' || !window.matchMedia) return

    const mql = window.matchMedia(DOCK_BREAKPOINT_QUERY)

    // Update isWide in a callback — not synchronously in the effect body.
    const handleChange = (e: MediaQueryListEvent) => {
      setIsWide(e.matches)
    }

    mql.addEventListener('change', handleChange)
    return () => mql.removeEventListener('change', handleChange)
  }, [mode])

  // ---------------------------------------------------------------------------
  // Effect: move focus into the panel on open; restore to trigger on close.
  // In push mode: focus moves into panel on open (still good UX), but no trap.
  // ---------------------------------------------------------------------------
  useEffect(() => {
    if (!open) {
      if (triggerRef?.current) {
        triggerRef.current.focus()
      }
      return
    }

    const panel = panelRef.current
    if (!panel) return

    const focusable = panel.querySelector<HTMLElement>(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
    )
    if (focusable) {
      firstFocusableRef.current = focusable
      focusable.focus()
    }
  }, [open, triggerRef])

  // ---------------------------------------------------------------------------
  // Effect: focus trap — OVERLAY MODE ONLY.
  // Push mode releases the trap so the user can interact with the main content.
  // ---------------------------------------------------------------------------
  useEffect(() => {
    if (!open || isPush) return

    const panel = panelRef.current
    if (!panel) return

    function getFocusable(): HTMLElement[] {
      return Array.from(
        panel!.querySelectorAll<HTMLElement>(
          'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
        ),
      )
    }

    function handleKeyDown(e: KeyboardEvent) {
      if (e.key !== 'Tab') return
      const focusable = getFocusable()
      if (focusable.length === 0) return

      const first = focusable[0]
      const last = focusable[focusable.length - 1]

      if (e.shiftKey) {
        if (document.activeElement === first) {
          e.preventDefault()
          last.focus()
        }
      } else {
        if (document.activeElement === last) {
          e.preventDefault()
          first.focus()
        }
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [open, isPush])

  // ---------------------------------------------------------------------------
  // Effect: shell shrink + data-docked + ResizeObserver — push mode only.
  //
  // Issue #361 — replaces the #338 paddingRight-on-main-content approach.
  //
  // Why #338 failed in the browser:
  //   [data-testid="main-content"] has maxWidth:1400px / margin:0 auto centering.
  //   DashboardRoute renders its own inner <main> with the same maxWidth/auto-margin
  //   which means it could still extend to full width regardless of paddingRight on
  //   the outer element.  At 1440px viewport the inner 1352px of visible content
  //   remained entirely under the fixed panel.
  //
  // Correct approach:
  //   Target [data-testid="app-shell"] — a FULL-WIDTH container with no maxWidth.
  //   Adding paddingRight here reserves viewport space for the fixed panel by
  //   narrowing the entire available width that all children (header, nav, main) see.
  //   maxWidth + margin:auto centering in children then re-centres correctly within
  //   the narrowed space, guaranteeing no overlap at any viewport >= 1280px.
  //
  //   ResizeObserver on the panel measures the actual rendered panel width so the
  //   reservation is always exact (clamp(360px,32vw,560px) resolves differently at
  //   different viewport sizes).
  //
  //   data-docked="true" is still set on [data-testid="main-content"] so the
  //   bento-grid CSS reflow rules in index.css keep working unchanged (they target
  //   children of main-content via a descendant combinator).
  // ---------------------------------------------------------------------------
  useEffect(() => {
    const shell = document.querySelector<HTMLElement>('[data-testid="app-shell"]')
    const main = document.querySelector<HTMLElement>('[data-testid="main-content"]')

    if (!open || !isPush) {
      // Clear reservations on both targets.
      if (shell) {
        shell.style.paddingRight = ''
        shell.style.transition = ''
      }
      if (main) {
        main.removeAttribute('data-docked')
      }
      return
    }

    if (!shell || !main) return

    // Mark main-content as docked so the bento grid CSS can reflow to single-column.
    main.setAttribute('data-docked', 'true')
    // Smooth transition on the full-width shell so the layout shift is not jarring.
    shell.style.transition = 'padding-right 0.2s ease'

    const panel = panelRef.current
    if (!panel) return

    // Measure actual panel width and apply it as paddingRight on the full-width shell.
    // ResizeObserver fires immediately on observe and on any subsequent resize,
    // keeping the reservation pixel-perfect with the rendered panel.
    const ro = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const w =
          entry.borderBoxSize?.[0]?.inlineSize ??
          entry.contentRect?.width ??
          0
        if (w > 0) {
          shell.style.paddingRight = `${Math.round(w)}px`
        }
      }
    })
    ro.observe(panel)

    return () => {
      ro.disconnect()
      if (shell) {
        shell.style.paddingRight = ''
        shell.style.transition = ''
      }
      if (main) {
        main.removeAttribute('data-docked')
      }
    }
  }, [open, isPush])

  if (!open) return null

  return (
    <>
      {/* Overlay — shown in effective overlay mode only. */}
      {!isPush && (
        <div
          data-testid="slide-over-overlay"
          style={{
            position: 'fixed',
            inset: 0,
            // D1 fix (#226): overlay must sit above AppHeader (z-index 100) so the
            // panel header row (breadcrumb + close button) is pointer-reachable.
            // AppHeader is sticky z-index 100; overlay=109, panel=110.
            zIndex: 109,
            background: 'rgba(0,0,0,0.5)',
          }}
          aria-hidden="true"
          onClick={onClose}
        />
      )}

      {/* Right-anchored panel */}
      <div
        ref={panelRef}
        role={isPush ? 'complementary' : 'dialog'}
        {...(!isPush ? { 'aria-modal': 'true' } : {})}
        aria-label={ariaLabel}
        data-testid="slide-over-panel"
        data-mode={effectiveMode}
        style={{
          position: 'fixed',
          top: 0,
          right: 0,
          bottom: 0,
          // D1 fix (#226): panel must sit above AppHeader (z-index 100) so its
          // header row (breadcrumb + close button) is not occluded and is
          // pointer-clickable. AppHeader=100, overlay=109, panel=110.
          zIndex: 110,
          width: PANEL_WIDTH,
          background: 'var(--fw-bg-card)',
          borderLeft: '1px solid var(--fw-border-l)',
          boxShadow: isPush ? 'none' : 'var(--fw-shadow-popup)',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
        }}
      >
        {/* Header */}
        {/*
         * Issue #336: ONE dense row — breadcrumb + inline meta + actions.
         * headerMeta (IpHeaderMeta for IP entities) is rendered inline in the same
         * flex row as the breadcrumb trail, not in a separate block below.
         * This keeps the IP appearing exactly once (breadcrumb last item) and keeps
         * total header height < 48 px (single line of text + 14 px top/bottom padding).
         */}
        <div
          data-testid="slide-over-header"
          style={{
            padding: '10px 20px',
            borderBottom: '1px solid var(--fw-border)',
            flexShrink: 0,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            minHeight: 0,
            overflow: 'hidden',
          }}
        >
          {/* Left region: breadcrumb trail + inline headerMeta (issue #336) */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 4,
              flex: 1,
              minWidth: 0,
              overflow: 'hidden',
            }}
          >
            {/* Breadcrumb trail */}
            <nav
              aria-label="Entity navigation"
              data-testid="slide-over-breadcrumb"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 4,
                fontSize: 13,
                color: 'var(--fw-t2)',
                flexWrap: 'nowrap',
                flexShrink: 0,
              }}
            >
              {breadcrumbs.map((crumb, i) => (
                <span key={i} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  {i > 0 && (
                    <span aria-hidden="true" style={{ color: 'var(--fw-t3)' }}>
                      /
                    </span>
                  )}
                  {crumb.onClick ? (
                    <button
                      type="button"
                      data-testid={`breadcrumb-${i}`}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: 'var(--fw-blue)',
                        cursor: 'pointer',
                        fontSize: 13,
                        padding: 0,
                        fontFamily: 'var(--fw-font-mono)',
                      }}
                      onClick={crumb.onClick}
                    >
                      {crumb.label}
                    </button>
                  ) : (
                    <span
                      data-testid={`breadcrumb-${i}`}
                      style={{
                        fontFamily: 'var(--fw-font-mono)',
                        color: 'var(--fw-t1)',
                        fontWeight: 600,
                      }}
                    >
                      {crumb.label}
                    </span>
                  )}
                </span>
              ))}
            </nav>

            {/* Generic entity meta slot (issue #265, #336): rendered INLINE in the header
                row rather than as a separate block below. IpHeaderMeta for IP panels;
                GroupPanel can fill this later. Truncates on narrow widths (overflow:hidden
                on the parent propagates). */}
            {headerMeta && (
              <div
                data-testid="slide-over-header-meta"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  minWidth: 0,
                  overflow: 'hidden',
                  flexShrink: 1,
                }}
              >
                {headerMeta}
              </div>
            )}
          </div>

          {/* Right region: pin toggle + close button */}
          <div style={{ display: 'flex', alignItems: 'center', flexShrink: 0, marginLeft: 8 }}>
            {/* Issue #269: Pin toggle button */}
            {onPinToggle && (
              <button
                type="button"
                data-testid="slide-over-pin-toggle"
                aria-label={mode === 'push' ? 'Unpin panel (return to overlay)' : 'Pin panel (push mode — page shifts)'}
                aria-pressed={mode === 'push'}
                title={mode === 'push' ? 'Unpin (return to overlay)' : 'Pin (dock panel — page shifts)'}
                style={{
                  background: mode === 'push' ? 'var(--fw-bg-input)' : 'none',
                  border: mode === 'push' ? '1px solid var(--fw-border-l)' : 'none',
                  color: mode === 'push' ? 'var(--fw-amber)' : 'var(--fw-t3)',
                  fontSize: 14,
                  cursor: 'pointer',
                  lineHeight: 1,
                  padding: '2px 8px',
                  borderRadius: 4,
                  flexShrink: 0,
                  marginRight: 6,
                }}
                onClick={onPinToggle}
              >
                {/* Pin icon: a simple push-pin glyph (U+1F4CC / U+1F4CD).
                    Pinned = filled pin (docked); unpinned = slanted outline. */}
                {mode === 'push' ? '\u{1F4CC}' : '\u{1F4CD}'}
              </button>
            )}

            {/* Close button */}
            <button
              type="button"
              data-testid="slide-over-close"
              aria-label={isPush ? 'Close panel' : 'Close (Esc)'}
              style={{
                background: 'none',
                border: 'none',
                color: 'var(--fw-t3)',
                fontSize: 20,
                cursor: 'pointer',
                lineHeight: 1,
                padding: '0 0 0 12px',
                flexShrink: 0,
              }}
              onClick={onClose}
            >
              &#x2715;
            </button>
          </div>
        </div>

        {/* Scrollable body
         *
         * UT-01 (#501): flex: 1 alone does NOT create a bounded scroll container in a
         * flex-column parent — the default min-height: auto for flex items allows the
         * child to grow beyond the parent's height. Adding minHeight: 0 overrides this
         * so the body is bounded by the panel's fixed height (top:0/bottom:0) and
         * overflowY: 'auto' actually creates an inner scroll region.
         * The header above has flexShrink: 0 (unchanged) so it stays fixed.
         * ADR-0043 D3: an inner scroll inside a slide-over panel is acceptable;
         * the no-inner-scrollbar rule applies only to cards/panels embedded in a page.
         */}
        <div
          data-testid="slide-over-body"
          style={{
            flex: 1,
            minHeight: 0,
            overflowY: 'auto',
            padding: '16px 20px',
          }}
        >
          {children}
        </div>
      </div>
    </>
  )
}
