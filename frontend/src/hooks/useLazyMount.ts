/**
 * useLazyMount — defer mounting of a component until its sentinel is near the viewport.
 *
 * Issue #504 (UT-05): extreme scroll offsets on the AI Engine page crash headless
 * Chromium because all panels (verdict cards, drift panel) render eagerly, making
 * the full-page layout cost very high. Deferring off-screen panels until they
 * approach the viewport reduces the eager DOM footprint substantially.
 *
 * Usage:
 *   const { sentinelRef, mounted } = useLazyMount()
 *   return (
 *     <div ref={sentinelRef}>
 *       {mounted ? <HeavyPanel /> : null}
 *     </div>
 *   )
 *
 * The sentinel `<div>` is always rendered (zero height, zero cost) so the
 * IntersectionObserver has something to watch. The heavy child mounts once
 * the sentinel enters the viewport (with `rootMargin`), and stays mounted
 * thereafter (no unmounting on scroll-out — that would cause content to jump).
 *
 * Fallback: if IntersectionObserver is not available (SSR, old browser, test
 * env without polyfill), `mounted` is `true` immediately — no behaviour change.
 *
 * ADR-0026: loopback-only; this hook has no network calls.
 */

import { useState, useRef, useEffect, useCallback, type RefObject } from 'react'

/** Default pre-load distance in pixels — start mounting this far before the fold. */
const DEFAULT_ROOT_MARGIN_PX = 300

interface UseLazyMountOptions {
  /**
   * Distance from the viewport edge at which mounting begins (IntersectionObserver
   * rootMargin string). Default: `"300px"` — mount content when the sentinel is
   * within 300px below the fold. Large enough that normal scrolling never sees a
   * flash of empty space; small enough to defer the eager layout cost.
   */
  rootMargin?: string
}

interface UseLazyMountResult {
  /** Attach to the wrapper element that wraps the deferred content. */
  sentinelRef: RefObject<HTMLDivElement | null>
  /**
   * True once the sentinel has entered the viewport.
   * Mount heavy children only when this is true.
   * Always true when IntersectionObserver is unavailable (graceful fallback).
   */
  mounted: boolean
}

export function useLazyMount(options: UseLazyMountOptions = {}): UseLazyMountResult {
  const { rootMargin = `${DEFAULT_ROOT_MARGIN_PX}px` } = options

  // Graceful fallback: if IntersectionObserver isn't available, mount eagerly.
  const hasIO = typeof IntersectionObserver !== 'undefined'
  const [mounted, setMounted] = useState(!hasIO)
  const sentinelRef = useRef<HTMLDivElement>(null)

  const mount = useCallback(() => setMounted(true), [])

  useEffect(() => {
    if (!hasIO) return
    if (mounted) return // already mounted — nothing to observe

    const el = sentinelRef.current
    if (!el) return

    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0]?.isIntersecting) {
          mount()
          observer.disconnect()
        }
      },
      { rootMargin },
    )

    observer.observe(el)

    return () => observer.disconnect()
  }, [hasIO, mounted, mount, rootMargin])

  return { sentinelRef, mounted }
}
