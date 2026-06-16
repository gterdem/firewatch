/**
 * EntityPanelProvider — app-level host for the entity slide-over panel (ADR-0037).
 *
 * Mounted ONCE in the app layout (App.tsx). Provides:
 *   - EntityPanelActionsContext: STABLE actions value (openEntity/closeEntity/closePanelAll)
 *     wrapped in useMemo — reference never changes after mount (issue #324).
 *   - EntityPanelContext: full state + actions (backward compat) — changes on stack change.
 *   - Breadcrumb stack state (pivot navigation).
 *   - SlideOver shell with entity-specific content (IpPanel for kind="ip").
 *   - Esc key: closes RulePopup first (handled inside IpPanel), then the panel.
 *   - Discovery cache fetched once for the lifetime of the app (for RulePopup hints).
 *   - headerMeta slot: IpHeaderMeta for IP entities (issue #265); the slot is
 *     entity-kind-agnostic in SlideOver — GroupPanel can fill it later.
 *
 * No per-source branching — IpPanel is rendered for kind="ip"; wave-2 adds
 * `kind="asn"` etc. via a simple switch, without changing this provider.
 */

import { useState, useEffect, useCallback, useMemo, useRef, type ReactNode } from 'react'
import { fetchSourceTypes } from '../../api/client'
import { fetchThreatScore } from '../../api/logs'
import type { ThreatScore } from '../../api/types'
import type { SourceTypeEntry } from '../../schema/types'
import { EntityPanelContext, EntityPanelActionsContext } from './EntityPanelContext'
import type { EntityRef } from './EntityPanelContext'
import SlideOver from './SlideOver'
import type { BreadcrumbItem } from './SlideOver'
import IpPanel from './ip/IpPanel'
import IpHeaderMeta from './ip/IpHeaderMeta'
import GroupPanel from './group/GroupPanel'
import type { ActorGroup } from '../../lib/actorRollup'
import CasePanel from './case/CasePanel'
import {
  getSlideOverMode,
  setSlideOverMode,
  subscribeSlideOverMode,
  type SlideOverMode,
} from './slideOverMode'

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

interface EntityPanelProviderProps {
  children: ReactNode
}

export default function EntityPanelProvider({ children }: EntityPanelProviderProps) {
  const [stack, setStack] = useState<EntityRef[]>([])
  const [discoveryCache, setDiscoveryCache] = useState<SourceTypeEntry[]>([])

  // Fast-path ThreatScore for the active IP entity — shared between IpHeaderMeta
  // (headerMeta slot) and IpPanel body (which also fetches it; browser HTTP cache
  // deduplicates the identical GET requests fired within the same session).
  // Non-null only when the active entity is kind="ip". Issue #265.
  const [activeIpScore, setActiveIpScore] = useState<ThreatScore | null | 'loading'>(null)

  // Issue #269: pin/push mode — synced from the slideOverMode module-scope store.
  const [panelMode, setPanelMode] = useState<SlideOverMode>(getSlideOverMode)

  // Ref to the element that triggered the current open — for focus restoration.
  const triggerRef = useRef<HTMLElement | null>(null)

  // Fetch discovery cache once on mount for RulePopup hints (ADR-0034).
  // Non-fatal: hints simply won't appear if discovery fails.
  useEffect(() => {
    let cancelled = false
    fetchSourceTypes()
      .then((types) => {
        if (!cancelled) setDiscoveryCache(types)
      })
      .catch(() => {
        // Non-fatal.
      })
    return () => { cancelled = true }
  }, [])

  // Fast-path score fetch for the active IP entity (issue #265).
  // Feeds IpHeaderMeta in the headerMeta slot. IpPanel fetches the same URL
  // independently; the browser HTTP cache deduplicates same-URL GETs fired in
  // close succession, so no meaningful extra latency is added.
  const activeEntity = stack[stack.length - 1] ?? null
  useEffect(() => {
    const kind = activeEntity?.kind
    const ip = activeEntity?.value ?? ''

    let cancelled = false

    // Kick off the fetch (or resolve to null for non-IP entities) asynchronously
    // so that all setState calls happen in async callbacks, not synchronously in
    // the effect body (avoids the react-hooks/set-state-in-effect lint rule).
    void (async () => {
      if (kind !== 'ip') {
        if (!cancelled) setActiveIpScore(null)
        return
      }
      if (!cancelled) setActiveIpScore('loading')
      try {
        const s = await fetchThreatScore(ip)
        if (!cancelled) setActiveIpScore(s)
      } catch {
        if (!cancelled) setActiveIpScore(null)
      }
    })()

    return () => { cancelled = true }
  }, [activeEntity?.kind, activeEntity?.value])

  // Issue #269: subscribe to slideOverMode store so mode changes propagate to render.
  useEffect(() => {
    return subscribeSlideOverMode((m) => setPanelMode(m))
  }, [])

  // Esc key — close the panel ONLY in overlay mode (push mode: only ✕ or unpin closes).
  // In overlay mode: IpPanel's RulePopup handles its own Esc with stopPropagation.
  useEffect(() => {
    if (stack.length === 0) return
    // Push mode: Esc must NOT close the panel (ADR-0037 addendum / issue #269).
    if (panelMode === 'push') return
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        // IpPanel's RulePopup has its own Esc handler that stops propagation
        // when the popup is open. If we get here, the popup is closed → close panel.
        setStack((prev) => prev.slice(0, -1))
      }
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [stack.length, panelMode])

  // openEntity: push a new entity (capture trigger element for focus restore).
  const openEntity = useCallback((ref: EntityRef) => {
    // Capture the currently focused element as the trigger.
    triggerRef.current = document.activeElement as HTMLElement | null
    setStack((prev) => [...prev, ref])
  }, [])

  // closeEntity: pop the top.
  const closeEntity = useCallback(() => {
    setStack((prev) => prev.slice(0, -1))
  }, [])

  // closePanelAll: clear the entire stack.
  const closePanelAll = useCallback(() => {
    setStack([])
  }, [])

  // ---------------------------------------------------------------------------
  // Issue #324: stable actions context value.
  //
  // useMemo with an empty dep array ensures this object reference NEVER changes
  // after mount. The callbacks themselves are stable (empty useCallback deps).
  // Action-only consumers (DashboardRoute via useEntityActions()) subscribe to
  // EntityPanelActionsContext and do NOT re-render when stack changes.
  // ---------------------------------------------------------------------------
  const stableActions = useMemo(
    () => ({ openEntity, closeEntity, closePanelAll }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  )

  // Issue #269: pin toggle — flips between overlay and push mode.
  const handlePinToggle = useCallback(() => {
    setSlideOverMode(panelMode === 'push' ? 'overlay' : 'push')
  }, [panelMode])

  // isOpen — panel is visible when the stack is non-empty.
  const isOpen = stack.length > 0

  // Build breadcrumb trail from the stack.
  const breadcrumbs: BreadcrumbItem[] = stack.map((ref, i) => {
    const isLast = i === stack.length - 1
    return {
      label: ref.value,
      // Clicking a breadcrumb item (not the last) pops back to that depth.
      onClick: isLast
        ? undefined
        : () => setStack((prev) => prev.slice(0, i + 1)),
    }
  })

  // ariaLabel for the dialog.
  const kindLabel = activeEntity?.kind === 'ip' ? 'IP'
    : activeEntity?.kind === 'asn' ? 'ASN group'
    : activeEntity?.kind === 'cidr' ? 'CIDR group'
    : activeEntity?.kind === 'case' ? 'Case'
    : activeEntity?.kind ?? ''
  const ariaLabel = activeEntity
    ? `${kindLabel} ${activeEntity.value} details`
    : 'Entity details'

  // Render entity content based on kind.
  function renderEntityContent(ref: EntityRef) {
    switch (ref.kind) {
      case 'ip':
        return <IpPanel ip={ref.value} discoveryCache={discoveryCache} />
      case 'asn':
      case 'cidr':
        // Group view — meta carries the ActorGroup computed by actorRollup (issue #212).
        // Cast is safe: ThreatActors always sets meta to ActorGroup when opening a group entity.
        if (ref.meta) {
          return <GroupPanel group={ref.meta as ActorGroup} />
        }
        return (
          <p style={{ color: 'var(--fw-t3)', fontSize: 13 }}>
            Group data unavailable for {ref.value}
          </p>
        )
      case 'case':
        // Case File — slide-over body (ADR-0053 D1 / issue #534).
        return <CasePanel caseId={ref.value} />
      default: {
        // Exhaustiveness guard — all EntityKind values should be handled above.
        const exhaustive: never = ref.kind
        return (
          <p style={{ color: 'var(--fw-t3)', fontSize: 13 }}>
            Unknown entity kind: {String(exhaustive)}
          </p>
        )
      }
    }
  }

  // Build the headerMeta slot for IP entities (issue #265).
  // When the active entity is kind="ip" and the fast score has resolved (or null),
  // IpHeaderMeta renders geo + ASN + first-seen + copy + provenance stamp.
  // The slot is entity-kind-agnostic in SlideOver — GroupPanel can fill it later.
  const headerMeta = activeEntity?.kind === 'ip' && activeIpScore !== 'loading'
    ? <IpHeaderMeta score={activeIpScore} />
    : undefined

  return (
    // Outer: stable actions — NEVER changes after mount (issue #324).
    <EntityPanelActionsContext.Provider value={stableActions}>
      {/* Inner: full state + actions — changes on every stack change (backward compat). */}
      <EntityPanelContext.Provider value={{ stack, openEntity, closeEntity, closePanelAll }}>
        {children}

        <SlideOver
          open={isOpen}
          onClose={closePanelAll}
          ariaLabel={ariaLabel}
          breadcrumbs={breadcrumbs}
          headerMeta={headerMeta}
          triggerRef={triggerRef}
          mode={panelMode}
          onPinToggle={handlePinToggle}
        >
          {activeEntity && renderEntityContent(activeEntity)}
        </SlideOver>
      </EntityPanelContext.Provider>
    </EntityPanelActionsContext.Provider>
  )
}
