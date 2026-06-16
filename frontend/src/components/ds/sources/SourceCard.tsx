/**
 * SourceCard (DS shell) — settings card chrome for one ingest source.
 *
 * ADR-0062 §A — collapse-by-default, active-first layout:
 *   - The header is now a disclosure `button` (WAI-ARIA Disclosure pattern).
 *   - The body + actions region collapses when `collapsible` is true and the
 *     card is not expanded.
 *   - `defaultExpanded` drives the expansion state. When the source becomes
 *     Active (defaultExpanded transitions false→true), the card auto-expands.
 *     When the user manually toggles, the user's choice takes effect immediately.
 *   - `headerSlot` is an optional right-side slot in the header for the Active
 *     toggle (ADR-0062 §B) — rendered next to the status pill.
 *
 * State model:
 *   `userOverride: boolean | null` — null means "follow defaultExpanded".
 *   When null: expanded = defaultExpanded (auto-expand when source becomes Active).
 *   When set: expanded = userOverride (user explicitly toggled).
 *   This avoids setState-in-effect while preserving reactive expansion behavior.
 *
 * ADR-0019: React + TS. No per-source hardcoding.
 */

import { useState, type HTMLAttributes, type ReactNode } from 'react'

export type SourceCardStatus = 'active' | 'listening' | 'syncing' | 'error' | 'idle'

export interface SourceCardProps extends HTMLAttributes<HTMLDivElement> {
  /** Source name shown in the header. */
  name: ReactNode
  /** Leading emoji (☁️ WAF, 🛰️ IDS, 📡 syslog…). */
  icon?: ReactNode
  /** Connection state — drives the ● status colour. */
  status?: SourceCardStatus
  /** Status text (defaults to the status value). */
  statusText?: ReactNode
  /**
   * Optional right-side header slot — rendered between the status pill and the
   * collapse affordance. Used by the page-level SourceCard to place the Active
   * toggle (ADR-0062 §B) in the always-visible header.
   *
   * Clicking this slot must NOT trigger the disclosure toggle (the slot handles
   * its own click events). The slot is rendered inside a stopPropagation wrapper
   * so toggling the Active switch does not expand/collapse the card.
   */
  headerSlot?: ReactNode
  /** 2-column config grid content (labels + inputs, driven by rjsf in F4). */
  children?: ReactNode
  /** Action buttons row (Sync / Test / Save…). */
  actions?: ReactNode
  /** Error message (monospace red block) when the source is failing. */
  error?: ReactNode
  /** Transient success message. */
  success?: ReactNode
  /**
   * When true, the card body + actions collapse into the header.
   * WAI-ARIA Disclosure pattern: header is `button` + `aria-expanded`.
   * Defaults to false (always-expanded, backwards-compatible).
   */
  collapsible?: boolean
  /**
   * Whether the card should be expanded. Only meaningful when `collapsible` is true.
   * Active sources should start expanded; Inactive sources collapsed.
   * Defaults to true (expanded) so existing renders are unchanged when
   * collapsible is not set.
   *
   * Reactive: when this transitions from false→true (source becomes Active),
   * the card auto-expands (userOverride is null → follows defaultExpanded).
   * Manual user toggle is preserved until the next prop change clears the override.
   */
  defaultExpanded?: boolean
}

function statusColor(status: SourceCardStatus): string {
  switch (status) {
    case 'active':
    case 'listening':
      return 'var(--fw-green)'
    case 'error':
      return 'var(--fw-red)'
    case 'syncing':
      return 'var(--fw-accent)'
    case 'idle':
    default:
      return 'var(--fw-t3)'
  }
}

export function SourceCard({
  name,
  icon,
  status = 'idle',
  statusText,
  headerSlot,
  children,
  actions,
  error,
  success,
  collapsible = false,
  defaultExpanded = true,
  className = '',
  style,
  ...rest
}: SourceCardProps) {
  // ADR-0062 §A: "userOverride" state model.
  // null → follow defaultExpanded (reactive: auto-expands when source becomes Active).
  // boolean → user explicitly toggled; their choice holds until the next cycle.
  // When defaultExpanded changes from false→true, the component auto-expands
  // because userOverride is null and expanded derives directly from defaultExpanded.
  const [userOverride, setUserOverride] = useState<boolean | null>(null)
  const expanded = userOverride !== null ? userOverride : defaultExpanded

  // When collapsible, the body is hidden unless expanded.
  // When not collapsible, always show the body (original behaviour).
  const bodyVisible = !collapsible || expanded

  function handleToggle() {
    setUserOverride((prev) => {
      // If user hasn't overridden yet, toggling flips from defaultExpanded.
      const current = prev !== null ? prev : defaultExpanded
      return !current
    })
  }

  return (
    <div
      className={`fw-srccard ${className}`}
      data-testid="ds-source-card"
      data-collapsible={collapsible ? 'true' : undefined}
      data-expanded={collapsible ? String(expanded) : undefined}
      style={{
        background: 'var(--fw-bg-card)',
        border: '1px solid var(--fw-border)',
        borderRadius: 'var(--fw-r-card)',
        overflow: 'hidden',
        fontFamily: 'var(--fw-font-ui)',
        ...style,
      }}
      {...rest}
    >
      {/* Header — disclosure button when collapsible, static div otherwise */}
      {collapsible ? (
        <div
          style={{
            padding: '12px 16px',
            borderBottom: bodyVisible ? '1px solid var(--fw-border)' : 'none',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 8,
          }}
        >
          {/* Left: name + icon — acts as the disclosure trigger */}
          <button
            type="button"
            aria-expanded={expanded}
            onClick={handleToggle}
            data-testid="ds-source-card-toggle"
            style={{
              background: 'none',
              border: 'none',
              padding: 0,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              fontSize: 'var(--fw-fs-h3)',
              fontWeight: 'var(--fw-fw-semibold)',
              color: 'var(--fw-t1)',
              flex: 1,
              minWidth: 0,
              textAlign: 'left',
              fontFamily: 'var(--fw-font-ui)',
            }}
          >
            {icon ? <span aria-hidden="true">{icon}</span> : null}
            {name}
          </button>

          {/* Right: status pill + headerSlot (Active toggle) + chevron */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
            <span
              data-status={status}
              style={{
                fontSize: 'var(--fw-fs-sm)',
                color: statusColor(status),
                fontWeight: 'var(--fw-fw-medium)',
              }}
            >
              {statusText ?? `● ${status}`}
            </span>

            {/* headerSlot: Active toggle — stopPropagation so it doesn't trigger expand/collapse */}
            {headerSlot ? (
              <span
                data-testid="ds-source-card-header-slot"
                onClick={(e) => e.stopPropagation()}
                style={{ display: 'flex', alignItems: 'center' }}
              >
                {headerSlot}
              </span>
            ) : null}

            {/* Collapse affordance chevron */}
            <button
              type="button"
              aria-expanded={expanded}
              aria-label={expanded ? 'Collapse card' : 'Expand card'}
              onClick={handleToggle}
              data-testid="ds-source-card-chevron"
              style={{
                background: 'none',
                border: 'none',
                padding: '2px 4px',
                cursor: 'pointer',
                color: 'var(--fw-t3)',
                fontSize: 12,
                lineHeight: 1,
                display: 'flex',
                alignItems: 'center',
              }}
            >
              {expanded ? '▲' : '▼'}
            </button>
          </div>
        </div>
      ) : (
        // Non-collapsible: original static header
        <div
          style={{
            padding: '12px 16px',
            borderBottom: '1px solid var(--fw-border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <span
            style={{
              fontSize: 'var(--fw-fs-h3)',
              fontWeight: 'var(--fw-fw-semibold)',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              color: 'var(--fw-t1)',
            }}
          >
            {icon ? <span aria-hidden="true">{icon}</span> : null}
            {name}
          </span>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span
              data-status={status}
              style={{
                fontSize: 'var(--fw-fs-sm)',
                color: statusColor(status),
                fontWeight: 'var(--fw-fw-medium)',
              }}
            >
              {statusText ?? `● ${status}`}
            </span>
            {headerSlot ? (
              <span
                data-testid="ds-source-card-header-slot"
                style={{ display: 'flex', alignItems: 'center' }}
              >
                {headerSlot}
              </span>
            ) : null}
          </div>
        </div>
      )}

      {/* Collapsible body region */}
      {bodyVisible ? (
        <>
          {/* Config grid body */}
          {children ? (
            <div
              style={{
                padding: '14px 16px',
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: '0 16px',
              }}
            >
              {children}
            </div>
          ) : null}

          {/* Actions row */}
          {actions ? (
            <div
              style={{
                padding: '0 16px 14px',
                display: 'flex',
                gap: 8,
                alignItems: 'center',
                flexWrap: 'wrap',
              }}
            >
              {actions}
            </div>
          ) : null}

          {/* Error block */}
          {error ? (
            <div
              role="alert"
              style={{
                margin: '0 16px 12px',
                padding: '10px 12px',
                background: 'rgba(239,68,68,0.082)',
                color: 'var(--fw-red)',
                borderRadius: 'var(--fw-r-sm)',
                border: '1px solid var(--fw-tint-red-bd)',
                fontSize: 'var(--fw-fs-sm)',
                fontFamily: 'var(--fw-font-mono)',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
              }}
            >
              {error}
            </div>
          ) : null}

          {/* Success row */}
          {success ? (
            <div
              role="status"
              style={{
                margin: '0 16px 12px',
                fontSize: 'var(--fw-fs-sm)',
                color: 'var(--fw-green)',
              }}
            >
              {success}
            </div>
          ) : null}
        </>
      ) : null}
    </div>
  )
}
