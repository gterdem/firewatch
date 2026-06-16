/**
 * HealthCard — #246 CellTooltip mini health-card popover content (issue #281).
 *
 * Renders the rich popover content for a source-health chip.  Two modes:
 *
 *   Single instance  — one source for this type.
 *     Shows: display name, status word, last event time (local + UTC via
 *     lib/time.ts), event count, supervisor state, sanitized last_error.
 *     WHERE health="not_configured": includes "Configure →" deep-link.
 *
 *   Multi-instance   — N instances share this source_type.
 *     Header row:  "<TypeLabel> · N instances"
 *     Per-instance rows:  source_id · health word · event count · last event
 *     Same "Configure →" link per unconfigured instance.
 *
 * Issue #335 (amended by ADR-0032 Amendment 1 R1 / issue #377):
 *   The "freshness threshold legend" chip row now shows OPERATIONAL vocabulary:
 *     green = ingesting (event within freshness window)
 *     amber = configured, no recent events
 *     red   = collector failure (parked / backoff / last_error)
 *     grey  = not configured
 *   The green/amber boundary uses the API `freshness_minutes` value, not a
 *   hardcoded constant.  Pass `freshnessMinutes` to both card variants.
 *
 * Issue #378 (ADR-0032 Amendment 1 R2):
 *   When health=amber, the tooltip splits into honest sub-states using
 *   `last_sync_status`:
 *     verified quiet  — last poll "ok", no new events
 *     never connected — no completed sync (last_sync_status is null)
 *     stale           — last sync was "error" or "no_data" some time ago
 *   Text nodes only (ADR-0029 D3).
 *
 * SECURITY (ADR-0029 D3):
 *   All values rendered as React text nodes — never via innerHTML /
 *   dangerouslySetInnerHTML. last_error is pre-sanitized server-side; we
 *   treat it as text nonetheless (defence-in-depth).
 *
 * Accessibility:
 *   This component renders inside a CellTooltip (role="tooltip"); it does
 *   not carry its own role. All text is rendered as text nodes.
 *
 * Styling:
 *   DS tokens only — no raw hex (ADR-0028 D6).
 */

import type { ReactNode } from 'react'
import type { SourceTypeGroup, SourceHealthItem } from '../../../lib/sourceHealth'
import { dotStateFromHealth } from '../../../lib/sourceHealth'
import { parseApiTimestamp, formatLocal, formatUtc } from '../../../lib/time'
import { formatRelativeTime } from '../../../lib/freshnessLadder'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Health → human-readable status word. */
const HEALTH_LABEL: Record<string, string> = {
  ok: 'Healthy',
  amber: 'No recent events',
  red: 'Error',
  not_configured: 'Not configured',
}

/** Map DotState → color token. */
const DOT_COLOR: Record<string, string> = {
  ok: 'var(--fw-health-ok)',
  warn: 'var(--fw-health-warn)',
  down: 'var(--fw-health-down)',
  idle: 'var(--fw-health-idle)',
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Render a colored status dot for inline use inside card rows. */
function StatusDot({ health }: { health: string }) {
  const state = dotStateFromHealth(health)
  return (
    <span
      aria-hidden="true"
      style={{
        display: 'inline-block',
        width: 7,
        height: 7,
        borderRadius: '50%',
        background: DOT_COLOR[state] ?? 'var(--fw-health-idle)',
        opacity: state === 'idle' ? 0.5 : 1,
        flexShrink: 0,
        marginTop: 1,
      }}
    />
  )
}

/** Format a nullable ISO timestamp as "local (UTC)" string, or "—" when absent. */
function formatTimePair(iso: string | null): string {
  if (!iso) return '—'
  const d = parseApiTimestamp(iso)
  const local = formatLocal(d, 'datetime')
  const utc = formatUtc(d)
  if (!local) return '—'
  return `${local} (${utc})`
}

/** Format an event count with thousands separators, or "—" when 0. */
function formatCount(n: number): string {
  if (n === 0) return '—'
  return n.toLocaleString()
}

/**
 * "Configure →" link row — shown when health is not_configured.
 * settingsHref is the deep-link to the Settings card for this source type.
 * Rendered as an <a> so keyboard and click both work.
 */
function ConfigureLink({ href }: { href: string }): ReactNode {
  return (
    <div style={{ marginTop: 8 }}>
      <a
        href={href}
        data-testid="health-card-configure-link"
        style={{
          fontSize: 'var(--fw-fs-xs)',
          color: 'var(--fw-blue)',
          textDecoration: 'none',
          fontWeight: 'var(--fw-fw-semibold)',
          display: 'inline-flex',
          alignItems: 'center',
          gap: 3,
        }}
      >
        Configure →
      </a>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Section label
// ---------------------------------------------------------------------------

function SectionLabel({ children }: { children: ReactNode }) {
  return (
    <div
      style={{
        fontSize: 'var(--fw-fs-2xs)',
        color: 'var(--fw-t3)',
        textTransform: 'uppercase',
        letterSpacing: 'var(--fw-ls-tight)',
        fontWeight: 'var(--fw-fw-semibold)',
        marginBottom: 4,
      }}
    >
      {children}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Amber sub-state (R2 — ADR-0032 Amendment 1 issue #378)
// ---------------------------------------------------------------------------

/**
 * Return the honest amber sub-state message based on sync evidence.
 *
 * Splits single amber into three states (ADR-0032 Amendment 1 R2):
 *   verified quiet — last poll completed OK, no new events (last_sync_status="ok")
 *   stale          — last sync was error or no_data some time ago (last_sync_status set but not ok)
 *   never connected — no completed sync since configuration (last_sync_status=null)
 */
function amberSubStateText(item: SourceHealthItem): string {
  // lastSyncAt/lastSyncStatus are optional (R2 additive fields); treat absence as null.
  const syncAt = item.lastSyncAt ?? null
  const syncStatus = item.lastSyncStatus ?? null
  if (syncStatus === 'ok') {
    const timeAgo = formatRelativeTime(syncAt)
    return timeAgo
      ? `Quiet — last poll OK ${timeAgo}, no new events`
      : 'Quiet — last poll OK, no new events'
  }
  if (syncStatus === 'no_data' || syncStatus === 'error') {
    const timeAgo = formatRelativeTime(syncAt)
    return timeAgo
      ? `Last successful poll ${timeAgo}`
      : 'Last successful poll unknown'
  }
  // null/undefined — no completed sync cycle
  return 'No events since configuration — check connection settings'
}

// ---------------------------------------------------------------------------
// Operational legend (R1 — ADR-0032 Amendment 1 issue #377)
// ---------------------------------------------------------------------------

/**
 * OperationalLegend — self-teaching dot legend shown at the bottom of every
 * HealthCard tooltip (replaces the recency-ladder from issue #335).
 *
 * ADR-0032 Amendment 1 R1 / issue #377:
 *   The old "green ≤2m / amber 2–60m / red >60m" recency ladder is deleted.
 *   The dot answers "is this collector working?", not "how old is the newest event?"
 *
 *   green = ingesting (event within freshness window — server `FRESHNESS_MINUTES`)
 *   amber = configured, no recent events (stale or quiet)
 *   red   = collector failure (parked / backoff / last_error)
 *   grey  = not configured
 *
 * The green/amber boundary text is rendered from `freshnessMinutes` (from GET
 * /stats `freshness_minutes`) — never a hardcoded constant.
 *
 * Also shows the last event relative time when available (contextual only).
 */
function OperationalLegend({
  lastEventAt,
  freshnessMinutes,
}: {
  lastEventAt: string | null
  freshnessMinutes: number
}) {
  const relTime = formatRelativeTime(lastEventAt)

  return (
    <div
      data-testid="freshness-legend"
      style={{
        marginTop: 10,
        paddingTop: 8,
        borderTop: '1px solid var(--fw-border)',
      }}
    >
      {/* Relative time of last ingested event */}
      {relTime && (
        <div
          data-testid="freshness-last-ingested"
          style={{
            fontSize: 'var(--fw-fs-xs)',
            color: 'var(--fw-t2)',
            marginBottom: 5,
          }}
        >
          last ingested {relTime}
        </div>
      )}

      {/* Operational vocabulary legend (R1) */}
      <div
        data-testid="freshness-threshold-legend"
        style={{
          display: 'flex',
          gap: 8,
          flexWrap: 'wrap',
        }}
      >
        <span
          data-testid="freshness-legend-ok"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 3,
            fontSize: 'var(--fw-fs-2xs)',
            color: 'var(--fw-t3)',
          }}
        >
          <span
            aria-hidden="true"
            style={{
              display: 'inline-block',
              width: 6,
              height: 6,
              borderRadius: '50%',
              background: 'var(--fw-health-ok)',
            }}
          />
          ingesting ({'≤'}{freshnessMinutes}m)
        </span>
        <span
          data-testid="freshness-legend-amber"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 3,
            fontSize: 'var(--fw-fs-2xs)',
            color: 'var(--fw-t3)',
          }}
        >
          <span
            aria-hidden="true"
            style={{
              display: 'inline-block',
              width: 6,
              height: 6,
              borderRadius: '50%',
              background: 'var(--fw-health-warn)',
            }}
          />
          no recent events
        </span>
        <span
          data-testid="freshness-legend-red"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 3,
            fontSize: 'var(--fw-fs-2xs)',
            color: 'var(--fw-t3)',
          }}
        >
          <span
            aria-hidden="true"
            style={{
              display: 'inline-block',
              width: 6,
              height: 6,
              borderRadius: '50%',
              background: 'var(--fw-health-down)',
            }}
          />
          collector failure
        </span>
        <span
          data-testid="freshness-legend-grey"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 3,
            fontSize: 'var(--fw-fs-2xs)',
            color: 'var(--fw-t3)',
          }}
        >
          <span
            aria-hidden="true"
            style={{
              display: 'inline-block',
              width: 6,
              height: 6,
              borderRadius: '50%',
              background: 'var(--fw-health-idle)',
              opacity: 0.5,
            }}
          />
          not configured
        </span>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Single-instance card content
// ---------------------------------------------------------------------------

function SingleInstanceCard({
  item,
  settingsHref,
  freshnessMinutes,
}: {
  item: SourceHealthItem
  settingsHref: string
  freshnessMinutes: number
}) {
  const statusWord = HEALTH_LABEL[item.health] ?? item.health
  const timePair = formatTimePair(item.lastEventAt)
  const count = formatCount(item.eventCount)

  return (
    <div data-testid="health-card-single" style={{ minWidth: 200 }}>
      {/* Header: display name + colored status */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          marginBottom: 8,
          paddingBottom: 6,
          borderBottom: '1px solid var(--fw-border)',
        }}
      >
        <StatusDot health={item.health} />
        <span
          data-testid="health-card-label"
          style={{
            fontSize: 'var(--fw-fs-sm)',
            fontWeight: 'var(--fw-fw-semibold)',
            color: 'var(--fw-t1)',
          }}
        >
          {String(item.label)}
        </span>
        <span
          data-testid="health-card-status-word"
          style={{
            fontSize: 'var(--fw-fs-xs)',
            color: 'var(--fw-t2)',
          }}
        >
          {String(statusWord)}
        </span>
      </div>

      {/* Details grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'auto 1fr',
          gap: '3px 8px',
          fontSize: 'var(--fw-fs-xs)',
          color: 'var(--fw-t2)',
        }}
      >
        <span style={{ color: 'var(--fw-t3)' }}>Last event</span>
        <span data-testid="health-card-last-event">{timePair}</span>

        <span style={{ color: 'var(--fw-t3)' }}>Events</span>
        <span data-testid="health-card-event-count">{count}</span>

        {item.supervisorState && (
          <>
            <span style={{ color: 'var(--fw-t3)' }}>Supervisor</span>
            <span data-testid="health-card-supervisor">{String(item.supervisorState)}</span>
          </>
        )}

        {item.lastError && (
          <>
            <span style={{ color: 'var(--fw-t3)' }}>Error</span>
            <span
              data-testid="health-card-last-error"
              style={{ color: 'var(--fw-health-down)' }}
            >
              {String(item.lastError)}
            </span>
          </>
        )}

        {/* R2: amber sub-state — honest provenance for "no recent events" */}
        {item.health === 'amber' && (
          <>
            <span style={{ color: 'var(--fw-t3)' }}>Status</span>
            <span data-testid="health-card-amber-detail" style={{ color: 'var(--fw-t2)' }}>
              {amberSubStateText(item)}
            </span>
          </>
        )}
      </div>

      {/* "Configure →" deep-link for not_configured instances */}
      {item.health === 'not_configured' && <ConfigureLink href={settingsHref} />}

      {/* Operational legend (R1 — replaces recency ladder) */}
      <OperationalLegend lastEventAt={item.lastEventAt} freshnessMinutes={freshnessMinutes} />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Multi-instance card content
// ---------------------------------------------------------------------------

function MultiInstanceCard({
  group,
  buildSettingsHref,
  freshnessMinutes,
}: {
  group: SourceTypeGroup
  buildSettingsHref: (sourceType: string) => string
  freshnessMinutes: number
}) {
  return (
    <div data-testid="health-card-multi" style={{ minWidth: 240 }}>
      {/* Header: type label + instance count */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          marginBottom: 6,
          paddingBottom: 6,
          borderBottom: '1px solid var(--fw-border)',
        }}
      >
        <span
          data-testid="health-card-type-label"
          style={{
            fontSize: 'var(--fw-fs-sm)',
            fontWeight: 'var(--fw-fw-semibold)',
            color: 'var(--fw-t1)',
          }}
        >
          {String(group.typeLabel)}
        </span>
        <span
          data-testid="health-card-instance-count"
          style={{ fontSize: 'var(--fw-fs-xs)', color: 'var(--fw-t3)' }}
        >
          · {group.instances.length} instances
        </span>
      </div>

      {/* Per-instance rows */}
      <SectionLabel>Instance</SectionLabel>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        {group.instances.map((inst) => {
          const statusWord = HEALTH_LABEL[inst.health] ?? inst.health
          const timePair = formatTimePair(inst.lastEventAt)
          const count = formatCount(inst.eventCount)
          return (
            <div
              key={inst.id}
              data-testid={`health-card-instance-${inst.id}`}
              style={{
                display: 'grid',
                gridTemplateColumns: 'auto 1fr auto auto',
                gap: '0 6px',
                alignItems: 'center',
                fontSize: 'var(--fw-fs-xs)',
                paddingBottom: 3,
                borderBottom: '1px solid var(--fw-border-faint, var(--fw-border))',
              }}
            >
              <StatusDot health={inst.health} />
              <span
                data-testid={`health-card-instance-id-${inst.id}`}
                style={{
                  color: 'var(--fw-t1)',
                  fontFamily: 'var(--fw-font-mono)',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
              >
                {String(inst.id)}
              </span>
              <span
                data-testid={`health-card-instance-status-${inst.id}`}
                style={{ color: 'var(--fw-t2)', whiteSpace: 'nowrap' }}
              >
                {String(statusWord)}
              </span>
              <span
                data-testid={`health-card-instance-count-${inst.id}`}
                style={{ color: 'var(--fw-t3)', whiteSpace: 'nowrap' }}
              >
                {count}
              </span>
              {/* Last event — full row below (gridColumn spans cols 2–end) */}
              <span />
              <span
                data-testid={`health-card-instance-last-event-${inst.id}`}
                style={{
                  color: 'var(--fw-t3)',
                  gridColumn: '2 / -1',
                  fontSize: 'var(--fw-fs-2xs)',
                  whiteSpace: 'nowrap',
                }}
              >
                {timePair}
              </span>

              {/* "Configure →" deep-link for unconfigured instances */}
              {inst.health === 'not_configured' && (
                <div style={{ gridColumn: '1 / -1', marginTop: 2 }}>
                  <ConfigureLink href={buildSettingsHref(inst.sourceType)} />
                </div>
              )}
            </div>
          )
        })}
      </div>

      {/* Operational legend (R1) — use most-recent lastEventAt across instances */}
      <OperationalLegend
        lastEventAt={
          group.instances
            .map((i) => i.lastEventAt)
            .filter((t): t is string => t !== null)
            .sort()
            .at(-1) ?? null
        }
        freshnessMinutes={freshnessMinutes}
      />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Public component
// ---------------------------------------------------------------------------

export interface HealthCardProps {
  /**
   * The type group to render — contains all instances and the worst-of health.
   * Single-instance groups render the compact card; multi renders the breakdown.
   */
  group: SourceTypeGroup
  /**
   * Build the deep-link href for the Settings card of a given source type.
   * Defaults to "#/settings?source=<type>" when not provided.
   */
  buildSettingsHref?: (sourceType: string) => string
  /**
   * Freshness window in minutes from GET /stats `freshness_minutes` (R1).
   * Determines the green/amber legend text: "ingesting (≤Nm)".
   * Defaults to 5 (the server constant) when the API field is absent.
   */
  freshnessMinutes?: number
}

/**
 * HealthCard — rich popover content for a source-health chip (issue #281).
 *
 * Rendered inside a CellTooltip (the trigger + WCAG wrapper is in HealthDot).
 * This component only provides content — it does not manage open state.
 */
export function HealthCard({ group, buildSettingsHref, freshnessMinutes = 5 }: HealthCardProps) {
  const resolvedHref = buildSettingsHref ?? ((t: string) => `#/settings?source=${t}`)

  if (group.instances.length === 1) {
    return (
      <SingleInstanceCard
        item={group.instances[0]}
        settingsHref={resolvedHref(group.sourceType)}
        freshnessMinutes={freshnessMinutes}
      />
    )
  }

  return (
    <MultiInstanceCard
      group={group}
      buildSettingsHref={resolvedHref}
      freshnessMinutes={freshnessMinutes}
    />
  )
}
