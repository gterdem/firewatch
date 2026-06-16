/**
 * ThreatActors — bounded top-N threat actor table (issue #205).
 * Wave-2: DDoS-aware rollup, distributed-attack banner, Top-movers sort (issue #212).
 * Issue #262: 5-column layout restored — LAST ACTIVE column re-added (#241 dropped it
 * as a stopgap when the pane was 1/3 width; now at ~60% width (~600 px) it fits.
 * useColumnPriority (#263) hides LAST ACTIVE first if the container somehow shrinks.
 * ScoreBadge compact variant (#263) used in Score column to keep cells tight.
 * Issue #264: count lines → drill-through links with #246 CellTooltip peek.
 *
 * Data: GET /threats (ThreatScore[]) — no separate endpoint needed.
 * Columns: IP · Last Active · Events · Blocked (Badge) · Score (ScoreBadge compact).
 *
 * Issue #205 changes:
 *   - Show at most TOP_N (6) actor rows, sorted by score descending.
 *   - Score-0 actors are excluded from rows (score=0 ⇒ not a threat actor).
 *   - Excluded/overflow actors shown as count text lines, not rows:
 *       "+68 below threshold"  (score-0 excluded actors)
 *       "+12 more"             (scored actors that overflow TOP_N)
 *   - IP column uses ClickableIp (#202) → entity slide-over.
 *   - Score column uses ScoreBadge (#200) — no local band thresholds.
 *   - "View all →" navigates to /ai (the AI Analysis per-IP table, the existing
 *     full sortable list of scored threat actors — confirmed full-actor surface).
 *   - No inner scrollbar at any data volume (Maintainer's hard rule).
 *
 * Issue #212 changes (wave-2):
 *   - WHEN scored-actor count > ROLLUP_CUTOFF (50): switch to ASN//24 group rows.
 *   - One-line distributed-attack banner when rollup is active.
 *   - Top-movers sort toggle (proxy: first_seen recency — flag in actorRollup.ts).
 *   - GroupedActorRow clicks open the slide-over group view (breadcrumb: group → IP).
 *
 * Issue #264 changes:
 *   - "+N more" and "+N below threshold" are now drill-through links (--fw-blue,
 *     chevron affordance, role="button", keyboard-operable).
 *   - "+N more" → /ai (score-descending, same as "View all →").
 *   - "+N below threshold" → /ai?filter=below-threshold (AIRoute reads + applies param).
 *   - Hover/focus on either count line shows a CellTooltip (#246) with next 5 actors
 *     (IP · score) as a progressive peek before committing to the full page.
 *   - Peek for "+N more" uses the overflow scored actors (already in memory).
 *   - Peek for "+N below threshold" uses the belowThreshold actors (already in memory).
 *   - Navigation works even when peek data is absent (peek is progressive enhancement).
 *
 * Row model is factored as ActorRow union:
 *   FlatActorRow  — wave-1 per-IP row.
 *   GroupedActorRow — wave-2 ASN//24 rollup row.
 *
 * SECURITY (ADR-0029 D3): all string fields are attacker-controlled.
 * Rendered as text nodes only — no dangerouslySetInnerHTML.
 *
 * ADR-0028 D6: colors via --fw-* tokens only.
 * ADR-0036 D1: score band derived from threat_level (ScoreBadge), never re-derived.
 *
 * Layout mirrors kit:
 *   <thead> IP / Last Active / Events / Blocked / Score
 *   <tbody> top-N scored rows (FlatRow or GroupRow)
 *   count lines: "+N more" overflow / "+N below threshold"
 *   footer:  "View all →" link → /ai
 */

import { useMemo, useState } from 'react'
import type { RefObject } from 'react'
import { useNavigate } from 'react-router-dom'
import type { ThreatScore } from '../../api/types'
import { Badge, CellTooltip, useColumnPriority } from '../ds'
import type { BadgeTone, ColumnDef } from '../ds'
import ClickableIp from '../entity/ClickableIp'
import { ScoreBadge } from '../ds'
import { useEntityPanel } from '../entity/EntityPanelContext'
import {
  ROLLUP_CUTOFF,
  groupThreats,
  sortThreats,
  type ActorGroup,
  type SortMode,
} from '../../lib/actorRollup'
import { parseApiTimestamp } from '../../lib/time'
import TimeText from './TimeText'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Maximum actor rows shown in the pane. Default 6 (kit layout). */
const TOP_N = 6

/** Maximum actors shown in the drill-through peek tooltip. */
const PEEK_N = 5

// ---------------------------------------------------------------------------
// Column definitions (issue #263 useColumnPriority contract)
// ---------------------------------------------------------------------------

/**
 * Column definitions for the threat-actors table.
 * IP and Score are `never: true` — always shown (primary triage signals).
 * LAST ACTIVE is priority 3 (drops first on narrow containers).
 * Events and Blocked are priority 2.
 *
 * At the 2:3 bento width (~600 px at 1400 px maxWidth + 300 px sidebar) all 5
 * columns fit. useColumnPriority handles graceful degradation if the container
 * unexpectedly shrinks (e.g. responsive breakpoints).
 *
 * minWidth estimates (px):
 *   ip         — 110 px (IPv4 monospace + ClickableIp)
 *   last-active— 80 px  (relative label "3h ago")
 *   events     — 60 px  (right-aligned number)
 *   blocked    — 65 px  (badge)
 *   score      — 46 px  (compact numeric chip)
 */
const COLUMN_DEFS: ColumnDef[] = [
  { key: 'ip',          priority: 1, never: true, minWidth: 110 },
  { key: 'last-active', priority: 3,              minWidth: 80  },
  { key: 'events',      priority: 2,              minWidth: 60  },
  { key: 'blocked',     priority: 2,              minWidth: 65  },
  { key: 'score',       priority: 1, never: true, minWidth: 46  },
]

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ThreatActorsProps {
  threats: ThreatScore[]
}

/** Wave-1: plain per-IP row. */
interface FlatActorRow {
  kind: 'flat'
  threat: ThreatScore
}

/** Wave-2: ASN or /24 CIDR rollup group row. */
interface GroupedActorRow {
  kind: 'grouped'
  group: ActorGroup
}

type ActorRow = FlatActorRow | GroupedActorRow

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function blockedTone(pct: number): BadgeTone {
  if (pct >= 80) return 'critical'
  if (pct >= 50) return 'high'
  if (pct >= 20) return 'medium'
  return 'low'
}

// ---------------------------------------------------------------------------
// CountDrillRow — drill-through count line with CellTooltip peek (#264)
// ---------------------------------------------------------------------------

interface CountDrillRowProps {
  /**
   * The count label text, e.g. "+12 more" or "+68 below threshold".
   * Rendered as text node only (SECURITY ADR-0029 D3 — count is computed, not attacker-supplied).
   */
  label: string
  /** Destination path — e.g. "/ai" or "/ai?filter=below-threshold". */
  href: string
  /** data-testid for the outer <tr>. */
  testId: string
  /**
   * Up to PEEK_N actors to show in the tooltip peek.
   * When empty the tooltip is omitted (peek is progressive enhancement).
   */
  peekActors: ThreatScore[]
  /** Navigation callback — separated from href so tests can assert it without JSDOM routing. */
  onActivate: () => void
  /**
   * colSpan for the <td> — pass visibleColumns.size so the cell spans all visible columns.
   * Defaults to 4 (the original fixed count) for backward compatibility.
   */
  colSpan?: number
}

/**
 * Peek tooltip content: up to 5 actors shown as IP · score rows.
 * SECURITY (ADR-0029 D3): source_ip is attacker-controlled — text node only.
 */
function PeekContent({ actors }: { actors: ThreatScore[] }) {
  return (
    <div
      style={{ display: 'flex', flexDirection: 'column', gap: 3 }}
      data-testid="count-drill-peek"
    >
      {actors.map((a) => (
        <div
          key={a.source_ip}
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            gap: 12,
            fontSize: 11,
          }}
        >
          <span
            style={{ fontFamily: 'var(--fw-font-mono)', color: 'var(--fw-t1)' }}
            data-testid="peek-ip"
          >
            {String(a.source_ip)}
          </span>
          <span
            style={{ fontFamily: 'var(--fw-font-mono)', color: 'var(--fw-t3)' }}
            data-testid="peek-score"
          >
            {a.score}
          </span>
        </div>
      ))}
    </div>
  )
}

/**
 * A table row that renders a count line as a first-class drill-through link.
 *
 * - Styled as a link (--fw-blue, chevron › affordance).
 * - role="button" + tabIndex=0 so it is keyboard-operable (Enter / Space).
 * - Wraps the link text in CellTooltip (#246) when peekActors is non-empty,
 *   showing up to PEEK_N actors (IP · score) on hover/focus.
 * - Navigation always works regardless of peek availability (progressive enhancement).
 */
function CountDrillRow({
  label,
  testId,
  peekActors,
  onActivate,
  colSpan = 4,
}: CountDrillRowProps) {
  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      onActivate()
    }
  }

  const linkContent = (
    <span
      style={{
        color: 'var(--fw-blue)',
        cursor: 'pointer',
        fontSize: 11,
        fontFamily: 'var(--fw-font-ui)',
        display: 'inline-flex',
        alignItems: 'center',
        gap: 2,
      }}
    >
      {label}
      {/* Chevron affordance — aria-hidden because it is decorative */}
      <span aria-hidden="true" style={{ fontSize: 10, opacity: 0.7 }}>›</span>
    </span>
  )

  return (
    <tr data-testid={testId}>
      <td
        colSpan={colSpan}
        style={{
          padding: '4px 10px',
          borderBottom: '1px solid var(--fw-border)',
        }}
      >
        <span
          role="button"
          tabIndex={0}
          data-testid={`${testId}-link`}
          onClick={onActivate}
          onKeyDown={handleKeyDown}
          style={{ display: 'inline-flex', alignItems: 'center' }}
          aria-label={`${label} — navigate to full list`}
        >
          {peekActors.length > 0 ? (
            <CellTooltip
              content={<PeekContent actors={peekActors.slice(0, PEEK_N)} />}
              data-testid={`${testId}-tooltip-trigger`}
            >
              {linkContent}
            </CellTooltip>
          ) : (
            linkContent
          )}
        </span>
      </td>
    </tr>
  )
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

/** Renders a single flat actor row. */
function FlatRow({ threat, visibleColumns }: { threat: ThreatScore; visibleColumns: Set<string> }) {
  const pct =
    threat.total_events > 0
      ? Math.round((threat.blocked_events / threat.total_events) * 100)
      : 0

  const lastSeenDate = threat.last_seen ? parseApiTimestamp(threat.last_seen) : null

  return (
    <tr
      data-testid="threat-actor-row"
      style={{ cursor: 'default' }}
    >
      {/* IP — always shown (never: true) */}
      <td style={{ padding: '5px 6px', borderBottom: '1px solid var(--fw-border)', fontSize: 12 }}>
        <ClickableIp value={threat.source_ip} style={{ fontSize: 11 }} />
      </td>

      {/* LAST ACTIVE — restored in #262 (was dropped in #241 for space in 1/3-width pane;
          now at ~60% width the column fits). Hidden by useColumnPriority on narrow containers. */}
      {visibleColumns.has('last-active') && (
        <td
          style={{
            padding: '5px 6px',
            borderBottom: '1px solid var(--fw-border)',
            fontSize: 11,
            color: 'var(--fw-t3)',
            whiteSpace: 'nowrap',
          }}
          data-testid="threat-actor-last-active"
        >
          {lastSeenDate
            ? <TimeText date={lastSeenDate} style="datetime" spanStyle={{ fontSize: 11, color: 'var(--fw-t3)' }} />
            : <span style={{ color: 'var(--fw-t3)' }}>—</span>}
        </td>
      )}

      {/* EVENTS */}
      {visibleColumns.has('events') && (
        <td
          style={{
            padding: '5px 6px',
            borderBottom: '1px solid var(--fw-border)',
            fontSize: 12,
            textAlign: 'right',
            fontFamily: 'var(--fw-font-mono)',
          }}
        >
          {threat.total_events.toLocaleString()}
        </td>
      )}

      {/* BLOCKED */}
      {visibleColumns.has('blocked') && (
        <td
          style={{
            padding: '5px 6px',
            borderBottom: '1px solid var(--fw-border)',
            textAlign: 'right',
          }}
        >
          <Badge tone={blockedTone(pct)}>
            {threat.blocked_events.toLocaleString()}
          </Badge>
        </td>
      )}

      {/* SCORE — always shown (never: true); compact variant to keep cell tight */}
      <td
        style={{
          padding: '5px 6px',
          borderBottom: '1px solid var(--fw-border)',
          textAlign: 'right',
        }}
      >
        <ScoreBadge
          score={threat.score}
          threatLevel={threat.threat_level}
          scoreBreakdown={threat.score_breakdown}
          variant="compact"
        />
      </td>
    </tr>
  )
}

/** Renders a single ASN//24 rollup group row. */
function GroupRow({ group, visibleColumns }: { group: ActorGroup; visibleColumns: Set<string> }) {
  const { openEntity } = useEntityPanel()
  const pct =
    group.totalEvents > 0
      ? Math.round((group.totalBlockedEvents / group.totalEvents) * 100)
      : 0

  function handleClick() {
    openEntity({ kind: group.kind, value: group.label, meta: group })
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      handleClick()
    }
  }

  return (
    <tr
      data-testid="threat-actor-group-row"
      style={{ cursor: 'pointer' }}
      onClick={handleClick}
      onKeyDown={handleKeyDown}
      tabIndex={0}
      role="button"
      aria-label={`Open group ${group.label}`}
    >
      {/* IP/group label — always shown */}
      <td style={{ padding: '5px 6px', borderBottom: '1px solid var(--fw-border)', fontSize: 12 }}>
        <span
          style={{
            fontFamily: 'var(--fw-font-mono)',
            color: 'var(--fw-blue)',
            fontWeight: 600,
            fontSize: 11,
          }}
          data-testid="group-row-label"
        >
          {group.label}
        </span>
        <span
          style={{
            fontSize: 10,
            color: 'var(--fw-t3)',
            marginLeft: 6,
          }}
        >
          {group.memberCount.toLocaleString()} IPs
        </span>
      </td>

      {/* LAST ACTIVE — rollup uses topSeen from the group's most recent member */}
      {visibleColumns.has('last-active') && (
        <td
          style={{
            padding: '5px 6px',
            borderBottom: '1px solid var(--fw-border)',
            fontSize: 11,
            color: 'var(--fw-t3)',
            whiteSpace: 'nowrap',
          }}
          data-testid="threat-actor-last-active"
        >
          {group.topMembers[0]?.last_seen
            ? <TimeText
                date={parseApiTimestamp(group.topMembers[0].last_seen)}
                style="datetime"
                spanStyle={{ fontSize: 11, color: 'var(--fw-t3)' }}
              />
            : <span style={{ color: 'var(--fw-t3)' }}>—</span>}
        </td>
      )}

      {/* EVENTS */}
      {visibleColumns.has('events') && (
        <td
          style={{
            padding: '5px 6px',
            borderBottom: '1px solid var(--fw-border)',
            fontSize: 12,
            textAlign: 'right',
            fontFamily: 'var(--fw-font-mono)',
          }}
        >
          {group.totalEvents.toLocaleString()}
        </td>
      )}

      {/* BLOCKED */}
      {visibleColumns.has('blocked') && (
        <td
          style={{
            padding: '5px 6px',
            borderBottom: '1px solid var(--fw-border)',
            textAlign: 'right',
          }}
        >
          <Badge tone={blockedTone(pct)}>
            {group.totalBlockedEvents.toLocaleString()}
          </Badge>
        </td>
      )}

      {/* SCORE — always shown; compact variant */}
      <td
        style={{
          padding: '5px 6px',
          borderBottom: '1px solid var(--fw-border)',
          textAlign: 'right',
        }}
      >
        <ScoreBadge
          score={group.topScore}
          threatLevel={group.topThreatLevel}
          scoreBreakdown={group.topMembers[0]?.score_breakdown}
          variant="compact"
        />
      </td>
    </tr>
  )
}

// ---------------------------------------------------------------------------
// Distributed-attack banner
// ---------------------------------------------------------------------------

interface RollupBannerProps {
  totalCount: number
}

/** One-line banner shown when rollup is active (rollup event = detection signal). */
function RollupBanner({ totalCount }: RollupBannerProps) {
  return (
    <div
      data-testid="rollup-banner"
      style={{
        padding: '6px 10px',
        marginBottom: 8,
        borderRadius: 4,
        background: 'color-mix(in srgb, var(--fw-orange) 12%, transparent)',
        border: '1px solid color-mix(in srgb, var(--fw-orange) 30%, transparent)',
        fontSize: 12,
        color: 'var(--fw-t2)',
        display: 'flex',
        alignItems: 'center',
        gap: 6,
      }}
    >
      <span
        style={{ color: 'var(--fw-orange)', fontWeight: 700, flexShrink: 0 }}
        aria-hidden="true"
      >
        !
      </span>
      <span>
        <strong style={{ color: 'var(--fw-t1)' }}>{totalCount.toLocaleString()}</strong>{' '}
        distinct sources in window — showing ASN rollup (likely distributed attack)
      </span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function ThreatActors({ threats }: ThreatActorsProps) {
  const navigate = useNavigate()
  const [sortMode, setSortMode] = useState<SortMode>('score')

  // useColumnPriority — responsive hiding for the 5-column table (issue #263).
  // containerRef wraps the table so ResizeObserver can track the pane width.
  const { containerRef, visibleColumns } = useColumnPriority(COLUMN_DEFS)

  if (threats.length === 0) {
    return (
      <p
        style={{ fontSize: 12, color: 'var(--fw-t3)', textAlign: 'center', padding: '16px 0' }}
        data-testid="threat-actors-empty"
      >
        No threat actors detected
      </p>
    )
  }

  // Partition: scored (score > 0) vs below-threshold (score === 0)
  const allScored = threats.filter((t) => t.score > 0)
  const belowThreshold = threats.filter((t) => t.score === 0)

  // Rollup decision: when scored count exceeds cutoff, switch to group rows.
  const isRollup = allScored.length > ROLLUP_CUTOFF

  // Build rows — memoized to stay O(n) at volume.
  // eslint-disable-next-line react-hooks/rules-of-hooks
  const { rows, overflowCount, overflowActors } = useMemo(() => {
    if (isRollup) {
      // Group mode: groupThreats returns groups sorted by topScore desc.
      const groups = groupThreats(allScored)
      const visibleGroups = groups.slice(0, TOP_N)
      const overflow = groups.length - visibleGroups.length
      const groupRows: ActorRow[] = visibleGroups.map(
        (group): GroupedActorRow => ({ kind: 'grouped', group }),
      )
      // In rollup mode there are no per-IP overflow actors for peek — return empty.
      return { rows: groupRows, overflowCount: overflow, overflowActors: [] as ThreatScore[] }
    }

    // Flat mode: sort then slice.
    const sorted = sortThreats(allScored, sortMode)
    const visible = sorted.slice(0, TOP_N)
    const overflow = sorted.length - visible.length
    // The actors beyond TOP_N are the peek candidates for "+N more" tooltip.
    const extras = sorted.slice(TOP_N, TOP_N + PEEK_N)
    const flatRows: ActorRow[] = visible.map(
      (threat): FlatActorRow => ({ kind: 'flat', threat }),
    )
    return { rows: flatRows, overflowCount: overflow, overflowActors: extras }
  }, [isRollup, allScored, sortMode])

  return (
    <div data-testid="threat-actors">
      {/* Distributed-attack banner — shown when rollup is active */}
      {isRollup && <RollupBanner totalCount={allScored.length} />}

      {/* Sort toggle — only shown in flat mode (rollup always sorts by top score) */}
      {!isRollup && (
        <div
          style={{
            display: 'flex',
            gap: 4,
            justifyContent: 'flex-end',
            marginBottom: 4,
          }}
          data-testid="sort-toggle"
        >
          <button
            type="button"
            data-testid="sort-by-score"
            onClick={() => setSortMode('score')}
            style={{
              background: sortMode === 'score' ? 'var(--fw-blue)' : 'none',
              border: `1px solid ${sortMode === 'score' ? 'var(--fw-blue)' : 'var(--fw-border)'}`,
              color: sortMode === 'score' ? 'var(--fw-on-dark)' : 'var(--fw-t3)',
              cursor: 'pointer',
              fontSize: 10,
              padding: '2px 8px',
              borderRadius: 4,
              fontFamily: 'var(--fw-font-ui)',
            }}
          >
            Top score
          </button>
          <button
            type="button"
            data-testid="sort-by-top-movers"
            onClick={() => setSortMode('top-movers')}
            style={{
              background: sortMode === 'top-movers' ? 'var(--fw-blue)' : 'none',
              border: `1px solid ${sortMode === 'top-movers' ? 'var(--fw-blue)' : 'var(--fw-border)'}`,
              color: sortMode === 'top-movers' ? 'var(--fw-on-dark)' : 'var(--fw-t3)',
              cursor: 'pointer',
              fontSize: 10,
              padding: '2px 8px',
              borderRadius: 4,
              fontFamily: 'var(--fw-font-ui)',
            }}
          >
            Top movers
          </button>
        </div>
      )}

      {/* No overflow: container must not introduce its own scrollbar (Maintainer's hard rule).
          containerRef attached so useColumnPriority can observe width changes. */}
      <div ref={containerRef as RefObject<HTMLDivElement>}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          {/*
            5-column layout: LAST ACTIVE restored in #262 (was dropped in #241 as stopgap).
            The 2:3 bento gives Threat actors ~60% width (~600 px) — enough for all 5 columns.
            useColumnPriority hides LAST ACTIVE first (priority 3) if the container shrinks.
            colSpan on footer/count rows = visibleColumns.size (dynamic).
          */}
          <tr>
            {/* IP — always shown */}
            <th
              style={{
                textAlign: 'left',
                padding: '6px 6px',
                fontSize: 10,
                color: 'var(--fw-t3)',
                textTransform: 'uppercase',
                letterSpacing: 0.5,
                borderBottom: '1px solid var(--fw-border)',
                fontWeight: 600,
              }}
            >
              IP
            </th>

            {/* LAST ACTIVE — responsive */}
            {visibleColumns.has('last-active') && (
              <th
                style={{
                  textAlign: 'left',
                  padding: '6px 6px',
                  fontSize: 10,
                  color: 'var(--fw-t3)',
                  textTransform: 'uppercase',
                  letterSpacing: 0.5,
                  borderBottom: '1px solid var(--fw-border)',
                  fontWeight: 600,
                  whiteSpace: 'nowrap',
                }}
                data-testid="col-last-active"
              >
                Last Active
              </th>
            )}

            {/* EVENTS — responsive */}
            {visibleColumns.has('events') && (
              <th
                style={{
                  textAlign: 'right',
                  padding: '6px 6px',
                  fontSize: 10,
                  color: 'var(--fw-t3)',
                  textTransform: 'uppercase',
                  letterSpacing: 0.5,
                  borderBottom: '1px solid var(--fw-border)',
                  fontWeight: 600,
                }}
              >
                Events
              </th>
            )}

            {/* BLOCKED — responsive */}
            {visibleColumns.has('blocked') && (
              <th
                style={{
                  textAlign: 'right',
                  padding: '6px 6px',
                  fontSize: 10,
                  color: 'var(--fw-t3)',
                  textTransform: 'uppercase',
                  letterSpacing: 0.5,
                  borderBottom: '1px solid var(--fw-border)',
                  fontWeight: 600,
                }}
              >
                Blocked
              </th>
            )}

            {/* SCORE — always shown */}
            <th
              style={{
                textAlign: 'right',
                padding: '6px 6px',
                fontSize: 10,
                color: 'var(--fw-t3)',
                textTransform: 'uppercase',
                letterSpacing: 0.5,
                borderBottom: '1px solid var(--fw-border)',
                fontWeight: 600,
              }}
              data-testid="col-score"
            >
              Score
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            if (row.kind === 'flat') {
              return <FlatRow key={row.threat.source_ip} threat={row.threat} visibleColumns={visibleColumns} />
            }
            if (row.kind === 'grouped') {
              return <GroupRow key={row.group.key} group={row.group} visibleColumns={visibleColumns} />
            }
            return null
          })}

          {/* "+N more" overflow count — drill-through to /ai (#264) */}
          {overflowCount > 0 && (
            <CountDrillRow
              label={`+${overflowCount} more`}
              href="/ai"
              testId="threat-actors-overflow"
              peekActors={overflowActors}
              onActivate={() => navigate('/ai')}
              colSpan={visibleColumns.size}
            />
          )}

          {/* "+N below threshold" — drill-through to /ai?filter=below-threshold (#264) */}
          {belowThreshold.length > 0 && (
            <CountDrillRow
              label={`+${belowThreshold.length} below threshold`}
              href="/ai?filter=below-threshold"
              testId="threat-actors-below-threshold"
              peekActors={belowThreshold}
              onActivate={() => navigate('/ai?filter=below-threshold')}
              colSpan={visibleColumns.size}
            />
          )}

          {/* "View all →" footer — navigates to /ai (AI Analysis per-IP table) */}
          <tr>
            <td
              colSpan={visibleColumns.size}
              style={{ textAlign: 'center', padding: 8 }}
            >
              <button
                type="button"
                data-testid="threat-actors-view-all"
                onClick={() => navigate('/ai')}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--fw-blue)',
                  cursor: 'pointer',
                  fontSize: 12,
                  fontFamily: 'var(--fw-font-ui)',
                  padding: 0,
                }}
              >
                View all →
              </button>
            </td>
          </tr>
        </tbody>
        </table>
      </div>
    </div>
  )
}
