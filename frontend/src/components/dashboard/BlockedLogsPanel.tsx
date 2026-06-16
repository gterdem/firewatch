/**
 * BlockedLogsPanel — "Recently Blocked Network Logs" pane (#253, part-2 P9).
 *
 * Rework changes (vs. the #113 version):
 *
 * 1. Title: "Recently Blocked Network Logs" (honest about recency + scope).
 * 2. Server-filtered blocked feed: action=blocked (#252 shorthand) — no more
 *    load-50-then-client-filter logic; every returned row is BLOCK/DROP.
 * 3. Bounded feed (≤25 rows): no inner scrollbar, no pagination.
 *    "View all →" navigates to /logs?action=blocked.
 * 4. Signature column: rule_name primary, rule_id fallback (EveBox/Security Onion
 *    precedent). Hover/focus reveals sid · category · source via CellTooltip (#246).
 * 5. Backend IP search: the Search-by-IP input debounces 300 ms then issues a
 *    backend query (?ip=) — not a client-side filter over the current 25 rows.
 * 6. Stable tabs: driven from GET /logs/categories (alphabetical), not from the
 *    loaded rows (which reshuffled as data changed).  Tab click = server re-fetch.
 * 7. ClickableIp in Source IP column → entity slide-over (ADR-0037).
 * 8. No inner scrollbar (Maintainer's hard rule): the pane is bounded; View-all handles
 *    deep exploration.
 *
 * Layout:
 *   <Tabs>        — category tabs (stable, endpoint-driven)
 *   <table>       — top-8 rows: Time · Source IP · Severity · Action · Signature
 *   <footer>      — "View all N blocked →" (when >8) or "View in Network Logs →"
 *                   (when ≤8) link to /logs?action=blocked (issue #333)
 *
 * SECURITY (ADR-0029 D3): all log fields are attacker-controlled.
 * Rendered as text nodes only — no dangerouslySetInnerHTML.
 *
 * ADR-0028 D6: colors via DS Badge tones — no raw hex.
 * ADR-0037: IPs via ClickableIp — entity slide-over.
 *
 * Time seam (#244): timestamp column uses parseApiTimestamp + TimeText.
 */

import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Badge, Tabs } from '../ds'
import type { BadgeTone } from '../ds'
import { parseApiTimestamp } from '../../lib/time'
import TimeText from './TimeText'
import { useBlockedLogs } from './useBlockedLogs'
import type { TimeRange } from '../../app/timeRange'
import { useBlockedCategories } from './useBlockedCategories'
import { RuleCellTooltip } from '../logs/RuleCellTooltip'
import ClickableIp from '../entity/ClickableIp'
import { formatIpGeoLabel } from '../../lib/ipGeoCell'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SEV_TONE: Record<string, BadgeTone> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
}
const ACT_TONE: Record<string, BadgeTone> = {
  BLOCK: 'block',
  block: 'block',
  ALLOW: 'allow',
  allow: 'allow',
  ALERT: 'alert',
  alert: 'alert',
  DROP: 'drop',
  drop: 'drop',
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface BlockedLogsPanelProps {
  /** Search query for backend IP filter — controlled by parent. */
  ipSearch: string
  /** Optional time range from the dashboard brush (issue #249).
   *  When null (default), the backend default window applies. */
  timeRange?: TimeRange | null
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function BlockedLogsPanel({ ipSearch, timeRange = null }: BlockedLogsPanelProps) {
  const [cat, setCat] = useState('all')
  const navigate = useNavigate()

  // Stable category tabs from GET /logs/categories (endpoint-driven, alphabetical)
  const { tabItems } = useBlockedCategories()

  // Server-filtered blocked feed: action=blocked + category tab + debounced IP + optional time range
  const { logs, total, loading, error } = useBlockedLogs(cat, ipSearch, timeRange)

  if (loading) {
    return (
      <p
        style={{ fontSize: 12, color: 'var(--fw-t3)', padding: '12px 16px' }}
        data-testid="blocked-logs-loading"
      >
        Loading…
      </p>
    )
  }

  if (error) {
    return (
      <p
        style={{ fontSize: 12, color: 'var(--fw-t3)', padding: '12px 16px' }}
        data-testid="blocked-logs-error"
      >
        Failed to load blocked logs.
      </p>
    )
  }

  return (
    <div data-testid="blocked-logs-panel">
      {/* Category tabs — stable, endpoint-driven order (not row-derived) */}
      <Tabs value={cat} onChange={setCat} items={tabItems} />

      {/* Log table — no inner scrollbar; bounded to top-8 rows (issue #333) */}
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr>
            {(['Time', 'Source IP', 'Severity', 'Action', 'Signature'] as const).map((h) => (
              <th
                key={h}
                style={{
                  textAlign: 'left',
                  padding: '8px 10px',
                  fontSize: 10,
                  color: 'var(--fw-t3)',
                  textTransform: 'uppercase',
                  letterSpacing: 0.5,
                  borderBottom: '1px solid var(--fw-border)',
                  fontWeight: 600,
                }}
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {logs.length === 0 ? (
            <tr>
              <td
                colSpan={5}
                style={{
                  textAlign: 'center',
                  padding: 16,
                  fontSize: 12,
                  color: 'var(--fw-t3)',
                }}
                data-testid="blocked-logs-empty"
              >
                No blocked logs
              </td>
            </tr>
          ) : (
            logs.map((l, i) => {
              const ts = parseApiTimestamp(String(l.timestamp))
              const sevTone = SEV_TONE[l.severity?.toLowerCase?.() ?? ''] ?? 'neutral'
              const actStr = String(l.action ?? '').toUpperCase()
              const actTone = ACT_TONE[actStr] ?? ACT_TONE[String(l.action ?? '')] ?? 'neutral'

              // Signature: rule_name preferred (post-#165), rule_id fallback.
              const ruleName = (l as Record<string, unknown>)['rule_name'] as string | null | undefined
              const ruleId = (l as Record<string, unknown>)['rule_id'] as string | number | null | undefined

              return (
                <tr key={i} data-testid="blocked-log-row">
                  {/* Time */}
                  <td
                    style={{
                      padding: '7px 10px',
                      borderBottom: '1px solid var(--fw-border)',
                      fontFamily: 'var(--fw-font-mono)',
                      fontSize: 11,
                      color: 'var(--fw-t3)',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    <TimeText date={ts} style="time-with-seconds" data-testid="blocked-log-time" />
                  </td>

                  {/* Source IP — ClickableIp → entity slide-over (ADR-0037).
                      Issue #334: geo suffix shows flag + (City, Country) from local
                      cache when present.  ClickableIp retains the bare IP as its
                      value (opens slide-over on click).  The geo text is a non-clickable
                      span alongside it so the interactive affordance is unambiguous.
                      SECURITY (ADR-0029 D3): geo fields from GeoIP cache rendered as
                      text nodes only. */}
                  <td
                    style={{
                      padding: '7px 10px',
                      borderBottom: '1px solid var(--fw-border)',
                      fontSize: 11,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                      maxWidth: 220,
                    }}
                    title={
                      (l as Record<string, unknown>)['geo_city'] ||
                      (l as Record<string, unknown>)['geo_country']
                        ? 'geo cached locally'
                        : undefined
                    }
                    data-testid="blocked-log-ip-cell"
                  >
                    {(() => {
                      const geoCity = (l as Record<string, unknown>)['geo_city'] as string | null | undefined
                      const geoCountry = (l as Record<string, unknown>)['geo_country'] as string | null | undefined
                      const geoLabel = formatIpGeoLabel(l.source_ip, geoCity, geoCountry)
                      // When geo is present, render: [ClickableIp] [geo suffix span]
                      // The geo suffix is the part after the IP (flag + city/country).
                      const geoSuffix = geoLabel.length > l.source_ip.length
                        ? geoLabel.slice(l.source_ip.length)
                        : ''
                      return (
                        <>
                          <ClickableIp value={l.source_ip} style={{ fontSize: 11 }} />
                          {geoSuffix && (
                            <span
                              style={{
                                fontSize: 10,
                                color: 'var(--fw-t3)',
                                fontFamily: 'var(--fw-font-ui)',
                                marginLeft: 3,
                              }}
                              data-testid="blocked-log-ip-geo"
                            >
                              {geoSuffix}
                            </span>
                          )}
                        </>
                      )
                    })()}
                  </td>

                  {/* Severity */}
                  <td
                    style={{
                      padding: '7px 10px',
                      borderBottom: '1px solid var(--fw-border)',
                    }}
                  >
                    <Badge tone={sevTone}>{l.severity}</Badge>
                  </td>

                  {/* Action */}
                  <td
                    style={{
                      padding: '7px 10px',
                      borderBottom: '1px solid var(--fw-border)',
                    }}
                  >
                    {l.action != null ? (
                      <Badge tone={actTone}>{String(l.action)}</Badge>
                    ) : (
                      <span style={{ color: 'var(--fw-t3)', fontSize: 11 }}>—</span>
                    )}
                  </td>

                  {/* Signature — rule_name primary, rule_id fallback; tooltip for sid/cat/src */}
                  <td
                    style={{
                      padding: '7px 10px',
                      borderBottom: '1px solid var(--fw-border)',
                      maxWidth: 280,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    <RuleCellTooltip
                      ruleName={ruleName}
                      ruleId={ruleId}
                      category={l.category}
                      sourceType={l.source_type}
                    />
                  </td>
                </tr>
              )
            })
          )}
        </tbody>
      </table>

      {/* Footer: deep-link to /logs?action=blocked (issue #252, #333).
          - When total > BLOCKED_FEED_LIMIT: "View all {N} blocked →" (true count).
          - When total ≤ BLOCKED_FEED_LIMIT: "View in Network Logs →" (no count claim).
          - When total === 0 (empty state): footer is hidden — nothing to navigate to. */}
      {total > 0 && (
        <div
          style={{
            padding: '8px 12px',
            borderTop: '1px solid var(--fw-border)',
            display: 'flex',
            justifyContent: 'flex-end',
          }}
        >
          <button
            type="button"
            data-testid="blocked-logs-view-all"
            onClick={() => navigate('/logs?action=blocked')}
            style={{
              background: 'none',
              border: 'none',
              cursor: 'pointer',
              fontSize: 12,
              color: 'var(--fw-blue)',
              fontFamily: 'var(--fw-font-ui)',
              padding: '2px 0',
            }}
          >
            {total > logs.length ? `View all ${total} blocked →` : 'View in Network Logs →'}
          </button>
        </div>
      )}
    </div>
  )
}
