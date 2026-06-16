/**
 * AnalyticsCharts — summary charts for the Analytics view (v2 kit restyle, MF-5 #162).
 *
 * Renders data from:
 *   GET /analytics/summary              — KPI StatCards (total events, blocked, IPs,
 *                                         block rate, top country, top rule).
 *   GET /analytics/categories-timeline  — category event counts over time.
 *
 * V2 restyle (MF-5 #162):
 *   - KPI tiles replaced with DS StatCard (fw-stat) from the DS barrel.
 *   - Category hues applied to timeline header and data cells via --fw-* token
 *     inline styles (no raw hex, F5 #111). Source: legacy colors-categories.card.html.
 *   - data-category attributes on th/td enable CSS and test assertions.
 *
 * The real /analytics/summary shape (ADR-0029 D1, store.get_analytics_summary):
 *   { total_ips, total_events, total_blocked, block_rate,
 *     top_country, unique_countries, top_rule }
 *
 * Category timeline shape confirmed from sqlite_store.py (fix #93):
 *   wide/pivoted rows — one row per period, each category as a named column.
 *
 * All data is rendered as text nodes — no dangerouslySetInnerHTML.
 */

import { StatCard } from '../ds'
import type { AnalyticsSummary, CategoryTimelineBucket } from '../../api/types'

interface AnalyticsChartsProps {
  summary: AnalyticsSummary
  timeline: CategoryTimelineBucket[]
}

/**
 * The category columns present in the wide-row response from
 * GET /analytics/categories-timeline, in display order.
 *
 * Shape confirmed from sqlite_store.py::get_categories_timeline (fix #93):
 * the server returns one row per period with each category as a named column.
 *
 * Hues from legacy/FireWatch SOC Design System/guidelines/colors-categories.card.html,
 * mapped to --fw-* tokens (no raw hex — F5 #111):
 *   sqli      → --fw-orange  (SQL Injection: orange)
 *   xss       → --fw-accent  (XSS: amber, FireWatch signature)
 *   bot       → --fw-blue    (Bot Activity: blue)
 *   ratelimit → --fw-red     (Rate Limited: red)
 *   geo       → --fw-cyan    (Geo-Blocked: cyan)
 *   lfi       → --fw-pink    (Local File Inclusion: pink)
 *   ids_alert → --fw-orange  (IDS Alert: orange, same hue as SQLi — Suricata events)
 */
const CATEGORY_COLUMNS: {
  key: keyof CategoryTimelineBucket
  label: string
  /** CSS custom property token for the category hue — no raw hex (F5 #111). */
  colorToken: string
}[] = [
  { key: 'sqli',      label: 'SQLi',       colorToken: 'var(--fw-orange)' },
  { key: 'xss',       label: 'XSS',        colorToken: 'var(--fw-accent)' },
  { key: 'bot',       label: 'Bot',        colorToken: 'var(--fw-blue)'   },
  { key: 'ratelimit', label: 'Rate Limit', colorToken: 'var(--fw-red)'    },
  { key: 'geo',       label: 'Geo Block',  colorToken: 'var(--fw-cyan)'   },
  { key: 'lfi',       label: 'LFI',        colorToken: 'var(--fw-pink)'   },
  { key: 'ids_alert', label: 'IDS Alert',  colorToken: 'var(--fw-orange)' },
]

/** Format category timeline with category hues on column headers and non-zero cells. */
function CategoryTimeline({ buckets }: { buckets: CategoryTimelineBucket[] }) {
  if (buckets.length === 0) {
    return (
      <p
        className="text-xs text-muted-foreground"
        data-testid="timeline-empty-analytics"
        style={{ color: 'var(--fw-t3)', fontSize: 'var(--fw-fs-xs)' }}
      >
        No timeline data.
      </p>
    )
  }

  // Show the most recent 10 periods.
  const rows = buckets.slice(-10)

  return (
    <div className="overflow-x-auto" data-testid="categories-timeline-chart">
      <table
        style={{
          width: '100%',
          fontSize: 'var(--fw-fs-xs)',
          borderCollapse: 'collapse',
          fontFamily: 'var(--fw-font-ui)',
        }}
      >
        <thead>
          <tr style={{ borderBottom: '1px solid var(--fw-border)' }}>
            <th
              style={{
                padding: '4px 8px',
                textAlign: 'left',
                fontWeight: 'var(--fw-fw-semibold)',
                color: 'var(--fw-t3)',
                fontSize: 'var(--fw-fs-2xs)',
                textTransform: 'uppercase',
                letterSpacing: 'var(--fw-ls-label)',
              }}
            >
              Period
            </th>
            {CATEGORY_COLUMNS.map((col) => (
              <th
                key={col.key as string}
                data-category={col.key as string}
                style={{
                  padding: '4px 8px',
                  textAlign: 'right',
                  fontWeight: 'var(--fw-fw-semibold)',
                  color: col.colorToken,
                  fontSize: 'var(--fw-fs-2xs)',
                  textTransform: 'uppercase',
                  letterSpacing: 'var(--fw-ls-label)',
                }}
              >
                {col.label}
              </th>
            ))}
            {/* #566: paddingRight:16 so "TOTAL" doesn't press the panel right edge. */}
            <th
              style={{
                padding: '4px 16px 4px 8px',
                textAlign: 'right',
                fontWeight: 'var(--fw-fw-semibold)',
                color: 'var(--fw-t2)',
                fontSize: 'var(--fw-fs-2xs)',
                textTransform: 'uppercase',
                letterSpacing: 'var(--fw-ls-label)',
              }}
            >
              Total
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr
              key={row.period}
              data-testid="timeline-row-analytics"
              style={{ borderBottom: '1px solid var(--fw-border)' }}
            >
              <td
                style={{
                  padding: '4px 8px',
                  fontFamily: 'var(--fw-font-mono)',
                  whiteSpace: 'nowrap',
                  color: 'var(--fw-t2)',
                  fontSize: 'var(--fw-fs-xs)',
                }}
              >
                {String(row.period)}
              </td>
              {CATEGORY_COLUMNS.map((col) => {
                const count = row[col.key] as number
                // Non-zero cells get the category hue; zero cells are muted.
                const cellColor = count > 0 ? col.colorToken : 'var(--fw-t3)'
                return (
                  <td
                    key={col.key as string}
                    data-category={col.key as string}
                    style={{
                      padding: '4px 8px',
                      textAlign: 'right',
                      fontFamily: 'var(--fw-font-mono)',
                      fontSize: 'var(--fw-fs-xs)',
                      color: cellColor,
                    }}
                  >
                    {count.toLocaleString()}
                  </td>
                )
              })}
              {/* #566: paddingRight:16 matches the Total header gutter. */}
              <td
                style={{
                  padding: '4px 16px 4px 8px',
                  textAlign: 'right',
                  fontFamily: 'var(--fw-font-mono)',
                  fontWeight: 'var(--fw-fw-semibold)',
                  color: 'var(--fw-t1)',
                  fontSize: 'var(--fw-fs-xs)',
                }}
              >
                {row.total.toLocaleString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default function AnalyticsCharts({ summary, timeline }: AnalyticsChartsProps) {
  const blockRateDisplay =
    typeof summary.block_rate === 'number' ? `${summary.block_rate.toFixed(1)}%` : '—'

  return (
    <div
      data-testid="analytics-charts"
      style={{ display: 'flex', flexDirection: 'column', gap: 20 }}
    >
      {/* Summary KPIs — DS StatCard with semantic accents.
          Accent mapping:
            total_events     → default  (neutral, headline number)
            total_blocked    → red      (blocked = danger)
            total_ips        → blue     (IP count = informational)
            block_rate       → red      (high block rate = danger signal)
            top_country      → cyan     (geo context)
            unique_countries → cyan     (geo context)
          Source: StatCard.tsx ACCENT_COLOR map + --fw-* token set. */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(140px, 1fr))',
          gap: 12,
        }}
        data-testid="analytics-kpis"
      >
        <StatCard
          value={summary.total_events.toLocaleString()}
          label="Total Events"
          icon="📋"
          accent="default"
          data-testid="analytics-total-events"
        />
        <StatCard
          value={summary.total_blocked.toLocaleString()}
          label="Blocked"
          icon="🛡️"
          accent="red"
          data-testid="analytics-total-blocked"
        />
        <StatCard
          value={summary.total_ips.toLocaleString()}
          label="Unique IPs"
          icon="🌐"
          accent="blue"
          data-testid="analytics-total-ips"
        />
        <StatCard
          value={blockRateDisplay}
          label="Block Rate"
          icon="📊"
          accent="red"
          data-testid="analytics-block-rate"
        />
        <StatCard
          value={summary.top_country}
          label="Top Country"
          icon="🌍"
          accent="cyan"
          data-testid="analytics-top-country"
        />
        <StatCard
          value={summary.unique_countries.toLocaleString()}
          label="Countries"
          icon="🗺️"
          accent="cyan"
          data-testid="analytics-unique-countries"
        />
      </div>

      {/* Top rule tile — shown only when a rule is available */}
      {summary.top_rule !== '' && (
        <div
          data-testid="analytics-top-rule-tile"
          style={{
            background: 'var(--fw-bg-input)',
            border: '1px solid var(--fw-border)',
            borderRadius: 'var(--fw-r-sm)',
            padding: '10px 14px',
          }}
        >
          <div
            style={{
              fontSize: 'var(--fw-fs-xs)',
              color: 'var(--fw-t3)',
              textTransform: 'uppercase',
              letterSpacing: 'var(--fw-ls-label)',
              marginBottom: 4,
            }}
          >
            Top Blocked Rule
          </div>
          <div
            data-testid="analytics-top-rule"
            style={{
              fontFamily: 'var(--fw-font-mono)',
              fontSize: 'var(--fw-fs-sm)',
              color: 'var(--fw-t1)',
            }}
          >
            {String(summary.top_rule)}
          </div>
        </div>
      )}

      {/* Category timeline — from GET /analytics/categories-timeline.
          Column headers and non-zero cells use category hue tokens (MF-5 #162). */}
      <div>
        <h3
          style={{
            fontSize: 'var(--fw-fs-2xs)',
            fontWeight: 'var(--fw-fw-semibold)',
            textTransform: 'uppercase',
            letterSpacing: 'var(--fw-ls-label)',
            color: 'var(--fw-t3)',
            marginBottom: 8,
            margin: '0 0 8px',
          }}
        >
          Categories Over Time
        </h3>
        <CategoryTimeline buckets={timeline} />
      </div>
    </div>
  )
}
