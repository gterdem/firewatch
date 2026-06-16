/**
 * GroupPanel — slide-over group view for an ASN or /24 CIDR rollup group (issue #212).
 *
 * Shown when the analyst clicks a group row in ThreatActors while rollup is active.
 * Displays:
 *   - Group header (label, member count, top score).
 *   - Top member IPs (up to 10), each rendered as ClickableIp for breadcrumb navigation.
 *
 * No data fetching — receives the ActorGroup directly from ThreatActors via EntityRef.meta.
 *
 * SECURITY (ADR-0029 D3): all string fields (label, source_ip, as_name) are attacker-controlled.
 * Rendered as text nodes only — no dangerouslySetInnerHTML.
 *
 * ADR-0037: group view is a new entity kind; EntityPanelProvider routes here via kind="asn"|"cidr".
 */

import type { ActorGroup } from '../../../lib/actorRollup'
import ClickableIp from '../ClickableIp'
import { ScoreBadge } from '../../ds'

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface GroupPanelProps {
  /** The rollup group to display — passed via EntityRef.meta from ThreatActors. */
  group: ActorGroup
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function GroupPanel({ group }: GroupPanelProps) {
  return (
    <div data-testid="group-panel">
      {/* ── Group header ─────────────────────────────────────── */}
      <div style={{ marginBottom: 20 }}>
        <div
          style={{
            fontSize: 18,
            fontWeight: 700,
            color: 'var(--fw-t1)',
            fontFamily: 'var(--fw-font-mono)',
            marginBottom: 4,
            wordBreak: 'break-all',
          }}
          data-testid="group-panel-label"
        >
          {group.label}
        </div>

        <div
          style={{
            display: 'flex',
            gap: 20,
            flexWrap: 'wrap',
            fontSize: 12,
            color: 'var(--fw-t3)',
            marginTop: 8,
          }}
        >
          <span data-testid="group-panel-member-count">
            <strong style={{ color: 'var(--fw-t1)' }}>
              {group.memberCount.toLocaleString()}
            </strong>{' '}
            {group.memberCount === 1 ? 'IP' : 'IPs'}
          </span>

          <span>
            Top score:{' '}
            <ScoreBadge
              score={group.topScore}
              threatLevel={group.topThreatLevel}
              scoreBreakdown={group.topMembers[0]?.score_breakdown}
            />
          </span>

          <span>
            Events: <strong style={{ color: 'var(--fw-t1)' }}>{group.totalEvents.toLocaleString()}</strong>
          </span>

          <span>
            Blocked: <strong style={{ color: 'var(--fw-t1)' }}>{group.totalBlockedEvents.toLocaleString()}</strong>
          </span>
        </div>
      </div>

      {/* ── Divider ──────────────────────────────────────────── */}
      <hr style={{ border: 'none', borderTop: '1px solid var(--fw-border)', marginBottom: 16 }} />

      {/* ── Top member IPs ───────────────────────────────────── */}
      <div style={{ marginBottom: 8 }}>
        <div
          style={{
            fontSize: 10,
            color: 'var(--fw-t3)',
            textTransform: 'uppercase',
            letterSpacing: 0.5,
            fontWeight: 600,
            marginBottom: 10,
          }}
        >
          Top IPs in group
        </div>

        <table
          style={{ width: '100%', borderCollapse: 'collapse' }}
          data-testid="group-panel-members-table"
        >
          <thead>
            <tr>
              {(['IP', 'Score', 'Events'] as const).map((h) => (
                <th
                  key={h}
                  style={{
                    textAlign: h === 'Score' || h === 'Events' ? 'right' : 'left',
                    padding: '6px 8px',
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
            {group.topMembers.map((member) => (
              <tr key={member.source_ip} data-testid="group-panel-member-row">
                <td
                  style={{
                    padding: '7px 8px',
                    borderBottom: '1px solid var(--fw-border)',
                    fontSize: 12,
                  }}
                >
                  <ClickableIp value={member.source_ip} style={{ fontSize: 11 }} />
                </td>
                <td
                  style={{
                    padding: '7px 8px',
                    borderBottom: '1px solid var(--fw-border)',
                    textAlign: 'right',
                  }}
                >
                  <ScoreBadge
                    score={member.score}
                    threatLevel={member.threat_level}
                    scoreBreakdown={member.score_breakdown}
                  />
                </td>
                <td
                  style={{
                    padding: '7px 8px',
                    borderBottom: '1px solid var(--fw-border)',
                    fontSize: 12,
                    textAlign: 'right',
                    fontFamily: 'var(--fw-font-mono)',
                  }}
                >
                  {member.total_events.toLocaleString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {group.memberCount > group.topMembers.length && (
          <div
            style={{
              padding: '6px 8px',
              fontSize: 11,
              color: 'var(--fw-t3)',
              borderTop: '1px solid var(--fw-border)',
            }}
            data-testid="group-panel-overflow"
          >
            +{(group.memberCount - group.topMembers.length).toLocaleString()} more IPs in this group
          </div>
        )}
      </div>
    </div>
  )
}
