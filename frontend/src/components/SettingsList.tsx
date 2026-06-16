/**
 * SettingsList — maps discovery response → DS SourceCard per installed plugin.
 *
 * ADR-0062 §A/§C changes:
 *
 * §A — Active-first sort (progressive disclosure):
 *   - Sources are partitioned into Active (instance present in GET /sources) and
 *     Inactive. Active sources render first (expanded by default via SourceCard
 *     defaultExpanded prop). Inactive sources render below (collapsed by default).
 *   - Active-state source of truth: GET /sources instance list (instance present
 *     ⇔ Active, ADR-0031 §A). One lookup feeds both sort and default-expansion.
 *     No extra per-card fan-out beyond what already exists.
 *   - Generic: no per-source-type branching (ADR-0010).
 *
 * §C — Real source_id in the instance label:
 *   - instanceLabel now shows the real source_id (from instance) or type_key
 *     (per ADR-0031 §B default). The "default" placeholder is removed.
 *
 * P5 (#116): updated to use a 2-column grid matching the kit oracle
 * (.sources-grid { grid-template-columns: 1fr 1fr }) from Settings.jsx.
 *
 * Issue #488 (R3): replaced dead-end empty state with a friendly FirstRunPanel;
 * added instance labeling above each card ("Display Name · source_id").
 *
 * Handles three states:
 *   - loading: discovery fetch in progress
 *   - empty: no plugins installed ([] response) → FirstRunPanel
 *   - populated: one labeled SourceCard per entry in a 2-col grid
 *
 * ADR-0010 / ADR-0028: purely discovery-driven — install a source ⇒ card
 * appears; uninstall ⇒ card disappears. No per-source code here.
 *
 * Issue #315: supervisorOffline prop is threaded to each SourceCard so they can
 * suppress their per-source sub-requests when the supervisor is absent (503).
 *
 * ADR-0035 (honest labeling): cards are labeled by instance identity using the
 * real source_id. In single-instance mode (ADR-0031 §B), the source_id equals
 * the type_key — shown as-is (e.g. "suricata"). Multi-instance support is coming.
 */

import { useState, useCallback, useEffect } from 'react'
import type { SourceTypeEntry } from '../schema/types'
import type { SourceInstance } from '../api/types'
import SourceCard from './SourceCard'
import { useSourceStatsHealth } from '../hooks/useSourceStatsHealth'
import type { SourceHealthLookup, SourceHealthItemLookup } from '../hooks/useSourceStatsHealth'
import { fetchSources } from '../api/sources'
import { ApiError } from '../api/client'

interface SettingsListProps {
  sources: SourceTypeEntry[]
  loading: boolean
  error: string | null
  /** When true, per-source sub-requests are suppressed (supervisor is absent). */
  supervisorOffline?: boolean
}

// ---------------------------------------------------------------------------
// Install command — the literal one-liner shown in the first-run panel.
// Must remain generic (no hardcoded source name).
// ---------------------------------------------------------------------------
const INSTALL_CMD = 'pip install firewatch-source-<name>'

// ---------------------------------------------------------------------------
// FirstRunPanel — friendly empty-state shown when no sources are installed.
// Explains what a source is, how to install one, and key local-first trust
// properties (ADR-0035).
// ---------------------------------------------------------------------------

interface FirstRunPanelProps {
  installCmd: string
}

function FirstRunPanel({ installCmd }: FirstRunPanelProps) {
  const [copied, setCopied] = useState(false)

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(installCmd)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // Clipboard write failed — the command remains selectable as plain text
      // so the user can copy it manually (EARS: unwanted — clipboard failure).
    }
  }, [installCmd])

  return (
    <div
      data-testid="first-run-panel"
      role="region"
      aria-label="Getting started with sources"
      style={{
        padding: '32px 24px',
        borderRadius: 8,
        border: '1px dashed var(--fw-border)',
        background: 'var(--fw-bg2)',
        maxWidth: 560,
      }}
    >
      {/* What is a source? */}
      <h3
        style={{
          margin: '0 0 8px',
          fontSize: 'var(--fw-fs-base)',
          fontWeight: 'var(--fw-fw-bold)',
          fontFamily: 'var(--fw-font-ui)',
          color: 'var(--fw-t1)',
        }}
      >
        What is a source?
      </h3>
      <p
        style={{
          margin: '0 0 20px',
          fontSize: 'var(--fw-fs-sm)',
          fontFamily: 'var(--fw-font-ui)',
          color: 'var(--fw-t2)',
          lineHeight: 1.5,
        }}
      >
        A source is a plugin that tells FireWatch where to collect telemetry — for example Suricata
        IDS logs, Azure WAF events, or syslog streams. Once installed, each source appears here as a
        settings card you configure and monitor in one place.
      </p>

      {/* Install command */}
      <p
        style={{
          margin: '0 0 8px',
          fontSize: 'var(--fw-fs-sm)',
          fontWeight: 'var(--fw-fw-bold)',
          fontFamily: 'var(--fw-font-ui)',
          color: 'var(--fw-t1)',
        }}
      >
        Install a source package:
      </p>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 20 }}>
        <code
          data-testid="install-command"
          tabIndex={0}
          style={{
            flex: 1,
            padding: '8px 12px',
            borderRadius: 6,
            background: 'var(--fw-bg3)',
            border: '1px solid var(--fw-border)',
            fontSize: 'var(--fw-fs-sm)',
            fontFamily: 'var(--fw-font-mono)',
            color: 'var(--fw-t1)',
            userSelect: 'all',
            outline: 'none',
          }}
          // Accessible focus ring via onFocus/onBlur — purely visual, no state needed.
          onFocus={(e) => {
            ;(e.currentTarget as HTMLElement).style.boxShadow = '0 0 0 2px var(--fw-accent)'
          }}
          onBlur={(e) => {
            ;(e.currentTarget as HTMLElement).style.boxShadow = 'none'
          }}
        >
          {installCmd}
        </code>
        <button
          type="button"
          data-testid="copy-install-cmd"
          onClick={handleCopy}
          aria-label="Copy install command to clipboard"
          style={{
            padding: '8px 14px',
            borderRadius: 6,
            border: '1px solid var(--fw-border)',
            background: 'var(--fw-bg3)',
            color: 'var(--fw-t1)',
            fontSize: 'var(--fw-fs-sm)',
            fontFamily: 'var(--fw-font-ui)',
            cursor: 'pointer',
            whiteSpace: 'nowrap',
          }}
        >
          {copied ? 'Copied!' : 'Copy'}
        </button>
      </div>

      {/* Accessible "copied" announcement */}
      <span
        role="status"
        aria-live="polite"
        aria-atomic="true"
        data-testid="copy-announcement"
        style={{
          position: 'absolute',
          width: 1,
          height: 1,
          overflow: 'hidden',
          clip: 'rect(0,0,0,0)',
          whiteSpace: 'nowrap',
        }}
      >
        {copied ? 'Install command copied to clipboard.' : ''}
      </span>

      {/* Auto-appear line */}
      <p
        style={{
          margin: '0 0 16px',
          fontSize: 'var(--fw-fs-sm)',
          fontFamily: 'var(--fw-font-ui)',
          color: 'var(--fw-t2)',
        }}
        data-testid="auto-appear-notice"
      >
        Installed sources appear below automatically — no page edits needed.
      </p>

      {/* Instance + local-first trust lines */}
      <div
        style={{
          padding: '12px 14px',
          borderRadius: 6,
          background: 'var(--fw-bg1)',
          border: '1px solid var(--fw-border)',
          fontSize: 'var(--fw-fs-xs)',
          fontFamily: 'var(--fw-font-ui)',
          color: 'var(--fw-t3)',
          lineHeight: 1.6,
        }}
      >
        <p
          style={{ margin: '0 0 6px' }}
          data-testid="single-instance-notice"
        >
          One instance per source is configured today. Multi-instance support (running two Suricata
          sensors, for example) is coming in a future release.
        </p>
        <p
          style={{ margin: 0 }}
          data-testid="local-first-notice"
        >
          Local-first: your configuration, secrets, and AI scoring stay on this machine — nothing
          leaves the device.
        </p>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Instance label helper — derives a human-friendly instance identifier.
// ADR-0062 §C: show the real source_id (defaulting to type_key), NOT "default".
// In single-instance mode (ADR-0031 §B), source_id === type_key, so the label
// reads "suricata" instead of the old "default" placeholder.
// This is generic: no per-source branching.
// ---------------------------------------------------------------------------
function instanceLabel(typeKey: string, instance: SourceInstance | null): string {
  if (instance?.source_id) return instance.source_id
  // No instance yet (source not active) — show type_key as the default id
  // per ADR-0031 §B: source_id defaults to type_key.
  return typeKey
}

// ---------------------------------------------------------------------------
// SourceItem — wraps a SourceCard with an honest instance label above it.
// ADR-0035: label by instance, not by type alone.
// ---------------------------------------------------------------------------
interface SourceItemProps {
  source: SourceTypeEntry
  supervisorOffline: boolean
  getServerHealth: SourceHealthLookup
  getServerHealthItem: SourceHealthItemLookup
  /**
   * The loaded instance for this source type (from the shared GET /sources fetch).
   * Used to derive the instance label (ADR-0062 §C) and Active state (for sort).
   * May be null if the source is not Active or instances haven't loaded yet.
   */
  instance: SourceInstance | null
}

function SourceItem({ source, supervisorOffline, getServerHealth, getServerHealthItem, instance }: SourceItemProps) {
  // ADR-0062 §C: show real source_id (type_key as default), not "default".
  const label = instanceLabel(source.type_key, instance)

  return (
    // #706 fix: removed the flex:1/height propagation that caused collapsed cards
    // to balloon when their row-neighbor was expanded (ADR-0062 collapse invalidated
    // the #574 equal-height assumption). align-items:start on the grid parent now
    // ensures each card sits at its natural height.
    <div style={{ display: 'flex', flexDirection: 'column' }}>
      <div
        data-testid={`instance-label-${source.type_key}`}
        aria-label={`${source.display_name} instance: ${label}`}
        style={{
          marginBottom: 6,
          fontSize: 'var(--fw-fs-xs)',
          fontFamily: 'var(--fw-font-ui)',
          color: 'var(--fw-t3)',
          letterSpacing: '.3px',
        }}
      >
        <span style={{ fontWeight: 'var(--fw-fw-bold)', color: 'var(--fw-t2)' }}>
          {source.display_name}
        </span>
        <span style={{ margin: '0 4px', color: 'var(--fw-t3)' }}>·</span>
        <span>{label}</span>
      </div>
      <SourceCard
        source={source}
        supervisorOffline={supervisorOffline}
        serverHealth={getServerHealth(source.type_key)}
        serverHealthItem={getServerHealthItem(source.type_key)}
      />
    </div>
  )
}

// ---------------------------------------------------------------------------
// SettingsList — main export
// ---------------------------------------------------------------------------

export default function SettingsList({
  sources,
  loading,
  error,
  supervisorOffline = false,
}: SettingsListProps) {
  // Fetch GET /stats once so each SourceCard can use the server-computed health
  // field (dot color, ADR-0032 Decision C) and event telemetry (event_count,
  // last_event_at — for the "Events" and "Last event" fields in the HealthCard
  // popover). One fetch serves all cards — no per-card polling.
  // Returns null per source until settled.
  const { getHealth, getHealthItem } = useSourceStatsHealth()

  // ADR-0062 §A: fetch GET /sources once at the list level to determine Active state
  // for each source. Active = instance present in GET /sources (ADR-0031 §A).
  // This single fetch drives both sort (active-first) and defaultExpanded.
  // We do NOT fan out one GET /sources per card — one shared fetch at list level.
  const [instances, setInstances] = useState<SourceInstance[]>([])

  useEffect(() => {
    if (supervisorOffline) return
    let cancelled = false
    fetchSources()
      .then((list) => {
        if (!cancelled) setInstances(list)
      })
      .catch((err) => {
        // 503: supervisor not running → no instances, graceful.
        // Other errors: silently absorb — instances empty, all cards inactive.
        if (err instanceof ApiError && err.status === 503) return
        // Silently absorb: all sources treated as inactive
      })
    return () => { cancelled = true }
  }, [supervisorOffline, sources])

  if (loading) {
    return (
      <p
        role="status"
        style={{
          color: 'var(--fw-t3)',
          fontSize: 'var(--fw-fs-sm)',
          fontFamily: 'var(--fw-font-ui)',
        }}
      >
        Loading source configurations…
      </p>
    )
  }

  if (error) {
    return (
      <p
        role="alert"
        style={{
          color: 'var(--fw-red)',
          fontSize: 'var(--fw-fs-sm)',
          fontFamily: 'var(--fw-font-ui)',
        }}
      >
        {error}
      </p>
    )
  }

  if (sources.length === 0) {
    return <FirstRunPanel installCmd={INSTALL_CMD} />
  }

  // ADR-0062 §A / Amendment 1 §1 (issue #737): partition sources into Active and Inactive.
  // Active = auto_sync_enabled === true (the real server-computed flag, NOT instance-presence).
  // Using instance-presence (instanceByType.has) was bug 2b: idle sources with an instance
  // record painted Active=ON, so the user never saw the toggle and the loop never started.
  // Active sources sort to the top; Inactive sources sort to the bottom.
  const instanceByType = new Map(instances.map((i) => [i.source_type, i]))

  const activeSources = sources.filter((s) => instanceByType.get(s.type_key)?.auto_sync_enabled === true)
  const inactiveSources = sources.filter((s) => instanceByType.get(s.type_key)?.auto_sync_enabled !== true)
  const sortedSources = [...activeSources, ...inactiveSources]

  return (
    <div
      className="sources-grid"
      data-testid="settings-list"
      style={{
        display: 'grid',
        /* #706 fix (1): use minmax(0,1fr) so both columns are exactly 50/50
           regardless of card content. Plain '1fr' resolves to minmax(auto,1fr)
           which lets a wide card (e.g. Azure WAF GUID field) stretch its column
           to ~751px and starve the Suricata column to ~494px. */
        gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)',
        /* #706 fix (2): use align-items:start so collapsed cards sit at their
           natural header-only height. The previous align-items:stretch (added by
           #574 for equal-height when every card was expanded) caused a collapsed
           card to balloon to match an expanded row-neighbor — invalidated by
           ADR-0062 collapse. The masonry approach would also work but align-items:start
           is simpler and meets the EARS criterion (collapsed card at natural height). */
        alignItems: 'start',
        gap: 16,
      }}
    >
      {sortedSources.map((source) => (
        <SourceItem
          key={source.type_key}
          source={source}
          supervisorOffline={supervisorOffline}
          getServerHealth={getHealth}
          getServerHealthItem={getHealthItem}
          instance={instanceByType.get(source.type_key) ?? null}
        />
      ))}
    </div>
  )
}
