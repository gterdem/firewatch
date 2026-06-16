/**
 * FacetFilters — DS-styled filter bar for the Logs explorer (#112).
 *
 * Layout matches soc-console/Logs.jsx exactly:
 *   - filter-row: Source / Category / Action / Severity Comboboxes + search Input
 *     + result-count mono span + CSV/JSON export buttons.
 *   - filter-chips row: one removable FilterChip per active facet.
 *
 * Wire to API:
 *   Source    → LogsFilter.source_type  (server param)
 *   Category  → LogsFilter.category    (server param)
 *   Severity  → LogsFilter.severity    (server param)
 *   Search    → LogsFilter.q           (server param → ?q= on GET /logs/paginated)
 *   Action    → LogsFilter.action      (server param — issue #252)
 *
 * Action is now a SERVER-SIDE filter (issue #252) — selecting an action value
 * triggers a new fetch with ?action= rather than filtering the current page
 * in the browser.  The "blocked" option (BLOCK + DROP) is first-class.
 *
 * EARS (ADR-0011):
 *   - WHEN a Combobox changes, onFilterChange fires with cursor reset.
 *   - WHEN a FilterChip ✕ is clicked, that facet clears and onFilterChange fires.
 *
 * ADR-0019: React + TS. DS barrel imports only (F5 adherence).
 */

import type { ComboOption } from '../ds'
import { Combobox, FilterChip, Button } from '../ds'
import type { LogsFilter } from '../../api/types'
import NlQueryInput from './NlQueryInput'

export interface FacetFiltersProps {
  filter: LogsFilter
  onFilterChange: (next: LogsFilter) => void
  /** Dynamic category options from server; static fallback if empty. */
  categoryOptions?: ComboOption[]
  /** Source options from server; static fallback if empty. */
  sourceOptions?: ComboOption[]
  /** Total matching from the latest page envelope. */
  totalMatching?: number
}

const SEVERITY_OPTIONS: ComboOption[] = [
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'informational', label: 'Informational' },
]

/**
 * Action filter options for GET /logs/paginated?action= (issue #252).
 *
 * "blocked" is the canonical shorthand for action ∈ {BLOCK, DROP} — resolved
 * server-side by the store's BLOCKED_ACTIONS definition.  Exact values (BLOCK,
 * DROP, ALLOW, ALERT) are also available for forensic drill-down.
 */
const ACTION_OPTIONS: ComboOption[] = [
  { value: 'blocked', label: 'Blocked (BLOCK + DROP)' },
  { value: 'BLOCK', label: 'Block' },
  { value: 'DROP', label: 'Drop' },
  { value: 'ALLOW', label: 'Allow' },
  { value: 'ALERT', label: 'Alert (IDS)' },
]

export default function FacetFilters({
  filter,
  onFilterChange,
  categoryOptions = [],
  sourceOptions = [],
  totalMatching,
}: FacetFiltersProps) {
  /** Partial update — always resets cursor (new server query). */
  function set(partial: Partial<LogsFilter>) {
    onFilterChange({ ...filter, ...partial, cursor: undefined })
  }

  /** Clear all server filters. */
  function clearAll() {
    onFilterChange({})
  }

  /**
   * Apply an NL-parsed FilterSpec (ML-6 / ADR-0049, EARS-1/EARS-2).
   *
   * Replaces the current filter with the validated FilterSpec from the local
   * LLM parse (not merged — NL query sets the full filter context).
   * The provenance is forwarded for logging; chip rendering is handled by
   * the existing chips array below (EARS-3 chip shows on the AI provenance
   * chip inside NlQueryInput itself).
   *
   * SECURITY: filter_spec values are pre-validated server-side (strict allowlist,
   * ADR-0049). Applying them here is equivalent to manual chip selection.
   */
  function handleNlFilter(nlSpec: Partial<LogsFilter>) {
    onFilterChange({ ...nlSpec, cursor: undefined })
  }

  // ---- active filter chip descriptors ----
  const chips: { key: string; label: string; onRemove: () => void }[] = []

  if (filter.ip) {
    chips.push({
      key: 'ip',
      label: `IP: ${filter.ip}`,
      onRemove: () => set({ ip: undefined }),
    })
  }
  if (filter.source_type) {
    const label = sourceOptions.find((o) => o.value === filter.source_type)?.label
    chips.push({
      key: 'source',
      label: `Source: ${String(label ?? filter.source_type)}`,
      onRemove: () => set({ source_type: undefined }),
    })
  }
  if (filter.category) {
    chips.push({
      key: 'category',
      label: `Category: ${filter.category}`,
      onRemove: () => set({ category: undefined }),
    })
  }
  if (filter.action) {
    const optionLabel = ACTION_OPTIONS.find((o) => o.value === filter.action)?.label
    chips.push({
      key: 'action',
      label: `Action: ${String(optionLabel ?? filter.action)}`,
      onRemove: () => set({ action: undefined }),
    })
  }
  if (filter.severity) {
    chips.push({
      key: 'severity',
      label: `Severity: ${filter.severity}`,
      onRemove: () => set({ severity: undefined }),
    })
  }
  if (filter.q) {
    chips.push({
      key: 'search',
      label: `Search: ${filter.q}`,
      onRemove: () => set({ q: undefined }),
    })
  }
  // ML-3 (#431) — destination_ip and protocol chips
  if (filter.destination_ip) {
    chips.push({
      key: 'destination_ip',
      label: `Dest IP: ${filter.destination_ip}`,
      onRemove: () => set({ destination_ip: undefined }),
    })
  }
  if (filter.protocol) {
    chips.push({
      key: 'protocol',
      label: `Protocol: ${filter.protocol}`,
      onRemove: () => set({ protocol: undefined }),
    })
  }
  // ML-13 (#441) — JA4 fingerprint chip (consume-only; absent when sensor does not emit JA4)
  if (filter.tls_ja4) {
    chips.push({
      key: 'tls_ja4',
      label: `JA4: ${filter.tls_ja4}`,
      onRemove: () => set({ tls_ja4: undefined }),
    })
  }

  return (
    <div
      data-testid="facet-filters"
      aria-label="Log filters"
      style={{
        background: 'var(--fw-bg-card)',
        border: '1px solid var(--fw-border)',
        borderRadius: 8,
        padding: 12,
        marginBottom: 12,
        fontFamily: 'var(--fw-font-ui)',
      }}
    >
      {/* ML-6 (#434): NL query bar — "Ask the network" (ADR-0049, zero-egress).
          Sits above the manual filter row; applies the validated FilterSpec as
          editable chips (EARS-1, EARS-3) or degrades to q= (EARS-2). */}
      <NlQueryInput onFilterApply={handleNlFilter} />

      {/* Filter row */}
      <div
        style={{
          display: 'flex',
          gap: 8,
          alignItems: 'flex-end',
          flexWrap: 'wrap',
        }}
      >
        {/* Source combobox */}
        <Combobox
          data-testid="filter-source-combo"
          label="Source"
          placeholder="All sources"
          options={sourceOptions}
          value={filter.source_type ?? ''}
          onChange={(val) => set({ source_type: val || undefined })}
          style={{ minWidth: 140 }}
        />

        {/* Category combobox */}
        <Combobox
          data-testid="filter-category-combo"
          label="Category"
          placeholder="All categories"
          options={categoryOptions}
          value={filter.category ?? ''}
          onChange={(val) => set({ category: val || undefined })}
          style={{ minWidth: 160 }}
        />

        {/* Action combobox — server-side filter (issue #252) */}
        <Combobox
          data-testid="filter-action-combo"
          label="Action"
          placeholder="All actions"
          options={ACTION_OPTIONS}
          value={filter.action ?? ''}
          onChange={(val) => set({ action: val || undefined })}
          style={{ minWidth: 160 }}
        />

        {/* Severity combobox */}
        <Combobox
          data-testid="filter-severity-combo"
          label="Severity"
          placeholder="All severities"
          options={SEVERITY_OPTIONS}
          value={filter.severity ?? ''}
          onChange={(val) => set({ severity: val || undefined })}
          style={{ minWidth: 130 }}
        />

        {/* Free-text search */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <span
            style={{
              fontSize: 'var(--fw-fs-2xs)',
              color: 'var(--fw-t3)',
              textTransform: 'uppercase',
              letterSpacing: 'var(--fw-ls-table)',
            }}
          >
            Search
          </span>
          <input
            type="search"
            value={filter.q ?? ''}
            placeholder="Search IP, signature, payload…"
            aria-label="Search logs"
            data-testid="filter-search"
            style={{
              background: 'var(--fw-bg-input)',
              color: 'var(--fw-t1)',
              border: '1px solid var(--fw-border)',
              borderRadius: 'var(--fw-r-xs)',
              padding: '6px 10px',
              fontSize: 'var(--fw-fs-sm)',
              fontFamily: 'var(--fw-font-ui)',
              outline: 'none',
              width: 220,
            }}
            onChange={(e) => set({ q: e.target.value || undefined })}
          />
        </div>

        {/* ML-3 (#431): Destination IP filter input */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <span
            style={{
              fontSize: 'var(--fw-fs-2xs)',
              color: 'var(--fw-t3)',
              textTransform: 'uppercase',
              letterSpacing: 'var(--fw-ls-table)',
            }}
          >
            Dest IP
          </span>
          <input
            type="text"
            value={filter.destination_ip ?? ''}
            placeholder="Destination IP…"
            aria-label="Filter by destination IP"
            data-testid="filter-dest-ip"
            style={{
              background: 'var(--fw-bg-input)',
              color: 'var(--fw-t1)',
              border: '1px solid var(--fw-border)',
              borderRadius: 'var(--fw-r-xs)',
              padding: '6px 10px',
              fontSize: 'var(--fw-fs-sm)',
              fontFamily: 'var(--fw-font-mono)',
              outline: 'none',
              width: 140,
            }}
            onChange={(e) => set({ destination_ip: e.target.value || undefined })}
          />
        </div>

        {/* ML-3 (#431): Protocol filter input */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <span
            style={{
              fontSize: 'var(--fw-fs-2xs)',
              color: 'var(--fw-t3)',
              textTransform: 'uppercase',
              letterSpacing: 'var(--fw-ls-table)',
            }}
          >
            Protocol
          </span>
          <input
            type="text"
            value={filter.protocol ?? ''}
            placeholder="TCP / UDP…"
            aria-label="Filter by protocol"
            data-testid="filter-protocol"
            style={{
              background: 'var(--fw-bg-input)',
              color: 'var(--fw-t1)',
              border: '1px solid var(--fw-border)',
              borderRadius: 'var(--fw-r-xs)',
              padding: '6px 10px',
              fontSize: 'var(--fw-fs-sm)',
              fontFamily: 'var(--fw-font-mono)',
              outline: 'none',
              width: 100,
            }}
            onChange={(e) => set({ protocol: e.target.value || undefined })}
          />
        </div>

        {/* ML-13 (#441): JA4 TLS fingerprint filter input.
            Consume-only — only Suricata rows with tls_ja4 populated match.
            SECURITY (ADR-0029 D3): fingerprint is sensor-normalised attacker-controlled
            TLS data; rendered as a text node only (no dangerouslySetInnerHTML). */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <span
            style={{
              fontSize: 'var(--fw-fs-2xs)',
              color: 'var(--fw-t3)',
              textTransform: 'uppercase',
              letterSpacing: 'var(--fw-ls-table)',
            }}
          >
            JA4
          </span>
          <input
            type="text"
            value={filter.tls_ja4 ?? ''}
            placeholder="JA4 fingerprint…"
            aria-label="Filter by JA4 TLS fingerprint"
            data-testid="filter-tls-ja4"
            style={{
              background: 'var(--fw-bg-input)',
              color: 'var(--fw-t1)',
              border: '1px solid var(--fw-border)',
              borderRadius: 'var(--fw-r-xs)',
              padding: '6px 10px',
              fontSize: 'var(--fw-fs-sm)',
              fontFamily: 'var(--fw-font-mono)',
              outline: 'none',
              width: 200,
            }}
            onChange={(e) => set({ tls_ja4: e.target.value || undefined })}
          />
        </div>

        {/* Result count */}
        {totalMatching !== undefined && (
          <span
            data-testid="filter-count"
            style={{
              fontSize: 'var(--fw-fs-sm)',
              color: 'var(--fw-t3)',
              fontFamily: 'var(--fw-font-mono)',
              alignSelf: 'flex-end',
              paddingBottom: 7,
              whiteSpace: 'nowrap',
            }}
          >
            {totalMatching.toLocaleString()} logs
          </span>
        )}

        {/* Export buttons */}
        <div style={{ display: 'flex', gap: 4, alignSelf: 'flex-end' }}>
          <Button
            variant="secondary"
            size="sm"
            data-testid="export-csv"
            onClick={() => {
              /* export CSV — out of scope for P1 */
            }}
          >
            CSV
          </Button>
          <Button
            variant="secondary"
            size="sm"
            data-testid="export-json"
            onClick={() => {
              /* export JSON — out of scope for P1 */
            }}
          >
            JSON
          </Button>
        </div>

        {/* Clear all */}
        {chips.length > 0 && (
          <Button
            variant="ghost"
            size="sm"
            data-testid="filter-clear"
            aria-label="Clear all filters"
            style={{ alignSelf: 'flex-end' }}
            onClick={clearAll}
          >
            Clear all
          </Button>
        )}
      </div>

      {/* Filter chips row */}
      {chips.length > 0 && (
        <div
          data-testid="filter-chips"
          style={{
            display: 'flex',
            gap: 4,
            flexWrap: 'wrap',
            marginTop: 8,
          }}
        >
          {chips.map((chip) => (
            <FilterChip key={chip.key} onRemove={chip.onRemove} data-testid={`chip-${chip.key}`}>
              {chip.label}
            </FilterChip>
          ))}
        </div>
      )}
    </div>
  )
}
