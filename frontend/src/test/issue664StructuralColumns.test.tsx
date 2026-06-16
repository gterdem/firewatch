/**
 * Tests for issue #664 — Option-B structural empty-column hiding (ADR-0060).
 *
 * EARS criteria covered:
 *
 * EARS-1: WHEN every source present in the scope declares a produces set that OMITS a
 *   column's canonical field, that column SHALL be structurally hidden.
 *   → test_azure_waf_only_hides_destip_protocol_tls_ja4_dns_destport
 *   → test_union_logic_across_present_sources (Suricata present → no hiding)
 *
 * EARS-2: WHEN at least one present source has empty produces (produces-all), no column
 *   SHALL be hidden.
 *   → test_empty_produces_suppresses_all_hiding
 *   → test_absent_produces_suppresses_all_hiding
 *
 * EARS-3: WHEN a column is hidden, a "+N fields not produced by this source" chip SHALL
 *   appear; activating it SHALL list each hidden column with its FIELD_NOTES note.
 *   → test_hidden_fields_chip_shows_count
 *   → test_hidden_fields_chip_popover_lists_field_notes
 *
 * EARS-4: WHEN present_source_types is empty/unknown, no columns SHALL be hidden (fail-open).
 *   → test_empty_present_sources_hides_nothing
 *
 * EARS-5: The structural-absence axis SHALL compose with useColumnPriority — neither replaces
 *   the other.
 *   → test_structurally_absent_columns_are_hidden_in_logs_table
 *   → test_non_absent_columns_remain_visible
 *
 * EARS-6: WHERE a source's real value is falsy but valid (e.g. Azure WAF destination_port=0),
 *   the column SHALL NOT be hidden — Option B never inspects values.
 *   → (Integration: this is structurally guaranteed — the hook inspects no row values)
 *   → test_azure_waf_chip_does_not_appear_when_suricata_also_present (structural, not value-based)
 *
 * SECURITY: all column labels and notes come from static constants — no attacker-controlled
 *   data is displayed in the chip or popover.
 *   → test_chip_renders_static_field_notes_only (FIELD_NOTES values only)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { renderHook } from '@testing-library/react'

import LogsTable from '../components/logs/LogsTable'
import { HiddenFieldsChip } from '../components/logs/HiddenFieldsChip'
import { useStructuralColumns, _resetSourceTypeMapCache } from '../components/logs/useStructuralColumns'
import { LOG_ENTRY_FIXTURE } from './readFixtures'
import { FIELD_NOTES, COLUMN_CANONICAL_FIELDS } from '../lib/fieldAvailability'
import type { SourceTypeEntry } from '../schema/types'
import type { LogEntry } from '../api/types'

// ---------------------------------------------------------------------------
// Source-type fixtures (RFC 5737 — no real plugin data)
//
// Azure WAF: declares produces WITHOUT destination_ip, protocol,
//   destination_port, tls_ja4, dns_query — the L7-only set.
// Suricata: declares the broad L3–L7 set INCLUDING all of the above.
// ---------------------------------------------------------------------------

const AZURE_WAF_SOURCE: SourceTypeEntry = {
  type_key: 'azure_waf',
  display_name: 'Azure WAF',
  version: '0.1.0',
  flavor: 'push',
  config_schema: {},
  produces: [
    'source_ip',
    'severity',
    'action',
    'category',
    'http_payload',
    'rule_id',
    'rule_name',
    'signature',
  ],
}

const SURICATA_SOURCE: SourceTypeEntry = {
  type_key: 'suricata',
  display_name: 'Suricata IDS/IPS',
  version: '0.1.0',
  flavor: 'pull',
  config_schema: {},
  produces: [
    'source_ip',
    'severity',
    'action',
    'category',
    'destination_ip',
    'protocol',
    'destination_port',
    'tls_ja4',
    'dns_query',
  ],
}

const UNKNOWN_SOURCE: SourceTypeEntry = {
  type_key: 'unknown_plugin',
  display_name: 'Unknown Plugin',
  version: '0.1.0',
  flavor: 'push',
  config_schema: {},
  // No produces declared → produces-all (ADR-0060 D2)
}

// ---------------------------------------------------------------------------
// Mock setup for API clients
// ---------------------------------------------------------------------------

const {
  mockFetchSourceTypes,
  mockFetchPaginatedLogs,
  mockFetchLogsStats,
  mockFetchTopPairs,
} = vi.hoisted(() => ({
  mockFetchSourceTypes: vi.fn(),
  mockFetchPaginatedLogs: vi.fn(),
  mockFetchLogsStats: vi.fn(),
  mockFetchTopPairs: vi.fn(),
}))

vi.mock('../api/client', () => ({
  fetchSourceTypes: mockFetchSourceTypes,
  fetchThreats: vi.fn().mockResolvedValue([]),
  fetchHealth: vi.fn().mockResolvedValue({ status: 'ok', ollama_connected: false, ollama_model: null, db_ok: true }),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: unknown) {
      super(String(message ?? status))
      this.status = status
    }
  },
  resolveBaseUrl: vi.fn(() => ''),
  assertLoopbackBase: vi.fn(),
  buildHeaders: vi.fn(() => ({})),
}))

vi.mock('../api/logs', () => ({
  fetchLogsStats: mockFetchLogsStats,
  fetchTopTalkers: vi.fn().mockResolvedValue([]),
  fetchProtocolMix: vi.fn().mockResolvedValue([]),
  fetchPaginatedLogs: mockFetchPaginatedLogs,
  fetchTopPairs: mockFetchTopPairs,
  fetchThreatScore: vi.fn().mockResolvedValue(null),
  fetchDetailedAnalysis: vi.fn().mockResolvedValue(null),
  fetchRules: vi.fn().mockResolvedValue([]),
  fetchIpEvents: vi.fn().mockResolvedValue(null),
  fetchEntityGraph: vi.fn().mockResolvedValue(null),
}))

const PAGINATED_EMPTY = {
  logs: [],
  next_cursor: null,
  has_more: false,
  total_matching: 0,
}

/** Azure WAF log entry with all L3 fields null — matches real Azure WAF events. */
const AZURE_LOG: LogEntry = {
  ...LOG_ENTRY_FIXTURE,
  id: 1001,
  source_type: 'azure_waf',
  destination_ip: null,
  protocol: null,
  destination_port: null,
  tls_ja4: null,
  dns_query: null,
}

beforeEach(() => {
  _resetSourceTypeMapCache()
  mockFetchSourceTypes.mockResolvedValue([AZURE_WAF_SOURCE, SURICATA_SOURCE])
  mockFetchPaginatedLogs.mockResolvedValue({ ...PAGINATED_EMPTY, logs: [AZURE_LOG] })
  mockFetchLogsStats.mockResolvedValue({
    total_events: 1,
    blocked_events: 0,
    distinct_ips: 1,
    present_source_types: ['azure_waf'],
  })
  mockFetchTopPairs.mockResolvedValue([])
})

// ---------------------------------------------------------------------------
// Helper: render LogsTable with a large container (keeps all priority columns visible)
// ---------------------------------------------------------------------------

// ADR-0063 D6: structurallyAbsent prop is removed from LogsTable — the structural
// hiding axis is retired for the logs table (long-tail columns now live in the detail panel).
// renderTable no longer accepts or passes structurallyAbsent.
function renderTable(logs: LogEntry[]) {
  vi.spyOn(Element.prototype, 'getBoundingClientRect').mockReturnValue({
    width: 1400, height: 40, top: 0, left: 0, bottom: 40, right: 1400,
    x: 0, y: 0, toJSON: () => ({}),
  } as DOMRect)

  const result = render(
    <MemoryRouter>
      <LogsTable
        logs={logs}
        onIpClick={vi.fn()}
      />
    </MemoryRouter>,
  )
  vi.restoreAllMocks()
  return result
}

// ---------------------------------------------------------------------------
// useStructuralColumns hook tests
// ---------------------------------------------------------------------------

describe('useStructuralColumns — union logic', () => {
  it('Azure-WAF-only: structurallyAbsent includes destip, protocol, tls_ja4, dns, destport', async () => {
    mockFetchSourceTypes.mockResolvedValue([AZURE_WAF_SOURCE])

    const { result } = renderHook(() =>
      useStructuralColumns(['azure_waf'])
    )

    await waitFor(() => expect(result.current.loading).toBe(false))

    const absent = result.current.structurallyAbsent
    expect(absent.has('destip')).toBe(true)
    expect(absent.has('protocol')).toBe(true)
    expect(absent.has('destport')).toBe(true)
    expect(absent.has('tls_ja4')).toBe(true)
    expect(absent.has('dns')).toBe(true)
  })

  it('Suricata + Azure WAF both present: union suppresses hiding — no column absent', async () => {
    mockFetchSourceTypes.mockResolvedValue([AZURE_WAF_SOURCE, SURICATA_SOURCE])

    const { result } = renderHook(() =>
      useStructuralColumns(['azure_waf', 'suricata'])
    )

    await waitFor(() => expect(result.current.loading).toBe(false))

    // Suricata produces destination_ip, protocol, etc. — union covers everything
    const absent = result.current.structurallyAbsent
    expect(absent.size).toBe(0)
  })

  it('Suricata only: structurallyAbsent is empty (produces all optional fields)', async () => {
    mockFetchSourceTypes.mockResolvedValue([SURICATA_SOURCE])

    const { result } = renderHook(() =>
      useStructuralColumns(['suricata'])
    )

    await waitFor(() => expect(result.current.loading).toBe(false))

    expect(result.current.structurallyAbsent.size).toBe(0)
  })
})

describe('useStructuralColumns — produces-all semantics (ADR-0060 D2)', () => {
  it('empty produces (absent field) = produces-all → no columns hidden', async () => {
    mockFetchSourceTypes.mockResolvedValue([UNKNOWN_SOURCE])

    const { result } = renderHook(() =>
      useStructuralColumns(['unknown_plugin'])
    )

    await waitFor(() => expect(result.current.loading).toBe(false))

    // Empty/absent produces means "produces-all" — hide nothing
    expect(result.current.structurallyAbsent.size).toBe(0)
  })

  it('when any present source is produces-all, no column is hidden (even if others declare)', async () => {
    mockFetchSourceTypes.mockResolvedValue([AZURE_WAF_SOURCE, UNKNOWN_SOURCE])

    const { result } = renderHook(() =>
      useStructuralColumns(['azure_waf', 'unknown_plugin'])
    )

    await waitFor(() => expect(result.current.loading).toBe(false))

    // UNKNOWN_SOURCE has no produces → produces-all → overrides Azure WAF hiding
    expect(result.current.structurallyAbsent.size).toBe(0)
  })
})

describe('useStructuralColumns — fail-open when present_source_types is empty', () => {
  it('empty presentSourceTypes → hides nothing (fail-open)', async () => {
    const { result } = renderHook(() =>
      useStructuralColumns([])
    )

    // Should resolve quickly even before fetch (empty input → immediate empty return)
    await waitFor(() => expect(result.current.structurallyAbsent.size).toBe(0))
  })

  it('source type not in discovery map → treated as produces-all → no hiding', async () => {
    // Only Azure WAF is in the discovery map, but we have 'zeek' present which is unknown
    mockFetchSourceTypes.mockResolvedValue([AZURE_WAF_SOURCE])

    const { result } = renderHook(() =>
      useStructuralColumns(['zeek'])
    )

    await waitFor(() => expect(result.current.loading).toBe(false))

    // 'zeek' not in map → produces-all → no hiding
    expect(result.current.structurallyAbsent.size).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// HiddenFieldsChip component tests
// ---------------------------------------------------------------------------

describe('HiddenFieldsChip — renders nothing when no columns absent', () => {
  it('renders null when structurallyAbsent is empty', () => {
    const { container } = render(
      <HiddenFieldsChip structurallyAbsent={new Set()} />
    )
    expect(container.firstChild).toBeNull()
  })
})

describe('HiddenFieldsChip — chip content', () => {
  it('shows "+N fields not produced by this source" chip with correct count', () => {
    render(
      <HiddenFieldsChip structurallyAbsent={new Set(['destip', 'protocol', 'tls_ja4', 'dns', 'destport'])} />
    )
    const chip = screen.getByTestId('hidden-fields-chip')
    expect(chip).toBeInTheDocument()
    expect(chip.textContent).toContain('+5 fields not produced by this source')
  })

  it('shows singular "field" for count of 1', () => {
    render(
      <HiddenFieldsChip structurallyAbsent={new Set(['tls_ja4'])} />
    )
    expect(screen.getByTestId('hidden-fields-chip').textContent).toContain('+1 field not produced by this source')
  })
})

describe('HiddenFieldsChip — popover lists FIELD_NOTES', () => {
  it('popover lists each hidden column display label on click', async () => {
    render(
      <HiddenFieldsChip structurallyAbsent={new Set(['destip', 'protocol', 'tls_ja4', 'dns', 'destport'])} />
    )

    fireEvent.click(screen.getByTestId('hidden-fields-chip'))

    await waitFor(() => {
      expect(screen.getByTestId('hidden-fields-popover')).toBeInTheDocument()
    })

    // All column display labels should appear
    const labels = screen.getAllByTestId('hidden-field-label')
    const labelTexts = labels.map((el) => el.textContent ?? '')
    expect(labelTexts).toContain('Destination')
    expect(labelTexts).toContain('Protocol')
    expect(labelTexts).toContain('JA4')
    expect(labelTexts).toContain('DNS / DGA')
    expect(labelTexts).toContain('Dest Port')
  })

  it('popover shows FIELD_NOTES text for each hidden column', async () => {
    render(
      <HiddenFieldsChip structurallyAbsent={new Set(['destip', 'tls_ja4'])} />
    )

    fireEvent.click(screen.getByTestId('hidden-fields-chip'))

    await waitFor(() => {
      expect(screen.getByTestId('hidden-fields-popover')).toBeInTheDocument()
    })

    // Check that FIELD_NOTES prose appears in the popover
    const notes = screen.getAllByTestId('hidden-field-note')
    const noteTexts = notes.map((el) => el.textContent ?? '')
    expect(noteTexts.some((t) => t.includes('L7-only sources'))).toBe(true)
    expect(noteTexts.some((t) => t.includes('JA4 TLS fingerprints'))).toBe(true)
  })

  it('all COLUMN_CANONICAL_FIELDS column keys map to a FIELD_NOTES entry', () => {
    // Static consistency check: every column in COLUMN_CANONICAL_FIELDS has a note.
    for (const [, { displayLabel }] of Object.entries(COLUMN_CANONICAL_FIELDS)) {
      expect(FIELD_NOTES[displayLabel]).toBeTruthy()
    }
  })

  it('popover is keyboard-accessible (chip has aria-expanded)', () => {
    render(
      <HiddenFieldsChip structurallyAbsent={new Set(['destip'])} />
    )
    const btn = screen.getByTestId('hidden-fields-chip')
    expect(btn).toHaveAttribute('aria-expanded', 'false')
    fireEvent.click(btn)
    expect(btn).toHaveAttribute('aria-expanded', 'true')
  })
})

// ---------------------------------------------------------------------------
// LogsTable integration — ADR-0063 D6: structural hiding retired from the table
// ---------------------------------------------------------------------------
//
// The long-tail optional columns (Destination, Protocol, Dest Port, JA4, DNS/DGA)
// are no longer inline in the table — they moved to the detail panel (ADR-0063 D3).
// There is nothing inline to hide, so the structural-hiding axis is retired for the
// logs table. The LogsTable component no longer accepts structurallyAbsent.
//
// Tests that verified the LogsTable+structurallyAbsent integration (EARS-5) are
// replaced by: (a) confirming the spine columns render, (b) confirming no Destination/
// Protocol/JA4/DNS columns appear inline (they are panel-only now).

describe('LogsTable — spine columns present; long-tail columns absent (ADR-0063 D6)', () => {
  it('renders the 7 spine column headers + expand chevron, no long-tail columns inline', () => {
    renderTable([AZURE_LOG])

    const headers = document.querySelectorAll('th')
    const headerTexts = Array.from(headers).map((th) => th.textContent?.trim() ?? '')

    // Spine columns always present
    expect(headerTexts.some((t) => /Time/i.test(t))).toBe(true)
    expect(headerTexts.some((t) => /Source IP/i.test(t))).toBe(true)
    expect(headerTexts.some((t) => /Signature/i.test(t))).toBe(true)
    expect(headerTexts.some((t) => /Action/i.test(t))).toBe(true)
    expect(headerTexts.some((t) => /Severity/i.test(t))).toBe(true)
    expect(headerTexts.some((t) => /AI Verdict/i.test(t))).toBe(true)

    // Long-tail columns NOT inline (moved to detail panel)
    expect(headerTexts).not.toContain('Destination')
    expect(headerTexts).not.toContain('Protocol')
    expect(headerTexts).not.toContain('JA4')
    expect(headerTexts).not.toContain('DNS / DGA')
    expect(headerTexts).not.toContain('Dest Port')
  })

  it('HiddenFieldsChip toolbar is NOT present (hiding axis retired for this table)', () => {
    renderTable([AZURE_LOG])
    expect(screen.queryByTestId('logs-table-toolbar')).not.toBeInTheDocument()
    expect(screen.queryByTestId('hidden-fields-chip')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// SECURITY: chip renders only static notes, not attacker-controlled data
// ---------------------------------------------------------------------------

describe('HiddenFieldsChip — SECURITY', () => {
  it('chip renders static FIELD_NOTES text only — no attacker-controlled interpolation', async () => {
    render(
      <HiddenFieldsChip structurallyAbsent={new Set(['destip', 'tls_ja4'])} />
    )
    fireEvent.click(screen.getByTestId('hidden-fields-chip'))

    await waitFor(() => screen.getByTestId('hidden-fields-popover'))

    // All note text should be from the static FIELD_NOTES constant
    const notes = screen.getAllByTestId('hidden-field-note')
    for (const note of notes) {
      const text = note.textContent ?? ''
      // Should not contain any HTML injection markers
      expect(text).not.toContain('<script>')
      expect(text).not.toContain('onerror')
      // Should be a known FIELD_NOTES value
      const knownNotes = Object.values(FIELD_NOTES)
      expect(knownNotes.some((n) => text.includes(n.slice(0, 20)))).toBe(true)
    }
  })
})
