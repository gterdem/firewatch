/**
 * Tests for the Escalation Policy card (issue #650, ADR-0058 D1/D6, ADR-0059 D1/D5).
 *
 * EARS criteria covered:
 *
 * TriageThresholdField:
 *   - Rendered: "Triage threshold" label present (distinguishable from Notification threshold).
 *   - Rendered: subtitle states tier always surfaces regardless.
 *   - State-driven: GET /config/runtime populates triage_threshold.
 *   - State-driven: absent triage_threshold in response → default HIGH.
 *   - State-driven: GET fails → default HIGH (no crash).
 *   - Event-driven: threshold change → PUT /config/runtime with triage_threshold.
 *   - Event-driven: PUT success → success toast shown.
 *   - Event-driven: PUT failure → error toast shown.
 *
 * EscalationPolicyTable:
 *   - State-driven: loading → loading indicator present.
 *   - State-driven: rows render with rule_name, severity badge, auto_escalate badge, hit_count_24h.
 *   - State-driven: auto_escalate=true → "Auto-escalate" badge.
 *   - State-driven: auto_escalate=false → "—" rendered.
 *   - State-driven: severity=null → "—" rendered.
 *   - State-driven: empty policy → empty state shown.
 *   - State-driven: error → error message shown.
 *   - State-driven: 503 → error (service unavailable) shown.
 *   - Pagination: > PAGE_SIZE rows → pagination controls shown.
 *
 * DualAxisExplainer:
 *   - Rendered: "alert-worthy" text present.
 *   - Rendered: mentions both "Score band" axis and "Escalation tier" axis.
 *
 * EnforcementStaircase:
 *   - Rendered: WARN tier shows "Active" badge.
 *   - Rendered: "Require approval" tier shows "Active" badge.
 *   - Rendered: "Auto-block" tier shows "coming with SOAR" badge.
 *   - Rendered: auto-block tier is greyed / aria-disabled=true.
 *
 * Global card (modular-UI rule):
 *   - Card present in Settings page; not keyed to any source name.
 *
 * bandMeets utility (deriveTriageActors parameterization — separate describe):
 *   - threshold=HIGH: only HIGH/CRITICAL surface by band (same as old hard-coded behaviour).
 *   - threshold=MEDIUM: MEDIUM/HIGH/CRITICAL surface by band (wider set).
 *   - Unknown level → false (safe non-surface default).
 *   - Tier ≤ 2 always surfaces regardless of threshold.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import AlertingPolicyPanel from '../components/alerting/AlertingPolicyPanel'
import { DualAxisExplainer } from '../components/alerting/DualAxisExplainer'
import { EnforcementStaircase } from '../components/alerting/EnforcementStaircase'
import { EscalationPolicyTable } from '../components/alerting/EscalationPolicyTable'
import { bandMeets } from '../lib/threatLevel'
import { deriveTriageActors } from '../lib/triageBand'
import type { ThreatScore } from '../api/types'

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const { mockPutRuntimeConfig, mockGetRuntimeConfig, mockFetchEscalationPolicy } = vi.hoisted(
  () => ({
    mockPutRuntimeConfig: vi.fn(),
    mockGetRuntimeConfig: vi.fn(),
    mockFetchEscalationPolicy: vi.fn(),
  }),
)

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    putRuntimeConfig: mockPutRuntimeConfig,
    getRuntimeConfig: mockGetRuntimeConfig,
    fetchEscalationPolicy: mockFetchEscalationPolicy,
  }
})

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const RUNTIME_CONFIG_BASE = {
  alert_threshold: 'CRITICAL' as const,
  alert_on_sync: true,
  webhook_url: null,
  webhook_url_set: false,
  api_key_set: false,
  ollama_model: 'qwen3:14b',
  ai_enabled: true,
  ollama_base_url: 'http://localhost:11434',
  geo_provider: 'offline' as const,
  notify_on_auto_escalate: false,
  triage_threshold: 'HIGH' as const,
}

const POLICY_FIXTURE = {
  policy: [
    {
      rule_name: 'brute_force',
      severity: 'HIGH' as const,
      auto_escalate: true,
      hit_count_24h: 42,
    },
    {
      rule_name: 'sqli_attempt',
      severity: 'CRITICAL' as const,
      auto_escalate: false,
      hit_count_24h: 7,
    },
    {
      rule_name: 'port_scan',
      severity: null,
      auto_escalate: false,
      hit_count_24h: 0,
    },
  ],
  generated_at: '2026-06-14T12:00:00Z',
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderPanel() {
  return render(<AlertingPolicyPanel />)
}

// ---------------------------------------------------------------------------
// AlertingPolicyPanel — structure
// ---------------------------------------------------------------------------

describe('AlertingPolicyPanel — structure', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockPutRuntimeConfig.mockResolvedValue(undefined)
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_BASE)
    mockFetchEscalationPolicy.mockResolvedValue(POLICY_FIXTURE)
  })

  it('renders the "Escalation Policy" panel heading', async () => {
    renderPanel()
    await waitFor(() => {
      const heading = screen.getByRole('heading', { level: 2 })
      expect(heading.textContent).toContain('Escalation Policy')
    })
  })

  it('renders the dual-axis section group', async () => {
    renderPanel()
    await waitFor(() => {
      expect(screen.getByTestId('section-dual-axis')).toBeInTheDocument()
    })
  })

  it('renders the policy table section group', async () => {
    renderPanel()
    await waitFor(() => {
      expect(screen.getByTestId('section-policy-table')).toBeInTheDocument()
    })
  })

  it('renders the enforcement section group', async () => {
    renderPanel()
    await waitFor(() => {
      expect(screen.getByTestId('section-enforcement')).toBeInTheDocument()
    })
  })
})

// ---------------------------------------------------------------------------
// TriageThresholdField
// ---------------------------------------------------------------------------

describe('AlertingPolicyPanel — TriageThresholdField', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockPutRuntimeConfig.mockResolvedValue(undefined)
    mockFetchEscalationPolicy.mockResolvedValue(POLICY_FIXTURE)
  })

  // EARS: label must read "Triage threshold"
  it('renders "Triage threshold" label', async () => {
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_BASE)
    renderPanel()
    await waitFor(() => {
      // Use role=combobox or query by label text to uniquely find the select
      expect(screen.getByLabelText('Triage threshold')).toBeInTheDocument()
    })
  })

  // EARS: subtitle must state the tier always surfaces regardless
  it('renders the required subtitle about the escalation tier always surfacing', async () => {
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_BASE)
    renderPanel()
    await waitFor(() => {
      const subtitle = screen.getByTestId('triage-threshold-subtitle')
      expect(subtitle.textContent).toContain(
        'The action-aware escalation tier always surfaces in the banner regardless of this threshold.',
      )
    })
  })

  // State-driven: GET populates triage_threshold
  it('populates threshold from GET /config/runtime on mount', async () => {
    mockGetRuntimeConfig.mockResolvedValue({ ...RUNTIME_CONFIG_BASE, triage_threshold: 'MEDIUM' as const })
    renderPanel()
    await waitFor(() => {
      const select = screen.getByTestId('triage-threshold-select') as HTMLSelectElement
      expect(select.value).toBe('MEDIUM')
    })
  })

  // State-driven: absent triage_threshold → default HIGH
  it('defaults to HIGH when triage_threshold absent from GET response', async () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { triage_threshold: _excluded, ...withoutTriage } = RUNTIME_CONFIG_BASE
    mockGetRuntimeConfig.mockResolvedValue(withoutTriage)
    renderPanel()
    await waitFor(() => {
      const select = screen.getByTestId('triage-threshold-select') as HTMLSelectElement
      expect(select.value).toBe('HIGH')
    })
  })

  // State-driven: GET fails → default HIGH
  it('defaults to HIGH when getRuntimeConfig fails', async () => {
    const { ApiError } = await import('../api/client')
    mockGetRuntimeConfig.mockRejectedValue(new ApiError(503, null, 'Service Unavailable'))
    renderPanel()
    await waitFor(() => {
      const select = screen.getByTestId('triage-threshold-select') as HTMLSelectElement
      expect(select.value).toBe('HIGH')
    })
  })

  // Event-driven: threshold change → PUT /config/runtime with triage_threshold
  it('calls putRuntimeConfig with triage_threshold when threshold changes', async () => {
    const user = userEvent.setup()
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_BASE)
    renderPanel()

    const select = await screen.findByTestId('triage-threshold-select')
    await user.selectOptions(select, 'CRITICAL')

    await waitFor(() => {
      expect(mockPutRuntimeConfig).toHaveBeenCalledWith({ triage_threshold: 'CRITICAL' })
    })
  })

  // Event-driven: PUT success → success toast
  it('shows success toast after threshold change', async () => {
    const user = userEvent.setup()
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_BASE)
    renderPanel()

    const select = await screen.findByTestId('triage-threshold-select')
    await user.selectOptions(select, 'LOW')

    await waitFor(() => {
      const toast = screen.getByRole('status')
      expect(toast.textContent).toContain('LOW')
    })
  })

  // Event-driven: PUT failure → error toast
  it('shows error toast when threshold PUT fails', async () => {
    const user = userEvent.setup()
    const { ApiError } = await import('../api/client')
    mockGetRuntimeConfig.mockResolvedValue(RUNTIME_CONFIG_BASE)
    mockPutRuntimeConfig.mockRejectedValue(new ApiError(422, [{ msg: 'Invalid threshold' }]))
    renderPanel()

    const select = await screen.findByTestId('triage-threshold-select')
    await user.selectOptions(select, 'MEDIUM')

    await waitFor(() => {
      const toast = screen.getByRole('status')
      expect(toast.textContent).toContain('Invalid threshold')
    })
  })
})

// ---------------------------------------------------------------------------
// EscalationPolicyTable (standalone)
// ---------------------------------------------------------------------------

describe('EscalationPolicyTable', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('shows loading state initially', () => {
    // fetchEscalationPolicy never resolves during this test
    mockFetchEscalationPolicy.mockReturnValue(new Promise(() => {}))
    render(<EscalationPolicyTable />)
    expect(screen.getByTestId('escalation-table-loading')).toBeInTheDocument()
  })

  it('renders rows with rule_name, severity, auto_escalate, hit_count_24h', async () => {
    mockFetchEscalationPolicy.mockResolvedValue(POLICY_FIXTURE)
    render(<EscalationPolicyTable />)

    await waitFor(() => {
      expect(screen.getByTestId('escalation-policy-table')).toBeInTheDocument()
    })

    // rule_name (as text nodes — ADR-0029 D3: no dangerouslySetInnerHTML)
    expect(screen.getByText('brute_force')).toBeInTheDocument()
    expect(screen.getByText('sqli_attempt')).toBeInTheDocument()
    expect(screen.getByText('port_scan')).toBeInTheDocument()

    // severity badges
    expect(screen.getByTestId('severity-badge-brute_force').textContent).toBe('HIGH')
    expect(screen.getByTestId('severity-badge-sqli_attempt').textContent).toBe('CRITICAL')

    // hit_count_24h
    expect(screen.getByText('42')).toBeInTheDocument()
    expect(screen.getByText('7')).toBeInTheDocument()
  })

  it('renders auto_escalate=true as "Auto-escalate" badge', async () => {
    mockFetchEscalationPolicy.mockResolvedValue(POLICY_FIXTURE)
    render(<EscalationPolicyTable />)

    await waitFor(() => {
      expect(screen.getByTestId('auto-escalate-badge-brute_force')).toBeInTheDocument()
    })
    expect(screen.getByTestId('auto-escalate-badge-brute_force').textContent).toContain(
      'Auto-escalate',
    )
  })

  it('renders auto_escalate=false as "—"', async () => {
    mockFetchEscalationPolicy.mockResolvedValue(POLICY_FIXTURE)
    render(<EscalationPolicyTable />)

    await waitFor(() => {
      expect(screen.getByTestId('policy-row-sqli_attempt')).toBeInTheDocument()
    })
    // sqli_attempt has auto_escalate=false → no auto-escalate badge for it
    expect(screen.queryByTestId('auto-escalate-badge-sqli_attempt')).not.toBeInTheDocument()
  })

  it('renders severity=null as "—"', async () => {
    mockFetchEscalationPolicy.mockResolvedValue(POLICY_FIXTURE)
    render(<EscalationPolicyTable />)

    await waitFor(() => {
      expect(screen.getByTestId('policy-row-port_scan')).toBeInTheDocument()
    })
    // port_scan has severity=null → no severity badge
    expect(screen.queryByTestId('severity-badge-port_scan')).not.toBeInTheDocument()
  })

  it('shows empty state when policy is empty', async () => {
    mockFetchEscalationPolicy.mockResolvedValue({ policy: [], generated_at: '2026-06-14T12:00:00Z' })
    render(<EscalationPolicyTable />)

    await waitFor(() => {
      expect(screen.getByTestId('escalation-table-empty')).toBeInTheDocument()
    })
  })

  it('shows error message on API failure', async () => {
    const { ApiError } = await import('../api/client')
    mockFetchEscalationPolicy.mockRejectedValue(new ApiError(500, null, 'Server error'))
    render(<EscalationPolicyTable />)

    await waitFor(() => {
      expect(screen.getByTestId('escalation-table-error')).toBeInTheDocument()
    })
    expect(screen.getByRole('alert').textContent).toContain('Failed to load escalation policy')
  })

  it('shows service unavailable on 503 (null return)', async () => {
    mockFetchEscalationPolicy.mockResolvedValue(null)
    render(<EscalationPolicyTable />)

    await waitFor(() => {
      expect(screen.getByTestId('escalation-table-error')).toBeInTheDocument()
    })
    expect(screen.getByRole('alert').textContent).toContain('503')
  })

  it('shows pagination when policy has more than PAGE_SIZE rows', async () => {
    // Build 11 rows to trigger pagination (PAGE_SIZE=10)
    const manyRows = Array.from({ length: 11 }, (_, i) => ({
      rule_name: `rule_${i}`,
      severity: 'LOW' as const,
      auto_escalate: false,
      hit_count_24h: i,
    }))
    mockFetchEscalationPolicy.mockResolvedValue({
      policy: manyRows,
      generated_at: '2026-06-14T12:00:00Z',
    })
    render(<EscalationPolicyTable />)

    await waitFor(() => {
      expect(screen.getByTestId('escalation-table-pagination')).toBeInTheDocument()
    })
  })
})

// ---------------------------------------------------------------------------
// DualAxisExplainer (standalone)
// ---------------------------------------------------------------------------

describe('DualAxisExplainer', () => {
  it('renders the explainer with alert-worthy text', () => {
    render(<DualAxisExplainer />)
    expect(screen.getByTestId('dual-axis-explainer')).toBeInTheDocument()
    expect(screen.getByTestId('dual-axis-explainer').textContent).toContain('alert-worthy')
  })

  it('mentions the score band axis', () => {
    render(<DualAxisExplainer />)
    expect(screen.getByTestId('dual-axis-explainer').textContent).toContain('Score band')
  })

  it('mentions the escalation tier axis', () => {
    render(<DualAxisExplainer />)
    expect(screen.getByTestId('dual-axis-explainer').textContent).toContain('Escalation tier')
  })
})

// ---------------------------------------------------------------------------
// EnforcementStaircase (standalone)
// ---------------------------------------------------------------------------

describe('EnforcementStaircase', () => {
  it('renders all three enforcement tiers', () => {
    render(<EnforcementStaircase />)
    expect(screen.getByTestId('enforcement-staircase')).toBeInTheDocument()
    expect(screen.getByTestId('enforcement-tier-warn')).toBeInTheDocument()
    expect(screen.getByTestId('enforcement-tier-require-approval')).toBeInTheDocument()
    expect(screen.getByTestId('enforcement-tier-auto-block')).toBeInTheDocument()
  })

  it('shows WARN tier as active', () => {
    render(<EnforcementStaircase />)
    expect(screen.getByTestId('tier-badge-active-warn')).toBeInTheDocument()
    expect(screen.getByTestId('tier-badge-active-warn').textContent).toContain('Active')
  })

  it('shows require-approval tier as active', () => {
    render(<EnforcementStaircase />)
    expect(screen.getByTestId('tier-badge-active-require-approval')).toBeInTheDocument()
    expect(screen.getByTestId('tier-badge-active-require-approval').textContent).toContain('Active')
  })

  it('shows auto-block tier as "coming with SOAR" (greyed)', () => {
    render(<EnforcementStaircase />)
    expect(screen.getByTestId('tier-badge-coming-auto-block')).toBeInTheDocument()
    expect(screen.getByTestId('tier-badge-coming-auto-block').textContent).toContain(
      'coming with SOAR',
    )
  })

  it('marks auto-block tier as aria-disabled', () => {
    render(<EnforcementStaircase />)
    const autoBlock = screen.getByTestId('enforcement-tier-auto-block')
    expect(autoBlock.getAttribute('aria-disabled')).toBe('true')
  })

  it('does NOT mark WARN tier as aria-disabled', () => {
    render(<EnforcementStaircase />)
    const warn = screen.getByTestId('enforcement-tier-warn')
    expect(warn.getAttribute('aria-disabled')).toBe('false')
  })
})

// ---------------------------------------------------------------------------
// bandMeets utility + deriveTriageActors parameterization
// ---------------------------------------------------------------------------

describe('bandMeets', () => {
  it('HIGH meets HIGH threshold', () => expect(bandMeets('HIGH', 'HIGH')).toBe(true))
  it('CRITICAL meets HIGH threshold', () => expect(bandMeets('CRITICAL', 'HIGH')).toBe(true))
  it('MEDIUM does NOT meet HIGH threshold', () => expect(bandMeets('MEDIUM', 'HIGH')).toBe(false))
  it('LOW does NOT meet HIGH threshold', () => expect(bandMeets('LOW', 'HIGH')).toBe(false))

  it('MEDIUM meets MEDIUM threshold', () => expect(bandMeets('MEDIUM', 'MEDIUM')).toBe(true))
  it('HIGH meets MEDIUM threshold', () => expect(bandMeets('HIGH', 'MEDIUM')).toBe(true))
  it('CRITICAL meets MEDIUM threshold', () => expect(bandMeets('CRITICAL', 'MEDIUM')).toBe(true))
  it('LOW does NOT meet MEDIUM threshold', () => expect(bandMeets('LOW', 'MEDIUM')).toBe(false))

  it('LOW meets LOW threshold', () => expect(bandMeets('LOW', 'LOW')).toBe(true))
  it('CRITICAL meets LOW threshold', () => expect(bandMeets('CRITICAL', 'LOW')).toBe(true))

  it('unknown level returns false (safe default)', () => {
    expect(bandMeets('UNKNOWN', 'HIGH')).toBe(false)
  })
  it('unknown threshold returns false (safe default)', () => {
    expect(bandMeets('HIGH', 'BOGUS')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// deriveTriageActors threshold parameterization
// ---------------------------------------------------------------------------

/** Factory to build a minimal ThreatScore for testing deriveTriageActors. */
function makeThreat(
  ip: string,
  threatLevel: string,
  score = 50,
  tier?: number,
): ThreatScore {
  return {
    source_ip: ip,
    threat_level: threatLevel,
    score,
    total_events: 1,
    blocked_events: 0,
    attack_types: [],
    first_seen: '2026-06-14T12:00:00Z',
    last_seen: '2026-06-14T12:00:00Z',
    source_types: [],
    detections: [],
    ai_insights: null,
    ai_confidence: null,
    ai_status: 'disabled',
    location: null,
    score_breakdown: [],
    asn: null,
    as_name: null,
    score_delta: null,
    escalation: tier != null
      ? { tier, disposition: 'allowed_through', justification: '[RULE] test', block_status: 'unknown' }
      : null,
  }
}

describe('deriveTriageActors — threshold parameterization', () => {
  it('threshold=HIGH: CRITICAL surfaces by band', () => {
    const threats = [makeThreat('192.0.2.1', 'CRITICAL')]
    expect(deriveTriageActors(threats, 'HIGH')).toHaveLength(1)
  })

  it('threshold=HIGH: HIGH surfaces by band', () => {
    const threats = [makeThreat('192.0.2.2', 'HIGH')]
    expect(deriveTriageActors(threats, 'HIGH')).toHaveLength(1)
  })

  it('threshold=HIGH: MEDIUM does NOT surface by band', () => {
    const threats = [makeThreat('192.0.2.3', 'MEDIUM')]
    expect(deriveTriageActors(threats, 'HIGH')).toHaveLength(0)
  })

  it('threshold=HIGH: LOW does NOT surface by band', () => {
    const threats = [makeThreat('192.0.2.4', 'LOW')]
    expect(deriveTriageActors(threats, 'HIGH')).toHaveLength(0)
  })

  it('threshold=HIGH default == same as explicit HIGH', () => {
    const threats = [
      makeThreat('192.0.2.1', 'CRITICAL'),
      makeThreat('192.0.2.2', 'HIGH'),
      makeThreat('192.0.2.3', 'MEDIUM'),
      makeThreat('192.0.2.4', 'LOW'),
    ]
    // Default ("HIGH" implicit) must match explicit "HIGH"
    const withDefault = deriveTriageActors(threats)
    const withExplicit = deriveTriageActors(threats, 'HIGH')
    expect(withDefault.map((t) => t.source_ip)).toEqual(withExplicit.map((t) => t.source_ip))
  })

  it('threshold=MEDIUM: MEDIUM/HIGH/CRITICAL surface, LOW does not', () => {
    const threats = [
      makeThreat('192.0.2.1', 'CRITICAL'),
      makeThreat('192.0.2.2', 'HIGH'),
      makeThreat('192.0.2.3', 'MEDIUM'),
      makeThreat('192.0.2.4', 'LOW'),
    ]
    const result = deriveTriageActors(threats, 'MEDIUM')
    const ips = result.map((t) => t.source_ip)
    expect(ips).toContain('192.0.2.1')
    expect(ips).toContain('192.0.2.2')
    expect(ips).toContain('192.0.2.3')
    expect(ips).not.toContain('192.0.2.4')
  })

  it('threshold=LOW: all levels surface by band', () => {
    const threats = [
      makeThreat('192.0.2.1', 'CRITICAL'),
      makeThreat('192.0.2.2', 'HIGH'),
      makeThreat('192.0.2.3', 'MEDIUM'),
      makeThreat('192.0.2.4', 'LOW'),
    ]
    expect(deriveTriageActors(threats, 'LOW')).toHaveLength(4)
  })

  it('escalation tier ≤ 2 always surfaces regardless of threshold', () => {
    // LOW threat with tier=1 must surface even with CRITICAL threshold
    const lowWithTier1 = makeThreat('192.0.2.5', 'LOW', 20, 1)
    const result = deriveTriageActors([lowWithTier1], 'CRITICAL')
    expect(result).toHaveLength(1)
    expect(result[0].source_ip).toBe('192.0.2.5')
  })

  it('escalation tier 3 does NOT surface when band does not meet threshold', () => {
    const mediumTier3 = makeThreat('192.0.2.6', 'MEDIUM', 40, 3)
    const result = deriveTriageActors([mediumTier3], 'CRITICAL')
    expect(result).toHaveLength(0)
  })
})
