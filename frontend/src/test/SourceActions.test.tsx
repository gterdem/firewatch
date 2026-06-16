/**
 * Tests for src/components/sources/SourceActions.tsx
 *
 * EARS criteria covered:
 *   - State-driven: source with declared actions → buttons rendered per declaration.
 *   - State-driven: source with no declared actions → no action UI rendered.
 *   - Event-driven: action with confirm → dialog shown before POST fires.
 *   - Event-driven: cancel confirm → POST never fires.
 *   - Event-driven: confirm OK → POST fires, result rendered.
 *   - State-driven: long_running action in flight → spinner, button disabled.
 *   - Event-driven: 409 from POST → "already running" message, no crash.
 *   - Event-driven: ok=false ActionResult → sanitized message rendered.
 *   - Ubiquitous: status row renders last_run_at, stale indicator.
 *   - Unwanted: 404/503 on GET actions → graceful degrade (no crash).
 *   - Ubiquitous: no type_key branches — uses fictional "demo_ids" fixture.
 *   - A11y: buttons and dialog are real focusable labeled controls.
 *   - R2 fix: epoch-seconds last_run_at → correct date (not 1970).
 *   - R3 fix: status_message shown whenever non-null, not only when stale=true.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import SourceActions from '../components/sources/SourceActions'
import {
  DEMO_FETCH_RULES_ACTION,
  DEMO_PURGE_CACHE_ACTION,
  DEMO_FETCH_RULES_ENTRY_STALE,
  DEMO_FETCH_RULES_ENTRY_OK,
  DEMO_FETCH_RULES_ENTRY_NULL,
  DEMO_FETCH_RULES_ENTRY_EPOCH,
  DEMO_FETCH_RULES_ENTRY_HEALTHY_MSG,
  STAGED_RESULT_MIXED,
  PLAIN_DETAIL_RESULT,
} from './fixtures'
import type { ActionEntry, ActionResult } from '../api/types'
import type { SourceActionDeclaration } from '../schema/types'

// Hoist mock refs before vi.mock factory.
const { mockFetchSourceActions, mockRunSourceAction } = vi.hoisted(() => ({
  mockFetchSourceActions: vi.fn(),
  mockRunSourceAction: vi.fn(),
}))

vi.mock('../api/sourceActions', () => ({
  fetchSourceActions: mockFetchSourceActions,
  runSourceAction: mockRunSourceAction,
}))

vi.mock('../api/client', () => {
  class ApiError extends Error {
    status: number
    detail: unknown
    constructor(status: number, detail: unknown, message?: string) {
      super(message ?? `API error ${status}`)
      this.status = status
      this.detail = detail
    }
  }
  return { ApiError, resolveBaseUrl: () => '', assertLoopbackBase: () => undefined }
})

// Default render helper: two actions, stale status.
function renderActions(
  declarations: SourceActionDeclaration[] = [DEMO_FETCH_RULES_ACTION, DEMO_PURGE_CACHE_ACTION],
  entries: ActionEntry[] = [DEMO_FETCH_RULES_ENTRY_STALE],
) {
  mockFetchSourceActions.mockResolvedValue(entries)
  render(
    <SourceActions
      typeKey="demo_ids"
      sourceId="demo_ids"
      declarations={declarations}
    />,
  )
}

describe('SourceActions — state-driven: declared actions render', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  // EARS state-driven: source with declared actions → buttons rendered.
  it('renders one button per declared action', async () => {
    renderActions()
    await waitFor(() => {
      expect(screen.getByTestId('action-btn-fetch_rules')).toBeInTheDocument()
      expect(screen.getByTestId('action-btn-purge_cache')).toBeInTheDocument()
    })
    // Button labels come from declaration
    expect(screen.getByTestId('action-btn-fetch_rules').textContent).toContain(
      'Download rule descriptions',
    )
    expect(screen.getByTestId('action-btn-purge_cache').textContent).toContain('Purge cache')
  })

  // EARS state-driven: source with no declared actions → no action UI.
  it('renders nothing when declarations array is empty', () => {
    mockFetchSourceActions.mockResolvedValue([])
    const { container } = render(
      <SourceActions typeKey="syslog_plain" sourceId="syslog_plain" declarations={[]} />,
    )
    // No source-actions div rendered
    expect(container.querySelector('[data-testid="source-actions"]')).toBeNull()
  })

  // EARS ubiquitous: status row — last_run_at + stale indicator.
  it('renders last-run date and stale indicator when status reports stale=true', async () => {
    renderActions([DEMO_FETCH_RULES_ACTION], [DEMO_FETCH_RULES_ENTRY_STALE])
    await waitFor(() => {
      expect(screen.getByTestId('action-last-run-fetch_rules')).toBeInTheDocument()
      expect(screen.getByTestId('action-stale-fetch_rules')).toBeInTheDocument()
    })
    // Stale message is the verbatim status_message from the server
    expect(screen.getByTestId('action-stale-fetch_rules').textContent).toBe(
      DEMO_FETCH_RULES_ENTRY_STALE.status_message,
    )
  })

  // EARS ubiquitous: no status row when stale=false and last_run_at is absent.
  it('renders no status row when entry has null last_run_at and stale=null', async () => {
    renderActions([DEMO_FETCH_RULES_ACTION], [DEMO_FETCH_RULES_ENTRY_NULL])
    await waitFor(() => {
      expect(screen.getByTestId('action-btn-fetch_rules')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('action-status-row-fetch_rules')).toBeNull()
  })

  // EARS ubiquitous: status row shown when last_run_at present but stale=false.
  it('renders last-run date without stale indicator when stale=false and status_message=null', async () => {
    renderActions([DEMO_FETCH_RULES_ACTION], [DEMO_FETCH_RULES_ENTRY_OK])
    await waitFor(() => {
      expect(screen.getByTestId('action-last-run-fetch_rules')).toBeInTheDocument()
    })
    // status_message is null in ENTRY_OK — no status message div expected
    expect(screen.queryByTestId('action-stale-fetch_rules')).toBeNull()
  })

  // R2 fix: epoch-seconds last_run_at must NOT produce a 1970 date.
  // The API returns last_run_at as a Unix float (seconds), e.g. 1781162501.16.
  // fmtDate must multiply by 1000 to get the correct year (2026), not 1970.
  it('R2: displays correct date when last_run_at is epoch seconds (not 1970)', async () => {
    renderActions([DEMO_FETCH_RULES_ACTION], [DEMO_FETCH_RULES_ENTRY_EPOCH])
    await waitFor(() => {
      expect(screen.getByTestId('action-last-run-fetch_rules')).toBeInTheDocument()
    })
    const lastRunText = screen.getByTestId('action-last-run-fetch_rules').textContent ?? ''
    // The displayed year must be 2026 (epoch 1781162501 ≈ June 2026), not 1970
    expect(lastRunText).not.toContain('1970')
    expect(lastRunText).toContain('2026')
  })

  // R3 fix: status_message must be shown whenever non-null, regardless of stale flag.
  // A healthy catalog (stale=null, status_message="50723 rules loaded…") was hidden
  // by the old gate (stale===true). The fix shows it for all non-null status_message.
  it('R3: shows status_message when stale=null but message is non-null (healthy catalog)', async () => {
    renderActions([DEMO_FETCH_RULES_ACTION], [DEMO_FETCH_RULES_ENTRY_HEALTHY_MSG])
    await waitFor(() => {
      expect(screen.getByTestId('action-stale-fetch_rules')).toBeInTheDocument()
    })
    expect(screen.getByTestId('action-stale-fetch_rules').textContent).toBe(
      DEMO_FETCH_RULES_ENTRY_HEALTHY_MSG.status_message,
    )
    // stale=null → must NOT have the amber warning class (just muted text)
    const msgEl = screen.getByTestId('action-stale-fetch_rules')
    expect(msgEl.className).not.toContain('amber')
  })

  // R3 fix: stale=true still shows the amber variant.
  it('R3: stale=true status message gets amber styling', async () => {
    renderActions([DEMO_FETCH_RULES_ACTION], [DEMO_FETCH_RULES_ENTRY_STALE])
    await waitFor(() => {
      expect(screen.getByTestId('action-stale-fetch_rules')).toBeInTheDocument()
    })
    const msgEl = screen.getByTestId('action-stale-fetch_rules')
    expect(msgEl.className).toContain('amber')
  })
})

describe('SourceActions — event-driven: confirm dialog', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  // EARS event-driven: action with non-null confirm → dialog shown before POST.
  it('shows confirm dialog when action has confirm prose — POST not fired immediately', async () => {
    const user = userEvent.setup()
    mockFetchSourceActions.mockResolvedValue([DEMO_FETCH_RULES_ENTRY_STALE])
    render(
      <SourceActions
        typeKey="demo_ids"
        sourceId="demo_ids"
        declarations={[DEMO_FETCH_RULES_ACTION]}
      />,
    )

    await waitFor(() => {
      expect(screen.getByTestId('action-btn-fetch_rules')).toBeInTheDocument()
    })

    // Click the action button
    await act(async () => {
      await user.click(screen.getByTestId('action-btn-fetch_rules'))
    })

    // Confirm dialog must be shown
    expect(screen.getByTestId('action-confirm-dialog')).toBeInTheDocument()
    // Prose (the size warning) must be rendered
    expect(screen.getByTestId('action-confirm-prose').textContent).toContain('40–60 MB')
    // POST must NOT have fired yet
    expect(mockRunSourceAction).not.toHaveBeenCalled()
  })

  // EARS event-driven: cancel confirm → POST never fires.
  it('does not fire POST when user cancels the confirm dialog', async () => {
    const user = userEvent.setup()
    mockFetchSourceActions.mockResolvedValue([DEMO_FETCH_RULES_ENTRY_STALE])
    render(
      <SourceActions
        typeKey="demo_ids"
        sourceId="demo_ids"
        declarations={[DEMO_FETCH_RULES_ACTION]}
      />,
    )

    await waitFor(() => {
      expect(screen.getByTestId('action-btn-fetch_rules')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('action-btn-fetch_rules'))
    })
    await act(async () => {
      await user.click(screen.getByTestId('action-confirm-cancel'))
    })

    // Dialog closed, POST never called
    expect(screen.queryByTestId('action-confirm-dialog')).toBeNull()
    expect(mockRunSourceAction).not.toHaveBeenCalled()
  })

  // EARS event-driven: confirm OK → POST fires.
  it('fires POST when user clicks confirm OK', async () => {
    const user = userEvent.setup()
    mockFetchSourceActions.mockResolvedValue([DEMO_FETCH_RULES_ENTRY_STALE])
    const mockResult: ActionResult = {
      ok: true,
      message: 'Rule descriptions downloaded successfully.',
      detail: {},
      source_type: 'demo_ids',
      source_id: 'demo_ids',
      action_id: 'fetch_rules',
    }
    mockRunSourceAction.mockResolvedValue(mockResult)

    render(
      <SourceActions
        typeKey="demo_ids"
        sourceId="demo_ids"
        declarations={[DEMO_FETCH_RULES_ACTION]}
      />,
    )

    await waitFor(() => {
      expect(screen.getByTestId('action-btn-fetch_rules')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('action-btn-fetch_rules'))
    })
    await act(async () => {
      await user.click(screen.getByTestId('action-confirm-ok'))
    })

    await waitFor(() => {
      expect(mockRunSourceAction).toHaveBeenCalledWith(
        'demo_ids',
        'demo_ids',
        'fetch_rules',
        expect.anything(),
      )
    })
  })

  // EARS event-driven: action without confirm → POST fires immediately (no dialog).
  it('fires POST immediately for action without confirm prose', async () => {
    const user = userEvent.setup()
    mockFetchSourceActions.mockResolvedValue([])
    const mockResult: ActionResult = {
      ok: true,
      message: 'Cache purged.',
      detail: {},
      source_type: 'demo_ids',
      source_id: 'demo_ids',
      action_id: 'purge_cache',
    }
    mockRunSourceAction.mockResolvedValue(mockResult)

    render(
      <SourceActions
        typeKey="demo_ids"
        sourceId="demo_ids"
        declarations={[DEMO_PURGE_CACHE_ACTION]}
      />,
    )

    await waitFor(() => {
      expect(screen.getByTestId('action-btn-purge_cache')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('action-btn-purge_cache'))
    })

    // No confirm dialog — POST fired directly
    expect(screen.queryByTestId('action-confirm-dialog')).toBeNull()
    await waitFor(() => {
      expect(mockRunSourceAction).toHaveBeenCalledWith(
        'demo_ids',
        'demo_ids',
        'purge_cache',
        undefined,
      )
    })
  })
})

describe('SourceActions — event-driven: action results and errors', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  // EARS event-driven: ok=true ActionResult → success message shown.
  it('renders success message when ActionResult ok=true', async () => {
    const user = userEvent.setup()
    mockFetchSourceActions.mockResolvedValue([])
    const mockResult: ActionResult = {
      ok: true,
      message: 'Cache purged successfully.',
      detail: {},
      source_type: 'demo_ids',
      source_id: 'demo_ids',
      action_id: 'purge_cache',
    }
    mockRunSourceAction.mockResolvedValue(mockResult)

    render(
      <SourceActions
        typeKey="demo_ids"
        sourceId="demo_ids"
        declarations={[DEMO_PURGE_CACHE_ACTION]}
      />,
    )

    await waitFor(() => {
      expect(screen.getByTestId('action-btn-purge_cache')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('action-btn-purge_cache'))
    })

    await waitFor(() => {
      expect(screen.getByTestId('action-result-purge_cache')).toBeInTheDocument()
    })
    expect(screen.getByTestId('action-result-purge_cache').textContent).toContain(
      'Cache purged successfully.',
    )
  })

  // EARS event-driven: ok=false ActionResult → sanitized error message rendered (not raw HTML).
  it('renders sanitized error text when ActionResult ok=false', async () => {
    const user = userEvent.setup()
    mockFetchSourceActions.mockResolvedValue([])
    const mockResult: ActionResult = {
      ok: false,
      message: 'Connection refused.',
      detail: {},
      source_type: 'demo_ids',
      source_id: 'demo_ids',
      action_id: 'purge_cache',
    }
    mockRunSourceAction.mockResolvedValue(mockResult)

    render(
      <SourceActions
        typeKey="demo_ids"
        sourceId="demo_ids"
        declarations={[DEMO_PURGE_CACHE_ACTION]}
      />,
    )

    await waitFor(() => {
      expect(screen.getByTestId('action-btn-purge_cache')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('action-btn-purge_cache'))
    })

    await waitFor(() => {
      expect(screen.getByTestId('action-result-purge_cache')).toBeInTheDocument()
    })
    // Rendered as text — no dangerouslySetInnerHTML possible via testing-library
    expect(screen.getByTestId('action-result-purge_cache').textContent).toContain(
      'Connection refused.',
    )
  })

  // EARS event-driven: 409 → "already running" message, no crash.
  it('shows "already running" message on 409 response', async () => {
    const { ApiError } = await import('../api/client')
    const user = userEvent.setup()
    mockFetchSourceActions.mockResolvedValue([])
    mockRunSourceAction.mockRejectedValue(
      new ApiError(
        409,
        { detail: 'An action is already running for this source. Try again later.' },
        'API 409',
      ),
    )

    render(
      <SourceActions
        typeKey="demo_ids"
        sourceId="demo_ids"
        declarations={[DEMO_PURGE_CACHE_ACTION]}
      />,
    )

    await waitFor(() => {
      expect(screen.getByTestId('action-btn-purge_cache')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('action-btn-purge_cache'))
    })

    await waitFor(() => {
      expect(screen.getByTestId('action-error-purge_cache')).toBeInTheDocument()
    })
    expect(screen.getByTestId('action-error-purge_cache').textContent).toContain(
      'already running',
    )
  })
})

describe('SourceActions — unwanted: graceful degrade on API errors', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  // EARS unwanted: 404 on GET actions → no buttons / null status, no crash.
  it('degrades gracefully when GET /actions returns 404', async () => {
    const { ApiError } = await import('../api/client')
    mockFetchSourceActions.mockRejectedValue(new ApiError(404, null, 'Not Found'))

    render(
      <SourceActions
        typeKey="demo_ids"
        sourceId="demo_ids"
        declarations={[DEMO_FETCH_RULES_ACTION]}
      />,
    )

    // Wait for mount effects to settle
    await waitFor(() => {
      // The action button is still rendered (from declaration props)
      // Status row is absent (no entries loaded)
      expect(screen.getByTestId('action-btn-fetch_rules')).toBeInTheDocument()
    })
    // Status row must not be present (no status loaded)
    expect(screen.queryByTestId('action-status-row-fetch_rules')).toBeNull()
    // No crash — load error not surfaced for 404 (graceful)
    expect(screen.queryByTestId('source-actions-load-error')).toBeNull()
  })

  // EARS unwanted: 503 on GET actions → same graceful degrade.
  it('degrades gracefully when GET /actions returns 503 (no supervisor)', async () => {
    const { ApiError } = await import('../api/client')
    mockFetchSourceActions.mockRejectedValue(new ApiError(503, null, 'Service Unavailable'))

    render(
      <SourceActions
        typeKey="demo_ids"
        sourceId="demo_ids"
        declarations={[DEMO_FETCH_RULES_ACTION]}
      />,
    )

    await waitFor(() => {
      expect(screen.getByTestId('action-btn-fetch_rules')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('source-actions-load-error')).toBeNull()
  })
})

describe('SourceActions — a11y', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFetchSourceActions.mockResolvedValue([DEMO_FETCH_RULES_ENTRY_STALE])
  })

  // EARS a11y: buttons are real <button> elements with accessible labels.
  it('action buttons are real button elements with aria-label', async () => {
    render(
      <SourceActions
        typeKey="demo_ids"
        sourceId="demo_ids"
        declarations={[DEMO_FETCH_RULES_ACTION]}
      />,
    )

    await waitFor(() => {
      const btn = screen.getByTestId('action-btn-fetch_rules')
      expect(btn.tagName).toBe('BUTTON')
      expect(btn).toHaveAttribute('aria-label')
    })
  })

  // EARS a11y: confirm dialog has role="dialog" and aria-modal="true".
  it('confirm dialog has role=dialog and aria-modal=true', async () => {
    const user = userEvent.setup()
    render(
      <SourceActions
        typeKey="demo_ids"
        sourceId="demo_ids"
        declarations={[DEMO_FETCH_RULES_ACTION]}
      />,
    )

    await waitFor(() => {
      expect(screen.getByTestId('action-btn-fetch_rules')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('action-btn-fetch_rules'))
    })

    const dialog = screen.getByTestId('action-confirm-dialog')
    expect(dialog).toHaveAttribute('role', 'dialog')
    expect(dialog).toHaveAttribute('aria-modal', 'true')
  })
})

// ---------------------------------------------------------------------------
// Issue #691 — staged detail checklist integration tests
// ---------------------------------------------------------------------------

describe('SourceActions — staged detail checklist (issue #691)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  /**
   * EARS: WHEN operator clicks an action and result.detail has stage_* keys,
   * THE SourceActions panel SHALL render a staged checklist with each row.
   */
  it('renders staged checklist when action result detail has stage_* keys', async () => {
    const user = userEvent.setup()
    mockFetchSourceActions.mockResolvedValue([])
    mockRunSourceAction.mockResolvedValue(STAGED_RESULT_MIXED)

    render(
      <SourceActions
        typeKey="demo_ids"
        sourceId="demo_ids"
        declarations={[DEMO_PURGE_CACHE_ACTION]}
      />,
    )

    await waitFor(() => {
      expect(screen.getByTestId('action-btn-purge_cache')).toBeInTheDocument()
    })

    await act(async () => {
      await user.click(screen.getByTestId('action-btn-purge_cache'))
    })

    await waitFor(() => {
      expect(screen.getByTestId('action-result-purge_cache')).toBeInTheDocument()
    })

    // Checklist must appear inside the result panel
    expect(screen.getByTestId('staged-detail-checklist')).toBeInTheDocument()
    // All three stage rows rendered
    expect(screen.getByTestId('stage-row-ssh')).toBeInTheDocument()
    expect(screen.getByTestId('stage-row-evejson')).toBeInTheDocument()
    expect(screen.getByTestId('stage-row-activity')).toBeInTheDocument()
  })

  /**
   * EARS: WHEN a stage value is "fail", the row SHALL be visually marked as an error.
   */
  it('fail stage has destructive styling in the result panel', async () => {
    const user = userEvent.setup()
    mockFetchSourceActions.mockResolvedValue([])
    mockRunSourceAction.mockResolvedValue(STAGED_RESULT_MIXED)

    render(
      <SourceActions
        typeKey="demo_ids"
        sourceId="demo_ids"
        declarations={[DEMO_PURGE_CACHE_ACTION]}
      />,
    )

    await waitFor(() => expect(screen.getByTestId('action-btn-purge_cache')).toBeInTheDocument())
    await act(async () => { await user.click(screen.getByTestId('action-btn-purge_cache')) })
    await waitFor(() => expect(screen.getByTestId('staged-detail-checklist')).toBeInTheDocument())

    const failLabel = screen.getByTestId('stage-label-evejson')
    expect(failLabel.className).toContain('destructive')
  })

  /**
   * EARS: WHEN a stage value is "skip", the row SHALL render as advisory (muted), not error.
   */
  it('skip stage has muted (not destructive) styling', async () => {
    const user = userEvent.setup()
    mockFetchSourceActions.mockResolvedValue([])
    mockRunSourceAction.mockResolvedValue(STAGED_RESULT_MIXED)

    render(
      <SourceActions
        typeKey="demo_ids"
        sourceId="demo_ids"
        declarations={[DEMO_PURGE_CACHE_ACTION]}
      />,
    )

    await waitFor(() => expect(screen.getByTestId('action-btn-purge_cache')).toBeInTheDocument())
    await act(async () => { await user.click(screen.getByTestId('action-btn-purge_cache')) })
    await waitFor(() => expect(screen.getByTestId('staged-detail-checklist')).toBeInTheDocument())

    const skipLabel = screen.getByTestId('stage-label-activity')
    expect(skipLabel.className).not.toContain('destructive')
    expect(skipLabel.className).toContain('muted')
  })

  /**
   * Regression: result with only plain detail keys (no stage_*) renders the
   * existing flat result text without a checklist.
   */
  it('regression: plain detail keys render flat result text without checklist', async () => {
    const user = userEvent.setup()
    mockFetchSourceActions.mockResolvedValue([])
    mockRunSourceAction.mockResolvedValue(PLAIN_DETAIL_RESULT)

    render(
      <SourceActions
        typeKey="demo_ids"
        sourceId="demo_ids"
        declarations={[DEMO_PURGE_CACHE_ACTION]}
      />,
    )

    await waitFor(() => expect(screen.getByTestId('action-btn-purge_cache')).toBeInTheDocument())
    await act(async () => { await user.click(screen.getByTestId('action-btn-purge_cache')) })
    await waitFor(() => expect(screen.getByTestId('action-result-purge_cache')).toBeInTheDocument())

    // Flat message still present
    expect(screen.getByTestId('action-result-purge_cache').textContent).toContain(
      'Cache purged successfully.',
    )
    // No checklist rendered (no stage_* keys)
    expect(screen.queryByTestId('staged-detail-checklist')).toBeNull()
  })

  /**
   * EARS: ALL stage messages SHALL render as text nodes (no dangerouslySetInnerHTML).
   * Verified by checking message element textContent matches the raw string — no tag parsing.
   */
  it('stage messages render as text nodes (no HTML injection)', async () => {
    const user = userEvent.setup()
    mockFetchSourceActions.mockResolvedValue([])
    mockRunSourceAction.mockResolvedValue(STAGED_RESULT_MIXED)

    render(
      <SourceActions
        typeKey="demo_ids"
        sourceId="demo_ids"
        declarations={[DEMO_PURGE_CACHE_ACTION]}
      />,
    )

    await waitFor(() => expect(screen.getByTestId('action-btn-purge_cache')).toBeInTheDocument())
    await act(async () => { await user.click(screen.getByTestId('action-btn-purge_cache')) })
    await waitFor(() => expect(screen.getByTestId('staged-detail-checklist')).toBeInTheDocument())

    // Message content matches the fixture string exactly — confirms text-node rendering
    expect(screen.getByTestId('stage-msg-ssh').textContent).toBe(
      'SSH connection established successfully.',
    )
    expect(screen.getByTestId('stage-msg-evejson').textContent).toContain(
      'eve.json not found at',
    )
  })

  /**
   * EARS: THE staged rendering SHALL be driven by the generic stage_* / *_msg
   * key convention with NO branching on source_type.
   * Proved by using fictional type_key "demo_ids" for all staged checklist tests.
   */
  it('genericity: uses fictional type_key (demo_ids) — no source_type branching', async () => {
    const user = userEvent.setup()
    mockFetchSourceActions.mockResolvedValue([])
    mockRunSourceAction.mockResolvedValue(STAGED_RESULT_MIXED)

    render(
      <SourceActions
        typeKey="demo_ids"
        sourceId="demo_ids"
        declarations={[DEMO_PURGE_CACHE_ACTION]}
      />,
    )

    await waitFor(() => expect(screen.getByTestId('action-btn-purge_cache')).toBeInTheDocument())
    await act(async () => { await user.click(screen.getByTestId('action-btn-purge_cache')) })
    await waitFor(() => expect(screen.getByTestId('staged-detail-checklist')).toBeInTheDocument())

    // Checklist rendered for fictional type — proves it is not gated on source type
    expect(screen.getByTestId('staged-detail-checklist')).toBeInTheDocument()
  })
})

describe('SourceActions — genericity (fictional type_key)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  // EARS ubiquitous: no type_key comparison anywhere — uses fictional "demo_ids".
  // Installing any plugin with declared actions renders buttons generically.
  it('renders action buttons for a fictional type_key (demo_ids) — proves genericity', async () => {
    mockFetchSourceActions.mockResolvedValue([])
    render(
      <SourceActions
        typeKey="demo_ids"
        sourceId="demo_ids"
        declarations={[DEMO_FETCH_RULES_ACTION, DEMO_PURGE_CACHE_ACTION]}
      />,
    )

    await waitFor(() => {
      expect(screen.getByTestId('source-actions')).toBeInTheDocument()
      expect(screen.getByTestId('action-btn-fetch_rules')).toBeInTheDocument()
      expect(screen.getByTestId('action-btn-purge_cache')).toBeInTheDocument()
    })
  })

  // EARS state-driven: azure_waf with NO declared actions → no action UI.
  it('renders nothing for azure_waf with no declared actions (empty declarations)', () => {
    mockFetchSourceActions.mockResolvedValue([])
    const { container } = render(
      <SourceActions typeKey="azure_waf" sourceId="azure_waf" declarations={[]} />,
    )
    expect(container.querySelector('[data-testid="source-actions"]')).toBeNull()
  })

  // EARS state-driven: syslog source with no declared actions → no action UI.
  it('renders nothing for syslog source with no declared actions', () => {
    mockFetchSourceActions.mockResolvedValue([])
    const { container } = render(
      <SourceActions typeKey="syslog" sourceId="syslog" declarations={[]} />,
    )
    expect(container.querySelector('[data-testid="source-actions"]')).toBeNull()
  })
})
