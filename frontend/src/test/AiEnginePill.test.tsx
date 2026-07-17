/**
 * Tests for AiEnginePill — global AI-engine status pill (issue #207).
 *
 * EARS acceptance criteria covered:
 *
 *   EARS-1 (ADR-0035 §4 / scope amendment P10): ONE global engine indicator;
 *     pill renders in the KPI strip right slot (#254 will dock it natively).
 *
 *   EARS-2: WHEN engine healthy, pill shows model name + status dot (active).
 *     WHEN degraded/offline, pill shows "AI offline".
 *
 *   EARS-3: health=null fallback — falls back to threat-derived aiStatus.
 *     WHEN both null → pill hidden (no flash during load).
 *
 *   EARS-4 (Security): click disclosure shows model name + status.
 *     Inference endpoint host NEVER rendered (PR #191 topology-leak posture).
 *
 *   EARS-5: pill is purely informational; non-interactive parts are
 *     accessible (aria-label, aria-expanded).
 *
 *   EARS-6 (ADR-0022): chip shows whatever model is configured.
 *     No hardcoded model name.
 */

import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import AiEnginePill from '../components/dashboard/AiEnginePill'
import type { HealthResponse } from '../api/types'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const HEALTH_ONLINE: HealthResponse = {
  status: 'ok',
  ollama_connected: true,
  ollama_model: 'llama3.2',
  db_ok: true,
  ai: 'active',
}

const HEALTH_OFFLINE: HealthResponse = {
  status: 'ok',
  ollama_connected: false,
  ollama_model: null,
  db_ok: true,
  ai: 'unreachable',
}

const HEALTH_ONLINE_DIFFERENT_MODEL: HealthResponse = {
  status: 'ok',
  ollama_connected: true,
  ollama_model: 'mistral:7b',
  db_ok: true,
  ai: 'active',
}

// ---------------------------------------------------------------------------
// EARS-1: pill renders
// ---------------------------------------------------------------------------

describe('AiEnginePill — pill renders (EARS-1)', () => {
  it('renders the pill button with data-testid="ai-engine-pill"', () => {
    render(<AiEnginePill health={HEALTH_ONLINE} />)
    expect(screen.getByTestId('ai-engine-pill')).toBeInTheDocument()
  })

  it('renders null when health=null and aiStatus=null (no flash during load)', () => {
    const { container } = render(<AiEnginePill health={null} aiStatus={null} />)
    expect(container.firstChild).toBeNull()
  })

  it('renders null when health and aiStatus are both absent (undefined)', () => {
    const { container } = render(<AiEnginePill />)
    expect(container.firstChild).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// EARS-2: engine state rendering
// ---------------------------------------------------------------------------

describe('AiEnginePill — engine state (EARS-2)', () => {
  it('shows model name + "active" when connected', () => {
    render(<AiEnginePill health={HEALTH_ONLINE} />)
    const pill = screen.getByTestId('ai-engine-pill')
    expect(pill).toHaveTextContent('llama3.2')
    expect(pill).toHaveTextContent('active')
  })

  it('shows "AI offline" when disconnected', () => {
    render(<AiEnginePill health={HEALTH_OFFLINE} />)
    const pill = screen.getByTestId('ai-engine-pill')
    expect(pill).toHaveTextContent('AI offline')
    // Should NOT contain "active"
    expect(pill.textContent).not.toContain('active')
  })

  it('shows "AI · active" (no model name) when connected but ollama_model=null', () => {
    const health: HealthResponse = { ...HEALTH_ONLINE, ollama_model: null }
    render(<AiEnginePill health={health} />)
    const pill = screen.getByTestId('ai-engine-pill')
    expect(pill.textContent).toContain('active')
    expect(pill.textContent).not.toContain('null')
  })

  it('ADR-0022: shows configured model name — no hardcoded model (EARS-6)', () => {
    render(<AiEnginePill health={HEALTH_ONLINE_DIFFERENT_MODEL} />)
    const pill = screen.getByTestId('ai-engine-pill')
    expect(pill).toHaveTextContent('mistral:7b')
    // Must NOT have hardcoded 'llama3.2'
    expect(pill.textContent).not.toContain('llama3.2')
  })
})

// ---------------------------------------------------------------------------
// EARS-3: health=null fallback
// ---------------------------------------------------------------------------

describe('AiEnginePill — health=null fallback (EARS-3)', () => {
  it('renders with aiStatus=active fallback when health=null', () => {
    render(<AiEnginePill health={null} aiStatus="active" />)
    const pill = screen.getByTestId('ai-engine-pill')
    expect(pill.textContent).toContain('active')
  })

  it('renders with aiStatus=unavailable fallback when health=null → offline state', () => {
    render(<AiEnginePill health={null} aiStatus="unavailable" />)
    const pill = screen.getByTestId('ai-engine-pill')
    // 'unavailable' → connected=false → offline label
    expect(pill.textContent).toContain('AI offline')
  })

  it('renders with aiStatus=disabled → offline state', () => {
    render(<AiEnginePill health={null} aiStatus="disabled" />)
    const pill = screen.getByTestId('ai-engine-pill')
    expect(pill.textContent).toContain('AI offline')
  })
})

// ---------------------------------------------------------------------------
// EARS-4: click disclosure — model name + status, NO endpoint host
// ---------------------------------------------------------------------------

describe('AiEnginePill — click disclosure (EARS-4, Security)', () => {
  it('disclosure not visible by default', () => {
    render(<AiEnginePill health={HEALTH_ONLINE} />)
    expect(screen.queryByTestId('ai-engine-pill-disclosure')).not.toBeInTheDocument()
  })

  it('disclosure opens on click', () => {
    render(<AiEnginePill health={HEALTH_ONLINE} />)
    fireEvent.click(screen.getByTestId('ai-engine-pill'))
    expect(screen.getByTestId('ai-engine-pill-disclosure')).toBeInTheDocument()
  })

  it('disclosure closes on second click (toggle)', () => {
    render(<AiEnginePill health={HEALTH_ONLINE} />)
    const btn = screen.getByTestId('ai-engine-pill')
    fireEvent.click(btn)
    fireEvent.click(btn)
    expect(screen.queryByTestId('ai-engine-pill-disclosure')).not.toBeInTheDocument()
  })

  it('disclosure shows model name (EARS-4 — model name in click detail)', () => {
    render(<AiEnginePill health={HEALTH_ONLINE} />)
    fireEvent.click(screen.getByTestId('ai-engine-pill'))
    const modelRow = screen.getByTestId('ai-engine-pill-model')
    expect(modelRow).toHaveTextContent('llama3.2')
  })

  it('disclosure shows "unknown" when model is null', () => {
    render(<AiEnginePill health={{ ...HEALTH_ONLINE, ollama_model: null }} />)
    fireEvent.click(screen.getByTestId('ai-engine-pill'))
    expect(screen.getByTestId('ai-engine-pill-model')).toHaveTextContent('unknown')
  })

  it('disclosure shows connection status', () => {
    render(<AiEnginePill health={HEALTH_ONLINE} />)
    fireEvent.click(screen.getByTestId('ai-engine-pill'))
    expect(screen.getByTestId('ai-engine-pill-status')).toHaveTextContent('connected')
  })

  it('disclosure shows "offline" when disconnected', () => {
    render(<AiEnginePill health={HEALTH_OFFLINE} />)
    fireEvent.click(screen.getByTestId('ai-engine-pill'))
    expect(screen.getByTestId('ai-engine-pill-status')).toHaveTextContent('offline')
  })

  it('SECURITY: inference endpoint host NEVER rendered in disclosure (PR #191 topology-leak)', () => {
    render(<AiEnginePill health={HEALTH_ONLINE} />)
    fireEvent.click(screen.getByTestId('ai-engine-pill'))
    const disclosure = screen.getByTestId('ai-engine-pill-disclosure')
    const html = disclosure.innerHTML
    // No URL patterns
    expect(html).not.toMatch(/https?:\/\//)
    expect(html).not.toMatch(/localhost:\d{4}/)
    expect(html).not.toMatch(/127\.0\.0\.1:\d{4}/)
    expect(html).not.toMatch(/\/v1\//)
  })
})

// ---------------------------------------------------------------------------
// EARS-5: accessibility
// ---------------------------------------------------------------------------

describe('AiEnginePill — accessibility (EARS-5)', () => {
  it('pill button has aria-label describing the engine state', () => {
    render(<AiEnginePill health={HEALTH_ONLINE} />)
    const btn = screen.getByTestId('ai-engine-pill')
    const label = btn.getAttribute('aria-label') ?? ''
    expect(label.toLowerCase()).toContain('active')
  })

  it('pill button has aria-label for offline state', () => {
    render(<AiEnginePill health={HEALTH_OFFLINE} />)
    const btn = screen.getByTestId('ai-engine-pill')
    const label = btn.getAttribute('aria-label') ?? ''
    expect(label.toLowerCase()).toContain('offline')
  })

  it('pill button has aria-expanded=false initially', () => {
    render(<AiEnginePill health={HEALTH_ONLINE} />)
    const btn = screen.getByTestId('ai-engine-pill')
    expect(btn.getAttribute('aria-expanded')).toBe('false')
  })

  it('pill button has aria-expanded=true after click', () => {
    render(<AiEnginePill health={HEALTH_ONLINE} />)
    const btn = screen.getByTestId('ai-engine-pill')
    fireEvent.click(btn)
    expect(btn.getAttribute('aria-expanded')).toBe('true')
  })

  it('pressing Enter on pill opens disclosure', () => {
    render(<AiEnginePill health={HEALTH_ONLINE} />)
    const btn = screen.getByTestId('ai-engine-pill')
    fireEvent.keyDown(btn, { key: 'Enter' })
    expect(screen.getByTestId('ai-engine-pill-disclosure')).toBeInTheDocument()
  })

  it('pressing Space on pill opens disclosure', () => {
    render(<AiEnginePill health={HEALTH_ONLINE} />)
    const btn = screen.getByTestId('ai-engine-pill')
    fireEvent.keyDown(btn, { key: ' ' })
    expect(screen.getByTestId('ai-engine-pill-disclosure')).toBeInTheDocument()
  })

  it('pressing Escape closes the disclosure', () => {
    render(<AiEnginePill health={HEALTH_ONLINE} />)
    const btn = screen.getByTestId('ai-engine-pill')
    fireEvent.click(btn) // open
    fireEvent.keyDown(btn, { key: 'Escape' }) // close
    expect(screen.queryByTestId('ai-engine-pill-disclosure')).not.toBeInTheDocument()
  })
})
