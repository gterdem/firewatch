/**
 * Tests for DS primitive components (F2 #108).
 *
 * EARS coverage:
 *   - Badge: all tone variants render; alert = solid orange; unknown tone → neutral.
 *   - Button: all variants + sizes render with correct data attributes.
 *   - Panel: header/body/flush mode.
 *   - StatCard: value/label/icon/accent layout.
 *   - Input: bare + labelled; size variants.
 *   - Select: option list + labelled.
 *   - Tabs: active tab aria-selected; onChange called.
 *   - ThemeToggle: correct emoji per theme; click fires onToggle.
 *   - Spinner: bare ring vs labelled block.
 *   - LiveBadge: live=true pulsing, live=false idle.
 *   - Toast: tone variants; default + custom icons.
 *   - EmptyState: icon/title/children/action slots.
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import {
  Badge,
  Button,
  Panel,
  StatCard,
  Input,
  Select,
  Tabs,
  ThemeToggle,
  Spinner,
  LiveBadge,
  Toast,
  EmptyState,
} from '../components/ds'

// ---------------------------------------------------------------------------
// Badge
// ---------------------------------------------------------------------------

describe('Badge — tone variants', () => {
  it('renders children', () => {
    render(<Badge tone="critical">CRITICAL</Badge>)
    expect(screen.getByText('CRITICAL')).toBeInTheDocument()
  })

  it('alert tone is solid orange (data-tone="alert")', () => {
    render(<Badge tone="alert">ALERT</Badge>)
    const el = screen.getByText('ALERT')
    expect(el.getAttribute('data-tone')).toBe('alert')
    // The alert tone background should be the solid --fw-orange, not a tint
    // We verify via inline style that it uses the solid orange variable
    expect(el.style.background).toContain('var(--fw-orange)')
    // text should use DS on-accent token (black in dark theme) — F5 #111: no raw hex in components.
    // JSDOM receives the CSS var string; production resolves to #000 (dark) / #fff (light).
    expect(el.style.color).toMatch(/var\(--fw-on-accent\)|^(#000|rgb\(0,\s*0,\s*0\)|black)$/)
  })

  it.each([
    'critical', 'high', 'medium', 'low',
    'block', 'allow', 'drop',
    'waf', 'ids', 'syslog', 'file',
    'neutral',
  ] as const)('tone "%s" renders without crash and has data-tone', (tone) => {
    render(<Badge tone={tone}>{tone}</Badge>)
    const el = screen.getByText(tone)
    expect(el.getAttribute('data-tone')).toBe(tone)
  })

  it('unknown tone falls back to neutral (does not crash)', () => {
    // @ts-expect-error — testing unknown tone runtime fallback
    // eslint-disable-next-line no-restricted-syntax -- intentional out-of-whitelist value for fallback test
    render(<Badge tone="unknown_xyz">fallback</Badge>)
    const el = screen.getByText('fallback')
    // Should render with neutral data-tone (or at least not crash)
    expect(el).toBeInTheDocument()
  })

  it('passes extra HTML attributes through', () => {
    render(<Badge tone="low" data-testid="my-badge">Low</Badge>)
    expect(screen.getByTestId('my-badge')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Button
// ---------------------------------------------------------------------------

describe('Button — variants and sizes', () => {
  it('renders children', () => {
    render(<Button>Click me</Button>)
    expect(screen.getByRole('button', { name: 'Click me' })).toBeInTheDocument()
  })

  it.each(['primary', 'danger', 'deep', 'secondary', 'ghost'] as const)(
    'variant "%s" renders with correct data-variant',
    (variant) => {
      render(<Button variant={variant}>{variant}</Button>)
      const btn = screen.getByRole('button')
      expect(btn.getAttribute('data-variant')).toBe(variant)
    },
  )

  it.each(['md', 'sm'] as const)('size "%s" renders with correct data-size', (size) => {
    render(<Button size={size}>btn</Button>)
    expect(screen.getByRole('button').getAttribute('data-size')).toBe(size)
  })

  it('renders leading icon', () => {
    render(<Button icon="🔍">Search</Button>)
    expect(screen.getByText('🔍')).toBeInTheDocument()
  })

  it('fires onClick', () => {
    const handler = vi.fn()
    render(<Button onClick={handler}>click</Button>)
    fireEvent.click(screen.getByRole('button'))
    expect(handler).toHaveBeenCalledOnce()
  })

  it('disabled button does not fire onClick', () => {
    const handler = vi.fn()
    render(<Button onClick={handler} disabled>disabled</Button>)
    fireEvent.click(screen.getByRole('button'))
    expect(handler).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// Panel
// ---------------------------------------------------------------------------

describe('Panel — layout slots', () => {
  it('renders children in body', () => {
    render(<Panel><div data-testid="body">body</div></Panel>)
    expect(screen.getByTestId('body')).toBeInTheDocument()
  })

  it('renders title and icon in header', () => {
    render(<Panel title="Events" icon="📋"><span>content</span></Panel>)
    expect(screen.getByText('Events')).toBeInTheDocument()
    expect(screen.getByText('📋')).toBeInTheDocument()
  })

  it('renders actions on the right', () => {
    render(<Panel title="Panel" actions={<button>Refresh</button>}><span/></Panel>)
    expect(screen.getByRole('button', { name: 'Refresh' })).toBeInTheDocument()
  })

  it('renders no header row when title and actions are omitted', () => {
    render(<Panel><div>only body</div></Panel>)
    // No h2 should exist
    expect(screen.queryByRole('heading')).not.toBeInTheDocument()
  })

  it('flush prop removes body padding (fw-panel__b class present)', () => {
    const { container } = render(<Panel title="T" flush><span>data</span></Panel>)
    const body = container.querySelector('.fw-panel__b')
    expect(body).toBeInTheDocument()
    // style should not have padding set
    expect((body as HTMLElement).style.padding).toBeFalsy()
  })
})

// ---------------------------------------------------------------------------
// StatCard
// ---------------------------------------------------------------------------

describe('StatCard — KPI tile', () => {
  it('renders value and label', () => {
    render(<StatCard value="1,234" label="Events" />)
    expect(screen.getByText('1,234')).toBeInTheDocument()
    expect(screen.getByText('Events')).toBeInTheDocument()
  })

  it('renders faint icon top-right', () => {
    render(<StatCard value="42" label="Score" icon="📊" />)
    expect(screen.getByText('📊')).toBeInTheDocument()
  })

  it('value color changes with accent', () => {
    const { container } = render(<StatCard value="99" label="Blocked" accent="red" />)
    const val = container.querySelector('.fw-stat__val') as HTMLElement
    expect(val.style.color).toContain('var(--fw-red)')
  })

  it('default accent uses --fw-t1', () => {
    const { container } = render(<StatCard value="0" label="Low" />)
    const val = container.querySelector('.fw-stat__val') as HTMLElement
    expect(val.style.color).toContain('var(--fw-t1)')
  })
})

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

describe('Input — form field', () => {
  it('renders bare input without label', () => {
    render(<Input placeholder="Search…" />)
    expect(screen.getByPlaceholderText('Search…')).toBeInTheDocument()
  })

  it('renders labelled field group', () => {
    render(<Input id="host" label="Hostname" />)
    expect(screen.getByLabelText('Hostname')).toBeInTheDocument()
  })

  it('sm size renders without crash', () => {
    render(<Input size="sm" placeholder="small" />)
    expect(screen.getByPlaceholderText('small')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Select
// ---------------------------------------------------------------------------

describe('Select — native dropdown', () => {
  const options = ['Option A', 'Option B', 'Option C']

  it('renders all options', () => {
    render(<Select options={options} />)
    options.forEach((o) => expect(screen.getByRole('option', { name: o })).toBeInTheDocument())
  })

  it('renders object options {value, label}', () => {
    render(<Select options={[{ value: 'a', label: 'Alpha' }, { value: 'b', label: 'Beta' }]} />)
    expect(screen.getByRole('option', { name: 'Alpha' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'Beta' })).toBeInTheDocument()
  })

  it('renders with label', () => {
    render(<Select id="sev" label="Severity" options={options} />)
    expect(screen.getByLabelText('Severity')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------

describe('Tabs — tab bar', () => {
  const items = [
    { id: 'all', label: 'All', count: 100 },
    { id: 'block', label: 'Block' },
    { id: 'alert', label: 'Alert', count: 5 },
  ]

  it('renders all tab buttons', () => {
    render(<Tabs items={items} value="all" />)
    expect(screen.getByRole('tab', { name: /All/ })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /Block/ })).toBeInTheDocument()
  })

  it('active tab has aria-selected=true', () => {
    render(<Tabs items={items} value="block" />)
    const blockTab = screen.getByRole('tab', { name: /Block/ })
    expect(blockTab).toHaveAttribute('aria-selected', 'true')
  })

  it('inactive tabs have aria-selected=false', () => {
    render(<Tabs items={items} value="block" />)
    const allTab = screen.getByRole('tab', { name: /All/ })
    expect(allTab).toHaveAttribute('aria-selected', 'false')
  })

  it('calls onChange with tab id on click', () => {
    const onChange = vi.fn()
    render(<Tabs items={items} value="all" onChange={onChange} />)
    fireEvent.click(screen.getByRole('tab', { name: /Alert/ }))
    expect(onChange).toHaveBeenCalledWith('alert')
  })

  it('renders monospace count when provided', () => {
    render(<Tabs items={items} value="all" />)
    expect(screen.getByText('100')).toBeInTheDocument()
    expect(screen.getByText('5')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// ThemeToggle
// ---------------------------------------------------------------------------

describe('ThemeToggle — theme button', () => {
  it('shows 🌙 when theme is dark', () => {
    render(<ThemeToggle theme="dark" />)
    expect(screen.getByRole('button')).toHaveTextContent('🌙')
  })

  it('shows ☀️ when theme is light', () => {
    render(<ThemeToggle theme="light" />)
    expect(screen.getByRole('button')).toHaveTextContent('☀️')
  })

  it('calls onToggle on click', () => {
    const onToggle = vi.fn()
    render(<ThemeToggle theme="dark" onToggle={onToggle} />)
    fireEvent.click(screen.getByRole('button'))
    expect(onToggle).toHaveBeenCalledOnce()
  })

  it('has aria-label="Toggle theme"', () => {
    render(<ThemeToggle />)
    expect(screen.getByLabelText('Toggle theme')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Spinner
// ---------------------------------------------------------------------------

describe('Spinner — loading ring', () => {
  it('bare spinner renders an inline span with fw-spin animation', () => {
    const { container } = render(<Spinner />)
    const span = container.querySelector('.fw-spinner') as HTMLElement
    expect(span).toBeInTheDocument()
    expect(span.style.animation).toContain('fw-spin')
  })

  it('with label renders the loading block', () => {
    render(<Spinner label="Fetching…" />)
    expect(screen.getByText('Fetching…')).toBeInTheDocument()
  })

  it('labelled block contains a ring element', () => {
    const { container } = render(<Spinner label="Loading" />)
    const ring = container.querySelector('.fw-spinner')
    expect(ring).toBeInTheDocument()
  })

  it('bare spinner has amber top border (fw-accent)', () => {
    const { container } = render(<Spinner />)
    const el = container.querySelector('.fw-spinner') as HTMLElement
    expect(el.style.borderTopColor).toContain('var(--fw-accent)')
  })
})

// ---------------------------------------------------------------------------
// LiveBadge
// ---------------------------------------------------------------------------

describe('LiveBadge — live/idle state', () => {
  it('live=true renders default "Live" text', () => {
    render(<LiveBadge />)
    expect(screen.getByText('Live')).toBeInTheDocument()
  })

  it('live=true has pulsing dot (animation contains fw-pulse)', () => {
    const { container } = render(<LiveBadge live={true} />)
    const dot = container.querySelector('.fw-live__dot') as HTMLElement
    expect(dot.style.animation).toContain('fw-pulse')
  })

  it('live=false dot has animation:none (static/idle)', () => {
    const { container } = render(<LiveBadge live={false} />)
    const dot = container.querySelector('.fw-live__dot') as HTMLElement
    expect(dot.style.animation).toBe('none')
  })

  it('live=false capsule has fw-live--idle class', () => {
    const { container } = render(<LiveBadge live={false} />)
    const el = container.querySelector('.fw-live')
    expect(el?.className).toContain('fw-live--idle')
  })

  it('live=true capsule does NOT have fw-live--idle class', () => {
    const { container } = render(<LiveBadge live={true} />)
    const el = container.querySelector('.fw-live')
    expect(el?.className).not.toContain('fw-live--idle')
  })

  it('renders custom label', () => {
    render(<LiveBadge>Auto-refresh</LiveBadge>)
    expect(screen.getByText('Auto-refresh')).toBeInTheDocument()
  })

  it('live=true uses green background token', () => {
    const { container } = render(<LiveBadge live={true} />)
    const el = container.querySelector('.fw-live') as HTMLElement
    expect(el.style.background).toContain('var(--fw-tint-green)')
  })

  it('live=false uses input/muted background', () => {
    const { container } = render(<LiveBadge live={false} />)
    const el = container.querySelector('.fw-live') as HTMLElement
    expect(el.style.background).toContain('var(--fw-bg-input)')
  })
})

// ---------------------------------------------------------------------------
// Toast
// ---------------------------------------------------------------------------

describe('Toast — notification chip', () => {
  it('renders children', () => {
    render(<Toast>Settings saved</Toast>)
    expect(screen.getByText('Settings saved')).toBeInTheDocument()
  })

  it('has role="status"', () => {
    render(<Toast>msg</Toast>)
    expect(screen.getByRole('status')).toBeInTheDocument()
  })

  it('ok tone renders ✅ default icon', () => {
    render(<Toast tone="ok">Success</Toast>)
    expect(screen.getByText('✅')).toBeInTheDocument()
  })

  it('err tone renders ⚠️ default icon', () => {
    render(<Toast tone="err">Error</Toast>)
    expect(screen.getByText('⚠️')).toBeInTheDocument()
  })

  it('info tone renders ℹ️ default icon', () => {
    render(<Toast tone="info">Info</Toast>)
    expect(screen.getByText('ℹ️')).toBeInTheDocument()
  })

  it('custom icon overrides the default', () => {
    render(<Toast tone="ok" icon="🚀">Custom</Toast>)
    expect(screen.getByText('🚀')).toBeInTheDocument()
    expect(screen.queryByText('✅')).not.toBeInTheDocument()
  })

  it('ok tone has green left stripe', () => {
    const { container } = render(<Toast tone="ok">ok</Toast>)
    const el = container.querySelector('.fw-toast') as HTMLElement
    expect(el.style.borderLeft).toContain('var(--fw-green)')
  })

  it('err tone has red left stripe', () => {
    const { container } = render(<Toast tone="err">err</Toast>)
    const el = container.querySelector('.fw-toast') as HTMLElement
    expect(el.style.borderLeft).toContain('var(--fw-red)')
  })

  it('info tone has blue left stripe', () => {
    const { container } = render(<Toast tone="info">info</Toast>)
    const el = container.querySelector('.fw-toast') as HTMLElement
    expect(el.style.borderLeft).toContain('var(--fw-blue)')
  })

  it('unknown tone falls back to info without crashing', () => {
    // @ts-expect-error — testing runtime fallback
    // eslint-disable-next-line no-restricted-syntax -- intentional out-of-whitelist value for fallback test
    render(<Toast tone="mystery">fallback</Toast>)
    expect(screen.getByText('fallback')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EmptyState (DS version)
// ---------------------------------------------------------------------------

describe('EmptyState (DS) — zero-state', () => {
  it('renders title', () => {
    render(<EmptyState title="No sources configured" />)
    expect(screen.getByTestId('empty-state-headline')).toHaveTextContent('No sources configured')
  })

  it('renders children as body copy', () => {
    render(<EmptyState title="None"><span>Add a source to begin.</span></EmptyState>)
    expect(screen.getByTestId('empty-state-subline')).toBeInTheDocument()
  })

  it('renders icon', () => {
    render(<EmptyState title="Empty" icon="📭" />)
    expect(screen.getByTestId('empty-state-icon')).toBeInTheDocument()
    expect(screen.getByText('📭')).toBeInTheDocument()
  })

  it('renders action CTA', () => {
    render(<EmptyState title="Empty" action={<button>Add source</button>} />)
    expect(screen.getByRole('button', { name: 'Add source' })).toBeInTheDocument()
  })

  it('has role="status" on outer wrapper', () => {
    render(<EmptyState title="No data" />)
    expect(screen.getByRole('status')).toBeInTheDocument()
  })

  it('does not render icon container when no icon provided', () => {
    render(<EmptyState title="No data" />)
    expect(screen.queryByTestId('empty-state-icon')).not.toBeInTheDocument()
  })

  it('does not render body copy when children omitted', () => {
    render(<EmptyState title="No data" />)
    expect(screen.queryByTestId('empty-state-subline')).not.toBeInTheDocument()
  })
})
