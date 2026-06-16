/**
 * AppNav — tab navigation bar (F1 #107).
 *
 * Matches the kit.css .nav / .nav-tab / .nav-badge recipe:
 *   - bg-card bottom-bordered strip
 *   - Tabs: 12px/20px padding, 13px/500 weight, muted color by default
 *   - Active tab: amber color + 2px amber bottom border (--fw-bw-accent)
 *   - Hover: text shifts from faint → muted
 *   - Count badges: mono, 9px, bg-input chip
 *
 * Route → tab mapping (matches App.jsx navs array):
 *   /dashboard  → "Dashboard"
 *   /ai         → "AI Engine"
 *   /logs       → "Network Logs"
 *   /analytics  → "Threat Intelligence"   (v2 extension; not in kit but in our routes)
 *   /settings   → "Settings"
 *
 * ADR-0019: React + Vite + TS. Uses react-router-dom NavLink for active detection.
 * OD-1 (approved): shell built from ported DS chrome, NOT coerced shadcn.
 */

import { NavLink } from 'react-router-dom'
import type { CSSProperties } from 'react'

interface NavItem {
  to: string
  label: string
  /** data-testid suffix (e.g. "dashboard" → data-testid="nav-dashboard") */
  testId: string
  /** Optional event count badge (monospace count chip) */
  badge?: string | number
}

const NAV_ITEMS: NavItem[] = [
  { to: '/dashboard', label: 'Dashboard', testId: 'dashboard' },
  { to: '/ai', label: 'AI Engine', testId: 'ai' },
  { to: '/logs', label: 'Network Logs', testId: 'logs' },
  { to: '/analytics', label: 'Threat Intelligence', testId: 'analytics' },
  { to: '/settings', label: 'Settings', testId: 'settings' },
]

const tabBase: CSSProperties = {
  padding: '12px 20px',
  fontSize: 'var(--fw-fs-body)',
  fontWeight: 'var(--fw-fw-medium)',
  color: 'var(--fw-t3)',
  cursor: 'pointer',
  borderBottomWidth: 'var(--fw-bw-accent)',
  borderBottomStyle: 'solid',
  borderBottomColor: 'transparent',
  transition: `all var(--fw-dur-fast) var(--fw-ease)`,
  display: 'flex',
  alignItems: 'center',
  gap: 6,
  textDecoration: 'none',
  userSelect: 'none',
  whiteSpace: 'nowrap',
}

const tabActive: CSSProperties = {
  ...tabBase,
  color: 'var(--fw-accent)',
  borderBottomColor: 'var(--fw-accent)',
}

export default function AppNav() {
  return (
    <nav
      data-testid="main-nav"
      aria-label="Main navigation"
      style={{
        display: 'flex',
        background: 'var(--fw-bg-card)',
        borderBottom: '1px solid var(--fw-border)',
        padding: '0 24px',
        overflowX: 'auto',
      }}
    >
      {NAV_ITEMS.map(({ to, label, testId, badge }) => (
        <NavLink
          key={to}
          to={to}
          data-testid={`nav-${testId}`}
          style={({ isActive }) => (isActive ? tabActive : tabBase)}
          onMouseEnter={(e) => {
            const el = e.currentTarget as HTMLAnchorElement
            if (!el.classList.contains('active')) {
              el.style.color = 'var(--fw-t2)'
            }
          }}
          onMouseLeave={(e) => {
            const el = e.currentTarget as HTMLAnchorElement
            // Restore only if not the active tab (NavLink sets style inline)
            if (el.getAttribute('aria-current') !== 'page') {
              el.style.color = 'var(--fw-t3)'
            }
          }}
        >
          {label}
          {badge != null && (
            <span
              data-testid={`nav-badge-${testId}`}
              style={{
                fontSize: 'var(--fw-fs-3xs)',
                fontFamily: 'var(--fw-font-mono)',
                background: 'var(--fw-bg-input)',
                border: '1px solid var(--fw-border)',
                padding: '1px 5px',
                borderRadius: 8,
                color: 'var(--fw-t3)',
              }}
            >
              {badge}
            </span>
          )}
        </NavLink>
      ))}
    </nav>
  )
}
