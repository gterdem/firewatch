/**
 * NotFoundView — catch-all 404 surface (issue #316).
 *
 * Rendered by the `*` route in App.tsx for any path that matches no known
 * route. Gives the user an honest dead-end with a single escape hatch back
 * to Dashboard — never a silent blank page.
 *
 * Design: plain DS chrome (no shadcn); single centred card, no external deps.
 */

import { Link } from 'react-router-dom'

export default function NotFoundView() {
  return (
    <div
      data-testid="not-found-view"
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '50vh',
        gap: 'var(--fw-sp-7)',
        textAlign: 'center',
      }}
    >
      <p
        data-testid="not-found-heading"
        style={{
          fontSize: '1.25rem',
          fontWeight: 600,
          color: 'var(--fw-text)',
        }}
      >
        Page not found
      </p>
      <p
        style={{
          fontSize: '0.875rem',
          color: 'var(--fw-text-muted)',
        }}
      >
        The path you requested does not exist.
      </p>
      <Link
        data-testid="not-found-dashboard-link"
        to="/dashboard"
        style={{
          fontSize: '0.875rem',
          color: 'var(--fw-accent)',
          textDecoration: 'underline',
        }}
      >
        Go to Dashboard
      </Link>
    </div>
  )
}
