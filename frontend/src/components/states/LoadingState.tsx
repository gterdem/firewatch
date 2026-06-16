/**
 * LoadingState — DS Spinner recipe wrapper (F2 #108).
 *
 * Wraps the DS Spinner ring with the same outer testids/role as #98 so
 * all existing call sites and tests keep working.
 *
 * Visual change vs #98:
 *   - Spinner ring: amber top (--fw-accent) / --fw-border-l base — matches DS recipe.
 *   - Label: --fw-t3 (DS faint text) — still calm/muted, non-alarming.
 *   - Layout: row (flex row, gap 8) instead of column — matches DS .fw-loading block.
 *
 * Testids preserved (PanelStates.test.tsx asserts these):
 *   data-testid="loading-state"         — outer wrapper
 *   data-testid="loading-state-spinner" — the ring
 *   data-testid="loading-state-label"   — the caption text
 *
 * Issue #108 — supersedes #98 LoadingState visual recipe.
 */

interface LoadingStateProps {
  /** Accessible label for the loading indicator. Defaults to "Loading…". */
  label?: string
  /** Additional CSS class names for the outer wrapper. */
  className?: string
}

/**
 * Centered loading indicator matching the DS .fw-loading block recipe.
 * Uses role="status" so screen readers announce the loading state.
 */
export default function LoadingState({ label = 'Loading…', className = '' }: LoadingStateProps) {
  return (
    <div
      className={className}
      data-testid="loading-state"
      role="status"
      aria-label={label}
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 8,
        textAlign: 'center',
        padding: 30,
        color: 'var(--fw-t3)',
        fontSize: 'var(--fw-fs-body)',
        fontFamily: 'var(--fw-font-ui)',
      }}
    >
      {/* DS Spinner ring — amber top, no icon library */}
      <span
        data-testid="loading-state-spinner"
        aria-hidden="true"
        style={{
          display: 'inline-block',
          width: 14,
          height: 14,
          border: '2px solid var(--fw-border-l)',
          borderTopColor: 'var(--fw-accent)',
          borderRadius: '50%',
          animation: 'fw-spin var(--fw-dur-spin) linear infinite',
          verticalAlign: 'middle',
        }}
      />
      {/* Label — muted-foreground class preserved for PanelStates.test.tsx assertions */}
      <p className="text-muted-foreground" data-testid="loading-state-label">
        {label}
      </p>
    </div>
  )
}
