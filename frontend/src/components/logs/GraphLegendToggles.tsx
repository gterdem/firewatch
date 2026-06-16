/**
 * GraphLegendToggles — legend chips that toggle node/edge kind visibility.
 *
 * Implements ADR-0061 D5 (legend chips → layer toggles):
 *   Clicking "Category" or "ASN" hides that node/edge kind client-side.
 *   IP nodes are ALWAYS shown (they are the primary entity).
 *
 * State: `hiddenKinds` is a Set<string> of node/edge kinds to suppress.
 *   Managed by the parent (EntityGraph) and passed in as a controlled prop.
 *
 * The component renders a row of toggle chips.  Active (visible) chips look
 * normal; suppressed (hidden) chips appear dimmed with a strikethrough.
 *
 * SECURITY: no attacker-controlled values are rendered here.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Edge/node kinds that can be toggled (IP nodes are always shown). */
export type ToggleableKind = 'asn' | 'category'

export interface LegendToggleItem {
  /** Kind string matching GraphNode.type / GraphEdge.kind. */
  kind: ToggleableKind
  /** Display label. */
  label: string
  /** Dot colour for this kind. */
  color: string
}

interface GraphLegendTogglesProps {
  /** Current set of hidden kinds. */
  hiddenKinds: ReadonlySet<string>
  /** Called when a kind is toggled. */
  onToggle: (kind: ToggleableKind) => void
}

// ---------------------------------------------------------------------------
// Fixed legend items (no per-source code — these are graph structural kinds,
// not source-specific values)
// ---------------------------------------------------------------------------

/** Always-visible items (IP nodes cannot be hidden). */
const IP_LEGEND_ITEMS: Array<{ color: string; label: string }> = [
  { color: 'var(--fw-red)',    label: 'CRITICAL IP' },
  { color: 'var(--fw-orange)', label: 'HIGH IP' },
  { color: 'var(--fw-blue)',   label: 'MEDIUM IP' },
  { color: 'var(--fw-green)',  label: 'LOW IP' },
  { color: 'var(--fw-t2)',     label: 'IP (no verdict)' },
]

/** Toggleable items — clicking hides/shows that kind. */
const TOGGLE_ITEMS: LegendToggleItem[] = [
  { kind: 'asn',      label: 'ASN',      color: 'var(--fw-cyan)' },
  { kind: 'category', label: 'Category', color: 'var(--fw-purple)' },
]

// ---------------------------------------------------------------------------
// Subcomponents
// ---------------------------------------------------------------------------

function StaticLegendDot({ color, label }: { color: string; label: string }) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 4,
        fontSize: 'var(--fw-fs-2xs)',
        fontFamily: 'var(--fw-font-ui)',
        color: 'var(--fw-t2)',
      }}
    >
      <span
        aria-hidden="true"
        style={{
          width: 8,
          height: 8,
          borderRadius: '50%',
          background: color,
          flexShrink: 0,
        }}
      />
      {label}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function GraphLegendToggles({
  hiddenKinds,
  onToggle,
}: GraphLegendTogglesProps) {
  return (
    <div
      style={{
        padding: '4px 12px',
        borderBottom: '1px solid var(--fw-border)',
        display: 'flex',
        gap: 16,
        flexWrap: 'wrap',
        alignItems: 'center',
      }}
      aria-label="Graph legend — click ASN or Category to toggle visibility"
    >
      {/* Static IP severity items — always shown */}
      {IP_LEGEND_ITEMS.map((item) => (
        <StaticLegendDot key={item.label} color={item.color} label={item.label} />
      ))}

      {/* Toggleable kind chips */}
      {TOGGLE_ITEMS.map(({ kind, label, color }) => {
        const hidden = hiddenKinds.has(kind)
        return (
          <button
            key={kind}
            type="button"
            onClick={() => onToggle(kind)}
            aria-pressed={!hidden}
            aria-label={`${label} — ${hidden ? 'hidden, click to show' : 'visible, click to hide'}`}
            data-testid={`legend-toggle-${kind}`}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 4,
              fontSize: 'var(--fw-fs-2xs)',
              fontFamily: 'var(--fw-font-ui)',
              color: hidden ? 'var(--fw-t4)' : 'var(--fw-t2)',
              background: 'none',
              border: '1px solid ' + (hidden ? 'var(--fw-border)' : 'var(--fw-border-l)'),
              borderRadius: 'var(--fw-r-sm)',
              padding: '1px 6px',
              cursor: 'pointer',
              opacity: hidden ? 0.5 : 1,
              textDecoration: hidden ? 'line-through' : 'none',
              outline: 'none',
              transition: 'opacity 0.15s',
            }}
          >
            <span
              aria-hidden="true"
              style={{
                width: 8,
                height: 8,
                borderRadius: '50%',
                background: hidden ? 'var(--fw-t4)' : color,
                flexShrink: 0,
              }}
            />
            {label}
          </button>
        )
      })}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Exports for testing/use
// ---------------------------------------------------------------------------

export { TOGGLE_ITEMS }
