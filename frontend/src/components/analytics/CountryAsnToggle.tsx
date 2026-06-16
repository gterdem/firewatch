/**
 * CountryAsnToggle — segmented control for the Threat Intelligence panel lens.
 *
 * EARS-1 (issue #533): the panel offers a "Country | ASN" segmented toggle.
 * Country mode keeps the existing geo dot-map.
 * ASN mode activates the AsnPanel ranked list beside the map.
 *
 * SECURITY (ADR-0029 D3): no attacker-controlled values in button labels.
 * Generic, no per-source code.
 */

export type ThreatLens = 'country' | 'asn'

interface CountryAsnToggleProps {
  value: ThreatLens
  onChange: (lens: ThreatLens) => void
}

const SEGMENTS: { value: ThreatLens; label: string }[] = [
  { value: 'country', label: 'Country' },
  { value: 'asn', label: 'ASN' },
]

export default function CountryAsnToggle({ value, onChange }: CountryAsnToggleProps) {
  return (
    <div
      role="group"
      aria-label="Threat Intelligence lens"
      data-testid="country-asn-toggle"
      style={{
        display: 'inline-flex',
        borderRadius: 'var(--fw-r-sm)',
        border: '1px solid var(--fw-border)',
        overflow: 'hidden',
        fontSize: 'var(--fw-fs-xs)',
        fontFamily: 'var(--fw-font-ui)',
        fontWeight: 'var(--fw-fw-semibold)',
      }}
    >
      {SEGMENTS.map((seg) => {
        const active = seg.value === value
        return (
          <button
            key={seg.value}
            type="button"
            role="radio"
            aria-checked={active}
            aria-label={`${seg.label} view`}
            data-testid={`lens-${seg.value}`}
            onClick={() => onChange(seg.value)}
            /* #572: inactive segment gets fw-toggle-seg-inactive for :hover feedback.
               Active segment is styled entirely via inline style (no hover class needed). */
            className={!active ? 'fw-toggle-seg-inactive' : undefined}
            style={{
              padding: '5px 14px',
              cursor: 'pointer',
              background: active ? 'var(--fw-accent)' : 'var(--fw-bg-card)',
              color: active ? 'var(--fw-bg)' : 'var(--fw-t2)',
              border: 'none',
              borderRight: seg.value === 'country' ? '1px solid var(--fw-border)' : 'none',
              transition: 'background 0.15s, color 0.15s',
            }}
          >
            {seg.label}
          </button>
        )
      })}
    </div>
  )
}
