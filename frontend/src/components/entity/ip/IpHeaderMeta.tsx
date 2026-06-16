/**
 * IpHeaderMeta — enriched meta fragment for the IP entity slide-over header (issue #265, #336).
 *
 * Renders inline with the breadcrumb row (issue #336 — one-line header pattern):
 *   · ⎘ · (City, Country) · AS <asn> <name> · first seen <rel> · geo cached locally
 *
 * The copy icon appears IMMEDIATELY after the IP (which is the breadcrumb last item, to the
 * left of this component in the same flex row). The trailing metadata truncates with a
 * `title` tooltip on narrow widths — never wraps to a second line (issue #336 EARS).
 *
 * The IP span is intentionally absent here — it lives in the SlideOver breadcrumb so that the
 * IP appears exactly once in the header (issue #336: "IP appearing exactly once").
 *
 * Data source: the fast /threats/{ip} DTO (ThreatScore) already fetched by
 * useIpDetails — zero added latency. Fields: location, asn, as_name, first_seen.
 *
 * Provenance stamp: "geo cached locally" (ADR-0035 spirit).
 * The ip_geo cache does not currently expose an entry-age field; degrading to
 * "cached locally" in v1. Backend follow-up needed: expose cache entry timestamp
 * on the fast DTO so we can show "geo cached locally · <age>".
 *
 * Graceful degradation (ADR-0035):
 *   - Any absent field is silently omitted — no placeholders, no fabricated values.
 *   - All fields null → renders nothing (empty fragment).
 *
 * SECURITY (ADR-0029 D3): location, as_name are GeoIP-resolved from an attacker-
 * controlled source IP — rendered as text nodes only; never via innerHTML.
 *
 * Entity-kind-agnostic caller contract: the caller (EntityPanelProvider) fills
 * the generic SlideOver `headerMeta` slot with this component for IP entities.
 * GroupPanel can fill the same slot with "1,204 IPs · AS 4837" later (issue #265
 * out-of-scope, but slot is designed for it).
 */

import { useState } from 'react'
import type { ThreatScore } from '../../../api/types'
import { parseApiTimestamp, relativeTime } from '../../../lib/time'

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface IpHeaderMetaProps {
  /** The ThreatScore from the fast /threats/{ip} fetch. Null while loading. */
  score: ThreatScore | null
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function IpHeaderMeta({ score }: IpHeaderMetaProps) {
  const [copied, setCopied] = useState(false)

  if (!score) return null

  const { source_ip, location, asn, as_name, first_seen } = score

  // Build meta fragments -- each fragment is only included when the field exists.
  const geoFragment = location ? '(' + location + ')' : null

  const asnFragment = (() => {
    if (asn !== null && asn !== undefined && as_name) return 'AS ' + String(asn) + ' ' + as_name
    if (asn !== null && asn !== undefined) return 'AS ' + String(asn)
    return null
  })()

  const firstSeenFragment = (() => {
    if (!first_seen) return null
    const d = parseApiTimestamp(first_seen)
    const rel = relativeTime(d)
    if (!rel) return null
    return 'first seen ' + rel
  })()

  // Nothing to show — all enrichment absent.
  const hasAnyMeta = geoFragment || asnFragment || firstSeenFragment
  if (!hasAnyMeta) return null

  // Build the full tooltip text for truncation accessibility (issue #336 EARS):
  // includes provenance so it's reachable even when the trailing text is clipped.
  const hasProv = geoFragment || asnFragment
  const tooltipParts = [
    geoFragment,
    asnFragment,
    firstSeenFragment,
    hasProv ? 'geo cached locally' : null,
  ].filter(Boolean)
  const fullTooltip = source_ip + ' · ' + tooltipParts.join(' · ')

  // Copy-IP affordance.
  function handleCopy() {
    void navigator.clipboard.writeText(source_ip).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }

  const SEP = <span aria-hidden="true" style={{ color: 'var(--fw-t3)', flexShrink: 0 }}>·</span>

  return (
    <div
      data-testid="ip-header-meta"
      title={fullTooltip}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 6,
        // No flex-wrap — trailing metadata truncates, never wraps (issue #336 EARS).
        flexWrap: 'nowrap',
        overflow: 'hidden',
        minWidth: 0,
        fontSize: 12,
        color: 'var(--fw-t2)',
        lineHeight: 1.4,
      }}
    >
      {/* Copy-IP button — immediately after the IP (breadcrumb is to the left in the flex row). */}
      {SEP}
      <button
        type="button"
        data-testid="ip-header-meta-copy"
        aria-label={'Copy IP address ' + source_ip}
        title={copied ? 'Copied!' : 'Copy ' + source_ip}
        onClick={handleCopy}
        style={{
          background: 'none',
          border: 'none',
          color: copied ? 'var(--fw-green)' : 'var(--fw-t3)',
          cursor: 'pointer',
          fontSize: 12,
          padding: 0,
          lineHeight: 1,
          flexShrink: 0,
        }}
      >
        {copied ? '✓' : '⎘'}
      </button>

      {/* Truncatable region — geo · asn · first-seen · provenance.
          white-space: nowrap + overflow: hidden + text-overflow: ellipsis ensure
          that on narrow widths the trailing text clips rather than wrapping (issue #336). */}
      <span
        data-testid="ip-header-meta-trailing"
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          overflow: 'hidden',
          minWidth: 0,
          flexWrap: 'nowrap',
          whiteSpace: 'nowrap',
          flexShrink: 1,
        }}
      >
        {/* Geo: (City, Country) */}
        {geoFragment && (
          <>
            {SEP}
            <span data-testid="ip-header-meta-geo">{geoFragment}</span>
          </>
        )}

        {/* ASN: AS <number> <name> */}
        {asnFragment && (
          <>
            {SEP}
            <span
              data-testid="ip-header-meta-asn"
              style={{ fontFamily: 'var(--fw-font-mono)', fontSize: 11 }}
            >
              {asnFragment}
            </span>
          </>
        )}

        {/* First-seen relative time */}
        {firstSeenFragment && (
          <>
            {SEP}
            <span
              data-testid="ip-header-meta-first-seen"
              style={{ color: 'var(--fw-t3)', fontSize: 11 }}
            >
              {firstSeenFragment}
            </span>
          </>
        )}

        {/* Provenance stamp — ADR-0035 honest enrichment disclosure.
            The ip_geo cache does not currently expose an entry-age field;
            degrading to "cached locally" here.
            Backend follow-up: expose cache entry timestamp on the fast DTO
            so we can show "geo cached locally · <age>". */}
        {hasProv && (
          <>
            {SEP}
            <span
              data-testid="ip-header-meta-provenance"
              title="Geo and ASN data is resolved from the local ip_geo cache, not queried live per request."
              style={{
                fontSize: 10,
                color: 'var(--fw-t3)',
                fontStyle: 'italic',
                cursor: 'default',
              }}
            >
              geo cached locally
            </span>
          </>
        )}
      </span>
    </div>
  )
}
