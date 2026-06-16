/**
 * socTokens — maps operational values to SOC semantic CSS token classes.
 *
 * ADR-0028 D6 / issue #96: single source of truth for how severity, action,
 * and source-type values map to the token set defined in index.css.
 *
 * Rules:
 * - Every returned class name MUST correspond to a token registered in index.css
 *   under @theme inline (--color-soc-*). No hardcoded hex at call sites.
 * - Theme-swappable: light/dark values live in CSS custom properties; the
 *   classes here are the same in both themes — CSS resolves the correct values.
 * - New severity/source/action values fall through to a neutral muted fallback
 *   so the UI never breaks on an unexpected enum value.
 *
 * SECURITY: these functions operate on server-provided enum strings. They are
 * used to select CSS classes only, never interpolated into innerHTML.
 */

/**
 * CSS badge classes for a severity level.
 *
 * Returns Tailwind utility classes that reference the SOC semantic tokens from
 * index.css. The three-part structure (text + bg + ring/border) mirrors the
 * legacy badge convention (.b-critical, .b-high, etc.) sourced from
 * legacy/dashboard.html lines 47-50.
 */
export function severityBadgeClasses(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'text-soc-critical-fg bg-soc-critical-bg border border-soc-critical-border'
    case 'high':
      return 'text-soc-high-fg bg-soc-high-bg border border-soc-high-border'
    case 'medium':
      return 'text-soc-medium-fg bg-soc-medium-bg border border-soc-medium-border'
    case 'low':
      return 'text-soc-low-fg bg-soc-low-bg border border-soc-low-border'
    default:
      return 'text-muted-foreground bg-muted border border-border'
  }
}

/**
 * CSS badge classes for a threat level (same semantic mapping as severity,
 * used in the AI Analysis table where the API returns uppercase CRITICAL/HIGH/…).
 */
export function threatLevelBadgeClasses(level: string): string {
  return severityBadgeClasses(level)
}

/**
 * Text + background CSS classes for a threat level used in the AI panel.
 * Returns only the text-color + font-weight variant (no bg/border) for inline
 * table cells that don't need the full badge chrome.
 */
export function threatLevelTextClasses(level: string): string {
  switch (level.toUpperCase()) {
    case 'CRITICAL':
      return 'text-soc-critical-fg font-bold'
    case 'HIGH':
      return 'text-soc-high-fg font-semibold'
    case 'MEDIUM':
      return 'text-soc-medium-fg'
    case 'LOW':
      return 'text-soc-low-fg'
    default:
      return 'text-muted-foreground'
  }
}

/**
 * CSS badge classes for a log ACTION value (BLOCK vs ALERT vs other).
 *
 * BLOCK → enforced token (red/strong) — visually distinct, must pop.
 * ALERT → watch token (amber) — pay attention, not yet blocked.
 * Other → muted neutral.
 *
 * Sourced from legacy .b-block / .b-alert / .b-allow (lines 51-54).
 */
export function actionBadgeClasses(action: string): string {
  switch (action.toLowerCase()) {
    case 'block':
    case 'blocked':
      return 'text-soc-enforced-fg bg-soc-enforced-bg border border-soc-enforced-border font-semibold'
    case 'alert':
    case 'alerted':
      return 'text-soc-watch-fg bg-soc-watch-bg border border-soc-watch-border'
    case 'allow':
    case 'allowed':
    case 'pass':
    case 'passed':
      return 'text-soc-ok-fg bg-soc-ok-bg border border-soc-ok-border'
    case 'drop':
    case 'dropped':
      return 'text-soc-enforced-fg bg-soc-enforced-bg border border-soc-enforced-border'
    default:
      return 'text-muted-foreground'
  }
}

/**
 * CSS badge classes for a source-type chip.
 *
 * Maps known source types to their semantic token color. Unknown source types
 * fall through to a muted neutral — new plugins appear without UI edits
 * (ADR-0024 modular-UI principle).
 *
 * Sourced from legacy .b-src-waf / .b-src-ids (lines 102-104).
 */
export function sourceTypeBadgeClasses(sourceType: string): string {
  switch (sourceType.toLowerCase()) {
    case 'azure_waf':
      return 'text-soc-src-waf-fg bg-soc-src-waf-bg border border-soc-src-waf-border'
    case 'suricata':
      return 'text-soc-src-ids-fg bg-soc-src-ids-bg border border-soc-src-ids-border'
    default:
      // Unknown source type → neutral muted badge.
      // New plugins get a visible chip automatically; no UI edit required.
      return 'text-muted-foreground bg-muted border border-border'
  }
}
