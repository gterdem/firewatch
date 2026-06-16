/**
 * FireWatch DS component barrel — F2 #108.
 *
 * This is the ONLY public import path for DS primitives.
 * Deep imports (e.g. 'ds/core/Badge') are forbidden by the F5 adherence lint.
 *
 * Usage:
 *   import { Badge, Panel, Button, Spinner, LiveBadge } from '@/components/ds'
 */

// core
export { Badge } from './core/Badge'
export type { BadgeProps, BadgeTone } from './core/Badge'

export { Button } from './core/Button'
export type { ButtonProps, ButtonVariant, ButtonSize } from './core/Button'

export { Panel } from './core/Panel'
export type { PanelProps } from './core/Panel'

export { StatCard } from './core/StatCard'
export type { StatCardProps, StatCardAccent } from './core/StatCard'

// forms
export { Input } from './forms/Input'
export type { InputProps } from './forms/Input'

export { Select } from './forms/Select'
export type { SelectProps, SelectOption } from './forms/Select'

// navigation
export { Tabs } from './nav/Tabs'
export type { TabsProps, TabItem } from './nav/Tabs'

export { ThemeToggle } from './nav/ThemeToggle'
export type { ThemeToggleProps } from './nav/ThemeToggle'

// feedback
export { Spinner } from './feedback/Spinner'
export type { SpinnerProps } from './feedback/Spinner'

export { LiveBadge } from './feedback/LiveBadge'
export type { LiveBadgeProps } from './feedback/LiveBadge'

export { Toast } from './feedback/Toast'
export type { ToastProps, ToastTone } from './feedback/Toast'

export { SyncBanner } from './feedback/SyncBanner'
export type { SyncBannerProps } from './feedback/SyncBanner'

export { EmptyState } from './feedback/EmptyState'
export type { EmptyStateProps } from './feedback/EmptyState'

// filters (F3 #109)
export { Combobox } from './filters/Combobox'
export type { ComboboxProps, ComboOption } from './filters/Combobox'

export { FilterChip } from './filters/FilterChip'
export type { FilterChipProps } from './filters/FilterChip'

// sources (F3 #109)
export { SourceBadge } from './sources/SourceBadge'
export type { SourceBadgeProps } from './sources/SourceBadge'

export { SourceHealth } from './sources/SourceHealth'
export type { SourceHealthProps, SourceHealthItem } from './sources/SourceHealth'

export { HealthDot } from './sources/HealthDot'
export type { HealthDotProps } from './sources/HealthDot'

export { HealthCard } from './sources/HealthCard'
export type { HealthCardProps } from './sources/HealthCard'

export { SourceCard } from './sources/SourceCard'
export type { SourceCardProps, SourceCardStatus } from './sources/SourceCard'

export { EventTimeline } from './sources/EventTimeline'
export type { EventTimelineProps, TimelineEvent } from './sources/EventTimeline'

// analytics (ADR-0035 / ADR-0036 — MH foundation, #200)
export { ProvenanceChip } from './analytics/ProvenanceChip'
export type { ProvenanceChipProps, ProvenanceDerivation } from './analytics/ProvenanceChip'

export { ProvenanceChipLegend } from './analytics/ProvenanceChipLegend'

export { ScoreBadge } from './analytics/ScoreBadge'
export type { ScoreBadgeProps, SeverityBand, ScoreBadgeVariant } from './analytics/ScoreBadge'

export { ScoreBreakdownPopover } from './analytics/ScoreBreakdownPopover'
export type { ScoreBreakdownPopoverProps } from './analytics/ScoreBreakdownPopover'

export { ConfidenceLabel } from './analytics/ConfidenceLabel'
export type { ConfidenceLabelProps, ConfidenceWord } from './analytics/ConfidenceLabel'

// tooltip (WCAG 1.4.13 cell hover primitive, #246)
export { CellTooltip } from './core/CellTooltip'
export type { CellTooltipProps } from './core/CellTooltip'

// dismissable disclosure primitive (#327 — outside-click + Esc + single-open)
export { useDismissableDisclosure } from './core/useDismissableDisclosure'
export type {
  DismissableDisclosureOptions,
  DismissableDisclosureResult,
} from './core/useDismissableDisclosure'

// hover/focus disclosure primitive (WCAG 1.4.13 tooltip trigger — #246, #666)
export { useHoverFocusDisclosure } from './core/useHoverFocusDisclosure'
export type {
  HoverFocusDisclosureOptions,
  HoverFocusDisclosureResult,
} from './core/useHoverFocusDisclosure'

// tooltip position hook (DS core positioning utility — #246)
export { useTooltipPosition } from './core/useTooltipPosition'
export type { TooltipPosition, UseTooltipPositionOptions } from './core/useTooltipPosition'

// sparkline (UTC-bucketed inline trend chart, #245)
export { Sparkline } from './core/Sparkline'
export type { SparklineProps } from './core/Sparkline'

// column-priority responsive table hook (#263)
export { useColumnPriority, computeVisibleColumns } from './core/useColumnPriority'
export type { ColumnDef, UseColumnPriorityResult } from './core/useColumnPriority'

// shared anchored-overlay popover primitive (issue #665 — reused by #666/#667/#668)
// TODO(#289): will migrate to @radix-ui/react-popover when the #289 sweep lands.
export { Popover } from './Popover'
export type { PopoverProps } from './Popover'
