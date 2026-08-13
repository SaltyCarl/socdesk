/**
 * Command-palette data model — shared, component-free types so the
 * palette's component modules stay react-refresh-clean (a file that
 * exports a component may not also export non-component values).
 */

/** Indicator taxonomy the lookup understands. `unknown` is a real state —
 *  absence of a classification is never dressed up as something else. */
export type IndicatorType = 'ip' | 'domain' | 'url' | 'hash' | 'cve' | 'unknown'

/** What a palette row *is*, which drives how selecting it behaves:
 *   lookup  · the live query, deep-linked to the lookup surface (#q=)
 *   recent  · a previously-looked-up indicator (localStorage)
 *   action  · an imperative command (theme, clipboard, …)
 *   view    · in-app navigation to a route */
export type CommandKind = 'lookup' | 'recent' | 'action' | 'view'

export interface CommandItem {
  /** Stable, unique within a build of the list. */
  id: string
  kind: CommandKind
  /** The primary, searchable text shown on the row. */
  label: string
  /** Right-aligned affordance (a path, a shortcut, a verb). */
  hint?: string
  /** Extra fuzzy-match terms that never render. */
  keywords?: string[]
  /** Indicator badge for `lookup` / `recent` rows. */
  indicatorType?: IndicatorType
  /** Destination for `view` rows. */
  href?: string
}

export interface CommandGroup {
  id: string
  heading: string
  items: CommandItem[]
}
