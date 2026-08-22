import { cx } from '../lib/cx'

/**
 * Button skin — kept in its own module so the component file exports only
 * a component (clean react-refresh). `buttonClasses` also lets a non-button
 * element (e.g. an <a>) borrow the exact button styling.
 *
 *   primary  · filled periwinkle — the one loud CTA
 *   ghost    · hairline neutral — the recessive workhorse
 *   tertiary · borderless/muted → hover reveals — "discoverable but not
 *              competing" actions (e.g. Report in the card action row)
 *   danger   · quiet tinted red — DESTRUCTIVE actions only (meaning-bearing,
 *              never decorative; stays a tint, not a fill, per the verdict rule)
 */
export type ButtonVariant = 'primary' | 'ghost' | 'tertiary' | 'danger'
export type ButtonSize = 'sm' | 'md'

const BASE =
  'inline-flex select-none items-center justify-center whitespace-nowrap ' +
  'rounded-md font-sans font-medium transition-colors duration-150 ease-brand ' +
  'outline-offset-2 focus-visible:outline-2 focus-visible:outline-accent ' +
  'disabled:pointer-events-none disabled:opacity-50'

const VARIANT: Record<ButtonVariant, string> = {
  primary: 'bg-accent text-ink-on-accent hover:bg-accent-dim',
  ghost:
    'border border-line bg-transparent text-paper hover:border-line-bright hover:bg-panel-soft',
  tertiary:
    'border border-transparent bg-transparent text-muted hover:border-line hover:bg-panel-soft hover:text-paper',
  danger:
    'border border-[var(--edge-red)] bg-transparent text-verdict-red hover:bg-[var(--tint-red)]',
}

const SIZE: Record<ButtonSize, string> = {
  sm: 'h-8 gap-1.5 px-3 text-xs',
  md: 'h-10 gap-2 px-4 text-base',
}

export function buttonClasses(
  variant: ButtonVariant = 'primary',
  size: ButtonSize = 'md',
  className?: string,
): string {
  return cx(BASE, VARIANT[variant], SIZE[size], className)
}
