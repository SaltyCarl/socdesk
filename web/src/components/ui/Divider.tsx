import { cx } from '../../lib/cx'

/**
 * Divider — a single hairline in the room-neutral line colour. The whole
 * system leans on 1px hairlines (Vantage grid discipline) rather than
 * boxes-in-boxes, so this is a first-class primitive.
 *
 *   orientation="horizontal" (default) — a full-width rule
 *   orientation="vertical"             — a full-height rule (needs a
 *                                        sized flex/grid parent)
 *   strong                              — the brighter --line-bright ink
 */
export function Divider({
  orientation = 'horizontal',
  strong = false,
  className,
}: {
  orientation?: 'horizontal' | 'vertical'
  strong?: boolean
  className?: string
}) {
  return (
    <div
      role="separator"
      aria-orientation={orientation}
      className={cx(
        strong ? 'bg-line-bright' : 'bg-line',
        orientation === 'horizontal' ? 'h-px w-full' : 'h-full w-px',
        className,
      )}
    />
  )
}
