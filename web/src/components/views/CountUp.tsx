import { cx } from '@socdesk/shared/lib/cx'
import { num } from './format'
import { useCountUp } from './useCountUp'

/**
 * A stat number that ticks 0 → value the first time it scrolls into view, then
 * holds the final value (see useCountUp for the reduced-motion / no-IO
 * fallback). Colour comes from the parent — this stays a plain number so the
 * verdict palette is never borrowed for decoration.
 *
 * ZERO layout shift: `tabular-nums` fixes each digit's WIDTH, but the digit
 * COUNT still grows while ticking (0 → 4,804), which would reflow the trailing
 * text. So the box reserves the FINAL value's character width up-front (a
 * `min-w-[Nch]` sized to the formatted length) and right-aligns the ticking
 * value into it — odometer-style, ones column fixed, nothing after it moves.
 * All widths are Tailwind classes; no inline style (CSP / forbid-dom-props).
 */

// Literal so Tailwind's scanner compiles them; indexed by character count.
const MIN_W = [
  'min-w-[1ch]', // 0 (unused — length is ≥ 1)
  'min-w-[1ch]',
  'min-w-[2ch]',
  'min-w-[3ch]',
  'min-w-[4ch]',
  'min-w-[5ch]',
  'min-w-[6ch]',
  'min-w-[7ch]',
  'min-w-[8ch]',
] as const

export function CountUp({
  value,
  duration,
  className,
}: {
  value: number
  duration?: number
  className?: string
}) {
  const { ref, value: display } = useCountUp<HTMLSpanElement>(value, { duration })
  const reserve = MIN_W[Math.min(num(value).length, MIN_W.length - 1)]
  return (
    <span
      ref={ref}
      className={cx('inline-block text-right tabular-nums', reserve, className)}
    >
      {num(display)}
    </span>
  )
}
