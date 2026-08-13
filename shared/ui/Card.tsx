import type { ReactNode } from 'react'
import { cx } from '../lib/cx'
import { MicroLabel } from './MicroLabel'

/**
 * Surfaces — two weights, both hairline-bordered, radius-lg (12px):
 *
 *   Panel · recessive work surface. Flat --panel, no shadow. The default
 *           container for dense content (Vantage grid discipline).
 *   Card  · a lifted --raised surface with e1 elevation. Use sparingly;
 *           the chrome stays quiet, so reserve elevation for things that
 *           truly float above the page.
 *
 * CardHeader / CardTitle / CardBody compose a titled card with the
 * shared micro-label eyebrow.
 */

const PADDING = {
  none: 'p-0',
  sm: 'p-3',
  md: 'p-5',
  lg: 'p-6',
} as const
export type SurfacePadding = keyof typeof PADDING

export function Panel({
  children,
  padding = 'md',
  className,
}: {
  children: ReactNode
  padding?: SurfacePadding
  className?: string
}) {
  return (
    <div
      className={cx(
        'rounded-lg border border-line bg-panel',
        PADDING[padding],
        className,
      )}
    >
      {children}
    </div>
  )
}

export function Card({
  children,
  padding = 'md',
  interactive = false,
  className,
}: {
  children: ReactNode
  padding?: SurfacePadding
  interactive?: boolean
  className?: string
}) {
  return (
    <div
      className={cx(
        'rounded-lg border border-line bg-raised shadow-e1',
        interactive &&
          'transition-colors duration-150 ease-brand hover:border-line-bright hover:shadow-e2',
        PADDING[padding],
        className,
      )}
    >
      {children}
    </div>
  )
}

export function CardHeader({
  eyebrow,
  title,
  aside,
  className,
}: {
  eyebrow?: ReactNode
  title: ReactNode
  aside?: ReactNode
  className?: string
}) {
  return (
    <div className={cx('flex items-start justify-between gap-4', className)}>
      <div className="flex flex-col gap-1.5">
        {eyebrow && <MicroLabel tone="accent">{eyebrow}</MicroLabel>}
        <h3 className="font-display text-md font-bold tracking-tight text-paper">
          {title}
        </h3>
      </div>
      {aside && <div className="shrink-0">{aside}</div>}
    </div>
  )
}

export function CardBody({
  children,
  className,
}: {
  children: ReactNode
  className?: string
}) {
  return (
    <div className={cx('text-base text-muted', className)}>{children}</div>
  )
}
