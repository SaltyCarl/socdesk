import type { ReactNode } from 'react'
import { cx } from '../../lib/cx'
import { MicroLabel } from '../ui'
import type { AsyncStatus } from './useStateData'

/**
 * The honest loading / empty / error vocabulary shared by every data view.
 *
 * Two rules the whole app keeps:
 *   • Loading shows a skeleton that mirrors the real layout, never a spinner
 *     over a blank page.
 *   • Empty and error STATE THE REASON. "Absence of data is not evidence of
 *     safety" (the verdict doctrine) applies to the collection layer too — a
 *     view that has nothing to show says why, and reassures that the rest of
 *     the desk still works.
 */

/** A single shimmer block. `animate-pulse` self-disables under the global
 *  reduced-motion kill switch, leaving a static placeholder — still honest. */
export function Skeleton({ className }: { className?: string }) {
  return (
    <div
      aria-hidden="true"
      className={cx('animate-pulse rounded-md bg-panel-soft', className)}
    />
  )
}

/** A stack of skeleton rows sized to the list/table that will replace them. */
export function SkeletonRows({
  rows = 6,
  className,
}: {
  rows?: number
  className?: string
}) {
  return (
    <div
      aria-hidden="true"
      className={cx('flex flex-col gap-2', className)}
      role="presentation"
    >
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-16 w-full" />
      ))}
    </div>
  )
}

function Notice({
  tone,
  eyebrow,
  title,
  children,
}: {
  tone: 'muted' | 'accent'
  eyebrow: string
  title: string
  children: ReactNode
}) {
  return (
    <div
      role={tone === 'accent' ? 'alert' : 'status'}
      className="flex flex-col items-start gap-2 rounded-lg border border-line bg-panel px-5 py-8"
    >
      <MicroLabel tone={tone === 'accent' ? 'accent' : 'faint'}>
        {eyebrow}
      </MicroLabel>
      <h3 className="font-display text-md font-bold tracking-tight text-paper">
        {title}
      </h3>
      <p className="max-w-xl text-base text-muted">{children}</p>
    </div>
  )
}

/** Ready, but nothing to show — a truthful empty. */
export function EmptyState({
  title,
  children,
}: {
  title: string
  children: ReactNode
}) {
  return (
    <Notice tone="muted" eyebrow="Nothing to show" title={title}>
      {children}
    </Notice>
  )
}

/** The fetch failed / the snapshot has not published. */
export function ErrorState({
  label,
  detail,
}: {
  label: string
  detail?: string | null
}) {
  return (
    <Notice tone="accent" eyebrow="Unavailable" title={`Couldn't load ${label}`}>
      The pipeline may not have published yet, or the data file could not be
      reached{detail ? ` (${detail})` : ''}. Everything else on this page still
      works.
    </Notice>
  )
}

/**
 * Gate a view's body on its fetch status. Loading → the caller's skeleton;
 * error → the standard honest error; ready → the children. "Empty" is
 * intentionally NOT handled here — only the view knows whether a ready payload
 * is empty after its own filters, so it renders its own EmptyState.
 */
export function AsyncGate({
  status,
  label,
  detail,
  skeleton,
  children,
}: {
  status: AsyncStatus
  label: string
  detail?: string | null
  skeleton: ReactNode
  children: ReactNode
}) {
  if (status === 'loading') return <>{skeleton}</>
  if (status === 'error') return <ErrorState label={label} detail={detail} />
  return <>{children}</>
}
