import type { ReactNode } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import { MicroLabel } from '../ui'
import { navigate } from '../palette/commands'

/**
 * Shared chrome for the daily-summary panels: a titled panel frame, an
 * upstream-authority stamp, and an SPA deep-link into the data desk.
 */

/* ---------------- source attribution stamp ---------------- */

/**
 * Cite the upstream AUTHORITY, not the internal filename — "NVD · EPSS · KEV",
 * "ransomware.live". A filename stamp is faux-transparency; the authority is
 * what an analyst actually needs to weigh the number.
 */
export function SourceStamp({ label }: { label: string }) {
  return (
    <MicroLabel tone="faint" className="whitespace-nowrap">
      {label}
    </MicroLabel>
  )
}

/* ---------------- SPA deep-link into /desk#<tab> ---------------- */

/**
 * A real `<a href>` (middle-click / ⌘-click open a new tab, and it's crawlable),
 * but a plain left-click is intercepted into the app's pushState navigation so
 * the desk opens without a full reload.
 */
export function DeskLink({
  tab,
  children,
  className,
}: {
  tab: string
  children: ReactNode
  className?: string
}) {
  const href = `/desk#${tab}`
  return (
    <a
      href={href}
      onClick={(e) => {
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return
        e.preventDefault()
        navigate(href)
      }}
      className={cx(
        'inline-flex items-center gap-1 font-mono text-micro font-semibold uppercase tracking-label text-accent',
        'underline-offset-2 transition-colors duration-150 ease-brand hover:text-accent-dim hover:underline',
        'outline-offset-2 focus-visible:outline-2 focus-visible:outline-accent',
        className,
      )}
    >
      {children}
      <span aria-hidden="true">→</span>
    </a>
  )
}

/* ---------------- panel frame ---------------- */

/**
 * The board's panel shell — a recessive work surface with a titled header, an
 * optional right-aligned aside (source stamp / deep-link), and a scroll-reveal
 * hook (`sd-reveal`, static under reduced motion). `accent` promotes it to the
 * lifted, accent-spined treatment reserved for the flagship panel.
 */
export function BoardPanel({
  eyebrow,
  title,
  aside,
  footer,
  accent = false,
  className,
  children,
}: {
  eyebrow: string
  title: ReactNode
  aside?: ReactNode
  footer?: ReactNode
  accent?: boolean
  className?: string
  children: ReactNode
}) {
  return (
    <section
      className={cx(
        'sd-reveal flex h-full flex-col gap-4 rounded-lg border p-5',
        accent
          ? 'border-[var(--edge-accent)] bg-raised shadow-e1'
          : 'border-line bg-panel',
        className,
      )}
    >
      <header className="flex flex-wrap items-start justify-between gap-x-4 gap-y-1">
        <div className="flex flex-col gap-1.5">
          <MicroLabel tone={accent ? 'accent' : 'muted'} tick={accent}>
            {eyebrow}
          </MicroLabel>
          <h3 className="font-display text-md font-bold tracking-tight text-paper">
            {title}
          </h3>
        </div>
        {aside && <div className="shrink-0 pt-0.5">{aside}</div>}
      </header>
      <div className="flex flex-1 flex-col">{children}</div>
      {footer && (
        <footer className="flex items-center justify-between gap-3 border-t border-line pt-3">
          {footer}
        </footer>
      )}
    </section>
  )
}

/* ---------------- honest inline empty ---------------- */

/** A truthful, low-drama empty line for a panel that has nothing to show. */
export function PanelEmpty({ children }: { children: ReactNode }) {
  return (
    <p className="flex min-h-16 items-center text-xs text-muted" role="status">
      {children}
    </p>
  )
}
