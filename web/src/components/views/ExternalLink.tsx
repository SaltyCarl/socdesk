import type { ReactNode } from 'react'

/**
 * The one external-link idiom (accent text + ↗, new tab, no referrer) shared by
 * every surface that links off-site — actor-profile advisories/reporting, the
 * sources table, and whatever comes next. Centralised for the same reason as
 * safeUrl/VictimLogo/CveLink: per-surface reimplementations are where the
 * divergences (and the leaks) grew. Callers pass an href that ALREADY went
 * through safeUrl — this component renders, it does not validate.
 *
 * `onion` marks a leak-site source plainly (the label, not the destination —
 * safeUrl never lets an .onion href through, so an onion-marked link's href is
 * always a clearnet page ABOUT the leak post, never the leak site itself).
 */
export function ExternalLink({
  href,
  children,
  onion = false,
  className,
}: {
  href: string
  children: ReactNode
  onion?: boolean
  className?: string
}) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className={
        className ?? 'inline-flex items-center gap-1 text-xs text-accent underline-offset-2 hover:underline'
      }
    >
      {children}
      <span aria-hidden="true">{onion ? '· .onion ↗' : '↗'}</span>
    </a>
  )
}
