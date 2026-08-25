import type { ReactNode } from 'react'
import { MicroLabel } from '../ui'

/**
 * The page header shared by every data view — eyebrow kicker, display title,
 * one-line intro, and an optional right-aligned status aside (count / freshness
 * stamp). Mirrors the gallery's Section header so the desk reads as one system.
 */
export function ViewHeader({
  eyebrow,
  kicker,
  title,
  intro,
  aside,
}: {
  eyebrow: string
  /** A small mono line above the H1 — e.g. the entity TYPE when the H1 itself
   *  is a resolved proper name (an actor's own name), so the "what kind of
   *  page is this" cue isn't lost. */
  kicker?: string
  title: string
  intro?: string
  aside?: ReactNode
}) {
  return (
    <header className="flex flex-col gap-4 border-b border-line pb-6 sm:flex-row sm:items-end sm:justify-between">
      <div className="flex flex-col gap-2">
        <MicroLabel tone="accent" tick>
          {eyebrow}
        </MicroLabel>
        {kicker && (
          <span className="font-mono text-micro font-semibold uppercase tracking-label text-faint">
            {kicker}
          </span>
        )}
        <h1 className="font-display text-xl font-extrabold tracking-tight text-paper">
          {title}
        </h1>
        {intro && <p className="max-w-2xl text-base text-muted">{intro}</p>}
      </div>
      {aside && <div className="shrink-0">{aside}</div>}
    </header>
  )
}
