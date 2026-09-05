import { MicroLabel } from '../ui'
import { KevBadge, MonoTag } from './Badges'
import { ExternalLink } from './ExternalLink'
import { epssShift } from '../overview/trendRows'
import { safeUrl } from './format'
import type { FeedItem, Story } from './types'

/**
 * StoryStrip — the "Corroborated" lead of the Desk briefing (OPEN-WORK §3). Each
 * row is one story covered by ≥2 distinct outlets: the headline + a "covered by
 * N · A, B, C" corroboration line + the CVE delta chips (KEV / EPSS shift),
 * expanding via <details> to the member reports (which are de-duped out of the
 * Lead/Sections upstream, so this is the only place they render). Honest: only
 * attributed outlets + catalog-sourced deltas; a real member title per link.
 */
function StoryRow({ story, itemsById }: { story: Story; itemsById: Map<string, FeedItem> }) {
  const d = story.delta
  const shift = d ? epssShift({ from: d.epss_from ?? null, to: d.epss_to ?? null }) : null
  const members = story.member_ids.map((id) => itemsById.get(id)).filter((m): m is FeedItem => Boolean(m))
  return (
    <details className="sd-reveal rounded-lg border border-line bg-panel p-4">
      <summary className="flex cursor-pointer list-none flex-col gap-1.5 marker:content-none [&::-webkit-details-marker]:hidden">
        <div className="flex flex-wrap items-center gap-1.5">
          {d?.kev && <KevBadge ransomware={d.kev_ransomware} />}
          {shift ? (
            <span className="font-mono text-micro text-accent-dim">
              EPSS {shift.from}→{shift.to}
            </span>
          ) : d?.epss != null ? (
            <span className="font-mono text-micro text-accent-dim">EPSS {Math.round(d.epss * 100)}%</span>
          ) : null}
          <MonoTag tone="muted">{story.entity}</MonoTag>
        </div>
        <span className="font-display text-base font-bold tracking-tight text-paper">{story.title}</span>
        <span className="font-mono text-micro text-faint">
          covered by {story.outlets.length} · {story.outlets.join(' · ')}
        </span>
      </summary>
      <div className="mt-3 flex flex-col gap-1.5 border-t border-line pt-3">
        {members.map((m) => {
          const href = safeUrl(m.url)
          return (
            <div key={m.id} className="flex items-baseline justify-between gap-3">
              <span className="line-clamp-1 text-xs text-muted">{m.title}</span>
              {href && <ExternalLink href={href}>open</ExternalLink>}
            </div>
          )
        })}
      </div>
    </details>
  )
}

export function StoryStrip({ stories, itemsById }: { stories: Story[]; itemsById: Map<string, FeedItem> }) {
  if (stories.length === 0) return null
  return (
    <section aria-label="Corroborated stories" className="flex flex-col gap-3">
      <MicroLabel tone="accent" tick>
        Corroborated — one story, multiple sources
      </MicroLabel>
      <div className="flex flex-col gap-2">
        {stories.map((s) => (
          <StoryRow key={s.key} story={s} itemsById={itemsById} />
        ))}
      </div>
    </section>
  )
}
