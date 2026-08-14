import type { FeedItem } from '../views/types'
import { rel, safeUrl } from '../views/format'
import { ScoreBadge, MonoTag } from '../views/Badges'
import { BoardPanel, DeskLink, SourceStamp, PanelEmpty } from './board-ui'

/**
 * Top of the queue — the highest-relevance reports the pipeline collected,
 * score-sorted (recency tie-break) exactly like the full Feed. Each row carries
 * the pipeline's own `why` rationale, so the ranking explains itself here too,
 * not only on the desk. This is the "what's hot" anchor tile.
 */

const TOP_N = 6

function byScore(a: FeedItem, b: FeedItem): number {
  const s = (b.score ?? -1) - (a.score ?? -1)
  if (s !== 0) return s
  return String(b.published_at ?? '').localeCompare(String(a.published_at ?? ''))
}

function QueueRow({ item }: { item: FeedItem }) {
  const href = safeUrl(item.url)
  const why = (item.why ?? []).slice(0, 3)
  const extra = (item.why?.length ?? 0) - why.length

  return (
    <div className="grid grid-cols-[auto_1fr_auto] items-start gap-3 border-b border-line py-3 first:pt-0 last:border-0 last:pb-0">
      <ScoreBadge score={item.score} />

      <div className="flex min-w-0 flex-col gap-1">
        {href ? (
          <a
            href={href}
            target="_blank"
            rel="noopener noreferrer"
            className="line-clamp-1 text-base font-semibold text-paper underline-offset-2 transition-colors duration-150 ease-brand hover:text-accent hover:underline"
          >
            {item.title}
          </a>
        ) : (
          <span className="line-clamp-1 text-base font-semibold text-paper">
            {item.title}
          </span>
        )}
        <div className="flex flex-wrap items-center gap-1.5">
          <MonoTag tone="faint">{item.category}</MonoTag>
          {why.map((w) => (
            <span
              key={w}
              className="rounded-sm border border-line bg-panel-soft px-1.5 py-0.5 font-mono text-micro text-muted"
            >
              {w}
            </span>
          ))}
          {extra > 0 && <span className="font-mono text-micro text-faint">+{extra}</span>}
        </div>
      </div>

      <div className="flex flex-col items-end gap-1 whitespace-nowrap">
        <span className="font-mono text-micro uppercase tracking-label text-faint">
          {item.source}
        </span>
        <span className="font-mono text-micro text-faint">{rel(item.published_at)}</span>
      </div>
    </div>
  )
}

export function TopOfQueue({ items }: { items: FeedItem[] }) {
  const top = [...items].sort(byScore).slice(0, TOP_N)

  return (
    <BoardPanel
      eyebrow="What's hot"
      title="Top of the queue"
      aside={<SourceStamp file="feed.json" />}
      footer={
        <>
          <span className="font-mono text-micro uppercase tracking-label text-faint">
            {items.length ? `${items.length} in queue` : 'Queue empty'}
          </span>
          <DeskLink tab="feed">Full feed</DeskLink>
        </>
      }
    >
      {top.length === 0 ? (
        <PanelEmpty>
          Nothing has been collected into the feed yet — the queue fills on the
          next successful pull.
        </PanelEmpty>
      ) : (
        <div className="flex flex-col">
          {top.map((it) => (
            <QueueRow key={it.id} item={it} />
          ))}
        </div>
      )}
    </BoardPanel>
  )
}
