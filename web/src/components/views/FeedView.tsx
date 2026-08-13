import {
  useDeferredValue,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react'
import { cx } from '../../lib/cx'
import type { FeedItem } from './types'
import { rel, safeUrl } from './format'
import { ScoreBadge, MonoTag } from './Badges'
import { EmptyState } from './states'

/**
 * The feed IS the work queue: score-sorted by default so the highest-relevance
 * reports lead, with the pipeline's `why` rationale printed on every row so the
 * ranking is explainable, never a black box. Priority (0–100 score, recency
 * tie-break) is the default order; Newest is the explicit chronological
 * alternative.
 */

const INIT = 25
const STEP = 100
const REVIEWED_KEY = 'socdesk-reviewed'

type Sort = 'priority' | 'newest'

function loadReviewed(): Set<string> {
  try {
    const raw = localStorage.getItem(REVIEWED_KEY)
    return new Set<string>(raw ? (JSON.parse(raw) as string[]) : [])
  } catch {
    return new Set<string>()
  }
}
function saveReviewed(set: Set<string>): void {
  try {
    localStorage.setItem(REVIEWED_KEY, JSON.stringify([...set]))
  } catch {
    /* best-effort */
  }
}

const byTimeDesc = (a: FeedItem, b: FeedItem): number =>
  String(b.published_at ?? '').localeCompare(String(a.published_at ?? ''))

/* ---------------- small internal controls ---------------- */

function SegButton({
  active,
  onClick,
  children,
}: {
  active: boolean
  onClick: () => void
  children: React.ReactNode
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cx(
        'inline-flex h-8 items-center px-3 font-mono text-micro font-semibold uppercase tracking-label transition-colors duration-150 ease-brand',
        'outline-offset-[-2px] focus-visible:outline-2 focus-visible:outline-accent',
        active
          ? 'text-paper shadow-[inset_0_-2px_0_var(--accent)]'
          : 'text-muted hover:text-paper',
      )}
    >
      {children}
    </button>
  )
}

function FilterChip({
  active,
  label,
  count,
  onClick,
}: {
  active: boolean
  label: string
  count: number
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cx(
        'inline-flex items-center gap-2 rounded-full border px-3 py-1 font-mono text-micro font-semibold uppercase tracking-label transition-colors duration-150 ease-brand',
        'outline-offset-2 focus-visible:outline-2 focus-visible:outline-accent',
        active
          ? 'border-[var(--edge-accent)] bg-[var(--tint-accent)] text-accent'
          : 'border-line bg-panel text-muted hover:border-line-bright hover:text-paper',
      )}
    >
      {label}
      <b className="font-semibold tabular-nums">{count}</b>
    </button>
  )
}

/* ---------------- the row ---------------- */

function Row({
  item,
  index,
  selected,
  reviewed,
  onSelect,
  onToggleReviewed,
}: {
  item: FeedItem
  index: number
  selected: boolean
  reviewed: boolean
  onSelect: () => void
  onToggleReviewed: () => void
}) {
  const href = safeUrl(item.url)
  const why = (item.why ?? []).slice(0, 3)
  const extraWhy = (item.why?.length ?? 0) - why.length

  return (
    <div
      data-idx={index}
      data-row
      onClick={onSelect}
      className={cx(
        'sd-reveal group grid grid-cols-[auto_1fr_auto] gap-4 rounded-lg border bg-panel px-4 py-3 transition-colors duration-150 ease-brand',
        selected
          ? 'border-[var(--edge-accent)]'
          : 'border-line hover:border-line-bright',
        reviewed && 'opacity-60',
      )}
    >
      {/* priority + category */}
      <div className="flex flex-col items-start gap-1.5">
        <ScoreBadge score={item.score} />
        <MonoTag tone="faint">{item.category}</MonoTag>
      </div>

      {/* the report */}
      <div className="min-w-0 flex flex-col gap-1">
        <div className="flex items-center gap-2">
          <span className="font-mono text-micro uppercase tracking-label text-faint">
            {item.source}
          </span>
          {item.grouped ? (
            <MonoTag tone="accent">digest · {item.grouped}</MonoTag>
          ) : null}
        </div>
        {href ? (
          <a
            href={href}
            target="_blank"
            rel="noopener noreferrer"
            onClick={(e) => e.stopPropagation()}
            className="text-base font-semibold text-paper underline-offset-2 hover:text-accent hover:underline"
          >
            {item.title}
          </a>
        ) : (
          <span className="text-base font-semibold text-paper">
            {item.title}
          </span>
        )}
        <p className="line-clamp-2 text-xs text-muted">{item.summary}</p>
        {(why.length > 0 || extraWhy > 0) && (
          <div className="mt-0.5 flex flex-wrap items-center gap-1.5">
            <span className="font-mono text-micro uppercase tracking-label text-faint">
              why
            </span>
            {why.map((w) => (
              <span
                key={w}
                className="rounded-sm border border-line bg-panel-soft px-1.5 py-0.5 font-mono text-micro text-muted"
              >
                {w}
              </span>
            ))}
            {extraWhy > 0 && (
              <span className="font-mono text-micro text-faint">
                +{extraWhy}
              </span>
            )}
          </div>
        )}
      </div>

      {/* meta + triage action */}
      <div className="flex flex-col items-end justify-between gap-2">
        <span className="whitespace-nowrap font-mono text-micro text-faint">
          {rel(item.published_at)}
        </span>
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation()
            onToggleReviewed()
          }}
          aria-pressed={reviewed}
          title={reviewed ? 'Reviewed — click to unmark' : 'Mark reviewed'}
          className={cx(
            'inline-flex size-7 items-center justify-center rounded-md border transition-colors duration-150 ease-brand',
            'outline-offset-2 focus-visible:outline-2 focus-visible:outline-accent',
            reviewed
              ? 'border-[var(--edge-accent)] bg-[var(--tint-accent)] text-accent'
              : 'border-line text-faint opacity-0 hover:border-line-bright hover:text-paper focus-visible:opacity-100 group-hover:opacity-100',
          )}
        >
          ✓
        </button>
      </div>
    </div>
  )
}

/* ---------------- the view ---------------- */

export function FeedView({ items }: { items: FeedItem[] }) {
  const [filter, setFilter] = useState('all')
  const [sort, setSort] = useState<Sort>('priority')
  const [limit, setLimit] = useState(INIT)
  const [rawQuery, setRawQuery] = useState('')
  const query = useDeferredValue(rawQuery)
  const [reviewed, setReviewed] = useState<Set<string>>(loadReviewed)
  const [sel, setSel] = useState(0)
  const listRef = useRef<HTMLDivElement>(null)

  const categories = useMemo(() => {
    const counts = new Map<string, number>()
    for (const it of items) counts.set(it.category, (counts.get(it.category) ?? 0) + 1)
    return [
      { key: 'all', count: items.length },
      ...[...counts.entries()]
        .sort((a, b) => b[1] - a[1])
        .map(([key, count]) => ({ key, count })),
    ]
  }, [items])

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase()
    const hit = items.filter((it) => {
      if (filter !== 'all' && it.category !== filter) return false
      if (!q) return true
      const hay = (
        it.title +
        ' ' +
        it.summary +
        ' ' +
        Object.values(it.entities ?? {})
          .flat()
          .join(' ')
      ).toLowerCase()
      return hay.includes(q)
    })
    return [...hit].sort(
      sort === 'newest'
        ? byTimeDesc
        : (a, b) => (b.score ?? -1) - (a.score ?? -1) || byTimeDesc(a, b),
    )
  }, [items, filter, query, sort])

  const shown = visible.slice(0, limit)

  // Reset selection when the query/filter/sort changes the result set.
  useEffect(() => {
    setSel(0)
  }, [filter, query, sort])

  const toggleReviewed = (id: string) => {
    setReviewed((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      saveReviewed(next)
      return next
    })
  }

  // j/k to move, r to review, Enter to open — the analyst keyboard triage loop.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = document.activeElement?.tagName
      if (tag === 'INPUT' || tag === 'TEXTAREA') return
      if (!shown.length) return
      if (e.key === 'j') {
        e.preventDefault()
        setSel((s) => Math.min(s + 1, shown.length - 1))
      } else if (e.key === 'k') {
        e.preventDefault()
        setSel((s) => Math.max(s - 1, 0))
      } else if (e.key === 'r') {
        const it = shown[sel]
        if (it) toggleReviewed(it.id)
      } else if (e.key === 'Enter') {
        const url = safeUrl(shown[sel]?.url)
        if (url) window.open(url, '_blank', 'noopener,noreferrer')
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [shown, sel])

  // Keep the selected row in view.
  useEffect(() => {
    listRef.current
      ?.querySelector(`[data-idx="${sel}"]`)
      ?.scrollIntoView({ block: 'nearest' })
  }, [sel])

  return (
    <div className="flex flex-col gap-5">
      {/* controls */}
      <div className="flex flex-col gap-4">
        <div className="flex flex-wrap items-center gap-3">
          <input
            type="search"
            value={rawQuery}
            onChange={(e) => {
              setRawQuery(e.target.value)
              setLimit(INIT)
            }}
            placeholder="Filter the queue — title, summary, entity…"
            aria-label="Filter feed"
            className="h-9 w-full max-w-md rounded-md border border-line bg-field px-3 font-mono text-base text-paper outline-offset-2 placeholder:text-faint focus-visible:outline-2 focus-visible:outline-accent"
          />
          <div className="ml-auto flex items-center gap-1 rounded-md border border-line bg-panel px-1">
            <SegButton active={sort === 'priority'} onClick={() => setSort('priority')}>
              Priority
            </SegButton>
            <SegButton active={sort === 'newest'} onClick={() => setSort('newest')}>
              Newest
            </SegButton>
          </div>
        </div>

        <div className="flex flex-wrap gap-2">
          {categories.map((c) => (
            <FilterChip
              key={c.key}
              active={filter === c.key}
              label={c.key}
              count={c.count}
              onClick={() => {
                setFilter(c.key)
                setLimit(INIT)
              }}
            />
          ))}
        </div>
      </div>

      {/* result meter */}
      <div className="flex items-center justify-between">
        <span className="font-mono text-micro uppercase tracking-label text-faint">
          {visible.length === 0
            ? 'No results'
            : `Showing ${shown.length} of ${visible.length}`}
        </span>
        <span className="font-mono text-micro text-faint">
          j / k move · r review · ⏎ open
        </span>
      </div>

      {/* the queue */}
      {visible.length === 0 ? (
        <EmptyState title="No reports match this filter">
          {query.trim() || filter !== 'all'
            ? 'Loosen the search or switch back to the “all” category — the collected reports are still here, just filtered out.'
            : 'Nothing has been collected into the feed yet. The pipeline publishes on a schedule; the queue fills on the next successful pull.'}
        </EmptyState>
      ) : (
        <>
          <div ref={listRef} className="flex flex-col gap-2">
            {shown.map((it, i) => (
              <Row
                key={it.id}
                item={it}
                index={i}
                selected={i === sel}
                reviewed={reviewed.has(it.id)}
                onSelect={() => setSel(i)}
                onToggleReviewed={() => toggleReviewed(it.id)}
              />
            ))}
          </div>
          {visible.length > limit && (
            <button
              type="button"
              onClick={() => setLimit((n) => n + STEP)}
              className="mx-auto rounded-md border border-line bg-panel px-4 py-2 font-mono text-xs text-muted transition-colors duration-150 ease-brand hover:border-line-bright hover:text-paper focus-visible:outline-2 focus-visible:outline-accent"
            >
              Load more — {visible.length - shown.length} remaining
            </button>
          )}
        </>
      )}
    </div>
  )
}
