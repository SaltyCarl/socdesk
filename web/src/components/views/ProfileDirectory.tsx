import { useDeferredValue, useMemo, useState } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import { MonoTag } from './Badges'
import { num } from './format'
import { CountUp } from './CountUp'
import { EmptyState } from './states'
import { ActorLink } from '../overview/board-ui'
import type { ProfileIndexEntry, ProfileKind } from './profiles'

/**
 * ProfileDirectory — the searchable index of every addressable profile (MITRE
 * actors + software, ransomware groups, named APTs). Search covers name / alias
 * / ATT&CK id (mirrors ActorsView); the kind chips filter by classification. A
 * ransomware group surfaces its live claim tally so the leader board reads at a
 * glance. Each row is a crawlable link into `/actor#g=<slug>`.
 */

const INIT = 30
const STEP = 60

type Filter = 'all' | 'ransomware' | 'apt' | 'malware'

const FILTERS: { key: Filter; label: string }[] = [
  { key: 'all', label: 'All' },
  { key: 'ransomware', label: 'Ransomware' },
  { key: 'apt', label: 'APT' },
  { key: 'malware', label: 'Malware' },
]

/** A single filter's membership test — additive flags, so a both-kinds group
 *  (Akira) legitimately answers to both Ransomware and APT. */
function matchesFilter(e: ProfileIndexEntry, f: Filter): boolean {
  switch (f) {
    case 'ransomware':
      return e.claimCount != null
    case 'apt':
      return e.kind === 'actor'
    case 'malware':
      return e.kind === 'malware'
    default:
      return true
  }
}

const KIND_LABEL: Record<ProfileKind, string> = {
  actor: 'APT / actor',
  ransomware: 'Ransomware',
  malware: 'Malware',
}

function ProfileRow({ entry }: { entry: ProfileIndexEntry }) {
  return (
    <ActorLink
      name={entry.slug}
      className="sd-reveal flex flex-col items-start gap-2 rounded-lg border border-line bg-panel p-4 hover:border-line-bright"
    >
      <div className="flex w-full items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-1.5">
          <MonoTag tone={entry.kind === 'malware' ? 'muted' : 'accent'}>
            {KIND_LABEL[entry.kind]}
          </MonoTag>
          {entry.hasMitre && (
            <span className="font-mono text-micro text-faint">{entry.attack_id}</span>
          )}
          {entry.hasIntel && <MonoTag tone="accent">seeded</MonoTag>}
        </div>
        {entry.claimCount != null && (
          <span className="whitespace-nowrap font-mono text-micro text-accent">
            {num(entry.claimCount)} claims
          </span>
        )}
      </div>
      <span className="font-display text-base font-bold tracking-tight text-paper">
        {entry.name}
      </span>
      {entry.aliases && entry.aliases.length > 0 && (
        <span className="line-clamp-1 font-mono text-micro text-muted">
          {entry.aliases.slice(0, 3).join(' · ')}
        </span>
      )}
    </ActorLink>
  )
}

export function ProfileDirectory({ entries }: { entries: ProfileIndexEntry[] }) {
  const [rawQuery, setRawQuery] = useState('')
  const query = useDeferredValue(rawQuery)
  const [filter, setFilter] = useState<Filter>('all')
  const [limit, setLimit] = useState(INIT)

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return entries
      .filter((e) => matchesFilter(e, filter))
      .filter((e) => {
        if (!q) return true
        const hay =
          e.name + ' ' + e.slug + ' ' + (e.attack_id ?? '') + ' ' + (e.aliases ?? []).join(' ')
        return hay.toLowerCase().includes(q)
      })
      .sort(
        (a, b) =>
          (b.claimCount ?? -1) - (a.claimCount ?? -1) || a.name.localeCompare(b.name),
      )
  }, [entries, query, filter])

  const shown = filtered.slice(0, limit)

  const reset = () => setLimit(INIT)

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-center gap-3">
        <input
          type="search"
          value={rawQuery}
          onChange={(e) => {
            setRawQuery(e.target.value)
            reset()
          }}
          placeholder="Search actor / group / malware, alias, ATT&CK id…"
          aria-label="Search profiles"
          className="h-9 w-full max-w-sm rounded-md border border-line bg-field px-3 font-mono text-base text-paper outline-offset-2 placeholder:text-faint focus-visible:outline-2 focus-visible:outline-accent"
        />
        <span className="ml-auto font-mono text-micro uppercase tracking-label text-faint">
          <CountUp value={filtered.length} /> of <CountUp value={entries.length} /> profiles
        </span>
      </div>

      <div className="flex flex-wrap gap-1.5">
        {FILTERS.map((f) => (
          <button
            key={f.key}
            type="button"
            onClick={() => {
              setFilter(f.key)
              reset()
            }}
            aria-pressed={filter === f.key}
            className={cx(
              'rounded-md border px-3 py-1 font-mono text-micro uppercase tracking-label transition-colors duration-150 ease-brand',
              'outline-offset-2 focus-visible:outline-2 focus-visible:outline-accent',
              filter === f.key
                ? 'border-[var(--edge-accent)] bg-[var(--tint-accent)] text-accent'
                : 'border-line bg-panel text-muted hover:border-line-bright hover:text-paper',
            )}
          >
            {f.label}
          </button>
        ))}
      </div>

      {filtered.length === 0 ? (
        <EmptyState title="No profile matches that search">
          Try a shorter term, an alias, or an ATT&amp;CK id like G0001 — the catalog is loaded, this
          filter just excludes everything.
        </EmptyState>
      ) : (
        <>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {shown.map((e) => (
              <ProfileRow key={e.slug} entry={e} />
            ))}
          </div>
          {filtered.length > limit && (
            <button
              type="button"
              onClick={() => setLimit((n) => n + STEP)}
              className="mx-auto rounded-md border border-line bg-panel px-4 py-2 font-mono text-xs text-muted transition-colors duration-150 ease-brand hover:border-line-bright hover:text-paper focus-visible:outline-2 focus-visible:outline-accent"
            >
              Load more — {num(filtered.length - shown.length)} remaining
            </button>
          )}
        </>
      )}
    </div>
  )
}
