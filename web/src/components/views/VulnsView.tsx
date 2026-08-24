import { useDeferredValue, useMemo, useState, type FormEvent } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import type { Cve } from './types'
import { day, humanize, num } from './format'
import { SeverityBadge, KevBadge, EpssMeter } from './Badges'
import { CountUp } from './CountUp'
import { EmptyState } from './states'
import {
  addTerm,
  loadWatchlist,
  matchesWatchlist,
  removeTerm,
  saveWatchlist,
} from './watchlist'

/**
 * Vulnerability triage, risk-sorted. Risk = KEV membership first (actively
 * exploited outranks everything), then EPSS exploitation probability — the
 * pipeline's own ordering philosophy. CVSS is shown but is deliberately NOT
 * the default sort: a 9.8 nobody exploits sits below a 7.5 on the KEV list.
 */

const INIT = 100
const STEP = 100

type SortKey = 'risk' | 'cvss' | 'epss' | 'cve' | 'published'
type SevFilter = 'all' | 'critical' | 'high' | 'medium' | 'low'

interface SortState {
  key: SortKey
  dir: 1 | -1
}

const riskKey = (c: Cve): number => (c.kev ? 2 : 0) + (c.epss ?? 0)

/* ---------------- controls ---------------- */

function SevChip({
  active,
  label,
  onClick,
}: {
  active: boolean
  label: string
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cx(
        'inline-flex items-center rounded-full border px-3 py-1 font-mono text-micro font-semibold uppercase tracking-label transition-colors duration-150 ease-brand',
        'outline-offset-2 focus-visible:outline-2 focus-visible:outline-accent',
        active
          ? 'border-[var(--edge-accent)] bg-[var(--tint-accent)] text-accent'
          : 'border-line bg-panel text-muted hover:border-line-bright hover:text-paper',
      )}
    >
      {label}
    </button>
  )
}

function Th({
  label,
  align = 'left',
  sortKey,
  sort,
  onSort,
  className,
}: {
  label: string
  align?: 'left' | 'right'
  sortKey?: SortKey
  sort: SortState
  onSort: (k: SortKey) => void
  className?: string
}) {
  const active = sortKey != null && sort.key === sortKey
  const arrow = active ? (sort.dir === -1 ? '▼' : '▲') : ''
  return (
    <th
      scope="col"
      aria-sort={active ? (sort.dir === -1 ? 'descending' : 'ascending') : undefined}
      className={cx(
        'sticky top-0 z-10 whitespace-nowrap border-b border-line bg-panel px-3 py-2.5 font-mono text-micro font-semibold uppercase tracking-label',
        align === 'right' ? 'text-right' : 'text-left',
        className,
      )}
    >
      {sortKey ? (
        <button
          type="button"
          onClick={() => onSort(sortKey)}
          className={cx(
            'inline-flex items-center gap-1 outline-offset-2 focus-visible:outline-2 focus-visible:outline-accent',
            active ? 'text-accent' : 'text-faint hover:text-paper',
          )}
        >
          {label}
          {arrow && <span aria-hidden="true">{arrow}</span>}
        </button>
      ) : (
        <span className="text-faint">{label}</span>
      )}
    </th>
  )
}

/* ---------------- view ---------------- */

export function VulnsView({ cves }: { cves: Cve[] }) {
  const [sort, setSort] = useState<SortState>({ key: 'risk', dir: -1 })
  const [sev, setSev] = useState<SevFilter>('all')
  const [kevOnly, setKevOnly] = useState(false)
  const [limit, setLimit] = useState(INIT)
  const [rawQuery, setRawQuery] = useState('')
  const query = useDeferredValue(rawQuery)

  // Watchlist: vendor/product strings the analyst owns. Persisted per-browser
  // only (no PII, never sent) — the filter + row marker read it, and it never
  // re-ranks the table (the pipeline scored the feed before the browser was
  // involved). Loaded once from storage; every change is written back.
  const [watchlist, setWatchlist] = useState<string[]>(() => loadWatchlist())
  const [watchOnly, setWatchOnly] = useState(false)
  const [watchInput, setWatchInput] = useState('')

  const kevCount = useMemo(() => cves.filter((c) => c.kev).length, [cves])
  const epssCount = useMemo(() => cves.filter((c) => c.epss != null).length, [cves])

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase()
    let out = cves.filter((c) => {
      if (kevOnly && !c.kev) return false
      if (watchOnly && !matchesWatchlist(c, watchlist)) return false
      if (sev !== 'all' && (c.cvss_severity ?? '').toLowerCase() !== sev) return false
      if (!q) return true
      const hay = (
        c.cve +
        ' ' +
        (c.title ?? '') +
        ' ' +
        (c.products ?? []).join(' ') +
        ' ' +
        (c.vendors ?? []).join(' ')
      ).toLowerCase()
      return hay.includes(q)
    })

    const keyFns: Record<SortKey, (c: Cve) => number | string> = {
      risk: riskKey,
      cvss: (c) => c.cvss ?? -1,
      epss: (c) => c.epss ?? -1,
      cve: (c) => c.cve,
      published: (c) => c.published_at ?? '',
    }
    const key = keyFns[sort.key]
    out = [...out].sort((a, b) => {
      const x = key(a)
      const y = key(b)
      const cmp =
        typeof x === 'number' && typeof y === 'number'
          ? x - y
          : String(x).localeCompare(String(y))
      return cmp * sort.dir
    })
    return out
  }, [cves, query, kevOnly, watchOnly, watchlist, sev, sort])

  const shown = rows.slice(0, limit)

  const onSort = (k: SortKey) => {
    setSort((prev) => (prev.key === k ? { key: k, dir: prev.dir === -1 ? 1 : -1 } : { key: k, dir: -1 }))
    setLimit(INIT)
  }

  // Persist on actual change only (not via a mount effect that would re-write
  // the just-loaded value and create the storage key on a first-ever visit).
  const addWatch = (e: FormEvent) => {
    e.preventDefault()
    const next = addTerm(watchlist, watchInput)
    if (next !== watchlist) {
      setWatchlist(next)
      saveWatchlist(next)
    }
    setWatchInput('')
    setLimit(INIT)
  }
  const dropWatch = (term: string) => {
    const next = removeTerm(watchlist, term)
    setWatchlist(next)
    saveWatchlist(next)
    if (!next.length) setWatchOnly(false)
  }

  return (
    <div className="flex flex-col gap-5">
      {/* stat strip */}
      <div className="flex flex-wrap gap-x-6 gap-y-1 font-mono text-micro uppercase tracking-label text-faint">
        <span>
          <b className="text-paper">
            <CountUp value={cves.length} />
          </b>{' '}
          tracked
        </span>
        <span>
          <b className="text-verdict-red">
            <CountUp value={kevCount} />
          </b>{' '}
          on CISA KEV
        </span>
        <span>
          <b className="text-paper">
            <CountUp value={epssCount} />
          </b>{' '}
          with EPSS
        </span>
      </div>

      {/* controls */}
      <div className="flex flex-wrap items-center gap-3">
        <input
          type="search"
          value={rawQuery}
          onChange={(e) => {
            setRawQuery(e.target.value)
            setLimit(INIT)
          }}
          placeholder="CVE id, product, vendor…"
          aria-label="Filter vulnerabilities"
          className="h-9 w-full max-w-xs rounded-md border border-line bg-field px-3 font-mono text-base text-paper outline-offset-2 placeholder:text-faint focus-visible:outline-2 focus-visible:outline-accent"
        />
        <div className="flex flex-wrap items-center gap-2">
          {(['all', 'critical', 'high', 'medium', 'low'] as SevFilter[]).map((s) => (
            <SevChip key={s} active={sev === s} label={s} onClick={() => { setSev(s); setLimit(INIT) }} />
          ))}
        </div>
        <div className="ml-auto flex items-center gap-2">
          <button
            type="button"
            onClick={() => { setKevOnly((v) => !v); setLimit(INIT) }}
            aria-pressed={kevOnly}
            className={cx(
              'inline-flex items-center rounded-full border px-3 py-1 font-mono text-micro font-semibold uppercase tracking-label transition-colors duration-150 ease-brand',
              'outline-offset-2 focus-visible:outline-2 focus-visible:outline-accent',
              kevOnly
                ? 'border-[var(--edge-red)] bg-[var(--tint-red)] text-verdict-red'
                : 'border-line bg-panel text-muted hover:border-line-bright hover:text-paper',
            )}
          >
            KEV only
          </button>
          <button
            type="button"
            onClick={() => { setWatchOnly((v) => !v); setLimit(INIT) }}
            aria-pressed={watchOnly}
            disabled={!watchlist.length}
            title={watchlist.length ? undefined : 'Add a vendor or product below first'}
            className={cx(
              'inline-flex items-center rounded-full border px-3 py-1 font-mono text-micro font-semibold uppercase tracking-label transition-colors duration-150 ease-brand',
              'outline-offset-2 focus-visible:outline-2 focus-visible:outline-accent disabled:cursor-not-allowed disabled:opacity-40',
              watchOnly
                ? 'border-[var(--edge-accent)] bg-[var(--tint-accent)] text-accent'
                : 'border-line bg-panel text-muted hover:border-line-bright hover:text-paper',
            )}
          >
            Watchlist only
          </button>
        </div>
      </div>

      {/* watchlist editor — vendor/product strings the analyst owns. Local to
          this browser, never transmitted; it filters and marks, never re-ranks. */}
      <form onSubmit={addWatch} className="flex flex-wrap items-center gap-2">
        <label className="font-mono text-micro uppercase tracking-label text-faint">
          Watchlist
        </label>
        <input
          type="text"
          value={watchInput}
          onChange={(e) => setWatchInput(e.target.value)}
          placeholder="add a vendor or product…"
          aria-label="Add a vendor or product to your watchlist"
          className="h-8 w-48 rounded-md border border-line bg-field px-3 font-mono text-xs text-paper outline-offset-2 placeholder:text-faint focus-visible:outline-2 focus-visible:outline-accent"
        />
        {watchlist.map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => dropWatch(t)}
            aria-label={`Remove ${t} from watchlist`}
            className="inline-flex items-center gap-1.5 rounded-full border border-[var(--edge-accent)] bg-[var(--tint-accent)] px-2.5 py-1 font-mono text-micro font-semibold text-accent outline-offset-2 transition-colors duration-150 ease-brand hover:border-line-bright focus-visible:outline-2 focus-visible:outline-accent"
          >
            {t}
            <span aria-hidden="true" className="text-faint">×</span>
          </button>
        ))}
        {!watchlist.length && (
          <span className="font-mono text-micro text-faint">
            e.g. fortinet, citrix — marks and filters what you own
          </span>
        )}
      </form>

      <div className="flex items-center justify-between">
        <span className="font-mono text-micro uppercase tracking-label text-faint">
          {rows.length === 0 ? 'No matches' : `Showing ${num(shown.length)} of ${num(rows.length)}`}
        </span>
      </div>

      {/* table */}
      {rows.length === 0 ? (
        <EmptyState title="No vulnerabilities match these filters">
          Clear the search, widen the severity, or turn off “KEV only”
          {watchOnly ? ' or “Watchlist only”' : ''} — the catalog is loaded,
          these rows are just filtered out.
        </EmptyState>
      ) : (
        <>
          <div className="overflow-x-auto rounded-lg border border-line">
            <table className="w-full min-w-[760px] border-collapse text-left">
              <thead>
                <tr>
                  <Th label="CVE" sortKey="cve" sort={sort} onSort={onSort} />
                  <Th label="Severity" sort={sort} onSort={onSort} />
                  <Th label="CVSS" align="right" sortKey="cvss" sort={sort} onSort={onSort} />
                  <Th label="EPSS" align="right" sortKey="epss" sort={sort} onSort={onSort} />
                  <Th label="Status" sortKey="risk" sort={sort} onSort={onSort} />
                  <Th label="Affected" sort={sort} onSort={onSort} />
                  <Th label="Published" align="right" sortKey="published" sort={sort} onSort={onSort} />
                </tr>
              </thead>
              <tbody>
                {shown.map((c) => {
                  const affected = [c.products?.[0], c.vendors?.[0]]
                    .filter(Boolean)
                    .map((v) => humanize(v))
                    .join(' / ')
                  const watched = matchesWatchlist(c, watchlist)
                  return (
                    <tr
                      key={c.cve}
                      className="border-b border-line last:border-0 align-top transition-colors duration-150 ease-brand hover:bg-panel-soft"
                    >
                      <td className="max-w-[22rem] px-3 py-2.5">
                        <div className="flex items-center gap-1.5 font-mono text-xs font-semibold text-paper">
                          {watched && (
                            <span
                              role="img"
                              title="On your watchlist"
                              aria-label="On your watchlist"
                              className="inline-block h-1.5 w-1.5 shrink-0 rounded-full bg-accent"
                            />
                          )}
                          {c.cve}
                        </div>
                        {c.title && (
                          <div className="line-clamp-1 text-micro text-muted">
                            {c.title}
                          </div>
                        )}
                      </td>
                      <td className="px-3 py-2.5">
                        <SeverityBadge severity={c.cvss_severity} />
                      </td>
                      <td className="px-3 py-2.5 text-right font-mono text-xs tabular-nums text-paper">
                        {c.cvss ?? '—'}
                      </td>
                      <td className="px-3 py-2.5 text-right">
                        <EpssMeter epss={c.epss} />
                      </td>
                      <td className="px-3 py-2.5">
                        {c.kev ? (
                          <KevBadge ransomware={c.kev_ransomware} />
                        ) : (
                          <span className="font-mono text-micro text-faint">—</span>
                        )}
                      </td>
                      <td className="px-3 py-2.5 text-xs text-muted">
                        {affected || '—'}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2.5 text-right font-mono text-micro text-faint">
                        {day(c.published_at)}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
          {rows.length > limit && (
            <button
              type="button"
              onClick={() => setLimit((n) => n + STEP)}
              className="mx-auto rounded-md border border-line bg-panel px-4 py-2 font-mono text-xs text-muted transition-colors duration-150 ease-brand hover:border-line-bright hover:text-paper focus-visible:outline-2 focus-visible:outline-accent"
            >
              Load more — {num(rows.length - shown.length)} remaining
            </button>
          )}
        </>
      )}
    </div>
  )
}
