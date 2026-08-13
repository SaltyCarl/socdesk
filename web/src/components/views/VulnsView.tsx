import { useDeferredValue, useMemo, useState } from 'react'
import { cx } from '../../lib/cx'
import type { Cve } from './types'
import { day, humanize, num, pct } from './format'
import { SeverityBadge, KevBadge } from './Badges'
import { CountUp } from './CountUp'
import { EmptyState } from './states'

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

// EPSS meter: a fixed ladder of literal width classes (Tailwind needs them
// present verbatim to compile — a dynamic `w-[${n}%]` would never generate).
const EPSS_W = [
  'w-[0%]', 'w-[5%]', 'w-[10%]', 'w-[15%]', 'w-[20%]', 'w-[25%]', 'w-[30%]',
  'w-[35%]', 'w-[40%]', 'w-[45%]', 'w-[50%]', 'w-[55%]', 'w-[60%]', 'w-[65%]',
  'w-[70%]', 'w-[75%]', 'w-[80%]', 'w-[85%]', 'w-[90%]', 'w-[95%]', 'w-[100%]',
] as const

function EpssMeter({ epss }: { epss?: number | null }) {
  if (epss == null) {
    return <span className="font-mono text-xs text-faint">—</span>
  }
  const clamped = Math.min(1, Math.max(0, epss))
  const w = EPSS_W[Math.round(clamped * 20)]
  const fill =
    epss >= 0.5 ? 'bg-verdict-red' : epss >= 0.1 ? 'bg-verdict-amber' : 'bg-line-strong'
  return (
    <div className="flex items-center justify-end gap-2">
      <span className="font-mono text-xs tabular-nums text-paper">{pct(epss)}</span>
      <span className="h-1.5 w-16 overflow-hidden rounded-full bg-panel-soft">
        <span className={cx('block h-full rounded-full', fill, w)} />
      </span>
    </div>
  )
}

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

  const kevCount = useMemo(() => cves.filter((c) => c.kev).length, [cves])
  const epssCount = useMemo(() => cves.filter((c) => c.epss != null).length, [cves])

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase()
    let out = cves.filter((c) => {
      if (kevOnly && !c.kev) return false
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
  }, [cves, query, kevOnly, sev, sort])

  const shown = rows.slice(0, limit)

  const onSort = (k: SortKey) => {
    setSort((prev) => (prev.key === k ? { key: k, dir: prev.dir === -1 ? 1 : -1 } : { key: k, dir: -1 }))
    setLimit(INIT)
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
        <button
          type="button"
          onClick={() => { setKevOnly((v) => !v); setLimit(INIT) }}
          aria-pressed={kevOnly}
          className={cx(
            'ml-auto inline-flex items-center rounded-full border px-3 py-1 font-mono text-micro font-semibold uppercase tracking-label transition-colors duration-150 ease-brand',
            'outline-offset-2 focus-visible:outline-2 focus-visible:outline-accent',
            kevOnly
              ? 'border-[var(--edge-red)] bg-[var(--tint-red)] text-verdict-red'
              : 'border-line bg-panel text-muted hover:border-line-bright hover:text-paper',
          )}
        >
          KEV only
        </button>
      </div>

      <div className="flex items-center justify-between">
        <span className="font-mono text-micro uppercase tracking-label text-faint">
          {rows.length === 0 ? 'No matches' : `Showing ${num(shown.length)} of ${num(rows.length)}`}
        </span>
      </div>

      {/* table */}
      {rows.length === 0 ? (
        <EmptyState title="No vulnerabilities match these filters">
          Clear the search, widen the severity, or turn off “KEV only” — the
          catalog is loaded, these rows are just filtered out.
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
                  return (
                    <tr
                      key={c.cve}
                      className="border-b border-line last:border-0 align-top transition-colors duration-150 ease-brand hover:bg-panel-soft"
                    >
                      <td className="max-w-[22rem] px-3 py-2.5">
                        <div className="font-mono text-xs font-semibold text-paper">
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
