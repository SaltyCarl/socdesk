import type { EpssMover, NewKevEntry, TrendsPayload } from '../views/types'
import { day } from '../views/format'
import { EpssMeter, KevBadge } from '../views/Badges'
import { BoardPanel, DeskLink, PanelEmpty, SourceStamp } from './board-ui'
import { epssShift, trendLabel } from './trendRows'

/**
 * "What changed" — the two granular lists behind the stat strip's KEV/feed
 * deltas: CVEs whose EPSS exploitation probability CLIMBED in the trends window,
 * and CVEs CISA JUST added to the Known-Exploited catalog. Both come from the
 * light trends.json the board already fetched, so this paints immediately
 * without the heavy cves.json. Each list degrades to an honest empty — a quiet
 * week or a young snapshot history legitimately has nothing to show.
 *
 * DOCTRINE: a rising EPSS is a real severity signal, so a climber's delta earns
 * amber ink — the same honest exception OverviewStats' KEV counter takes — while
 * KEV membership keeps the reserved red via KevBadge. No fabricated rows.
 */

function MoverRow({ m }: { m: EpssMover }) {
  const shift = epssShift(m)
  return (
    <div className="flex items-center justify-between gap-3 border-b border-line py-3 first:pt-0 last:border-0 last:pb-0">
      <div className="flex min-w-0 flex-col gap-0.5">
        <span className="font-mono text-xs font-semibold text-paper">{m.cve}</span>
        <span className="truncate text-micro text-muted">{trendLabel(m.product)}</span>
      </div>
      <div className="flex shrink-0 items-center gap-2.5">
        {m.kev && <KevBadge />}
        {shift ? (
          <span className="font-mono text-xs tabular-nums text-muted">
            {shift.from} <span aria-hidden="true">→</span>{' '}
            <span className="text-paper">{shift.to}</span>{' '}
            <span className={`font-semibold ${shift.dir < 0 ? 'text-muted' : 'text-verdict-amber'}`}>
              {shift.dir < 0 ? '▼' : '▲'} {shift.points}
            </span>
          </span>
        ) : (
          <EpssMeter epss={m.to ?? m.from} />
        )}
      </div>
    </div>
  )
}

function KevRow({ k }: { k: NewKevEntry }) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-line py-3 first:pt-0 last:border-0 last:pb-0">
      <div className="flex min-w-0 flex-col gap-0.5">
        <span className="font-mono text-xs font-semibold text-paper">{k.cve}</span>
        <span className="truncate text-micro text-muted">{trendLabel(k.product)}</span>
      </div>
      <div className="flex shrink-0 items-center gap-2.5">
        {k.ransomware && <KevBadge ransomware />}
        <EpssMeter epss={k.epss} />
        <span className="w-20 text-right font-mono text-micro text-faint">
          added {day(k.added)}
        </span>
      </div>
    </div>
  )
}

export function WhatChanged({ trends }: { trends: TrendsPayload }) {
  const movers = trends.epss_movers ?? []
  const newKev = trends.new_kev ?? []
  // The mover baseline is whatever snapshot build_trends actually compared
  // against (~7d back, but it falls back to yesterday on a young history), so
  // state the real comparison date rather than a hard-coded "7 days".
  const comparedTo = trends.totals?.compared_to
  const since = comparedTo ? day(comparedTo) : 'the last snapshot'

  return (
    <div className="grid grid-cols-1 items-stretch gap-4 lg:grid-cols-2">
      <BoardPanel
        eyebrow="EPSS exploitation probability ▲"
        title="Climbing"
        aside={<SourceStamp label="FIRST · EPSS" />}
        footer={
          <>
            <span className="max-w-md text-xs text-muted">
              CVEs whose modelled exploitation probability rose materially since{' '}
              {since} — early movement, often ahead of a KEV listing.
            </span>
            <DeskLink tab="vulnerabilities">Vulnerabilities</DeskLink>
          </>
        }
      >
        {movers.length === 0 ? (
          <PanelEmpty>No material EPSS moves since {since}.</PanelEmpty>
        ) : (
          <div className="flex flex-col">
            {movers.map((m) => (
              <MoverRow key={m.cve} m={m} />
            ))}
          </div>
        )}
      </BoardPanel>

      <BoardPanel
        eyebrow="CISA KEV · newly added"
        title="New to Known-Exploited"
        aside={<SourceStamp label="CISA KEV" />}
        footer={
          <>
            <span className="max-w-md text-xs text-muted">
              CVEs CISA added to the Known-Exploited Vulnerabilities catalog in
              the last 7 days — confirmed in-the-wild exploitation.
            </span>
            <DeskLink tab="vulnerabilities">Vulnerabilities</DeskLink>
          </>
        }
      >
        {newKev.length === 0 ? (
          <PanelEmpty>No new KEV additions in the last 7 days.</PanelEmpty>
        ) : (
          <div className="flex flex-col">
            {newKev.map((k) => (
              <KevRow key={k.cve} k={k} />
            ))}
          </div>
        )}
      </BoardPanel>
    </div>
  )
}
