import { cx } from '@socdesk/shared/lib/cx'
import type { TrendsPayload } from '../views/types'
import { day, num } from '../views/format'
import { CountUp } from '../views/CountUp'
import { Sparkline } from './Sparkline'
import { SourceStamp } from './board-ui'

/**
 * Since-yesterday strip — the "what changed overnight" read. Two headline
 * counters (tracked reports · CISA KEV membership) with signed day-over-day
 * deltas, plus a 7-day collection-volume sparkline. Counters count up on reveal.
 *
 * Delta colour = DIRECTION, never a verdict, with one honest exception: a rise
 * in KEV membership means more actively-exploited CVEs, which is genuine
 * severity, so a positive KEV delta earns amber. Feed volume carries no
 * severity, so its delta stays neutral ink.
 */

function Delta({ value, severe = false }: { value?: number; severe?: boolean }) {
  const v = value ?? 0
  if (v === 0) {
    return <span className="font-mono text-xs tabular-nums text-faint">±0</span>
  }
  const up = v > 0
  const tone = severe && up ? 'text-verdict-amber' : 'text-muted'
  return (
    <span className={cx('font-mono text-xs font-semibold tabular-nums', tone)}>
      <span aria-hidden="true">{up ? '▲' : '▼'}</span>
      {up ? '+' : '−'}
      {Math.abs(v)}
    </span>
  )
}

function Counter({
  value,
  delta,
  label,
  severe = false,
}: {
  value: number
  delta?: number
  label: string
  severe?: boolean
}) {
  return (
    <div className="flex items-baseline gap-2.5">
      <span className="font-display text-2xl font-extrabold tabular-nums text-paper">
        <CountUp value={value} />
      </span>
      <div className="flex flex-col gap-0.5">
        <Delta value={delta} severe={severe} />
        <span className="font-mono text-micro uppercase tracking-label text-faint">
          {label}
        </span>
      </div>
    </div>
  )
}

export function SinceYesterday({ trends }: { trends: TrendsPayload }) {
  const t = trends.totals ?? {}
  const volume = trends.volume ?? []
  const comparedTo = t.compared_to ? day(t.compared_to) : null

  return (
    <section className="sd-reveal flex flex-col gap-4 rounded-lg border border-line bg-panel px-5 py-4 lg:flex-row lg:items-center lg:justify-between">
      <div className="flex flex-wrap items-center gap-x-8 gap-y-3">
        <Counter value={t.feed_count ?? 0} delta={t.feed_delta} label="tracked reports" />
        <span aria-hidden="true" className="hidden h-8 w-px bg-line sm:block" />
        <Counter value={t.kev_count ?? 0} delta={t.kev_delta} label="on CISA KEV" severe />
        {comparedTo && (
          <span className="font-mono text-micro uppercase tracking-label text-faint">
            vs {comparedTo}
          </span>
        )}
      </div>

      <div className="flex items-center gap-3">
        <div className="flex flex-col items-end gap-1">
          <span className="font-mono text-micro uppercase tracking-label text-faint">
            7-day volume
          </span>
          <span className="font-mono text-micro tabular-nums text-muted">
            {volume.length ? `${num(volume[volume.length - 1]?.count)} today` : '—'}
          </span>
        </div>
        <Sparkline points={volume} label="7-day collected-report volume" />
        <SourceStamp file="trends.json" />
      </div>
    </section>
  )
}
