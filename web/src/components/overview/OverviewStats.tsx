import { cx } from '@socdesk/shared/lib/cx'
import type { TrendsPayload } from '../views/types'
import { day, num } from '../views/format'
import { CountUp } from '../views/CountUp'
import { Divider } from '../ui'
import { Sparkline } from './Sparkline'
import type { RansomSummary } from './aggregations'

/**
 * The daily-summary stat strip — deliberately MIXED so the top line is not two
 * CVE counters: tracked reports and CISA-KEV membership (with day-over-day
 * deltas) sit beside the window's ransomware victim-claims and active groups,
 * with the 7-day collection-volume sparkline. Numbers count up on reveal.
 *
 * Delta colour = DIRECTION, never a verdict, with one honest exception: a rise
 * in KEV membership means more actively-exploited CVEs (real severity), so a
 * positive KEV delta earns amber. Report volume carries no severity → neutral.
 */

function Delta({ value, severe = false }: { value: number; severe?: boolean }) {
  if (value === 0) {
    return <span className="font-mono text-xs tabular-nums text-faint">±0</span>
  }
  const up = value > 0
  const tone = severe && up ? 'text-verdict-amber' : 'text-muted'
  return (
    <span className={cx('font-mono text-xs font-semibold tabular-nums', tone)}>
      <span aria-hidden="true">{up ? '▲' : '▼'}</span>
      {up ? '+' : '−'}
      {Math.abs(value)}
    </span>
  )
}

function Stat({
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
  // Vertical KPI: number (+ delta) on the baseline row, label on its own full-
  // cell-width line beneath. In a 4-up grid the number-beside-label layout
  // starves the label into 2–3 wrapped lines; stacking gives it the whole cell.
  return (
    <div className="flex flex-1 flex-col gap-1">
      <div className="flex items-baseline gap-2">
        <span className="font-display text-2xl font-extrabold tabular-nums text-paper">
          <CountUp value={value} />
        </span>
        {delta !== undefined && <Delta value={delta} severe={severe} />}
      </div>
      <span className="font-mono text-micro uppercase tracking-label text-faint">
        {label}
      </span>
    </div>
  )
}

export function OverviewStats({
  trends,
  ransom,
}: {
  trends: TrendsPayload
  ransom: RansomSummary
}) {
  const t = trends.totals ?? {}
  const volume = trends.volume ?? []
  const comparedTo = t.compared_to ? day(t.compared_to) : null

  return (
    <section className="sd-reveal flex flex-col gap-5 rounded-lg border border-line bg-panel px-5 py-4 lg:flex-row lg:items-center lg:justify-between lg:gap-8">
      {/* Four mixed counters: a deterministic 2×2 grid on phones (so the fourth
          stat can never orphan — a flex-wrap artifact), collapsing to one even
          flex row on sm+ with hairline vertical rules BETWEEN the cells. The
          dividers are display:none on the phone grid, so they take no cell. */}
      <div className="grid grid-cols-2 gap-x-8 gap-y-4 sm:flex sm:items-stretch sm:gap-6 lg:flex-1">
        <Stat value={t.feed_count ?? 0} delta={t.feed_delta} label="tracked reports" />
        <Divider orientation="vertical" className="hidden sm:block" />
        <Stat value={t.kev_count ?? 0} delta={t.kev_delta} label="on CISA KEV" severe />
        <Divider orientation="vertical" className="hidden sm:block" />
        <Stat value={ransom.totalClaims} label="ransomware claims" />
        <Divider orientation="vertical" className="hidden sm:block" />
        <Stat value={ransom.groupCount} label="active groups" />
      </div>

      <div className="flex items-center gap-3 border-t border-line pt-4 lg:border-l lg:border-t-0 lg:pl-8 lg:pt-0">
        <div className="flex flex-col items-end gap-1">
          <span className="font-mono text-micro uppercase tracking-label text-faint">
            reports / day
          </span>
          <span className="whitespace-nowrap font-mono text-micro tabular-nums text-muted">
            {volume.length ? `${num(volume[volume.length - 1]?.count)} today` : '—'}
            {comparedTo ? ` · vs ${comparedTo}` : ''}
          </span>
        </div>
        <Sparkline points={volume} label="7-day collected-report volume" />
      </div>
    </section>
  )
}
