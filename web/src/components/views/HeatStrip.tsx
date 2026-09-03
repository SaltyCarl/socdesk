import { cx } from '@socdesk/shared/lib/cx'
import { num } from './format'
import { dayLabel, heatClass } from './activity-ui'
import type { DayBucket } from './profiles'

/** 31-day daily claim heat strip — always renders when the group has ≥1 claim in
 *  the window (the retired weekly chart refused to draw under 2 distinct weeks,
 *  which was most claiming groups). Digest tallies distribute by their carried
 *  per-claim dates (profiles.ts::dailyClaimsFor). Static, no SVG lib; cell titles
 *  are hover-only (touch-inert) so the cells are aria-hidden and the container
 *  carries the summary sentence.
 *
 *  `compact` renders the spark form for the synthesis band: shorter cells, no
 *  bottom label row (the band supplies its own cadence caption).
 *
 *  CALLERS MUST GUARD `daily.length > 0` — the strip dereferences `daily[0]`
 *  (activity.daily can be [] even when activity is non-null; see dailyClaimsFor). */
export function HeatStrip({ daily, compact = false }: { daily: DayBucket[]; compact?: boolean }) {
  const max = Math.max(1, ...daily.map((d) => d.count))
  const total = daily.reduce((s, d) => s + d.count, 0)
  const peak = daily.reduce((a, b) => (b.count >= a.count ? b : a), daily[0])
  return (
    <div className="flex flex-col gap-1.5">
      <div
        role="img"
        aria-label={`Daily claim volume, ${dayLabel(daily[0].date)} to ${dayLabel(daily[daily.length - 1].date)}: ${total} claims, peaking at ${peak.count} on ${dayLabel(peak.date)}.`}
        className="grid grid-cols-[repeat(31,minmax(0,1fr))] gap-0.5"
      >
        {daily.map((d) => (
          <div
            key={d.date}
            aria-hidden="true"
            title={`${dayLabel(d.date)} · ${d.count} claim${d.count === 1 ? '' : 's'}`}
            className={cx(compact ? 'h-3 rounded-[2px]' : 'h-6 rounded-[2px]', heatClass(d.count, max))}
          />
        ))}
      </div>
      {!compact && (
        <div className="flex items-center justify-between font-mono text-micro text-faint">
          <span>{dayLabel(daily[0].date)}</span>
          <span className="text-accent">peak {num(peak.count)}</span>
          <span>{dayLabel(daily[daily.length - 1].date)}</span>
        </div>
      )}
    </div>
  )
}
