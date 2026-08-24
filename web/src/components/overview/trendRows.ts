import type { EpssMover } from '../views/types'
import { humanize, pct } from '../views/format'

/** Product/vendor label for a trends row — humanized, em-dash when absent. */
export function trendLabel(product?: string | null): string {
  return humanize(product) || '—'
}

/**
 * The EPSS shift for a climber row: the formatted from→to endpoints plus a
 * signed percentage-point delta. Returns null when the producer omitted an
 * endpoint (a snapshot can lack one), so the row degrades to the single current
 * value rather than render "— → —". The delta is derived from the endpoints
 * when `delta` is absent, so the two never disagree.
 */
export function epssShift(
  m: Pick<EpssMover, 'from' | 'to' | 'delta'>,
): { from: string; to: string; points: string } | null {
  if (m.from == null || m.to == null) return null
  const pts = Math.round((m.delta ?? m.to - m.from) * 100)
  const sign = pts > 0 ? '+' : pts < 0 ? '−' : '±'
  return { from: pct(m.from), to: pct(m.to), points: `${sign}${Math.abs(pts)} pts` }
}
