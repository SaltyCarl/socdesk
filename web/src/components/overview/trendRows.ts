import type { EpssMover } from '../views/types'
import { humanize } from '../views/format'

/** Product/vendor label for a trends row — humanized, em-dash when absent. */
export function trendLabel(product?: string | null): string {
  return humanize(product) || '—'
}

/**
 * The EPSS shift for a climber row: the formatted from→to endpoints, a signed
 * percentage-point delta, and a direction. Returns null when the producer
 * omitted an endpoint (a snapshot can lack one), so the row degrades to the
 * single current value rather than render "— → —".
 *
 * The delta is computed from the ROUNDED endpoints (not the raw floats), so the
 * three displayed numbers are always self-consistent — 14% → 21% always reads
 * "+7 pts", never "+6" from an independently-rounded raw delta. `dir` lets the
 * row pick the glyph/tint (a rise is the expected case; the producer only emits
 * rises today, but a fall must not render as an amber ▲).
 */
export function epssShift(
  m: Pick<EpssMover, 'from' | 'to'>,
): { from: string; to: string; points: string; dir: 1 | -1 | 0 } | null {
  if (m.from == null || m.to == null) return null
  const fromPct = Math.round(m.from * 100)
  const toPct = Math.round(m.to * 100)
  const pts = toPct - fromPct
  const sign = pts > 0 ? '+' : pts < 0 ? '−' : '±'
  return {
    from: `${fromPct}%`,
    to: `${toPct}%`,
    points: `${sign}${Math.abs(pts)} pts`,
    dir: pts > 0 ? 1 : pts < 0 ? -1 : 0,
  }
}
