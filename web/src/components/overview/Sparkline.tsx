import { cx } from '@socdesk/shared/lib/cx'
import type { VolumePoint } from '../views/types'

/**
 * A tiny 7-day volume sparkline. Pure SVG geometry (points/`d` are DATA
 * attributes, never inline style — CSP-clean), periwinkle stroke over a faint
 * accent-tint area. This is decoration in service of a real read: the shape of
 * collection volume over the week, not a fabricated metric.
 *
 * `preserveAspectRatio="none"` lets the fixed 0–100 × 0–32 viewBox stretch to
 * whatever width the strip gives it; `vector-effect: non-scaling-stroke` keeps
 * the line a crisp ~1.5px at any width.
 */

const W = 100
const H = 32
const PAD_Y = 4

function project(points: VolumePoint[]): { line: string; area: string; last: [number, number] } | null {
  const vals = points.map((p) => p.count)
  if (vals.length < 2) return null
  const min = Math.min(...vals)
  const max = Math.max(...vals)
  const span = max - min || 1
  const stepX = W / (vals.length - 1)
  const xy = vals.map((v, i) => {
    const x = i * stepX
    const y = H - PAD_Y - ((v - min) / span) * (H - PAD_Y * 2)
    return [x, y] as [number, number]
  })
  const line = xy.map(([x, y]) => `${x.toFixed(2)},${y.toFixed(2)}`).join(' ')
  const last = xy[xy.length - 1]
  const area =
    `M${xy[0][0].toFixed(2)},${H} ` +
    xy.map(([x, y]) => `L${x.toFixed(2)},${y.toFixed(2)}`).join(' ') +
    ` L${last[0].toFixed(2)},${H} Z`
  return { line, area, last }
}

export function Sparkline({
  points,
  className,
  label,
}: {
  points: VolumePoint[]
  className?: string
  label?: string
}) {
  const proj = project(points ?? [])
  if (!proj) return null
  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      preserveAspectRatio="none"
      className={cx('block h-9 w-32 overflow-visible', className)}
      role="img"
      aria-label={label ?? '7-day collection volume'}
    >
      <path d={proj.area} className="fill-[var(--tint-accent)] stroke-none" />
      <polyline
        points={proj.line}
        className="fill-none stroke-[var(--accent)]"
        strokeWidth={1.5}
        strokeLinejoin="round"
        strokeLinecap="round"
        vectorEffect="non-scaling-stroke"
      />
      <circle cx={proj.last[0]} cy={proj.last[1]} r={2.2} className="fill-[var(--accent)]" />
    </svg>
  )
}
