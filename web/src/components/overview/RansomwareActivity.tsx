import { useEffect, useRef, useState } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import { prefersReducedMotion } from '@socdesk/shared/lib/motion'
import { num } from '../views/format'
import { CountUp } from '../views/CountUp'
import { ActorLink, BoardPanel, DeskLink, SourceStamp, PanelEmpty } from './board-ui'
import { barWidthClass } from './widths'
import type { RansomSummary } from './aggregations'

/**
 * Ransomware activity — the flagship answer to "who is actively hitting people
 * right now". Leak-site groups ranked by the victim claims they posted this
 * window, drawn straight from ransomware.live posts. Full-width bar leaderboard
 * so magnitude reads at a glance (one group routinely dwarfs the rest).
 *
 * Accent-framed for weight, and crowned with the window's total claims as the
 * ONE hero-scale number (neutral ink — a volume fact, never a verdict). Bars are
 * periwinkle (a volume measure, not a verdict); the count is the fact. Honest
 * empty when the leak sites are quiet.
 */

const TOP_N = 8

function GroupRow({
  ordinal,
  name,
  claims,
  max,
}: {
  ordinal: number
  name: string
  claims: number
  max: number
}) {
  // The bar sweeps from 0 → its bucket on first paint (compositor-cheap width
  // transition). Reduced motion mounts at the final width — no sweep. Widths are
  // LITERAL ladder classes (barWidthClass), never an inline style (CSP).
  const target = barWidthClass(claims / max)
  const [w, setW] = useState(() => (prefersReducedMotion() ? target : 'w-[0%]'))
  useEffect(() => {
    if (prefersReducedMotion()) return
    const id = requestAnimationFrame(() => setW(target))
    return () => cancelAnimationFrame(id)
  }, [target])

  return (
    <div className="group flex items-center gap-4 py-3 transition-colors duration-150 ease-brand hover:bg-panel-soft">
      <span className="w-5 shrink-0 font-mono text-micro font-semibold tabular-nums tracking-label text-accent">
        {String(ordinal).padStart(2, '0')}
      </span>
      <ActorLink
        name={name}
        className="w-40 shrink-0 truncate font-mono text-base font-semibold text-paper hover:text-accent hover:underline"
      >
        {name}
      </ActorLink>
      <span className="h-2 flex-1 overflow-hidden rounded-full bg-panel-soft">
        <span
          className={cx(
            'block h-full rounded-full bg-accent transition-[width] duration-[var(--duration-slow)] ease-brand group-hover:bg-accent-dim',
            w,
          )}
        />
      </span>
      <span className="w-16 shrink-0 text-right">
        <span className="font-display text-md font-extrabold tabular-nums text-paper">
          {claims}
        </span>
      </span>
    </div>
  )
}

export function RansomwareActivity({ summary }: { summary: RansomSummary }) {
  const rows = summary.groups.slice(0, TOP_N)
  const max = rows[0]?.claims ?? 1

  // Pointer spotlight — flagship ONLY. A soft accent glow that tracks the cursor,
  // written as CSSOM custom-property updates on a ref (never a JSX style prop, so
  // the strict style-src 'self' holds); the gradient itself is a STATIC compiled
  // utility that reads those vars. Gated on fine pointers + reduced-motion.
  const spotRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const el = spotRef.current
    if (!el) return
    if (prefersReducedMotion() || !window.matchMedia('(pointer:fine)').matches) return
    const onMove = (e: PointerEvent) => {
      const r = el.getBoundingClientRect()
      el.style.setProperty('--mx', `${e.clientX - r.left}px`)
      el.style.setProperty('--my', `${e.clientY - r.top}px`)
    }
    el.addEventListener('pointermove', onMove)
    return () => el.removeEventListener('pointermove', onMove)
  }, [])

  return (
    <div ref={spotRef} className="relative">
      <BoardPanel
        accent
        eyebrow="Leak-site victim claims"
        title="Ransomware activity"
        aside={<SourceStamp label="ransomware.live" />}
        footer={
          <>
            <span className="font-mono text-micro uppercase tracking-label text-faint">
              {num(summary.totalClaims)} claims · {num(summary.groupCount)} groups
            </span>
            <DeskLink tab="feed">Feed</DeskLink>
          </>
        }
      >
        {/* the ONE hero number: total claims in the window (neutral ink) */}
        <div className="flex flex-col gap-1">
          <CountUp
            value={summary.totalClaims}
            className="font-display text-2xl font-extrabold text-paper md:text-display"
          />
          <span className="font-mono text-micro uppercase tracking-label text-faint">
            claims this window · {num(summary.groupCount)} active groups
          </span>
        </div>

        {rows.length === 0 ? (
          <div className="mt-4">
            <PanelEmpty>No leak-site victim claims were posted in this window.</PanelEmpty>
          </div>
        ) : (
          <div className="mt-4 flex flex-col divide-y divide-line">
            {rows.map((g, i) => (
              <GroupRow key={g.name} ordinal={i + 1} name={g.name} claims={g.claims} max={max} />
            ))}
          </div>
        )}
      </BoardPanel>

      {/* pointer spotlight overlay — static gradient, dynamic position vars */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 rounded-lg bg-[radial-gradient(circle_220px_at_var(--mx)_var(--my),color-mix(in_srgb,var(--accent)_10%,transparent),transparent_70%)]"
      />
    </div>
  )
}
