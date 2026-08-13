import type { ReactNode } from 'react'
import { cx } from '../lib/cx'

/**
 * MicroLabel — the shared micro-label token. Mono, ≥11px floor, wide
 * tracking, uppercase. The eyebrow / field-label / stat-key voice used
 * everywhere a small mono caption is needed.
 *
 *   tone="muted"  (default) — recessive caption
 *   tone="accent"           — periwinkle eyebrow (product voice)
 *   tone="faint"            — the quietest labels
 *   tick                    — a 14px accent lead tick (kicker style)
 */
export type MicroLabelTone = 'muted' | 'accent' | 'faint'

const TONE: Record<MicroLabelTone, string> = {
  muted: 'text-muted',
  accent: 'text-accent',
  faint: 'text-faint',
}

export function MicroLabel({
  children,
  tone = 'muted',
  tick = false,
  as: Tag = 'span',
  className,
}: {
  children: ReactNode
  tone?: MicroLabelTone
  tick?: boolean
  as?: 'span' | 'p' | 'div'
  className?: string
}) {
  return (
    <Tag
      className={cx(
        'inline-flex items-center gap-2 font-mono text-micro font-semibold uppercase tracking-label',
        TONE[tone],
        className,
      )}
    >
      {tick && (
        <span
          aria-hidden="true"
          className="inline-block h-px w-3.5 shrink-0 bg-accent"
        />
      )}
      {children}
    </Tag>
  )
}
