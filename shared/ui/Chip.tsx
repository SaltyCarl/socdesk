import type { ReactNode } from 'react'
import { cx } from '../lib/cx'

/**
 * Chip / Badge — one primitive, three families of variant:
 *
 * VERDICT-SEVERITY (meaning-bearing colour + a leading dot — a source's
 * CONFIRMED read on a specific indicator):
 *   malicious   · red      · confirmed adverse
 *   suspicious  · amber    · flagged, unconfirmed
 *   grayware    · amber    · PUA/grayware — "flagged, not malware" (a
 *                            deliberately distinct state, not red)
 *   benign      · green    · a source looked and found nothing adverse
 *   unknown     · grey     · no data — absence is NOT safety, so NEVER green
 *
 * SIGNAL-SPECIFICITY (reserved-colour EVOLUTION, owner-approved 2026-08-19:
 * the PowerShell analyzer's technique-signal chips graduate colour by risk
 * tier instead of staying uniformly periwinkle. Same red/amber hues as
 * VERDICT-SEVERITY above, but the claim is different — a signal's tier, not
 * a source's confirmed verdict. Anti-cry-wolf is load-bearing here: only
 * near-dispositive (a technique with NO legitimate use) earns red; strong
 * (corroborated, still has benign twins) earns amber; weak stays the plain
 * periwinkle `technique` treatment below — never escalated):
 *   signal-near-dispositive · red    · no legitimate use
 *   signal-strong           · amber · corroborated, still has benign twins
 *
 * CATALOG / SOURCE-CLASS (facts about a source — periwinkle/neutral only,
 * NEVER a verdict hue; ranked by the confidence ladder):
 *   catalog     · accent   · catalog/identity (highest authority)
 *   behavioral  · paper    · behavioral/observed
 *   reputation  · muted    · reputation-score
 *   list        · faint    · list-membership (weakest)
 *
 * GENERAL: neutral (default) · accent (product tag).
 */
export type ChipVariant =
  | 'neutral'
  | 'accent'
  | 'technique'
  | 'signal-near-dispositive'
  | 'signal-strong'
  | 'catalog'
  | 'behavioral'
  | 'reputation'
  | 'list'
  | 'malicious'
  | 'suspicious'
  | 'grayware'
  | 'benign'
  | 'unknown'

const VARIANT: Record<ChipVariant, string> = {
  neutral: 'border-line bg-panel-soft text-muted',
  accent: 'border-[var(--edge-accent)] bg-[var(--tint-accent)] text-accent',
  // technique/LOLBin signal, weak tier — periwinkle, never a verdict hue
  technique: 'border-[var(--edge-accent)] bg-[var(--tint-accent)] text-accent',
  // technique-signal specificity tiers — see SIGNAL-SPECIFICITY above
  'signal-near-dispositive': 'border-[var(--edge-red)] bg-[var(--tint-red)] text-verdict-red',
  'signal-strong': 'border-[var(--edge-gold)] bg-[var(--tint-gold)] text-verdict-amber',
  // source-class — hierarchy by ink weight, no verdict hue
  catalog: 'border-[var(--edge-accent)] bg-[var(--tint-accent)] text-accent',
  behavioral: 'border-line-bright bg-panel-soft text-paper',
  reputation: 'border-line bg-panel-soft text-muted',
  list: 'border-line bg-panel text-faint',
  // verdict-severity — meaning-bearing
  malicious: 'border-[var(--edge-red)] bg-[var(--tint-red)] text-verdict-red',
  suspicious: 'border-[var(--edge-gold)] bg-[var(--tint-gold)] text-verdict-amber',
  grayware: 'border-[var(--edge-gold)] bg-[var(--tint-gold)] text-verdict-amber',
  benign: 'border-[var(--edge-green)] bg-[var(--tint-green)] text-verdict-green',
  unknown: 'border-line bg-panel-soft text-muted',
}

const VERDICT_DOT: Partial<Record<ChipVariant, string>> = {
  malicious: 'bg-verdict-red',
  suspicious: 'bg-verdict-amber',
  grayware: 'bg-verdict-amber',
  benign: 'bg-verdict-green',
  unknown: 'bg-faint',
}

const DEFAULT_LABEL: Record<ChipVariant, string> = {
  neutral: 'label',
  accent: 'tag',
  technique: 'technique',
  'signal-near-dispositive': 'near-dispositive',
  'signal-strong': 'strong',
  catalog: 'catalog / identity',
  behavioral: 'behavioral / observed',
  reputation: 'reputation-score',
  list: 'list-membership',
  malicious: 'malicious',
  suspicious: 'suspicious',
  grayware: 'grayware',
  benign: 'benign',
  unknown: 'unknown',
}

export function Chip({
  variant = 'neutral',
  pill = false,
  children,
  className,
}: {
  variant?: ChipVariant
  pill?: boolean
  children?: ReactNode
  className?: string
}) {
  const dot = VERDICT_DOT[variant]
  return (
    <span
      className={cx(
        'inline-flex items-center gap-1.5 border px-2 py-0.5 font-mono text-micro font-semibold uppercase leading-none tracking-label whitespace-nowrap',
        pill ? 'rounded-full' : 'rounded-sm',
        VARIANT[variant],
        className,
      )}
    >
      {dot && (
        <span
          aria-hidden="true"
          className={cx('inline-block size-1.5 rounded-full', dot)}
        />
      )}
      {children ?? DEFAULT_LABEL[variant]}
    </span>
  )
}
