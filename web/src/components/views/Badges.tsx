import type { ReactNode } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import { pct, severityKey, type SeverityKey } from './format'

/**
 * View-local badges for the numeric/catalog facts the shared Chip primitive
 * doesn't cover (CVE severity, KEV membership, a priority-score pill). They
 * reuse the exact token tints Chip uses, so the palette stays one system, and
 * they keep the verdict-colour rule: red/amber only where the number MEANS a
 * severity; neutral ink otherwise; green is never borrowed for these.
 */

const BADGE_BASE =
  'inline-flex items-center gap-1.5 rounded-sm border px-2 py-0.5 ' +
  'font-mono text-micro font-semibold uppercase leading-none tracking-label ' +
  'whitespace-nowrap'

/* ---------------- CVE severity ---------------- */

const SEV_SKIN: Record<SeverityKey, string> = {
  critical: 'border-[var(--edge-red)] bg-[var(--tint-red)] text-verdict-red',
  high: 'border-[var(--edge-gold)] bg-[var(--tint-gold)] text-verdict-amber',
  medium: 'border-line-bright bg-panel-soft text-paper',
  low: 'border-line bg-panel-soft text-muted',
  unknown: 'border-line bg-panel text-faint',
}

export function SeverityBadge({ severity }: { severity?: string | null }) {
  const key = severityKey(severity)
  return (
    <span className={cx(BADGE_BASE, SEV_SKIN[key])}>
      {key === 'unknown' ? '—' : key}
    </span>
  )
}

/* ---------------- KEV membership ----------------
 * Actively-exploited is the strongest severity fact a CVE can carry, so it
 * earns the reserved red — meaning, not decoration. `·R` marks a KEV entry
 * CISA links to ransomware campaigns. */

export function KevBadge({ ransomware = false }: { ransomware?: boolean }) {
  return (
    <span
      className={cx(
        BADGE_BASE,
        'border-[var(--edge-red)] bg-[var(--tint-red)] text-verdict-red',
      )}
      title={
        ransomware
          ? 'CISA Known Exploited Vulnerability — linked to ransomware'
          : 'CISA Known Exploited Vulnerability'
      }
    >
      KEV{ransomware ? ' ·R' : ''}
    </span>
  )
}

/* ---------------- priority score ----------------
 * The pipeline's 0–100 relevance rank as a tinted pill. Tone tracks urgency
 * (red ≥80, amber ≥60), then neutral — green withheld (a low rank is lower in
 * the queue, not "safe"). */

function scoreSkin(score: number | null | undefined): string {
  if (score == null) return 'border-line bg-panel text-faint'
  if (score >= 80) return 'border-[var(--edge-red)] bg-[var(--tint-red)] text-verdict-red'
  if (score >= 60)
    return 'border-[var(--edge-gold)] bg-[var(--tint-gold)] text-verdict-amber'
  if (score >= 40) return 'border-line-bright bg-panel-soft text-paper'
  return 'border-line bg-panel-soft text-muted'
}

export function ScoreBadge({ score }: { score?: number | null }) {
  return (
    <span
      className={cx(
        'inline-flex min-w-9 items-center justify-center rounded-md border px-2 py-1',
        'font-mono text-base font-semibold leading-none tabular-nums',
        scoreSkin(score),
      )}
      title="Pipeline relevance score (0–100)"
    >
      {score == null ? '—' : score}
    </span>
  )
}

/* ---------------- EPSS meter ----------------
 * EPSS exploitation probability as a value + a fixed-ladder bar. The width
 * classes are LITERAL (Tailwind needs them present verbatim to compile — a
 * dynamic `w-[${n}%]` would never generate). Fill tone tracks exploitation
 * likelihood: red ≥0.5, amber ≥0.1, else neutral line ink (not a verdict). */

const EPSS_W = [
  'w-[0%]', 'w-[5%]', 'w-[10%]', 'w-[15%]', 'w-[20%]', 'w-[25%]', 'w-[30%]',
  'w-[35%]', 'w-[40%]', 'w-[45%]', 'w-[50%]', 'w-[55%]', 'w-[60%]', 'w-[65%]',
  'w-[70%]', 'w-[75%]', 'w-[80%]', 'w-[85%]', 'w-[90%]', 'w-[95%]', 'w-[100%]',
] as const

export function EpssMeter({ epss }: { epss?: number | null }) {
  if (epss == null) {
    return <span className="font-mono text-xs text-faint">—</span>
  }
  const clamped = Math.min(1, Math.max(0, epss))
  const w = EPSS_W[Math.round(clamped * 20)]
  const fill =
    epss >= 0.5 ? 'bg-verdict-red' : epss >= 0.1 ? 'bg-verdict-amber' : 'bg-line-strong'
  return (
    <div className="flex items-center justify-end gap-2">
      <span className="font-mono text-xs tabular-nums text-paper">{pct(epss)}</span>
      <span className="h-1.5 w-16 overflow-hidden rounded-full bg-panel-soft">
        <span className={cx('block h-full rounded-full', fill, w)} />
      </span>
    </div>
  )
}

/* ---------------- generic mono tag ----------------
 * A neutral, non-verdict label for source names, categories, ATT&CK ids —
 * facts that carry no severity, so they stay in room ink. */

export function MonoTag({
  children,
  tone = 'muted',
  className,
}: {
  children: ReactNode
  tone?: 'muted' | 'accent' | 'faint'
  className?: string
}) {
  const ink =
    tone === 'accent'
      ? 'border-[var(--edge-accent)] bg-[var(--tint-accent)] text-accent'
      : tone === 'faint'
        ? 'border-line bg-panel text-faint'
        : 'border-line bg-panel-soft text-muted'
  return <span className={cx(BADGE_BASE, ink, className)}>{children}</span>
}
