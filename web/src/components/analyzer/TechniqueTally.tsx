import type { Characterization, Signal } from '@socdesk/shared/analyzer'
import { Chip, MicroLabel } from '@socdesk/shared/ui'

/** The technique-signal tally — the analyzer's headline. Renders a count line
 *  (or the gated characterization when present), then one periwinkle chip per
 *  signal — a tier-tagged fact, sorted strongest-first — each citing the
 *  substring that fired it. Chips stay periwinkle facts; the gated
 *  characterization callout is the analyzer's one *considered* severity read,
 *  and it alone carries a verdict-severity hue: red for high-confidence
 *  malicious, amber for suspicious. */

const CALLOUT: Record<Characterization['level'], { box: string; eyebrowClass: string; label: string }> = {
  'high-confidence-malicious': {
    box: 'border-[var(--edge-red)] bg-[var(--tint-red)]',
    eyebrowClass: 'text-verdict-red',
    label: 'High-confidence malicious behaviour',
  },
  suspicious: {
    box: 'border-[var(--edge-gold)] bg-[var(--tint-gold)]',
    eyebrowClass: 'text-verdict-amber',
    label: 'Suspicious — review',
  },
}

const RANK: Record<Signal['specificity'], number> = { 'near-dispositive': 0, strong: 1, weak: 2 }
const TIER_LABEL: Record<Signal['specificity'], string> = { 'near-dispositive': 'near-disp', strong: 'strong', weak: 'weak' }

export function TechniqueTally({
  signals,
  characterization,
}: {
  signals: Signal[]
  characterization: Characterization | null
}) {
  if (!signals.length) return null
  const techniqueCount = new Set(signals.flatMap((s) => s.techniqueIds)).size
  const sorted = [...signals].sort((a, b) => RANK[a.specificity] - RANK[b.specificity])

  return (
    <div className="flex flex-col gap-2">
      <MicroLabel tone="muted">Technique signals</MicroLabel>

      {characterization ? (
        <div className={`rounded-md border p-3 ${CALLOUT[characterization.level].box}`}>
          <span className={`font-mono text-micro font-semibold uppercase tracking-label ${CALLOUT[characterization.level].eyebrowClass}`}>
            {CALLOUT[characterization.level].label}
          </span>
          <p className="mt-1 text-xs font-semibold text-paper">{characterization.read}</p>
        </div>
      ) : (
        <p className="font-mono text-micro uppercase tracking-label text-faint">
          {signals.length} technique {signals.length === 1 ? 'signal' : 'signals'} across {techniqueCount} ATT&amp;CK{' '}
          {techniqueCount === 1 ? 'technique' : 'techniques'} — not a synthesized verdict
        </p>
      )}

      <ul className="flex flex-col gap-1.5">
        {sorted.map((s) => (
          <li key={s.id} className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-micro text-faint">[{TIER_LABEL[s.specificity]}]</span>
            <Chip variant="technique">{s.label}</Chip>
            <span className="font-mono text-micro text-faint">{s.techniqueIds.join(' · ')}</span>
            {s.trigger && (
              <code className="min-w-0 truncate font-mono text-micro text-muted">{s.trigger}</code>
            )}
          </li>
        ))}
      </ul>
    </div>
  )
}
