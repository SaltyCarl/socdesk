import type { Characterization, Signal } from '@socdesk/shared/analyzer'
import type { ChipVariant } from '@socdesk/shared/ui'
import { Chip, MicroLabel } from '@socdesk/shared/ui'

/** The technique-signal tally — the analyzer's headline. Renders a count line
 *  (or the gated characterization when present), then one chip per signal,
 *  sorted strongest-first, each citing the substring that fired it. Chip
 *  colour graduates by specificity (reserved-colour EVOLUTION, owner-approved
 *  2026-08-19): near-dispositive reads red, strong reads amber, weak stays
 *  the plain periwinkle `technique` treatment — anti-cry-wolf preserved, only
 *  the tier that has earned it goes loud. The gated characterization callout
 *  remains the analyzer's one *considered* severity read, same red/amber
 *  hues, one level up from a per-signal fact. */

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
// Signal specificity -> chip colour tier (reserved-colour evolution — see Chip.tsx).
const CHIP_VARIANT: Record<Signal['specificity'], ChipVariant> = {
  'near-dispositive': 'signal-near-dispositive',
  strong: 'signal-strong',
  weak: 'technique',
}

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
          {signals.length} signal{signals.length === 1 ? '' : 's'} · {techniqueCount} ATT&amp;CK{' '}
          technique{techniqueCount === 1 ? '' : 's'} — not a synthesized verdict
        </p>
      )}

      <ul className="flex flex-col gap-1.5">
        {sorted.map((s) => (
          <li key={s.id} className="flex flex-wrap items-center gap-2">
            <Chip variant={CHIP_VARIANT[s.specificity]}>{s.label}</Chip>
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
