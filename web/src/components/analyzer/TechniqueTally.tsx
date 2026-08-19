import type { Characterization, Signal } from '@socdesk/shared/analyzer'
import { Chip, MicroLabel } from '@socdesk/shared/ui'

/** The technique-signal tally — the analyzer's headline. Renders a count line
 *  (or the near-dispositive-gated characterization when present), then one
 *  periwinkle chip per signal, each citing the substring that fired it. No
 *  synthesized score; red/amber/green never appear here (reserved-colour law). */
export function TechniqueTally({
  signals,
  characterization,
}: {
  signals: Signal[]
  characterization: Characterization | null
}) {
  if (!signals.length) return null
  const techniqueCount = new Set(signals.flatMap((s) => s.techniqueIds)).size

  return (
    <div className="flex flex-col gap-2">
      <MicroLabel tone="muted">Technique signals</MicroLabel>

      {characterization ? (
        <div className="rounded-md border border-[var(--edge-accent)] bg-[var(--tint-accent)] p-3">
          <span className="font-mono text-micro font-semibold uppercase tracking-label text-accent">
            High-confidence malicious behaviour
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
        {signals.map((s) => (
          <li key={s.id} className="flex flex-wrap items-center gap-2">
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
