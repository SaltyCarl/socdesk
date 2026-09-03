import { cx } from '@socdesk/shared/lib/cx'
import { techniqueUrl } from './relations'

/** A single ATT&CK technique chip, deep-linking to attack.mitre.org. `distinctive`
 *  gives the accent-tinted treatment for a low-prevalence (≤3 tracked groups)
 *  technique — used by the tactic matrix, the no-catalog fallback, AND the
 *  SynthesisBand distinctive lead (shared so the tint never drifts). */
export function TechniqueChip({
  id,
  name,
  hint,
  distinctive = false,
}: {
  id: string
  name?: string
  /** Extra title text (e.g. the snapshot-prevalence derivation). */
  hint?: string
  /** Accent-tinted treatment for a low-prevalence technique. */
  distinctive?: boolean
}) {
  const base = name ? `${id} · ${name}` : id
  return (
    <a
      href={techniqueUrl(id)}
      target="_blank"
      rel="noopener noreferrer"
      title={hint ? `${base} — ${hint}` : base}
      className={cx(
        'inline-flex items-center gap-1.5 rounded-sm border px-1.5 py-0.5 transition-colors duration-150 ease-brand',
        distinctive
          ? 'border-[var(--edge-accent)] bg-[var(--tint-accent)] hover:border-line-bright'
          : 'border-line bg-panel-soft hover:border-line-bright',
      )}
    >
      <span className="font-mono text-micro font-semibold text-accent-dim">{id}</span>
      {name && <span className="text-micro text-muted">{name}</span>}
    </a>
  )
}
