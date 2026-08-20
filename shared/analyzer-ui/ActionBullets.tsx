import type { ActionBullet } from '@socdesk/shared/analyzer'
import { MicroLabel } from '@socdesk/shared/ui'

// Confidence-tier marker — plain mono glyphs, not a Chip: bullets are
// sentences, not discrete tagged facts (TechniqueTally's Chip stays reserved
// for the signal tally). ● resolved, ~ inferred, ○ opaque (quarantined below).
const TIER_MARK: Record<ActionBullet['confidence'], string> = {
  resolved: '●',
  inferred: '~',
  opaque: '○',
}

// Glyph ink weight — resolved reads at normal (paper) weight, inferred reads
// muted so "we couldn't pin this down" is legible at a glance without a
// second read of the sentence. No verdict hue either way — that stays
// TechniqueTally's characterization callout.
const TIER_MARK_CLASS: Record<ActionBullet['confidence'], string> = {
  resolved: 'text-paper',
  inferred: 'text-muted',
  opaque: 'text-faint',
}

/** Spec §7 / §9 — the "what did it do" breakdown. Renders resolved/inferred
 *  bullets as an execution-ordered list, then opaque (WSH/HTA honesty
 *  notices, malformed-decode notes) in a separate muted "Could not resolve"
 *  block — never promoted into the confident list (D3/D6). No per-bullet
 *  technique IDs — those live on TechniqueTally's signal chips now; this
 *  narrative stays plain-English. Reserved-colour law: plain paper/muted/
 *  faint ink only, no verdict hue — that stays TechniqueTally's
 *  characterization callout. */
export function ActionBullets({ bullets }: { bullets: ActionBullet[] }) {
  if (!bullets.length) return null
  const confident = bullets.filter((b) => b.confidence !== 'opaque').sort((a, b) => a.order - b.order)
  const opaque = bullets.filter((b) => b.confidence === 'opaque').sort((a, b) => a.order - b.order)

  return (
    <div className="flex flex-col gap-2">
      <MicroLabel tone="muted">What it did</MicroLabel>

      {confident.length > 0 && (
        <ol className="flex flex-col gap-1.5">
          {confident.map((b) => (
            <li key={b.order} className="flex flex-wrap items-start gap-2">
              <span className={`font-mono text-micro ${TIER_MARK_CLASS[b.confidence]}`}>{TIER_MARK[b.confidence]}</span>
              <span className="min-w-0 flex-1 text-xs text-paper">{b.text}</span>
            </li>
          ))}
        </ol>
      )}

      {opaque.length > 0 && (
        <div className="rounded-md border border-line bg-panel-soft/40 p-3">
          <MicroLabel tone="faint">Could not resolve</MicroLabel>
          <ul className="mt-1.5 flex flex-col gap-1">
            {opaque.map((b) => (
              <li key={b.order} className="flex items-start gap-2">
                <span className={`font-mono text-micro ${TIER_MARK_CLASS[b.confidence]}`}>{TIER_MARK[b.confidence]}</span>
                <span className="min-w-0 flex-1 text-xs text-muted">{b.text}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
