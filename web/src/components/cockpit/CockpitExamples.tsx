// CockpitExamples.tsx — the idle cockpit's reference gallery, folded in from the
// retired /lookup ExamplesGallery. Collapsed behind a native <details>
// disclosure ("See a sample card") so it never out-ranks the live board; opened,
// it shows one family tab per indicator kind and renders that stub as a single
// EscalationCard (NOT the retired triptych — no copy-card PNG, no analyst
// console). Static: CompareIp's fetch is gated behind a user open, so a stub
// card issues no network call.
import { useState } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import { EscalationCard, STUBS, type EffectiveTheme } from '@socdesk/shared/verdict-cards'
import { MicroLabel } from '../ui'

export function CockpitExamples({ theme }: { theme?: EffectiveTheme }) {
  const [sel, setSel] = useState(STUBS[0].id)
  const stub = STUBS.find((s) => s.id === sel) ?? STUBS[0]

  return (
    <details className="mx-auto w-full max-w-md">
      <summary className="cursor-pointer select-none font-mono text-xs text-muted">
        See a sample card
      </summary>
      <div className="mt-4 flex flex-col gap-4">
        <MicroLabel tone="faint" tick>
          One sample card per indicator family
        </MicroLabel>
        <div className="flex flex-wrap gap-2" role="tablist" aria-label="Example indicator type">
          {STUBS.map((s) => {
            const active = s.id === sel
            return (
              <button
                key={s.id}
                type="button"
                role="tab"
                aria-selected={active}
                onClick={() => setSel(s.id)}
                className={cx(
                  'inline-flex items-baseline gap-2 rounded-md border px-3 py-1.5 font-mono text-xs transition-colors duration-150 ease-brand',
                  'outline-offset-2 focus-visible:outline-2 focus-visible:outline-accent',
                  active
                    ? 'border-[var(--edge-accent)] bg-[var(--tint-accent)] text-accent'
                    : 'border-line bg-panel text-muted hover:border-line-bright hover:text-paper',
                )}
              >
                <span className="font-semibold">{s.label}</span>
                <span className="text-micro text-faint">{s.hint}</span>
              </button>
            )
          })}
        </div>
        <EscalationCard data={stub.data} theme={theme} />
      </div>
    </details>
  )
}
