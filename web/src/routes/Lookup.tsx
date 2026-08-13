// Lookup.tsx — the escalation-card review surface.
//
// Renders the stubbed VerdictData for each entity type in BOTH registers: the
// client escalation card + its deterministic copy-card PNG (left) and the dense
// analyst console (right). This is the visual-QA route the lead screenshots at
// integration — the T1/T2 lookup loop lands here once the omnibox is wired in.

import { useState, type ReactNode } from 'react'
import { cx } from '../lib/cx'
import { MicroLabel } from '../components/ui'
import {
  AnalystVerdict,
  CardCanvasPreview,
  EscalationCard,
  STUBS,
} from '../components/verdict'

function Label({ children }: { children: ReactNode }) {
  return (
    <MicroLabel tone="faint" className="mb-3">
      {children}
    </MicroLabel>
  )
}

export function Lookup() {
  const [sel, setSel] = useState(STUBS[0].id)
  const stub = STUBS.find((s) => s.id === sel) ?? STUBS[0]

  return (
    <div className="flex flex-col gap-8">
      <header className="border-b border-line pb-8">
        <MicroLabel tone="accent" tick>
          Escalation system
        </MicroLabel>
        <h1 className="mt-3 font-display text-2xl font-extrabold tracking-display text-paper">
          One card, a type-appropriate hero
        </h1>
        <p className="mt-3 max-w-2xl text-md text-muted">
          An honest, attributed, source-class-aware escalation artifact. The tally
          leads as coverage (never a threat score); every source is attributed;
          geo is context, never a verdict; and hashes and CVEs are banner-led — the
          identity or exploitation fact leads, not a cross-source vote.
        </p>
      </header>

      <div className="flex flex-wrap gap-2" role="tablist" aria-label="Indicator type">
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

      <div className="grid gap-8 lg:grid-cols-2">
        <div className="flex flex-col gap-8">
          <div>
            <Label>Client register — escalation card</Label>
            <EscalationCard data={stub.data} />
          </div>
          <div>
            <Label>Copy card — deterministic PNG on the clipboard</Label>
            <div className="rounded-lg border border-dashed border-line-bright bg-ink p-5">
              <CardCanvasPreview data={stub.data} />
            </div>
          </div>
        </div>

        <div>
          <Label>Analyst register — console</Label>
          <AnalystVerdict data={stub.data} />
        </div>
      </div>
    </div>
  )
}
