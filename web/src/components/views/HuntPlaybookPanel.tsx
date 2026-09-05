import { useState } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import { MicroLabel } from '../ui'
import { ExternalLink } from './ExternalLink'
import { TechniqueChip } from './TechniqueChip'
import { KqlBlock } from './HuntKql'
import { DIALECT_CAVEAT } from './huntCaveat'
import { safeUrl } from './format'
import { injectIoc, playbooksForType } from './playbooks'
import { useStateData } from './useStateData'
import type { Playbook, PlaybooksPayload } from './types'

/**
 * HuntPlaybookPanel — the "Investigate in your SIEM" surface under the enrichment
 * EscalationCard. The analyst picks the alert that triggered the lookup and gets
 * an ordered, IOC-parameterized, Kustainer-validated KQL playbook (general IP
 * pivot first, then scenario hunts). Honest: a starting point, not a detection
 * guarantee; a follow-on {{upn}} the pivot must surface stays visible, never
 * fabricated.
 *
 * The presentational VIEW is split from the data wrapper so it unit-tests without
 * mocking the fetch, and so selection stays async-safe: `selected` is DERIVED
 * (`find ?? matches[0]`), not captured in a useState initializer that would latch
 * `undefined` while the fetch is still loading.
 */
export function HuntPlaybookPanelView({
  playbooks,
  iocType,
  iocValue,
}: {
  playbooks: Playbook[]
  iocType: string
  iocValue: string
}) {
  const [selectedId, setSelectedId] = useState<string>()
  const matches = playbooksForType(playbooks, iocType)
  if (matches.length === 0) {
    // Enrichable but uncovered (domain / hash / url today) — state it honestly
    // rather than rendering nothing, which reads as a bug. The wrapper gates on
    // `ready`, so this never flashes while the fetch is still loading.
    return (
      <section aria-label="Hunt playbooks" className="rounded-lg border border-line bg-panel p-4">
        <p className="text-xs text-muted">
          No SIEM playbook for {iocType} yet — IP indicators supported today.
        </p>
      </section>
    )
  }
  const selected = matches.find((p) => p.id === selectedId) ?? matches[0]
  const provenance = [
    'SOCDesk',
    selected.source.license,
    selected.tested ? `tested ${selected.tested}` : undefined,
  ]
    .filter(Boolean)
    .join(' · ')
  const sourceHref = safeUrl(selected.source.url)

  return (
    <section
      aria-label="Hunt playbooks"
      className="flex flex-col gap-3 rounded-lg border border-line bg-panel p-4"
    >
      <MicroLabel tone="accent" tick>
        Investigate in your SIEM
      </MicroLabel>
      <span className="font-display text-md font-bold tracking-tight text-paper">{selected.title}</span>
      <p className="text-xs leading-relaxed text-muted">
        Playbooks for the alert that sent you here — parameterized with your indicator, syntax-validated
        against the Kusto emulator. A starting point, not a detection guarantee: verify table names and
        your own schema first.
      </p>

      {matches.length > 1 && (
        <div className="flex flex-wrap gap-1.5">
          {matches.map((p) => (
            <button
              key={p.id}
              type="button"
              onClick={() => setSelectedId(p.id)}
              aria-pressed={p.id === selected.id}
              className={cx(
                'rounded-md border px-2.5 py-1 font-mono text-micro uppercase tracking-label transition-colors duration-150 ease-brand',
                'outline-offset-2 focus-visible:outline-2 focus-visible:outline-accent',
                p.id === selected.id
                  ? 'border-[var(--edge-accent)] bg-[var(--tint-accent)] text-accent'
                  : 'border-line bg-panel text-muted hover:border-line-bright hover:text-paper',
              )}
            >
              {p.title}
            </button>
          ))}
        </div>
      )}

      <p className="text-micro text-faint">{DIALECT_CAVEAT.log_analytics}</p>

      <div className="flex flex-col">
        {selected.steps.map((step, i) => {
          const kql = injectIoc(step.kql, step.param, iocType, iocValue)
          const followOn = kql.includes('{{')
          return (
            <div
              key={step.id}
              className="flex flex-col gap-1.5 border-b border-line py-3 first:pt-0 last:border-0 last:pb-0"
            >
              <span className="text-sm font-semibold text-paper">
                {i + 1}. {step.title}
              </span>
              <KqlBlock kql={kql} />
              {followOn && (
                <p className="text-micro text-faint">
                  Replace the remaining <code className="text-accent-dim">{`{{${step.param}}}`}</code>{' '}
                  with a value an earlier step surfaced (e.g. an account the IP pivot returned) — never
                  guessed.
                </p>
              )}
            </div>
          )
        })}
      </div>

      {selected.techniques.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {selected.techniques.map((t) => (
            <TechniqueChip key={t} id={t} />
          ))}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 font-mono text-micro text-faint">
        <span>{provenance}</span>
        {sourceHref && <ExternalLink href={sourceHref}>source</ExternalLink>}
      </div>
    </section>
  )
}

/** Data wrapper — self-fetches the committed playbooks.json and renders the view
 *  (which returns null while loading / when the enriched type has no playbook). */
export function HuntPlaybookPanel({ iocType, iocValue }: { iocType: string; iocValue: string }) {
  const { status, data } = useStateData<PlaybooksPayload>('playbooks')
  // Don't flash the "no playbook" empty state while the fetch is still loading —
  // only render once the payload is ready (or errored, treated as no data).
  if (status !== 'ready') return null
  return <HuntPlaybookPanelView playbooks={data?.playbooks ?? []} iocType={iocType} iocValue={iocValue} />
}
