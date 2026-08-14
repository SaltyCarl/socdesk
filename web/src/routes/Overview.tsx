import { lazy, Suspense, useRef, useState } from 'react'
import type { FormEvent, KeyboardEvent, MouseEvent, ReactNode } from 'react'
import { MicroLabel } from '../components/ui'
import { SituationalBoard } from '../components/overview'
import type { GlobeApi } from '../components/hero/useGlobe3'
import { runEnrich, type EnrichStatus } from '../components/hero/enrichFly'
import { lookupHash, submitLookup } from '../components/palette/commands'
// The hero-shell classes (.sdh-hero / .sdh-atmos / .sdh-enter*) must be present
// on FIRST paint — this route is synchronous, so importing the co-located CSS
// here puts them in the main bundle even though the globe canvas itself streams
// in later from the lazy chunk below.
import '../components/hero/globe.css'

/**
 * Overview (`/`) — the crown-jewel landing. The copy column, live omnibox, and
 * the situational board render INSTANTLY from the main bundle; only the three.js
 * globe VISUAL is code-split into its own chunk and mounted behind
 * `Suspense fallback={null}`, so `three` never blocks first paint.
 *
 * The omnibox is REAL: an indicator is enriched through the site's own
 * /api/enrich Pages Function (runEnrich), and the live result is dispatched on
 * `socdesk:enrich-result` — the lazily-mounted globe listens for that event and
 * lands the result on its real coordinates with the real sourced verdict card.
 * A shared `apiRef` lets an emptied input fly the globe home. There is no mock
 * fly-to table; failure and no-geolocation states are stated honestly inline.
 */

const GlobeStage3 = lazy(() =>
  import('../components/hero/GlobeStage3').then((m) => ({ default: m.GlobeStage3 })),
)

const DEMO_INDICATORS = ['185.220.101.34', '1.1.1.1', '8.8.8.8']

const CHIP_CLS =
  'rounded-md border border-line bg-panel px-2.5 py-1 font-mono text-xs text-muted transition-colors duration-150 ease-brand hover:border-line-bright hover:text-paper focus-visible:outline-2 focus-visible:outline-accent'

/** An honest one-liner for each non-landed enrich outcome (a landing needs no
 *  words — the globe + card say it). Returns null when there's nothing to say. */
function statusLine(s: EnrichStatus): string | null {
  switch (s.state) {
    case 'checking':
      return `Checking ${s.indicator}…`
    case 'unsupported':
      return `${s.indicator} isn't an enrichable indicator (IP, domain, URL, or hash).`
    case 'no-geo':
      return `Enriched ${s.indicator} — no geolocation to plot (context only).`
    case 'error':
      return `Lookup unavailable: ${s.reason}.`
    default:
      return null
  }
}

export interface OverviewProps {
  kicker?: string
  title?: ReactNode
  subtitle?: ReactNode
}

export function Overview({
  kicker = 'Live threat surface',
  title,
  subtitle,
}: OverviewProps) {
  const apiRef = useRef<GlobeApi | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const abortRef = useRef<AbortController | null>(null)
  const [status, setStatus] = useState<EnrichStatus>({ state: 'idle' })

  const enrich = (value: string) => {
    const v = value.trim()
    if (!v) return
    abortRef.current?.abort()
    const ctrl = new AbortController()
    abortRef.current = ctrl
    setStatus({ state: 'checking', indicator: v })
    void runEnrich(v, ctrl.signal).then((s) => {
      if (!ctrl.signal.aborted) setStatus(s)
    })
  }

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault()
      enrich(e.currentTarget.value)
    }
  }
  const onInput = (e: FormEvent<HTMLInputElement>) => {
    if (e.currentTarget.value.trim() === '') {
      abortRef.current?.abort()
      setStatus({ state: 'idle' })
      apiRef.current?.flyBack()
    }
  }
  const flyDemo = (v: string) => {
    enrich(v)
    if (inputRef.current) inputRef.current.value = v
  }

  // The globe landing is the ambient bonus; the full escalation card at /lookup
  // is the primary payoff. Once an indicator is in play, offer a direct path to
  // it (SPA-navigated, but a real href so it right-clicks / opens in a new tab).
  // /lookup runs its OWN fetch on arrival — no cross-surface result is smuggled.
  const openFullCard = (e: MouseEvent<HTMLAnchorElement>, q: string) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return
    e.preventDefault()
    submitLookup(q)
  }

  const line = statusLine(status)
  const indicator = 'indicator' in status ? status.indicator : null

  return (
    <div className="flex flex-col">
      {/* -------- globe hero -------- */}
      <section className="sdh-hero relative py-16">
        <div className="sdh-atmos" aria-hidden="true" />

        {/* copy column — renders immediately, above the globe */}
        <div className="relative z-[2] flex max-w-xl flex-col items-start gap-5">
          <MicroLabel tone="accent" tick className="sdh-enter sdh-enter-1">
            {kicker}
          </MicroLabel>
          <h1 className="sdh-enter sdh-enter-2 font-display text-display font-extrabold tracking-display text-paper">
            {title ?? (
              <>
                IOC in. <span className="text-accent">OSINT</span> out.
              </>
            )}
          </h1>
          <p className="sdh-enter sdh-enter-3 max-w-lg text-md text-muted">
            {subtitle ??
              'Reported malicious IPs and ransomware victim-countries, plotted from real sources. Enrich any indicator to land it live — verdict-toned and attributed. Drag to spin, scroll to zoom.'}
          </p>

          <div className="sdh-enter sdh-enter-4 mt-1 flex w-full max-w-md flex-col gap-3">
            <input
              ref={inputRef}
              type="text"
              inputMode="text"
              autoComplete="off"
              spellCheck={false}
              aria-label="Look up an indicator and land it on the globe"
              placeholder="Enrich an IP / domain / hash — 185.220.101.34"
              onKeyDown={onKeyDown}
              onInput={onInput}
              className="w-full rounded-md border border-line bg-field px-3 py-2 font-mono text-base text-paper outline-offset-2 placeholder:text-faint focus-visible:outline-2 focus-visible:outline-accent"
            />
            {line && (
              <p className="font-mono text-xs text-muted" role="status">
                {line}
              </p>
            )}
            {indicator && (
              <a
                href={`/lookup${lookupHash(indicator)}`}
                onClick={(e) => openFullCard(e, indicator)}
                className="inline-flex w-fit items-center gap-1 font-mono text-xs font-semibold text-accent underline-offset-2 outline-offset-2 hover:underline focus-visible:outline-2 focus-visible:outline-accent"
              >
                Open full escalation card <span aria-hidden="true">→</span>
              </a>
            )}
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-micro uppercase tracking-[0.14em] text-faint">
                Try
              </span>
              {DEMO_INDICATORS.map((v) => (
                <button key={v} type="button" onClick={() => flyDemo(v)} className={CHIP_CLS}>
                  {v}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* globe visual — lazy (three.js chunk); nothing to render while it loads */}
        <Suspense fallback={null}>
          <GlobeStage3 apiRef={apiRef} />
        </Suspense>
      </section>

      {/* -------- situational board -------- */}
      <SituationalBoard />
    </div>
  )
}
