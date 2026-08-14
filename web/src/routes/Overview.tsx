import { lazy, Suspense, useRef } from 'react'
import type { FormEvent, KeyboardEvent, ReactNode } from 'react'
import { MicroLabel } from '../components/ui'
import { SituationalBoard } from '../components/overview'
import type { GlobeApi } from '../components/hero/useGlobe3'
// The hero-shell classes (.sdh-hero / .sdh-atmos / .sdh-enter*) must be present
// on FIRST paint — this route is synchronous, so importing the co-located CSS
// here puts them in the main bundle even though the globe canvas itself streams
// in later from the lazy chunk below.
import '../components/hero/globe.css'

/**
 * Overview (`/`) — the crown-jewel landing. The copy column, demo omnibox, and
 * the situational board render INSTANTLY from the main bundle; only the three.js
 * globe VISUAL is code-split into its own chunk and mounted behind
 * `Suspense fallback={null}`, so `three` never blocks first paint. The globe
 * canvas fades in (`.sdh-globe.is-ready`) once its chunk resolves.
 *
 * The lazily-mounted globe shares an imperative `apiRef`, so the omnibox can fly
 * it once the chunk is live; the calls no-op harmlessly before then. `GlobeApi`
 * is a type-only import, so pulling it here adds no `three` weight to this bundle.
 */

const GlobeStage3 = lazy(() =>
  import('../components/hero/GlobeStage3').then((m) => ({ default: m.GlobeStage3 })),
)

const DEMO_INDICATORS = ['185.220.101.34', '45.146.164.110', '8.8.8.8']

const CHIP_CLS =
  'rounded-md border border-line bg-panel px-2.5 py-1 font-mono text-xs text-muted transition-colors duration-150 ease-brand hover:border-line-bright hover:text-paper focus-visible:outline-2 focus-visible:outline-accent'

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

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault()
      apiRef.current?.flyToIndicator(e.currentTarget.value)
    }
  }
  const onInput = (e: FormEvent<HTMLInputElement>) => {
    if (e.currentTarget.value.trim() === '') apiRef.current?.flyBack()
  }
  const flyDemo = (v: string) => {
    apiRef.current?.flyToIndicator(v)
    if (inputRef.current) inputRef.current.value = v
  }

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
              'Every enriched indicator lands on the globe — verdict-toned, sized by severity, attributed in a glance. Drag to spin, scroll to zoom.'}
          </p>

          <div className="sdh-enter sdh-enter-4 mt-1 flex w-full max-w-md flex-col gap-3">
            <input
              ref={inputRef}
              type="text"
              inputMode="text"
              autoComplete="off"
              spellCheck={false}
              aria-label="Fly the globe to an indicator"
              placeholder="Try an IP — 185.220.101.34"
              onKeyDown={onKeyDown}
              onInput={onInput}
              className="w-full rounded-md border border-line bg-field px-3 py-2 font-mono text-base text-paper outline-offset-2 placeholder:text-faint focus-visible:outline-2 focus-visible:outline-accent"
            />
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-micro uppercase tracking-[0.14em] text-faint">
                Recent
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
