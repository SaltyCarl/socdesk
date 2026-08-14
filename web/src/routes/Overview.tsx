import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import type { FormEvent, KeyboardEvent, MouseEvent, ReactNode } from 'react'
import { MicroLabel } from '../components/ui'
import { SituationalBoard } from '../components/overview'
import { CardCanvasPreview, EscalationCard } from '@socdesk/shared/verdict-cards'
import type { GlobeApi } from '../components/hero/useGlobe3'
import { ENRICH_EVENT } from '../components/hero/enrichFly'
import { geoPresent, type EnrichApiResult } from '../components/hero/heroLayers'
import { lookupHash, submitLookup } from '../components/palette/commands'
import { useEffectiveTheme, type EffectiveTheme } from '../components/lookup/useEffectiveTheme'
import { useLookup, type LookupState } from '../components/lookup/useLookup'
import { LookupStatus } from '../components/lookup/LookupStates'
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
 * The omnibox is the product in miniature: an indicator is resolved through the
 * SAME shared `useLookup` unit the /lookup surface uses, and the answer renders
 * INLINE below the hero — the real EscalationCard + its deterministic copy-card
 * PNG, or the honest degraded state (checking / declined / unavailable /
 * unsupported), plus a link to the dense analyst console at /lookup.
 *
 * ONE fetch, two payoffs: for an enrichable indicator useLookup makes a single
 * /api/enrich round-trip; its RAW body is dispatched on `socdesk:enrich-result`
 * so the lazily-mounted globe lands it on real coordinates, while its mapped
 * VerdictData feeds the inline card — never a second request. A CVE resolves
 * from the committed catalog (no geo, so no globe landing — honest). Emptying the
 * input collapses the result zone and flies the globe home.
 */

const GlobeStage3 = lazy(() =>
  import('../components/hero/GlobeStage3').then((m) => ({ default: m.GlobeStage3 })),
)

const DEMO_INDICATORS = ['185.220.101.34', '1.1.1.1', '8.8.8.8']

const CHIP_CLS =
  'rounded-md border border-line bg-panel px-2.5 py-1 font-mono text-xs text-muted transition-colors duration-150 ease-brand hover:border-line-bright hover:text-paper focus-visible:outline-2 focus-visible:outline-accent'

const FULL_VIEW_CLS =
  'inline-flex w-fit items-center gap-1 font-mono text-xs font-semibold text-accent underline-offset-2 outline-offset-2 hover:underline focus-visible:outline-2 focus-visible:outline-accent'

/**
 * The inline result zone under the hero. Renders the escalation card + its
 * copy-card PNG on `ok`, or the shared honest degraded state otherwise, with a
 * deep link to the full analyst console. `idle` renders nothing (the caller
 * unmounts the zone entirely so the board returns to its normal position).
 */
function LandingResult({
  state,
  theme,
  onFullView,
}: {
  state: LookupState
  theme: EffectiveTheme
  onFullView: (e: MouseEvent<HTMLAnchorElement>, q: string) => void
}) {
  if (state.kind === 'idle') return null
  const indicator = 'indicator' in state ? state.indicator : ''

  return (
    <div className="flex flex-col gap-5 border-t border-line pt-8">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <MicroLabel tone="accent" tick>
          {indicator ? `Escalation card — ${indicator}` : 'Escalation card'}
        </MicroLabel>
        {indicator && (
          <a
            href={`/lookup${lookupHash(indicator)}`}
            onClick={(e) => onFullView(e, indicator)}
            className={FULL_VIEW_CLS}
          >
            Full analyst view <span aria-hidden="true">→</span>
          </a>
        )}
      </div>

      {state.kind === 'ok' ? (
        <div className="grid gap-6 lg:grid-cols-2">
          <EscalationCard data={state.data} theme={theme} />
          <div className="rounded-lg border border-dashed border-line-bright bg-ink p-5">
            <CardCanvasPreview data={state.data} theme={theme} />
          </div>
        </div>
      ) : (
        <LookupStatus state={state} />
      )}
    </div>
  )
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
  const resultRef = useRef<HTMLElement | null>(null)
  // `active` is the SUBMITTED indicator that drives the inline result + the
  // globe. Empty string → no result zone (collapsed) and the globe flies home.
  const [active, setActive] = useState('')
  const theme = useEffectiveTheme()
  const state = useLookup(active)

  // ONE fetch feeds both surfaces. useLookup owns the single /api/enrich round-
  // trip; here we route its outcome to the globe: the raw body lands an
  // enrichable indicator with real geo, and anything non-plottable (a CVE, a
  // hash, a geoless domain, or any failed/empty state) flies the globe home so a
  // stale landing never sits under a mismatched card. `checking` is left alone.
  useEffect(() => {
    const api = apiRef.current
    if (state.kind === 'ok' && state.raw && geoPresent(state.raw)) {
      document.dispatchEvent(new CustomEvent<EnrichApiResult>(ENRICH_EVENT, { detail: state.raw }))
    } else if (state.kind !== 'checking') {
      api?.flyBack()
    }
  }, [state])

  // Reveal the answer: a new submit lands the result below a tall hero, off the
  // first fold — bring it into view. Reduced motion → an instant jump.
  useEffect(() => {
    if (!active) return
    const el = resultRef.current
    if (!el) return
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    el.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' })
  }, [active])

  const submit = (value: string) => setActive(value.trim())

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault()
      submit(e.currentTarget.value)
    }
  }
  const onInput = (e: FormEvent<HTMLInputElement>) => {
    // Clearing the field collapses the result zone (idle → globe flies home).
    if (e.currentTarget.value.trim() === '') setActive('')
  }
  const flyDemo = (v: string) => {
    setActive(v)
    if (inputRef.current) inputRef.current.value = v
  }

  // The full analyst console lives at /lookup. Left-click SPA-navigates there;
  // modified clicks keep the real href so it right-clicks / opens in a new tab.
  const openFullView = (e: MouseEvent<HTMLAnchorElement>, q: string) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return
    e.preventDefault()
    submitLookup(q)
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
              'Reported malicious IPs and ransomware victim-countries, plotted from real sources. Enrich any indicator to get its attributed escalation card inline — and watch it land live on the globe. Drag to spin, scroll to zoom.'}
          </p>

          <div className="sdh-enter sdh-enter-4 mt-1 flex w-full max-w-md flex-col gap-3">
            <input
              ref={inputRef}
              type="text"
              inputMode="text"
              autoComplete="off"
              spellCheck={false}
              aria-label="Look up an indicator — get its escalation card inline and land it on the globe"
              placeholder="Enrich an IP / domain / hash — 185.220.101.34"
              onKeyDown={onKeyDown}
              onInput={onInput}
              className="w-full rounded-md border border-line bg-field px-3 py-2 font-mono text-base text-paper outline-offset-2 placeholder:text-faint focus-visible:outline-2 focus-visible:outline-accent"
            />
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

      {/* -------- inline result zone — reveals on submit, collapses on clear -------- */}
      {active && (
        <section
          key={active}
          ref={resultRef}
          aria-label="Lookup result"
          className="scroll-mt-8 motion-safe:animate-[sd-rise_var(--duration-slow)_var(--ease-brand)_both]"
        >
          <LandingResult state={state} theme={theme} onFullView={openFullView} />
        </section>
      )}

      {/* -------- situational board -------- */}
      <SituationalBoard />
    </div>
  )
}
