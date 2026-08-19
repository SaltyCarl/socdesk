import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import type { FormEvent, KeyboardEvent, MouseEvent, ReactNode } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import { MicroLabel } from '../components/ui'
import { SituationalBoard } from '../components/overview'
import { EscalationCard, type CompareResult } from '@socdesk/shared/verdict-cards'
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
 * Overview (`/`) — the crown-jewel landing, restructured as a LOOKUP COCKPIT:
 * the globe and the escalation card read as ONE integrated answer, not two
 * stapled-together features.
 *
 * The hero content column has TWO states, driven by whether a lookup is active:
 *
 *   Idle    — kicker · the "IOC in. OSINT out." H1 · the copy paragraph · the
 *             omnibox · the TRY chips, with the globe bleeding off the right.
 *   Result  — the omnibox stays PINNED near the top (the next lookup needs no
 *             scroll), the marketing intro COLLAPSES (its job is done), and the
 *             real EscalationCard renders directly below the omnibox — IN the
 *             hero column, BESIDE the globe — with a "Full analyst view →" deep
 *             link under it. The honest degraded states (checking / declined /
 *             unavailable / unsupported) render in that same slot via the shared
 *             LookupStatus wording.
 *
 * ONE fetch, two payoffs: for an enrichable indicator `useLookup` makes a single
 * /api/enrich round-trip; its RAW body is dispatched on `socdesk:enrich-result`
 * so the lazily-mounted globe lands it on real coordinates, while its mapped
 * VerdictData feeds the inline card — never a second request. A CVE resolves
 * from the committed catalog (no geo, so no globe landing — honest). Emptying the
 * input returns the hero to Idle (copy back, card gone) and flies the globe home.
 *
 * The dense analyst triptych (client card + copy-card PNG + console) lives at
 * /lookup; the landing shows ONLY the EscalationCard (the copy-card PNG is still
 * produced on demand by the card's own embedded Copy card / Copy text actions).
 */

const GlobeStage3 = lazy(() =>
  import('../components/hero/GlobeStage3').then((m) => ({ default: m.GlobeStage3 })),
)

const DEMO_INDICATORS = ['185.220.101.34', '1.1.1.1', '8.8.8.8']

const CHIP_CLS =
  'rounded-md border border-line bg-panel px-2.5 py-1 font-mono text-xs text-muted transition-colors duration-150 ease-brand hover:border-line-bright hover:text-paper focus-visible:outline-2 focus-visible:outline-accent'

const FULL_VIEW_CLS =
  'inline-flex w-fit items-center gap-1 font-mono text-xs font-semibold text-accent underline-offset-2 outline-offset-2 hover:underline focus-visible:outline-2 focus-visible:outline-accent'

// Standard enter used for the card reveal + the compact result brand line. The
// `sd-rise` keyframe animates FROM opacity 0 to the RESTING state, so nothing is
// ever stranded invisible; `motion-safe` drops it entirely under reduced motion.
const REVEAL_CLS =
  'motion-safe:animate-[sd-rise_var(--duration-slow)_var(--ease-brand)_both]'

/**
 * The result slot that lives in the hero column beside the globe. On `ok` it is
 * the real EscalationCard; every other resolved state is the shared honest
 * degraded rendering. Both are followed by a deep link into the full analyst
 * console. `idle` renders nothing (the caller only mounts this in Result mode).
 */
function LandingResult({
  state,
  theme,
  onFullView,
  onCompare,
}: {
  state: LookupState
  theme: EffectiveTheme
  onFullView: (e: MouseEvent<HTMLAnchorElement>, q: string) => void
  onCompare: (c: CompareResult | null) => void
}) {
  if (state.kind === 'idle') return null
  const indicator = 'indicator' in state ? state.indicator : ''

  return (
    <div className="flex w-full max-w-md flex-col gap-3">
      {state.kind === 'ok' ? (
        <EscalationCard data={state.data} theme={theme} onCompare={onCompare} />
      ) : (
        <LookupStatus state={state} />
      )}
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
  // `active` is the SUBMITTED indicator that drives the result slot + the globe.
  // Empty string → Idle (the intro returns, the card is gone, the globe flies
  // home). Any non-empty value → Result mode.
  const [active, setActive] = useState('')
  const theme = useEffectiveTheme()
  const state = useLookup(active)
  const isResult = active !== ''

  const brand = title ?? (
    <>
      IOC in. <span className="text-accent">OSINT</span> out.
    </>
  )

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

  const submit = (value: string) => setActive(value.trim())

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault()
      submit(e.currentTarget.value)
    }
  }
  const onInput = (e: FormEvent<HTMLInputElement>) => {
    // Clearing the field returns the hero to Idle (globe flies home).
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

  // A Compare-IP result on the landing card draws the two-IP great-circle arc on
  // the globe (real coords, both precise); clearing it removes the arc. Country-
  // level geo has no meaningful point, so it clears rather than draw a fake line.
  const onCompareArc = (c: CompareResult | null) => {
    const api = apiRef.current
    if (!api) return
    if (c && c.first.precise && c.second.precise) {
      api.drawArc({ lat: c.first.lat, lng: c.first.lon }, { lat: c.second.lat, lng: c.second.lon })
    } else {
      api.clearArc()
    }
  }

  return (
    <div className="flex flex-col">
      {/* -------- lookup cockpit: two-state hero -------- */}
      <section className={cx('sdh-hero relative py-16', isResult && 'is-result')}>
        <div className="sdh-atmos" aria-hidden="true" />

        {/* content column — renders immediately, layered above the globe. Spacing
            is per-child (mt-*) rather than a parent `gap` so the collapsing intro
            leaves NO dead gap behind when it folds away in Result mode. */}
        <div className="relative z-[2] flex max-w-xl flex-col items-start">
          <MicroLabel tone="accent" tick className="sdh-enter sdh-enter-1">
            {kicker}
          </MicroLabel>

          {/* Marketing intro (H1 + copy) — collapses in Result mode via a
              grid-template-rows fold. It is a REVERSIBLE collapse (idle ⇄ result),
              not a stranded entrance: the row goes 1fr → 0fr while the inner fades,
              and both return to their resting state when the omnibox is cleared.
              Reduced motion → the fold is instant (no transition). */}
          <div
            className={cx(
              'grid w-full transition-[grid-template-rows] duration-[600ms] ease-brand motion-reduce:transition-none',
              isResult ? 'grid-rows-[0fr]' : 'grid-rows-[1fr]',
            )}
          >
            <div
              className={cx(
                'min-h-0 overflow-hidden transition-opacity duration-150 ease-brand motion-reduce:transition-none',
                isResult ? 'opacity-0' : 'opacity-100',
              )}
            >
              <div className="flex flex-col items-start gap-5 pt-5">
                <h1 className="sdh-enter sdh-enter-2 font-display text-display font-extrabold tracking-display text-paper">
                  {brand}
                </h1>
                <p className="sdh-enter sdh-enter-3 max-w-lg text-md text-muted">
                  {subtitle ??
                    'Reported malicious IPs and ransomware victim-countries, plotted from real sources. Enrich any indicator to get its attributed escalation card inline — and watch it land live on the globe. Drag to spin, scroll to zoom.'}
                </p>
              </div>
            </div>
          </div>

          {/* Result mode keeps a TRIMMED brand presence: the big intro folds away
              and this compact wordmark condenses in, so the header never eats the
              vertical space the card needs beside the globe. */}
          {isResult && (
            <h2
              className={cx(
                'mt-5 font-display text-lg font-extrabold tracking-tight text-paper',
                REVEAL_CLS,
              )}
            >
              {brand}
            </h2>
          )}

          {/* Omnibox — PERSISTENT across both states (kept in a stable position so
              the input never remounts and its value survives the state flip). In
              Result mode it sits pinned near the top: the next lookup needs no
              scroll. */}
          <div className="sdh-enter sdh-enter-4 mt-5 flex w-full max-w-md flex-col gap-3">
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
          </div>

          {/* Slot below the omnibox: the answer in Result mode, the TRY chips in
              Idle. Keying the result on `active` re-runs the reveal for each new
              indicator; within one indicator (checking → ok) the slot stays
              mounted so the spinner swaps to the card without re-animating. */}
          {isResult ? (
            <div
              key={active}
              role="region"
              aria-label="Lookup result"
              className={cx('mt-6 w-full', REVEAL_CLS)}
            >
              <LandingResult state={state} theme={theme} onFullView={openFullView} onCompare={onCompareArc} />
            </div>
          ) : (
            <div className="sdh-enter sdh-enter-4 mt-4 flex w-full max-w-md flex-wrap items-center gap-2">
              <span className="font-mono text-micro uppercase tracking-[0.14em] text-faint">
                Try
              </span>
              {DEMO_INDICATORS.map((v) => (
                <button key={v} type="button" onClick={() => flyDemo(v)} className={CHIP_CLS}>
                  {v}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* globe visual — lazy (three.js chunk); nothing to render while it loads.
            On desktop it bleeds off the right beside the card; below the desktop
            width `.sdh-hero.is-result` demotes it to a faint corner backdrop so it
            never overlaps the stacked card (see globe.css). */}
        <Suspense fallback={null}>
          <GlobeStage3 apiRef={apiRef} />
        </Suspense>
      </section>

      {/* -------- situational board — unchanged, sits below the hero -------- */}
      <SituationalBoard />
    </div>
  )
}
