import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import type { MouseEvent, ReactNode } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import { MicroLabel } from '../components/ui'
import { SituationalBoard } from '../components/overview'
import type { CompareResult } from '@socdesk/shared/verdict-cards'
import type { GlobeApi } from '../components/hero/useGlobe3'
import { ENRICH_EVENT } from '../components/hero/enrichFly'
import { geoPresent, type EnrichApiResult } from '../components/hero/heroLayers'
import { submitLookup } from '../components/palette/commands'
import { useEffectiveTheme } from '../components/lookup/useEffectiveTheme'
import { useCockpitInput, type CockpitResult } from '../components/cockpit/useCockpitInput'
import { ResultRegion } from '../components/cockpit/ResultRegion'
import { CockpitOmnibox } from '../components/cockpit/CockpitOmnibox'
// The hero-shell classes (.sdh-hero / .sdh-atmos / .sdh-enter*) must be present
// on FIRST paint — this route is synchronous, so importing the co-located CSS
// here puts them in the main bundle even though the globe canvas itself streams
// in later from the lazy chunk below.
import '../components/hero/globe.css'

/**
 * Overview (`/`) — the POLYMORPHIC cockpit: one omnibox classifies a pasted
 * indicator or PowerShell command and routes it to enrichment or the local
 * analyzer, rendering either result in the same docked slot beside the globe
 * (design spec, full document).
 */

const GlobeStage3 = lazy(() =>
  import('../components/hero/GlobeStage3').then((m) => ({ default: m.GlobeStage3 })),
)

const DEMO_INDICATORS = ['185.220.101.34', '1.1.1.1', '8.8.8.8']

const CHIP_CLS =
  'rounded-md border border-line bg-panel px-2.5 py-1 font-mono text-xs text-muted transition-colors duration-150 ease-brand hover:border-line-bright hover:text-paper focus-visible:outline-2 focus-visible:outline-accent'

// Standard enter used for the card reveal + the compact result brand line.
const REVEAL_CLS =
  'motion-safe:animate-[sd-rise_var(--duration-slow)_var(--ease-brand)_both]'

/** Whether the CURRENT cockpit result has no geography to land on: a command
 *  result, an unclassified submission, or an indicator that has resolved
 *  (past `checking`) without geo. `checking` stays non-geoless so the globe
 *  doesn't flicker dim before the outcome is known (design spec §3.6, §3.8). */
function isGeolessResult(cockpit: CockpitResult, submitted: string): boolean {
  if (cockpit.kind === 'command') return true
  if (cockpit.kind === 'unclassified') return submitted !== ''
  const state = cockpit.state
  if (state.kind === 'idle' || state.kind === 'checking') return false
  if (state.kind === 'ok') return !(state.raw && geoPresent(state.raw))
  return true // declined / unavailable / unsupported — no geo
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
  // `liveValue` is the raw, uncommitted omnibox text (drives the input-morph
  // + ModeChip live detection). `submitted` is the COMMITTED (post-Enter)
  // value that drives the result region + the globe — empty string -> Idle.
  // `submittedOverride` carries a ModeChip correction through to
  // useCockpitInput, captured at submit time so a later live edit can't
  // retroactively change what already fired. useCockpitInput classifies the
  // pair and runs the matching hook; the unselected hook is fed '' internally,
  // so only ONE round-trip (or zero, for a command) ever fires per submit.
  const [liveValue, setLiveValue] = useState('')
  const [submitted, setSubmitted] = useState('')
  const [submittedOverride, setSubmittedOverride] = useState<'indicator' | 'command' | null>(null)
  const theme = useEffectiveTheme()
  const cockpit = useCockpitInput(submitted, submittedOverride)
  const isResult = cockpit.kind !== 'unclassified' || submitted !== ''
  const resultIsGeoless = isGeolessResult(cockpit, submitted)

  const brand = title ?? (
    <>
      IOC in. <span className="text-accent">OSINT</span> out.
    </>
  )

  // The globe only ever lands on an INDICATOR result with real geo. A command
  // or unclassified result — and any indicator state that isn't a geo-bearing
  // `ok` — flies the globe home so a stale landing never sits under a
  // mismatched result. `checking` is left alone (mirrors the old behaviour).
  useEffect(() => {
    const api = apiRef.current
    if (cockpit.kind === 'indicator') {
      const state = cockpit.state
      if (state.kind === 'ok' && state.raw && geoPresent(state.raw)) {
        document.dispatchEvent(new CustomEvent<EnrichApiResult>(ENRICH_EVENT, { detail: state.raw }))
      } else if (state.kind !== 'checking') {
        api?.flyBack()
      }
      return
    }
    api?.flyBack()
  }, [cockpit.kind, cockpit.state])

  // Loop cost: a geoless result stops the render loop instead of merely
  // dimming it behind CSS — IntersectionObserver-based gating doesn't see a
  // CSS opacity change, so without this the globe would keep burning GPU
  // behind the .is-geoless dim (design spec §2.4, §3.8).
  useEffect(() => {
    if (resultIsGeoless) apiRef.current?.suspend()
    else apiRef.current?.resume()
  }, [resultIsGeoless])

  const submit = (value: string, kindOverride: 'indicator' | 'command' | null) => {
    const trimmed = value.trim()
    setSubmitted(trimmed)
    setSubmittedOverride(trimmed ? kindOverride : null)
  }

  const onOmniboxChange = (v: string) => {
    setLiveValue(v)
    // Clearing the field returns the hero to Idle (globe flies home).
    if (v.trim() === '') {
      setSubmitted('')
      setSubmittedOverride(null)
    }
  }

  const flyDemo = (v: string) => {
    setLiveValue(v)
    submit(v, null)
  }

  // The full analyst console lives at /lookup. Left-click SPA-navigates there;
  // modified clicks keep the real href so it right-clicks / opens in a new tab.
  const openFullView = (e: MouseEvent<HTMLAnchorElement>, q: string) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return
    e.preventDefault()
    submitLookup(q)
  }

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
      <section
        className={cx(
          'sdh-hero relative py-16',
          isResult && 'is-result',
          resultIsGeoless && 'is-geoless',
        )}
      >
        <div className="sdh-atmos" aria-hidden="true" />

        <div className="relative z-[2] flex max-w-xl flex-col items-start">
          <MicroLabel tone="accent" tick className="sdh-enter sdh-enter-1">
            {kicker}
          </MicroLabel>

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

          <div className="sdh-enter sdh-enter-4 mt-5 flex w-full max-w-md flex-col gap-3">
            <CockpitOmnibox value={liveValue} onChange={onOmniboxChange} onSubmit={submit} />
          </div>

          {isResult ? (
            <div
              key={`${cockpit.kind}:${submitted}`}
              role="region"
              aria-label="Cockpit result"
              className={cx('mt-6 w-full', REVEAL_CLS)}
            >
              <ResultRegion cockpit={cockpit} theme={theme} onFullView={openFullView} onCompare={onCompareArc} />
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

        <Suspense fallback={null}>
          <GlobeStage3 apiRef={apiRef} />
        </Suspense>
      </section>

      <SituationalBoard />
    </div>
  )
}
