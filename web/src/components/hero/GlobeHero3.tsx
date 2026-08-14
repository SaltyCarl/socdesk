/**
 * GlobeHero3 — the three.js hero as a SELF-CONTAINED section (A/B candidate;
 * NOT wired into the Overview route, which composes GlobeStage3 + its own copy
 * column). Same engine (useGlobe3), same real data layers (useHeroPins), same
 * redesigned card (TipCard), and the same live-enrich omnibox seam (runEnrich →
 * socdesk:enrich-result → the globe lands the real result).
 *
 * CSP: zero inline styles in JSX; runtime writes go through setProperty in
 * useGlobe3. Styling = Tailwind + the bundled ./globe.css.
 */

import { useRef, useState } from 'react'
import type { KeyboardEvent, FormEvent, ReactNode, RefObject } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import { MicroLabel } from '../ui'
import { useGlobe3, type GlobeApi } from './useGlobe3'
import { useHeroPins } from './useHeroPins'
import { TipCard } from './TipCard'
import { runEnrich, type EnrichStatus } from './enrichFly'
import './globe.css'

const DEMO_INDICATORS = ['185.220.101.34', '1.1.1.1', '8.8.8.8']

const CHIP_CLS =
  'rounded-md border border-line bg-panel px-2.5 py-1 font-mono text-xs text-muted transition-colors duration-150 ease-brand hover:border-line-bright hover:text-paper focus-visible:outline-2 focus-visible:outline-accent'

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

export interface GlobeHero3Props {
  kicker?: string
  title?: ReactNode
  subtitle?: ReactNode
  demo?: boolean
  apiRef?: RefObject<GlobeApi | null>
  className?: string
}

export function GlobeHero3({
  kicker = 'Live threat surface · three.js',
  title,
  subtitle,
  demo = true,
  apiRef,
  className,
}: GlobeHero3Props) {
  const { pins } = useHeroPins()
  const g = useGlobe3(pins, apiRef)
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
      g.api.flyBack()
    }
  }
  const flyDemo = (v: string) => {
    enrich(v)
    if (inputRef.current) inputRef.current.value = v
  }

  const line = statusLine(status)

  return (
    <section ref={g.rootRef} className={cx('sdh-hero relative py-16', className)}>
      <div className="sdh-atmos" aria-hidden="true" />

      <div className="relative z-[2] flex max-w-xl flex-col items-start gap-5">
        <MicroLabel tone="accent" tick className="sdh-enter sdh-enter-1">
          {kicker}
        </MicroLabel>
        <h1 className="sdh-enter sdh-enter-2 font-display text-display font-extrabold tracking-display text-paper">
          {title ?? (
            <>
              Threats, <span className="text-accent">in depth.</span>
            </>
          )}
        </h1>
        <p className="sdh-enter sdh-enter-3 max-w-lg text-md text-muted">
          {subtitle ??
            'Reported malicious IPs and ransomware victim-countries, plotted from real sources. Look up any indicator to land it live. Drag to spin, scroll to zoom.'}
        </p>

        {demo && (
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
        )}
      </div>

      <div className="sdh-wrap" aria-hidden="true">
        <div ref={g.stageRef} className="sdh-stage">
          <canvas ref={g.canvasRef} className="sdh-globe" />
        </div>
        <div className="sdh-hint">Drag to spin · scroll to zoom</div>
      </div>

      <div
        ref={g.tipRef}
        className={cx('sdh-tip', g.activeCard && 'is-visible')}
        role="tooltip"
        aria-hidden={g.activeCard ? 'false' : 'true'}
      >
        {g.activeCard && <TipCard card={g.activeCard} />}
      </div>
    </section>
  )
}
