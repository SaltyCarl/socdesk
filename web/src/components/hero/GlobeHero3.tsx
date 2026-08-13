/**
 * GlobeHero3 — the three.js hero (A/B candidate; NOT wired into the Overview
 * route). Same shell as GlobeHero (copy column + demo omnibox + DOM glass
 * tooltip) but the globe is a real 3D dot-sphere with proper light-mode material
 * (see useGlobe3). Pins, arcs and the landed marker are three.js objects; only
 * the tooltip stays DOM (.sdh-tip), re-driven by Vector3.project(camera).
 *
 * CSP: zero inline styles in JSX; runtime writes go through setProperty in
 * useGlobe3. Styling = Tailwind + the bundled ./globe.css.
 */

import { useRef } from 'react'
import type { KeyboardEvent, FormEvent, ReactNode, RefObject } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import { MicroLabel } from '../ui'
import { useGlobe3, type GlobeApi } from './useGlobe3'
import { type Pin } from './pins'
import './globe.css'

const DEMO_INDICATORS = ['185.220.101.34', '45.146.164.110', '8.8.8.8']

const CHIP_CLS =
  'rounded-md border border-line bg-panel px-2.5 py-1 font-mono text-xs text-muted transition-colors duration-150 ease-brand hover:border-line-bright hover:text-paper focus-visible:outline-2 focus-visible:outline-accent'

/** Analyst verdict tooltip content (position + show state owned by useGlobe3). */
function TipContent({ pin }: { pin: Pin }) {
  return (
    <>
      <div className="sdh-tip-head">
        <span className="sdh-tip-type">{pin.type}</span>
        <span className="sdh-tip-ind">{pin.ind}</span>
      </div>
      <div className="sdh-tip-body">
        <div className="sdh-tip-what">{pin.what}</div>
        <div className="sdh-tip-actor">{pin.actor}</div>
        <div className="sdh-tip-metrics">
          <div className="sdh-tip-score">
            {pin.sev}
            <span>/100</span>
          </div>
          <div className="sdh-tip-consensus">
            <b>{pin.consensus}</b> sources<small>consensus flag</small>
          </div>
          <div className="sdh-tip-meter">
            <i />
          </div>
        </div>
        <div className="sdh-tip-rows">
          <div className="sdh-tip-row">
            <span className="sdh-k">Last seen</span>
            <span className="sdh-v">{pin.seen}</span>
          </div>
          <div className="sdh-tip-row">
            <span className="sdh-k">Trend</span>
            <span className={cx('sdh-v', `sdh-trend-${pin.trend.d}`)}>{pin.trend.t}</span>
          </div>
          <div className="sdh-tip-row">
            <span className="sdh-k">Geo / ASN</span>
            <span className="sdh-v">{pin.geo}</span>
          </div>
        </div>
      </div>
      <div className="sdh-tip-hint">Enter to open verdict</div>
    </>
  )
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
  const g = useGlobe3(apiRef)
  const inputRef = useRef<HTMLInputElement>(null)

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault()
      g.api.flyToIndicator(e.currentTarget.value)
    }
  }
  const onInput = (e: FormEvent<HTMLInputElement>) => {
    if (e.currentTarget.value.trim() === '') g.api.flyBack()
  }
  const flyDemo = (v: string) => {
    g.api.flyToIndicator(v)
    if (inputRef.current) inputRef.current.value = v
  }

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
            'A real 3D dot-sphere — proper light-mode material, depth-buffer occlusion, and the same spring fly-to. Drag to spin, scroll to zoom.'}
        </p>

        {demo && (
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
        className={cx('sdh-tip', g.activePin && 'is-visible')}
        role="tooltip"
        aria-hidden={g.activePin ? 'false' : 'true'}
      >
        {g.activePin && <TipContent pin={g.activePin} />}
      </div>
    </section>
  )
}
