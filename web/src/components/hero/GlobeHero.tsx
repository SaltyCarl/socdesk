/**
 * GlobeHero — the home-hero showpiece: a matte periwinkle cobe dot-matrix globe
 * bleeding off the right edge, with a low-contrast CSS aurora behind it and a
 * two-column layout (copy left, globe right). PORTED from the vanilla site
 * (site/js/globe.js + site/css/globe.css) onto React + the installed cobe@2.
 *
 * Behaviours: auto-spin + drag inertia, graded 3-state hover (off-globe = full
 * spin, over-canvas = ~30%, over a pin = halt), gesture zoom (wheel + pinch),
 * verdict-toned projected pins with an analyst tooltip, and a critically-damped
 * fly-to on a `socdesk:enrich-result` event (or the demo omnibox / chips).
 *
 * Integration contract (see the delivery report):
 *   • Fires on `document` CustomEvent `socdesk:enrich-result` (detail = the
 *     enrich result object) — the enrich client / command palette dispatches it.
 *   • Or drive imperatively: pass `apiRef` and call
 *     apiRef.current.flyToLatLng / flyToIndicator / flyBack.
 *
 * CSP: zero inline styles in JSX (eslint react/forbid-dom-props). All runtime
 * positioning is `el.style.setProperty` inside useGlobe. Styling ships as
 * Tailwind utilities + the bundled ./globe.css (static 'self' CSS).
 */

import { useRef } from 'react'
import type { KeyboardEvent, FormEvent, ReactNode, RefObject } from 'react'
import { cx } from '../../lib/cx'
import { MicroLabel } from '../ui'
import { useGlobe, type GlobeApi } from './useGlobe'
import { PINS, type Pin } from './pins'
import './globe.css'

const DEMO_INDICATORS = ['185.220.101.34', '45.146.164.110', '8.8.8.8']

const CHIP_CLS =
  'rounded-md border border-line bg-panel px-2.5 py-1 font-mono text-xs text-muted transition-colors duration-150 ease-brand hover:border-line-bright hover:text-paper focus-visible:outline-2 focus-visible:outline-accent'

/** Analyst verdict tooltip content (position + show state owned by useGlobe). */
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

export interface GlobeHeroProps {
  kicker?: string
  title?: ReactNode
  subtitle?: ReactNode
  /** show the local demo omnibox + indicator chips (default true). */
  demo?: boolean
  /** receive the imperative fly-to API for programmatic control. */
  apiRef?: RefObject<GlobeApi | null>
  className?: string
}

export function GlobeHero({
  kicker = 'Live threat surface',
  title,
  subtitle,
  demo = true,
  apiRef,
  className,
}: GlobeHeroProps) {
  const g = useGlobe(apiRef)
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

      {/* copy column — sits above the globe */}
      <div className="relative z-[2] flex max-w-xl flex-col items-start gap-5">
        <MicroLabel tone="accent" tick className="sdh-enter sdh-enter-1">
          {kicker}
        </MicroLabel>
        <h1 className="sdh-enter sdh-enter-2 font-display text-display font-extrabold tracking-display text-paper">
          {title ?? (
            <>
              Threats, <span className="text-accent">located.</span>
            </>
          )}
        </h1>
        <p className="sdh-enter sdh-enter-3 max-w-lg text-md text-muted">
          {subtitle ??
            'Every enriched indicator lands on the globe — verdict-toned, sized by severity, attributed in a glance. Drag to spin, scroll to zoom.'}
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

      {/* globe — decorative visual; the data lives in the copy + tooltip */}
      <div className="sdh-wrap" aria-hidden="true">
        <div ref={g.stageRef} className="sdh-stage">
          {/* fresnel rim — behind the canvas (MOVE 2) */}
          <div className="sdh-limb" />
          <canvas ref={g.canvasRef} className="sdh-globe" />
          {/* great-circle attack arcs — SVG pool: 4 ambient + 1 scored (MOVE 1).
             Geometry (d), draw-on (stroke-dashoffset) + opacity written per-frame
             in useGlobe; pathLength=1 normalises the draw-on. */}
          <svg
            ref={g.arcsRef}
            className="sdh-arcs"
            viewBox="0 0 1000 1000"
            preserveAspectRatio="none"
          >
            {[0, 1, 2, 3].map((i) => (
              <path key={i} className="sdh-arc" pathLength={1} />
            ))}
            <path className="sdh-arc sdh-arc-scored" pathLength={1} />
          </svg>
          <div ref={g.pinsRef} className="sdh-pins">
            {PINS.map((p) => (
              <div key={p.id} className={cx('sdh-pin', `sdh-${p.tier}`)} />
            ))}
          </div>
          <div ref={g.landedRef} className="sdh-pin sdh-landed">
            <div className="sdh-pin-disc" />
            <div className="sdh-pin-pulse" />
          </div>
        </div>
        <div className="sdh-hint">
          Drag to spin · scroll to zoom
        </div>
      </div>

      {/* tooltip — position:fixed, driven by useGlobe (setProperty) */}
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
