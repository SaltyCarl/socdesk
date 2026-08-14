/**
 * GlobeStage3 — the three.js globe VISUAL only (canvas + projected pins + the
 * DOM verdict tooltip), split out of GlobeHero3 so the Overview can render its
 * copy column + situational board INSTANTLY while `three` code-splits into this
 * chunk and streams in behind a `Suspense fallback={null}`.
 *
 * The hero copy + demo omnibox now live in the Overview page (no `three`
 * dependency); this component owns ONLY the globe and drives it through the same
 * committed `useGlobe3` engine. The parent shares a `apiRef` so the omnibox can
 * fly the globe once this chunk has mounted (calls no-op harmlessly before then).
 *
 * CSP: zero inline styles in JSX; every runtime write goes through setProperty
 * inside useGlobe3. Styling = Tailwind + the bundled ./globe.css (also imported
 * by the Overview so the hero-shell classes are present on first paint).
 */

import { useCallback } from 'react'
import type { ReactNode, RefObject } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import { useGlobe3, type GlobeApi } from './useGlobe3'
import { type Pin } from './pins'
import './globe.css'

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

export interface GlobeStage3Props {
  /** Receive the imperative fly-to API for the parent's omnibox / enrich seam. */
  apiRef?: RefObject<GlobeApi | null>
  /** Optional gesture hint (defaults to the standard drag/zoom affordance). */
  hint?: ReactNode
}

export function GlobeStage3({ apiRef, hint }: GlobeStage3Props) {
  const g = useGlobe3(apiRef)

  // useGlobe3's rootRef is typed HTMLElement (it lived on a <section>); attach it
  // to this decorative <div> via a stable callback ref so there is no ref-variance
  // cast. The intersection gate observes this wrap — it's on screen exactly when
  // the globe is, which is all the loop-gating needs.
  const setRoot = useCallback(
    (el: HTMLDivElement | null) => {
      g.rootRef.current = el
    },
    [g.rootRef],
  )

  return (
    <>
      <div ref={setRoot} className="sdh-wrap" aria-hidden="true">
        <div ref={g.stageRef} className="sdh-stage">
          <canvas ref={g.canvasRef} className="sdh-globe" />
        </div>
        <div className="sdh-hint">{hint ?? 'Drag to spin · scroll to zoom'}</div>
      </div>

      <div
        ref={g.tipRef}
        className={cx('sdh-tip', g.activePin && 'is-visible')}
        role="tooltip"
        aria-hidden={g.activePin ? 'false' : 'true'}
      >
        {g.activePin && <TipContent pin={g.activePin} />}
      </div>
    </>
  )
}
