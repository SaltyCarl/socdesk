/**
 * GlobeStage3 — the three.js globe VISUAL only (canvas + the DOM verdict
 * tooltip), split out of the Overview so the copy column + situational board
 * render INSTANTLY while `three` code-splits into this chunk behind a
 * `Suspense fallback={null}`.
 *
 * This chunk OWNS the globe and its data: it loads the two real layers
 * (useHeroPins — abuse.ch reported IPs + ransomware.live victim countries) and
 * feeds them to the committed `useGlobe3` engine. The parent shares an `apiRef`
 * for flyBack, and the enrich landing arrives via the `socdesk:enrich-result`
 * event the engine already listens for (dispatched by the Overview omnibox).
 *
 * CSP: zero inline styles in JSX; every runtime write goes through setProperty
 * inside useGlobe3. Styling = Tailwind + the bundled ./globe.css.
 */

import { useCallback } from 'react'
import type { ReactNode, RefObject } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import { useGlobe3, type GlobeApi } from './useGlobe3'
import { useHeroPins } from './useHeroPins'
import { TipCard } from './TipCard'
import './globe.css'

export interface GlobeStage3Props {
  /** Receive the imperative fly-back API for the parent's omnibox seam. */
  apiRef?: RefObject<GlobeApi | null>
  /** Optional gesture hint (defaults to the standard drag/zoom affordance). */
  hint?: ReactNode
}

export function GlobeStage3({ apiRef, hint }: GlobeStage3Props) {
  const { pins } = useHeroPins()
  const g = useGlobe3(pins, apiRef)

  // useGlobe3's rootRef is typed HTMLElement; attach it to this decorative
  // <div> via a stable callback ref. The intersection gate observes this wrap —
  // it's on screen exactly when the globe is, which is all the loop-gating needs.
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
        className={cx('sdh-tip', g.activeCard && 'is-visible')}
        role="tooltip"
        aria-hidden={g.activeCard ? 'false' : 'true'}
      >
        {g.activeCard && <TipCard card={g.activeCard} />}
      </div>
    </>
  )
}
