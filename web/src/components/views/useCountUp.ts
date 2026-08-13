// useCountUp.ts — tick a stat number 0 → value the first time it scrolls into
// view, once per mount, on rAF with an ease-out curve.
//
// CSP + no-layout-shift contract: this hook writes ONLY React state (never a
// style attribute — `react/forbid-dom-props` bans inline styles and the strict
// `style-src 'self'` forbids them anyway). The caller formats the value with
// the shared thousands separator and MUST render it with `tabular-nums`, so
// every intermediate frame occupies the same width and the number never
// reflows while ticking.
//
// Reduced-motion, or a browser without IntersectionObserver, renders the final
// value instantly with no animation. Premium motion is for the SITE showcase;
// the extension does not use this.

import { useEffect, useRef, useState } from 'react'
import { prefersReducedMotion } from '@socdesk/shared/lib/motion'

export interface CountUpOptions {
  /** Total tween time in ms (spec: ~600–900). */
  duration?: number
}

const easeOutCubic = (t: number): number => 1 - Math.pow(1 - t, 3)

/** True when we must skip the animation and show the final value at once. */
const skipAnimation = (): boolean =>
  prefersReducedMotion() || typeof IntersectionObserver === 'undefined'

export function useCountUp<T extends HTMLElement = HTMLElement>(
  target: number,
  opts: CountUpOptions = {},
): { ref: React.RefObject<T | null>; value: number } {
  const { duration = 750 } = opts
  const ref = useRef<T | null>(null)
  const [display, setDisplay] = useState<number>(() =>
    skipAnimation() ? Math.round(target) : 0,
  )

  // Latest target, read live inside the frame loop so an async data update
  // (or a filtered count) that lands mid-tween retargets smoothly.
  const targetRef = useRef(target)
  targetRef.current = target

  const playedRef = useRef(false) // the one-shot has been consumed
  const settledRef = useRef(false) // final value reached (or skipped)

  useEffect(() => {
    if (playedRef.current) return
    const el = ref.current
    if (skipAnimation() || !el) {
      playedRef.current = true
      settledRef.current = true
      setDisplay(Math.round(targetRef.current))
      return
    }

    let raf = 0
    const io = new IntersectionObserver(
      (entries) => {
        if (!entries[0]?.isIntersecting || playedRef.current) return
        playedRef.current = true
        io.disconnect()
        const start = performance.now()
        const step = (now: number) => {
          const t = Math.min(1, (now - start) / duration)
          setDisplay(Math.round(targetRef.current * easeOutCubic(t)))
          if (t < 1) {
            raf = requestAnimationFrame(step)
          } else {
            settledRef.current = true
            setDisplay(targetRef.current)
          }
        }
        raf = requestAnimationFrame(step)
      },
      { threshold: 0.1 },
    )
    io.observe(el)

    return () => {
      io.disconnect()
      if (raf) cancelAnimationFrame(raf)
    }
  }, [duration])

  // Once settled, follow live target changes (e.g. a filtered count) directly,
  // with no re-animation — the one-shot has already played.
  useEffect(() => {
    if (settledRef.current) setDisplay(target)
  }, [target])

  return { ref, value: display }
}
