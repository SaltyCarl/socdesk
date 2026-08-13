/**
 * SOCDesk motion language.
 *
 * WHY THIS SHAPE (CSP): every animation here runs through Motion.dev's
 * `animate()` / `hover()` / `press()`, which drive WAAPI (`element.animate`)
 * and CSSOM property writes (`el.style.setProperty`) — NOT injected
 * `<style>` tags or HTML `style=""` attributes. So the strict
 * `style-src 'self'` / `script-src 'self'` posture holds. Never reach for
 * a CSS-in-JS lib or `element.setAttribute('style', …)`.
 *
 * WHEN TO USE WHICH (the decision the team follows):
 *   • Native CSS `@keyframes` + `animation-delay`  → one-shot load
 *     choreography (see `sd-rise` in index.css). Zero JS.
 *   • CSS scroll-driven (`animation-timeline`)      → scroll reveals /
 *     hero melt (see `sd-reveal`). Progressive-enhanced, static fallback.
 *   • Motion `animate()` (WAAPI)                     → discrete enter/exit
 *     of mounted/unmounted UI, list staggers, toasts.
 *   • Motion springs (this file's SPRING configs)    → micro-interactions
 *     that respond to input: press/hover scale, pill morph.
 *
 * The numeric tokens below MIRROR the CSS custom properties in index.css
 * (`--duration-*`, `--ease-*`). Keep them in sync by hand — the JS side
 * cannot read build-time `@theme` values.
 */

import { useEffect, useRef, type RefObject } from 'react'
import { animate, hover, press, stagger } from 'motion'

/* -- durations, in SECONDS (Motion's unit) -- */
export const DUR = {
  fast: 0.15, // --duration-fast   · taps, hover feedback
  base: 0.24, // --duration-base   · exits, small moves
  slow: 0.6, //  --duration-slow   · enters, load choreography
  draw: 1.1, //  --duration-draw   · stroke-on draws
} as const

/* -- easing curves (cubic-bezier control points) -- */
export const EASE = {
  brand: [0.16, 1, 0.3, 1], //   --ease-brand    · expo-out, most enters
  brandInOut: [0.65, 0, 0.35, 1], // --ease-brand-io · moves / reorders
} as const

/* -- Motion.dev spring configs for input-driven micro-interactions -- */
export const SPRING = {
  press: { type: 'spring', stiffness: 540, damping: 30, mass: 1 },
  gentle: { type: 'spring', stiffness: 260, damping: 26, mass: 1 },
  snappy: { type: 'spring', stiffness: 700, damping: 34, mass: 1 },
} as const

/** True when the OS asks for reduced motion. Every helper honours it. */
export function prefersReducedMotion(): boolean {
  try {
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches
  } catch {
    return false
  }
}

type El = Element | Element[] | NodeListOf<Element>

/**
 * Standard enter: fade + short rise. Reduced-motion → element is left at
 * its resting state (it was never hidden). Returns the playback controls
 * (or null when skipped) so callers can `.stop()` on unmount.
 */
export function enter(
  el: El,
  opts: { delay?: number; y?: number } = {},
) {
  const { delay = 0, y = 8 } = opts
  if (prefersReducedMotion()) return null
  return animate(
    el,
    { opacity: [0, 1], transform: [`translateY(${y}px)`, 'translateY(0px)'] },
    { duration: DUR.slow, delay, ease: EASE.brand },
  )
}

/** Standard exit: quick fade + settle down. */
export function exit(el: El) {
  if (prefersReducedMotion()) return null
  return animate(
    el,
    { opacity: [1, 0], transform: ['translateY(0px)', 'translateY(6px)'] },
    { duration: DUR.base, ease: EASE.brandInOut },
  )
}

/** Staggered enter for a list of siblings (70ms-ish default cascade). */
export function enterStagger(
  els: El,
  opts: { each?: number; y?: number } = {},
) {
  const { each = 0.06, y = 10 } = opts
  if (prefersReducedMotion()) return null
  return animate(
    els,
    { opacity: [0, 1], transform: [`translateY(${y}px)`, 'translateY(0px)'] },
    { duration: DUR.slow, delay: stagger(each), ease: EASE.brand },
  )
}

/**
 * React hook: attach spring-backed press (and optional hover) scale
 * feedback to a ref'd element. No-ops under reduced motion. Because it
 * animates `scale` via Motion (WAAPI/CSSOM), it emits no inline styles.
 */
export function usePressScale(
  ref: RefObject<HTMLElement | null>,
  opts: { down?: number; hover?: number } = {},
): void {
  const { down = 0.97, hover: hoverScale = 1 } = opts
  useEffect(() => {
    const el = ref.current
    if (!el || prefersReducedMotion()) return
    const cleanups: Array<() => void> = []

    cleanups.push(
      press(el, (target) => {
        animate(target, { scale: down }, SPRING.press)
        return () => animate(target, { scale: 1 }, SPRING.gentle)
      }),
    )
    if (hoverScale !== 1) {
      cleanups.push(
        hover(el, (target) => {
          animate(target, { scale: hoverScale }, SPRING.gentle)
          return () => animate(target, { scale: 1 }, SPRING.gentle)
        }),
      )
    }
    return () => cleanups.forEach((fn) => fn())
  }, [ref, down, hoverScale])
}

/** React hook: run the standard enter once on mount. */
export function useEnterOnMount(
  ref: RefObject<HTMLElement | null>,
  opts: { delay?: number; y?: number } = {},
): void {
  useEffect(() => {
    const el = ref.current
    if (!el) return
    const controls = enter(el, opts)
    return () => controls?.stop()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
}

/** Convenience: a fresh ref typed for the hooks above. */
export function useMotionRef<T extends HTMLElement>() {
  return useRef<T>(null)
}
