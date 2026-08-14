// useInView — resolve `true` the first time a ref scrolls near the viewport,
// then latch. Used to DEFER the heavy cves.json fetch (~5 MB) for the
// "Exploited ≠ severe" panel until the analyst scrolls toward it, so the crown
// -jewel landing paints on the tiny trends/feed/health payloads alone.
//
// No IntersectionObserver (older engines, SSR) → resolves true immediately, so
// the panel still works; it just fetches eagerly. `rootMargin` prefetches a
// little before the panel is actually on screen for a seamless reveal.

import { useEffect, useRef, useState } from 'react'
import type { RefObject } from 'react'

export function useInView<T extends HTMLElement = HTMLElement>(
  rootMargin = '400px',
): { ref: RefObject<T | null>; inView: boolean } {
  const ref = useRef<T | null>(null)
  const [inView, setInView] = useState(
    () => typeof IntersectionObserver === 'undefined',
  )

  useEffect(() => {
    if (inView) return
    const el = ref.current
    if (!el) return
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          setInView(true)
          io.disconnect()
        }
      },
      { rootMargin },
    )
    io.observe(el)
    return () => io.disconnect()
  }, [inView, rootMargin])

  return { ref, inView }
}
