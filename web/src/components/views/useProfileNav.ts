// useProfileNav.ts — the profile's jump-nav model + the DOM wiring that makes the
// native <details> accordions print-whole and scrollspy-aware.
//
// IMPORTANT: SOCDesk is HASH-ROUTED — the profile route lives in the URL hash
// (`/actor#g=<slug>`). So in-page navigation must NOT use `#section` fragments
// (that would overwrite `g=<slug>` and break the page). The jump-nav and the
// synthesis-band links therefore scroll+open by element id via `openAndScrollTo`
// WITHOUT touching the URL. (Deep-linking a section via a shareable URL would need
// a non-hash channel, e.g. a `?s=` query param — deferred; it must not collide
// with the hash router.)
//
// SSR-SAFE BY CONTRACT: ActorProfile renders via renderToStaticMarkup in the
// node-env test harness, so nothing here touches window/document during render or
// in a useState initializer — every DOM access is inside useEffect / an event
// handler (neither runs under renderToStaticMarkup).

import { useEffect, useState } from 'react'

export interface NavSection {
  id: string
  label: string
}

/** The jump-nav landmarks, in document order, gated on existence. Overview is
 *  always present (identity + synthesis + intel). Victims / Reporting are
 *  collapsed sections but deliberately NOT nav landmarks (the bar stays thin). */
export function navSections(flags: {
  hasActivity: boolean
  hasFingerprint: boolean
  hasHuntpack: boolean
  hasRelated: boolean
}): NavSection[] {
  const out: NavSection[] = [{ id: 'overview', label: 'Overview' }]
  if (flags.hasActivity) out.push({ id: 'activity', label: 'Activity' })
  if (flags.hasFingerprint) out.push({ id: 'fingerprint', label: 'Fingerprint' })
  if (flags.hasHuntpack) out.push({ id: 'huntpack', label: 'Hunt pack' })
  if (flags.hasRelated) out.push({ id: 'related', label: 'Related' })
  return out
}

/** Open a section's `<details>` (if it is one) and scroll it into view under the
 *  sticky stack. DOM-touching — call ONLY from a client event handler. Used by the
 *  nav buttons + synthesis-band links so a jump never mutates the URL hash (which
 *  the app reserves for its `g=<slug>` route). `scroll-mt-[6.5rem]` on each anchor
 *  supplies the sticky-header offset. */
export function openAndScrollTo(id: string): void {
  const el = document.getElementById(id)
  if (!el) return
  if (el instanceof HTMLDetailsElement) el.open = true
  el.scrollIntoView({ behavior: 'smooth', block: 'start' })
}

/**
 * Wires print-whole + scrollspy for the profile. Returns the id of the section
 * currently in view (`''` until the observer fires, and always `''` under SSR).
 * The caller MUST pass a STABLE `sections` reference (memoize on the existence
 * flags) — the effect re-subscribes only when the set of section ids changes.
 */
export function useProfileNav(sections: NavSection[]): { activeId: string } {
  const [activeId, setActiveId] = useState('')
  const key = sections.map((s) => s.id).join(',')

  useEffect(() => {
    // (1) print: open every collapsed reference section, restore afterwards.
    let reclosed: HTMLDetailsElement[] = []
    const onBeforePrint = () => {
      reclosed = Array.from(
        document.querySelectorAll<HTMLDetailsElement>('[data-collapsible]'),
      ).filter((d) => !d.open)
      reclosed.forEach((d) => (d.open = true))
    }
    const onAfterPrint = () => {
      reclosed.forEach((d) => (d.open = false))
      reclosed = []
    }
    window.addEventListener('beforeprint', onBeforePrint)
    window.addEventListener('afterprint', onAfterPrint)

    // (2) scrollspy: the topmost section crossing below the sticky stack wins.
    let observer: IntersectionObserver | null = null
    const els = key
      .split(',')
      .map((id) => document.getElementById(id))
      .filter((e): e is HTMLElement => Boolean(e))
    if (els.length && 'IntersectionObserver' in window) {
      observer = new IntersectionObserver(
        (entries) => {
          const visible = entries.filter((e) => e.isIntersecting)
          if (!visible.length) return
          const top = visible.reduce((a, b) =>
            a.boundingClientRect.top <= b.boundingClientRect.top ? a : b,
          )
          setActiveId(top.target.id)
        },
        // top -104px = header (56) + nav (~44); shrink the active band to the
        // upper viewport so "current" tracks what you're reading.
        { rootMargin: '-104px 0px -55% 0px', threshold: 0 },
      )
      els.forEach((el) => observer!.observe(el))
    }

    return () => {
      window.removeEventListener('beforeprint', onBeforePrint)
      window.removeEventListener('afterprint', onAfterPrint)
      observer?.disconnect()
    }
  }, [key])

  return { activeId }
}
