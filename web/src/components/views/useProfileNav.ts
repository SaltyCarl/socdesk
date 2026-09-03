// useProfileNav.ts — the profile's jump-nav model + the DOM wiring that makes the
// native <details> accordions deep-linkable, print-whole, and scrollspy-aware.
//
// SSR-SAFE BY CONTRACT: ActorProfile is rendered via renderToStaticMarkup in the
// node-env test harness, so NOTHING here may touch window / document /
// IntersectionObserver during render or in a useState initializer. Every DOM
// access lives inside useEffect (which never runs under renderToStaticMarkup).

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

/** `#huntpack` → `huntpack`; a bare `#` or empty string → null. */
export function targetIdFromHash(hash: string): string | null {
  const id = hash.replace(/^#/, '').trim()
  return id ? id : null
}

/** Opens the `<details>` a fragment targets and scrolls to it (used on mount and
 *  on every hashchange). No-op when the target isn't a details (decision-layer
 *  anchors are plain sections). Exported for direct unit reasoning; DOM-touching,
 *  so only ever called from inside the effect / event handlers. */
function openAndScrollTo(id: string | null): void {
  if (!id) return
  const el = document.getElementById(id)
  if (!el) return
  if (el instanceof HTMLDetailsElement) el.open = true
  el.scrollIntoView()
}

/**
 * Wires deep-link-open + print-whole + scrollspy for the profile.
 * Returns the id of the section currently in view (`''` until the observer
 * fires, and always `''` under SSR — the nav simply renders with no active item).
 *
 * The caller MUST pass a STABLE `sections` reference (memoize on the existence
 * flags) — the effect re-subscribes only when the set of section ids changes.
 */
export function useProfileNav(sections: NavSection[]): { activeId: string } {
  const [activeId, setActiveId] = useState('')
  const key = sections.map((s) => s.id).join(',')

  useEffect(() => {
    // (1) deep-link: open + scroll to the hash target now and on every change.
    const onHashChange = () => openAndScrollTo(targetIdFromHash(window.location.hash))
    onHashChange()
    window.addEventListener('hashchange', onHashChange)

    // (2) print: open every collapsed reference section, restore afterwards.
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

    // (3) scrollspy: the topmost section crossing below the sticky stack wins.
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
      window.removeEventListener('hashchange', onHashChange)
      window.removeEventListener('beforeprint', onBeforePrint)
      window.removeEventListener('afterprint', onAfterPrint)
      observer?.disconnect()
    }
  }, [key])

  return { activeId }
}
