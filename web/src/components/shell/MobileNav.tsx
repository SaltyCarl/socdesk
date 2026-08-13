import {
  useEffect,
  useId,
  useRef,
  useState,
  type MouseEvent as ReactMouseEvent,
} from 'react'
import { createPortal } from 'react-dom'
import { animate } from 'motion'
import { cx } from '@socdesk/shared/lib/cx'
import { DUR, EASE, prefersReducedMotion } from '@socdesk/shared/lib/motion'
import type { NavItem } from '../ui'

/**
 * MobileNav — the phone-width menu. Shell-owned so `ui/Topbar` stays
 * untouched; it rides the Topbar's right slot and only appears at the
 * breakpoint where the inline nav links hide (`md:hidden`, mirroring
 * Topbar's `md:flex` nav). Desktop is unchanged.
 *
 * Pattern: a WAI-ARIA disclosure — the hamburger carries
 * `aria-expanded` + `aria-controls`, and reveals a slide-down sheet
 * (anchored under the h-14 topbar) of the SAME `items`, rendered as real
 * `<a>` links. Normal-click navigates via pushState + a synthetic
 * popstate (the SPA path App.tsx's `useRoute` listens for) and closes the
 * sheet; modifier-clicks fall through to the browser (open-in-new-tab).
 *
 * Dismiss on: item-select · Escape · outside pointer · crossing to
 * desktop. Focus moves to the first link on open and returns to the
 * trigger on close. Enter/exit run on WAAPI (same sanctioned Motion.dev
 * path), skipped under reduced motion. Tailwind only, zero inline styles.
 */

/** SPA navigation — matches the desktop mechanism (href + pushState/popstate). */
function navigate(href: string): void {
  if (href.startsWith('#')) {
    window.location.hash = href
    return
  }
  window.history.pushState({}, '', href)
  window.dispatchEvent(new PopStateEvent('popstate'))
}

export function MobileNav({ items = [] }: { items?: NavItem[] }) {
  const [open, setOpen] = useState(false)
  const [mounted, setMounted] = useState(false)
  const panelId = useId()
  const panelRef = useRef<HTMLDivElement>(null)
  const btnRef = useRef<HTMLButtonElement>(null)

  const show = () => {
    setMounted(true)
    setOpen(true)
  }
  const close = () => setOpen(false)

  // Enter: focus the first link. The reveal is a DECLARATIVE CSS keyframe
  // (`sd-rise`, applied via the panel's class) — NOT a script-driven WAAPI
  // animation. A fixed element whose reveal is owned by Motion's
  // `animate()` (default fill:'none') reverts + leaves a stale, non-painting
  // composited layer the instant it finishes, so the open sheet flashes then
  // vanishes. Here the OPEN state is the element's committed style (visible
  // by default), and CSS only tweens the entrance toward it. Reduced-motion
  // still shows the sheet (the global RM kill-switch zeroes the duration).
  useEffect(() => {
    if (!open || !mounted) return
    const panel = panelRef.current
    const raf = requestAnimationFrame(() =>
      panel?.querySelector<HTMLAnchorElement>('a')?.focus(),
    )
    return () => cancelAnimationFrame(raf)
  }, [open, mounted])

  // Exit: animate out, then unmount + return focus to the trigger.
  useEffect(() => {
    if (open || !mounted) return
    const panel = panelRef.current
    const done = () => {
      setMounted(false)
      btnRef.current?.focus()
    }
    if (!panel || prefersReducedMotion()) {
      done()
      return
    }
    const controls = animate(
      panel,
      { opacity: [1, 0], transform: ['translateY(0px)', 'translateY(-6px)'] },
      { duration: DUR.fast, ease: EASE.brandInOut },
    )
    controls.finished.then(done).catch(done)
  }, [open, mounted])

  // Dismiss on Escape / outside pointer while open.
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        setOpen(false)
      }
    }
    const onPointer = (e: PointerEvent) => {
      const t = e.target as Node
      if (panelRef.current?.contains(t) || btnRef.current?.contains(t)) return
      setOpen(false)
    }
    document.addEventListener('keydown', onKey)
    document.addEventListener('pointerdown', onPointer)
    return () => {
      document.removeEventListener('keydown', onKey)
      document.removeEventListener('pointerdown', onPointer)
    }
  }, [open])

  // Auto-close when the viewport grows to desktop (nav links reappear).
  useEffect(() => {
    const mq = window.matchMedia('(min-width: 768px)')
    const onChange = () => {
      if (mq.matches) setOpen(false)
    }
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [])

  const onItemClick = (e: ReactMouseEvent<HTMLAnchorElement>, item: NavItem) => {
    if (item.href && e.button === 0 && !e.metaKey && !e.ctrlKey && !e.shiftKey && !e.altKey) {
      e.preventDefault()
      navigate(item.href)
    }
    setOpen(false)
  }

  return (
    <>
      <button
        ref={btnRef}
        type="button"
        onClick={() => (open ? close() : show())}
        aria-expanded={open}
        aria-controls={panelId}
        aria-label={open ? 'Close menu' : 'Open menu'}
        className={cx(
          'inline-flex size-9 items-center justify-center rounded-md border border-line bg-field text-muted md:hidden',
          'transition-colors duration-150 ease-brand hover:border-line-bright hover:text-paper',
          'outline-offset-2 focus-visible:outline-2 focus-visible:outline-accent',
        )}
      >
        {open ? <CloseGlyph /> : <MenuGlyph />}
      </button>

      {mounted &&
        // Portaled to <body>: rendered in place, these position:fixed overlays are
        // trapped inside the Topbar's stacking context (a sticky, backdrop-filtered
        // bar) and paint BEHIND `main`. As a direct body child the panel joins the
        // root stacking context, so its z-40 wins over the page content.
        createPortal(
          <div className="md:hidden">
            <div
              aria-hidden="true"
              className="fixed inset-0 top-14 z-30 bg-ink/60"
            />
            <div
              ref={panelRef}
              id={panelId}
              className="fixed inset-x-0 top-14 z-40 border-b border-line bg-raised shadow-e2 animate-[sd-rise_var(--duration-base)_var(--ease-brand)_backwards]"
            >
              <nav
                aria-label="Primary"
                className="mx-auto flex max-w-6xl flex-col gap-0.5 px-3 py-3"
              >
                {items.map((item) => (
                  <a
                    key={item.label}
                    href={item.href ?? '#'}
                    aria-current={item.active ? 'page' : undefined}
                    onClick={(e) => onItemClick(e, item)}
                    className={cx(
                      'flex items-center rounded-md border-l-2 px-3 py-2.5 font-sans text-base transition-colors duration-150 ease-brand',
                      'outline-offset-[-2px] focus-visible:outline-2 focus-visible:outline-accent',
                      item.active
                        ? 'border-accent bg-[var(--tint-accent)] text-paper'
                        : 'border-transparent text-muted hover:bg-panel-soft hover:text-paper',
                    )}
                  >
                    {item.label}
                  </a>
                ))}
              </nav>
            </div>
          </div>,
          document.body,
        )}
    </>
  )
}

/* -- icons (inline SVG, currentColor — no new deps, no inline style) -- */

function MenuGlyph() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M4 7h16M4 12h16M4 17h16"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinecap="round"
      />
    </svg>
  )
}

function CloseGlyph() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M6 6l12 12M18 6L6 18"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinecap="round"
      />
    </svg>
  )
}
