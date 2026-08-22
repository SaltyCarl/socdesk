import { useEffect, useId, useRef, useState } from 'react'
import { animate } from 'motion'
import { cx } from '@socdesk/shared/lib/cx'
import { DUR, EASE, prefersReducedMotion } from '@socdesk/shared/lib/motion'
import { Card, Divider, MicroLabel } from '@socdesk/shared/ui'
import { navigate } from '../palette/commands'
import { useSession } from '../../lib/useSession'
import { isContributorSeen } from '../../lib/contributorSeen'
import { accountView } from '../../lib/accountChrome'

/**
 * AccountControl — the quiet-until-relevant contributor entry (Part A). Invisible
 * to the 99% who only look up: an unseen browser renders no DOM and fires no
 * session probe. A returning contributor sees a "Sign in" link (signed out) or
 * an @handle chip + menu (signed in). Signing in / out never touches the read
 * loop. contributorSeen outlives sign-out, so the quiet link returns.
 */
export function AccountControl() {
  const [seen, setSeen] = useState(false)
  useEffect(() => setSeen(isContributorSeen()), [])
  if (!seen) return null // no DOM, and (crucially) AccountMenu's probe never mounts
  return <AccountMenu />
}

const signInHref = () =>
  `/api/auth/github/start?return=${encodeURIComponent(location.pathname + location.hash)}`

function AccountMenu() {
  const session = useSession()
  const view = accountView(true, session.status)
  const [open, setOpen] = useState(false)
  const menuId = useId()
  const wrapRef = useRef<HTMLDivElement>(null)
  const panelRef = useRef<HTMLDivElement>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)

  // Dismiss on Escape / outside pointer; move focus to the first item on open;
  // return focus to the trigger on close. Same contract as MobileNav.
  useEffect(() => {
    if (!open) return
    const raf = requestAnimationFrame(() =>
      panelRef.current?.querySelector<HTMLElement>('[role="menuitem"]')?.focus(),
    )
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        setOpen(false)
        triggerRef.current?.focus()
      }
    }
    const onPointer = (e: PointerEvent) => {
      if (wrapRef.current?.contains(e.target as Node)) return
      setOpen(false)
      triggerRef.current?.focus()
    }
    document.addEventListener('keydown', onKey)
    document.addEventListener('pointerdown', onPointer)
    return () => {
      cancelAnimationFrame(raf)
      document.removeEventListener('keydown', onKey)
      document.removeEventListener('pointerdown', onPointer)
    }
  }, [open])

  // Panel enter (WAAPI, reduced-motion-safe) — same sanctioned lib/motion path.
  useEffect(() => {
    const panel = panelRef.current
    if (!open || !panel || prefersReducedMotion()) return
    animate(
      panel,
      { opacity: [0, 1], transform: ['translateY(-6px)', 'translateY(0px)'] },
      { duration: DUR.base, ease: EASE.brand },
    )
  }, [open])

  const signOut = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' })
    } catch {
      /* best-effort; the cookie clears server-side */
    }
    setOpen(false)
    // Optimistic — stay on page; contributorSeen persists so "Sign in" returns.
    location.reload()
  }

  if (view === 'none') return null

  if (view === 'signin') {
    return (
      <a
        href={signInHref()}
        className="font-mono text-micro font-semibold uppercase tracking-label text-muted outline-offset-2 transition-colors duration-150 ease-brand hover:text-paper focus-visible:outline-2 focus-visible:outline-accent"
      >
        Sign in
      </a>
    )
  }

  const handle = session.login ? `@${session.login}` : 'Account'
  return (
    <div ref={wrapRef} className="relative">
      <button
        ref={triggerRef}
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={menuId}
        aria-label={`Account menu, signed in as ${session.login ?? 'contributor'}`}
        className={cx(
          'inline-flex h-8 items-center gap-1.5 rounded-md border border-line bg-panel px-2.5 font-mono text-micro font-semibold text-muted',
          'outline-offset-2 transition-colors duration-150 ease-brand hover:border-line-bright hover:text-paper focus-visible:outline-2 focus-visible:outline-accent',
        )}
      >
        <span className="text-accent">{handle}</span>
        <Chevron open={open} />
      </button>

      {open && (
        <div ref={panelRef} className="absolute right-0 top-full z-40 mt-1.5 w-56">
          <Card padding="sm">
            <div id={menuId} role="menu" aria-label="Account" className="flex flex-col gap-1">
              <div className="flex flex-col gap-0.5 px-1 pb-1">
                <MicroLabel tone="faint">Signed in with GitHub</MicroLabel>
                <span className="font-mono text-xs font-semibold text-paper">{handle}</span>
              </div>
              <Divider />
              <a
                href="/reports"
                role="menuitem"
                onClick={(e) => {
                  if (e.button === 0 && !e.metaKey && !e.ctrlKey && !e.shiftKey && !e.altKey) {
                    e.preventDefault()
                    navigate('/reports')
                    setOpen(false)
                  }
                }}
                className="rounded-md px-2 py-1.5 font-sans text-xs text-muted outline-offset-[-2px] transition-colors duration-150 ease-brand hover:bg-panel-soft hover:text-paper focus-visible:outline-2 focus-visible:outline-accent"
              >
                My reports
              </a>
              <button
                type="button"
                role="menuitem"
                onClick={signOut}
                className="rounded-md px-2 py-1.5 text-left font-sans text-xs text-muted outline-offset-[-2px] transition-colors duration-150 ease-brand hover:bg-panel-soft hover:text-paper focus-visible:outline-2 focus-visible:outline-accent"
              >
                Sign out
              </button>
            </div>
          </Card>
        </div>
      )}
    </div>
  )
}

function Chevron({ open }: { open: boolean }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      className={cx('size-3.5 shrink-0 transition-transform duration-150 ease-brand', open && 'rotate-180')}
      aria-hidden="true"
    >
      <path d="M6 9l6 6 6-6" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}
