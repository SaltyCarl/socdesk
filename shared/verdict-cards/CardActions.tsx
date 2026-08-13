// CardActions.tsx — the two copy-out buttons, a live canvas preview, and a
// Sonner-style copy toast.
//
// Buttons are labelled by TARGET ("Copy card" / "Copy text"), never by a verdict
// or an action (spec §3 honesty). copyCard reports the truth — it flips to
// "Downloaded" when the browser refuses an image clipboard write, and "Blocked"
// when neither path works, so the analyst is never told success on a silent
// failure. The toast mirrors that truth: it only appears on a real success or a
// real download, and names which one happened. The preview renders the exact
// deterministic PNG the button copies.

import { useCallback, useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { animate } from 'motion'
import type { VerdictData } from '../verdict'
import { Button } from '../ui'
import { DUR, EASE, prefersReducedMotion } from '../lib/motion'
import { copyCard, copyText } from './copy'
import { renderVerdictCanvas } from '../card/drawVerdict'
import type { CanvasTheme } from '../card/palette'

/* ---------- transient button status (immediate, in-place) ---------------- */

function useFlash(): [string | null, (msg: string) => void] {
  const [msg, setMsg] = useState<string | null>(null)
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)
  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current)
  }, [])
  const flash = (m: string) => {
    setMsg(m)
    if (timer.current) clearTimeout(timer.current)
    timer.current = setTimeout(() => setMsg(null), 1800)
  }
  return [msg, flash]
}

/* ---------- the copy toast ----------------------------------------------- */

interface ToastState {
  id: number
  message: string
}

/** A single, stacking-safe toast: each `show` replaces the current one and
 *  refreshes the auto-dismiss timer, so rapid actions never pile up. */
function useToast(duration = 2500): { toast: ToastState | null; show: (message: string) => void } {
  const [toast, setToast] = useState<ToastState | null>(null)
  const idRef = useRef(0)
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)
  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current)
  }, [])
  const show = useCallback(
    (message: string) => {
      idRef.current += 1
      setToast({ id: idRef.current, message })
      if (timer.current) clearTimeout(timer.current)
      timer.current = setTimeout(() => setToast(null), duration)
    },
    [duration],
  )
  return { toast, show }
}

function CheckGlyph() {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="none"
      className="size-4 shrink-0 stroke-[var(--accent)]"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M3.5 8.5 L6.5 11.5 L12.5 4.5" />
    </svg>
  )
}

/**
 * The toast surface. Portaled to <body> so a `position: fixed` element can't be
 * trapped inside an ancestor's stacking context and paint behind the page.
 * Motion runs through the sanctioned lib/motion tokens on WAAPI (no inline
 * styles, CSP-clean); reduced motion fades opacity only, with no slide. Chrome
 * is espresso/periwinkle + paper — never a verdict hue (it's a UI confirmation).
 */
function ToastHost({ toast }: { toast: ToastState | null }) {
  const ref = useRef<HTMLDivElement>(null)
  const [active, setActive] = useState<ToastState | null>(null)

  // Adopt a new / refreshed toast (keeps it mounted through its exit).
  useEffect(() => {
    if (toast) setActive(toast)
  }, [toast])

  // Enter (and re-enter on refresh) is a COMMITTED CSS keyframe on the panel
  // (`sd-rise`, keyed by toast id so each new toast replays it) — NOT a Motion
  // WAAPI tween. A WAAPI opacity animation over an `opacity-0` base reverts to
  // hidden the instant it finishes (fill:'none'), so the toast would flash then
  // vanish for the rest of its life. The resting state is now the committed
  // (visible) style; CSS only tweens the entrance toward it. Reduced motion is
  // handled by the global RM kill-switch (duration → 0 → instantly visible).

  // Exit when the toast clears, then unmount.
  useEffect(() => {
    if (toast || !active) return
    const el = ref.current
    if (!el) {
      setActive(null)
      return
    }
    const reduce = prefersReducedMotion()
    const controls = animate(
      el,
      reduce
        ? { opacity: [1, 0] }
        : { opacity: [1, 0], transform: ['translateY(0px)', 'translateY(16px)'] },
      { duration: DUR.base, ease: EASE.brandInOut },
    )
    let done = false
    controls.finished.then(() => !done && setActive(null)).catch(() => {})
    return () => {
      done = true
    }
  }, [toast, active])

  if (!active) return null
  return createPortal(
    <div className="pointer-events-none fixed inset-x-0 bottom-6 z-[100] flex justify-center px-4">
      <div
        ref={ref}
        key={active.id}
        role="status"
        aria-live="polite"
        className="pointer-events-auto inline-flex items-center gap-2.5 rounded-lg border border-line-bright bg-raised px-4 py-2.5 text-xs font-medium text-paper shadow-e3 animate-[sd-rise_var(--duration-base)_var(--ease-brand)_backwards]"
      >
        <CheckGlyph />
        {active.message}
      </div>
    </div>,
    document.body,
  )
}

/* ---------- the actions -------------------------------------------------- */

export function CardActions({ data, theme }: { data: VerdictData; theme?: CanvasTheme }) {
  const [cardMsg, flashCard] = useFlash()
  const [textMsg, flashText] = useFlash()
  const { toast, show } = useToast()

  const onCard = async () => {
    const r = await copyCard(data, theme ? { theme } : {})
    if (r === 'copied') {
      flashCard('Copied ✓')
      show('Card copied to clipboard')
    } else if (r === 'downloaded') {
      flashCard('Downloaded ↓')
      show('Card downloaded')
    } else {
      flashCard('Blocked')
    }
  }
  const onText = async () => {
    if (await copyText(data)) {
      flashText('Copied ✓')
      show('Text copied')
    } else {
      flashText('Blocked')
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      <Button variant="primary" size="sm" onClick={onCard}>
        {cardMsg ?? 'Copy card'}
      </Button>
      <Button variant="ghost" size="sm" onClick={onText}>
        {textMsg ?? 'Copy text'}
      </Button>
      <ToastHost toast={toast} />
    </div>
  )
}

/**
 * Render the deterministic copy-card PNG into the DOM for preview. Waits for the
 * brand faces so the canvas doesn't substitute a fallback, then swaps the drawn
 * canvas in. CSS (className) scales the intrinsic 2× bitmap down responsively.
 */
export function CardCanvasPreview({ data, theme }: { data: VerdictData; theme?: CanvasTheme }) {
  const holder = useRef<HTMLDivElement>(null)

  useEffect(() => {
    let cancelled = false
    const run = async () => {
      try {
        await document.fonts?.ready
      } catch {
        /* proceed with whatever faces are available */
      }
      if (cancelled || !holder.current) return
      let canvas: HTMLCanvasElement
      try {
        canvas = renderVerdictCanvas(data, theme ? { theme } : {})
      } catch {
        return
      }
      canvas.className = 'block h-auto w-full max-w-[420px] rounded-lg border border-line-bright shadow-e2'
      canvas.setAttribute('role', 'img')
      canvas.setAttribute('aria-label', `Escalation copy-card for ${data.indicator}`)
      holder.current.replaceChildren(canvas)
    }
    void run()
    return () => {
      cancelled = true
    }
  }, [data, theme])

  return <div ref={holder} className="flex justify-center" />
}
