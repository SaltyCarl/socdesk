// CardActions.tsx — the two copy-out buttons + a live canvas preview.
//
// Buttons are labelled by TARGET ("Copy card" / "Copy text"), never by a verdict
// or an action (spec §3 honesty). copyCard reports the truth — it flips to
// "Downloaded" when the browser refuses an image clipboard write, and "Blocked"
// when neither path works, so the analyst is never told success on a silent
// failure. The preview renders the exact deterministic PNG the button copies.

import { useEffect, useRef, useState } from 'react'
import type { VerdictData } from '../../lib/verdict'
import { Button } from '../ui'
import { copyCard, copyText } from './copy'
import { renderVerdictCanvas } from './drawVerdict'
import type { CanvasTheme } from './palette'

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

export function CardActions({ data, theme }: { data: VerdictData; theme?: CanvasTheme }) {
  const [cardMsg, flashCard] = useFlash()
  const [textMsg, flashText] = useFlash()

  const onCard = async () => {
    const r = await copyCard(data, theme ? { theme } : {})
    flashCard(r === 'copied' ? 'Copied ✓' : r === 'downloaded' ? 'Downloaded ↓' : 'Blocked')
  }
  const onText = async () => {
    flashText((await copyText(data)) ? 'Copied ✓' : 'Blocked')
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      <Button variant="primary" size="sm" onClick={onCard}>
        {cardMsg ?? 'Copy card'}
      </Button>
      <Button variant="ghost" size="sm" onClick={onText}>
        {textMsg ?? 'Copy text'}
      </Button>
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
