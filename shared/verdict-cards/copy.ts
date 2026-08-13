// copy.ts — the two copy-out actions the escalation card exposes.
//
//   Copy card → a client-facing PNG on the clipboard (the visual artifact).
//   Copy text → the attributed plain-text block (composeEscalation) — survives
//               plain-text ticket queues and mail-filters, travels alongside
//               the image for deliverability + accessibility.
//
// Both are feature-detected and NEVER throw. copyCard returns the TRUTH about
// what happened (this project has shipped a button that claimed success while
// the clipboard silently rejected the write), so the UI can tell the analyst
// whether the image is really on the clipboard or was downloaded instead.

import type { VerdictData } from '../verdict'
import { composeEscalation } from '../verdict'
import { renderVerdictCanvas, type DrawOptions } from '../card/drawVerdict'

export type CopyCardResult = 'copied' | 'downloaded' | 'failed'

function toBlob(canvas: HTMLCanvasElement): Promise<Blob | null> {
  return new Promise((resolve) => canvas.toBlob((b) => resolve(b), 'image/png'))
}

/** Ensure the self-hosted brand faces are resolved before the canvas is painted
 *  (canvas substitutes a fallback face otherwise). Best-effort. */
async function fontsReady(): Promise<void> {
  try {
    await document.fonts?.ready
  } catch {
    /* no FontFaceSet — proceed with whatever is available */
  }
}

/**
 * Render the card and put it on the clipboard as a PNG. Falls back to a file
 * download when the browser refuses image clipboard writes (Firefox, insecure
 * origin, denied permission). Returns which path actually succeeded.
 */
export async function copyCard(data: VerdictData, opts: DrawOptions = {}): Promise<CopyCardResult> {
  await fontsReady()
  let canvas: HTMLCanvasElement
  try {
    canvas = renderVerdictCanvas(data, opts)
  } catch {
    return 'failed'
  }

  try {
    if (navigator.clipboard?.write && typeof ClipboardItem !== 'undefined') {
      const blob = await toBlob(canvas)
      if (blob) {
        await navigator.clipboard.write([new ClipboardItem({ 'image/png': blob })])
        return 'copied'
      }
    }
  } catch {
    /* fall through to download */
  }

  return (await downloadCanvas(canvas, data.indicator)) ? 'downloaded' : 'failed'
}

async function downloadCanvas(canvas: HTMLCanvasElement, indicator: string): Promise<boolean> {
  const blob = await toBlob(canvas)
  if (!blob) return false
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `indicator-${indicator.replace(/[^\w.-]+/g, '_').slice(0, 60)}.png`
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
  return true
}

/** Copy the attributed plain-text escalation block. Returns success. */
export async function copyText(data: VerdictData, now?: Date): Promise<boolean> {
  const text = composeEscalation(data, now)
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text)
      return true
    }
  } catch {
    /* clipboard denied */
  }
  return false
}
