// ReportDialog — the modal report form, rebuilt on the one overlay pattern the
// app already has: a native <dialog> + showModal() + WAAPI motion via
// shared/lib/motion, Escape/backdrop close, native focus trap. Signed-out
// analysts see a non-accusatory sign-in gate; signed-in analysts get the
// category/evidence/comment form + Turnstile, which POSTs to /api/report and
// walks the full terminal state machine (reportOutcome).
//
// ADAPTATION: MicroLabel's `as` prop is typed 'span' | 'p' | 'div' only (see
// shared/ui/MicroLabel.tsx) — it does NOT accept 'label'. Each field label is
// instead a real <label htmlFor=...> wrapping a plain MicroLabel, associated
// with the control via matching id (the controls also carry an explicit
// aria-label, so the accessible name is set either way; the <label> adds a
// genuine semantic association + click-to-focus).

import { useEffect, useRef, useState } from 'react'
import { animate } from 'motion'
import { DUR, EASE, prefersReducedMotion } from '@socdesk/shared/lib/motion'
import type { IndicatorType } from '@socdesk/shared/indicators'
import { Button, MicroLabel } from '../ui'
import { useSession } from '../../lib/useSession'
import { dialogView } from './dialogView'
import { reportOutcome, type ReportOutcome } from './reportOutcome'
import { SUCCESS_ICON_CLASS, SUCCESS_TEXT_CLASS } from './reportChrome'

const CATEGORIES = [
  'brute-force', 'ssh', 'port-scan', 'web-app-attack', 'phishing',
  'malware-c2', 'scanner', 'spam', 'exploited-host', 'other',
]
const EVIDENCE_MAX = 2000
const COMMENT_MAX = 1000

export interface ReportDialogProps {
  iocType: IndicatorType
  iocValue: string
  open: boolean
  onClose: () => void
}

function CheckGlyph() {
  return (
    <svg viewBox="0 0 16 16" fill="none" className={SUCCESS_ICON_CLASS} strokeWidth={2}
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M3.5 8.5 L6.5 11.5 L12.5 4.5" />
    </svg>
  )
}

function counterClass(n: number, max: number): string {
  return n > max * 0.9 ? 'text-verdict-amber' : 'text-muted'
}

export function ReportDialog({ iocType, iocValue, open, onClose }: ReportDialogProps) {
  const session = useSession()
  const dialogRef = useRef<HTMLDialogElement>(null)
  const panelRef = useRef<HTMLDivElement>(null)
  const widgetRef = useRef<HTMLDivElement>(null)
  const tokenRef = useRef<string>('')
  const widgetIdRef = useRef<string>('')

  const [category, setCategory] = useState('')
  const [evidence, setEvidence] = useState('')
  const [comment, setComment] = useState('')
  const [touchedEvidence, setTouchedEvidence] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [outcome, setOutcome] = useState<ReportOutcome | null>(null)

  // A POST-time 401 (`expired`) must FORCE the sign-in gate: the mount-time
  // session probe still reads 'in', so dialogView() alone would leave us on
  // 'fill' with no matching render branch (an empty dialog). Expired overrides.
  const view = outcome?.kind === 'expired' ? 'gate' : dialogView(session.status)

  // Native dialog open/close + panel motion (CommandPalette pattern).
  useEffect(() => {
    const dlg = dialogRef.current
    const panel = panelRef.current
    if (!dlg) return
    if (open) {
      if (!dlg.open) {
        try { dlg.showModal() } catch { /* already open */ }
      }
      if (panel && !prefersReducedMotion()) {
        animate(panel,
          { opacity: [0, 1], transform: ['translateY(-8px) scale(0.985)', 'translateY(0px) scale(1)'] },
          { duration: DUR.base, ease: EASE.brand })
      }
    } else if (dlg.open) {
      dlg.close()
    }
  }, [open])

  // Turnstile — load + render once signed in and on the fill screen.
  useEffect(() => {
    if (!open || view !== 'fill' || !widgetRef.current) return
    if (!document.querySelector('script[src^="https://challenges.cloudflare.com/turnstile"]')) {
      const s = document.createElement('script')
      s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js'
      s.async = true
      document.head.appendChild(s)
    }
    const id = setInterval(() => {
      // @ts-expect-error injected global
      if (window.turnstile && widgetRef.current && !widgetRef.current.dataset.rendered) {
        widgetRef.current.dataset.rendered = '1'
        // @ts-expect-error injected global
        widgetIdRef.current = window.turnstile.render(widgetRef.current, {
          sitekey: import.meta.env.VITE_TURNSTILE_SITEKEY,
          appearance: 'interaction-only',
          size: 'compact',
          callback: (t: string) => { tokenRef.current = t },
        })
        clearInterval(id)
      }
    }, 200)
    return () => clearInterval(id)
  }, [open, view])

  const resetTurnstile = () => {
    // @ts-expect-error injected global
    if (window.turnstile && widgetIdRef.current) window.turnstile.reset(widgetIdRef.current)
    tokenRef.current = ''
  }

  const submit = async () => {
    setTouchedEvidence(true)
    if (!evidence.trim() || !category) return // no request; inline messages handle it
    setSubmitting(true)
    setOutcome(null)
    let status = 0
    let body: { deduped?: boolean; error?: string } | null = null
    try {
      const r = await fetch('/api/report', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          ioc_type: iocType, ioc_value: iocValue, category, evidence, comment,
          turnstileToken: tokenRef.current,
        }),
      })
      status = r.status
      body = await r.json().catch(() => null)
    } catch {
      status = 0
    }
    const next = reportOutcome(status, body)
    setSubmitting(false)
    setOutcome(next)
    if (next.kind === 'turnstile' || next.kind === 'error' || next.kind === 'invalid') resetTurnstile()
  }

  const signInHref = `/api/auth/github/start?return=${encodeURIComponent(location.pathname + location.hash)}`
  const evidenceEmpty = touchedEvidence && !evidence.trim()

  return (
    <dialog
      ref={dialogRef}
      aria-label={`Report ${iocValue}`}
      onCancel={(e) => { e.preventDefault(); onClose() }}
      onClick={(e) => { if (e.target === dialogRef.current) onClose() }}
      className="mx-auto mt-[14vh] w-[min(28rem,calc(100%-2rem))] max-w-full bg-transparent p-0 text-paper outline-none backdrop:bg-ink/75 backdrop:backdrop-blur-[3px] max-sm:mt-[8vh]"
    >
      <div ref={panelRef} className="flex w-full flex-col gap-3 rounded-lg border border-line bg-raised p-5 shadow-e3">
        <div className="flex items-center justify-between gap-4">
          <MicroLabel tone="accent">Report indicator</MicroLabel>
          <span className="break-all font-mono text-micro text-muted">{iocValue}</span>
        </div>

        {view === 'loading' && <p className="text-xs text-muted">Checking your session…</p>}

        {view === 'gate' && (
          <div className="flex flex-col gap-3">
            <p className="text-xs leading-relaxed text-muted">
              {outcome?.kind === 'expired'
                ? 'Your session expired. Sign in again — your draft is kept.'
                : 'Reporting needs a quick GitHub sign-in (so reports are attributable). Look-ups never do.'}
            </p>
            <div className="flex items-center gap-2">
              <Button variant="primary" size="sm" onClick={() => (location.href = signInHref)}>
                Sign in with GitHub
              </Button>
              <Button variant="ghost" size="sm" onClick={onClose}>Cancel</Button>
            </div>
          </div>
        )}

        {view === 'fill' && outcome?.kind === 'queued' && (
          <div className="flex flex-col gap-3" role="status" aria-live="polite">
            <p className={`inline-flex items-center gap-2 text-sm font-medium ${SUCCESS_TEXT_CLASS}`}>
              <CheckGlyph /> Queued for review — thanks.
            </p>
            <div className="flex items-center gap-2">
              <Button variant="primary" size="sm" onClick={() => { location.href = '/reports' }}>
                View my reports
              </Button>
              <Button variant="ghost" size="sm" onClick={onClose}>Done</Button>
            </div>
          </div>
        )}

        {view === 'fill' && outcome?.kind === 'deduped' && (
          <div className="flex flex-col gap-3" role="status" aria-live="polite">
            <p className={`inline-flex items-center gap-2 text-sm font-medium ${SUCCESS_TEXT_CLASS}`}>
              <CheckGlyph /> Already reported — you have an open report for this indicator.
            </p>
            <div className="flex items-center gap-2">
              <Button variant="primary" size="sm" onClick={() => { location.href = '/reports' }}>
                View my reports
              </Button>
              <Button variant="ghost" size="sm" onClick={onClose}>Done</Button>
            </div>
          </div>
        )}

        {view === 'fill' && outcome?.kind === 'banned' && (
          <p role="status" aria-live="polite"
             className="rounded-md border border-[var(--edge-gold)] px-3 py-2 text-xs text-verdict-amber">
            This account cannot submit reports.
          </p>
        )}

        {view === 'fill' && outcome?.kind === 'capped' && (
          <p role="status" aria-live="polite"
             className="rounded-md border border-[var(--edge-gold)] px-3 py-2 text-xs text-verdict-amber">
            Daily limit reached (25/day). Try again tomorrow.
          </p>
        )}

        {view === 'fill' && (!outcome || ['turnstile', 'invalid', 'error'].includes(outcome.kind)) && (
          <div className="flex flex-col gap-3">
            <div className="flex flex-col gap-1">
              <label htmlFor="report-category">
                <MicroLabel tone="muted">Category</MicroLabel>
              </label>
              <select
                id="report-category"
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                aria-label="Report category"
                className="rounded-md border border-line bg-field px-2 py-1.5 font-sans text-xs text-paper outline-offset-2 focus-visible:outline-2 focus-visible:outline-accent"
              >
                <option value="" disabled>Select a category</option>
                {CATEGORIES.map((c) => (<option key={c} value={c}>{c}</option>))}
              </select>
            </div>

            <div className="flex flex-col gap-1">
              <div className="flex items-baseline justify-between">
                <label htmlFor="report-evidence">
                  <MicroLabel tone="muted">Evidence</MicroLabel>
                </label>
                <span className={`font-mono text-micro ${counterClass(evidence.length, EVIDENCE_MAX)}`}>
                  {evidence.length} / {EVIDENCE_MAX}
                </span>
              </div>
              <textarea
                id="report-evidence"
                value={evidence}
                onChange={(e) => setEvidence(e.target.value.slice(0, EVIDENCE_MAX))}
                onBlur={() => setTouchedEvidence(true)}
                required
                rows={3}
                aria-label="Evidence — what you observed"
                placeholder="What you observed — don't paste sensitive/internal data"
                className="rounded-md border border-line bg-field px-2 py-1.5 font-mono text-xs text-paper outline-offset-2 placeholder:text-faint focus-visible:outline-2 focus-visible:outline-accent"
              />
              {evidenceEmpty && <p className="text-micro text-muted">Evidence is required.</p>}
            </div>

            <div className="flex flex-col gap-1">
              <div className="flex items-baseline justify-between">
                <label htmlFor="report-comment">
                  <MicroLabel tone="muted">Comment (optional)</MicroLabel>
                </label>
                <span className={`font-mono text-micro ${counterClass(comment.length, COMMENT_MAX)}`}>
                  {comment.length} / {COMMENT_MAX}
                </span>
              </div>
              <input
                id="report-comment"
                value={comment}
                onChange={(e) => setComment(e.target.value.slice(0, COMMENT_MAX))}
                aria-label="Optional comment"
                placeholder="Anything else worth noting"
                className="rounded-md border border-line bg-field px-2 py-1.5 font-sans text-xs text-paper outline-offset-2 placeholder:text-faint focus-visible:outline-2 focus-visible:outline-accent"
              />
            </div>

            <div className="flex flex-col gap-1">
              <MicroLabel tone="muted">Verification</MicroLabel>
              <div ref={widgetRef} className="min-h-[65px]" />
            </div>

            {outcome?.kind === 'turnstile' && (
              <p role="status" aria-live="polite" className="text-xs text-muted">
                Verification failed — please complete the challenge and resubmit.
              </p>
            )}
            {outcome?.kind === 'invalid' && (
              <p role="status" aria-live="polite" className="text-xs text-muted">
                {outcome.field === 'evidence'
                  ? 'Evidence is required.'
                  : 'That report was rejected — check the indicator and try again.'}
              </p>
            )}
            {outcome?.kind === 'error' && (
              <p role="status" aria-live="polite" className="text-xs text-muted">
                Something went wrong — your draft is kept. Try again.
              </p>
            )}

            <div className="flex items-center gap-2">
              <Button variant="primary" size="sm" disabled={submitting} onClick={submit}>
                {submitting ? 'Submitting…' : 'Submit report'}
              </Button>
              <Button variant="ghost" size="sm" onClick={onClose}>Cancel</Button>
            </div>
          </div>
        )}
      </div>
    </dialog>
  )
}
