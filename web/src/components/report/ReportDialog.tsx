// ReportDialog — the modal report form, rebuilt on the one overlay pattern the
// app already has: a native <dialog> + showModal() + WAAPI motion via
// shared/lib/motion, Escape/backdrop close, native focus trap. Signed-out
// analysts see a non-accusatory sign-in gate; signed-in analysts get the form
// (Task 8). The lookup/analyzer read path is untouched.

import { useEffect, useRef } from 'react'
import { animate } from 'motion'
import { DUR, EASE, prefersReducedMotion } from '@socdesk/shared/lib/motion'
import type { IndicatorType } from '@socdesk/shared/indicators'
import { Button, MicroLabel } from '../ui'
import { useSession } from '../../lib/useSession'
import { dialogView } from './dialogView'

export interface ReportDialogProps {
  iocType: IndicatorType
  iocValue: string
  open: boolean
  onClose: () => void
}

export function ReportDialog({ iocType, iocValue, open, onClose }: ReportDialogProps) {
  const session = useSession()
  const dialogRef = useRef<HTMLDialogElement>(null)
  const panelRef = useRef<HTMLDivElement>(null)
  const view = dialogView(session.status)

  useEffect(() => {
    const dlg = dialogRef.current
    const panel = panelRef.current
    if (!dlg) return
    if (open) {
      if (!dlg.open) {
        try {
          dlg.showModal()
        } catch {
          /* already open (StrictMode double-invoke) */
        }
      }
      if (panel && !prefersReducedMotion()) {
        animate(
          panel,
          { opacity: [0, 1], transform: ['translateY(-8px) scale(0.985)', 'translateY(0px) scale(1)'] },
          { duration: DUR.base, ease: EASE.brand },
        )
      }
    } else if (dlg.open) {
      dlg.close()
    }
  }, [open])

  const signInHref = `/api/auth/github/start?return=${encodeURIComponent(
    location.pathname + location.hash,
  )}`

  return (
    <dialog
      ref={dialogRef}
      aria-label={`Report ${iocValue}`}
      onCancel={(e) => {
        e.preventDefault()
        onClose()
      }}
      onClick={(e) => {
        if (e.target === dialogRef.current) onClose()
      }}
      className="mx-auto mt-[14vh] w-[min(28rem,calc(100%-2rem))] max-w-full bg-transparent p-0 text-paper outline-none backdrop:bg-ink/75 backdrop:backdrop-blur-[3px] max-sm:mt-[8vh]"
    >
      <div
        ref={panelRef}
        className="flex w-full flex-col gap-3 rounded-lg border border-line bg-raised p-5 shadow-e3"
      >
        <div className="flex items-center justify-between gap-4">
          <MicroLabel tone="accent">Report indicator</MicroLabel>
          <span className="break-all font-mono text-micro text-muted">{iocValue}</span>
        </div>

        {view === 'loading' && <p className="text-xs text-muted">Checking your session…</p>}

        {view === 'gate' && (
          <div className="flex flex-col gap-3">
            <p className="text-xs leading-relaxed text-muted">
              Reporting needs a quick GitHub sign-in (so reports are attributable). Look-ups never do.
            </p>
            <div className="flex items-center gap-2">
              <Button variant="primary" size="sm" onClick={() => (location.href = signInHref)}>
                Sign in with GitHub
              </Button>
              <Button variant="ghost" size="sm" onClick={onClose}>
                Cancel
              </Button>
            </div>
          </div>
        )}

        {view === 'fill' && (
          <p className="text-xs text-muted" data-testid="report-fill-placeholder">
            {iocType} form — added in Task 8.
          </p>
        )}
      </div>
    </dialog>
  )
}
