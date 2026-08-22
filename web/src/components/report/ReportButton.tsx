// ReportButton — the real "report this indicator" affordance. Mounted in the
// EscalationCard header action row (via Lookup's reportSlot), at a quieter
// weight than the Copy-text ghost so hierarchy reads Copy card > Copy text >
// Report. Opens the report form, which itself gates on GitHub sign-in; the
// lookup/analyzer read path is unaffected.

import { useEffect, useState } from 'react'
import type { IndicatorType } from '@socdesk/shared/indicators'
import { markContributorSeen } from '../../lib/contributorSeen'
import { Button } from '../ui'
import { clearDraft, loadDraft, type ReportDraft } from './draft'
import { ReportDialog } from './ReportDialog'

function FlagGlyph() {
  return (
    <svg viewBox="0 0 24 24" fill="none" className="size-4 shrink-0" aria-hidden="true">
      <path
        d="M5 21V4m0 0h11l-2 4 2 4H5"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

export function ReportButton({ iocType, iocValue }: { iocType: IndicatorType; iocValue: string }) {
  const [open, setOpen] = useState(false)
  const [restored, setRestored] = useState<ReportDraft | null>(null)

  // Restore a draft stashed before the GitHub OAuth round trip: if the user
  // typed a report, hit sign-in, and came back, re-open the dialog with what
  // they had instead of losing it silently.
  useEffect(() => {
    const d = loadDraft(iocType, iocValue)
    if (d?.pendingOpen) {
      setRestored(d)
      setOpen(true)
      clearDraft(iocType, iocValue)
    }
  }, [iocType, iocValue])

  return (
    <>
      <Button
        variant="tertiary"
        size="sm"
        aria-label="Report this indicator"
        onClick={() => {
          markContributorSeen()
          setOpen(true)
        }}
      >
        <FlagGlyph />
        Report
      </Button>
      {open && (
        <ReportDialog
          iocType={iocType}
          iocValue={iocValue}
          open={open}
          initialDraft={restored ?? undefined}
          onClose={() => setOpen(false)}
        />
      )}
    </>
  )
}
