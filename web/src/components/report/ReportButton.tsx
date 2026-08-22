// ReportButton — the real "report this indicator" affordance. Mounted in the
// EscalationCard header action row (via Lookup's reportSlot), at a quieter
// weight than the Copy-text ghost so hierarchy reads Copy card > Copy text >
// Report. Opens the report form, which itself gates on GitHub sign-in; the
// lookup/analyzer read path is unaffected.

import { useState } from 'react'
import type { IndicatorType } from '@socdesk/shared/indicators'
import { markContributorSeen } from '../../lib/contributorSeen'
import { Button } from '../ui'
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
        <ReportDialog iocType={iocType} iocValue={iocValue} open={open} onClose={() => setOpen(false)} />
      )}
    </>
  )
}
