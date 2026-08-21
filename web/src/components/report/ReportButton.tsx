// ReportButton — the low-key "report this indicator" affordance mounted on
// the resolved escalation card. Opens the report form inline (which itself
// gates on GitHub sign-in); the lookup/analyzer read path is unaffected —
// this is purely additive.

import { useState } from 'react'
import type { IndicatorType } from '@socdesk/shared/indicators'
import { ReportForm } from './ReportForm'

export function ReportButton({ iocType, iocValue }: { iocType: IndicatorType; iocValue: string }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="font-mono text-micro text-faint transition-colors hover:text-paper"
      >
        Report this indicator
      </button>
      {open && <ReportForm iocType={iocType} iocValue={iocValue} onClose={() => setOpen(false)} />}
    </>
  )
}
