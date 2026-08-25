import type { DecodeState } from '@socdesk/shared/analyzer'
import { MicroLabel } from '@socdesk/shared/ui'

/** Honesty band (spec §4.2): shown when the analyzer could not fully resolve
 *  the input. Reserved-colour law — NEUTRAL/periwinkle, never red/amber: this
 *  is a "we could not open it" fact (gray-means-unknown), not an earned
 *  severity verdict. */
export function PartialDecodeNotice({ state }: { state: DecodeState }) {
  if (state !== 'partial') return null
  return (
    <div className="rounded-md border border-line bg-panel-soft/40 p-3">
      <MicroLabel tone="muted">Partially decoded</MicroLabel>
      <p className="mt-1 text-xs text-muted">
        An inner construct could not be resolved. A thin result here is not a clean result — escalate for manual review.
      </p>
    </div>
  )
}
