import { ViewHeader } from '../components/views/ViewFrame'
import { ToolbeltView } from '../components/views/ToolbeltView'

/**
 * /toolbelt — a stub surface for the analyst micro-tools. No data fetch; the
 * tools are listed as planned, not faked as working.
 */
export function ToolbeltRoute() {
  return (
    <div className="flex flex-col gap-6">
      <ViewHeader
        eyebrow="Utilities"
        title="Toolbelt"
        intro="Standalone analyst micro-tools — defang/refang, base64, indicator typing. Scaffolded here, wired in a later pass."
      />
      <ToolbeltView />
    </div>
  )
}
