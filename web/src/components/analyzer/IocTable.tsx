import type { ExtractedIoc } from '@socdesk/shared/analyzer'
import { MicroLabel } from '@socdesk/shared/ui'
import { submitLookup } from '../palette/commands'

export function IocTable({ iocs }: { iocs: ExtractedIoc[] }) {
  if (!iocs.length) return null
  return (
    <div className="flex flex-col gap-2">
      <MicroLabel tone="muted">Indicators — one click looks them up</MicroLabel>
      <ul className="flex flex-col rounded-md border border-line">
        {iocs.map((i) => (
          <li key={i.raw} className="flex items-center gap-2 px-3 py-2 even:bg-panel-soft/40">
            <span className="w-16 shrink-0 font-mono text-micro uppercase tracking-label text-faint">{i.type}</span>
            <span className="min-w-0 flex-1 truncate font-mono text-xs text-paper">{i.defanged}</span>
            <button
              type="button"
              onClick={() => submitLookup(i.raw)}
              className="shrink-0 rounded-md border border-line px-2 py-1 font-mono text-micro font-semibold uppercase tracking-label text-muted hover:border-line-bright hover:text-paper"
            >
              Look up →
            </button>
          </li>
        ))}
      </ul>
    </div>
  )
}
