import type { ExtractedIoc } from '@socdesk/shared/analyzer'
import { MicroLabel } from '@socdesk/shared/ui'
import { submitLookup } from '../palette/commands'

/**
 * `onLookup`, when given, replaces the default route-navigate with an
 * in-place callback — the cockpit's ResultRegion passes one so an extracted
 * IOC click pivots the cockpit's own committed value/kind instead of
 * navigating away (design spec fast-follow). The standalone `/analyzer`
 * route renders this component with no `onLookup`, so it falls back to
 * `submitLookup` unchanged — this component stays context-agnostic either
 * way; it never assumes a cockpit is present.
 */
export function IocTable({
  iocs,
  onLookup,
}: {
  iocs: ExtractedIoc[]
  onLookup?: (raw: string) => void
}) {
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
              onClick={() => (onLookup ? onLookup(i.raw) : submitLookup(i.raw))}
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
