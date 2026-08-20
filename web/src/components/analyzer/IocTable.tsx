import { useState } from 'react'
import type { ExtractedIoc } from '@socdesk/shared/analyzer'
import { MicroLabel } from '@socdesk/shared/ui'
import { InlineLookup } from './InlineLookup'

/**
 * Each IOC row's control expands an inline escalation directly beneath that
 * row, in the same column — never a navigate-away. Single-open: picking a
 * new row collapses whichever was already open, so the table never grows
 * more than one card tall. The analyzer output above is never touched or
 * replaced (design spec: seamless inline lookup, no lost context).
 */
export function IocTable({ iocs }: { iocs: ExtractedIoc[] }) {
  const [open, setOpen] = useState<string | null>(null)
  if (!iocs.length) return null
  return (
    <div className="flex flex-col gap-2">
      <MicroLabel tone="muted">Indicators — one click looks them up</MicroLabel>
      <ul className="flex flex-col rounded-md border border-line">
        {iocs.map((i) => {
          const expanded = open === i.raw
          return (
            <li key={i.raw} className="flex flex-col even:bg-panel-soft/40">
              <div className="flex items-center gap-2 px-3 py-2">
                <span className="w-16 shrink-0 font-mono text-micro uppercase tracking-label text-faint">{i.type}</span>
                <span className="min-w-0 flex-1 truncate font-mono text-xs text-paper">{i.defanged}</span>
                <button
                  type="button"
                  aria-expanded={expanded}
                  onClick={() => setOpen(expanded ? null : i.raw)}
                  className="shrink-0 rounded-md border border-line px-2 py-1 font-mono text-micro font-semibold uppercase tracking-label text-muted hover:border-line-bright hover:text-paper"
                >
                  {expanded ? 'Collapse ▴' : 'Look up →'}
                </button>
              </div>
              {expanded && (
                <div className="border-t border-line bg-ink/40 py-3 pl-4 pr-3">
                  <div className="border-l-2 border-accent/40 pl-3">
                    <InlineLookup raw={i.raw} />
                  </div>
                </div>
              )}
            </li>
          )
        })}
      </ul>
    </div>
  )
}
