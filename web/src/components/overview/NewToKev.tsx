import { cx } from '@socdesk/shared/lib/cx'
import type { NewKevEntry } from '../views/types'
import { day, humanize, pct } from '../views/format'
import { KevBadge } from '../views/Badges'
import { BoardPanel, SourceStamp, PanelEmpty } from './board-ui'

/**
 * New to CISA KEV — the CVEs that entered the Known Exploited Vulnerabilities
 * catalog in the compared window. Ransomware-linked entries pin to the top when
 * the snapshot flags them; otherwise the list orders by EPSS (highest
 * exploitation probability first). Empty → an honest "nothing new" line, never a
 * fabricated row.
 *
 * DATA GAP: trends.json's new_kev rows do not currently carry a ransomware flag
 * (it lives in cves.json), so pinning is EPSS-driven in practice today.
 */

function epssTone(epss?: number | null): string {
  if (epss == null) return 'text-faint'
  if (epss >= 0.5) return 'text-verdict-red'
  if (epss >= 0.1) return 'text-verdict-amber'
  return 'text-muted'
}

function rank(e: NewKevEntry): number {
  return (e.ransomware ? 1 : 0) * 10 + (e.epss ?? 0)
}

function KevRow({ entry }: { entry: NewKevEntry }) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-line py-2.5 first:pt-0 last:border-0 last:pb-0">
      <div className="flex min-w-0 flex-col gap-0.5">
        <div className="flex items-center gap-2">
          <span className="truncate text-base font-semibold text-paper">
            {entry.product ? humanize(entry.product) : entry.cve}
          </span>
          {entry.ransomware && <KevBadge ransomware />}
        </div>
        <span className="font-mono text-micro text-faint">
          {entry.cve}
          {entry.added ? ` · added ${day(entry.added)}` : ''}
        </span>
      </div>
      <div className="flex shrink-0 flex-col items-end">
        <span className={cx('font-mono text-base font-semibold tabular-nums', epssTone(entry.epss))}>
          {pct(entry.epss)}
        </span>
        <span className="font-mono text-micro uppercase tracking-label text-faint">EPSS</span>
      </div>
    </div>
  )
}

export function NewToKev({ entries }: { entries: NewKevEntry[] }) {
  const rows = [...entries].sort((a, b) => rank(b) - rank(a))

  return (
    <BoardPanel
      eyebrow="Newly exploited"
      title="New to CISA KEV"
      aside={<SourceStamp file="trends.json" />}
    >
      {rows.length === 0 ? (
        <PanelEmpty>Nothing new to CISA KEV in this window.</PanelEmpty>
      ) : (
        <div className="flex flex-col">
          {rows.map((e) => (
            <KevRow key={e.cve} entry={e} />
          ))}
        </div>
      )}
    </BoardPanel>
  )
}
