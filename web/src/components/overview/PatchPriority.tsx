import type { Cve } from '../views/types'
import { humanize } from '../views/format'
import { EpssMeter, KevBadge } from '../views/Badges'
import { BoardPanel, DeskLink, SourceStamp, PanelEmpty } from './board-ui'
import { patchPriority } from './aggregations'

/**
 * Patch priority — what to remediate first. CVEs that are KEV-listed or carry a
 * high EPSS exploitation probability, ranked by exploitation risk (KEV first,
 * EPSS breaks ties). This absorbs the CVE reads that were previously spread
 * across three panels; the deeper cuts live on the Vulnerabilities desk.
 */

function affected(c: Cve): string {
  const a = [c.products?.[0], c.vendors?.[0]].filter(Boolean).map((v) => humanize(v))
  return a.join(' / ') || '—'
}

function CveRow({ c }: { c: Cve }) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-line py-2.5 first:pt-0 last:border-0 last:pb-0">
      <div className="flex min-w-0 flex-col gap-0.5">
        <span className="font-mono text-xs font-semibold text-paper">{c.cve}</span>
        <span className="truncate text-micro text-muted">{affected(c)}</span>
      </div>
      <div className="flex shrink-0 items-center gap-2.5">
        {c.kev && <KevBadge ransomware={c.kev_ransomware} />}
        <EpssMeter epss={c.epss} />
        <span className="w-14 text-right font-mono text-micro text-faint">
          CVSS {c.cvss?.toFixed(1) ?? '—'}
        </span>
      </div>
    </div>
  )
}

export function PatchPriority({ cves }: { cves: Cve[] }) {
  const rows = patchPriority(cves)

  return (
    <BoardPanel
      eyebrow="KEV / EPSS exploitation risk"
      title="Patch priority"
      aside={<SourceStamp label="NVD · EPSS · KEV" />}
      footer={
        <>
          <span className="max-w-md text-xs text-muted">
            CVSS ranks theoretical severity; KEV and EPSS rank observed
            exploitation — where they disagree is useful triage signal.
          </span>
          <DeskLink tab="vulnerabilities">Vulnerabilities</DeskLink>
        </>
      }
    >
      {rows.length === 0 ? (
        <PanelEmpty>
          No KEV-listed or high-EPSS CVEs are in the catalog right now.
        </PanelEmpty>
      ) : (
        <div className="flex flex-col">
          {rows.map((c) => (
            <CveRow key={c.cve} c={c} />
          ))}
        </div>
      )}
    </BoardPanel>
  )
}
