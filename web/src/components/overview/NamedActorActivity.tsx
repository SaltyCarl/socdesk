import { Fragment } from 'react'
import { rel, safeUrl } from '../views/format'
import { MonoTag } from '../views/Badges'
import { ActorLink, BoardPanel, DeskLink, PanelEmpty } from './board-ui'
import type { ActorReport } from './aggregations'

/**
 * Named-actor activity — APT and campaign reporting that names a threat actor
 * (Sandworm, Kimsuky, Midnight Blizzard…), newest first. Each row leads with the
 * actor, then the headline and the reporting outlet, so the read is "who is
 * being reported on, and by whom". Provenance rides each row (the outlet), so
 * the panel needs no separate source stamp.
 *
 * This lane is honestly small — most campaign items name no actor — so a quiet
 * window shows a plain empty line rather than padded filler.
 */

function ActorRow({ report }: { report: ActorReport }) {
  const href = safeUrl(report.url)
  return (
    <div className="flex flex-col gap-1 border-b border-line py-4 first:pt-0 last:border-0 last:pb-0">
      <div className="flex items-center gap-2">
        <MonoTag tone="ghost">{report.category}</MonoTag>
        <span className="truncate font-mono text-xs font-semibold text-paper">
          {report.actors.map((a, i) => (
            <Fragment key={a}>
              {i > 0 && <span className="text-faint"> · </span>}
              <ActorLink name={a} className="hover:text-accent hover:underline">
                {a}
              </ActorLink>
            </Fragment>
          ))}
        </span>
      </div>
      {href ? (
        <a
          href={href}
          target="_blank"
          rel="noopener noreferrer"
          className="line-clamp-2 text-base text-paper underline-offset-2 transition-colors duration-150 ease-brand hover:text-accent hover:underline"
        >
          {report.title}
        </a>
      ) : (
        <span className="line-clamp-2 text-base text-paper">{report.title}</span>
      )}
      <div className="flex items-center gap-2 font-mono text-micro text-faint">
        <span className="truncate">{report.outlet}</span>
        <span aria-hidden="true">·</span>
        <span className="whitespace-nowrap">{rel(report.published_at)}</span>
      </div>
    </div>
  )
}

export function NamedActorActivity({ reports }: { reports: ActorReport[] }) {
  return (
    <BoardPanel
      eyebrow="APT & campaign reporting"
      title="Named-actor activity"
      footer={<DeskLink tab="feed">Feed</DeskLink>}
    >
      {reports.length === 0 ? (
        <PanelEmpty>No named-actor activity in this window.</PanelEmpty>
      ) : (
        <div className="flex flex-col">
          {reports.map((r) => (
            <ActorRow key={r.id} report={r} />
          ))}
        </div>
      )}
    </BoardPanel>
  )
}
