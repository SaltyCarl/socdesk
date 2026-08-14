import { cx } from '@socdesk/shared/lib/cx'
import { num } from '../views/format'
import { BoardPanel, DeskLink, SourceStamp, PanelEmpty } from './board-ui'
import { barWidthClass } from './widths'
import type { RansomSummary } from './aggregations'

/**
 * Ransomware activity — the flagship answer to "who is actively hitting people
 * right now". Leak-site groups ranked by the victim claims they posted this
 * window, drawn straight from ransomware.live posts. Full-width bar leaderboard
 * so magnitude reads at a glance (one group routinely dwarfs the rest).
 *
 * Accent-framed for weight. Bars are periwinkle (a volume measure, not a
 * verdict); the count is the fact. Honest empty when the leak sites are quiet.
 */

const TOP_N = 8

function GroupRow({ name, claims, max }: { name: string; claims: number; max: number }) {
  return (
    <div className="flex items-center gap-4 py-2">
      <span className="w-40 shrink-0 truncate font-mono text-base font-semibold text-paper">
        {name}
      </span>
      <span className="h-2 flex-1 overflow-hidden rounded-full bg-panel-soft">
        <span
          className={cx('block h-full rounded-full bg-accent', barWidthClass(claims / max))}
        />
      </span>
      <span className="w-16 shrink-0 text-right">
        <span className="font-display text-md font-extrabold tabular-nums text-paper">
          {claims}
        </span>
      </span>
    </div>
  )
}

export function RansomwareActivity({ summary }: { summary: RansomSummary }) {
  const rows = summary.groups.slice(0, TOP_N)
  const max = rows[0]?.claims ?? 1

  return (
    <BoardPanel
      accent
      eyebrow="Leak-site victim claims"
      title="Ransomware activity"
      aside={<SourceStamp label="ransomware.live" />}
      footer={
        <>
          <span className="font-mono text-micro uppercase tracking-label text-faint">
            {num(summary.totalClaims)} claims · {num(summary.groupCount)} groups
          </span>
          <DeskLink tab="feed">Feed</DeskLink>
        </>
      }
    >
      {rows.length === 0 ? (
        <PanelEmpty>No leak-site victim claims were posted in this window.</PanelEmpty>
      ) : (
        <div className="flex flex-col">
          {rows.map((g) => (
            <GroupRow key={g.name} name={g.name} claims={g.claims} max={max} />
          ))}
        </div>
      )}
    </BoardPanel>
  )
}
