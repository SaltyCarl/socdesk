import { cx } from '@socdesk/shared/lib/cx'
import { num } from '../views/format'
import type { AsnLeaderboardPayload, AsnNetwork } from '../views/types'
import { BoardPanel, DeskLink, PanelEmpty, SourceStamp } from './board-ui'
import { barWidthClass } from './widths'
import { topNetworks } from './aggregations'

/**
 * ISP Abuse Leaderboard — a compact landing teaser for the full /desk#networks
 * table. Networks ranked by the volume of abusive IPs reported to SOCDesk
 * (community, owner-moderated) and published on the abuse.ch blocklists — a
 * count of reported/blocklisted IPs HOSTED on a network, same "not a verdict
 * on the operator" framing AsnLeaderboardView holds for the full table.
 *
 * Mirrors RansomwareActivity's ordinal + bar + count row idiom, minus the
 * flagship-only hero number and pointer spotlight (those stay reserved for the
 * one flagship panel). Honest empty when no network has been ranked yet — no
 * IPinfo token, or no abusive IPs at all.
 */

const TOP_N = 5

function NetworkRow({
  ordinal,
  network,
  max,
}: {
  ordinal: number
  network: AsnNetwork
  max: number
}) {
  // A volume bar, same ladder + treatment RansomwareActivity's GroupRow uses
  // (periwinkle = a volume measure here, not a verdict on the network).
  const w = barWidthClass((network.ip_count ?? 0) / max)
  return (
    <div className="flex items-center gap-4 border-b border-line py-3 first:pt-0 last:border-0 last:pb-0">
      <span className="w-5 shrink-0 font-mono text-micro font-semibold tabular-nums tracking-label text-accent">
        {String(ordinal).padStart(2, '0')}
      </span>
      <div className="flex w-40 min-w-0 shrink-0 flex-col gap-0.5">
        <span className="truncate font-mono text-xs font-semibold text-paper">
          {network.isp ?? network.asn ?? 'Unknown network'}
        </span>
        <span className="truncate text-micro text-faint">
          {network.asn ?? '—'}
          {network.country ? ` · ${network.country}` : ''}
        </span>
      </div>
      <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-panel-soft">
        <span className={cx('block h-full rounded-full bg-accent', w)} />
      </span>
      <span className="w-10 shrink-0 text-right font-mono text-sm font-semibold tabular-nums text-paper">
        {num(network.ip_count)}
      </span>
    </div>
  )
}

export function NetworkAbuseLeaderboard({ payload }: { payload: AsnLeaderboardPayload }) {
  const networks = payload.networks ?? []
  const rows = topNetworks(networks, TOP_N)
  const max = rows[0]?.ip_count ?? 1

  return (
    <BoardPanel
      eyebrow="Abuse by network"
      title="ISP Abuse Leaderboard"
      aside={<SourceStamp label="abuse.ch · community" />}
      footer={
        <>
          <span className="font-mono text-micro uppercase tracking-label text-faint">
            {num(payload.total_abusive_ips)} abusive IPs · {num(networks.length)} networks
          </span>
          <DeskLink tab="networks">ISP Abuse Leaderboard</DeskLink>
        </>
      }
    >
      {rows.length === 0 ? (
        <PanelEmpty>No abusive-IP reports have been attributed to a network yet.</PanelEmpty>
      ) : (
        <div className="flex flex-col">
          {rows.map((n, i) => (
            <NetworkRow key={n.asn ?? i} ordinal={i + 1} network={n} max={max} />
          ))}
        </div>
      )}
    </BoardPanel>
  )
}
