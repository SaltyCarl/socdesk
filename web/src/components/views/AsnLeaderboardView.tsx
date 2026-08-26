import { cx } from '@socdesk/shared/lib/cx'
import type { AsnLeaderboardPayload, AsnNetwork } from './types'
import { num } from './format'
import { EmptyState } from './states'
import { barWidthClass } from '../overview/widths'

/**
 * The abuse-by-network leaderboard — autonomous systems ranked by the volume of
 * abusive IPs reported to SOCDesk and published on the abuse.ch blocklists.
 * Reported/blocklisted volume hosted on a network, NOT a verdict on the
 * operator: the count is neutral ink, and `sources` keeps a community
 * allegation distinct from an abuse.ch published C2. Ranking is done in the
 * pipeline; this view does not re-sort.
 */

function Chip({ label, accent = false }: { label: string; accent?: boolean }) {
  return (
    <span
      className={cx(
        'inline-flex items-center rounded-sm border px-2 py-0.5 font-mono text-micro font-semibold uppercase tracking-label',
        accent
          ? 'border-[var(--edge-accent)] bg-[var(--tint-accent)] text-accent'
          : 'border-line bg-panel-soft text-muted',
      )}
    >
      {label}
    </span>
  )
}

const HEADERS = ['#', 'ASN', 'ISP', 'Country', 'Abusive IPs', 'Reported for', 'Source(s)', 'Examples'] as const

export function AsnLeaderboardView({ payload }: { payload: AsnLeaderboardPayload | null }) {
  const networks: AsnNetwork[] = payload?.networks ?? []
  // Bar magnitude is relative to the busiest network (pipeline pre-sorts desc,
  // but Math.max is order-independent). Min 1 avoids a divide-by-zero.
  const maxIps = Math.max(1, ...networks.map((n) => n.ip_count ?? 0))

  if (!networks.length) {
    return (
      <EmptyState title="No networks to rank yet">
        The pipeline has not placed any reported IP on an ASN — an IPinfo token
        is needed to map IPs to networks, or there are no abusive IPs to rank.
        Everything else on this page still works.
      </EmptyState>
    )
  }

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap gap-x-6 gap-y-1 font-mono text-micro uppercase tracking-label text-faint">
        <span>
          <b className="text-accent">{num(payload?.total_abusive_ips)}</b> abusive IPs
        </span>
        <span>
          <b className="text-paper">{num(payload?.unattributed_ips)}</b> unattributed
        </span>
      </div>

      <div className="overflow-x-auto rounded-lg border border-line">
        <table className="w-full min-w-[860px] border-collapse text-left">
          <thead>
            <tr>
              {HEADERS.map((h, i) => (
                <th
                  key={h}
                  scope="col"
                  className={cx(
                    'border-b border-line bg-panel px-3 py-2.5 font-mono text-micro font-semibold uppercase tracking-label text-faint',
                    i === 4 && 'text-right',
                  )}
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {networks.map((n, i) => (
              <tr
                key={n.asn ?? i}
                className="border-b border-line align-top last:border-0 transition-colors duration-150 ease-brand hover:bg-panel-soft"
              >
                <td className="px-3 py-2.5 font-mono text-micro text-faint">{i + 1}</td>
                <td className="px-3 py-2.5 font-mono text-xs font-semibold text-paper">{n.asn ?? '—'}</td>
                <td className="px-3 py-2.5 text-xs text-paper">{n.isp ?? '—'}</td>
                <td className="px-3 py-2.5 font-mono text-micro text-muted">{n.country ?? '—'}</td>
                <td className="whitespace-nowrap px-3 py-2.5 text-right">
                  <div className="flex items-center justify-end gap-2">
                    <span
                      aria-hidden="true"
                      className="hidden h-1.5 w-16 overflow-hidden rounded-full bg-panel-soft sm:inline-block"
                    >
                      <span
                        className={cx('block h-full rounded-full bg-accent', barWidthClass((n.ip_count ?? 0) / maxIps))}
                      />
                    </span>
                    <span className="font-mono text-sm tabular-nums text-paper">{num(n.ip_count)}</span>
                  </div>
                  {n.report_count ? (
                    <div className="mt-0.5 font-mono text-micro text-faint">({num(n.report_count)} reported)</div>
                  ) : null}
                </td>
                <td className="px-3 py-2.5">
                  <div className="flex flex-wrap gap-1">
                    {(n.categories ?? []).length ? (
                      (n.categories ?? []).map((c) => <Chip key={c} label={c} />)
                    ) : (
                      <span className="font-mono text-micro text-faint">—</span>
                    )}
                  </div>
                </td>
                <td className="px-3 py-2.5">
                  <div className="flex flex-wrap gap-1">
                    {(n.sources ?? []).map((s) => (
                      <Chip key={s} label={s} accent={s === 'community'} />
                    ))}
                  </div>
                </td>
                <td className="px-3 py-2.5 font-mono text-micro text-muted">
                  {(n.examples ?? []).join(', ') || '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <p className="max-w-2xl text-micro text-faint">
        Reported/blocklisted abuse volume hosted on a network — not a verdict on
        the network or its operator. ASN/ISP mapping by IPinfo.
      </p>
    </div>
  )
}
