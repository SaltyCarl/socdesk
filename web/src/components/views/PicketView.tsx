import { type ReactNode } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import { MicroLabel } from '../ui'
import { EmptyState } from './states'
import { num, rel } from './format'
import { barWidthClass } from '../overview/widths'
import { Sparkline } from '../overview/Sparkline'
import { histogramPoints, statusCopy, statusLabel } from './picketModel'
import type { PicketCred, PicketPayload } from './types'

/**
 * /desk#picket — SOCDESK · PICKET, telemetry from SOCDesk's own honeypot.
 * Volume measures in periwinkle only; NO verdict colour anywhere (colour law).
 * Credentials are aggregate values, never pairs. A silent sensor is stated as
 * "no export", never rendered as zero attacks.
 */

const FRAME = 'What automated bots try against an unsolicited sensor — context, never a verdict on any network or operator.'

function Bar({ frac }: { frac: number }) {
  return (
    <span className="h-1.5 w-full overflow-hidden rounded-full bg-panel-soft">
      <span className={cx('block h-full rounded-full bg-accent', barWidthClass(frac))} />
    </span>
  )
}

function Block({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="flex flex-col gap-3 rounded-lg border border-line bg-panel p-5">
      <MicroLabel tone="muted">{title}</MicroLabel>
      {children}
    </section>
  )
}

function CredList({ rows, label }: { rows: PicketCred[]; label: string }) {
  const max = rows[0]?.hits_7d ?? 1
  return (
    <Block title={label}>
      {rows.length === 0 ? (
        <p className="text-xs text-muted">None above the publication floor (3 attempts) this week.</p>
      ) : (
        <ol className="flex flex-col gap-2">
          {rows.map((r) => (
            <li key={r.value} className="flex items-center gap-3">
              <code className="w-40 truncate font-mono text-xs text-paper">{r.value}</code>
              <Bar frac={r.hits_7d / max} />
              <span className="w-12 text-right font-mono text-xs tabular-nums text-paper">{num(r.hits_7d)}</span>
            </li>
          ))}
        </ol>
      )}
    </Block>
  )
}

export function PicketView({ payload }: { payload: PicketPayload | null }) {
  if (!payload) {
    return (
      <EmptyState title="No sensor telemetry yet">
        The Picket sensor has not published an export the pipeline could read. Everything else on the desk still works.
      </EmptyState>
    )
  }
  const { sensor, totals, by_protocol, top_ips, top_countries, top_isps } = payload
  const maxIp = top_ips[0]?.hits_7d ?? 1
  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-baseline gap-x-6 gap-y-2">
        <MicroLabel tone={sensor.status === 'live' ? 'accent' : 'muted'} tick>
          {statusLabel(sensor.status)}
        </MicroLabel>
        <p className="text-sm text-muted">{statusCopy(sensor)}</p>
        <p className="font-mono text-micro text-faint">
          {sensor.protocols.join(' · ')} · up {num(sensor.uptime_days)} d · knock-knock {sensor.knockknock_version}
          {sensor.ring_reset_at ? ` · counters reset ${rel(sensor.ring_reset_at)}` : ''}
        </p>
      </div>
      <p className="max-w-2xl text-micro text-faint">telemetry from my own sensor — {FRAME}</p>

      <div className="grid gap-4 sm:grid-cols-3">
        <Block title="Knocks · 24 h"><span className="font-display text-2xl font-extrabold text-paper">{num(totals.knocks_24h)}</span></Block>
        <Block title="Knocks · 7 d"><span className="font-display text-2xl font-extrabold text-paper">{num(totals.knocks_7d)}</span></Block>
        <Block title="Distinct IPs · 7 d"><span className="font-display text-2xl font-extrabold text-paper">{num(totals.unique_ips_7d)}</span></Block>
      </div>

      <Block title="Seven days, by day">
        <Sparkline points={histogramPoints(payload.histogram_7d, payload.generated_at)} className="h-16 w-full" label="knocks per day, last 7 days" />
        <p className="font-mono text-micro text-faint">{num(totals.knocks_total)} knocks since {rel(totals.since)}</p>
      </Block>

      <Block title="By protocol · 7 d">
        <ol className="flex flex-col gap-2">
          {by_protocol.map((p) => (
            <li key={p.proto} className="flex items-center gap-3">
              <span className="w-20 font-mono text-xs font-semibold text-paper">{p.proto}</span>
              <Bar frac={p.share_pct / 100} />
              <span className="w-16 text-right font-mono text-xs tabular-nums text-paper">{p.share_pct}%</span>
            </li>
          ))}
        </ol>
      </Block>

      <Block title="Top sources · 7 d">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] text-left">
            <thead>
              <tr>{['IP', 'Attempts', 'Protocols', 'Country', 'ASN · ISP', 'First seen', 'Last seen'].map((h) => (
                <th key={h} scope="col" className="border-b border-line py-2 pr-3 font-mono text-micro font-semibold uppercase tracking-label text-faint">{h}</th>))}</tr>
            </thead>
            <tbody>
              {top_ips.map((r) => (
                <tr key={r.ip} className="border-b border-line last:border-0">
                  <td className="py-2 pr-3 font-mono text-xs text-paper">{r.ip}</td>
                  <td className="py-2 pr-3"><div className="flex items-center gap-2"><Bar frac={r.hits_7d / maxIp} /><span className="font-mono text-xs tabular-nums text-paper">{num(r.hits_7d)}</span></div></td>
                  <td className="py-2 pr-3 font-mono text-micro text-muted">{r.protocols.map((p) => p.proto).join(' · ')}</td>
                  <td className="py-2 pr-3 font-mono text-micro text-muted">{r.country ?? '—'}</td>
                  <td className="py-2 pr-3 text-xs text-muted">{r.asn ? `AS${r.asn}` : '—'}{r.isp ? ` · ${r.isp}` : ''}</td>
                  <td className="py-2 pr-3 font-mono text-micro text-faint">{rel(r.first_seen)}</td>
                  <td className="py-2 pr-3 font-mono text-micro text-faint">{rel(r.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Block>

      <div className="grid gap-4 md:grid-cols-2">
        <CredList rows={payload.top_usernames} label="Usernames tried · 7 d" />
        <CredList rows={payload.top_passwords} label="Passwords tried · 7 d" />
      </div>
      <p className="text-micro text-faint">Credentials are shown as separate aggregate lists — never as the pairs bots submit — and anything resembling a real identity is dropped before publication.</p>

      <div className="grid gap-4 md:grid-cols-2">
        <Block title="Countries · 7 d">
          <ol className="flex flex-col gap-2">{top_countries.map((c) => (
            <li key={c.iso} className="flex items-center gap-3"><span className="w-40 truncate text-xs text-paper">{c.name || c.iso}</span><Bar frac={c.hits_7d / (top_countries[0]?.hits_7d || 1)} /><span className="w-12 text-right font-mono text-xs tabular-nums text-paper">{num(c.hits_7d)}</span></li>))}</ol>
        </Block>
        <Block title="Networks · 7 d">
          <ol className="flex flex-col gap-2">{top_isps.map((i) => (
            <li key={`${i.asn}-${i.isp}`} className="flex items-center gap-3"><span className="w-40 truncate text-xs text-paper">{i.isp}</span><Bar frac={i.hits_7d / (top_isps[0]?.hits_7d || 1)} /><span className="w-12 text-right font-mono text-xs tabular-nums text-paper">{num(i.hits_7d)}</span></li>))}</ol>
        </Block>
      </div>

      <p className="max-w-2xl text-micro text-faint">{payload.attribution}</p>
    </div>
  )
}
