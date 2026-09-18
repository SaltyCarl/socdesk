import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { PicketView } from '../PicketView'
import type { PicketPayload } from '../types'

// The chip ages the export from the real clock (I7), so a fixture that must read
// "live" needs an exported_at relative to now rather than a fixed 2026-07-28 stamp.
const minutesAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString().replace(/\.\d{3}Z$/, 'Z')

const payload: PicketPayload = {
  generated_at: '2026-07-28T12:00:00Z',
  sensor: { id: 'picket-1', uptime_days: 3, protocols: ['SSH', 'TELNET'], status: 'live',
            export_age_minutes: 25, exported_at: minutesAgo(25), knockknock_version: '1.9.0', country: 'DE' },
  totals: { knocks_total: 9001, since: '2026-07-25T12:00:00Z', knocks_24h: 42, knocks_7d: 42, unique_ips_7d: 1 },
  histogram_7d: Array.from({ length: 168 }, (_, i) => (i === 167 ? 42 : 0)),
  by_protocol: [{ proto: 'SSH', hits_7d: 900, hits_total: 8000, share_pct: 90 }],
  top_ips: [{ ip: '203.0.113.5', hits_7d: 900, hits_total: 900, first_seen: '2026-07-20T01:00:00Z',
              last_seen: '2026-07-28T11:00:00Z', protocols: [{ proto: 'SSH', hits_total: 900 }], country: 'CN', asn: 64500, isp: 'Example Hosting' },
            { ip: '5.6.7.9', hits_7d: 12, hits_total: 12, last_seen: '2026-07-28T11:00:00Z',
              protocols: [{ proto: 'SSH', hits_total: 12 }] }],
  top_usernames: [{ value: 'root', hits_7d: 400, hits_total: 3000 }],
  top_passwords: [{ value: '123456', hits_7d: 200, hits_total: 1800 }],
  top_countries: [{ iso: 'CN', name: 'China', hits_7d: 500, hits_total: 4000 }],
  top_isps: [{ isp: 'Example Hosting', asn: 64500, hits_7d: 300, hits_total: 2000 }],
}

describe('PicketView', () => {
  const html = renderToStaticMarkup(<PicketView payload={payload} />)

  it('renders every block with the honest framing and no verdict colour', () => {
    for (const s of ['Sensor reporting', 'SSH', '203.0.113.5', 'root', '123456', 'China', 'Example Hosting',
                     'context, never a verdict', 'telemetry from my own sensor']) {
      expect(html).toContain(s)
    }
    expect(html).not.toMatch(/text-verdict-(red|amber|green)|bg-\[var\(--tint-(red|amber|green)\)\]/)
  })

  it('renders an em dash for an IP with no first_seen, without dropping the row', () => {
    expect(html).toContain('<td class="py-2 pr-3 font-mono text-micro text-faint">—</td>')
    expect(html).toContain('5.6.7.9')
  })

  it('never renders a username:password pair', () => {
    expect(html).not.toMatch(/root\s*[:/]\s*123456/)
  })

  it('states a silent sensor honestly instead of zeros', () => {
    const silent = renderToStaticMarkup(
      <PicketView payload={{ ...payload, sensor: { ...payload.sensor, status: 'silent', export_age_minutes: 2880, exported_at: minutesAgo(2880) } }} />,
    )
    expect(silent).toContain('Sensor silent')
    expect(silent).toContain('last received')
  })

  it('ages the export client-side: a frozen "live" payload reads Silent once the export is old', () => {
    // I7: the pipeline stamped live/25 min and then stopped; the chip label AND the
    // copy must both follow the clock, so they never disagree with each other.
    const frozen = { ...payload, sensor: { ...payload.sensor, status: 'live' as const, export_age_minutes: 25, exported_at: minutesAgo(3 * 1440) } }
    const frozenHtml = renderToStaticMarkup(<PicketView payload={frozen} />)
    expect(frozenHtml).toContain('>Silent<')
    expect(frozenHtml).toContain('Sensor silent')
    expect(frozenHtml).not.toContain('>Live<')
    expect(frozenHtml).not.toContain('Sensor reporting')
    expect(html).toContain('>Live<')
  })

  it('renders an explicit empty state for a null payload', () => {
    expect(renderToStaticMarkup(<PicketView payload={null} />)).toContain('No sensor telemetry yet')
  })
})
