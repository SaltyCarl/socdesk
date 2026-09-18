import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { PicketTeaser } from '../PicketTeaser'
import type { PicketPayload } from '../../views/types'

const payload = {
  generated_at: '2026-07-28T12:00:00Z',
  sensor: { id: 'picket-1', uptime_days: 3, protocols: ['SSH'], status: 'live', export_age_minutes: 25,
            exported_at: '2026-07-28T11:35:00Z', knockknock_version: '1.9.0' },
  totals: { knocks_total: 9001, since: '2026-07-25T12:00:00Z', knocks_24h: 42, knocks_7d: 300, unique_ips_7d: 7 },
  histogram_7d: Array.from({ length: 168 }, () => 1),
  by_protocol: [], top_ips: [], top_usernames: [], top_passwords: [],
  top_countries: [{ iso: 'CN', name: 'China', hits_7d: 500, hits_total: 4000 }], top_isps: [],
} as PicketPayload

describe('PicketTeaser', () => {
  it('shows knocks/24h, top country, and links to the desk tab', () => {
    const html = renderToStaticMarkup(<PicketTeaser payload={payload} />)
    expect(html).toContain('42')
    expect(html).toContain('China')
    expect(html).toContain('#picket')
    expect(html).toContain('Picket')
  })
  it('is an honest empty when there is no payload', () => {
    expect(renderToStaticMarkup(<PicketTeaser payload={null} />)).toContain('No sensor telemetry yet')
  })
  it('states a silent sensor rather than zeros', () => {
    const html = renderToStaticMarkup(<PicketTeaser payload={{ ...payload, sensor: { ...payload.sensor, status: 'silent', export_age_minutes: 3000 } }} />)
    expect(html).toContain('Sensor silent')
  })
})
