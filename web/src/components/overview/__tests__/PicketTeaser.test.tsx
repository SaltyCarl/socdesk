import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { PicketTeaser } from '../PicketTeaser'
import { PicketSlot } from '../SituationalBoard'
import type { PicketPayload } from '../../views/types'

// The teaser ages the export from the real clock (I7), so a fixture that must read
// "live" needs an exported_at relative to now rather than a fixed 2026-07-28 stamp.
const minutesAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString().replace(/\.\d{3}Z$/, 'Z')

const payload = {
  generated_at: '2026-07-28T12:00:00Z',
  sensor: { id: 'picket-1', uptime_days: 3, protocols: ['SSH'], status: 'live', export_age_minutes: 25,
            exported_at: minutesAgo(25), knockknock_version: '1.9.0' },
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
    const html = renderToStaticMarkup(<PicketTeaser payload={{ ...payload, sensor: { ...payload.sensor, status: 'silent', export_age_minutes: 3000, exported_at: minutesAgo(3000) } }} />)
    expect(html).toContain('Sensor silent')
  })
  it('says "reporting" only while the export is genuinely recent', () => {
    expect(renderToStaticMarkup(<PicketTeaser payload={payload} />)).toContain('Sensor reporting')
    // frozen payload: the pipeline stamped "live · 25 min" but the export is two days old
    const frozen = { ...payload, sensor: { ...payload.sensor, exported_at: minutesAgo(2 * 1440 + 5) } }
    const html = renderToStaticMarkup(<PicketTeaser payload={frozen} />)
    expect(html).toContain('Sensor silent')
    expect(html).not.toContain('Sensor reporting')
  })
})

describe('PicketSlot (landing-board gate)', () => {
  // I8 option b (ruling R28): no picket.json exists until the first successful export
  // — the pipeline writes none — so a 404 is "no telemetry yet", not a fetch failure.
  it('renders the honest empty, not the error panel, when picket.json is missing (HTTP 404)', () => {
    const html = renderToStaticMarkup(<PicketSlot picket={{ status: 'error', data: null, error: 'HTTP 404' }} />)
    expect(html).toContain('No sensor telemetry yet')
    expect(html).not.toContain('Unavailable')
  })
  it('keeps every other failure as the standard error state', () => {
    const html = renderToStaticMarkup(<PicketSlot picket={{ status: 'error', data: null, error: 'HTTP 500' }} />)
    expect(html).toContain('Unavailable')
    expect(html).toContain('HTTP 500')
    expect(html).not.toContain('No sensor telemetry yet')
  })
  it('passes a ready payload through to the teaser', () => {
    const html = renderToStaticMarkup(<PicketSlot picket={{ status: 'ready', data: payload, error: null }} />)
    expect(html).toContain('China')
  })
})
