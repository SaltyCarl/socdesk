import { describe, expect, it } from 'vitest'
import {
  LIVE_MINUTES, SILENT_MINUTES, exportAgeMinutes, formatAge, histogramPoints, sensorStatus, statusCopy, statusLabel,
} from '../picketModel'
import type { PicketSensor } from '../types'

// "now" is pinned 25 minutes after the fixture's exported_at, so the pipeline-
// stamped figures (export_age_minutes 25, status live) and the client clock agree.
const NOW = Date.parse('2026-07-28T12:00:00Z')

const sensor = (over: Partial<PicketSensor> = {}): PicketSensor => ({
  id: 'picket-1', uptime_days: 3, protocols: ['SSH', 'TELNET'], status: 'live',
  export_age_minutes: 25, exported_at: '2026-07-28T11:35:00Z', knockknock_version: '1.9.0', ...over,
})

describe('picketModel', () => {
  it('labels the three sensor states', () => {
    expect(statusLabel('live')).toBe('Live')
    expect(statusLabel('stale')).toBe('Stale')
    expect(statusLabel('silent')).toBe('Silent')
  })

  it('never phrases a silent sensor as zero attacks', () => {
    const c = statusCopy(sensor({ status: 'silent', export_age_minutes: 2880 }), NOW + 2880 * 60_000)
    expect(c).toMatch(/no export/i)
    expect(c).not.toMatch(/0 attacks|no attacks/i)
    expect(statusCopy(sensor(), NOW)).toMatch(/25 min/)
  })

  it('mirrors the pipeline thresholds (pipeline/picket.py LIVE_MINUTES / SILENT_MINUTES)', () => {
    expect(LIVE_MINUTES).toBe(90)
    expect(SILENT_MINUTES).toBe(1440)
    expect(sensorStatus(sensor(), NOW + 89 * 60_000 - 25 * 60_000)).toBe('live')
    expect(sensorStatus(sensor(), NOW + 90 * 60_000 - 25 * 60_000)).toBe('stale')
    expect(sensorStatus(sensor(), NOW + 1440 * 60_000 - 25 * 60_000)).toBe('silent')
  })

  it('ages the export from the client clock, so a frozen payload cannot claim to be live', () => {
    // I7: GitHub Actions stops -> picket.json freezes with status "live", age 25 min.
    // Three days later the chip must say what is true NOW.
    const threeDaysLater = NOW + 3 * 86_400_000
    const frozen = sensor({ status: 'live', export_age_minutes: 25 })
    expect(exportAgeMinutes(frozen, threeDaysLater)).toBe(3 * 1440 + 25)
    expect(sensorStatus(frozen, threeDaysLater)).toBe('silent')
    const c = statusCopy(frozen, threeDaysLater)
    expect(c).toMatch(/Sensor silent/)
    expect(c).toMatch(/3 d/)
    expect(c).not.toMatch(/25 min|reporting/)
    expect(statusLabel(sensorStatus(frozen, threeDaysLater))).toBe('Silent')
  })

  it('falls back to the pipeline-stamped age and status when exported_at is unparseable', () => {
    const odd = sensor({ exported_at: 'garbage', status: 'stale', export_age_minutes: 120 })
    expect(exportAgeMinutes(odd, NOW)).toBe(120)
    expect(sensorStatus(odd, NOW)).toBe('stale')
    expect(statusCopy(odd, NOW)).toMatch(/Sensor stale · no export for 2 h/)
  })

  it('never reports a negative age when the client clock is behind the export', () => {
    expect(exportAgeMinutes(sensor(), NOW - 3_600_000)).toBe(0)
    expect(sensorStatus(sensor(), NOW - 3_600_000)).toBe('live')
  })

  it('formats ages humanely', () => {
    expect(formatAge(25)).toBe('25 min')
    expect(formatAge(120)).toBe('2 h')
    expect(formatAge(2880)).toBe('2 d')
  })

  it('folds 168 hourly buckets into 7 daily points, oldest first', () => {
    const hist = Array.from({ length: 168 }, (_, i) => (i >= 144 ? 1 : 0))   // last day = 24
    const pts = histogramPoints(hist, '2026-07-28T12:00:00Z')
    expect(pts).toHaveLength(7)
    expect(pts[6]).toEqual({ date: '2026-07-28', count: 24 })
    expect(pts[0]).toEqual({ date: '2026-07-22', count: 0 })
  })

  it('tolerates a short or missing histogram', () => {
    expect(histogramPoints([], undefined)).toEqual([])
    expect(histogramPoints([1, 2, 3], undefined)).toHaveLength(1)
  })
})
