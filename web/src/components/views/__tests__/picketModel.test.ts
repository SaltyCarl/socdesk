import { describe, expect, it } from 'vitest'
import { formatAge, histogramPoints, statusCopy, statusLabel } from '../picketModel'
import type { PicketSensor } from '../types'

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
    const c = statusCopy(sensor({ status: 'silent', export_age_minutes: 2880 }))
    expect(c).toMatch(/no export/i)
    expect(c).not.toMatch(/0 attacks|no attacks/i)
    expect(statusCopy(sensor())).toMatch(/25 min/)
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
