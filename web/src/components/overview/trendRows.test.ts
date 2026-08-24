import { describe, it, expect } from 'vitest'
import { epssShift, trendLabel } from './trendRows'

describe('trendLabel', () => {
  it('humanizes an underscored product slug', () => {
    expect(trendLabel('zimbra_collaboration_suite')).toBe('zimbra collaboration suite')
  })
  it('falls back to an em-dash when the product is missing or empty', () => {
    expect(trendLabel()).toBe('—')
    expect(trendLabel('')).toBe('—')
    expect(trendLabel(null)).toBe('—')
  })
})

describe('epssShift', () => {
  it('formats from→to endpoints and a signed percentage-point delta', () => {
    // The live producer's shape: {cve, from, to, delta, kev, product}.
    expect(epssShift({ from: 0.75594, to: 0.96868, delta: 0.21274 })).toEqual({
      from: '76%',
      to: '97%',
      points: '+21 pts',
    })
  })
  it('derives the delta from the endpoints when the producer omits it', () => {
    expect(epssShift({ from: 0.2, to: 0.5 })?.points).toBe('+30 pts')
  })
  it('marks a rare downward move with a minus sign', () => {
    expect(epssShift({ from: 0.5, to: 0.2 })?.points).toBe('−30 pts')
  })
  it('degrades to null when an endpoint is missing', () => {
    expect(epssShift({ to: 0.9 })).toBeNull()
    expect(epssShift({ from: 0.9 })).toBeNull()
    expect(epssShift({})).toBeNull()
  })
})
