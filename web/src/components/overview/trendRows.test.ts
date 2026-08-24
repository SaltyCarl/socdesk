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
  it('formats from→to endpoints and a percentage-point delta from them', () => {
    expect(epssShift({ from: 0.75594, to: 0.96868 })).toEqual({
      from: '76%',
      to: '97%',
      points: '+21 pts',
      dir: 1,
    })
  })
  it('keeps endpoints and the delta self-consistent (single rounding)', () => {
    // 0.144→0.206 rounds to 14%→21%; the pill must read +7, not a raw-delta +6
    expect(epssShift({ from: 0.144, to: 0.206 })).toEqual({
      from: '14%',
      to: '21%',
      points: '+7 pts',
      dir: 1,
    })
  })
  it('marks a rare downward move with a minus sign and a down direction', () => {
    const s = epssShift({ from: 0.5, to: 0.2 })
    expect(s?.points).toBe('−30 pts')
    expect(s?.dir).toBe(-1)
  })
  it('degrades to null when an endpoint is missing', () => {
    expect(epssShift({ to: 0.9 })).toBeNull()
    expect(epssShift({ from: 0.9 })).toBeNull()
    expect(epssShift({})).toBeNull()
  })
})
