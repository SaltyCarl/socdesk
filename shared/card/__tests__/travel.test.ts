import { describe, it, expect } from 'vitest'
import { haversineMiles, travelAssessment, travelSummary } from '../travel'

describe('haversineMiles', () => {
  it('is ~0 for identical points', () => {
    expect(haversineMiles(40, -74, 40, -74)).toBeCloseTo(0, 5)
  })
  it('~69 mi per degree of longitude at the equator', () => {
    const d = haversineMiles(0, 0, 0, 1)
    expect(d).toBeGreaterThan(68)
    expect(d).toBeLessThan(70)
  })
  it('NYC → LA ≈ 2,450 mi', () => {
    const d = haversineMiles(40.7128, -74.006, 34.0522, -118.2437)
    expect(d).toBeGreaterThan(2400)
    expect(d).toBeLessThan(2500)
  })
  it('is symmetric', () => {
    expect(haversineMiles(51.5, -0.12, 48.85, 2.35)).toBeCloseTo(
      haversineMiles(48.85, 2.35, 51.5, -0.12),
      6,
    )
  })
})

describe('travelAssessment', () => {
  it('is distance-only when no time gap', () => {
    const t = travelAssessment(500, null)
    expect(t.band).toBeNull()
    expect(t.mph).toBeNull()
    expect(t.read).toMatch(/time between the two sign-ins/i)
    expect(t.milesLabel).toBe('500 mi')
  })
  it('treats zero / negative minutes as distance-only', () => {
    expect(travelAssessment(500, 0).band).toBeNull()
    expect(travelAssessment(500, -5).band).toBeNull()
  })
  it('within commercial speed → plausible', () => {
    const t = travelAssessment(500, 60) // 500 mph
    expect(t.band).toBe('plausible')
    expect(t.mph).toBeCloseTo(500, 0)
  })
  it('faster than a flight → implausible', () => {
    const t = travelAssessment(1000, 60) // 1000 mph
    expect(t.band).toBe('implausible')
    expect(t.read).toMatch(/VPN\/proxy|account compromise/i)
  })
  it('beyond any aircraft → impossible', () => {
    expect(travelAssessment(2400, 15).band).toBe('impossible') // 9600 mph
  })
  it('formats mph with thousands separators', () => {
    expect(travelAssessment(2400, 15).mphLabel).toBe('9,600 mph')
  })
})

describe('travelSummary', () => {
  it('carries the route and distance as a clean factual line (no caveat)', () => {
    const s = travelSummary('Frankfurt, DE', 'Ashburn, US', travelAssessment(2412, 15))
    expect(s).toContain('Frankfurt, DE → Ashburn, US')
    expect(s).toContain('2,412 mi')
    expect(s).not.toMatch(/investigative lead|VPNs, proxies/i)
  })
  it('omits velocity when distance-only', () => {
    expect(travelSummary('A', 'B', travelAssessment(500, null))).not.toMatch(/mph/)
  })
})
