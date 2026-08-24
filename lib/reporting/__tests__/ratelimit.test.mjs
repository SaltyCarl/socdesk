import { describe, expect, it } from 'vitest'
import { overIpDailyCap, reportIpKey, IP_DAILY_REPORT_CAP, REPORT_IP_TTL_S } from '../ratelimit.mjs'

describe('overIpDailyCap', () => {
  it('is false below the cap, true at/above it (boundary at 40)', () => {
    expect(overIpDailyCap(IP_DAILY_REPORT_CAP - 1)).toBe(false)
    expect(overIpDailyCap(IP_DAILY_REPORT_CAP)).toBe(true)
    expect(overIpDailyCap(IP_DAILY_REPORT_CAP + 5)).toBe(true)
  })
  it('sits above the per-account cap (25) so an honest single account is never blocked', () => {
    expect(IP_DAILY_REPORT_CAP).toBeGreaterThan(25)
  })
  it('fail-open: NaN/undefined count is under cap', () => {
    expect(overIpDailyCap(undefined)).toBe(false)
    expect(overIpDailyCap(NaN)).toBe(false)
  })
})

describe('reportIpKey', () => {
  it('is rl:report:<ip>:<utcday> and stable across a UTC day', () => {
    const a = reportIpKey('203.0.113.7', new Date('2026-08-24T00:00:01Z'))
    const b = reportIpKey('203.0.113.7', new Date('2026-08-24T23:59:59Z'))
    expect(a).toBe('rl:report:203.0.113.7:20260824')
    expect(b).toBe(a)
  })
  it('TTL is 26h (self-expiring, no deletes)', () => {
    expect(REPORT_IP_TTL_S).toBe(93_600)
  })
})
