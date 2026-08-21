import { describe, expect, it } from 'vitest'
import { overDailyCap, DAILY_REPORT_CAP } from '../policy.mjs'
describe('overDailyCap', () => {
  it('is false below the cap, true at/above it', () => {
    expect(overDailyCap(DAILY_REPORT_CAP - 1)).toBe(false)
    expect(overDailyCap(DAILY_REPORT_CAP)).toBe(true)
    expect(overDailyCap(DAILY_REPORT_CAP + 5)).toBe(true)
  })
})
