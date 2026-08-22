import { describe, expect, it } from 'vitest'
import { statusChipVariant } from './myReportsModel'

describe('statusChipVariant — status → neutral/accent, never a verdict hue', () => {
  it('queued and other in-flight states are neutral', () => {
    expect(statusChipVariant('queued')).toBe('neutral')
    expect(statusChipVariant('reviewing')).toBe('neutral')
    expect(statusChipVariant('rejected')).toBe('neutral')
  })
  it('an actioned/terminal state rides the accent', () => {
    expect(statusChipVariant('published')).toBe('accent')
    expect(statusChipVariant('accepted')).toBe('accent')
    expect(statusChipVariant('actioned')).toBe('accent')
  })
  it('is case-insensitive', () => {
    expect(statusChipVariant('PUBLISHED')).toBe('accent')
  })
  it('an unknown status defaults to neutral', () => {
    expect(statusChipVariant('whatever')).toBe('neutral')
  })
})
