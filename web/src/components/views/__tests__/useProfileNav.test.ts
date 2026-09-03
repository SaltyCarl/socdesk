import { describe, expect, it } from 'vitest'
import { navSections, targetIdFromHash } from '../useProfileNav'

describe('navSections — jump-nav landmarks', () => {
  it('always leads with Overview, in document order, gated on existence', () => {
    const all = navSections({ hasActivity: true, hasFingerprint: true, hasHuntpack: true, hasRelated: true })
    expect(all.map((s) => s.id)).toEqual(['overview', 'activity', 'fingerprint', 'huntpack', 'related'])
  })

  it('omits absent sections but keeps Overview', () => {
    const bare = navSections({ hasActivity: false, hasFingerprint: false, hasHuntpack: false, hasRelated: false })
    expect(bare.map((s) => s.id)).toEqual(['overview'])
  })

  it('keeps document order when only some exist', () => {
    const some = navSections({ hasActivity: false, hasFingerprint: true, hasHuntpack: true, hasRelated: false })
    expect(some.map((s) => s.id)).toEqual(['overview', 'fingerprint', 'huntpack'])
  })
})

describe('targetIdFromHash', () => {
  it('strips the leading # and trims', () => {
    expect(targetIdFromHash('#huntpack')).toBe('huntpack')
  })
  it('returns null for empty / bare-hash fragments', () => {
    expect(targetIdFromHash('')).toBeNull()
    expect(targetIdFromHash('#')).toBeNull()
    expect(targetIdFromHash('  ')).toBeNull()
  })
})
