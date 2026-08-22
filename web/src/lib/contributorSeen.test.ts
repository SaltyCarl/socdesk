import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { isContributorSeen, markContributorSeen } from './contributorSeen'

function fakeStorage(): Storage {
  const m = new Map<string, string>()
  return {
    getItem: (k: string) => (m.has(k) ? (m.get(k) as string) : null),
    setItem: (k: string, v: string) => void m.set(k, v),
    removeItem: (k: string) => void m.delete(k),
    clear: () => m.clear(),
    key: () => null,
    length: 0,
  } as unknown as Storage
}

describe('contributorSeen — sd_contributor localStorage bit', () => {
  beforeEach(() => vi.stubGlobal('localStorage', fakeStorage()))
  afterEach(() => vi.unstubAllGlobals())

  it('is false before anything is written', () => {
    expect(isContributorSeen()).toBe(false)
  })
  it('is true once marked', () => {
    markContributorSeen()
    expect(isContributorSeen()).toBe(true)
  })
  it('never throws when storage is blocked (private mode / SSR)', () => {
    vi.stubGlobal('localStorage', {
      getItem: () => {
        throw new Error('blocked')
      },
      setItem: () => {
        throw new Error('blocked')
      },
    } as unknown as Storage)
    expect(() => markContributorSeen()).not.toThrow()
    expect(isContributorSeen()).toBe(false)
  })
})
