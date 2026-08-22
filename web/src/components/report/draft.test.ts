import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { clearDraft, draftKey, loadDraft, saveDraft } from './draft'

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

describe('report draft — sessionStorage keyed to the resolved indicator', () => {
  beforeEach(() => vi.stubGlobal('sessionStorage', fakeStorage()))
  afterEach(() => vi.unstubAllGlobals())

  it('namespaces the key to type + value', () => {
    expect(draftKey('ipv4', '45.9.148.20')).toBe('sd-report-draft:ipv4:45.9.148.20')
  })
  it('round-trips a draft', () => {
    saveDraft('ipv4', '45.9.148.20', { category: 'scanner', evidence: 'hit', comment: 'x', pendingOpen: true })
    expect(loadDraft('ipv4', '45.9.148.20')).toEqual({
      category: 'scanner', evidence: 'hit', comment: 'x', pendingOpen: true,
    })
  })
  it('returns null for a missing draft', () => {
    expect(loadDraft('domain', 'evil.com')).toBeNull()
  })
  it('only restores onto the SAME indicator', () => {
    saveDraft('ipv4', '1.1.1.1', { category: 'ssh', evidence: 'e', comment: '', pendingOpen: true })
    expect(loadDraft('ipv4', '2.2.2.2')).toBeNull()
  })
  it('tolerates malformed JSON (returns null, no throw)', () => {
    sessionStorage.setItem(draftKey('ipv4', '1.1.1.1'), '{not json')
    expect(loadDraft('ipv4', '1.1.1.1')).toBeNull()
  })
  it('clearDraft removes it', () => {
    saveDraft('ipv4', '1.1.1.1', { category: 'ssh', evidence: 'e', comment: '', pendingOpen: true })
    clearDraft('ipv4', '1.1.1.1')
    expect(loadDraft('ipv4', '1.1.1.1')).toBeNull()
  })
  it('never throws when storage is blocked', () => {
    vi.stubGlobal('sessionStorage', {
      getItem: () => { throw new Error('blocked') },
      setItem: () => { throw new Error('blocked') },
      removeItem: () => { throw new Error('blocked') },
    } as unknown as Storage)
    expect(() => saveDraft('ipv4', '1.1.1.1', { category: '', evidence: '', comment: '', pendingOpen: true })).not.toThrow()
    expect(loadDraft('ipv4', '1.1.1.1')).toBeNull()
  })
})
