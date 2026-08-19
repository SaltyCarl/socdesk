import { describe, expect, it } from 'vitest'
import { detectType } from '@socdesk/shared/indicators'
import { classifyIndicator } from './classify'

describe('classifyIndicator — delegates to detectType (design spec §3.2)', () => {
  it('agrees with detectType on ipv4/ipv6 -> ip', () => {
    expect(classifyIndicator('185.220.101.34')).toBe('ip')
    expect(classifyIndicator('2001:db8::1')).toBe('ip')
  })
  it('agrees with detectType on hash lengths -> hash', () => {
    // canonical md5("") — 32 hex chars. (The brief's fixture was missing the
    // trailing 'e', same 31-char typo as shared/intent.test.ts's md5 fixture;
    // corrected per that task's precedent.)
    expect(classifyIndicator('d41d8cd98f00b204e9800998ecf8427e')).toBe('hash') // md5
  })
  it('agrees with detectType on domain/url/cve', () => {
    expect(classifyIndicator('evil-example.com')).toBe('domain')
    expect(classifyIndicator('https://example.com/path')).toBe('url')
    expect(classifyIndicator('CVE-2024-12345')).toBe('cve')
  })
  it('a lone "/" is no longer classified as url (the previously-divergent case)', () => {
    // Old classify.ts: `s.includes('/')` -> 'url'. detectType has no such
    // rule (its url branch requires an http(s):// prefix) — consolidation
    // removes the looseness, so the two classifiers can no longer disagree.
    expect(classifyIndicator('/')).toBe('unknown')
    expect(detectType('/')).toBe('')
  })
  it('empty input is unknown', () => {
    expect(classifyIndicator('')).toBe('unknown')
  })
})
