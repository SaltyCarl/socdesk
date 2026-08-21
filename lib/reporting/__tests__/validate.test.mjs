import { describe, expect, it } from 'vitest'
import { validateReport, CATEGORIES } from '../validate.mjs'

const base = { ioc_type: 'ipv4', ioc_value: '45.9.148.20', category: 'scanner', evidence: 'hit my honeypot on 22/tcp' }

describe('validateReport', () => {
  it('accepts a well-formed report (ioc arrives already-clean from the card)', () => {
    const r = validateReport({ ...base, comment: 'x' })
    expect(r.ok).toBe(true)
    expect(r.clean.ioc_value).toBe('45.9.148.20')
    expect(r.clean.category).toBe('scanner')
  })
  it('rejects an ioc that does not match its type', () => {
    expect(validateReport({ ...base, ioc_value: 'not-an-ip' }).ok).toBe(false)
  })
  it('rejects a defanged ioc — validate does not refang; the card supplies clean values', () => {
    expect(validateReport({ ...base, ioc_value: '45[.]9[.]148[.]20' }).ok).toBe(false)
  })
  it('rejects a private/reserved ip (enrich validate)', () => {
    expect(validateReport({ ...base, ioc_value: '10.0.0.1' }).ok).toBe(false)
  })
  it('rejects an unknown category', () => {
    const r = validateReport({ ...base, category: 'not-a-category' })
    expect(r.ok).toBe(false); expect(r.error).toBe('category')
  })
  it('requires non-empty evidence', () => {
    const r = validateReport({ ...base, evidence: '   ' })
    expect(r.ok).toBe(false); expect(r.error).toBe('evidence')
  })
  it('rejects over-length evidence', () => {
    expect(validateReport({ ...base, evidence: 'x'.repeat(3000) }).ok).toBe(false)
  })
  it('CATEGORIES includes the AbuseIPDB-aligned set', () => {
    expect(CATEGORIES).toContain('brute-force'); expect(CATEGORIES).toContain('phishing')
  })
})
