import { describe, expect, it } from 'vitest'
import { faviconSrc, monogram } from '../logo'

describe('faviconSrc', () => {
  it('builds a same-origin proxy URL for a valid domain', () => {
    expect(faviconSrc('acme.com')).toBe('/api/favicon?d=acme.com')
  })

  it('lowercases and trims before validating', () => {
    expect(faviconSrc('  ACME.CoM ')).toBe('/api/favicon?d=acme.com')
  })

  it('accepts multi-label subdomains', () => {
    expect(faviconSrc('mail.acme.co.uk')).toBe('/api/favicon?d=mail.acme.co.uk')
  })

  it('rejects a bare hostname with no dot (never a request)', () => {
    expect(faviconSrc('localhost')).toBeNull()
  })

  it('rejects a full URL — no scheme, no path ever reaches the proxy', () => {
    expect(faviconSrc('https://acme.com/x')).toBeNull()
    expect(faviconSrc('acme.com/../evil')).toBeNull()
  })

  it('rejects a port or userinfo', () => {
    expect(faviconSrc('acme.com:8080')).toBeNull()
    expect(faviconSrc('user@acme.com')).toBeNull()
  })

  it('rejects empty / missing input', () => {
    expect(faviconSrc('')).toBeNull()
    expect(faviconSrc(undefined)).toBeNull()
    expect(faviconSrc(null)).toBeNull()
  })
})

describe('monogram', () => {
  it('takes the initials of the first two words', () => {
    expect(monogram('Acme Industries')).toBe('AI')
  })

  it('takes two letters of a single-word name', () => {
    expect(monogram('Globex')).toBe('GL')
  })

  it('ignores punctuation and extra whitespace', () => {
    expect(monogram('  Initech, LLC ')).toBe('IL')
  })

  it('falls back to ? for an empty / missing name', () => {
    expect(monogram('')).toBe('?')
    expect(monogram(undefined)).toBe('?')
    expect(monogram('   ')).toBe('?')
  })
})
