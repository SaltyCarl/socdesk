import { describe, it, expect } from 'vitest'
import { intelSource } from './intelSource'

describe('intelSource', () => {
  it('names CISA for a www.cisa.gov advisory URL', () => {
    expect(intelSource('https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a')).toEqual({
      org: 'CISA',
      product: 'CISA #StopRansomware advisory',
    })
  })

  it('names HHS HC3 for a www.hhs.gov advisory URL', () => {
    expect(
      intelSource('https://www.hhs.gov/sites/default/files/qilin-threat-profile-tlpclear.pdf'),
    ).toEqual({ org: 'HHS HC3', product: 'HHS HC3 threat profile' })
  })

  it('resolves HHS HC3 via the aspr.hhs.gov subdomain', () => {
    expect(intelSource('https://aspr.hhs.gov/HC3/some-product.pdf').org).toBe('HHS HC3')
  })

  it('falls back honestly for an absent or unparseable URL, never fabricating an agency', () => {
    expect(intelSource(undefined)).toEqual({ org: 'the source', product: 'the source advisory' })
    expect(intelSource('not a url')).toEqual({ org: 'the source', product: 'the source advisory' })
  })

  it('does not match a lookalike host that merely contains the domain as a substring', () => {
    // A schema-adversarial case shouldn't reach here (the host gate rejects
    // it upstream), but the helper itself must not be substring-fooled.
    expect(intelSource('https://www.hhs.gov.evil.example/x').org).toBe('the source')
    expect(intelSource('https://evilcisa.gov/x').org).toBe('the source')
  })
})
