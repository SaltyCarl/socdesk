import { describe, it, expect } from 'vitest'
import { cveLookupHref } from './intelHref'

describe('cveLookupHref', () => {
  it('builds the in-app CVE lookup deep link', () => {
    expect(cveLookupHref('CVE-2023-20269')).toBe('/lookup#q=CVE-2023-20269')
  })
  it('encodes the query value', () => {
    expect(cveLookupHref('CVE-2023-4966')).toBe('/lookup#q=CVE-2023-4966')
  })
})
