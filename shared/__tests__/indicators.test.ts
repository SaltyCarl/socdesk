import { describe, expect, it } from 'vitest'
import { safeUrl } from '../indicators'

describe('safeUrl (shared)', () => {
  it('passes http and https through', () => {
    expect(safeUrl('https://example.com/a')).toBe('https://example.com/a')
    expect(safeUrl('http://example.com/')).toBe('http://example.com/')
  })

  it('drops non-http(s) schemes and garbage', () => {
    expect(safeUrl('javascript:alert(1)')).toBe('')
    expect(safeUrl('data:text/html,<x>')).toBe('')
    expect(safeUrl('nope')).toBe('')
    expect(safeUrl(null)).toBe('')
    expect(safeUrl(undefined)).toBe('')
  })

  it('never hyperlinks a .onion host', () => {
    expect(safeUrl('http://abcxyz.onion/claim-1')).toBe('')
    expect(safeUrl('http://deep.sub.onion:8080/x')).toBe('')
    expect(safeUrl('http://ABCXYZ.ONION/x')).toBe('')
  })

  it('keeps a clearnet host that merely contains "onion"', () => {
    expect(safeUrl('https://onions.com/x')).toBe('https://onions.com/x')
  })
})
