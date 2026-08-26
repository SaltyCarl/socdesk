import { describe, expect, it } from 'vitest'
import { safeUrl } from '../format'

describe('safeUrl', () => {
  it('passes http and https through', () => {
    expect(safeUrl('https://example.com/a?b=c')).toBe('https://example.com/a?b=c')
    expect(safeUrl('http://example.com/')).toBe('http://example.com/')
  })

  it('drops non-http(s) schemes to the empty string', () => {
    expect(safeUrl('javascript:alert(1)')).toBe('')
    expect(safeUrl('data:text/html,<x>')).toBe('')
    expect(safeUrl('ftp://example.com')).toBe('')
    expect(safeUrl('not a url')).toBe('')
    expect(safeUrl('')).toBe('')
    expect(safeUrl(null)).toBe('')
    expect(safeUrl(undefined)).toBe('')
  })

  it('never hyperlinks a .onion host, even though it is http', () => {
    expect(safeUrl('http://abcxyz.onion/site/blog?uuid=1')).toBe('')
    expect(safeUrl('http://ijzn3sicr.onion/entity/acme')).toBe('')
    expect(safeUrl('http://deep.sub.onion:8080/x')).toBe('')
    // host is normalised to lowercase by URL parsing, but guard explicitly too
    expect(safeUrl('http://ABCXYZ.ONION/x')).toBe('')
    expect(safeUrl('https://abcxyz.onion/x')).toBe('')
  })

  it('does NOT drop a clearnet host that merely contains the substring "onion"', () => {
    expect(safeUrl('https://onions.com/recipes')).toBe('https://onions.com/recipes')
    expect(safeUrl('https://the-onion.example/x')).toBe('https://the-onion.example/x')
  })
})
