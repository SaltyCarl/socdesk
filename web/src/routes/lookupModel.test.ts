import { describe, expect, it } from 'vitest'
import { parseQ } from './lookupModel'

describe('parseQ', () => {
  it('decodes a plain indicator', () => {
    expect(parseQ('#q=1.1.1.1')).toBe('1.1.1.1')
  })
  it('decodes a percent-encoded command', () => {
    expect(parseQ('#q=powershell%20-enc%20AAA')).toBe('powershell -enc AAA')
  })
  it('returns empty for an empty q value', () => {
    expect(parseQ('#q=')).toBe('')
  })
  it('returns empty for no hash', () => {
    expect(parseQ('')).toBe('')
  })
  it('returns empty for a bare hash', () => {
    expect(parseQ('#')).toBe('')
  })
  it('returns empty when there is no q param', () => {
    expect(parseQ('#foo')).toBe('')
  })
  it('finds q after another param', () => {
    expect(parseQ('#a=1&q=8.8.8.8')).toBe('8.8.8.8')
  })
  it('falls back to the raw token on malformed encoding', () => {
    expect(parseQ('#q=%E0%A4%A')).toBe('%E0%A4%A')
  })
  it('trims surrounding whitespace', () => {
    expect(parseQ('#q=%20%208.8.8.8%20')).toBe('8.8.8.8')
  })
})
