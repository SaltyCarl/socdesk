import { describe, it, expect } from 'vitest'
import { addTerm, matchesWatchlist, normalizeTerm, removeTerm } from './watchlist'
import type { Cve } from './types'

const cve = (over: Partial<Cve> = {}): Cve => ({ cve: 'CVE-2026-0001', ...over })

describe('normalizeTerm', () => {
  it('trims, lowercases, and collapses inner whitespace', () => {
    expect(normalizeTerm('  Fortinet  ')).toBe('fortinet')
    expect(normalizeTerm('Cisco   ASA')).toBe('cisco asa')
  })
})

describe('addTerm', () => {
  it('appends a normalised term', () => {
    expect(addTerm([], 'Fortinet')).toEqual(['fortinet'])
  })
  it('keeps a legitimate short vendor like f5', () => {
    expect(addTerm([], 'F5')).toEqual(['f5'])
  })
  it('returns the same array (no-op) for a blank, too-short, or duplicate term', () => {
    const terms = ['fortinet']
    expect(addTerm(terms, '  ')).toBe(terms)
    expect(addTerm(terms, 'a')).toBe(terms) // below the 2-char floor
    expect(addTerm(terms, 'FORTINET')).toBe(terms)
  })
})

describe('removeTerm', () => {
  it('drops the term', () => {
    expect(removeTerm(['fortinet', 'citrix'], 'fortinet')).toEqual(['citrix'])
  })
})

describe('matchesWatchlist', () => {
  it('matches a term against products or vendors on a word boundary', () => {
    expect(matchesWatchlist(cve({ products: ['FortiOS'], vendors: ['Fortinet'] }), ['fortinet'])).toBe(true)
    expect(matchesWatchlist(cve({ title: 'Citrix NetScaler bug' }), ['citrix'])).toBe(true)
    expect(matchesWatchlist(cve({ vendors: ['F5'] }), ['f5'])).toBe(true)
  })
  it('does not match a term buried inside a larger word (no bare substring)', () => {
    expect(matchesWatchlist(cve({ title: 'PHP deserialization' }), ['hp'])).toBe(false)
    expect(matchesWatchlist(cve({ title: 'email spoofing' }), ['ai'])).toBe(false)
  })
  it('does not match the CVE id itself', () => {
    expect(matchesWatchlist(cve({ cve: 'CVE-2026-1234' }), ['2026-1234'])).toBe(false)
  })
  it('is false for an empty watchlist or no hit', () => {
    expect(matchesWatchlist(cve({ vendors: ['Fortinet'] }), [])).toBe(false)
    expect(matchesWatchlist(cve({ vendors: ['Fortinet'] }), ['citrix'])).toBe(false)
  })
})
