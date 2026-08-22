import { describe, expect, it } from 'vitest'
import {
  AA_NORMAL, contrastRatio, DARK_TOKENS, LIGHT_TOKENS, READABLE_TEXT, SURFACES,
} from './contrast'

describe('contrastRatio — WCAG 2.x', () => {
  it('white on black is 21:1', () => {
    expect(contrastRatio('#FFFFFF', '#000000')).toBeCloseTo(21, 0)
  })
})

describe('legibility — readable text clears AA on every surface (both themes)', () => {
  for (const [name, T] of [['dark', DARK_TOKENS], ['light', LIGHT_TOKENS]] as const) {
    for (const surface of SURFACES) {
      for (const token of READABLE_TEXT) {
        it(`${name}: ${token} on ${surface} ≥ ${AA_NORMAL}`, () => {
          expect(contrastRatio(T[token], T[surface])).toBeGreaterThanOrEqual(AA_NORMAL)
        })
      }
    }
  }
})

describe('legibility — --faint is BELOW AA (why readable text must not use it)', () => {
  it('dark: faint on panel is below 4.5', () => {
    expect(contrastRatio(DARK_TOKENS.faint, DARK_TOKENS.panel)).toBeLessThan(AA_NORMAL)
  })
  it('light: faint on panel is below 4.5', () => {
    expect(contrastRatio(LIGHT_TOKENS.faint, LIGHT_TOKENS.panel)).toBeLessThan(AA_NORMAL)
  })
})
