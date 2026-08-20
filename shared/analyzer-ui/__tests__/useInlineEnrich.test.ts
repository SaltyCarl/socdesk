import { describe, expect, it } from 'vitest'
import { inlineInitialState } from '../useInlineEnrich'

describe('inlineInitialState (the analyzer inline-lookup resolver)', () => {
  it('is idle for empty input', () => {
    expect(inlineInitialState('').kind).toBe('idle')
  })
  it('checks an enrichable IP (refanged)', () => {
    expect(inlineInitialState('45[.]9[.]148[.]20')).toEqual({ kind: 'checking', indicator: '45.9.148.20' })
  })
  it('checks an enrichable domain and URL', () => {
    expect(inlineInitialState('evil.test').kind).toBe('checking')
    expect(inlineInitialState('http://evil.test/a').kind).toBe('checking')
  })
  it('is unsupported for a CVE (not inline-enrichable) and for junk', () => {
    expect(inlineInitialState('CVE-2024-1234').kind).toBe('unsupported')
    expect(inlineInitialState('not an indicator ☺').kind).toBe('unsupported')
  })
})
