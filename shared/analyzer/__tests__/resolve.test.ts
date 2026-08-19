// shared/analyzer/__tests__/resolve.test.ts
import { describe, expect, it } from 'vitest'
import { foldConcat, resolveVars } from '../resolve'

describe('foldConcat', () => {
  it('collapses a chain of string-literal concatenations', () => {
    expect(foldConcat("'IE'+'X'")).toBe("'IEX'")
    expect(foldConcat("'Down'+'load'+'String'")).toBe("'DownloadString'")
  })
  it('preserves non-foldable tokens around a concat', () => {
    expect(foldConcat("IEX ('Ne'+'w')")).toBe("IEX ( 'New' )")
  })
  it('leaves a lone string untouched (no + operator)', () => {
    expect(foldConcat("'http://a/x'")).toBe("'http://a/x'")
  })
  it('does not fold across a non-string operand (refuses)', () => {
    // $x is not a literal → the + chain is not foldable; leave tokens as-is
    expect(foldConcat("'a'+$x")).toBe("'a' + $x")
  })
  it('escapes embedded single quotes when re-quoting a folded value', () => {
    // 'can''t' lexes to value `can't`; folded with 'stop' → `can'tstop`; re-quoted with '' escaping
    expect(foldConcat("'can''t'+'stop'")).toBe("'can''tstop'")
  })
})

describe('resolveVars', () => {
  it('substitutes a variable bound once to a string literal', () => {
    // $u = 'http://a/x' ; IEX $u   →   … IEX 'http://a/x'
    expect(resolveVars("$u = 'http://a/x' ; IEX $u")).toContain("IEX 'http://a/x'")
  })
  it('refuses a variable assigned twice (leaves it unsubstituted)', () => {
    const out = resolveVars("$u = 'a' ; $u = 'b' ; IEX $u")
    expect(out).toContain('IEX $u') // ambiguous → not substituted
  })
  it('leaves a variable with no literal binding alone', () => {
    expect(resolveVars('IEX $undefined')).toContain('IEX $undefined')
  })
})
