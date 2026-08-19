// shared/analyzer/__tests__/resolve.test.ts
import { describe, expect, it } from 'vitest'
import { foldConcat } from '../resolve'

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
})
