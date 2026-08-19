import { describe, expect, it } from 'vitest'
import { tokenize, stringLiterals } from '../lex'

describe('tokenize — literal safety', () => {
  it("single-quoted strings take no escapes (backtick is literal)", () => {
    const t = tokenize("$x = 'a`nb'")
    const s = t.find((tok) => tok.type === 'string')!
    expect(s.value).toBe('a`nb') // backtick + n stay literal inside single quotes
  })

  it('double-quoted strings resolve backtick escapes', () => {
    const t = tokenize('"a`nb`tc"')
    expect(t[0].type).toBe('string')
    expect(t[0].value).toBe('a\nb\tc') // `n → newline, `t → tab
  })

  it('a quote inside the other quote type is content, not a delimiter', () => {
    const t = tokenize(`'he said "hi"'`)
    expect(t[0].value).toBe('he said "hi"')
  })

  it('stringLiterals returns every literal payload in order', () => {
    const t = tokenize(`iwr 'http://a/x' ; IEX 'stuff'`)
    expect(stringLiterals(t)).toEqual(['http://a/x', 'stuff'])
  })
})
