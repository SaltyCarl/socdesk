// shared/analyzer/__tests__/wsh.test.ts
import { describe, expect, it } from 'vitest'
import { decodeNumericCharCodes } from '../wsh'

describe('decodeNumericCharCodes', () => {
  it('decodes a VBScript Chr() concat chain', () => {
    expect(decodeNumericCharCodes('Chr(72)&Chr(105)')).toBe('Hi')
  })

  it('decodes a JScript String.fromCharCode() call', () => {
    expect(decodeNumericCharCodes('String.fromCharCode(72,105)')).toBe('Hi')
  })

  it('does NOT touch a string-concat case — out of scope per §4', () => {
    expect(decodeNumericCharCodes('"a" & "b"')).toBe('"a" & "b"')
  })
})
