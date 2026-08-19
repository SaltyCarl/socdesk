import { describe, expect, it } from 'vitest'
import { decodeEnc, looksBase64 } from '../fold'

// UTF-16LE bytes of "IEX 'hi'" → Base64. Precomputed so the test is deterministic.
const ENC = 'SQBFAFgAIAAnAGgAaQAnAA=='

describe('decodeEnc', () => {
  it('decodes a -EncodedCommand as Base64 → UTF-16LE (not UTF-8)', () => {
    expect(decodeEnc(ENC)).toBe("IEX 'hi'")
  })
  it('looksBase64 accepts the payload and rejects a URL', () => {
    expect(looksBase64(ENC)).toBe(true)
    expect(looksBase64('http://a/x')).toBe(false)
  })
})
