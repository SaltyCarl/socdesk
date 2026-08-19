import { describe, expect, it } from 'vitest'
import { decodeEnc, looksBase64, inflate, bytesToText } from '../fold'

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

async function deflateRaw(text: string): Promise<Uint8Array> {
  const cs = new CompressionStream('deflate-raw')
  const stream = new Blob([new TextEncoder().encode(text)]).stream().pipeThrough(cs)
  return new Uint8Array(await new Response(stream).arrayBuffer())
}
async function gzip(text: string): Promise<Uint8Array> {
  const cs = new CompressionStream('gzip')
  const stream = new Blob([new TextEncoder().encode(text)]).stream().pipeThrough(cs)
  return new Uint8Array(await new Response(stream).arrayBuffer())
}

describe('inflate', () => {
  it('inflates a raw-DEFLATE blob (PowerShell DeflateStream)', async () => {
    const out = await inflate(await deflateRaw("IEX 'payload'"))
    expect(out).not.toBeNull()
    expect(bytesToText(out!)).toBe("IEX 'payload'")
  })
  it('inflates a gzip blob (detected by magic bytes)', async () => {
    const out = await inflate(await gzip('hello gzip'))
    expect(bytesToText(out!)).toBe('hello gzip')
  })
  it('returns null for non-compressed bytes', async () => {
    expect(await inflate(new TextEncoder().encode('not compressed'))).toBeNull()
  })
})
