export function fromBase64(b64: string): Uint8Array {
  const clean = b64.replace(/\s+/g, '')
  const bin = atob(clean)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/** A -EncodedCommand payload is Base64 of UTF-16LE script text (the #1 gotcha:
 *  it is NOT UTF-8). */
export function decodeEnc(b64: string): string {
  return new TextDecoder('utf-16le').decode(fromBase64(b64))
}

const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/
export function looksBase64(s: string): boolean {
  const t = s.replace(/\s+/g, '')
  return t.length >= 8 && t.length % 4 === 0 && B64_RE.test(t)
}
