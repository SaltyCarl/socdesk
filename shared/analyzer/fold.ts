/** Analysts paste -enc payloads (and embedded Base64 blobs) straight out of
 *  EDR/Sysmon logs, where the blob is routinely line-wrapped with spaces/
 *  newlines (console width, log formatting). Strip whitespace ONLY — every
 *  other character passes through untouched, so a genuinely malformed
 *  payload still fails the length/charset gates below exactly as before. */
function stripWs(s: string): string {
  return s.replace(/\s+/g, '')
}

export function fromBase64(b64: string): Uint8Array {
  const clean = stripWs(b64)
  const bin = atob(clean)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/** A -EncodedCommand payload is Base64 of UTF-16LE script text (the #1 gotcha:
 *  it is NOT UTF-8). Whitespace is stripped before decoding (see stripWs) so a
 *  line-wrapped blob decodes identically to its unwrapped form. */
export function decodeEnc(b64: string): string {
  return new TextDecoder('utf-16le').decode(fromBase64(stripWs(b64)))
}

const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/
export function looksBase64(s: string): boolean {
  const t = stripWs(s)
  return t.length >= 8 && t.length % 4 === 0 && B64_RE.test(t)
}

export function bytesToText(bytes: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes)
}

async function decompress(bytes: Uint8Array, format: 'gzip' | 'deflate-raw'): Promise<Uint8Array | null> {
  try {
    const ds = new DecompressionStream(format)
    // TS's generic Uint8Array<ArrayBufferLike> isn't assignable to BlobPart
    // (which wants ArrayBufferView<ArrayBuffer>) — cast; runtime behavior unchanged.
    const stream = new Blob([bytes as BlobPart]).stream().pipeThrough(ds)
    return new Uint8Array(await new Response(stream).arrayBuffer())
  } catch {
    return null
  }
}

/** Inflate a gzip (magic 1F 8B) or raw-DEFLATE blob. Returns null if neither
 *  applies — PowerShell's DeflateStream is raw DEFLATE, so 'deflate-raw'. */
export async function inflate(bytes: Uint8Array): Promise<Uint8Array | null> {
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
    return decompress(bytes, 'gzip')
  }
  return decompress(bytes, 'deflate-raw')
}
