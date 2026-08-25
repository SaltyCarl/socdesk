import { tokenize, stringLiterals } from './lex'
import { looksBase64 } from './fold'
import type { Interpreter } from './preprocess'

export interface ResidueFinding {
  construct: string   // 'base64' | 'char-assembly' | 'dynamic-exec' | 'cmd-var'
  note: string
  bytes: number
  entropy: number
}

/** Shannon entropy (bits/char) of a string — a residual-blob honesty stat. */
function entropy(s: string): number {
  if (!s) return 0
  const freq = new Map<string, number>()
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1)
  let h = 0
  for (const c of freq.values()) { const p = c / s.length; h -= p * Math.log2(p) }
  return Math.round(h * 100) / 100
}

const DECODE_API = /frombase64string|\[convert\]::from|::frombase64/i
const SINK = /\biex\b|invoke-expression|\.invoke\(|(?:^|\s)&\s*\(/i
const CHAR_ASM = /\[char(?:\[\])?\]|\[array\]::reverse/i
const FMT_REPLACE = /-f\b|-replace\b|\.replace\(/i
const GETSTRING = /getstring/i
const FETCH_HINT = /downloadstring|downloaddata|invoke-webrequest|net\.webclient|iwr\b|irm\b/i

/** Scan the DEEPEST decoded text for encoding constructs that produced no
 *  decode layer — the honesty spine (spec §4.1). Each finding becomes an
 *  opaque DecodedLayer + an opaque bullet in analyze(). Conservative by
 *  design: every rule carries a benign-twin discriminator so an honest
 *  "opaque, escalate" never becomes cry-wolf. Deduped by construct. */
export function detectResidue(text: string, interpreter: Interpreter): ResidueFinding[] {
  const out: ResidueFinding[] = []
  const push = (construct: string, note: string, sample: string) => {
    if (out.some((f) => f.construct === construct)) return
    out.push({ construct, note, bytes: sample.replace(/\s+/g, '').length, entropy: entropy(sample) })
  }
  const lits = stringLiterals(tokenize(text))

  // R1 — a base64 literal handed to a decode API but not decoded into a layer.
  if (DECODE_API.test(text)) {
    const b64 = lits.find((l) => l.replace(/\s+/g, '').length >= 16 && looksBase64(l))
    if (b64) push('base64', 'a Base64 blob passed to a decode API could not be decoded', b64)
  }

  // R2/R3 — a dynamic-exec sink over a still-unresolved obfuscation construct.
  // Excludes a plain network fetch operand (that is download-cradle's job).
  if (SINK.test(text) && !FETCH_HINT.test(text)) {
    if (CHAR_ASM.test(text)) push('char-assembly', 'a [char]/-join character-assembly construct feeding execution could not be resolved', text)
    else if (FMT_REPLACE.test(text) || GETSTRING.test(text)) push('dynamic-exec', 'an obfuscated string feeding execution could not be resolved', text)
  }

  // R4 — cmd variable substring/reassembly (cmd interpreter path only).
  if (interpreter === 'cmd') {
    const sub = text.match(/%[A-Za-z_][\w]*:~\d+(?:,-?\d+)?%/)
    if (sub) push('cmd-var', 'a cmd %VAR:~n,m% substring construct could not be resolved', sub[0])
  }

  return out
}
