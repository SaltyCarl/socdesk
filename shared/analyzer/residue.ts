import { tokenize, stringLiterals } from './lex'
import { looksBase64 } from './fold'
import { FETCH } from './techniques'
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
// [char]-array assembly AND a bare -join/reversal idiom (e.g. a VARIABLE-
// subject `$s[-1..-3] -join ''` — resolve() intentionally leaves this
// unfolded since $s isn't a literal, per resolve.ts's own "leaves a
// variable-subject reversal untouched" doctrine) are the same class of
// construction evidence per spec §4.1's R2/R3 list — whole-branch review
// finding 2: a bare `-join` was previously only matched INSIDE the
// char-array pattern, so a reversal/array-assembly over a variable produced
// zero layers/signals/bullets, identical to benign input.
const CHAR_ASM = /\[char(?:\[\])?\]|\[array\]::reverse|-join\b/i
const FMT_REPLACE = /-f\b|-replace\b|\.replace\(/i
const GETSTRING = /getstring/i
// A variable operand concatenated with `+` (either side) — spec §4.1's
// "concat-with-variables" construction evidence, e.g. `IEX ($a + $b)` where
// $a/$b could not be resolved to literals.
const VAR_CONCAT = /\$[A-Za-z_]\w*\s*\+|\+\s*\$[A-Za-z_]\w*/

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
  let base64Found = false

  // R1 — a base64 literal handed to a decode API but not decoded into a layer.
  if (DECODE_API.test(text)) {
    const b64 = lits.find((l) => l.replace(/\s+/g, '').length >= 16 && looksBase64(l))
    if (b64) { push('base64', 'a Base64 blob passed to a decode API could not be decoded', b64); base64Found = true }
  }

  // R2/R3 — a dynamic-exec sink over a still-unresolved obfuscation construct.
  // Excludes a plain network fetch operand (that is download-cradle's job) —
  // checked against the canonical fetch vocabulary, not a hand-copied subset.
  const lower = text.toLowerCase()
  const hasFetch = FETCH.some((f) => lower.includes(f))
  if (SINK.test(text) && !hasFetch) {
    if (CHAR_ASM.test(text)) push('char-assembly', 'a [char]/-join character-assembly construct feeding execution could not be resolved', text)
    else if (FMT_REPLACE.test(text)) push('dynamic-exec', 'an obfuscated string feeding execution could not be resolved', text)
    else if (VAR_CONCAT.test(text)) push('dynamic-exec', 'a variable-concatenation construct feeding execution could not be resolved', text)
    // GetString off an already-flagged base64 blob is the SAME residue, not a second finding.
    else if (GETSTRING.test(text) && !base64Found) push('dynamic-exec', 'an obfuscated string feeding execution could not be resolved', text)
  }

  // R4 — cmd variable substring/reassembly (cmd interpreter path only).
  if (interpreter === 'cmd') {
    const sub = text.match(/%[A-Za-z_][\w]*:~-?\d+(?:,-?\d+)?%/)
    if (sub) push('cmd-var', 'a cmd %VAR:~n,m% substring construct could not be resolved', sub[0])
  }

  return out
}
