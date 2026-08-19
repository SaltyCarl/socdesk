export interface Token {
  type: 'string' | 'bareword' | 'punct'
  value: string // resolved content (for strings, the literal payload)
  raw: string   // exact source slice including quotes
  start: number
  end: number
}

const DQ_ESCAPES: Record<string, string> = { n: '\n', t: '\t', r: '\r', '0': '\0', a: '\x07', b: '\b', f: '\f', v: '\v' }
const PUNCT = new Set(['|', ';', '(', ')', '{', '}', '[', ']', ',', '='])

/** Lex PowerShell into a flat token stream. The ONLY correctness guarantee we
 *  rely on downstream: string-literal contents are extracted exactly, so a
 *  backtick-escape or an inner quote is never mistaken for structure. */
export function tokenize(source: string): Token[] {
  const out: Token[] = []
  let i = 0
  const n = source.length
  while (i < n) {
    const c = source[i]
    if (c === ' ' || c === '\t' || c === '\r' || c === '\n') { i++; continue }
    if (c === "'") { // single-quoted: literal; '' is an escaped quote
      const start = i; i++
      let v = ''
      while (i < n) {
        if (source[i] === "'") {
          if (source[i + 1] === "'") { v += "'"; i += 2; continue }
          i++; break
        }
        v += source[i]; i++
      }
      out.push({ type: 'string', value: v, raw: source.slice(start, i), start, end: i })
      continue
    }
    if (c === '"') { // double-quoted: backtick escapes; "" is an escaped quote
      const start = i; i++
      let v = ''
      while (i < n) {
        if (source[i] === '`' && i + 1 < n) { const e = source[i + 1]; v += DQ_ESCAPES[e] ?? e; i += 2; continue }
        if (source[i] === '"') {
          if (source[i + 1] === '"') { v += '"'; i += 2; continue }
          i++; break
        }
        v += source[i]; i++
      }
      out.push({ type: 'string', value: v, raw: source.slice(start, i), start, end: i })
      continue
    }
    if (PUNCT.has(c)) { out.push({ type: 'punct', value: c, raw: c, start: i, end: i + 1 }); i++; continue }
    // bareword: run until whitespace or punct or a quote (backtick escapes a char)
    const start = i
    let v = ''
    while (i < n) {
      const d = source[i]
      if (d === ' ' || d === '\t' || d === '\r' || d === '\n' || PUNCT.has(d) || d === "'" || d === '"') break
      if (d === '`' && i + 1 < n) { v += source[i + 1]; i += 2; continue } // outside strings: backtick = no-op escape
      v += d; i++
    }
    out.push({ type: 'bareword', value: v, raw: source.slice(start, i), start, end: i })
  }
  return out
}

/** Every string-literal payload, in source order. */
export function stringLiterals(tokens: Token[]): string[] {
  return tokens.filter((t) => t.type === 'string').map((t) => t.value)
}
