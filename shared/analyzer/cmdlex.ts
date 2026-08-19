// shared/analyzer/cmdlex.ts
//
// cmd.exe caret (^) deobfuscation — a raw-text→raw-text normalizer, NOT a
// tokenizer. cmd's caret rule has the opposite quote-scoping shape from
// PowerShell's backtick rule (PS: backtick escapes inside nothing special;
// cmd: caret is suppressed INSIDE double quotes), so it cannot be folded into
// lex.ts's token stream without corrupting PS literal-safety — it must be a
// separate module.
//
// NON-NEGOTIABLE: this module's normalizer is invoked ONLY from preprocess.ts's
// cmd body-extraction branch (interpreter === 'cmd'). Never call it from any
// other interpreter's path, including 'unknown' — running caret-stripping on
// PowerShell text corrupts legitimate regex literals such as '^https?://'.

/** Track double-quote parity only — single quotes are not tracked at all
 *  (cmd does not caret-process inside "…", but it DOES caret-process inside a
 *  for /f's '…' list, which is a list delimiter, not a cmd string-literal
 *  quote). Outside "…": ^^ -> ^; a bare ^ is dropped and the next character is
 *  kept literally (mirrors lex.ts:56-57's backtick no-op-escape mechanic,
 *  keyed on ^ instead of `). Inside "…": carets are left untouched. A
 *  trailing ^ at end-of-line is a line-continuation marker, not a
 *  per-character escape — it must not consume past EOL into a synthetic next
 *  character. */
export function deobfuscateCaret(text: string): string {
  let out = ''
  let inDouble = false
  let i = 0
  const n = text.length
  while (i < n) {
    const c = text[i]
    if (c === '"') { inDouble = !inDouble; out += c; i++; continue }
    if (!inDouble && c === '^') {
      const next = text[i + 1]
      if (next === undefined || next === '\n' || next === '\r') { out += c; i++; continue }
      if (next === '^') { out += '^'; i += 2; continue }
      out += next; i += 2; continue
    }
    out += c; i++
  }
  return out
}
