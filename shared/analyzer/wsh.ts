// shared/analyzer/wsh.ts
//
// Grammar-light numeric-char-code decode for VBScript/JScript payloads (§4) —
// Chr(72)&Chr(105) (VBScript) and String.fromCharCode(72,105) (JScript) ->
// their literal text. A regex-driven text->text transform, NOT a WSH
// lexer/interpreter: no string-concat folding, no Execute/eval recursion —
// both are explicit, bounded, out-of-scope follow-ups (spec §4's YAGNI cut).
// Interpreter-gated to mshta/wscript/cscript by its ONE call site in
// report.ts — Chr()/fromCharCode syntax has no PowerShell meaning.

function decodeChrChain(text: string): string {
  return text.replace(/Chr\(\d{1,3}\)(?:\s*&\s*Chr\(\d{1,3}\))*/gi, (chain) => {
    const codes = [...chain.matchAll(/Chr\((\d{1,3})\)/gi)].map((m) => Number(m[1]))
    return codes.map((c) => String.fromCharCode(c)).join('')
  })
}

function decodeFromCharCode(text: string): string {
  return text.replace(/String\.fromCharCode\(([\d,\s]+)\)/gi, (_m, args: string) => {
    const codes = args.split(',').map((s) => Number(s.trim())).filter((n) => !Number.isNaN(n))
    return codes.map((c) => String.fromCharCode(c)).join('')
  })
}

export function decodeNumericCharCodes(text: string): string {
  return decodeFromCharCode(decodeChrChain(text))
}
