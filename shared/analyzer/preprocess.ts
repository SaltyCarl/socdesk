import type { EvasionFlag } from './types'
import { deobfuscateCaret } from './cmdlex'

// PowerShell accepts unambiguous prefixes of parameter names; match the ones
// that carry evasion meaning. Each entry: canonical flag → { regex, technique }.
const FLAG_RULES: { flag: string; re: RegExp; techniqueIds: string[] }[] = [
  // Capture group tolerates interior whitespace (spaces/newlines) so a
  // line-wrapped -enc blob pasted out of an EDR/Sysmon log — routinely
  // wrapped at console width — is captured whole; fold.ts strips it before
  // decoding. A bare `[A-Za-z0-9+/=]{8,}` here would silently truncate the
  // capture at the first wrap point.
  { flag: '-enc', re: /(?:^|\s)-e(?:c|nc|ncodedcommand)?\s+([A-Za-z0-9+/=\s]{8,})/i, techniqueIds: ['T1027', 'T1140'] },
  { flag: '-nop', re: /(?:^|\s)-nop(?:rofile)?\b/i, techniqueIds: ['T1059.001'] },
  { flag: '-w', re: /(?:^|\s)-w(?:indowstyle)?\s+(?:hidden|h|1|minimized)\b/i, techniqueIds: ['T1564.003'] },
  { flag: '-ep', re: /(?:^|\s)-e(?:p|xec(?:utionpolicy)?)\s+(?:bypass|unrestricted)\b/i, techniqueIds: ['T1059.001'] },
  { flag: '-noni', re: /(?:^|\s)-noni(?:nteractive)?\b/i, techniqueIds: ['T1059.001'] },
  { flag: '-sta', re: /(?:^|\s)-sta\b/i, techniqueIds: ['T1059.001'] },
]

export type Interpreter = 'powershell' | 'cmd' | 'mshta' | 'wscript' | 'cscript' | 'unknown'

// Same path/quote-prefix shape as the PS-wrapper strip below — a leading token
// optionally preceded by a quoted/unquoted path, then the interpreter binary
// name. Order = specificity: check the four new interpreters before falling
// back to powershell/pwsh.
const INTERPRETER_RE: { interpreter: Interpreter; re: RegExp }[] = [
  { interpreter: 'cmd', re: /^\s*(?:["']?[^"'\s]*\b)?cmd(?:\.exe)?\b/i },
  { interpreter: 'mshta', re: /^\s*(?:["']?[^"'\s]*\b)?mshta(?:\.exe)?\b/i },
  { interpreter: 'wscript', re: /^\s*(?:["']?[^"'\s]*\b)?wscript(?:\.exe)?\b/i },
  { interpreter: 'cscript', re: /^\s*(?:["']?[^"'\s]*\b)?cscript(?:\.exe)?\b/i },
  { interpreter: 'powershell', re: /^\s*(?:["']?[^"'\s]*\b)?(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b/i },
]

export function detectInterpreter(input: string): Interpreter {
  for (const { interpreter, re } of INTERPRETER_RE) {
    if (re.test(input)) return interpreter
  }
  return 'unknown'
}

// WSH-scoped flag rules — structurally the same shape as FLAG_RULES, gated to
// only ever be checked from the wscript/cscript branch below so they can never
// collide with PowerShell's own -w/-nop/etc.
const WSH_FLAG_RULES: { flag: string; re: RegExp; techniqueIds: string[] }[] = [
  { flag: '//E:vbscript', re: /\/\/E:vbscript\b/i, techniqueIds: ['T1059.005'] },
  { flag: '//E:jscript', re: /\/\/E:jscript\b/i, techniqueIds: ['T1059.007'] },
  { flag: '//B', re: /\/\/B\b/i, techniqueIds: ['T1564.003'] },
  { flag: '//NoLogo', re: /\/\/NoLogo\b/i, techniqueIds: ['T1564.003'] },
]

// Extract the /c or /k body, mirroring the shape of the existing -Command
// extraction: match a flag, take the rest of the line.
function extractCmdBody(input: string): string {
  const m = input.match(/\/(?:c|k)\s+(.*)$/is)
  const body = m ? m[1] : input
  return deobfuscateCaret(body).trim()
}

// The argument itself IS the payload: a URL, a local .hta path, or an inline
// vbscript:/javascript: scheme. Strip only the leading mshta(.exe) token.
function extractMshtaBody(input: string): string {
  const m = input.match(/^\s*(?:["']?[^"'\s]*\b)?mshta(?:\.exe)?\b\s*(.*)$/is)
  return (m ? m[1] : input).trim()
}

// Extract the .vbs/.js target (or inline target) and recognize //E:/-B/-NoLogo
// as evasion/config flags, pushed into the shared `flags` array.
function extractWshBody(input: string, flags: EvasionFlag[]): string {
  for (const rule of WSH_FLAG_RULES) {
    const m = input.match(rule.re)
    if (!m) continue
    flags.push({ flag: rule.flag, raw: m[0].trim(), techniqueIds: rule.techniqueIds })
  }
  const stripped = input
    .replace(/^\s*(?:["']?[^"'\s]*\b)?(?:wscript(?:\.exe)?|cscript(?:\.exe)?)\b/i, '')
    .replace(/\/\/\S+/g, '')
  return stripped.trim()
}

export function preprocess(input: string): { script: string; encoded: string | null; flags: EvasionFlag[]; interpreter: Interpreter } {
  const flags: EvasionFlag[] = []
  let encoded: string | null = null
  for (const rule of FLAG_RULES) {
    const m = input.match(rule.re)
    if (!m) continue
    flags.push({ flag: rule.flag, raw: m[0].trim(), techniqueIds: rule.techniqueIds })
    if (rule.flag === '-enc' && m[1]) encoded = m[1]
  }
  const interpreter = detectInterpreter(input)
  let script: string
  if (interpreter === 'cmd') {
    script = extractCmdBody(input)
  } else if (interpreter === 'mshta') {
    script = extractMshtaBody(input)
  } else if (interpreter === 'wscript' || interpreter === 'cscript') {
    script = extractWshBody(input, flags)
  } else {
    // powershell / unknown — unchanged from Task 2/pre-increment behavior.
    let s = input.replace(/^\s*(?:["']?[^"'\s]*\b)?(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b/i, '')
    const cmd = s.match(/-c(?:ommand)?\s+(.*)$/is)
    if (cmd) s = cmd[1]
    script = s
  }
  return { script: script.trim(), encoded, flags, interpreter }
}
