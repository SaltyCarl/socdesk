import type { EvasionFlag } from './types'

// PowerShell accepts unambiguous prefixes of parameter names; match the ones
// that carry evasion meaning. Each entry: canonical flag → { regex, technique }.
const FLAG_RULES: { flag: string; re: RegExp; techniqueIds: string[] }[] = [
  { flag: '-enc', re: /(?:^|\s)-e(?:c|nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{8,})/i, techniqueIds: ['T1027', 'T1140'] },
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
  // Strip a leading powershell(.exe)/pwsh invocation wrapper; keep the -Command body if present.
  // (per-interpreter body extraction lands in Task 3 — unchanged here.)
  let script = input.replace(/^\s*(?:["']?[^"'\s]*\b)?(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b/i, '')
  const cmd = script.match(/-c(?:ommand)?\s+(.*)$/is)
  if (cmd) script = cmd[1]
  return { script: script.trim(), encoded, flags, interpreter }
}
