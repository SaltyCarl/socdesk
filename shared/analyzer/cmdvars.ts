// shared/analyzer/cmdvars.ts
//
// cmd.exe set/%var% reassembly (review 2.5). Runs ONLY from preprocess.ts's
// cmd branch (extractCmdBody), AFTER caret de-obfuscation — never on
// PowerShell text. Straight-line, depth-1 reference expansion, var map capped
// so a hostile `set` chain can't spin the analyzer.
//
// LITERAL-SAFETY: cmd's set/%var% operates on raw command-line text (cmd has
// no PowerShell-style string tokens in the same sense), so a raw-text
// approach is acceptable here — but a %VAR% reference is only substituted
// when VAR was actually `set` in the same text. An unresolved reference to an
// unknown/environment var (e.g. a bare %PATH%) is left untouched so it stays
// honest and residue.ts's R4 can still flag an unresolved %VAR:~n,m%.

const MAX_VARS = 64

/** Parse straight-line `set VAR=VALUE` (and quoted `set "VAR=VALUE"`), then
 *  substitute `%VAR%`/`!VAR!` and `%VAR:~n,m%`/`!VAR:~n,m!` references
 *  depth-1 (no recursive re-expansion of a substituted value). Returns the
 *  reassembled text and whether anything changed (a signal for the caller). */
export function reassembleCmdVars(text: string): { text: string; changed: boolean } {
  const vars = new Map<string, string>()
  const setRe = /\bset\s+(?:"([A-Za-z_]\w*)=([^"]*)"|([A-Za-z_]\w*)=([^&|<>\r\n]*))/gi
  let m: RegExpExecArray | null
  while ((m = setRe.exec(text)) !== null) {
    if (vars.size >= MAX_VARS) break
    const name = (m[1] ?? m[3] ?? '').toLowerCase()
    const value = m[2] ?? m[4] ?? ''
    if (name) vars.set(name, value.trim())
  }
  if (!vars.size) return { text, changed: false }

  // delayed-expansion (!VAR!) is treated the same as %VAR% when the payload
  // opts in via `setlocal enabledelayedexpansion` (or the bare directive).
  const delayed = /enabledelayedexpansion/i.test(text)

  const expand = (name: string, spec?: string): string | null => {
    const v = vars.get(name.toLowerCase())
    if (v === undefined) return null
    if (!spec) return v
    // %VAR:~n,m% — n may be negative (from end); m optional, may be negative.
    const sm = spec.match(/^~(-?\d+)(?:,(-?\d+))?$/)
    if (!sm) return v
    const n = Number(sm[1])
    const start = n < 0 ? Math.max(v.length + n, 0) : n
    if (sm[2] === undefined) return v.slice(start)
    const len = Number(sm[2])
    return len < 0 ? v.slice(start, v.length + len) : v.slice(start, start + len)
  }

  let changed = false
  const substitute = (name: string, spec: string): string | undefined => {
    const rep = expand(name, spec ? spec.slice(1) : undefined)
    if (rep === null) return undefined
    changed = true
    return rep
  }

  // Delimiters must be paired (%VAR% or !VAR!, never mixed) — a backreference
  // on the opening delimiter enforces that, rather than a loose [%!] class.
  const out = delayed
    ? text.replace(
        /([%!])([A-Za-z_]\w*)((?::~-?\d+(?:,-?\d+)?)?)\1/g,
        (whole: string, _delim: string, name: string, spec: string) => substitute(name, spec) ?? whole,
      )
    : text.replace(
        /%([A-Za-z_]\w*)((?::~-?\d+(?:,-?\d+)?)?)%/g,
        (whole: string, name: string, spec: string) => substitute(name, spec) ?? whole,
      )
  return { text: out, changed }
}
