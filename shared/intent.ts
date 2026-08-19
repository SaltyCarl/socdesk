// intent.ts — the cockpit's DATA-BOUNDARY classifier: routes a pasted omnibox
// value to enrichment or the local analyzer before either surface ever sees
// it.
//
// This is the single source of truth every submit path MUST call BEFORE
// detectType (shared/indicators.ts) gets anywhere near the raw value.
// detectType alone is not safe here: its URL regex is prefix-only
// (`/^https?:\/\//i`, not end-anchored — indicators.ts:61), so a pasted
// script whose FIRST LINE is a download URL classifies as `'url'` under
// detectType alone, and the entire multi-line blob would be sent to the
// third-party /api/enrich endpoint as `?q=<full text>` (indicators.ts:110-112
// -> useLookup.ts:106 -> shared/verdict/client.ts:81-98). A pasted command
// must NEVER reach /api/enrich — classifyCockpitInput is the guard that makes
// that true.
//
// Pure, synchronous, no I/O — safe to call on every keystroke as well as on
// submit.

import { detectType, refang } from './indicators'

export type CockpitInputKind = 'indicator' | 'command' | 'unclassified'

/** Command/script tokens that only show up in a PowerShell or shell paste —
 *  never in a bare indicator. `invoke-\w+` covers Invoke-Expression's many
 *  cmdlet siblings (Invoke-WebRequest, Invoke-RestMethod, …) without listing
 *  them one by one. Word-bounded, so `powershell` also fires inside a bare
 *  LOLBin filename like `powershell.exe` (the `.` is a non-word boundary) —
 *  that is intentional: it stops that filename being misread as a domain by
 *  detectType's domain regex (indicators.ts:62). `rundll32.exe` is NOT
 *  covered by this token list (a known, lesser gap the design spec §2.1
 *  calls out and explicitly leaves out of v1 scope). */
const COMMAND_TOKEN_RE = /\b(powershell|pwsh|iex|invoke-expression|invoke-\w+|new-object)\b/i

/** `-e`, `-enc`, or `-encodedcommand` — PowerShell's Base64 payload flag in
 *  every abbreviation the interpreter accepts. */
const ENC_FLAG_RE = /-e(nc|ncodedcommand)?\b/i

/** Shell/PS punctuation that never appears in a bare indicator: statement
 *  separator, pipe, backtick (PowerShell's escape/obfuscation character), and
 *  a command-substitution open. On their own these are too common to trust
 *  (a URL query string can contain `|`) — they only count alongside >=2
 *  whitespace-separated tokens, i.e. something that reads as a command line
 *  rather than a single pasted value. */
const SHELL_PUNCT_RE = /[;|`]|\$\(/

function looksLikeCommand(raw: string): boolean {
  if (raw.includes('\n')) return true
  if (COMMAND_TOKEN_RE.test(raw)) return true
  if (ENC_FLAG_RE.test(raw)) return true
  if (SHELL_PUNCT_RE.test(raw)) {
    const tokenCount = raw.trim().split(/\s+/).filter(Boolean).length
    if (tokenCount >= 2) return true
  }
  return false
}

/**
 * Classify a raw omnibox value. Command wins ties — a value that is BOTH
 * command-shaped and indicator-shaped (e.g. `powershell.exe`, which also
 * satisfies detectType's domain regex) still resolves to `'command'`,
 * because the command check runs first and returns immediately. This
 * ordering is the data-boundary guarantee: detectType only ever sees a
 * value this function has already ruled out as a command.
 */
export function classifyCockpitInput(raw: string): CockpitInputKind {
  if (looksLikeCommand(raw)) return 'command'
  if (detectType(refang(raw)) !== '') return 'indicator'
  return 'unclassified'
}
