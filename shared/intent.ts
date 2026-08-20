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
 *  never in a bare indicator. Word-bounded, so `powershell` also fires inside
 *  a bare LOLBin filename like `powershell.exe` (the `.` is a non-word
 *  boundary) — that is intentional: it stops that filename being misread as
 *  a domain by detectType's domain regex (indicators.ts:62). `rundll32` and
 *  the rest of the cmd/multi-interpreter LOLBin set are covered separately
 *  by EXE_NAME_RE below, which adds a dot-continuation guard those names
 *  need (a bare `rundll32.io`/`finger.io`/`certutil.info` reads as a
 *  plausible domain in a way `powershell.io` does not, so those need to stay
 *  indicators while `powershell.exe` intentionally does not). Invoke-*
 *  cmdlets (Invoke-Expression, Invoke-WebRequest, Invoke-Mimikatz, …) are
 *  handled separately by INVOKE_RE below, NOT here — a plain `\b`
 *  word-boundary match on `invoke-\w+`/`invoke-expression` also fires inside
 *  a hyphenated domain like `invoke-example.com` (the `.` is a non-word
 *  boundary too), which is a false positive: a domain, not a command. */
const COMMAND_TOKEN_RE = /\b(powershell|pwsh|iex|new-object)\b/i

/** Invoke-<cmdlet> forms (Invoke-Expression, Invoke-WebRequest,
 *  Invoke-Mimikatz, …), covering the family without listing every cmdlet by
 *  name. A real cmdlet invocation is always followed by whitespace, a `(`
 *  (method-call style), or end-of-string — never by more identifier
 *  characters straight into a TLD. That lookahead is what lets `Invoke-
 *  WebRequest https://…`/`Invoke-Expression(...)`/a bare `Invoke-Mimikatz`
 *  match while `invoke-example.com` (followed by `.com`) does not. Anchored
 *  to a preceding token boundary (start-of-string or whitespace) for the
 *  same reason ENC_FLAG_RE is: it must look like a standalone token, not a
 *  fragment stitched mid-word. */
const INVOKE_RE = /(?:^|\s)invoke-[a-z]+(?=[\s(]|$)/i

/** `-e`, `-enc`, or `-encodedcommand` — PowerShell's Base64 payload flag in
 *  every abbreviation the interpreter accepts. Anchored to a preceding token
 *  boundary (start-of-string or whitespace): a real PowerShell flag is always
 *  preceded by whitespace (or starts the string), never sits mid-word. That
 *  anchor is what stops it firing inside a hyphenated domain label or path
 *  segment like `site-enc.com`, `sync-enc.io`, or `/setup-enc` — none of
 *  which have whitespace before the `-e`/`-enc` — while still matching a
 *  real ` -enc <b64>`/`-enc <b64>`-at-start flag. */
const ENC_FLAG_RE = /(?:^|\s)-e(nc|ncodedcommand)?\b/i

/** Distinctive multi-interpreter / LOLBin executable names — `mshta`,
 *  `cscript`/`wscript`, and a handful of LOLBins (`regsvr32`, `rundll32`,
 *  `certutil`, `bitsadmin`, `finger`, `wmic`, `msiexec`) that only ever show
 *  up as the leading token of a command line, never as a bare indicator —
 *  with one wrinkle: several of them ALSO read as plausible domain labels
 *  (`finger.io`, `wmic.io`, `certutil.info`, `bitsadmin.io`, …). The
 *  trailing negative lookahead `(?!\.[a-z])` excludes exactly that shape —
 *  a dot immediately followed by a letter reads as a TLD continuation — so
 *  `finger.io` stays a bare domain while `finger user@host`,
 *  `mshta http://…`, and `regsvr32 /s …` still match. An optional `.exe`
 *  suffix is allowed before the boundary so `regsvr32.exe` also matches. */
const EXE_NAME_RE =
  /\b(?:mshta|[cw]script|regsvr32|rundll32|certutil|bitsadmin|finger|wmic|msiexec)(?:\.exe)?\b(?!\.[a-z])/i

/** cmd.exe (or cmd) invoked with its `/c` or `/k` run-and-exit flag — the
 *  unambiguous cmd.exe interpreter shape, e.g. `cmd.exe /c whoami` or
 *  `cmd /k dir`. */
const CMD_INTERPRETER_RE = /\bcmd(?:\.exe)?\s+\/[ck]\b/i

/** cmd's FOR loop in any of its `/f`, `/l`, `/r`, … variants
 *  (`for /f %%i in (...) do ...`) — a shape that only appears in a
 *  batch/cmd command line, never in a bare indicator. */
const CMD_FORLOOP_RE = /\bfor\s+\/[a-z]\b/i

/** Shell/PS punctuation that never appears in a bare indicator: statement
 *  separator, pipe, backtick (PowerShell's escape/obfuscation character), a
 *  command-substitution open, and cmd.exe's `&`/`&&` command separator. The
 *  `&`/`&&` alternative only matches when whitespace-flanked (`\s&\s`) or
 *  doubled (`&&`) — a bare, un-flanked single `&` also shows up in an
 *  ordinary URL query string (`?a=1&b=2`, no surrounding whitespace), so
 *  that shape is deliberately NOT matched. On their own these are too
 *  common to trust (a URL query string can contain `|`) — they only count
 *  alongside >=2 whitespace-separated tokens, i.e. something that reads as
 *  a command line rather than a single pasted value. */
const SHELL_PUNCT_RE = /[;|`]|\$\(|\s&\s|&&/

function looksLikeCommand(raw: string): boolean {
  if (raw.includes('\n')) return true
  if (COMMAND_TOKEN_RE.test(raw)) return true
  if (INVOKE_RE.test(raw)) return true
  if (ENC_FLAG_RE.test(raw)) return true
  if (EXE_NAME_RE.test(raw)) return true
  if (CMD_INTERPRETER_RE.test(raw)) return true
  if (CMD_FORLOOP_RE.test(raw)) return true
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
