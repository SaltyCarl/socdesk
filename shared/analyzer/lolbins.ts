import type { RuleContext } from './types'

/** A LOLBAS/native binary that becomes suspicious ONLY in a download/exec form.
 *  `bin` is the binary name; `context` are the discriminators that separate the
 *  abusive form from benign use (a URL, an install/exec switch). A bare mention
 *  of `bin` never fires — one of `context` must co-occur. Public-sources only
 *  (lolbas-project.github.io + MS docs); hand-authored, no live fetch. */
export interface LolbinEntry {
  bin: string
  context: string[]      // at least one must co-occur with `bin`
  techniqueIds: string[]
}

export const LOLBINS: LolbinEntry[] = [
  { bin: 'certutil', context: ['-urlcache', '-verifyctl', 'http://', 'https://'], techniqueIds: ['T1105'] },
  { bin: 'bitsadmin', context: ['/transfer', '/addfile', 'http://', 'https://'], techniqueIds: ['T1105', 'T1197'] },
  { bin: 'mshta', context: ['http://', 'https://', 'javascript:', 'vbscript:', '.hta'], techniqueIds: ['T1218.005'] },
  { bin: 'regsvr32', context: ['/i:http', 'scrobj', 'http://', 'https://'], techniqueIds: ['T1218.010'] },
  { bin: 'rundll32', context: ['javascript:', 'url.dll,fileprotocolhandler', 'mshtml,runhtmlapplication'], techniqueIds: ['T1218.011'] },
  { bin: 'msiexec', context: ['/i http', '/i https', '/package http'], techniqueIds: ['T1218.007'] },
  { bin: 'wmic', context: ['process call create', '/node:', 'format:http'], techniqueIds: ['T1047'] },
  { bin: 'installutil', context: ['/logfile=', 'logtoconsole'], techniqueIds: ['T1218.004'] },
  { bin: 'conhost', context: ['--headless'], techniqueIds: ['T1059.001'] },
  // finger.exe fetching a payload via a for /f download/exec cradle — the
  // discriminator is real co-occurrence with the cradle shape, not a bare
  // mention (finger alone is used for legitimate directory-protocol lookups).
  { bin: 'finger', context: ['for /f', 'do %'], techniqueIds: ['T1105'] },
  // NOTE: `start` is intentionally NOT a standalone LOLBin entry — it's a
  // companion discriminator only, usable inside cmd-cradle/clickfix's own
  // test() functions. `start notepad.exe` alone is unremarkable; registering
  // it here would fire on ordinary benign shell usage.
]

/** Match the first LOLBin whose binary name AND at least one discriminator both
 *  appear in the decoded corpus. Returns a single hit (the highest-value one, in
 *  table order) — the rule layer renders it as one 'lolbin' signal naming the
 *  binary. Case-insensitive; substring over token values (literal-safe) with a
 *  whole-text fallback for phrase discriminators like 'process call create'. */
export function matchLolbin(ctx: RuleContext): { hit: boolean; trigger?: string; techniqueIds?: string[]; label?: string } {
  const present = (needle: string): boolean => {
    const k = needle.toLowerCase()
    return ctx.words.some((w) => w.includes(k)) || ctx.lower.includes(k)
  }
  for (const e of LOLBINS) {
    if (!present(e.bin)) continue
    if (!e.context.some(present)) continue
    return { hit: true, trigger: e.bin, techniqueIds: e.techniqueIds, label: `LOLBin: ${e.bin}` }
  }
  return { hit: false }
}
