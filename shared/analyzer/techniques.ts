import type { EvasionFlag, RuleContext, Signal, Specificity } from './types'
import type { Interpreter } from './preprocess'
import { tokenize } from './lex'
import { matchLolbin } from './lolbins'

export interface RuleHit {
  hit: boolean
  trigger?: string
  techniqueIds?: string[]  // overrides the rule's static ids when a rule is data-driven (LOLBins)
  label?: string           // overrides the rule's static label (LOLBins name the binary)
}

export interface SignatureRule {
  id: string
  label: string
  techniqueIds: string[]
  baseSpecificity: Specificity
  upgradesWith: string[]   // companion rule ids: if any co-fires, bump this rule one tier
  test(ctx: RuleContext): RuleHit
}

/** Build the read-only match context once per analysis. `words` are lowercased
 *  bareword/string token values (backtick obfuscation already stripped by the
 *  lexer); `lower` is the whole-text fallback for multi-word phrases. */
export function buildContext(text: string, flags: EvasionFlag[], interpreter: Interpreter = 'unknown'): RuleContext {
  const tokens = tokenize(text)
  const words = tokens
    .filter((t) => t.type === 'bareword' || t.type === 'string')
    .map((t) => t.value.toLowerCase())
  return { text, lower: text.toLowerCase(), tokens, words, flags, interpreter }
}

// ---- match helpers (all case-insensitive; token-value first, whole-text fallback) ----

function present(ctx: RuleContext, needle: string): boolean {
  const k = needle.toLowerCase()
  return ctx.words.some((w) => w.includes(k)) || ctx.lower.includes(k)
}
function hasAll(ctx: RuleContext, needles: string[]): boolean {
  return needles.every((n) => present(ctx, n))
}
function hasAny(ctx: RuleContext, needles: string[]): boolean {
  return needles.some((n) => present(ctx, n))
}
function flagSet(ctx: RuleContext): Set<string> {
  return new Set(ctx.flags.map((f) => f.flag))
}
const TRIGGER_MAX = 64

/** A short, single-line context snippet around a match at `start` in `text` —
 *  never crosses a newline. `text` here is `analyze()`'s scan corpus: the raw
 *  input plus every decode layer, joined with '\n'. Deriving a trigger from a
 *  matched TOKEN's raw span used to be unsafe: an unterminated quote in one
 *  joined fragment lexes straight through the newline into the next, so the
 *  "matching" token could span two unrelated layers and its raw slice spliced
 *  fragments from both into one garbled run-on string (e.g. a mshta wrapper's
 *  closing quote fusing with a later decoded-layer copy of the same script).
 *  Anchoring the window to the line containing `start`, with a hard length
 *  cap, makes that structurally impossible — the result is always one clean
 *  fragment. */
function triggerWindow(text: string, start: number): string {
  const lineStart = text.lastIndexOf('\n', Math.max(start - 1, 0)) + 1
  const lineEndIdx = text.indexOf('\n', start)
  const lineEnd = lineEndIdx === -1 ? text.length : lineEndIdx
  const windowStart = Math.max(lineStart, start - 8)
  const windowEnd = Math.min(lineEnd, start + TRIGGER_MAX)
  const snippet = text.slice(windowStart, windowEnd).trim()
  return windowEnd < lineEnd ? snippet + '…' : snippet
}

/** Audit trigger for the first needle that matches. Searches the plain
 *  corpus text first (cheap, and immune to the corpus-join issue
 *  triggerWindow guards against); falls back to a token's parsed VALUE only
 *  for a match that exists solely in de-obfuscated form (e.g. a backtick-
 *  split keyword) — either way the returned snippet is windowed, never a raw
 *  token span. */
function triggerFor(ctx: RuleContext, needles: string[]): string {
  for (const n of needles) {
    const k = n.toLowerCase()
    const idx = ctx.lower.indexOf(k)
    if (idx !== -1) return triggerWindow(ctx.text, idx)
    const tok = ctx.tokens.find(
      (t) => (t.type === 'bareword' || t.type === 'string') && t.value.toLowerCase().includes(k),
    )
    if (tok) return triggerWindow(ctx.text, tok.start)
  }
  return needles[0]
}

// Shared vocab.
const FETCH = ['downloadstring', 'downloaddata', 'downloadfile', 'invoke-webrequest', 'iwr', 'invoke-restmethod', 'irm', 'net.webclient', 'start-bitstransfer', 'httpclient', 'system.net.webrequest', 'wget', 'curl']

/** IEX / Invoke-Expression / '&' call-operator sink present. `&` is a bareword
 *  to the lexer (not a punct), so it lands in `words`. */
function hasIexSink(ctx: RuleContext): boolean {
  return hasAny(ctx, ['iex', 'invoke-expression', '.invoke(']) || ctx.words.includes('&')
}

// ---- the rule table (extended by Tasks 3–5) ----

const WSH_HTA_INTERPRETERS: Interpreter[] = ['mshta', 'wscript', 'cscript']
const MSHTA_DISCRIMINATORS = ['http://', 'https://', 'javascript:', 'vbscript:', '.hta']

export const RULES: SignatureRule[] = [
  {
    id: 'download-cradle',
    label: 'download cradle',
    techniqueIds: ['T1059.001', 'T1105'],
    baseSpecificity: 'strong',
    upgradesWith: ['amsi-reflection', 'clickfix', 'evasion-cluster'],
    test(ctx) {
      const fetches = hasAny(ctx, FETCH)
      // Discriminator: fetched content must flow into an interpreter, not a file.
      if (fetches && hasIexSink(ctx)) return { hit: true, trigger: triggerFor(ctx, FETCH) }
      return { hit: false }
    },
  },
  {
    id: 'disk-dropper',
    label: 'download-to-disk then execute',
    techniqueIds: ['T1105', 'T1059.001'],
    baseSpecificity: 'strong',
    upgradesWith: ['evasion-cluster', 'defender-tamper', 'clickfix'],
    test(ctx) {
      // Discriminator: fetched content must land on DISK (not flow into an
      // interpreter — that's download-cradle's job), and a separate local-exec
      // sink must then launch it. Either half alone is routine and benign
      // (a bare fetch-to-disk with no launch; a bare Start-Process on an
      // unrelated .exe with no fetch) — both are shipped as negative tests.
      const DISK_NEEDLES = ['downloadfile', '-outfile', 'start-bitstransfer', 'curl -o', 'wget -o']
      // 'ii ' (the Invoke-Item alias) is deliberately NOT a bare substring
      // needle here — it collides with "ascii" (`-Encoding ascii`), firing on
      // a benign fetch-to-disk with no execution. Alias coverage instead uses
      // the bounded II_ALIAS_RE below, gated on the same command-separator
      // requirement as the bare-.exe fallback.
      const EXEC_NEEDLES = ['start-process', 'saps', 'invoke-item']
      // Both fallback patterns require a command separator (`;`/`&`/`|`)
      // immediately before the token — NEVER the start of the corpus. In
      // analyze()'s real pipeline the corpus starts with the verbatim raw
      // input (report.ts), so an unanchored `^` branch previously matched a
      // fully-qualified fetch tool's own name at position 0 — e.g.
      // `certutil.exe -urlcache -split -f http://x.test/a.exe dest.exe` or
      // `powershell.exe -Command "iwr ... -OutFile a.exe"` — firing on pure
      // fetch-to-disk with no execution at all. A separator-anchored token
      // (e.g. `& a.exe`, `; ii payload`) is never confused with the fetching
      // command's own filename, which sits at the very start of the corpus.
      const II_ALIAS_RE = /[;&|]\s*&?\s*ii\s/i
      const EXE_SINK_RE = /[;&|]\s*&?\s*['"]?[^'"\s]+\.exe\b/i
      const diskNeedle = DISK_NEEDLES.find((n) => present(ctx, n))
      const certutilDisk = !diskNeedle && hasAny(ctx, ['certutil']) && hasAny(ctx, ['-urlcache', '-split'])
      if (!diskNeedle && !certutilDisk) return { hit: false }
      const execNeedle = EXEC_NEEDLES.find((n) => present(ctx, n))
      const iiMatch = execNeedle ? undefined : II_ALIAS_RE.exec(ctx.text)
      const exeMatch = execNeedle || iiMatch ? undefined : EXE_SINK_RE.exec(ctx.text)
      if (!execNeedle && !iiMatch && !exeMatch) return { hit: false }
      // Trigger needles are built from what ACTUALLY matched on this input
      // (never a static list that might miss the branch that fired) — the
      // Task 12 lesson: triggerFor must never fall through to a fabricated
      // needles[0] default.
      const execTrigger = execNeedle ?? (iiMatch ? iiMatch[0].trim() : exeMatch![0].trim())
      const triggerNeedles = [diskNeedle ?? 'certutil', execTrigger]
      return { hit: true, trigger: triggerFor(ctx, triggerNeedles) }
    },
  },
  {
    id: 'cmd-cradle',
    label: 'cmd.exe download/exec cradle',
    techniqueIds: ['T1059.003', 'T1105'],
    baseSpecificity: 'strong',
    upgradesWith: ['clickfix', 'evasion-cluster'],
    test(ctx) {
      // Discriminator: the for /f loop construct alone must not fire — it
      // needs a download/exec inner command co-occurring, exactly as a bare
      // iwr/curl alone doesn't fire download-cradle without an IEX sink.
      const loop = hasAny(ctx, ['for /f'])
      const inner = hasAny(ctx, ['finger', 'curl', 'certutil', 'bitsadmin', 'powershell', 'pwsh'])
      if (loop && inner) return { hit: true, trigger: triggerFor(ctx, ['for /f']) }
      return { hit: false }
    },
  },
  {
    id: 'evasion-cluster',
    label: 'evasion flag cluster',
    techniqueIds: ['T1059.001', 'T1564.003', 'T1027'],
    baseSpecificity: 'weak',
    upgradesWith: ['download-cradle', 'amsi-reflection', 'clickfix'],
    test(ctx) {
      const flags = flagSet(ctx)
      const cluster = ['-enc', '-nop', '-w', '-ep', '-noni', '-sta'].filter((f) => flags.has(f)).length
      // Discriminator: a cluster is only suspicious with -enc or an inline fetch;
      // the same flags running a LOCAL -File automation are benign.
      const localFile = /-file\b/i.test(ctx.text) || present(ctx, '-file')
      const payload = flags.has('-enc') || hasAny(ctx, FETCH) || hasIexSink(ctx)
      if (cluster >= 3 && payload && !localFile) {
        return { hit: true, trigger: ctx.flags.map((f) => f.flag).join(' ') }
      }
      return { hit: false }
    },
  },
  {
    id: 'amsi-reflection',
    label: 'AMSI bypass via reflection',
    techniqueIds: ['T1562.001'],
    baseSpecificity: 'near-dispositive',
    upgradesWith: [],
    test(ctx) {
      // AmsiUtils + (amsiInitFailed | SetValue) reflection patch — zero benign use.
      if (hasAll(ctx, ['amsiutils']) && hasAny(ctx, ['amsiinitfailed', 'setvalue'])) {
        return { hit: true, trigger: triggerFor(ctx, ['amsiutils']) }
      }
      return { hit: false }
    },
  },
  {
    id: 'amsi-memory-patch',
    label: 'AMSI memory patch',
    techniqueIds: ['T1562.001'],
    baseSpecificity: 'near-dispositive',
    upgradesWith: [],
    test(ctx) {
      if (hasAll(ctx, ['amsiscanbuffer']) && hasAny(ctx, ['virtualprotect', 'writeprocessmemory'])) {
        return { hit: true, trigger: triggerFor(ctx, ['amsiscanbuffer']) }
      }
      return { hit: false }
    },
  },
  {
    id: 'etw-tamper',
    label: 'ETW tampering',
    techniqueIds: ['T1562.006'],
    baseSpecificity: 'strong',
    upgradesWith: ['amsi-reflection', 'fileless-loader'],
    test(ctx) {
      // Mentioning an ETW API is normal in .NET diagnostics/tracing; the
      // "tampering" fact is true only when a patch/hook/silence primitive co-occurs.
      const api = hasAny(ctx, ['etweventwrite', 'eventpipe', 'nttraceevent', 'etweventunregister'])
      const patch = hasAny(ctx, ['virtualprotect', 'writeprocessmemory', 'getprocaddress', 'setvalue', '[reflection.assembly]::load', 'ntsetinformationprocess'])
      if (api && patch) {
        return { hit: true, trigger: triggerFor(ctx, ['etweventwrite', 'eventpipe', 'nttraceevent']) }
      }
      return { hit: false }
    },
  },
  {
    id: 'defender-tamper',
    label: 'Defender tampering',
    techniqueIds: ['T1562.001'],
    baseSpecificity: 'strong',
    upgradesWith: ['download-cradle', 'amsi-reflection', 'persistence'],
    test(ctx) {
      // Set/Add-MpPreference: installer collision → STRONG (needs corroboration),
      // not near-dispositive.
      if (hasAny(ctx, ['set-mppreference', 'add-mppreference']) &&
          hasAny(ctx, ['disablerealtimemonitoring', 'disableioavprotection', 'disablebehaviormonitoring', 'exclusionpath', 'exclusionextension', 'exclusionprocess'])) {
        return { hit: true, trigger: triggerFor(ctx, ['set-mppreference', 'add-mppreference']) }
      }
      return { hit: false }
    },
  },
  {
    id: 'shadow-recovery-tamper',
    label: 'shadow-copy / recovery destruction',
    techniqueIds: ['T1490'],
    baseSpecificity: 'near-dispositive',
    upgradesWith: [],
    test(ctx) {
      // Destructive verb must co-occur with its object — a bare `vssadmin list`
      // is benign admin work. Pasted one-liner context: no legitimate use.
      const del =
        (hasAny(ctx, ['vssadmin']) && hasAny(ctx, ['delete shadows', 'resize shadowstorage'])) ||
        (hasAny(ctx, ['wmic']) && hasAll(ctx, ['shadowcopy', 'delete'])) ||
        (hasAny(ctx, ['wbadmin']) && hasAny(ctx, ['delete catalog', 'delete systemstatebackup'])) ||
        (hasAny(ctx, ['bcdedit']) && hasAny(ctx, ['recoveryenabled no', 'bootstatuspolicy ignoreallfailures']))
      if (del) {
        return {
          hit: true,
          trigger: triggerFor(ctx, [
            'delete shadows', 'resize shadowstorage', 'shadowcopy', 'delete catalog',
            'delete systemstatebackup', 'recoveryenabled', 'bootstatuspolicy ignoreallfailures',
          ]),
        }
      }
      return { hit: false }
    },
  },
  {
    id: 'clickfix',
    label: 'ClickFix / paste-and-run',
    techniqueIds: ['T1204', 'T1059.001', 'T1218.005', 'T1105'],
    baseSpecificity: 'strong',
    upgradesWith: ['download-cradle', 'amsi-reflection'],
    test(ctx) {
      const headless = hasAll(ctx, ['conhost', '--headless'])
      const hta = hasAny(ctx, ['mshta']) && hasAny(ctx, ['http://', 'https://', 'javascript:', '.hta'])
      const decoyPhrases = ['verify you are human', 'i am not a robot', 'ray id', 'captcha', 'press win+r', 'press enter to verify']
      // A bare '--verify' is a routine signature-verification flag (`gpg --verify
      // sig.asc file`, `openssl ... -verify`) — count it as a ClickFix decoy only
      // when it co-occurs with real lure/fetch context, never as a bare token.
      const verifyDecoy = hasAny(ctx, ['--verify']) && (hasAny(ctx, ['press enter', 'press win+r']) || hasAny(ctx, FETCH))
      const decoy = hasAny(ctx, decoyPhrases) || verifyDecoy
      // A hidden/-nop fetch+IEX cradle by itself is a download-cradle concern
      // (review 2.4) — ClickFix additionally requires a genuine paste-and-run
      // trait: a lure phrase, --verify decoy, headless conhost, or an mshta lure.
      const realTrait = headless || hta || decoy
      if (realTrait) {
        const decoyTrigger = decoyPhrases.find((p) => present(ctx, p)) ?? (verifyDecoy ? '--verify' : undefined)
        const trigger = headless ? '--headless' : decoyTrigger ?? triggerFor(ctx, [...FETCH, 'mshta'])
        return { hit: true, trigger }
      }
      return { hit: false }
    },
  },
  {
    id: 'beaconing',
    label: 'beaconing / C2 loop',
    techniqueIds: ['T1071.001', 'T1571'],
    baseSpecificity: 'strong',
    upgradesWith: ['download-cradle', 'reverse-shell'],
    test(ctx) {
      const loop = hasAny(ctx, ['while']) && hasAny(ctx, ['start-sleep'])
      const talk = hasAny(ctx, FETCH) || hasAny(ctx, ['tcpclient', 'net.sockets', 'udpclient'])
      if (loop && talk) return { hit: true, trigger: triggerFor(ctx, ['start-sleep', 'while']) }
      return { hit: false }
    },
  },
  {
    id: 'reverse-shell',
    label: 'reverse shell',
    techniqueIds: ['T1059.001', 'T1095'],
    baseSpecificity: 'near-dispositive',
    upgradesWith: [],
    test(ctx) {
      // A raw socket whose stream feeds IEX — Nishang Invoke-PowerShellTcp style.
      // No legitimate PowerShell one-liner pipes a TCP stream into the interpreter.
      const socket = hasAny(ctx, ['tcpclient', 'net.sockets.tcpclient', 'invoke-powershelltcp'])
      if (socket && hasIexSink(ctx) && hasAny(ctx, ['getstream', 'read(', 'invoke-powershelltcp'])) {
        return { hit: true, trigger: triggerFor(ctx, ['tcpclient', 'invoke-powershelltcp']) }
      }
      return { hit: false }
    },
  },
  {
    id: 'fileless-loader',
    label: 'in-memory loader / shellcode',
    techniqueIds: ['T1055', 'T1620'],
    baseSpecificity: 'strong',
    upgradesWith: ['amsi-reflection', 'amsi-memory-patch', 'etw-tamper'],
    test(ctx) {
      const alloc = hasAny(ctx, ['virtualalloc', 'ntallocatevirtualmemory', '[reflection.assembly]::load', 'createthread', 'createremotethread'])
      const shell = hasAny(ctx, ['byte[]', '[byte[]]', 'marshal.copy', 'add-type', 'getdelegatefor'])
      if (alloc && shell) return { hit: true, trigger: triggerFor(ctx, ['virtualalloc', 'createthread', '[reflection.assembly]::load']) }
      return { hit: false }
    },
  },
  {
    id: 'persistence',
    label: 'persistence',
    techniqueIds: ['T1053.005', 'T1547.001', 'T1546.003', 'T1543.003'],
    baseSpecificity: 'strong',
    upgradesWith: ['download-cradle', 'amsi-reflection', 'clickfix'],
    test(ctx) {
      const p = hasAny(ctx, ['register-scheduledtask', 'schtasks', 'currentversion\\run', 'runonce', 'new-service', '__eventfilter', 'commandlineeventconsumer', 'startup\\'])
      if (p) return { hit: true, trigger: triggerFor(ctx, ['register-scheduledtask', 'schtasks', 'runonce', 'new-service']) }
      return { hit: false }
    },
  },
  {
    id: 'lolbin',
    label: 'LOLBin',
    techniqueIds: ['T1218'],
    baseSpecificity: 'strong',
    upgradesWith: ['download-cradle', 'clickfix'],
    test(ctx) {
      return matchLolbin(ctx)
    },
  },
  {
    id: 'mshta-interpreter',
    label: 'mshta execution',
    techniqueIds: ['T1218.005'],
    baseSpecificity: 'strong',
    upgradesWith: ['clickfix', 'download-cradle'],
    test(ctx) {
      // interpreter === 'mshta' is itself the discriminator that distinguishes
      // this from a mere LOLBin text mention; a URL/.hta/inline-script target
      // is still required — the "bin AND discriminator" contract, never a
      // bare invocation.
      if (ctx.interpreter !== 'mshta') return { hit: false }
      if (!hasAny(ctx, MSHTA_DISCRIMINATORS)) return { hit: false }
      const inlineScript = hasAny(ctx, ['vbscript:', 'javascript:'])
      const techniqueIds = inlineScript ? ['T1218.005', 'T1059.005'] : ['T1218.005']
      return { hit: true, trigger: triggerFor(ctx, MSHTA_DISCRIMINATORS), techniqueIds }
    },
  },
  {
    id: 'wsh-script-exec',
    label: 'WSH script execution',
    techniqueIds: ['T1059.005', 'T1059.007'],
    baseSpecificity: 'strong',
    upgradesWith: ['clickfix', 'download-cradle'],
    test(ctx) {
      if (ctx.interpreter !== 'wscript' && ctx.interpreter !== 'cscript') return { hit: false }
      const suspiciousPath = hasAny(ctx, ['\\appdata\\', '\\temp\\', '\\public\\', '\\programdata\\'])
      const inlineEval = hasAny(ctx, ['//e:'])
      if (!suspiciousPath && !inlineEval) return { hit: false }
      const vbs = /\.vbs\b/i.test(ctx.text)
      const js = /\.js\b/i.test(ctx.text)
      if (!vbs && !js) return { hit: false }
      return { hit: true, trigger: triggerFor(ctx, ['.vbs', '.js', '//e:']), techniqueIds: vbs ? ['T1059.005'] : ['T1059.007'] }
    },
  },
  {
    id: 'wsh-decode-limits',
    label: 'WSH/HTA support is numeric char-code decode only; string-concatenation and Execute/eval are not resolved — a thin result here is not a clean result.',
    techniqueIds: [],
    baseSpecificity: 'weak',
    upgradesWith: [],
    test(ctx) {
      if (!WSH_HTA_INTERPRETERS.includes(ctx.interpreter)) return { hit: false }
      return { hit: true, trigger: ctx.interpreter }
    },
  },
  {
    id: 'wsh-concat-eval-present',
    label: 'string-concat / eval obfuscation present — not resolved; elevated suspicion warranted',
    techniqueIds: [],
    baseSpecificity: 'weak',
    upgradesWith: [],
    test(ctx) {
      if (!WSH_HTA_INTERPRETERS.includes(ctx.interpreter)) return { hit: false }
      const concat = /"[^"]*"\s*&\s*"[^"]*"/.test(ctx.text) || /"[^"]*"\s*\+\s*"[^"]*"/.test(ctx.text)
      const evalCall = hasAny(ctx, ['execute(', 'executeglobal(', 'eval('])
      if (!concat && !evalCall) return { hit: false }
      return { hit: true, trigger: triggerFor(ctx, ['execute(', 'executeglobal(', 'eval(']) }
    },
  },
  {
    id: 'cmd-var-obfuscation',
    label: 'cmd variable-substitution obfuscation',
    techniqueIds: ['T1140', 'T1027'],
    baseSpecificity: 'weak',
    upgradesWith: ['cmd-cradle', 'download-cradle'],
    test(ctx) {
      // The reassembly-shape tell: a `set X=…` followed by a `%X%`/`!X!`
      // reference to the SAME var name — informational, like the wsh-*
      // limit rules (review 2.5): surfaces even when preprocess.ts's cmd-var
      // reassembly (Task 16) only half-resolves the construct, since this
      // rule reads the CORPUS text directly rather than the reassembled
      // result. A bare %PATH% with no matching `set` must never fire (the
      // benign twin) — reassembleCmdVars.ts's own LITERAL-SAFETY guarantee
      // mirrored here: only a var actually `set` in the text counts.
      const m = ctx.text.match(/\bset\s+"?([A-Za-z_][\w]*)=/i)
      if (!m) return { hit: false }
      const name = m[1]
      const ref = ctx.text.match(new RegExp(`[%!]${name}[:%!]`, 'i'))
      if (!ref) return { hit: false }
      return { hit: true, trigger: triggerFor(ctx, [m[0], ref[0]]) }
    },
  },
  {
    id: 'offensive-tool',
    label: 'named offensive tool',
    techniqueIds: ['T1003', 'T1059.001'],
    baseSpecificity: 'near-dispositive',
    upgradesWith: [],
    test(ctx) {
      // Named offensive/credential-theft tooling — mimikatz (and its sekurlsa::
      // module namespace / DumpCreds verb), Rubeus, Invoke-Kerberoast, SafetyKatz.
      // Zero legitimate use: these are distinctive tool names, never a bare word
      // like 'user' that would collide with routine admin cmdlets (Get-LocalUser).
      // The trigger needle list is intentionally IDENTICAL to the hasAny() gate
      // list — a Task 12/13 lesson: triggerFor must never fall through to a
      // fabricated needles[0] default for a needle that didn't actually fire.
      const NEEDLES = ['invoke-mimikatz', 'sekurlsa::', 'dumpcreds', 'rubeus', 'invoke-kerberoast', 'safetykatz']
      if (hasAny(ctx, NEEDLES)) {
        return { hit: true, trigger: triggerFor(ctx, NEEDLES) }
      }
      return { hit: false }
    },
  },
]

/** Run every rule once; emit one Signal per hit, in table order (deterministic).
 *  A rule's test may override label/techniqueIds (LOLBins are data-driven). */
export function runRules(ctx: RuleContext): Signal[] {
  const out: Signal[] = []
  for (const rule of RULES) {
    const r = rule.test(ctx)
    if (!r.hit) continue
    out.push({
      id: rule.id,
      label: r.label ?? rule.label,
      techniqueIds: r.techniqueIds ?? rule.techniqueIds,
      specificity: rule.baseSpecificity,
      trigger: r.trigger ?? rule.label,
    })
  }
  return out
}

const ORDER: Specificity[] = ['weak', 'strong', 'near-dispositive']
function bump(s: Specificity): Specificity {
  return ORDER[Math.min(ORDER.indexOf(s) + 1, ORDER.length - 1)]
}

/** Signals + co-occurrence upgrade: a rule whose `upgradesWith` names a
 *  companion that also fired is raised one specificity tier (capped at
 *  near-dispositive). Every single token has a benign twin — company is the
 *  accuracy mechanism. */
export function classify(ctx: RuleContext): Signal[] {
  const signals = runRules(ctx)
  const fired = new Set(signals.map((s) => s.id))
  const byId = new Map(RULES.map((r) => [r.id, r]))
  return signals.map((s) => {
    const rule = byId.get(s.id)
    if (rule && rule.upgradesWith.some((id) => fired.has(id))) {
      return { ...s, specificity: bump(s.specificity) }
    }
    return s
  })
}

// Re-exported so later rules (Tasks 3–5) and their tests can reuse the vocab/helpers.
export { hasAll, hasAny, present, flagSet, triggerFor, hasIexSink, FETCH, matchLolbin, MSHTA_DISCRIMINATORS }
