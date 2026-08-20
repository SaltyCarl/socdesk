// shared/analyzer/bullets.ts
//
// Spec §7 — the "what did it do" breakdown, execution-ordered plain-English
// action bullets. Each ActionRule fires ONLY on facts the parser already
// resolved (layers/signals/iocs from report.ts's analyze()) — it never
// invents intent; maliciousness lives only in techniques.ts's signal layer.
//
// Ordering (D2, a documented DELTA from spec §7's literal (statementIndex,
// dataflowDepth), SOC-reviewed): the pipeline is flat token-passes, not an
// AST (§2 doctrine), so there is no statement index or dataflow depth to
// sort by. Instead: a fixed verb-family priority (delivery → reveal-nested →
// deobfuscate → decode → decompress → evade → fetch → execute → inject →
// persist → beacon), with a DecodedLayer's `index` as a secondary tie-break
// when a bullet is anchored to one.
//
// RENDER RULE (SOC must-fix, binding for every rule below): branch on the
// resolved sub-fact and emit ONLY it — never a slash/pipe hedge ("X / Y"),
// never a word (e.g. "hidden") that wasn't actually resolved. Where a fact
// has multiple independent sub-facts (AMSI bypass method, Defender tamper
// mode), that's TWO separate ActionRules that can both fire, not one rule
// picking between them.

import type {
  ActionBullet,
  ConfidenceTier,
  DecodedLayer,
  ExtractedIoc,
  RuleContext,
  Signal,
} from './types'
import { FETCH } from './techniques'
import { defang } from '../verdict/doctrine'

export type VerbFamily =
  | 'delivery' | 'interpreter-transition' | 'deobfuscate' | 'decode' | 'decompress' | 'evade'
  | 'fetch' | 'execute' | 'inject' | 'persist' | 'beacon'

// D2's revised 11-tier order. `deobfuscate` (3) has no rule in v1 — reserved
// for the deferred D8 "deobfuscates caret-escaped cmd" bullet, so it slots in
// at the right priority with no reordering when that lands.
export const FAMILY_PRIORITY: Record<VerbFamily, number> = {
  delivery: 1,
  'interpreter-transition': 2,
  deobfuscate: 3,
  decode: 4,
  decompress: 5,
  evade: 6,
  fetch: 7,
  execute: 8,
  inject: 9,
  persist: 10,
  beacon: 11,
}

/** The ctx an ActionRule matches against: the same RuleContext techniques.ts
 *  rules use, widened with the layer/IOC/signal facts report.ts has already
 *  computed by the time deriveBullets runs. */
export interface BulletContext extends RuleContext {
  layers: DecodedLayer[]
  iocs: ExtractedIoc[]
  signals: Signal[]
}

/** What an ActionRule's fires() hands to its own render() — the facts needed
 *  to write the bullet, never invented by render() itself. */
export interface Match {
  layerIndex: number             // tie-break within a verb-family (D2); 0 when not layer-anchored
  confidence: ConfidenceTier
  iocs: string[]                 // raw IOC values referenced inline, verbatim
  techniqueIds: string[]
  vars: Record<string, string>   // resolved interpolation values (url, host, mechanism, …)
}

export interface ActionRule {
  id: string
  requiredFacts: string[]        // documentation of what fires() gates on
  family: VerbFamily
  fires(ctx: BulletContext): Match | null
  render(m: Match): { verb: string; text: string }
}

const HOST_TYPES = new Set(['url', 'domain', 'ipv4', 'ipv6'])

// ---- F1 (whole-branch review, CRITICAL): per-behavior host attribution. ----
// The retired `findHostIoc()` returned the FIRST host-type IOC in the whole
// flat iocs array — reused across download-cradle/lolbin-msiexec/beacon-loop/
// reverse-shell, so on a multi-host sample a bullet could name a host that
// belongs to a DIFFERENT behavior entirely. Every helper below resolves a
// host from THAT construct's own text (a regex anchored to the construct
// itself), never from the flat list — a bullet must never name a host it
// can't attribute to its own behavior.

/** A resolved host, independent of whether extractIocs's catalog happened to
 *  keep it (it always scans the same corpus, so it usually did) — falls back
 *  to defanging the raw match directly so a construct-local resolution is
 *  never blocked on the global IOC list's own type filters. */
interface HostRef { raw: string; defanged: string; layerIndex: number }
function hostRefFromRaw(ctx: BulletContext, raw: string): HostRef {
  const found = ctx.iocs.find((i) => i.raw === raw)
  return found
    ? { raw: found.raw, defanged: found.defanged, layerIndex: found.layerIndex }
    : { raw, defanged: defang(raw), layerIndex: 0 }
}

// reverse-shell-open: host:port from the reverse-shell construct itself —
// `New-Object Net.Sockets.TCPClient('HOST', PORT)` / `TCPClient(HOST,PORT)`.
const TCPCLIENT_RE = /tcpclient\s*\(\s*['"]?([^'"(),\s]+)['"]?\s*,\s*(\d+)\s*\)/i
function reverseShellHostPort(ctx: BulletContext): { host: HostRef; port: string } | null {
  const m = ctx.text.match(TCPCLIENT_RE)
  if (!m) return null
  const raw = m[1]
  if (!raw || raw.startsWith('$')) return null // an unresolved variable, not a literal host — not parseable
  return { host: hostRefFromRaw(ctx, raw), port: m[2] }
}

// beacon-loop: a fetch/URL resolvable inside the loop's own BRACED BODY —
// never the flat first IOC (which might be an unrelated behavior's host,
// e.g. a reverse-shell target that also happens to sit inside the loop), and
// never a naive forward window either: a window can cross the loop's closing
// brace and pick up an unrelated construct's host that merely sits nearby in
// the corpus (the same cross-behavior misattribution class as F1, caught on
// scoped re-review). Find the `{` that opens the loop body after `while`,
// balanced-scan to its matching `}`, and only accept a host found strictly
// within that body. An unbalanced/absent brace pair degrades honestly rather
// than guessing a window.
function beaconLoopHost(ctx: BulletContext): HostRef | null {
  const whileIdx = ctx.lower.indexOf('while')
  if (whileIdx === -1) return null
  const openBrace = ctx.text.indexOf('{', whileIdx)
  if (openBrace === -1) return null
  let depth = 0
  let closeBrace = -1
  for (let i = openBrace; i < ctx.text.length; i++) {
    const c = ctx.text[i]
    if (c === '{') depth++
    else if (c === '}') {
      depth--
      if (depth === 0) { closeBrace = i; break }
    }
  }
  if (closeBrace === -1) return null // unbalanced — never guess past it
  const body = ctx.text.slice(openBrace, closeBrace + 1)
  const m = body.match(/https?:\/\/[^\s'"()<>]+/i)
  if (!m) return null
  return hostRefFromRaw(ctx, m[0])
}

// download-cradle-fetch / lolbin-msiexec: the URL adjacent to THIS
// construct's own fetch call (DownloadString/iwr/irm/msiexec /i), not the
// global first IOC. Safe simplification (SOC-approved): when the construct
// regex can't isolate a URL but the analysis has exactly ONE host IOC total,
// naming it is fine; with MULTIPLE and no isolation, degrade honestly.
function constructUrlHost(ctx: BulletContext, constructRe: RegExp): HostRef | undefined {
  const m = ctx.text.match(constructRe)
  if (m && m[1]) return hostRefFromRaw(ctx, m[1])
  const hostIocs = ctx.iocs.filter((i) => HOST_TYPES.has(i.type))
  if (hostIocs.length === 1) {
    const only = hostIocs[0]
    return { raw: only.raw, defanged: only.defanged, layerIndex: only.layerIndex }
  }
  return undefined
}

const FETCH_URL_RE = new RegExp(
  '\\b(?:' + FETCH.map((k) => k.replace(/\./g, '\\.')).join('|') + ')\\b[^\\n]{0,80}?(https?:\\/\\/[^\\s\'"()<>]+)',
  'i',
)
const MSIEXEC_URL_RE = /msiexec(?:\.exe)?\s*\/i\s+['"]?(https?:\/\/[^\s'"()<>]+)/i

// ---- F2/F3 (whole-branch review, MAJOR): method from the signal trigger. ----
// The retired `downloadMethod()` independently re-scanned `ctx.lower` (wrong
// priority order — `start-bitstransfer` checked ahead of `downloadstring`, so
// a commented-out BITS line could out-rank the real construct — plus a
// leading-space requirement on ` irm`/` iwr` that missed a position-0 irm/iwr)
// instead of using the `download-cradle` Signal.trigger techniques.ts already
// computed via `triggerFor(ctx, FETCH)` — the same fact `mshta-execute` below
// already threads through as `s.trigger`.
function downloadMethodFromTrigger(trigger: string): string {
  const t = trigger.toLowerCase()
  if (t.includes('downloadstring') || t.includes('downloaddata') || t.includes('downloadfile') || t.includes('net.webclient')) return 'WebClient.DownloadString'
  if (t.includes('invoke-webrequest') || t.includes('iwr')) return 'Invoke-WebRequest'
  if (t.includes('invoke-restmethod') || t.includes('irm')) return 'Invoke-RestMethod'
  if (t.includes('bitsadmin') || t.includes('start-bitstransfer')) return 'BITS transfer'
  return trigger.replace(/^\.+/, '')
}

// The clickfix SIGNAL (techniques.ts) fires broadly — including on a bare
// hidden+no-profile+fetch+IEX cradle with NO literal verification-prompt text
// (its own `hiddenFetchIex` branch). Asserting "presents a fake
// human-verification prompt" there would be an invented fact. The delivery
// bullet re-checks for the actual decoy phrase / headless-conhost text — the
// same discriminators techniques.ts's own decoy/headless branches use — so it
// only fires when a real ClickFix presentation is present in the corpus.
const CLICKFIX_DECOY_PHRASES = ['verify you are human', 'i am not a robot', 'ray id', 'captcha', 'press win+r', 'press enter to verify']
function isClickfixPresentation(ctx: BulletContext): boolean {
  const decoy = CLICKFIX_DECOY_PHRASES.some((p) => ctx.lower.includes(p)) ||
    (ctx.lower.includes('--verify') && (ctx.lower.includes('press enter') || ctx.lower.includes('press win+r')))
  const headless = ctx.lower.includes('conhost') && ctx.lower.includes('--headless')
  return decoy || headless
}

const FLAG_DESCRIPTOR: Record<string, string> = {
  '-w': 'hidden',
  '-nop': 'no-profile',
  '-ep': 'execution-policy bypass',
  '-noni': 'non-interactive',
  '-sta': 'single-threaded apartment',
}

export const RULES: ActionRule[] = [
  // ---- Delivery (tier 1, SOC must-fix #1 — was unmapped) ----
  {
    id: 'clickfix-delivery',
    requiredFacts: ['signal: clickfix', 'a real decoy/headless presentation in the corpus'],
    family: 'delivery',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'clickfix')
      if (!s) return null
      if (!isClickfixPresentation(ctx)) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: {} }
    },
    render() {
      return { verb: 'Presents', text: 'Presents a fake human-verification prompt instructing the user to paste and run this command (ClickFix pattern)' }
    },
  },

  // ---- Interpreter transitions (tier 2 — reveal-nested, not "execute") ----
  {
    id: 'cmd-launches-powershell',
    requiredFacts: ['layer: cmd→powershell hop'],
    family: 'interpreter-transition',
    fires(ctx) {
      const layer = ctx.layers.find((l) => l.transform.startsWith('cmd→powershell'))
      if (!layer) return null
      const hidden = ctx.flags.some((f) => f.flag === '-w')
      return { layerIndex: layer.index, confidence: 'resolved', iocs: [], techniqueIds: ['T1059.001', 'T1059.003'], vars: { hidden: hidden ? '1' : '0' } }
    },
    render(m) {
      const text = m.vars.hidden === '1'
        ? 'Launches a PowerShell child process from cmd.exe (hidden window)'
        : 'Launches a PowerShell child process from cmd.exe'
      return { verb: 'Launches', text }
    },
  },
  {
    id: 'mshta-execute',
    requiredFacts: ['signal: mshta-interpreter'],
    family: 'interpreter-transition',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'mshta-interpreter')
      if (!s) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: { trigger: s.trigger } }
    },
    render(m) {
      return { verb: 'Executes', text: `Executes an mshta payload (${m.vars.trigger})` }
    },
  },
  {
    id: 'wsh-execute',
    requiredFacts: ['signal: wsh-script-exec'],
    family: 'interpreter-transition',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'wsh-script-exec')
      if (!s) return null
      const lang = s.techniqueIds.includes('T1059.005') ? 'vbs' : 'js'
      const host = ctx.interpreter === 'cscript' ? 'cscript' : 'wscript'
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: { lang, host } }
    },
    render(m) {
      return { verb: 'Runs', text: `Runs a ${m.vars.lang} script via ${m.vars.host}` }
    },
  },

  // ---- Deobfuscate/decode/decompress (tiers 3-5) ----
  {
    id: 'decode-enc',
    requiredFacts: ['layer: Base64 → UTF-16LE'],
    family: 'decode',
    fires(ctx) {
      const layer = ctx.layers.find((l) => l.transform === 'Base64 → UTF-16LE')
      if (!layer) return null
      return { layerIndex: layer.index, confidence: layer.state === 'fully-decoded' ? 'resolved' : 'opaque', iocs: [], techniqueIds: ['T1027', 'T1140'], vars: { state: layer.state } }
    },
    render(m) {
      if (m.vars.state === 'fully-decoded') {
        return { verb: 'Decodes', text: 'Decodes a Base64 -EncodedCommand (UTF-16LE)' }
      }
      return { verb: 'Decodes', text: 'Attempts to decode a Base64 -EncodedCommand — payload malformed, could not resolve' }
    },
  },
  {
    id: 'decompress-inflate',
    requiredFacts: ['layer: Base64 → inflate'],
    family: 'decompress',
    fires(ctx) {
      const layer = ctx.layers.find((l) => l.transform === 'Base64 → inflate')
      if (!layer) return null
      return { layerIndex: layer.index, confidence: 'resolved', iocs: [], techniqueIds: [], vars: {} }
    },
    render() {
      // The pipeline (fold.ts's inflate()) checks the gzip magic bytes
      // internally but doesn't surface which of gzip/raw-DEFLATE it used up
      // to report.ts's layer — naming the exact algo per D5's literal
      // "{gzip|raw-DEFLATE}" would need a small fold.ts/report.ts fact-surfacing
      // addition (D4-shaped), out of scope for this delta. Generic wording
      // until that fact exists.
      return { verb: 'Decompresses', text: 'Decompresses an embedded blob with gzip/DEFLATE in memory' }
    },
  },
  {
    id: 'decode-charcode',
    requiredFacts: ['layer: Chr()/fromCharCode → text'],
    family: 'decode',
    fires(ctx) {
      const layer = ctx.layers.find((l) => l.transform === 'Chr()/fromCharCode → text')
      if (!layer) return null
      return { layerIndex: layer.index, confidence: 'resolved', iocs: [], techniqueIds: [], vars: {} }
    },
    render() {
      return { verb: 'Decodes', text: 'Decodes Chr()/fromCharCode-encoded text' }
    },
  },

  // ---- Evade/tamper (tier 6) — one bullet per RESOLVED sub-fact (SOC must-fix #3) ----
  {
    id: 'amsi-reflection-bypass',
    requiredFacts: ['signal: amsi-reflection'],
    family: 'evade',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'amsi-reflection')
      if (!s) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: {} }
    },
    render() {
      return { verb: 'Disables', text: 'Disables AMSI (script scanning) via reflection' }
    },
  },
  {
    id: 'amsi-memory-patch-bypass',
    requiredFacts: ['signal: amsi-memory-patch'],
    family: 'evade',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'amsi-memory-patch')
      if (!s) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: {} }
    },
    render() {
      return { verb: 'Disables', text: 'Disables AMSI via an in-memory patch (AmsiScanBuffer)' }
    },
  },
  {
    id: 'etw-blind',
    requiredFacts: ['signal: etw-tamper'],
    family: 'evade',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'etw-tamper')
      if (!s) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: {} }
    },
    render() {
      return { verb: 'Blinds', text: 'Blinds ETW logging' }
    },
  },
  {
    id: 'defender-disable-rtm',
    requiredFacts: ['signal: defender-tamper', 'Set-MpPreference -Disable*'],
    family: 'evade',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'defender-tamper')
      if (!s) return null
      const rtm = ctx.lower.includes('disablerealtimemonitoring') || ctx.lower.includes('disableioavprotection') || ctx.lower.includes('disablebehaviormonitoring')
      if (!rtm) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: {} }
    },
    render() {
      return { verb: 'Disables', text: 'Disables Microsoft Defender real-time monitoring' }
    },
  },
  {
    id: 'defender-add-exclusion',
    requiredFacts: ['signal: defender-tamper', 'Add-MpPreference -ExclusionPath'],
    family: 'evade',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'defender-tamper')
      if (!s) return null
      const excl = ctx.lower.includes('exclusionpath') || ctx.lower.includes('exclusionprocess') || ctx.lower.includes('exclusionextension')
      if (!excl) return null
      // best-effort resolved-path capture; the rule still fires (a resolved
      // sub-fact — SOME exclusion was added) even when the path itself doesn't
      // parse cleanly, degrading the render rather than the confidence tier.
      const m = ctx.text.match(/-Exclusion(?:Path|Process|Extension)\s+(['"]?)([^\s'";]+)\1/i)
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: { path: m ? m[2] : '' } }
    },
    render(m) {
      const text = m.vars.path
        ? `Adds a Microsoft Defender exclusion for ${m.vars.path}`
        : 'Adds a Microsoft Defender exclusion — path not resolved'
      return { verb: 'Adds', text }
    },
  },
  {
    id: 'evasion-hidden-run',
    requiredFacts: ['signal: evasion-cluster'],
    family: 'evade',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'evasion-cluster')
      if (!s) return null
      const descriptors = (['-w', '-nop', '-ep', '-noni', '-sta'] as const)
        .filter((f) => ctx.flags.some((fl) => fl.flag === f))
        .map((f) => FLAG_DESCRIPTOR[f])
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: { descriptors: descriptors.join(', ') } }
    },
    render(m) {
      return { verb: 'Runs', text: `Runs ${m.vars.descriptors || 'with a clustered evasion-flag set'}` }
    },
  },

  // ---- Fetch/download (tier 7) — method named (SOC must-fix #4) ----
  {
    id: 'download-cradle-fetch',
    requiredFacts: ['signal: download-cradle'],
    family: 'fetch',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'download-cradle')
      if (!s) return null
      const host = constructUrlHost(ctx, FETCH_URL_RE)
      const method = downloadMethodFromTrigger(s.trigger)
      return {
        layerIndex: host?.layerIndex ?? 0,
        confidence: host ? 'resolved' : 'inferred',
        iocs: host ? [host.raw] : [],
        techniqueIds: s.techniqueIds,
        vars: { url: host ? host.defanged : '', method: method ?? '' },
      }
    },
    render(m) {
      let text: string
      if (m.vars.url && m.vars.method) {
        text = `Downloads content from ${m.vars.url} via ${m.vars.method}`
      } else if (m.vars.url) {
        // F3 (whole-branch review): a resolved URL must never fall through to
        // the "assembled at runtime" wording just because the method didn't
        // separately resolve — the URL IS a resolved fact.
        text = `Downloads content from ${m.vars.url} — method not resolved`
      } else if (m.vars.method) {
        text = `Downloads content via ${m.vars.method} — target URL not resolved`
      } else {
        text = 'Downloads content from a URL assembled at runtime — not resolved'
      }
      return { verb: 'Downloads', text }
    },
  },
  {
    id: 'cmd-cradle-fetch',
    requiredFacts: ['signal: cmd-cradle'],
    family: 'fetch',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'cmd-cradle')
      if (!s) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: {} }
    },
    render() {
      return { verb: 'Fetches', text: 'Fetches a command via for /f or finger and executes its output' }
    },
  },

  // ---- LOLBins (tier 7) — one bullet per binary+behaviour, keyed off the
  // generic `lolbin` signal's `trigger` (the matched binary name; see
  // lolbins.ts's matchLolbin, which sets trigger: e.bin). mshta/finger/conhost/
  // installutil are intentionally NOT here: mshta already has its own
  // mshta-execute rule (a duplicate would double up the reveal); finger's
  // fetch action is already covered by cmd-cradle-fetch; conhost/installutil
  // have no dedicated D5 bullet text (SOC must-fix #1 only names these 6). ----
  {
    id: 'lolbin-certutil',
    requiredFacts: ['signal: lolbin (certutil)'],
    family: 'fetch',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'lolbin' && x.trigger === 'certutil')
      if (!s) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: {} }
    },
    render() {
      return { verb: 'Decodes', text: 'Decodes/downloads a payload via certutil' }
    },
  },
  {
    id: 'lolbin-bitsadmin',
    requiredFacts: ['signal: lolbin (bitsadmin)'],
    family: 'fetch',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'lolbin' && x.trigger === 'bitsadmin')
      if (!s) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: {} }
    },
    render() {
      return { verb: 'Fetches', text: 'Fetches a file via bitsadmin/BITS transfer' }
    },
  },
  {
    id: 'lolbin-regsvr32',
    requiredFacts: ['signal: lolbin (regsvr32)'],
    family: 'fetch',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'lolbin' && x.trigger === 'regsvr32')
      if (!s) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: {} }
    },
    render() {
      return { verb: 'Registers', text: 'Registers and executes a remote script via regsvr32 (Squiblydoo)' }
    },
  },
  {
    id: 'lolbin-rundll32',
    requiredFacts: ['signal: lolbin (rundll32)'],
    family: 'fetch',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'lolbin' && x.trigger === 'rundll32')
      if (!s) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: {} }
    },
    render() {
      return { verb: 'Executes', text: 'Executes code via rundll32' }
    },
  },
  {
    id: 'lolbin-msiexec',
    requiredFacts: ['signal: lolbin (msiexec)'],
    family: 'fetch',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'lolbin' && x.trigger === 'msiexec')
      if (!s) return null
      const host = constructUrlHost(ctx, MSIEXEC_URL_RE)
      return { layerIndex: host?.layerIndex ?? 0, confidence: host ? 'resolved' : 'inferred', iocs: host ? [host.raw] : [], techniqueIds: s.techniqueIds, vars: { url: host ? host.defanged : '' } }
    },
    render(m) {
      const text = m.vars.url
        ? `Installs from a remote MSI via msiexec /i ${m.vars.url}`
        : 'Installs from a remote MSI via msiexec /i — URL not resolved'
      return { verb: 'Installs', text }
    },
  },
  {
    id: 'lolbin-wmic',
    requiredFacts: ['signal: lolbin (wmic)'],
    family: 'fetch',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'lolbin' && x.trigger === 'wmic')
      if (!s) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: {} }
    },
    render() {
      return { verb: 'Executes', text: 'Executes via wmic' }
    },
  },

  // ---- Execute (tier 8) ----
  {
    id: 'download-exec-memory',
    requiredFacts: ['signal: download-cradle'],
    family: 'execute',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'download-cradle')
      if (!s) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: {} }
    },
    render() {
      return { verb: 'Executes', text: 'Executes the downloaded content in memory (not written to disk)' }
    },
  },

  // ---- Inject/load (tier 9) ----
  {
    id: 'inmemory-inject',
    requiredFacts: ['signal: fileless-loader'],
    family: 'inject',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'fileless-loader')
      if (!s) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: {} }
    },
    render() {
      return { verb: 'Allocates', text: 'Allocates executable memory and starts a thread on embedded shellcode (in-memory injection)' }
    },
  },

  // ---- Persist (tier 10) ----
  {
    id: 'creates-persistence',
    requiredFacts: ['signal: persistence'],
    family: 'persist',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'persistence')
      if (!s) return null
      let mechanism = 'a persistence mechanism'
      if (ctx.lower.includes('__eventfilter') || ctx.lower.includes('commandlineeventconsumer')) mechanism = 'a WMI event subscription'
      else if (ctx.lower.includes('schtasks') || ctx.lower.includes('register-scheduledtask')) mechanism = 'a scheduled task'
      else if (ctx.lower.includes('runonce') || ctx.lower.includes('currentversion\\run')) mechanism = 'an autostart Run-key'
      else if (ctx.lower.includes('new-service')) mechanism = 'a service'
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: { mechanism } }
    },
    render(m) {
      return { verb: 'Creates', text: `Creates ${m.vars.mechanism} (persists across reboot)` }
    },
  },

  // ---- Beacon/C2 (tier 11) ----
  {
    id: 'beacon-loop',
    requiredFacts: ['signal: beaconing'],
    family: 'beacon',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'beaconing')
      if (!s) return null
      // F1 (whole-branch review): the host comes from a fetch/URL resolvable
      // INSIDE the loop's own text — never the flat first IOC, which may
      // belong to an entirely different behavior (e.g. a reverse-shell target
      // that also happens to sit elsewhere in the corpus).
      const host = beaconLoopHost(ctx)
      const sleepMatch = ctx.text.match(/Start-Sleep\s+(?:-Seconds\s+)?(\d+)/i)
      return {
        layerIndex: host?.layerIndex ?? 0,
        confidence: host ? 'resolved' : 'inferred',
        iocs: host ? [host.raw] : [],
        techniqueIds: s.techniqueIds,
        vars: { host: host ? host.defanged : '', interval: sleepMatch ? sleepMatch[1] : '' },
      }
    },
    render(m) {
      const suffix = m.vars.interval ? ` every ~${m.vars.interval}s` : ''
      const text = m.vars.host
        ? `Beacons to ${m.vars.host} in a loop${suffix}`
        : `Beacons to a remote host in a loop${suffix}`
      return { verb: 'Beacons', text }
    },
  },
  {
    id: 'reverse-shell-open',
    requiredFacts: ['signal: reverse-shell'],
    family: 'beacon',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'reverse-shell')
      if (!s) return null
      // F1 (whole-branch review): host:port comes ONLY from this construct's
      // own TCPClient(host, port) call — never the flat first IOC, which may
      // name an unrelated behavior's host (e.g. a download URL).
      const hp = reverseShellHostPort(ctx)
      return {
        layerIndex: hp?.host.layerIndex ?? 0,
        confidence: hp ? 'resolved' : 'inferred',
        iocs: hp ? [hp.host.raw] : [],
        techniqueIds: s.techniqueIds,
        vars: { host: hp ? hp.host.defanged : '', port: hp ? hp.port : '' },
      }
    },
    render(m) {
      const text = m.vars.host ? `Opens a reverse shell to ${m.vars.host}:${m.vars.port}` : 'Opens a reverse shell to a remote endpoint'
      return { verb: 'Opens', text }
    },
  },

  // ---- WSH/HTA honesty notices — quarantined to opaque, never promoted (D3/D6) ----
  {
    id: 'wsh-not-resolved',
    requiredFacts: ['signal: wsh-decode-limits'],
    family: 'decode',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'wsh-decode-limits')
      if (!s) return null
      return { layerIndex: 0, confidence: 'opaque', iocs: [], techniqueIds: [], vars: {} }
    },
    render() {
      return { verb: 'Notes', text: 'WSH/HTA support is numeric char-code decode only — string-concatenation and Execute/eval are not resolved' }
    },
  },
  {
    id: 'wsh-concat-eval-not-resolved',
    requiredFacts: ['signal: wsh-concat-eval-present'],
    family: 'decode',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'wsh-concat-eval-present')
      if (!s) return null
      return { layerIndex: 0, confidence: 'opaque', iocs: [], techniqueIds: [], vars: {} }
    },
    render() {
      return { verb: 'Notes', text: 'String-concat / eval obfuscation present in this script — not resolved' }
    },
  },
]

/** Run every rule; assemble hits into order-numbered ActionBullets sorted by
 *  verb-family priority, then layer index (D2). Called from report.ts's
 *  analyze() right before the return, mirroring classify(buildContext(...))
 *  at report.ts:202. */
export function deriveBullets(ctx: RuleContext, layers: DecodedLayer[], iocs: ExtractedIoc[], signals: Signal[]): ActionBullet[] {
  const bctx: BulletContext = { ...ctx, layers, iocs, signals }
  const hits: { rule: ActionRule; m: Match }[] = []
  for (const rule of RULES) {
    const m = rule.fires(bctx)
    if (m) hits.push({ rule, m })
  }
  hits.sort((a, b) => {
    const pa = FAMILY_PRIORITY[a.rule.family]
    const pb = FAMILY_PRIORITY[b.rule.family]
    if (pa !== pb) return pa - pb
    return a.m.layerIndex - b.m.layerIndex
  })
  return hits.map(({ rule, m }, i) => {
    const { verb, text } = rule.render(m)
    return { order: i + 1, verb, text, confidence: m.confidence, iocs: m.iocs, techniqueIds: m.techniqueIds }
  })
}
