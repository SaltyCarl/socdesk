import type { AnalysisResult, Characterization, DecodedLayer, EvasionFlag, Signal } from './types'
import { preprocess, type Interpreter } from './preprocess'
import { tokenize, stringLiterals } from './lex'
import { decodeEnc, looksBase64, fromBase64, inflate, bytesToText } from './fold'
import { extractIocs } from './extract'
import { resolve, normalize } from './resolve'
import { buildContext, classify, RULES } from './techniques'
import { decodeNumericCharCodes } from './wsh'

const WRAPPER_INTERPRETERS = new Set<Interpreter>(['cmd', 'mshta', 'wscript', 'cscript'])
const WSH_INTERPRETERS = new Set<Interpreter>(['mshta', 'wscript', 'cscript'])
const NESTED_REENTRY_MAX_DEPTH = 4

// detectInterpreter (preprocess.ts) is anchored to the start of the string —
// real wrapper shapes routinely bury the nested launcher somewhere past
// position 0 (mshta's launcher inside a quoted Run() argument; cmd running a
// command before the launcher, or via `start /min launcher`). When the
// anchored check comes back 'unknown', fall back to a non-anchored search for
// the first embedded launcher token and resume decoding from there.
const EMBEDDED_LAUNCHER_RE = /\b(?:powershell|pwsh|cmd|mshta|wscript|cscript)(?:\.exe)?\b/i

/** cmd/mshta/wscript/cscript wrappers overwhelmingly exist to launch a NESTED
 *  interpreter (canonically `cmd /c powershell -w hidden -enc <blob>`). Loop
 *  the extracted body back through preprocess() so a nested powershell -enc/
 *  -Command payload is decoded exactly as a top-level PowerShell input would
 *  be — depth-capped (plus a seen-set for cycle detection) so a hostile
 *  wrapper-in-wrapper cannot spin the analyzer, the same discipline the
 *  IEX-recursion loop below already applies. Each hop is recorded as its own
 *  decode-ladder layer naming the transition, e.g. `cmd→powershell`. */
function reenterNestedInterpreter(
  outerInterpreter: Interpreter,
  outerScript: string,
): {
  script: string
  encoded: string | null
  flags: EvasionFlag[]
  finalInterpreter: Interpreter
  layers: { transform: string; text: string }[]
  contextTexts: string[]
} {
  const hopLayers: { transform: string; text: string }[] = []
  // Every body seen along the way, including ones the fallback below jumps
  // past (e.g. a `for /f … do cmd.exe /c %e` cradle whose prefix carries its
  // own signal-relevant text) — folded into analyze()'s signal corpus so a
  // later hop's truncation never erases an earlier body's content.
  const contextTexts: string[] = [outerScript]
  let fromInterpreter = outerInterpreter
  let script = outerScript
  let encoded: string | null = null
  let flags: EvasionFlag[] = []
  const seen = new Set<string>([outerScript])
  for (let depth = 0; depth < NESTED_REENTRY_MAX_DEPTH; depth++) {
    if (!WRAPPER_INTERPRETERS.has(fromInterpreter)) break
    const inner = preprocess(script)
    if (inner.interpreter === 'unknown') {
      // Non-anchored fallback: the launcher wasn't the first token — search
      // for it further in and, if found, resume decoding from that point.
      // This still costs one iteration of the depth cap and is still subject
      // to the seen-set cycle guard below, so a hostile input can't use it
      // to spin the analyzer.
      const m = script.match(EMBEDDED_LAUNCHER_RE)
      if (!m || m.index === undefined || m.index === 0) break
      const resumed = script.slice(m.index)
      if (seen.has(resumed)) break
      seen.add(resumed)
      script = resumed
      contextTexts.push(script)
      continue
    }
    if (seen.has(inner.script)) break
    seen.add(inner.script)
    hopLayers.push({ transform: `${fromInterpreter}→${inner.interpreter}${inner.encoded ? ' -enc' : ''}`, text: inner.script })
    script = inner.script
    contextTexts.push(script)
    encoded = inner.encoded
    flags = flags.concat(inner.flags)
    fromInterpreter = inner.interpreter
    if (fromInterpreter === 'powershell') break // reached PS: the existing -enc/layer logic below takes over
  }
  return { script, encoded, flags, finalInterpreter: fromInterpreter, layers: hopLayers, contextTexts }
}

/** Dedupe EvasionFlags by (flag, raw), keeping first occurrence order. The
 *  outer preprocess(input) scan and the nested-reentry inner preprocess()
 *  calls both scan overlapping text for the same PS flag regexes (e.g.
 *  `cmd /c powershell -w hidden -enc …` matches `-w`/`-enc` both on the raw
 *  input and again on the extracted/re-entered script), so flags gets
 *  concatenated with duplicates before this final pass — which otherwise
 *  surface as duplicate React keys in AnalyzerResult's EvasionFlag chips. */
function dedupeFlags(flags: EvasionFlag[]): EvasionFlag[] {
  const seen = new Set<string>()
  const out: EvasionFlag[] = []
  for (const f of flags) {
    const key = f.flag + '|' + f.raw
    if (seen.has(key)) continue
    seen.add(key)
    out.push(f)
  }
  return out
}

export async function analyze(input: string): Promise<AnalysisResult> {
  const outer = preprocess(input)
  let { script, encoded, flags } = outer
  let interpreter = outer.interpreter
  const layers: DecodedLayer[] = []
  // Every intermediate wrapper body the reentry loop passed through — see
  // reenterNestedInterpreter's contextTexts doc comment.
  let reentryContext: string[] = []

  if (WRAPPER_INTERPRETERS.has(interpreter)) {
    const reentered = reenterNestedInterpreter(interpreter, script)
    for (const hop of reentered.layers) {
      layers.push({ index: layers.length, transform: hop.transform, text: hop.text, state: 'fully-decoded' })
    }
    script = reentered.script
    encoded = reentered.encoded
    flags = flags.concat(reentered.flags)
    interpreter = reentered.finalInterpreter
    reentryContext = reentered.contextTexts
  }

  // Layer N: -enc Base64 → UTF-16LE. (unchanged below, now seeded from the
  // possibly-nested script/encoded.)
  let current = script
  if (encoded) {
    if (looksBase64(encoded)) {
      const text = decodeEnc(encoded)
      layers.push({ index: layers.length, transform: 'Base64 → UTF-16LE', text, state: 'fully-decoded' })
      current = text
    } else {
      // Malformed/truncated -EncodedCommand payload (e.g. length not a multiple
      // of 4) — never let atob throw out of analyze(); surface it honestly.
      layers.push({
        index: layers.length,
        transform: 'Base64 → UTF-16LE',
        text: null,
        state: 'opaque',
        residual: { bytes: encoded.length, entropy: 0, note: 'malformed -EncodedCommand payload — could not Base64-decode' },
      })
    }
  }

  // Layer: WSH/HTA numeric char-code decode — interpreter-gated (§4).
  if (WSH_INTERPRETERS.has(interpreter)) {
    const decoded = decodeNumericCharCodes(current)
    if (decoded !== current) {
      layers.push({ index: layers.length, transform: 'Chr()/fromCharCode → text', text: decoded, state: 'fully-decoded' })
      current = decoded
    }
  }

  // Layer 2 (depth 1): an embedded Base64 blob that inflates (gzip/raw-DEFLATE cradle).
  for (const lit of stringLiterals(tokenize(current))) {
    if (!looksBase64(lit)) continue
    const inflated = await inflate(fromBase64(lit))
    if (inflated) {
      const text = bytesToText(inflated)
      if (isMostlyPrintable(text)) {
        layers.push({ index: layers.length, transform: 'Base64 → inflate', text, state: 'fully-decoded' })
        break // depth 1: one inflate; deeper recursion is Phase 2
      }
    }
  }

  // Collect IOC-scan texts + their true layer index: every existing decode layer,
  // then the resolve/recurse chain seeded from the last layer (or the raw script).
  const seen = new Set<string>()
  const scan: { index: number; text: string }[] = []
  for (const l of layers) {
    if (l.text != null && !seen.has(l.text)) { seen.add(l.text); scan.push({ index: l.index, text: l.text }) }
  }
  let work = layers.length ? (layers[layers.length - 1].text ?? '') : current
  let workIndex = layers.length ? layers[layers.length - 1].index : 0
  for (let depth = 0; depth < 6; depth++) {
    const resolved = resolve(work)
    if (seen.has(resolved)) break
    seen.add(resolved)
    let idx = workIndex
    if (resolved !== normalize(work) && layers.length) {
      layers.push({ index: layers.length, transform: 'resolve (fold/substitute)', text: resolved, state: 'fully-decoded' })
      idx = layers.length - 1
    }
    scan.push({ index: idx, text: resolved })
    const next = iexStringTarget(resolved)
    if (!next || seen.has(next)) break
    work = next
    workIndex = idx
  }
  const iocs = extractIocs(scan)

  // Signatures run over the decoded corpus: the raw input (so launcher/wrapper
  // tokens like `conhost --headless` survive preprocess()'s -Command extraction),
  // the outer (preprocessed) script, every intermediate nested-reentry body (so a
  // fallback hop's truncation never erases an earlier wrapper body's own signal
  // content — e.g. a `for /f … do cmd.exe /c %e` cradle prefix), plus every
  // resolved layer/recursion text, so a signal in an inner cradle counts. Rules
  // dedup by id (classify/runRules emit one Signal per rule), so overlap across
  // these sources can't double-count; IOC extraction reads `scan`, not `corpus`,
  // so this doesn't affect IOCs.
  const corpus = [input, ...reentryContext, script, ...scan.map((s) => s.text)].filter(Boolean).join('\n')
  const signals = classify(buildContext(corpus, flags, interpreter))
  const characterization = deriveCharacterization(signals)

  const fullyDecoded = layers.filter((l) => l.state === 'fully-decoded').length
  const state = layers.length === 0 || fullyDecoded === layers.length ? 'fully-decoded' : 'partial'
  const fractionAccounted = layers.length === 0 ? 1 : fullyDecoded / layers.length
  const decodedScript = [...layers].reverse().find((l) => l.text != null)?.text ?? script
  const copyText = composeCopyText(layers, iocs, signals, characterization, decodedScript)

  return {
    input,
    flags: dedupeFlags(flags),
    layers,
    iocs,
    signals,
    characterization,
    bullets: [],
    confidence: { fractionAccounted, state },
    copyText,
    checkedAt: new Date().toISOString(),
  }
}

// Intrinsically near-dispositive rules — techniques with NO legitimate use
// (AMSI reflection/memory-patch, reverse shell). This is a BASE property, not
// the post-co-occurrence specificity: a strong signal that companionship merely
// upgraded still has benign twins, so it must never earn a "no legitimate use"
// characterization (anti-cry-wolf).
const NEAR_DISPOSITIVE_BASE = new Set(
  RULES.filter((r) => r.baseSpecificity === 'near-dispositive').map((r) => r.id),
)

// Rule id → its BASE specificity (pre-co-occurrence-upgrade), for the copyText
// signals line — see composeCopyText below.
const BASE_SPECIFICITY = new Map(RULES.map((r) => [r.id, r.baseSpecificity]))

/** Specificity-gated: emit a characterization ONLY when at least one signal's
 *  underlying rule is INTRINSICALLY near-dispositive (a technique with no
 *  legitimate use) — gated on the rule's base specificity, not the
 *  post-co-occurrence-upgrade specificity on the signal itself, so a strong
 *  signal upgraded by companionship (e.g. defender-tamper + download-cradle)
 *  never earns a "no legitimate use" claim it hasn't intrinsically earned.
 *  The `read` and `basis` are built solely from those near-dispositive
 *  signals — the "malicious" word is earned by named techniques, never a
 *  black-box stamp. Weak/strong-only patterns (which benign RMM/installer/GPO
 *  tooling shares) return null. */
function deriveCharacterization(signals: Signal[]): Characterization | null {
  // Tier 1 — high-confidence malicious: at least one INTRINSICALLY near-dispositive
  // signal (no legitimate use), gated on the rule's BASE specificity.
  const nd = signals.filter((s) => NEAR_DISPOSITIVE_BASE.has(s.id))
  if (nd.length) {
    const read =
      'High-confidence malicious behaviour: ' +
      nd.map((s) => `${s.label} (no legitimate use)`).join(' + ')
    return { level: 'high-confidence-malicious', basis: nd.map((s) => s.id), read }
  }
  // Tier 2 — suspicious: no intrinsically-near-dispositive signal, but a STRONG
  // signal was corroborated up to near-dispositive by co-occurring companions
  // (its effective specificity reached near-dispositive while its base did not).
  // This is the beacon shape (evasion cluster + download cradle). Hedged, never
  // "malicious" — the strong signals have real benign twins, so this says "review".
  const corroborated = signals.filter(
    (s) => s.specificity === 'near-dispositive' && !NEAR_DISPOSITIVE_BASE.has(s.id),
  )
  if (corroborated.length) {
    const read =
      'Suspicious — review: ' +
      corroborated.map((s) => s.label).join(' + ') +
      ' (elevated by co-occurring signals)'
    return { level: 'suspicious', basis: corroborated.map((s) => s.id), read }
  }
  return null
}

// Return the literal string an IEX/& sink executes, if it resolved to one.
// (.Invoke() as a recursion sink is not handled yet — see the analyzer roadmap.)
function iexStringTarget(text: string): string | null {
  const toks = tokenize(text)
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i]
    const sink =
      (t.type === 'bareword' && /^(iex|invoke-expression|&)$/i.test(t.value)) ||
      (t.type === 'punct' && t.value === '&')
    if (!sink) continue
    // skip an optional '(' then take the first string literal in the operand
    for (let j = i + 1; j < toks.length && j < i + 4; j++) {
      if (toks[j].type === 'string') return toks[j].value
      if (toks[j].type === 'bareword' || toks[j].type === 'punct') {
        if (toks[j].value !== '(' ) break
      }
    }
  }
  return null
}

function composeCopyText(
  layers: DecodedLayer[],
  iocs: AnalysisResult['iocs'],
  signals: Signal[],
  characterization: Characterization | null,
  decodedScript: string,
): string {
  const lines: string[] = ['PowerShell static analysis — STATIC analysis, script was NOT executed', '']
  if (characterization) lines.push(characterization.read, '')
  if (signals.length) {
    lines.push('Behaviour signals:')
    signals.forEach((s) => lines.push(`  [${BASE_SPECIFICITY.get(s.id) ?? s.specificity}] ${s.label} (${s.techniqueIds.join(', ')})`))
    lines.push('')
  }
  if (decodedScript) {
    lines.push(layers.length ? 'Decoded script:' : 'Script:')
    const capped = decodedScript.length > 4000 ? decodedScript.slice(0, 4000) + '\n… [truncated]' : decodedScript
    lines.push(capped, '')
  }
  if (layers.length) {
    lines.push('Decoded layers:')
    layers.forEach((l) => lines.push(`  ${l.index + 1}. ${l.transform}`))
    lines.push('')
  }
  if (iocs.length) {
    lines.push('Indicators:')
    iocs.forEach((i) => lines.push(`  ${i.type.toUpperCase()}  ${i.defanged}`))
  } else {
    lines.push('Indicators: (none extracted)')
  }
  return lines.join('\n')
}

/** Accept a decompressed layer only if it's mostly printable text — raw-DEFLATE
 *  "succeeds" on ~0.4% of arbitrary base64, producing binary garbage that must
 *  not be presented as a decoded layer. Printable = tab/newline/CR or >= 0x20. */
function isMostlyPrintable(s: string): boolean {
  if (!s) return false
  let printable = 0
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || (c >= 160 && c !== 0xfffd)) printable++
  }
  return printable / s.length >= 0.85
}
