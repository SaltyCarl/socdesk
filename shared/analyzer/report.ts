import type { AnalysisResult, Characterization, DecodedLayer, Signal } from './types'
import { preprocess } from './preprocess'
import { tokenize, stringLiterals } from './lex'
import { decodeEnc, looksBase64, fromBase64, inflate, bytesToText } from './fold'
import { extractIocs } from './extract'
import { resolve, normalize } from './resolve'
import { buildContext, classify, RULES } from './techniques'

export async function analyze(input: string): Promise<AnalysisResult> {
  const { script, encoded, flags } = preprocess(input)
  const layers: DecodedLayer[] = []

  // Layer 1: -enc Base64 → UTF-16LE.
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
  // the outer (preprocessed) script, plus every resolved layer/recursion text, so
  // a signal in an inner cradle counts. Rules dedup by id (classify/runRules emit
  // one Signal per rule), so the input/script overlap can't double-count; IOC
  // extraction reads `scan`, not `corpus`, so this doesn't affect IOCs.
  const corpus = [input, script, ...scan.map((s) => s.text)].filter(Boolean).join('\n')
  const signals = classify(buildContext(corpus, flags))
  const characterization = deriveCharacterization(signals)

  const fullyDecoded = layers.filter((l) => l.state === 'fully-decoded').length
  const state = layers.length === 0 || fullyDecoded === layers.length ? 'fully-decoded' : 'partial'
  const fractionAccounted = layers.length === 0 ? 1 : fullyDecoded / layers.length
  const decodedScript = [...layers].reverse().find((l) => l.text != null)?.text ?? script
  const copyText = composeCopyText(layers, iocs, signals, characterization, decodedScript)

  return {
    input,
    flags,
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
  const nd = signals.filter((s) => NEAR_DISPOSITIVE_BASE.has(s.id))
  if (!nd.length) return null
  const read =
    'High-confidence malicious behaviour: ' +
    nd.map((s) => `${s.label} (no legitimate use)`).join(' + ')
  return { level: 'high-confidence-malicious', basis: nd.map((s) => s.id), read }
}

// Return the literal string an IEX/&/.Invoke() executes, if it resolved to one.
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
