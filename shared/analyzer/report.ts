import type { AnalysisResult, DecodedLayer } from './types'
import { preprocess } from './preprocess'
import { tokenize, stringLiterals } from './lex'
import { decodeEnc, looksBase64, fromBase64, inflate, bytesToText } from './fold'
import { extractIocs } from './extract'
import { resolve } from './resolve'

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
      layers.push({ index: layers.length, transform: 'Base64 → inflate', text: bytesToText(inflated), state: 'fully-decoded' })
      break // depth 1: one inflate; deeper recursion is Phase 2
    }
  }

  // Phase 2a: resolve token-obfuscation on the current text, and recurse through
  // IEX/&/.Invoke() whose operand resolves to a literal string. Depth-capped;
  // dedupe by resolved content so `$x='IEX $x'` can't spin.
  const seen = new Set<string>()
  const texts: string[] = [] // texts to scan for IOCs
  let work = layers.length ? (layers[layers.length - 1].text ?? '') : current
  for (let depth = 0; depth < 6; depth++) {
    const resolved = resolve(work)
    if (seen.has(resolved)) break
    seen.add(resolved)
    texts.push(resolved)
    if (resolved !== work && layers.length) {
      layers.push({ index: layers.length, transform: 'resolve (fold/substitute)', text: resolved, state: 'fully-decoded' })
    }
    // find an IEX/&/.Invoke() target that is now a string literal → next layer
    const next = iexStringTarget(resolved)
    if (!next || seen.has(next)) break
    work = next
  }

  const iocs = extractIocs(texts.map((text, index) => ({ index, text })))

  const fullyDecoded = layers.filter((l) => l.state === 'fully-decoded').length
  const state = layers.length === 0 || fullyDecoded === layers.length ? 'fully-decoded' : 'partial'
  const fractionAccounted = layers.length === 0 ? 1 : fullyDecoded / layers.length
  const copyText = composeCopyText(layers, iocs)

  return {
    input,
    flags,
    layers,
    iocs,
    signals: [],
    characterization: null,
    bullets: [],
    confidence: { fractionAccounted, state },
    copyText,
    checkedAt: new Date().toISOString(),
  }
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

function composeCopyText(layers: DecodedLayer[], iocs: AnalysisResult['iocs']): string {
  const lines: string[] = ['PowerShell static analysis — STATIC analysis, script was NOT executed', '']
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
