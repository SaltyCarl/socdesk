import type { AnalysisResult, DecodedLayer } from './types'
import { preprocess } from './preprocess'
import { tokenize, stringLiterals } from './lex'
import { decodeEnc, looksBase64, fromBase64, inflate, bytesToText } from './fold'
import { extractIocs } from './extract'

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

  // Layers to scan for IOCs: the decoded layers, or the raw script if nothing decoded.
  const scan = layers.length ? layers.map((l) => ({ index: l.index, text: l.text })) : [{ index: 0, text: current }]
  const iocs = extractIocs(scan)

  const state = layers.every((l) => l.state === 'fully-decoded') ? 'fully-decoded' : 'partial'
  const copyText = composeCopyText(input, layers, iocs)

  return {
    input,
    flags,
    layers,
    iocs,
    signals: [],
    characterization: null,
    bullets: [],
    confidence: { fractionAccounted: 1, state },
    copyText,
    checkedAt: new Date().toISOString(),
  }
}

function composeCopyText(input: string, layers: DecodedLayer[], iocs: AnalysisResult['iocs']): string {
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
