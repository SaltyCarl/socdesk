import type { AnalysisResult } from './types'

export async function analyze(input: string): Promise<AnalysisResult> {
  return {
    input,
    flags: [],
    layers: [],
    iocs: [],
    signals: [],
    characterization: null,
    bullets: [],
    confidence: { fractionAccounted: 1, state: 'fully-decoded' },
    copyText: '',
    checkedAt: new Date().toISOString(),
  }
}
