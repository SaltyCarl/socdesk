import { describe, expect, it } from 'vitest'
import { analyze } from '../report'

describe('analyze (scaffold)', () => {
  it('returns a shaped AnalysisResult for empty input', async () => {
    const r = await analyze('')
    expect(r.input).toBe('')
    expect(r.flags).toEqual([])
    expect(r.layers).toEqual([])
    expect(r.iocs).toEqual([])
    expect(r.signals).toEqual([])
    expect(r.characterization).toBeNull()
    expect(r.bullets).toEqual([])
    expect(typeof r.copyText).toBe('string')
    expect(r.confidence.state).toBe('fully-decoded')
  })
})
