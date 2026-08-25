// shared/analyzer/__tests__/review-samples.test.ts
import { describe, it, expect } from 'vitest'
import { analyze } from '../report'

// The 7 samples from SOCDesk-Analyzer-Review-2026-08-24.pdf. Expected values
// RATCHET as phases land — a change here is intentional, never silent.
describe('review battery — end state after Phase 1', () => {
  it('#2 benign Get-ChildItem: silent, fully-decoded', async () => {
    const r = await analyze('Get-ChildItem -Recurse | Where Length -gt 1MB | Sort | Select')
    expect(r.signals).toEqual([])
    expect(r.confidence.state).toBe('fully-decoded')
  })
  it('#6 plain-base64 inner stage: now DECODED (Phase 2)', async () => {
    const b64 = btoa('Invoke-Mimikatz -DumpCreds; net user hacker P@ss /add')
    const r = await analyze(`IEX([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${b64}')))`)
    expect(r.layers.some((l) => /Base64 → text/.test(l.transform))).toBe(true)
    expect(r.confidence.state).toBe('fully-decoded')
  })
  it('#7 benign regsvr32 /u: no regsvr32 bullet at all (no fabricated narrative)', async () => {
    const r = await analyze('regsvr32 /u /s C:\\Program Files\\MyApp\\shell-extension.dll')
    expect(r.bullets.some((b) => /regsvr32/i.test(b.text))).toBe(false)
  })
})
