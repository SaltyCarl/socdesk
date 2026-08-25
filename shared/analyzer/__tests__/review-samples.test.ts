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
  it('#3 AMSI bypass + Defender tamper + shadow-copy/recovery destruction: shadow-recovery-tamper now fires (Phase 12, review 2.4)', async () => {
    const r = await analyze(
      "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true); Set-MpPreference -DisableRealtimeMonitoring $true; vssadmin delete shadows /all /quiet",
    )
    expect(r.signals.some((s) => s.id === 'shadow-recovery-tamper')).toBe(true)
    expect(r.characterization).not.toBeNull()
    expect(r.characterization!.level).toBe('high-confidence-malicious')
    expect(r.characterization!.basis).toContain('shadow-recovery-tamper')
    expect(r.bullets.some((b) => b.text === 'Deletes volume shadow copies / disables recovery — destroys ransomware rollback')).toBe(true)
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
