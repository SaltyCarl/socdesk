// shared/analyzer/__tests__/cmdvars.test.ts
import { describe, it, expect } from 'vitest'
import { reassembleCmdVars } from '../cmdvars'

describe('reassembleCmdVars (review 2.5)', () => {
  it('reassembles set x=power & set y=shell & %x%%y%', () => {
    const r = reassembleCmdVars('set x=power&&set y=shell&&%x%%y% -c whoami')
    expect(r.text.toLowerCase()).toContain('powershell')
    expect(r.changed).toBe(true)
  })
  it('handles quoted set "x=..."', () => {
    expect(reassembleCmdVars('set "x=cmd"&&%x% /c dir').text.toLowerCase()).toContain('cmd /c dir')
  })
  it('resolves %COMSPEC:~n,m% substrings when COMSPEC is set', () => {
    const r = reassembleCmdVars('set COMSPEC=C:\\Windows\\System32\\cmd.exe&&%COMSPEC:~-7%')
    expect(r.text.toLowerCase()).toContain('cmd.exe')
  })
  it('leaves a bare %PATH% untouched (no reassembly)', () => {
    expect(reassembleCmdVars('echo %PATH%').changed).toBe(false)
  })
  it('is bounded — a var map over 64 entries does not spin', () => {
    const many = Array.from({ length: 200 }, (_, i) => `set v${i}=${i}`).join('&')
    expect(() => reassembleCmdVars(many)).not.toThrow()
  })
})
