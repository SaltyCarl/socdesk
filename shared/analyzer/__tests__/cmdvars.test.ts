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

  // Gap (a) — the !VAR! delayed-expansion branch had zero committed tests.
  it('resolves !VAR! under enabledelayedexpansion the same as %VAR%', () => {
    const r = reassembleCmdVars('setlocal enabledelayedexpansion & set x=power & set y=shell & !x!!y!')
    expect(r.text.toLowerCase()).toContain('powershell')
    expect(r.changed).toBe(true)
  })

  it('resolves !VAR:~n,m! substrings under enabledelayedexpansion', () => {
    const r = reassembleCmdVars(
      'setlocal enabledelayedexpansion & set COMSPEC=C:\\Windows\\System32\\cmd.exe & !COMSPEC:~-7!',
    )
    expect(r.text.toLowerCase()).toContain('cmd.exe')
  })

  it('does not substitute mismatched delimiters (%x! stays literal) even though !x! resolves', () => {
    const r = reassembleCmdVars('setlocal enabledelayedexpansion & set x=power & %x! !x!')
    expect(r.text).toContain('%x!')
    expect(r.text.toLowerCase()).toContain('power')
  })

  // Gap (b) — an unknown %VAR% must stay literal even when OTHER vars ARE set
  // (the guarantee this task most needs to protect: expand()'s null-check
  // must never start expanding a var that was never `set`).
  it('leaves an unknown %PATH% literal even when other vars are set', () => {
    const r = reassembleCmdVars('set x=power&&set y=shell&&%x%%y% %PATH%')
    expect(r.text.toLowerCase()).toContain('powershell')
    expect(r.text).toContain('%PATH%')
  })
})
