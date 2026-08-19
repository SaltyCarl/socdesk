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
