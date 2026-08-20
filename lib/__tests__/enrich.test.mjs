// lib/__tests__/enrich.test.mjs
// Covers the AlienVault OTX enrich source: it is CONTEXT (community campaign /
// actor attribution), never a tally-voting verdict, and it degrades honestly
// when its key is absent. Uses a mock fetch so no network is touched.
import { describe, expect, it } from 'vitest'
import { enrich } from '../enrich.mjs'

/** A fetch stub: OTX URLs get the given payload; everything else 404s (so the
 *  other domain sources return "unknown" cleanly instead of throwing). */
function mockFetch(otxPayload) {
  return async (url) => {
    if (String(url).includes('otx.alienvault.com')) {
      return { status: 200, ok: true, json: async () => otxPayload }
    }
    return { status: 404, ok: false, json: async () => ({}) }
  }
}

const PULSES = {
  pulse_info: {
    count: 2,
    pulses: [
      { name: 'Akira ransomware infra', tags: ['ransomware', 'akira'], adversary: 'Akira', malware_families: [{ display_name: 'Akira' }], created: '2026-07-01' },
      { name: 'APT29 c2', tags: ['apt29', 'cozybear'], adversary: 'APT29', malware_families: [], created: '2026-06-15' },
    ],
  },
}

describe('OTX enrich source', () => {
  it('returns community pulse attribution as a context source (never a verdict)', async () => {
    const out = await enrich(mockFetch(PULSES), 'domain', 'evil.test', { OTX_API_KEY: 'test' })
    const otx = out.sources.find((s) => s.name === 'AlienVault OTX')
    expect(otx).toBeTruthy()
    expect(otx.kind).toBe('context')
    expect(otx.verdict).toBe('unknown') // context — excluded from the tally
    expect(otx.headline).toContain('2 pulses')
    expect(otx.headline).toContain('Akira')
    const facts = Object.fromEntries(otx.facts)
    expect(facts.Pulses).toBe('2')
    expect(facts['Adversary / malware']).toContain('APT29')
    expect(facts.Tags).toContain('ransomware')
    expect(otx.url).toContain('otx.alienvault.com/indicator/domain/evil.test')
  })

  it('does not let OTX inflate the verdict tally', async () => {
    const out = await enrich(mockFetch(PULSES), 'domain', 'evil.test', { OTX_API_KEY: 'test' })
    // OTX + RDAP are both context; neither counts toward consulted/flagged.
    expect(out.flagged).toBe(0)
  })

  it('says "No community pulses" when OTX has no record', async () => {
    const out = await enrich(mockFetch({ pulse_info: { count: 0, pulses: [] } }), 'domain', 'clean.test', { OTX_API_KEY: 'test' })
    const otx = out.sources.find((s) => s.name === 'AlienVault OTX')
    expect(otx.headline).toMatch(/no community pulses/i)
  })

  it('reports OTX as not configured (never silently absent) when the key is missing', async () => {
    const out = await enrich(mockFetch(PULSES), 'domain', 'evil.test', {})
    expect(out.sources.find((s) => s.name === 'AlienVault OTX')).toBeUndefined()
    expect(out.errors.some((e) => e.source === 'AlienVault OTX' && /not configured/i.test(e.reason))).toBe(true)
  })

  it('maps an IP to the OTX IPv4 endpoint + ip pivot link', async () => {
    let called = ''
    const fetchImpl = async (url) => {
      if (String(url).includes('otx.alienvault.com')) { called = String(url); return { status: 200, ok: true, json: async () => PULSES } }
      return { status: 404, ok: false, json: async () => ({}) }
    }
    const out = await enrich(fetchImpl, 'ipv4', '45.9.148.20', { OTX_API_KEY: 'test' })
    expect(called).toContain('/indicators/IPv4/45.9.148.20/general')
    const otx = out.sources.find((s) => s.name === 'AlienVault OTX')
    expect(otx.url).toContain('otx.alienvault.com/indicator/ip/45.9.148.20')
  })
})
