// lib/__tests__/enrich.test.mjs
// Covers the AlienVault OTX enrich source: it is CONTEXT (community campaign /
// actor attribution), never a tally-voting verdict, and it degrades honestly
// when its key is absent. Uses a mock fetch so no network is touched.
import { describe, expect, it } from 'vitest'
import { enrich, _internals } from '../enrich.mjs'

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

/** Only the abuseipdb URL answers; everything else 404s cleanly. */
function mockAbuse(payload, capture) {
  return async (url) => {
    if (String(url).includes('abuseipdb.com')) {
      if (capture) capture(String(url))
      return { status: 200, ok: true, json: async () => payload }
    }
    return { status: 404, ok: false, json: async () => ({}) }
  }
}

describe('AbuseIPDB abuse categories', () => {
  it('surfaces the most-reported categories from a verbose response, most-frequent first', async () => {
    const payload = {
      data: {
        abuseConfidenceScore: 65,
        totalReports: 4,
        reports: [
          { categories: [18, 22] }, // Brute-Force, SSH
          { categories: [18, 14] }, // Brute-Force, Port Scan
          { categories: [22, 18] }, // SSH, Brute-Force
          { categories: [14] }, //     Port Scan
        ],
      },
    }
    const out = await enrich(mockAbuse(payload), 'ipv4', '1.2.3.4', { ABUSEIPDB_API_KEY: 'x' })
    const a = out.sources.find((s) => s.name === 'AbuseIPDB')
    const facts = Object.fromEntries(a.facts)
    // 18 Brute-Force ×3, 22 SSH ×2, 14 Port Scan ×2 → Brute-Force leads.
    expect(facts['Abuse categories'].startsWith('Brute-Force')).toBe(true)
    expect(facts['Abuse categories']).toContain('SSH')
    expect(facts['Abuse categories']).toContain('Port Scan')
    // and the top categories ride the card-visible headline
    expect(a.headline).toContain('Brute-Force')
  })

  it('shows — when there are no reports', async () => {
    const out = await enrich(
      mockAbuse({ data: { abuseConfidenceScore: 0, totalReports: 0 } }),
      'ipv4', '8.8.8.8', { ABUSEIPDB_API_KEY: 'x' })
    const facts = Object.fromEntries(out.sources.find((s) => s.name === 'AbuseIPDB').facts)
    expect(facts['Abuse categories']).toBe('—')
  })

  it('requests the verbose endpoint (categories only come back with it)', async () => {
    let called = ''
    await enrich(mockAbuse({ data: {} }, (u) => (called = u)), 'ipv4', '1.2.3.4', { ABUSEIPDB_API_KEY: 'x' })
    expect(called).toContain('verbose')
  })
})

describe('blocking axis + planSources (Track B1)', () => {
  const byName = (n) => _internals.SOURCES.find((s) => s.name === n)

  it('marks ONLY OTX and RDAP as non-blocking', () => {
    expect(byName('AlienVault OTX').blocking).toBe(false)
    expect(byName('RDAP').blocking).toBe(false)
    // ipinfo is context-but-BLOCKING (feeds the globe pin) — must stay blocking.
    expect(byName('ipinfo').blocking).toBeUndefined()
    for (const n of ['AbuseIPDB', 'VirusTotal', 'GreyNoise', 'MalwareBazaar', 'urlscan'])
      expect(byName(n).blocking, `${n} must block`).toBeUndefined()
  })

  it('partitions ipv4 sources: ipinfo blocking, OTX non-blocking', () => {
    const plan = _internals.planSources('ipv4', { ABUSEIPDB_API_KEY: 'x', VT_API_KEY: 'k', OTX_API_KEY: 't' })
    expect(plan.blocking.map((s) => s.name)).toEqual(['AbuseIPDB', 'VirusTotal', 'GreyNoise', 'ipinfo'])
    expect(plan.nonBlocking.map((s) => s.name)).toEqual(['AlienVault OTX'])
  })

  it('partitions domain sources: RDAP + OTX non-blocking, in SOURCES order', () => {
    // OTX requires its own key (no optionalKey — see the "not configured" guardrail
    // test above), so it must be keyed here for it to land in `usable`/`nonBlocking`.
    const plan = _internals.planSources('domain', { VT_API_KEY: 'k', OTX_API_KEY: 't' })
    expect(plan.nonBlocking.map((s) => s.name)).toEqual(['RDAP', 'AlienVault OTX'])
    expect(plan.usable.map((s) => s.name)).toEqual(['VirusTotal', 'urlscan', 'RDAP', 'AlienVault OTX'])
  })

  it('tags each not-configured skip with its blocking-ness', () => {
    // sha256, no keys: VT + MalwareBazaar are blocking; OTX is non-blocking.
    const plan = _internals.planSources('sha256', {})
    const skip = Object.fromEntries(plan.skipped.map((s) => [s.source, s.blocking]))
    expect(skip).toEqual({ VirusTotal: true, MalwareBazaar: true, 'AlienVault OTX': false })
  })
})

describe('phased assembler — behavior-preserving extraction (Track B1)', () => {
  const mockFetchOTX = (payload) => async (url) =>
    String(url).includes('otx.alienvault.com')
      ? { status: 200, ok: true, json: async () => payload }
      : { status: 404, ok: false, json: async () => ({}) }

  it('exports the four phases via _internals', () => {
    for (const k of ['planSources', 'dispatchSources', 'collectResults', 'assemble'])
      expect(typeof _internals[k]).toBe('function')
  })

  it('dispatch starts every source (blocking + non-blocking) and collect awaits them', async () => {
    const plan = _internals.planSources('domain', { VT_API_KEY: 'k', OTX_API_KEY: 't' })
    const dispatched = _internals.dispatchSources(mockFetchOTX({ pulse_info: { count: 3, pulses: [] } }),
      { type: 'domain', value: 'evil.test' }, { VT_API_KEY: 'k', OTX_API_KEY: 't' }, plan)
    expect(dispatched.blocking.length + dispatched.context.length).toBe(plan.usable.length)
    const collected = await _internals.collectResults(dispatched, plan)
    // zero-delay OTX mock is microtask-ready, so it rides along even at grace 0
    expect(collected.sources.find((s) => s.name === 'AlienVault OTX')).toBeTruthy()
  })

  it('is byte-identical to the pre-extraction response for a fully-mocked run', async () => {
    const out = await enrich(mockFetchOTX({ pulse_info: { count: 2, pulses: [
      { name: 'x', tags: ['t'], adversary: 'A', malware_families: [] }] } }),
      'domain', 'evil.test', { VT_API_KEY: 'k', OTX_API_KEY: 't' }, new Date('2026-08-22T00:00:00Z'))
    expect(out.type).toBe('domain')
    expect(out.checked_at).toBe('2026-08-22T00:00:00.000Z')
    expect(out.sources.map((s) => s.name)).toEqual(['VirusTotal', 'urlscan', 'RDAP', 'AlienVault OTX'])
    expect(out.consulted).toBe(2)   // VT + urlscan; RDAP + OTX are context, excluded
    expect(out.flagged).toBe(0)
  })
})
