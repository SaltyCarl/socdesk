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

function deferred() { let resolve; const promise = new Promise((r) => (resolve = r)); return { promise, resolve } }

describe('non-blocking grace-race — verdict-speed return (Track B1)', () => {
  it('returns before a slow context source settles; it does not gate the response', async () => {
    const gate = deferred()
    let enrichReturned = false, otxSettledAfterReturn = null
    const fetchImpl = async (url) => {
      const u = String(url)
      if (u.includes('otx.alienvault.com')) {
        await gate.promise                       // OTX blocks until released
        otxSettledAfterReturn = enrichReturned
        return { status: 200, ok: true, json: async () => ({ pulse_info: { count: 1, pulses: [] } }) }
      }
      if (u.includes('abuseipdb.com'))
        return { status: 200, ok: true, json: async () => ({ data: { abuseConfidenceScore: 0, totalReports: 0 } }) }
      return { status: 404, ok: false, json: async () => ({}) } // VT/GreyNoise/ipinfo resolve fast
    }
    // VT keyed so it is NOT a blocking not-configured skip (would force partial).
    const out = await enrich(fetchImpl, 'ipv4', '1.2.3.4',
      { ABUSEIPDB_API_KEY: 'x', VT_API_KEY: 'k', OTX_API_KEY: 't' })
    enrichReturned = true

    expect(out.sources.find((s) => s.name === 'AlienVault OTX')).toBeUndefined() // dropped
    expect(out.sources.find((s) => s.name === 'AbuseIPDB')).toBeTruthy()          // verdicts present
    expect(out.errors.some((e) => e.source === 'AlienVault OTX')).toBe(false)     // silent (not a fast error)

    gate.resolve()
    await gate.promise
    expect(otxSettledAfterReturn).toBe(true) // enrich RETURNED before OTX settled
  })

  it('a fast (microtask-ready) context source still rides along', async () => {
    const fetchImpl = async (url) =>
      String(url).includes('otx.alienvault.com')
        ? { status: 200, ok: true, json: async () => ({ pulse_info: { count: 4, pulses: [] } }) }
        : { status: 404, ok: false, json: async () => ({}) }
    const out = await enrich(fetchImpl, 'ipv4', '1.2.3.4',
      { ABUSEIPDB_API_KEY: 'x', VT_API_KEY: 'k', OTX_API_KEY: 't' })
    const otx = out.sources.find((s) => s.name === 'AlienVault OTX')
    expect(otx).toBeTruthy()
    expect(otx.headline).toContain('4 pulses')
  })

  it('latency: a 1500ms context source does not delay the response (belt-and-suspenders)', async () => {
    const fetchImpl = async (url) => {
      if (String(url).includes('otx.alienvault.com'))
        return new Promise((res) => setTimeout(() => res({ status: 200, ok: true, json: async () => ({ pulse_info: { count: 1, pulses: [] } }) }), 1500))
      if (String(url).includes('abuseipdb.com'))
        return { status: 200, ok: true, json: async () => ({ data: { abuseConfidenceScore: 0, totalReports: 0 } }) }
      return { status: 404, ok: false, json: async () => ({}) }
    }
    const t0 = performance.now()
    const out = await enrich(fetchImpl, 'ipv4', '1.2.3.4',
      { ABUSEIPDB_API_KEY: 'x', VT_API_KEY: 'k', OTX_API_KEY: 't' })
    expect(performance.now() - t0).toBeLessThan(500) // well under the 1500ms context source
    expect(out.sources.find((s) => s.name === 'AlienVault OTX')).toBeUndefined()
  })
})

describe('skipped_context + fast-fail + partial decoupling (Track B1)', () => {
  const gnIpinfo404 = (u) => ({ status: 404, ok: false, json: async () => ({}) })

  it('a slow context drop is listed in skipped_context, not errors, and never partial', async () => {
    const gate = deferred()
    const fetchImpl = async (url) => {
      const u = String(url)
      if (u.includes('otx.alienvault.com')) { await gate.promise; return { status: 200, ok: true, json: async () => ({ pulse_info: { count: 1, pulses: [] } }) } }
      if (u.includes('abuseipdb.com')) return { status: 200, ok: true, json: async () => ({ data: { abuseConfidenceScore: 0, totalReports: 0 } }) }
      return gnIpinfo404(u)
    }
    const out = await enrich(fetchImpl, 'ipv4', '1.2.3.4', { ABUSEIPDB_API_KEY: 'x', VT_API_KEY: 'k', OTX_API_KEY: 't' })
    expect(out.skipped_context).toEqual(['AlienVault OTX'])
    expect(out.errors.some((e) => e.source === 'AlienVault OTX')).toBe(false)
    expect(out.partial).toBe(false) // ⇒ cacheable
    gate.resolve(); await gate.promise
  })

  it('a FAST context failure (bad key → 401) is named in errors WITHOUT setting partial', async () => {
    const fetchImpl = async (url) => {
      const u = String(url)
      if (u.includes('otx.alienvault.com')) return { status: 401, ok: false, json: async () => ({}) } // fast, real error
      if (u.includes('abuseipdb.com')) return { status: 200, ok: true, json: async () => ({ data: { abuseConfidenceScore: 0, totalReports: 0 } }) }
      return gnIpinfo404(u)
    }
    const out = await enrich(fetchImpl, 'ipv4', '1.2.3.4', { ABUSEIPDB_API_KEY: 'x', VT_API_KEY: 'k', OTX_API_KEY: 't' })
    const err = out.errors.find((e) => e.source === 'AlienVault OTX')
    expect(err).toBeTruthy()
    expect(err.reason).toMatch(/API key/i)
    expect(out.skipped_context).toEqual([])
    expect(out.partial).toBe(false) // OTX is non-blocking — a fast fail must not gate the cache
  })

  it('partial reflects blocking health only (the cache invariant)', async () => {
    // (a) slow OTX dropped, all blocking OK → partial false
    const gate = deferred()
    const slowOtx = async (url) => {
      const u = String(url)
      if (u.includes('otx.alienvault.com')) { await gate.promise; return { status: 200, ok: true, json: async () => ({ pulse_info: { count: 0, pulses: [] } }) } }
      if (u.includes('abuseipdb.com')) return { status: 200, ok: true, json: async () => ({ data: { abuseConfidenceScore: 0, totalReports: 0 } }) }
      return gnIpinfo404(u)
    }
    const ok = await enrich(slowOtx, 'ipv4', '1.2.3.4', { ABUSEIPDB_API_KEY: 'x', VT_API_KEY: 'k', OTX_API_KEY: 't' })
    expect(ok.partial).toBe(false)
    gate.resolve(); await gate.promise

    // (b) a BLOCKING source rejects (AbuseIPDB 500) → partial true
    const badBlocking = async (url) => {
      const u = String(url)
      if (u.includes('abuseipdb.com')) return { status: 500, ok: false, json: async () => ({}) }
      if (u.includes('otx.alienvault.com')) return { status: 200, ok: true, json: async () => ({ pulse_info: { count: 0, pulses: [] } }) }
      return gnIpinfo404(u)
    }
    const bad = await enrich(badBlocking, 'ipv4', '1.2.3.4', { ABUSEIPDB_API_KEY: 'x', VT_API_KEY: 'k', OTX_API_KEY: 't' })
    expect(bad.partial).toBe(true)

    // (c) ONLY a non-blocking source not-configured (no OTX key) → partial false, OTX still named
    const noOtxKey = await enrich(async (url) =>
      String(url).includes('abuseipdb.com')
        ? { status: 200, ok: true, json: async () => ({ data: { abuseConfidenceScore: 0, totalReports: 0 } }) }
        : gnIpinfo404(String(url)),
      'ipv4', '1.2.3.4', { ABUSEIPDB_API_KEY: 'x', VT_API_KEY: 'k' })
    expect(noOtxKey.partial).toBe(false)
    expect(noOtxKey.errors.some((e) => e.source === 'AlienVault OTX' && /not configured/i.test(e.reason))).toBe(true)
  })
})

describe('invariants under context omission (Track B1)', () => {
  const blocking404 = (u) =>
    String(u).includes('abuseipdb.com')
      ? { status: 200, ok: true, json: async () => ({ data: { abuseConfidenceScore: 60, totalReports: 5 } }) }
      : { status: 404, ok: false, json: async () => ({}) }

  it('tally (consulted/flagged/tone) is identical whether OTX rides along or is dropped', async () => {
    const env = { ABUSEIPDB_API_KEY: 'x', VT_API_KEY: 'k', OTX_API_KEY: 't' }
    const fast = await enrich(async (url) =>
      String(url).includes('otx.alienvault.com')
        ? { status: 200, ok: true, json: async () => ({ pulse_info: { count: 9, pulses: [] } }) }
        : blocking404(String(url)), 'ipv4', '1.2.3.4', env)

    const gate = deferred()
    const dropped = await enrich(async (url) => {
      const u = String(url)
      if (u.includes('otx.alienvault.com')) { await gate.promise; return { status: 200, ok: true, json: async () => ({ pulse_info: { count: 9, pulses: [] } }) } }
      return blocking404(u)
    }, 'ipv4', '1.2.3.4', env)
    gate.resolve(); await gate.promise

    expect(dropped.consulted).toBe(fast.consulted)
    expect(dropped.flagged).toBe(fast.flagged)
    expect(dropped.tone).toBe(fast.tone)
  })

  it('preserves SOURCES order and keeps ipinfo before OTX (globe-pin invariant)', async () => {
    const env = { ABUSEIPDB_API_KEY: 'x', VT_API_KEY: 'k', OTX_API_KEY: 't' }
    const out = await enrich(async (url) =>
      String(url).includes('otx.alienvault.com')
        ? { status: 200, ok: true, json: async () => ({ pulse_info: { count: 1, pulses: [] } }) }
        : { status: 404, ok: false, json: async () => ({}) }, 'ipv4', '1.2.3.4', env)
    expect(out.sources.map((s) => s.name)).toEqual(['AbuseIPDB', 'VirusTotal', 'GreyNoise', 'ipinfo', 'AlienVault OTX'])
    const ipinfoIdx = out.sources.findIndex((s) => s.kind === 'context')       // FIRST context row
    expect(out.sources[ipinfoIdx].name).toBe('ipinfo')
    expect(ipinfoIdx).toBeLessThan(out.sources.findIndex((s) => s.name === 'AlienVault OTX'))

    // dropped OTX: ipinfo still the (only) context row, verdicts in order
    const gate = deferred()
    const dropped = await enrich(async (url) => {
      const u = String(url)
      if (u.includes('otx.alienvault.com')) { await gate.promise; return { status: 200, ok: true, json: async () => ({ pulse_info: { count: 1, pulses: [] } }) } }
      return { status: 404, ok: false, json: async () => ({}) }
    }, 'ipv4', '1.2.3.4', env)
    gate.resolve(); await gate.promise
    expect(dropped.sources.map((s) => s.name)).toEqual(['AbuseIPDB', 'VirusTotal', 'GreyNoise', 'ipinfo'])
  })
})
