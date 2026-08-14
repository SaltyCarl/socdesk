// heroLayers.test.ts — the hero globe's honest data layer (pure, node-env).
//
// Covers the two aggregations + the enrich-card model. The emphasis is the
// HONESTY contract: honest-empty on absence, no fabricated fields, and the SAME
// "Country: XX" parse the profile system uses.

import { describe, it, expect } from 'vitest'
import type { FeedItem } from '../views/types'
import {
  buildIpPins,
  buildRansomCountryPins,
  buildEnrichCard,
  parseCoords,
  geoPresent,
  type ThreatIpsPayload,
  type EnrichApiResult,
} from './heroLayers'

/* ---------------- layer 1 — reported IPs ---------------- */

describe('buildIpPins', () => {
  it('is honest-empty for a missing/empty payload', () => {
    expect(buildIpPins(null)).toEqual([])
    expect(buildIpPins(undefined)).toEqual([])
    expect(buildIpPins({ ips: [] })).toEqual([])
  })

  it('maps real fields and drops rows without finite coordinates', () => {
    const payload: ThreatIpsPayload = {
      ips: [
        {
          ip: '50.16.16.211', country: 'us', lat: 39.0437, lng: -77.4875,
          source: 'feodotracker', malware: 'QakBot', port: 443,
          first_seen: '2025-12-30T13:56:31Z', last_seen: '2026-03-12T00:00:00Z',
          geo_precision: 'city',
        },
        // no geo → dropped, never plotted at (0,0)
        { ip: '10.0.0.1', lat: NaN as unknown as number, lng: 0, source: 'threatfox' },
      ],
    }
    const pins = buildIpPins(payload)
    expect(pins).toHaveLength(1)
    const p = pins[0]
    expect(p.kind).toBe('ip')
    expect(p.ip).toBe('50.16.16.211')
    expect(p.country).toBe('US')
    expect(p.sourceLabel).toBe('Feodo Tracker')
    expect(p.malware).toBe('QakBot')
    expect(p.port).toBe('443')
    expect(p.firstSeen).toBe('2025-12-30')
    expect(p.lastSeen).toBe('2026-03-12')
    expect(p.approxGeo).toBe(false)
    expect(p.lookupHref).toContain('50.16.16.211')
    expect(p.r).toHaveLength(3)
    expect(p.r.every((n) => Number.isFinite(n))).toBe(true)
  })

  it('never invents a malware family (unclassified stays honest)', () => {
    const pins = buildIpPins({ ips: [{ ip: '1.2.3.4', lat: 1, lng: 2, source: 'threatfox' }] })
    expect(pins[0].malware).toBe('Unclassified')
    expect(pins[0].sourceLabel).toBe('ThreatFox')
    expect(pins[0].port).toBe('')
  })
})

/* ---------------- layer 2 — ransomware by victim country ---------------- */

function ransomItem(actor: string, summary: string, extra: Partial<FeedItem> = {}): FeedItem {
  return {
    id: `${actor}-${Math.random()}`,
    source: 'ransomwarelive',
    category: 'ransomware',
    title: 'a new victim claim',
    summary,
    url: 'https://example.test',
    entities: { actors: [actor] },
    ...extra,
  }
}

describe('buildRansomCountryPins', () => {
  it('is honest-empty for a quiet/empty feed', () => {
    expect(buildRansomCountryPins(null)).toEqual([])
    expect(buildRansomCountryPins([])).toEqual([])
    // a digest carries no country → cannot be placed → empty
    expect(
      buildRansomCountryPins([
        ransomItem('clop', 'Grouped: Healthcare, Technology', { grouped: 5 }),
      ]),
    ).toEqual([])
  })

  it('aggregates single located claims by country with top groups', () => {
    const feed: FeedItem[] = [
      ransomItem('kairos', 'Sector: Manufacturing — Country: US. detail'),
      ransomItem('akira', 'Sector: Technology — Country: US. detail'),
      ransomItem('akira', 'Sector: Healthcare — Country: US. detail'),
      ransomItem('qilin', 'Sector: Energy — Country: IT. detail'),
      // digest → dropped
      ransomItem('clop', 'Grouped: Healthcare', { grouped: 9 }),
      // unknown-country literal '?' → parseCountry returns undefined → dropped
      ransomItem('play', 'Sector: Other — Country: ?. detail'),
    ]
    const pins = buildRansomCountryPins(feed)
    const us = pins.find((p) => p.country === 'US')
    const it = pins.find((p) => p.country === 'IT')
    expect(pins).toHaveLength(2)
    // largest first
    expect(pins[0].country).toBe('US')
    expect(us?.claims).toBe(3)
    expect(us?.groups[0]).toMatchObject({ name: 'akira', slug: 'akira', claims: 2 })
    expect(us?.kind).toBe('ransom')
    expect(us?.r).toHaveLength(3)
    expect(it?.claims).toBe(1)
    // US (more claims) sizes >= IT
    expect((us?.sizePx ?? 0)).toBeGreaterThanOrEqual(it?.sizePx ?? 0)
  })
})

/* ---------------- layer 3 — enrich card ---------------- */

const enrichResult: EnrichApiResult = {
  indicator: '50.16.16.211',
  type: 'ipv4',
  checked_at: '2026-08-14T10:58:26Z',
  consulted: 4,
  flagged: 3,
  tone: 'red',
  partial: false,
  sources: [
    { name: 'AbuseIPDB', verdict: 'malicious', headline: '100% abuse confidence · 42 reports', url: 'https://www.abuseipdb.com/check/50.16.16.211' },
    { name: 'VirusTotal', verdict: 'malicious', headline: '7/70 engines flag this as malicious', url: 'https://www.virustotal.com/gui/ip-address/50.16.16.211' },
    { name: 'ipinfo', kind: 'context', headline: 'Ashburn, US', url: 'https://ipinfo.io/50.16.16.211',
      facts: [['Location', 'Ashburn, Virginia, US'], ['Coordinates', '39.0437,-77.4875'], ['ASN', 'AS14618'], ['Organisation', 'Amazon']] },
  ],
}

describe('parseCoords / geoPresent', () => {
  it('reads the real coordinate from the context row', () => {
    expect(parseCoords(enrichResult)).toEqual({ lat: 39.0437, lng: -77.4875 })
    expect(geoPresent(enrichResult)).toBe(true)
  })
  it('is null when there is no geolocation (hash / no context row)', () => {
    expect(parseCoords({ sources: [{ name: 'MalwareBazaar', verdict: 'malicious', headline: 'x', url: 'y' }] })).toBeNull()
    expect(geoPresent({})).toBe(false)
    expect(geoPresent(null)).toBe(false)
  })
})

describe('buildEnrichCard', () => {
  it('builds the tally + attributed findings + geo context without inventing a verdict', () => {
    const card = buildEnrichCard(enrichResult)
    expect(card.kind).toBe('enrich')
    expect(card.indicator).toBe('50.16.16.211')
    expect(card.type).toBe('IPV4')
    expect(card.tone).toBe('red')
    expect(card.consulted).toBe(4)
    expect(card.flagged).toBe(3)
    // scored sources only (context excluded), capped at 2, verbatim headlines
    expect(card.findings).toHaveLength(2)
    expect(card.findings[0]).toMatchObject({ name: 'AbuseIPDB' })
    expect(card.findings.some((f) => f.name === 'ipinfo')).toBe(false)
    // context surfaces as geo/ASN, labelled context by the card, never in the tally
    expect(card.geoText).toBe('Ashburn, Virginia, US')
    expect(card.asnText).toBe('AS14618 · Amazon')
    expect(card.primaryUrl).toContain('abuseipdb.com')
    expect(card.checkedAt).toBe('2026-08-14')
  })

  it('degrades to a grey tally when nothing was consulted', () => {
    const card = buildEnrichCard({ indicator: 'x', type: 'domain', consulted: 0, flagged: 0, sources: [] })
    expect(card.tone).toBe('grey')
    expect(card.findings).toEqual([])
    expect(card.geoText).toBe('')
  })
})
