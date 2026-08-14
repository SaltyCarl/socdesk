// heroLayers.ts — the hero globe's HONEST data model.
//
// Three layers, each sourced and honest-empty-tolerant. NO invented intel:
//
//   1. Reported-IP scatter  — abuse.ch Feodo Tracker + ThreatFox blocklist IPs
//      (data/state/threat_ips.json). Real fields only; NO fabricated per-IP
//      verdict/score. Geolocation is hosting/registrar, not operator.
//   2. Ransomware-by-country — ransomware.live leak-site claims aggregated by
//      the claimed-victim COUNTRY (feed.json), parsed with the SAME "Country: XX"
//      rule the profile system uses (views/profiles.ts::parseCountry) so the two
//      surfaces can never disagree. Country → centroid via the bundled pipeline
//      table. This is where victims are HIT, never attacker origin.
//   3. Enrich landing        — the live /api/enrich result for a looked-up
//      indicator (built here from the raw response; landed on real coords).
//
// Pure functions + types only — no React, no three, no DOM, no I/O. The whole
// layer is unit-testable in a plain Node env (see heroLayers.test.ts).

import { unitVec, type Vec3 } from './pins'
import { COUNTRY_CENTROIDS } from './vendor/country_centroids'
import { claimCount } from '../overview/aggregations'
import { parseCountry } from '../views/profiles'
import type { FeedItem } from '../views/types'

/* ============================================================
   Layer 1 — reported-IP scatter (data/state/threat_ips.json)
   ============================================================ */

export type ThreatIpSource = 'feodotracker' | 'threatfox'

export interface ThreatIp {
  ip: string
  country?: string
  lat: number
  lng: number
  source: ThreatIpSource | string
  malware?: string
  port?: number | null
  first_seen?: string
  last_seen?: string
  geo_precision?: 'city' | 'country' | string
}

export interface ThreatIpsPayload {
  generated_at?: string
  attribution?: string
  count?: number
  ips?: ThreatIp[]
}

/* ============================================================
   Hero pin union — one buffer, two honest layers. Both periwinkle (the pin
   colour is a single shader uniform). IP pins are a fixed size; ransomware
   pins are sized by claim volume. `r` is the model-space plot point.
   ============================================================ */

export interface IpPin {
  kind: 'ip'
  r: Vec3
  sizePx: number
  ip: string
  country: string
  source: ThreatIpSource | string
  sourceLabel: string
  malware: string
  port: string
  firstSeen: string
  lastSeen: string
  approxGeo: boolean
  /** honest external verify link (abuse.ch is the publisher; AbuseIPDB the pivot). */
  lookupHref: string
}

export interface RansomGroupSlice {
  name: string
  slug: string
  claims: number
}

export interface RansomCountryPin {
  kind: 'ransom'
  r: Vec3
  sizePx: number
  country: string
  countryName: string
  claims: number
  groups: RansomGroupSlice[]
}

export type HeroPin = IpPin | RansomCountryPin

/* -- sizing (px diameter fed to the pin shader's aSize) -------------------- */

const IP_PIN_PX = 9.5 // fixed — no fabricated severity to size by
const RANSOM_MIN_PX = 10
const RANSOM_MAX_PX = 22

/** ISO code → English country name. Intl.DisplayNames is CSP-safe (no eval) and
 *  present in every evergreen browser + Node 18+. Falls back to the raw code. */
export function countryName(code: string): string {
  const cc = String(code || '').toUpperCase()
  if (!cc) return ''
  try {
    const dn = new Intl.DisplayNames(['en'], { type: 'region' })
    return dn.of(cc) ?? cc
  } catch {
    return cc
  }
}

function sourceLabel(source: string): string {
  if (source === 'feodotracker') return 'Feodo Tracker'
  if (source === 'threatfox') return 'ThreatFox'
  return source || 'abuse.ch'
}

/**
 * Layer 1 — one pin per reported IP with real geo. Honest-empty tolerant: a
 * missing/short list yields []. Rows without a finite lat/lng are dropped
 * (never plotted at 0,0). No per-IP verdict is invented.
 */
export function buildIpPins(payload: ThreatIpsPayload | null | undefined): IpPin[] {
  const ips = payload?.ips
  if (!Array.isArray(ips) || ips.length === 0) return []
  const out: IpPin[] = []
  for (const row of ips) {
    if (!row || typeof row.ip !== 'string') continue
    const lat = Number(row.lat)
    const lng = Number(row.lng)
    if (!Number.isFinite(lat) || !Number.isFinite(lng)) continue
    const source = String(row.source || '')
    out.push({
      kind: 'ip',
      r: unitVec(lat, lng),
      sizePx: IP_PIN_PX,
      ip: row.ip,
      country: String(row.country || '').toUpperCase(),
      source,
      sourceLabel: sourceLabel(source),
      malware: String(row.malware || '').trim() || 'Unclassified',
      port: row.port == null ? '' : String(row.port),
      firstSeen: day(row.first_seen),
      lastSeen: day(row.last_seen),
      approxGeo: row.geo_precision !== 'city',
      lookupHref: `https://www.abuseipdb.com/check/${encodeURIComponent(row.ip)}`,
    })
  }
  return out
}

/** ISO date → YYYY-MM-DD, or "—" when absent. */
function day(s?: string): string {
  return s ? String(s).slice(0, 10) : '—'
}

/**
 * Layer 2 — aggregate ransomware.live leak-site claims by claimed-victim
 * country. Only SINGLE claims carry a country (digests roll country up and
 * drop it — parseCountry returns undefined for them), so this layer is honestly
 * partial: it plots located claims, never a total. Each country pin is sized by
 * its located-claim volume and carries its top contributing groups.
 *
 * Honest-empty tolerant: a quiet window (no located claims) → [].
 */
export function buildRansomCountryPins(feed: FeedItem[] | null | undefined): RansomCountryPin[] {
  if (!Array.isArray(feed) || feed.length === 0) return []

  // country → { total claims, per-group tallies }
  const byCountry = new Map<string, { claims: number; groups: Map<string, number> }>()

  for (const it of feed) {
    if (!it || it.source !== 'ransomwarelive') continue
    if (it.grouped != null) continue // digest rows drop the country — can't place
    const code = parseCountry(it.summary ?? '')
    if (!code) continue
    if (!COUNTRY_CENTROIDS[code]) continue // no centroid → can't place, don't guess
    const n = claimCount(it)
    const bucket = byCountry.get(code) ?? { claims: 0, groups: new Map<string, number>() }
    bucket.claims += n
    const actor = it.entities?.actors?.[0]
    if (actor) bucket.groups.set(actor, (bucket.groups.get(actor) ?? 0) + n)
    byCountry.set(code, bucket)
  }

  if (byCountry.size === 0) return []

  let maxClaims = 1
  for (const { claims } of byCountry.values()) maxClaims = Math.max(maxClaims, claims)

  const pins: RansomCountryPin[] = []
  for (const [code, { claims, groups }] of byCountry) {
    const centroid = COUNTRY_CENTROIDS[code]
    const topGroups: RansomGroupSlice[] = [...groups.entries()]
      .map(([name, c]) => ({ name, slug: name.toLowerCase(), claims: c }))
      .sort((a, b) => b.claims - a.claims || a.name.localeCompare(b.name))
      .slice(0, 3)
    pins.push({
      kind: 'ransom',
      r: unitVec(centroid[0], centroid[1]),
      sizePx: ransomSize(claims, maxClaims),
      country: code,
      countryName: countryName(code),
      claims,
      groups: topGroups,
    })
  }
  // largest first — a stable, meaningful order (not buffer/plot order)
  pins.sort((a, b) => b.claims - a.claims || a.country.localeCompare(b.country))
  return pins
}

/** sqrt scale (area-proportional) from claim volume, clamped to the pin band. */
function ransomSize(claims: number, maxClaims: number): number {
  const t = Math.sqrt(Math.max(1, claims) / Math.max(1, maxClaims))
  return RANSOM_MIN_PX + (RANSOM_MAX_PX - RANSOM_MIN_PX) * t
}

/* ============================================================
   Layer 3 — the live /api/enrich landing card model.
   The raw response is lib/enrich.mjs's shape: a consensus TALLY + per-source
   rows (each a source's OWN finding, never SOCDesk's). We build a card from it
   WITHOUT inventing a verdict — SOCDesk counts sources, it does not pronounce.
   ============================================================ */

export type EnrichTone = 'red' | 'amber' | 'green' | 'grey'

export interface EnrichSourceRaw {
  name?: string
  verdict?: string
  kind?: string
  headline?: string
  facts?: Array<[string, string]>
  url?: string
  screenshot?: string
}

export interface EnrichApiResult {
  indicator?: string
  type?: string
  checked_at?: string
  consulted?: number
  flagged?: number
  tone?: string
  sources?: EnrichSourceRaw[]
  partial?: boolean
  errors?: Array<{ source: string; reason: string }>
  error?: string
}

export interface EnrichFinding {
  name: string
  text: string
  url: string
}

export interface EnrichCard {
  kind: 'enrich'
  indicator: string
  type: string
  tone: EnrichTone
  consulted: number
  flagged: number
  findings: EnrichFinding[]
  /** ipinfo geo/ASN context — labelled context, never a verdict. */
  geoText: string
  asnText: string
  checkedAt: string
  partial: boolean
  /** the primary verify pivot (first scored source's own url), when present. */
  primaryUrl: string
  primaryLabel: string
}

const COORD_RE = /^\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*$/

/** Pull the real lat/lng out of the enrich result's context (ipinfo) row —
 *  the ONLY coordinates we hold. Returns null when the indicator has no geo
 *  (hashes, most domains) so the caller can degrade honestly (no landing). */
export function parseCoords(result: EnrichApiResult | null | undefined): { lat: number; lng: number } | null {
  const sources = result?.sources
  if (!Array.isArray(sources)) return null
  const ctx = sources.find((s) => s && s.kind === 'context')
  if (!ctx || !Array.isArray(ctx.facts)) return null
  const co = ctx.facts.find((f) => Array.isArray(f) && /coordinates/i.test(String(f[0])))
  if (!co) return null
  const m = String(co[1]).match(COORD_RE)
  if (!m) return null
  const lat = parseFloat(m[1])
  const lng = parseFloat(m[2])
  if (!Number.isFinite(lat) || !Number.isFinite(lng)) return null
  return { lat, lng }
}

/** True when the enrich result carries real coordinates (so a landing is honest). */
export function geoPresent(result: EnrichApiResult | null | undefined): boolean {
  return parseCoords(result) != null
}

function fact(row: EnrichSourceRaw | undefined, key: string): string {
  if (!row?.facts) return ''
  const hit = row.facts.find((f) => Array.isArray(f) && String(f[0]).toLowerCase() === key)
  const v = hit ? String(hit[1]).trim() : ''
  return v === '—' ? '' : v
}

const TONES: ReadonlySet<string> = new Set(['red', 'amber', 'green', 'grey'])

/**
 * Build the enrich landing card from the raw /api/enrich response. Real fields
 * only: the consensus tally, each source's own one-line finding, and the ipinfo
 * geo/ASN as CONTEXT. Never synthesises a verdict word.
 */
export function buildEnrichCard(result: EnrichApiResult): EnrichCard {
  const sources = Array.isArray(result.sources) ? result.sources : []
  const scored = sources.filter((s) => s && s.kind !== 'context')
  const ctx = sources.find((s) => s && s.kind === 'context')

  const findings: EnrichFinding[] = scored
    .filter((s) => s.headline)
    .slice(0, 2)
    .map((s) => ({
      name: String(s.name || 'Source'),
      text: String(s.headline || ''),
      url: String(s.url || ''),
    }))

  const primary = scored.find((s) => s.url)
  const location = fact(ctx, 'location')
  const asn = fact(ctx, 'asn')
  const org = fact(ctx, 'organisation') || fact(ctx, 'organization')
  const asnText = [asn, org].filter(Boolean).join(' · ')

  return {
    kind: 'enrich',
    indicator: String(result.indicator || ''),
    type: String(result.type || '').toUpperCase(),
    tone: TONES.has(String(result.tone)) ? (result.tone as EnrichTone) : 'grey',
    consulted: Number(result.consulted ?? 0),
    flagged: Number(result.flagged ?? 0),
    findings,
    geoText: location,
    asnText,
    checkedAt: day(result.checked_at),
    partial: Boolean(result.partial),
    primaryUrl: primary ? String(primary.url) : '',
    primaryLabel: primary ? `Verify at ${primary.name}` : '',
  }
}
