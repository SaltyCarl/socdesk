// profiles.ts — the actor / ransomware-group / malware PROFILE fusion layer.
//
// A profile fuses up to four INDEPENDENT snapshots into one honest picture of a
// single named entity:
//   • MITRE ATT&CK fingerprint (actors.json / malware.json) — the encyclopedia
//   • ransomware.live leak-site activity (feed.json) — who they are hitting now
//   • APT / campaign reporting (feed.json) — what outlets are writing about them
//   • relations.json co-occurrence — what else shows up alongside them
//
// The honesty doctrine (shared/verdict/doctrine.ts) governs every selector here:
// SOCDesk emits NO verdict of its own and NEVER synthesises a description, TTP,
// sector, or summary for a group that lacks one. A missing piece degrades to a
// null / empty field the card can state truthfully — never a fabricated one.
//
// Pure functions, no React, no I/O — the whole fusion is unit-testable in a
// plain Node env (see __tests__/profiles.test.ts).

import type { FeedItem, Profile, RelationsPayload } from './types'
import { buildRelationsIndex, relatedFor, type RelatedRow } from './relations'
import { claimCount } from '../overview/aggregations'

/* ---------------- shared MITRE helpers (pure, mirrors ActorsView) ---------- */

/** ATT&CK deep-link for a group (G####) or software (S####) id. Mirrors
 *  ActorsView.tsx:29-34 — kept here so the profile system is self-contained. */
export function attackUrl(kind: 'actor' | 'malware', id?: string): string {
  if (!id) return ''
  return kind === 'actor'
    ? `https://attack.mitre.org/groups/${encodeURIComponent(id)}/`
    : `https://attack.mitre.org/software/${encodeURIComponent(id)}/`
}

/** Strip ATT&CK markdown noise so the description reads as prose. Mirrors
 *  ActorsView.tsx:37-43 (citations + `[text](url)` links collapse to text). */
export function cleanDescription(d?: string): string {
  return (d ?? '')
    .replace(/\(Citation:[^)]*\)/g, '')
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    .replace(/\s{2,}/g, ' ')
    .trim()
}

/* ---------------- profile directory index --------------------------------- */

/** What a directory row *is*. A single entity can carry more than one truth
 *  (Akira is a MITRE actor AND an active ransomware group), so the flags below
 *  are additive — `kind` is only the primary classification for filtering. */
export type ProfileKind = 'actor' | 'ransomware' | 'malware'

export interface ProfileIndexEntry {
  /** Lowercased name — the address slug (matches feed entities + hash `#g=`). */
  slug: string
  /** Display name in its original casing (canonical MITRE name when known). */
  name: string
  /** Primary classification: MITRE actor → actor, MITRE software → malware, a
   *  leak-site-only group → ransomware. Drives the directory kind filter. */
  kind: ProfileKind
  /** True when an ATT&CK profile exists (by name OR alias). */
  hasMitre: boolean
  /** G#### / S#### when hasMitre. */
  attack_id?: string
  /** ATT&CK aliases (when hasMitre) — carried for directory search only. */
  aliases?: string[]
  /** Leak-site victim claims in the window — present iff the group posts claims. */
  claimCount?: number
}

/** Name + alias → profile, first-writer-wins (so a canonical name is never
 *  shadowed by another profile's alias collision). */
function aliasIndex(profiles: Profile[]): Map<string, Profile> {
  const m = new Map<string, Profile>()
  for (const p of profiles) {
    if (!p?.name) continue
    const n = p.name.toLowerCase()
    if (!m.has(n)) m.set(n, p)
  }
  // aliases second so a real name always wins over an alias.
  for (const p of profiles) {
    for (const a of p.aliases ?? []) {
      if (!a) continue
      const k = a.toLowerCase()
      if (!m.has(k)) m.set(k, p)
    }
  }
  return m
}

/**
 * The searchable directory: the UNION of MITRE actors + MITRE software + the
 * ransomware groups that posted leak-site claims + the actors named in APT /
 * campaign reporting. De-duplicated by slug; when an entity appears in more than
 * one source its flags MERGE (Akira keeps its actor fingerprint AND gains its
 * claim tally). A leak-site / reporting name that only exists via an ATT&CK
 * ALIAS still resolves `hasMitre` so the directory badge matches the card.
 */
export function buildProfileIndex(
  actors: Profile[],
  malware: Profile[],
  feed: FeedItem[],
): ProfileIndexEntry[] {
  const bySlug = new Map<string, ProfileIndexEntry>()

  const aliasesOf = (p: Profile): string[] =>
    (p.aliases ?? []).filter((a) => a && a.toLowerCase() !== p.name.toLowerCase())

  for (const p of actors) {
    if (!p?.name) continue
    const slug = p.name.toLowerCase()
    if (bySlug.has(slug)) continue
    bySlug.set(slug, {
      slug, name: p.name, kind: 'actor', hasMitre: true, attack_id: p.attack_id, aliases: aliasesOf(p),
    })
  }
  for (const p of malware) {
    if (!p?.name) continue
    const slug = p.name.toLowerCase()
    if (bySlug.has(slug)) continue
    bySlug.set(slug, {
      slug, name: p.name, kind: 'malware', hasMitre: true, attack_id: p.attack_id, aliases: aliasesOf(p),
    })
  }

  // ransomware.live groups — sum each group's claims with the board's parser.
  const claims = new Map<string, { raw: string; count: number }>()
  for (const it of feed) {
    if (it.source !== 'ransomwarelive') continue
    const raw = it.entities?.actors?.[0]
    if (!raw) continue
    const slug = raw.toLowerCase()
    const cur = claims.get(slug) ?? { raw, count: 0 }
    cur.count += claimCount(it)
    claims.set(slug, cur)
  }
  for (const [slug, { raw, count }] of claims) {
    const existing = bySlug.get(slug)
    if (existing) existing.claimCount = count
    else bySlug.set(slug, { slug, name: raw, kind: 'ransomware', hasMitre: false, claimCount: count })
  }

  // actors named in APT / campaign reporting (resolve ATT&CK by name OR alias).
  const actorAlias = aliasIndex(actors)
  const malwareAlias = aliasIndex(malware)
  for (const it of feed) {
    if (it.category !== 'apt' && it.category !== 'campaign') continue
    for (const raw of it.entities?.actors ?? []) {
      if (!raw) continue
      const slug = raw.toLowerCase()
      if (bySlug.has(slug)) continue
      const mitre = actorAlias.get(slug) ?? malwareAlias.get(slug)
      bySlug.set(slug, {
        slug,
        name: raw,
        kind: 'actor',
        hasMitre: Boolean(mitre),
        attack_id: mitre?.attack_id,
        aliases: mitre ? aliasesOf(mitre) : undefined,
      })
    }
  }

  return [...bySlug.values()]
}

/* ---------------- the fused profile --------------------------------------- */

export interface MitreFingerprint {
  kind: 'actor' | 'malware'
  name: string
  attack_id?: string
  attackUrl: string
  aliases: string[]
  description: string
  techniques: string[]
  software: string[]
}

/** One leak-site victim claim (or a rolled-up digest). Victim names are never
 *  republished — only the sector / country the source attributed. */
export interface RansomClaim {
  id: string
  title: string
  published_at?: string
  /** Raw source url (frequently a .onion claim link). Validate before render. */
  url: string
  /** Present on digest rows: how many claims were rolled up. */
  grouped?: number
  /** Parsed target sector for a single claim (digests roll up into `sectors`). */
  sector?: string
  /** Parsed target country for a single claim (digests DROP country). */
  country?: string
}

export interface RansomwareActivity {
  /** Total victim claims across the window (singles + digest tallies). */
  totalClaims: number
  /** Claim posts, newest first. */
  items: RansomClaim[]
  /** Distinct target sectors, sentinels ("Not Found") dropped. */
  sectors: string[]
  /** Distinct target countries — from SINGLE claims only (digests omit it), so
   *  this is honestly partial when digests are present. */
  countries: string[]
}

export interface Report {
  id: string
  /** Headline with the "[Outlet]" prefix stripped. */
  title: string
  /** Reporting outlet parsed from the "[Outlet]" prefix, else the source. */
  outlet: string
  published_at?: string
  url?: string
  /** The REAL ingested summary prose — never synthesised. */
  summary: string
}

export interface ProfileResult {
  slug: string
  /** Display name (canonical MITRE name when known, else the reported handle). */
  name: string
  fingerprint: MitreFingerprint | null
  ransomware: RansomwareActivity | null
  reporting: Report[]
  related: RelatedRow[]
}

const OUTLET_RE = /^\s*\[([^\]]+)\]\s*/

/** Sector labels the upstream emits as a non-value — dropped rather than shown
 *  as a junk chip (honest-empty a field over a bad parse). "Other" is KEPT: it
 *  is a real, if coarse, bucket the source chose, not a parse failure. */
const SECTOR_SENTINEL = /^(not found|unknown|n\/?a|none|undisclosed)$/i

function isRealSector(s: string): boolean {
  return s.length > 0 && !SECTOR_SENTINEL.test(s)
}

/**
 * Parse target sectors out of a ransomware.live summary.
 *   single : "Sector: Energy & Utilities — Country: IT. Claim detail…"
 *   digest : "Grouped: Agriculture and Food Production, Healthcare, Technology"
 * Sector names never contain a comma (the digest delimiter) and — in this feed —
 * never a dash, so the single form terminates safely on the "— Country:" pivot.
 *
 * Failure modes handled: a missing "Sector:"/"Grouped:" prefix → [] (no guess);
 * a sentinel value ("Not Found") → dropped; a summary that omits the "— Country:"
 * pivot → a period/end-of-string fallback so a malformed single still yields its
 * sector rather than swallowing the trailing prose.
 */
function parseSectors(summary: string, grouped: boolean): string[] {
  const text = summary ?? ''
  if (grouped) {
    const m = text.match(/Grouped:\s*(.+)$/i)
    if (!m) return []
    return m[1].split(',').map((x) => x.trim()).filter(isRealSector)
  }
  // Single: prefer the "— Country:" pivot; fall back to the first sentence.
  let m = text.match(/Sector:\s*(.+?)\s*[—–—-]\s*Country:/i)
  if (!m) m = text.match(/Sector:\s*([^.]+)/i)
  if (!m) return []
  const one = m[1].trim().replace(/[.\s]+$/, '').trim()
  return isRealSector(one) ? [one] : []
}

/** Parse the ISO-3166 country from a SINGLE claim summary ("Country: IT.").
 *  The literal "?" the source uses for unknown fails the `[A-Za-z]{2,3}` shape
 *  and is naturally excluded — no special-casing needed. */
function parseCountry(summary: string): string | undefined {
  const m = (summary ?? '').match(/Country:\s*([A-Za-z]{2,3})\b/)
  return m ? m[1].toUpperCase() : undefined
}

/** The MITRE fingerprint for a slug — actor catalog first, then software. Match
 *  on lowercased name OR alias. null when the slug has no ATT&CK profile at all
 *  (the ransomware-only / reporting-only case). */
function findFingerprint(
  slug: string,
  actors: Profile[],
  malware: Profile[],
): MitreFingerprint | null {
  const match = (profiles: Profile[]): Profile | undefined =>
    profiles.find(
      (p) =>
        Boolean(p?.name) &&
        (p.name.toLowerCase() === slug ||
          (p.aliases ?? []).some((a) => a?.toLowerCase() === slug)),
    )
  const actorHit = match(actors)
  const p = actorHit ?? match(malware)
  if (!p) return null
  const kind: 'actor' | 'malware' = actorHit ? 'actor' : 'malware'
  return {
    kind,
    name: p.name,
    attack_id: p.attack_id,
    attackUrl: attackUrl(kind, p.attack_id),
    // Drop the self-name ATT&CK often lists as its own first alias.
    aliases: (p.aliases ?? []).filter((a) => a && a.toLowerCase() !== p.name.toLowerCase()),
    description: cleanDescription(p.description),
    techniques: p.techniques ?? [],
    software: p.software ?? [],
  }
}

/** Leak-site activity for a slug, or null when the group posted no claims. */
function ransomwareActivity(slug: string, feed: FeedItem[]): RansomwareActivity | null {
  const matched = feed.filter(
    (it) => it.source === 'ransomwarelive' && it.entities?.actors?.[0]?.toLowerCase() === slug,
  )
  if (!matched.length) return null

  const sorted = [...matched].sort((a, b) =>
    String(b.published_at ?? '').localeCompare(String(a.published_at ?? '')),
  )
  let totalClaims = 0
  const items: RansomClaim[] = []
  const sectors = new Set<string>()
  const countries = new Set<string>()

  for (const it of sorted) {
    totalClaims += claimCount(it)
    const isGrouped = it.grouped != null
    for (const s of parseSectors(it.summary, isGrouped)) sectors.add(s)
    let sector: string | undefined
    let country: string | undefined
    if (!isGrouped) {
      sector = parseSectors(it.summary, false)[0]
      country = parseCountry(it.summary)
      if (country) countries.add(country)
    }
    items.push({
      id: it.id,
      title: it.title,
      published_at: it.published_at,
      url: it.url,
      grouped: it.grouped,
      sector,
      country,
    })
  }

  return { totalClaims, items, sectors: [...sectors], countries: [...countries] }
}

/** APT / campaign reporting that names the slug, newest first. */
function reportsFor(slug: string, feed: FeedItem[]): Report[] {
  const rows: Report[] = []
  for (const it of feed) {
    if (it.category !== 'apt' && it.category !== 'campaign') continue
    if (!(it.entities?.actors ?? []).some((a) => a?.toLowerCase() === slug)) continue
    const m = (it.title ?? '').match(OUTLET_RE)
    rows.push({
      id: it.id,
      title: (it.title ?? '').replace(OUTLET_RE, ''),
      outlet: m ? m[1] : it.source,
      published_at: it.published_at,
      url: it.url,
      summary: it.summary ?? '',
    })
  }
  rows.sort((a, b) => String(b.published_at ?? '').localeCompare(String(a.published_at ?? '')))
  return rows
}

/** The reported handle in its original casing (leak-site or reporting), for the
 *  display name when no MITRE canonical name exists. */
function rawNameFor(slug: string, feed: FeedItem[]): string | undefined {
  for (const it of feed) {
    for (const a of it.entities?.actors ?? []) {
      if (a && a.toLowerCase() === slug) return a
    }
  }
  return undefined
}

/**
 * Fuse the four snapshots for one slug. Every field degrades to a HONEST empty
 * on its own:
 *   • fingerprint null  → no ATT&CK profile on file
 *   • ransomware null   → no leak-site claims for this group
 *   • reporting []      → no APT/campaign article names this actor
 *   • related []        → no ATT&CK links / feed co-occurrences (ransomware-only
 *                         groups have no relations node, so this is empty — the
 *                         card states that rather than synthesising links).
 */
export function profileFor(
  slug: string,
  data: {
    actors: Profile[]
    malware: Profile[]
    feed: FeedItem[]
    relations: RelationsPayload | null
  },
): ProfileResult {
  const s = slug.trim().toLowerCase()
  if (!s) {
    return { slug: '', name: '', fingerprint: null, ransomware: null, reporting: [], related: [] }
  }

  const fingerprint = findFingerprint(s, data.actors, data.malware)
  const ransomware = ransomwareActivity(s, data.feed)
  const reporting = reportsFor(s, data.feed)

  const index = buildRelationsIndex(data.relations)
  const name = fingerprint?.name ?? rawNameFor(s, data.feed) ?? s
  // Query relations by the MITRE canonical name + aliases (so an alias-matched
  // actor like "Midnight Blizzard" resolves its APT29 node); a ransomware-only
  // name has no node → honest empty.
  const relNames = fingerprint ? [fingerprint.name, ...fingerprint.aliases] : [name]
  const related = relatedFor(index, relNames)

  return { slug: s, name, fingerprint, ransomware, reporting, related }
}
