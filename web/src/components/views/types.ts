// types.ts — the shape of the collected-state payloads the data views consume.
//
// Ported verbatim from the live pipeline's /data/state/*.json (see
// site/js/views.js + data.js). These are DATA-VIEW types only — the live
// indicator/verdict model lives in src/lib/verdict and is not touched here.
// Every field is optional-tolerant: the views must survive a partial or
// not-yet-published payload without throwing (honest empties, never a blank
// screen).

/* ---------------- feed (the work queue) ---------------- */

export interface FeedEntities {
  actors?: string[]
  malware?: string[]
  vendors?: string[]
  cves?: string[]
}

/** One collected report. `score` is the pipeline's 0–100 relevance rank and
 *  `why` is its human-readable explanation — the two fields that make the
 *  queue explainable rather than a black box. */
export interface FeedItem {
  id: string
  source: string
  category: string
  title: string
  summary: string
  url: string
  severity?: string
  entities?: FeedEntities
  iocs?: string[]
  published_at?: string
  collected_at?: string
  score?: number | null
  why?: string[]
  /** present on digest rows: how many reports were rolled up */
  grouped?: number
}

export interface FeedPayload {
  generated_at?: string
  schema_version?: number
  items: FeedItem[]
}

/* ---------------- vulnerabilities (KEV / CVSS / EPSS) ---------------- */

export interface Cve {
  cve: string
  title?: string
  cvss?: number | null
  cvss_severity?: string | null
  epss?: number | null
  epss_percentile?: number | null
  kev?: boolean
  kev_date_added?: string
  /** CISA-set federal remediation deadline (YYYY-MM-DD); '' when none. */
  kev_due_date?: string
  /** CISA's prescribed remediation, verbatim; '' when none. */
  kev_required_action?: string
  kev_ransomware?: boolean
  vendors?: string[]
  products?: string[]
  published_at?: string
  last_modified?: string
}

export interface CvePayload {
  generated_at?: string
  schema_version?: number
  cves: Cve[]
}

/* ---------------- actors & malware (ATT&CK profiles) ---------------- */

export interface Profile {
  name: string
  attack_id?: string
  aliases?: string[]
  description?: string
  techniques?: string[]
  software?: string[]
}

export interface ProfilePayload {
  generated_at?: string
  schema_version?: number
  profiles: Profile[]
}

/** A profile with the origin catalog stamped on, so one merged grid can carry
 *  both actors and malware without losing which is which. */
export type ProfileKind = 'actor' | 'malware'
export interface KindedProfile extends Profile {
  kind: ProfileKind
}

/* ---------------- relations (the ranked RELATED block) ---------------- */

export type RelNodeType =
  | 'actor'
  | 'malware'
  | 'cve'
  | 'product'
  | 'technique'
  | 'vendor'

export interface RelNode {
  id: string
  type: RelNodeType | string
  name: string
  degree?: number
  kev?: boolean
}

/** evidence[0] === 'attack' → ATT&CK structure; 'cve-db' → CVE database;
 *  anything else → live feed-item ids (each entry is one feed report). */
export type Evidence = string[]

export interface RelEdge {
  type: string
  src: string
  dst: string
  weight: number
  evidence: Evidence
}

export interface RelationsPayload {
  generated_at?: string
  schema_version?: number
  nodes: RelNode[]
  edges: RelEdge[]
}

/* ---------------- trends (the since-yesterday deltas) ---------------- */

/** Day-over-day totals for the two headline counters. Deltas are signed
 *  (yesterday → today); `compared_to` is the ISO date the deltas measure from. */
export interface TrendsTotals {
  feed_count?: number
  feed_delta?: number
  kev_count?: number
  kev_delta?: number
  compared_to?: string
}

/** One CVE that entered CISA KEV in the compared window. `ransomware` is
 *  optional — the trends snapshot may not carry the flag (it lives in cves.json),
 *  so consumers must tolerate its absence. */
export interface NewKevEntry {
  cve: string
  added?: string
  epss?: number | null
  product?: string
  ransomware?: boolean
}

/** One CVE whose EPSS exploitation probability climbed materially in the trends
 *  window (produced by pipeline/history.py `build_trends`). The producer emits
 *  the snapshot endpoints `from`/`to`, the signed `delta`, and a `kev` flag.
 *  Every field beyond `cve` is optional: a snapshot may lack an endpoint, so the
 *  view degrades to the single current value rather than fabricate a shift. */
export interface EpssMover {
  cve: string
  product?: string
  from?: number | null
  to?: number | null
  delta?: number | null
  kev?: boolean
}

/** One day's collected-report count for the 7-day volume sparkline. */
export interface VolumePoint {
  date: string
  count: number
}

export interface TrendsPayload {
  generated_at?: string
  schema_version?: number
  totals?: TrendsTotals
  new_kev?: NewKevEntry[]
  epss_movers?: EpssMover[]
  volume?: VolumePoint[]
}

/* ---------------- health (collection status) ---------------- */

export interface HealthSource {
  source: string
  ok: boolean
  error?: string
  items: number
  last_success_at?: string
}

export interface HealthPayload {
  generated_at?: string
  schema_version?: number
  sources: HealthSource[]
  pipeline_warnings?: string[]
}

/* ---------------- sources (the registry) ---------------- */

export interface RegistrySource {
  name: string
  kind: string
  slug?: string
  url?: string
  coverage?: string
  enabled?: boolean
}

export interface RegistryPayload {
  generated_at?: string
  schema_version?: number
  sources: RegistrySource[]
}

/* ---------------- networks (ASN abuse leaderboard) ---------------- */

/** One network (ASN) row. Reported/blocklisted abuse volume hosted on the
 *  network — NOT a verdict on the operator. `report_count` (distinct
 *  report-bearing IPs) is always <= `ip_count`; `sources` distinguishes a
 *  community allegation from an abuse.ch published blocklist entry. */
export interface AsnNetwork {
  asn?: string
  isp?: string
  country?: string
  ip_count?: number
  report_count?: number
  categories?: string[]
  sources?: string[]
  examples?: string[]
}

export interface AsnLeaderboardPayload {
  generated_at?: string
  schema_version?: number
  attribution?: string
  count?: number
  total_abusive_ips?: number
  unattributed_ips?: number
  cap?: number
  truncated?: boolean
  networks: AsnNetwork[]
}
