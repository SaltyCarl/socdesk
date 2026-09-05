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
  /** Attributed leak-site victim name on a ransomware claim item — already
   *  clean_text'd at collection (Task 1). Inert text: NEVER render via
   *  dangerouslySetInnerHTML. Absent on digest / non-claim items. */
  victim?: string
  /** Bare hostname for the claimed victim's domain — hostname-guarded at
   *  collection (Task 1). Inert text, same render rule as `victim`. */
  domain?: string
  /** On a grouped digest row ONLY: the individual victims the digest
   *  collapsed, newest-first, capped at 100 — carried through so the Desk
   *  feed can stay a single noise-reduced row while the profile still
   *  expands every claimed victim. Same inert-text render rule as
   *  `victim`/`domain`. Absent on non-digest items. */
  claims?: { victim: string; domain?: string; date?: string; url?: string }[]
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
  /** CISA-set remediation due date (YYYY-MM-DD); absent when none. */
  kev_due_date?: string
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

/** ATT&CK technique id → human name (technique_names.json). A separate catalog
 *  so the per-actor `techniques` list stays id-only (the relations pipeline
 *  consumes it as strings); the frontend joins names for display. */
export interface TechniqueNamesPayload {
  generated_at?: string
  schema_version?: number
  names: Record<string, string>
}

/** Publish-time KEV/EPSS/CVSS join for a seed group's initial-access CVEs
 *  (ransomware_intel.json `cve_context`) — so the profile page can
 *  priority-order its CVE chips without loading the ~10 MB catalog. Fields
 *  are OMITTED when unknown, never null/false noise. */
export interface CveContext {
  kev?: boolean
  kev_ransomware?: boolean
  epss?: number
  cvss?: number
  kev_due_date?: string
}

/** ATT&CK technique id → tactic slugs, plus the matrix's OWN kill-chain
 *  order + display names (technique_tactics.json). The order ships from the
 *  bundle because the tactic vocabulary drifts — never hardcode it. */
export interface TechniqueTacticsPayload {
  generated_at?: string
  schema_version?: number
  tactics: Record<string, string[]>
  order: { slug: string; name: string }[]
}

/** One validated hunting query (hunt_packs.json). kql is the verbatim
 *  upstream/authored query; source carries the license trail. */
export interface HuntRule {
  id: string
  title: string
  kql: string
  techniques: string[]
  tables?: string[]
  dialect: 'advanced_hunting' | 'log_analytics'
  tested?: string
  source: {
    kind: 'sentinel' | 'sigma' | 'socdesk'
    url: string
    license: string
    author?: string
    rule_id?: string
    modified?: string
  }
}

export interface HuntPacksPayload {
  generated_at?: string
  schema_version?: number
  collected_at?: string
  allowlist_sha1?: string
  rules: HuntRule[]
}

/** One step of an enrichment Hunt Playbook (playbooks.json). `param` is the
 *  placeholder family the step's `{{param}}` token injects (ip/upn/...); `kind`
 *  is pivot (the general IOC search) or scenario (the alert-specific hunt). */
export interface PlaybookStep {
  id: string
  title: string
  kind: 'pivot' | 'scenario'
  param: string
  dialect: string
  tables?: string[]
  kql: string
}

/** One alert->KQL playbook: pick the alert that triggered the lookup, get an
 *  ordered set of IOC-parameterized steps. Sourced from data/hunt/playbooks. */
export interface Playbook {
  id: string
  title: string
  alert_sources?: string[]
  ioc_types: string[]
  techniques: string[]
  tested?: string
  source: { kind: string; url: string; license: string; author?: string }
  steps: PlaybookStep[]
}

export interface PlaybooksPayload {
  generated_at: string
  schema_version: number
  playbooks: Playbook[]
}

/** A cross-source cluster: one story covered by ≥2 distinct outlets (stories.json,
 *  OPEN-WORK §3). `delta` is present on CVE stories with catalog data. */
export interface StoryDelta {
  kev?: boolean
  kev_ransomware?: boolean
  epss?: number
  epss_from?: number
  epss_to?: number
}

export interface Story {
  key: string
  entity: string
  entity_type: 'cve' | 'actor' | 'malware'
  title: string
  outlets: string[]
  member_ids: string[]
  member_count: number
  published_at: string
  severity?: string
  delta?: StoryDelta
}

export interface StoriesPayload {
  generated_at: string
  schema_version: number
  stories: Story[]
}

/** Bare ransomware-group names from ransomware.live /v2/groups
 *  (ransomware_groups.json) — the name-only directory coverage layer.
 *  Names only by design (R3): no editorial rides along. */
export interface RansomwareGroupsPayload {
  generated_at?: string
  schema_version?: number
  names: string[]
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

/* ---------------- ransomware intel (curated public-domain seed) -------- */

/** One curated group entry, in ONE of two provenance tiers (see
 *  `isVendorSourced` in intelSource.ts — the discriminator is whether
 *  `advisory` is present):
 *  - GOV tier: sourced from a public-domain US federal advisory — a CISA
 *    #StopRansomware joint advisory or an HHS HC3 threat profile (see
 *    `intelSource`, which derives the attributing org from `advisory.url`'s
 *    host). Carries `advisory` (+ optionally `note_image`, gov-host-locked).
 *  - VENDOR tier: no `advisory` at all — instead `sources[]` cites one or
 *    more reputable vendor threat-reports (Unit 42, SOCRadar, FortiGuard,
 *    Halcyon, Group-IB, …; `sources[].url` is NOT host-locked). Every field
 *    is an atomic fact the cited report explicitly states, never the
 *    vendor's own prose or curated list reproduced wholesale — see
 *    docs/research/vendor-sourcing-spike.md. Never carries `note_image`
 *    (vendor figures aren't public domain).
 *  Fields are optional in TS since a seed entry may honestly omit a field
 *  the source document never covered (honest-empty over a fabricated
 *  value). */
export interface RansomIntel {
  slug: string
  name: string
  aliases?: string[]
  /** Match-only lowercase leak-site / name-only slug variants that are the SAME
   *  operation as this seed (LockBit's CISA advisory is keyed `lockbit`, but the
   *  active leak-site slug is `lockbit5`). Resolves the intel panel + seeded
   *  badge for a variant slug WITHOUT rendering as display aliases. */
  slug_aliases?: string[]
  first_seen?: string
  raas?: boolean
  initial_access_cves?: string[]
  advisory?: { id: string; url: string }
  tools?: string[]
  ransom_note?: string[]
  extensions?: string[]
  /** ISO `YYYY-MM-DD` the source advisory/profile was published — honestly
   *  absent when the seed entry has no advisory date on file. */
  advisory_date?: string
  /** ISO `YYYY-MM-DD` this seed entry was last reviewed for accuracy. */
  last_reviewed?: string
  /** A cisa.gov or hhs.gov URL (schema-gated — see
   *  ransomware_intel.schema.json) for the advisory's figure/note image —
   *  only 2 seeded groups (alphv, rhysida) carry this; absent for everyone
   *  else. */
  note_image?: string
  /** Named provenance for the seed entry's claims (advisory sections, vendor
   *  writeups, …) — honestly empty when the seed carries none. */
  sources?: { id: string; url: string }[]
}

export interface RansomIntelPayload {
  generated_at?: string
  schema_version?: number
  groups?: RansomIntel[]
  /** Publish-time KEV/EPSS join for the seed's initial-access CVEs. */
  cve_context?: Record<string, CveContext>
}

/* ---------------- claimed victims (attributed leak-site facts) ------------ */

/** One attributed leak-site victim claim, mapped from a `ransomwarelive`
 *  FeedItem for a single actor slug. `victim`/`domain` are already sanitized
 *  inert text at collection (Task 1) — never rendered via
 *  dangerouslySetInnerHTML. This is a REPUBLISHED, UNVERIFIED leak-site claim
 *  (honesty doctrine): SOCDesk states the attribution, never a verdict. */
export interface ClaimedVictim {
  id: string
  victim: string
  domain?: string
  sector?: string
  country?: string
  date?: string
  claimUrl: string
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
