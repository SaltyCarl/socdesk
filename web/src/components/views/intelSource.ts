// intelSource.ts — derives the ATTRIBUTING PUBLIC-DOMAIN SOURCE for a curated
// ransomware_intel.json seed entry from its advisory URL host, so the render
// layer never hardcodes a single publisher's name. Two sources are seeded
// today — CISA (#StopRansomware joint advisories) and HHS HC3 (Health Sector
// Cybersecurity Coordination Center threat profiles) — both US federal
// executive-agency products on the same 17 U.S.C. §105 public-domain footing
// (see schemas/ransomware_intel.schema.json's host gate). Pure, no I/O.

export interface IntelSource {
  /** Short org label for badges/links, e.g. "CISA seeded", "CISA advisory
   *  <id>". */
  org: string
  /** The org's own name for the document TYPE, for the attribution
   *  sentence, e.g. "the group's <product>". */
  product: string
}

const KNOWN_SOURCES: { host: string; source: IntelSource }[] = [
  { host: 'cisa.gov', source: { org: 'CISA', product: 'CISA #StopRansomware advisory' } },
  { host: 'hhs.gov', source: { org: 'HHS HC3', product: 'HHS HC3 threat profile' } },
]

/** A generic, honestly-worded fallback for a host the seed's own schema gate
 *  admits but this helper doesn't yet name — never fabricates an agency. */
const FALLBACK: IntelSource = { org: 'the source', product: 'the source advisory' }

/** The attributing source for a seed entry's `advisory.url` (or any URL from
 *  the same seed, e.g. `note_image`). Matches the host's registrable domain
 *  (a subdomain like `aspr.hhs.gov` or `www.cisa.gov` still resolves), never
 *  a substring — mirrors the schema's own host-anchoring discipline. */
export function intelSource(url?: string): IntelSource {
  let host = ''
  try {
    host = new URL(String(url ?? '')).hostname.toLowerCase()
  } catch {
    return FALLBACK
  }
  const hit = KNOWN_SOURCES.find((k) => host === k.host || host.endsWith(`.${k.host}`))
  return hit ? hit.source : FALLBACK
}

/* ---------------- vendor-reported Tier-3 depth (no gov advisory) -------- */
//
// A SEPARATE, lower trust tier from the public-domain seed above. These
// entries have NO `advisory` (that field stays gov-host-locked — see the
// schema) — instead they carry `sources[]` (unlocked host) pointing at a
// reputable vendor threat-report (Unit 42, SOCRadar, FortiGuard, Halcyon,
// Group-IB, Trend Micro, Check Point, Securelist, Huntress, Red Piranha,
// WatchGuard, …). Every field on a vendor entry is an ATOMIC FACT the cited
// report explicitly states (a CVE id, a tool name, an alias, a first-seen
// date) — never the vendor's own prose, ransom-note text, or curated TTP
// list reproduced wholesale (Feist: facts aren't copyrightable, a vendor's
// original expression and curated selection/arrangement are — see
// docs/research/vendor-sourcing-spike.md). The render MUST NOT reuse the
// gov advisory panel's language or treatment for these — `isVendorSourced`
// is the discriminator the render branches on.

/** True when a seed entry is the VENDOR tier: no public-domain advisory, but
 *  at least one cited source. Never true for a gov-seeded entry (which
 *  always carries `advisory`) and never true for an entry with neither
 *  (nothing to attribute — the intel panel doesn't render at all). */
export function isVendorSourced(intel: { advisory?: unknown; sources?: unknown[] }): boolean {
  return !intel.advisory && Array.isArray(intel.sources) && intel.sources.length > 0
}

/** Human-readable display name for a vendor `sources[].id`. Extend this map
 *  as new vendor reports are curated into the seed — never fabricates a name
 *  beyond what the cited report's own byline states; an id not yet mapped
 *  falls back to itself rather than guessing. */
const VENDOR_NAMES: Record<string, string> = {
  'group-ib': 'Group-IB',
  huntress: 'Huntress',
  fortiguard: 'FortiGuard',
  halcyon: 'Halcyon',
  'mitre-attack': 'MITRE ATT&CK',
  checkpoint: 'Check Point Research',
  securelist: 'Securelist (Kaspersky)',
  cybersecuritynews: 'Cybersecurity News',
  redpiranha: 'Red Piranha',
  watchguard: 'WatchGuard',
  unit42: 'Palo Alto Unit 42',
  socradar: 'SOCRadar',
  mandiant: 'Mandiant',
  talos: 'Cisco Talos',
  bitdefender: 'Bitdefender',
  trendmicro: 'Trend Micro',
  microsoft: 'Microsoft',
}

/** Display label for one vendor source id — the mapped name when known,
 *  else the raw id verbatim (honest-unknown, never invents a name). */
export function vendorLabel(id: string): string {
  return VENDOR_NAMES[id] ?? id
}
