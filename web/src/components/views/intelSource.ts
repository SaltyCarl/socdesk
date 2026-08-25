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
