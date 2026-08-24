// lookupModel.ts — the pure glue for the live /lookup surface.
//
// Two side-effect-free helpers, kept out of Lookup.tsx so the route file exports
// only its component (clean react-refresh):
//   * parseQ          — pure parse of a hash string into the decoded `#q=` value
//                       (unit-tested; readLookupQuery is the window wrapper).
//   * readLookupQuery — decode the `#q=` deep link the omnibox + palette write.
//   * cveToVerdict    — resolve a catalog CVE row into the shared VerdictData the
//                       escalation-card system renders.
//
// A CVE is NOT enrichable via /api/enrich (it is authoritative single-source,
// spec §5 — not a cross-source vote), so it is assembled here from the committed
// KEV/CVSS/EPSS snapshot (cves.json) into the SAME VerdictData shape the CVE stub
// uses, so EscalationCard renders its exploitation-status hero identically.

import type { FactRow, SourceVerdict, VerdictData, VerdictSource } from '@socdesk/shared/verdict'
import { consensus, deriveBand, isIdentityType } from '@socdesk/shared/verdict'
import type { Cve } from '../components/views/types'

/** Pure parse of a location-hash string into the decoded `#q=<indicator>`
 *  value; '' when absent or malformed. Extracted from readLookupQuery so it is
 *  unit-testable in the repo's node-env vitest (no `window`). Mirror of the
 *  writer in palette/commands.ts::lookupHash. */
export function parseQ(hash: string): string {
  const h = hash.replace(/^#/, '')
  const m = h.match(/(?:^|&)q=([^&]*)/)
  if (!m) return ''
  try {
    return decodeURIComponent(m[1]).trim()
  } catch {
    return m[1].trim()
  }
}

/** Read the decoded `#q=<indicator>` from the current location hash; '' when
 *  absent. Mirror of the writer in palette/commands.ts::lookupHash. */
export function readLookupQuery(): string {
  return parseQ(window.location.hash)
}

const SEVERITY_LABEL: Record<string, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  none: 'None',
}

/** Normalise the catalog's shouty severity enum (CRITICAL) to the card's
 *  title-case register (Critical). Unknown values pass through verbatim. */
function severityLabel(s?: string | null): string {
  const raw = String(s ?? '').trim()
  return SEVERITY_LABEL[raw.toLowerCase()] ?? raw
}

/** ISO datetime → bare YYYY-MM-DD (the recency tag + staleness check want a
 *  date, not a millisecond timestamp). '' → null (absence, not staleness). */
function isoDate(s?: string | null): string | null {
  const d = String(s ?? '').slice(0, 10)
  return /^\d{4}-\d{2}-\d{2}$/.test(d) ? d : null
}

/**
 * Assemble one catalog CVE row into the shared VerdictData. Mirrors the CVE
 * STUB: a CISA KEV catalog source (present only when actually KEV-listed, so the
 * `kev` banner never lies) plus an NVD authoritative source carrying CVSS/EPSS/vendor.
 * `snapshotAt` stamps the card's "sources queried" line with the snapshot time —
 * honest that this is committed catalog data, not a live query.
 */
export function cveToVerdict(cve: Cve, snapshotAt?: string): VerdictData {
  const sev = severityLabel(cve.cvss_severity)
  const cvssNum = typeof cve.cvss === 'number' ? cve.cvss : NaN

  const scoreFacts: FactRow[] = []
  if (cve.cvss != null) scoreFacts.push(['CVSS', String(cve.cvss)])
  if (sev) scoreFacts.push(['Severity', sev])
  if (cve.epss != null) scoreFacts.push(['EPSS', String(cve.epss)])
  if (cve.vendors?.[0]) scoreFacts.push(['Vendor', cve.vendors[0]])
  if (cve.products?.[0]) scoreFacts.push(['Product', cve.products[0]])

  const scoreFinding =
    cve.cvss != null
      ? `CVSS ${cve.cvss} base score${sev ? ` (${sev})` : ''}`
      : 'a scored vulnerability'
  const scoreVerdict: SourceVerdict = cvssNum >= 7 ? 'suspicious' : 'unknown'

  const sources: VerdictSource[] = []

  if (cve.kev) {
    // "Overdue" is decided HERE (deterministically, against the snapshot date —
    // the honest as-of reference), never in the card: the past-due remediation
    // deadline is a CISA fact, so it travels as an attributed row + a clause on
    // CISA's own finding, and the card only renders what it is handed.
    const due = isoDate(cve.kev_due_date)
    const ref = isoDate(snapshotAt)
    const overdue = due != null && ref != null && due < ref

    const kevFacts: FactRow[] = []
    if (cve.kev_date_added) kevFacts.push(['Added', cve.kev_date_added])
    if (due) kevFacts.push(['Remediation due', due])
    if (overdue) kevFacts.push(['Status', 'Overdue'])
    if (cve.kev_required_action) kevFacts.push(['Required action', cve.kev_required_action])

    sources.push({
      name: 'CISA KEV',
      verdict: 'malicious',
      class: 'catalog',
      kev: true,
      finding:
        'listing in the Known Exploited Vulnerabilities catalog; exploitation observed in the wild' +
        (cve.kev_ransomware ? '; known use in ransomware campaigns' : '') +
        (overdue ? `; past the CISA remediation due date of ${due}` : ''),
      recency: isoDate(cve.kev_date_added),
      url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
      facts: kevFacts.length ? kevFacts : undefined,
    })
  }

  sources.push({
    name: 'NVD',
    verdict: scoreVerdict,
    class: 'authoritative',
    finding: scoreFinding,
    recency: isoDate(cve.last_modified ?? cve.published_at),
    url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.cve)}`,
    facts: scoreFacts.length ? scoreFacts : undefined,
  })

  const { consulted, flagged, tone } = consensus(sources)

  return {
    indicator: cve.cve,
    type: 'cve',
    consulted,
    flagged,
    tone,
    band: deriveBand(sources),
    sources,
    context: [],
    errors: [],
    partial: false,
    checkedAt: snapshotAt ?? '',
    identityLed: isIdentityType('cve'),
  }
}
