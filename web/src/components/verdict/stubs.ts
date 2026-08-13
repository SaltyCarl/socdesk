// stubs.ts — self-contained sample VerdictData for the escalation-card system.
//
// The IP / domain / URL / hash cases are built as raw /api/enrich responses and
// run through the REAL `mapResponse` pipeline, so their tally, band, source
// classes and PUA flags are all doctrine-derived exactly as a live lookup would
// produce them (not hand-set). The CVE case is assembled directly because CVEs
// are authoritative single-source (spec §5) — not enriched through this client —
// and the reference needs the `kev` flag the enrich mapper does not carry.
//
// Findings/headlines are stored VERB-LESS (bare predicates) per the doctrine
// contract: the class verb — "catalogs" / "reports" / "classifies" / "confirms"
// — is supplied by doctrine.predicate()/phraseFinding(), so it prints exactly
// once, source-subject-first, wherever a source speaks.

import type { EnrichResponse } from '../../lib/verdict'
import type { VerdictData, VerdictSource } from '../../lib/verdict'
import { consensus, deriveBand, isIdentityType, mapResponse } from '../../lib/verdict'

const CHECKED_AT = '2026-08-12T14:22:00.000Z'

/* ---------- IP — geo hero ------------------------------------------------ */

const RAW_IP: EnrichResponse = {
  indicator: '185.220.101.42',
  type: 'ipv4',
  checked_at: CHECKED_AT,
  partial: true,
  errors: [{ source: 'urlscan', reason: 'not applicable to an IP' }],
  sources: [
    {
      name: 'AbuseIPDB',
      verdict: 'malicious',
      headline: '98% abuse confidence · 1,204 reports in 90 days',
      facts: [
        ['Abuse confidence', '98%'],
        ['Reports', '1,204'],
        ['Last reported', '2026-08-10'],
        ['Tor exit node', 'yes'],
      ],
      url: 'https://www.abuseipdb.com/check/185.220.101.42',
    },
    {
      name: 'GreyNoise',
      verdict: 'malicious',
      headline: 'malicious · observed scanning · tagged Tor exit',
      facts: [['Last seen', '2026-08-11']],
      url: 'https://viz.greynoise.io/ip/185.220.101.42',
    },
    {
      name: 'MalwareBazaar',
      verdict: 'malicious',
      headline: '3 samples · family Cobalt Strike',
      facts: [
        ['Samples', '3'],
        ['Family', 'Cobalt Strike'],
      ],
      url: 'https://bazaar.abuse.ch/browse.php?search=185.220.101.42',
    },
    {
      name: 'ThreatFox',
      verdict: 'malicious',
      headline: '2 IOCs · threat type botnet C2',
      facts: [['IOCs', '2']],
      url: 'https://threatfox.abuse.ch/browse.php?search=ioc%3A185.220.101.42',
    },
    {
      name: 'VirusTotal',
      verdict: 'suspicious',
      headline: '12 / 94 engines flag this indicator',
      facts: [
        ['Detections', '12/94'],
        ['Last analysed', '2026-08-09'],
      ],
      url: 'https://www.virustotal.com/gui/ip-address/185.220.101.42',
    },
    {
      name: 'Spamhaus',
      verdict: 'benign',
      headline: 'no current listing on any blocklist',
      facts: [['Listed', 'no']],
      url: 'https://check.spamhaus.org/',
    },
    {
      name: 'ipinfo',
      verdict: 'unknown',
      kind: 'context',
      headline: 'Frankfurt, Germany · AS3209 (Vodafone)',
      facts: [
        ['Country', 'DE'],
        ['City', 'Frankfurt'],
        ['ASN', 'AS3209'],
        ['Organisation', 'Vodafone'],
        ['Coordinates', '50.11, 8.68'],
      ],
      url: 'https://ipinfo.io/185.220.101.42',
    },
  ],
}

/* ---------- domain — registration-age hero ------------------------------- */

const RAW_DOMAIN: EnrichResponse = {
  indicator: 'secure-account-verify.com',
  type: 'domain',
  checked_at: CHECKED_AT,
  partial: false,
  errors: [],
  sources: [
    {
      name: 'urlscan',
      verdict: 'suspicious',
      headline: 'a credential-harvesting page imitating a bank login',
      facts: [
        ['Page title', 'Account Security Verification'],
        ['Last scanned', '2026-08-11'],
      ],
      url: 'https://urlscan.io/search/#secure-account-verify.com',
    },
    {
      name: 'VirusTotal',
      verdict: 'suspicious',
      headline: '4 / 92 engines flag this domain',
      facts: [['Detections', '4/92']],
      url: 'https://www.virustotal.com/gui/domain/secure-account-verify.com',
    },
    {
      name: 'GreyNoise',
      verdict: 'unknown',
      headline: 'no scanning activity on record',
      facts: [['Last seen', '—']],
      url: 'https://viz.greynoise.io/',
    },
    {
      name: 'WHOIS',
      verdict: 'unknown',
      kind: 'context',
      headline: 'registered 5 days ago via NameSilo',
      facts: [
        ['Registered', '2026-08-07'],
        ['Registrar', 'NameSilo, LLC'],
        ['Age', '5 days'],
      ],
      url: 'https://whois.domaintools.com/secure-account-verify.com',
    },
    {
      name: 'ipinfo',
      verdict: 'unknown',
      kind: 'context',
      headline: 'resolves to Ashburn, United States · AS14618 (Amazon)',
      facts: [
        ['Country', 'US'],
        ['City', 'Ashburn'],
        ['ASN', 'AS14618'],
        ['Organisation', 'Amazon'],
      ],
      url: 'https://ipinfo.io/',
    },
  ],
}

/* ---------- URL — scanned-page hero -------------------------------------- */

const RAW_URL: EnrichResponse = {
  indicator: 'https://login-microsoftonline.support-verify.com/auth',
  type: 'url',
  checked_at: CHECKED_AT,
  partial: false,
  errors: [],
  sources: [
    {
      name: 'urlscan',
      verdict: 'malicious',
      headline: 'a phishing page targeting Microsoft 365',
      facts: [
        ['Final URL', 'https://login-microsoftonline.support-verify.com/auth'],
        ['Page title', 'Sign in to your Microsoft account'],
        ['Verdict', 'phishing'],
        ['Scanned', '2026-08-12'],
      ],
      url: 'https://urlscan.io/',
    },
    {
      name: 'VirusTotal',
      verdict: 'suspicious',
      headline: '7 / 94 engines flag this URL',
      facts: [['Detections', '7/94']],
      url: 'https://www.virustotal.com/gui/url',
    },
  ],
}

/* ---------- hash — malware-identity hero (confirmed malware) -------------- */

const RAW_HASH: EnrichResponse = {
  indicator: '7f9c2a4e1b8d3c6f0a5e2d9b4c7a1f8e6d3b0c9a2e5f8d1b4c7a0e3f6d9b2c5a8',
  type: 'sha256',
  checked_at: CHECKED_AT,
  partial: false,
  errors: [],
  sources: [
    {
      name: 'MalwareBazaar',
      verdict: 'malicious',
      headline: 'a known Cobalt Strike sample · delivery: email attachment',
      facts: [
        ['Family', 'Cobalt Strike'],
        ['File type', 'PE · EXE'],
        ['Size', '248 KB'],
        ['Signed', 'No'],
        ['First seen', '2024-03-12'],
        ['Last seen', '2026-08-09'],
        ['Submissions', '4,214'],
        ['Sources', '380'],
        ['Delivery', 'email attachment'],
        ['Seen as', 'invoice_2026.exe · svchost32.exe · update.dll'],
      ],
      url: 'https://bazaar.abuse.ch/sample/7f9c2a4e/',
    },
    {
      name: 'VirusTotal',
      verdict: 'malicious',
      headline: '58 of 72 engines flag this file',
      facts: [
        ['Detections', '58/72'],
        ['Last analysed', '2026-08-01'],
      ],
      url: 'https://www.virustotal.com/gui/file/7f9c2a4e',
    },
    {
      name: 'ThreatFox',
      verdict: 'malicious',
      headline: 'known command-and-control infrastructure',
      facts: [
        ['Threat type', 'botnet C2'],
        ['IOCs', '2'],
      ],
      url: 'https://threatfox.abuse.ch/browse.php?search=hash',
    },
    {
      name: 'Hybrid Analysis',
      verdict: 'malicious',
      headline: 'process injection and network beaconing at runtime',
      facts: [['Last analysed', '2026-07-30']],
      url: 'https://www.hybrid-analysis.com/',
    },
  ],
}

/* ---------- hash — grayware / PUA honesty state --------------------------- */

const RAW_HASH_PUA: EnrichResponse = {
  indicator: 'c1a2b3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90',
  type: 'sha256',
  checked_at: CHECKED_AT,
  partial: false,
  errors: [],
  sources: [
    {
      name: 'VirusTotal',
      verdict: 'suspicious',
      headline: '22 of 71 engines flag this — potentially-unwanted (bundleware), mostly PUA labels',
      facts: [
        ['Family', 'DriverBooster'],
        ['File type', 'PE · EXE'],
        ['Size', '6.4 MB'],
        ['Signed', 'Yes (IObit)'],
        ['First seen', '2025-11-02'],
        ['Last seen', '2026-08-05'],
        ['Submissions', '1,180'],
        ['Detections', '22/71'],
      ],
      url: 'https://www.virustotal.com/gui/file/c1a2b3d4',
      tags: ['pua', 'bundleware', 'adware'],
    },
  ],
}

/* ---------- CVE — exploitation-status banner (assembled directly) -------- */

function assemble(
  indicator: string,
  type: VerdictData['type'],
  sources: VerdictSource[],
  errors: VerdictData['errors'] = [],
): VerdictData {
  const { consulted, flagged, tone } = consensus(sources)
  return {
    indicator,
    type,
    consulted,
    flagged,
    tone,
    band: deriveBand(sources),
    sources,
    context: [],
    errors,
    partial: errors.length > 0,
    checkedAt: CHECKED_AT,
    identityLed: isIdentityType(type),
  }
}

const CVE_DATA: VerdictData = assemble('CVE-2026-31801', 'cve', [
  {
    name: 'CISA KEV',
    verdict: 'malicious',
    class: 'catalog',
    kev: true,
    finding: 'listing in the Known Exploited Vulnerabilities catalog; exploitation observed in the wild',
    recency: '2026-07-15',
    url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    facts: [
      ['CVSS', '9.8'],
      ['Severity', 'Critical'],
      ['EPSS', '0.94'],
      ['Vendor', 'Ivanti'],
      ['Product', 'Connect Secure'],
      ['Added', '2026-07-15'],
      ['Action due', '2026-08-05'],
    ],
  },
  {
    name: 'NVD',
    verdict: 'suspicious',
    class: 'score',
    finding: '9.8 (Critical) — unauthenticated remote code execution',
    recency: '2026-07-10',
    url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-31801',
    facts: [
      ['CVSS', '9.8'],
      ['Vector', 'network · low complexity · no privileges'],
    ],
  },
])

/* ---------- the selectable registry the Lookup route renders ------------- */

export interface Stub {
  id: string
  label: string
  hint: string
  data: VerdictData
}

export const STUBS: Stub[] = [
  { id: 'ip', label: 'IP', hint: 'geo hero', data: mapResponse(RAW_IP) },
  { id: 'domain', label: 'Domain', hint: 'registration-age', data: mapResponse(RAW_DOMAIN) },
  { id: 'url', label: 'URL', hint: 'scanned page', data: mapResponse(RAW_URL) },
  { id: 'hash', label: 'Hash', hint: 'malware identity', data: mapResponse(RAW_HASH) },
  { id: 'hash-pua', label: 'Hash · PUA', hint: 'grayware state', data: mapResponse(RAW_HASH_PUA) },
  { id: 'cve', label: 'CVE', hint: 'exploitation banner', data: CVE_DATA },
]
