// Test fixtures + builders. Not a test file itself.
import type { VerdictData, VerdictSource } from '../types';
import type { EnrichResponse, RawSource } from '../map';

/** Build a VerdictSource with sensible defaults; override any field. */
export function src(over: Partial<VerdictSource> = {}): VerdictSource {
  return {
    name: 'AbuseIPDB',
    verdict: 'benign',
    class: 'score',
    finding: 'no adverse findings',
    recency: null,
    url: 'https://example.test/verify',
    ...over,
  };
}

/** Build a VerdictData with defaults; sources/context/errors default empty. */
export function data(over: Partial<VerdictData> = {}): VerdictData {
  return {
    indicator: '185.220.101.42',
    type: 'ipv4',
    consulted: 0,
    flagged: 0,
    tone: 'grey',
    band: 'grey',
    sources: [],
    context: [],
    errors: [],
    partial: false,
    checkedAt: '2026-08-12T00:00:00.000Z',
    identityLed: false,
    ...over,
  };
}

/** A raw /api/enrich response for an IP (AbuseIPDB adverse + ipinfo context). */
export const RAW_IP: EnrichResponse = {
  indicator: '185.220.101.42',
  type: 'ipv4',
  checked_at: '2026-08-12T09:00:00.000Z',
  partial: false,
  errors: [{ source: 'urlscan', reason: 'not configured' }],
  sources: [
    {
      name: 'AbuseIPDB',
      verdict: 'malicious',
      headline: '98% abuse confidence · 1204 reports in 90 days',
      facts: [
        ['Abuse confidence', '98%'],
        ['Last reported', '2026-08-10'],
        ['Tor exit node', 'yes'],
      ],
      url: 'https://www.abuseipdb.com/check/185.220.101.42',
    },
    {
      name: 'GreyNoise',
      verdict: 'unknown',
      headline: 'Not observed scanning the internet — this is not a safety verdict',
      facts: [['Last seen', '—']],
      url: 'https://viz.greynoise.io/ip/185.220.101.42',
    },
    {
      name: 'ipinfo',
      verdict: 'unknown',
      kind: 'context',
      headline: 'Frankfurt, Germany · AS3209',
      facts: [
        ['ASN', 'AS3209'],
        ['Organisation', 'Vodafone'],
      ],
      url: 'https://ipinfo.io/185.220.101.42',
    } as RawSource,
  ],
};

/** A raw /api/enrich response for a hash (MalwareBazaar catalog + VT ratio). */
export const RAW_HASH: EnrichResponse = {
  indicator: 'a'.repeat(64),
  type: 'sha256',
  checked_at: '2026-08-12T09:00:00.000Z',
  partial: false,
  errors: [],
  sources: [
    {
      name: 'MalwareBazaar',
      verdict: 'malicious',
      headline: 'Known sample — family Cobalt Strike',
      facts: [
        ['Family', 'Cobalt Strike'],
        ['First seen', '2026-01-04'],
      ],
      url: 'https://bazaar.abuse.ch/sample/aaa/',
    },
    {
      name: 'VirusTotal',
      verdict: 'malicious',
      headline: '45/70 engines flag this as malicious',
      facts: [['Last analysed', '2026-08-01']],
      url: 'https://www.virustotal.com/gui/file/aaa',
    },
  ],
};
