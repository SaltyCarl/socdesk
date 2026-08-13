// live-headline.test.ts — locks the Phase-2 dogfood finding.
//
// These are REAL /api/enrich responses captured from https://socdesk.io on
// 2026-08-13 (ipv4 8.8.8.8, domain google.com, sha256 EICAR). The live server
// emits verb-FUL VirusTotal headlines — "N/91 engines flag this AS MALICIOUS" —
// which, prefixed by the doctrine's score-class verb ("reports"), previously
// rendered the doubled, verdict-restating "VirusTotal reports N/91 engines flag
// this as malicious". map.ts normalizeFinding() rewrites the "flag this as
// <verdict>" clause to a bare "flagged this" so the class verb applies exactly
// once. This test pins that so a future doctrine/map change can't regress it.

import { describe, expect, it } from 'vitest';
import { mapResponse, type EnrichResponse } from '../map';
import { phraseFinding, predicate } from '../doctrine';

/* ---- captured live responses (trimmed to the asserted sources) ---------- */

const LIVE_IP: EnrichResponse = {
  indicator: '8.8.8.8',
  type: 'ipv4',
  checked_at: '2026-08-13T12:41:13.449Z',
  sources: [
    {
      name: 'AbuseIPDB',
      verdict: 'benign',
      headline: '0% abuse confidence · 192 reports in 90 days',
      url: 'https://www.abuseipdb.com/check/8.8.8.8',
    },
    {
      name: 'VirusTotal',
      verdict: 'benign',
      headline: '0/91 engines flag this as malicious',
      url: 'https://www.virustotal.com/gui/ip-address/8.8.8.8',
    },
  ],
  partial: false,
  errors: [],
};

const LIVE_DOMAIN: EnrichResponse = {
  indicator: 'google.com',
  type: 'domain',
  checked_at: '2026-08-13T12:41:30.516Z',
  sources: [
    {
      name: 'VirusTotal',
      verdict: 'suspicious',
      headline: '1/91 engines flag this as malicious',
      url: 'https://www.virustotal.com/gui/domain/google.com',
    },
  ],
  partial: false,
  errors: [],
};

const LIVE_HASH: EnrichResponse = {
  indicator: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
  type: 'sha256',
  checked_at: '2026-08-13T12:41:33.102Z',
  sources: [
    {
      name: 'VirusTotal',
      verdict: 'malicious',
      headline: '64/66 engines flag this as malicious',
      url: 'https://www.virustotal.com/gui/file/x',
    },
  ],
  partial: false,
  errors: [],
};

describe('live-headline normalization (Phase-2 dogfood)', () => {
  it('strips the VirusTotal verdict-word tail into the verb-less contract', () => {
    const d = mapResponse(LIVE_DOMAIN);
    const vt = d.sources.find((s) => s.name === 'VirusTotal')!;
    // verdict word gone from the prose; it survives only as s.verdict.
    expect(vt.finding).toBe('1/91 engines flagged this');
    expect(vt.verdict).toBe('suspicious');
    expect(vt.finding).not.toMatch(/as malicious/i);
  });

  it('applies the class verb exactly once — no doubled / verdict-restating verb', () => {
    for (const body of [LIVE_IP, LIVE_DOMAIN, LIVE_HASH]) {
      const vt = mapResponse(body).sources.find((s) => s.name === 'VirusTotal')!;
      const line = phraseFinding(vt);
      // BEFORE the fix this was e.g. "VirusTotal reports 1/91 engines flag this
      // as malicious" — the doubled "reports … flag … as malicious".
      expect(line).not.toMatch(/reports .*flag this as malicious/i);
      // exactly one class verb ("reports"), then the bare predicate.
      expect(line).toMatch(/^VirusTotal reports \d+\/\d+ engines flagged this$/);
    }
  });

  it('renders the exact before/after phrasing for the domain case', () => {
    const vt = mapResponse(LIVE_DOMAIN).sources.find((s) => s.name === 'VirusTotal')!;
    expect(predicate(vt)).toBe('reports 1/91 engines flagged this');
    expect(phraseFinding(vt)).toBe('VirusTotal reports 1/91 engines flagged this');
  });

  it('leaves already verb-less live headlines (AbuseIPDB) untouched', () => {
    const abuse = mapResponse(LIVE_IP).sources.find((s) => s.name === 'AbuseIPDB')!;
    expect(abuse.finding).toBe('0% abuse confidence · 192 reports in 90 days');
    expect(phraseFinding(abuse)).toBe(
      'AbuseIPDB reports 0% abuse confidence · 192 reports in 90 days',
    );
  });

  it('maps the live responses into coherent VerdictData (tone/band)', () => {
    expect(mapResponse(LIVE_IP).tone).toBe('green'); // 0 of 2 flagged
    const dom = mapResponse(LIVE_DOMAIN);
    expect(dom.flagged).toBe(1);
    expect(dom.consulted).toBe(1);
  });
});
