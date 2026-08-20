import { describe, expect, it } from 'vitest';
import {
  cveLead,
  cveModel,
  domainAgeLevel,
  domainModel,
  gaugeCaption,
  gaugeSegments,
  hashModel,
  isBannerLed,
  urlModel,
} from '../model';
import { STUBS } from '../../verdict-cards/stubs';

const dataFor = (id: string) => STUBS.find((s) => s.id === id)!.data;

describe('gaugeSegments + gaugeCaption (shared by card + console)', () => {
  it('emits one severity-ordered segment per consulted source', () => {
    for (const stub of STUBS) {
      const segs = gaugeSegments(stub.data);
      expect(segs).toHaveLength(stub.data.sources.length);
      const rank = { malicious: 0, suspicious: 1, benign: 2, unknown: 3 } as const;
      const ranks = segs.map((v) => rank[v]);
      expect(ranks).toEqual([...ranks].sort((a, b) => a - b));
    }
  });

  it('captions the tally halves without throwing', () => {
    const cap = gaugeCaption(dataFor('ip'));
    expect(typeof cap.left).toBe('string');
    expect(cap.right).toMatch(/not flagged$/);
  });
});

describe('isBannerLed (identity + CVE lead their hero, not a tally)', () => {
  it('is true for hashes and CVEs, false for ip/domain/url', () => {
    expect(isBannerLed(dataFor('hash'))).toBe(true);
    expect(isBannerLed(dataFor('hash-pua'))).toBe(true);
    expect(isBannerLed(dataFor('cve'))).toBe(true);
    expect(isBannerLed(dataFor('ip'))).toBe(false);
    expect(isBannerLed(dataFor('domain'))).toBe(false);
    expect(isBannerLed(dataFor('url'))).toBe(false);
  });
});

describe('hashModel (malware identity, spec §3.4)', () => {
  it('pulls the family + classification from the catalog facts', () => {
    const hm = hashModel(dataFor('hash'));
    expect(hm.family).toBe('Cobalt Strike');
    expect(hm.grayware).toBe(false);
    expect(hm.fileType).toBe('PE · EXE');
  });

  it('flags the grayware/PUA state distinctly', () => {
    const hm = hashModel(dataFor('hash-pua'));
    expect(hm.grayware).toBe(true);
    expect(hm.classification).toMatch(/grayware/i);
  });
});

describe('domainModel + domainAgeLevel (registration-age tell, spec §3.3)', () => {
  it('reads the newly-registered tell from the WHOIS facts (deterministic age)', () => {
    const dm = domainModel(dataFor('domain'));
    expect(dm.newlyRegistered).toBe(true);
    expect(dm.registered).toBe('2026-08-07');
    expect(dm.registrar).toMatch(/NameSilo/);
  });

  it('buckets age into the discrete maturity meter', () => {
    expect(domainAgeLevel(5)).toBe(1);
    expect(domainAgeLevel(60)).toBe(2);
    expect(domainAgeLevel(200)).toBe(3);
    expect(domainAgeLevel(700)).toBe(4);
    expect(domainAgeLevel(4000)).toBe(5);
    expect(domainAgeLevel(NaN)).toBe(0);
  });

  it('says "unavailable" with an honest note when the registry (RDAP) lookup failed', () => {
    const dm = domainModel({
      context: [],
      sources: [],
      errors: [{ source: 'RDAP', reason: 'The operation was aborted due to timeout' }],
    } as unknown as Parameters<typeof domainModel>[0]);
    expect(dm.ageLabel).toBe('Registration age unavailable');
    expect(dm.ageNote).toMatch(/timed out/i);
  });

  it('says "unknown" with no note when there is simply no registration record', () => {
    const dm = domainModel({
      context: [],
      sources: [],
      errors: [],
    } as unknown as Parameters<typeof domainModel>[0]);
    expect(dm.ageLabel).toBe('Registration age unknown');
    expect(dm.ageNote).toBe('');
  });
});

describe('cveModel + cveLead (exploitation status, spec §5)', () => {
  it('surfaces KEV + CVSS + EPSS from the assembled facts', () => {
    const cm = cveModel(dataFor('cve'));
    expect(cm.kev).toBe(true);
    expect(cm.cvss).toBe('9.8');
    expect(cm.cvssSeverity).toBe('Critical');
    expect(cm.epssPct).toBe(94);
    expect(cm.vendor).toBe('Ivanti');
  });

  it('leads source-subject-first with the KEV confirmation', () => {
    const lead = cveLead(dataFor('cve'));
    expect(lead).toContain('CISA KEV');
    expect(lead).toContain('confirms');
  });
});

describe('urlModel (the scanned page, spec §3.3)', () => {
  it('picks the urlscan slot and its final URL', () => {
    const um = urlModel(dataFor('url'));
    expect(um.scanner).toBe('urlscan');
    expect(um.verdict).toBe('malicious');
    expect(um.finalUrl).toContain('support-verify.com');
  });
});

describe('determinism', () => {
  it('same VerdictData in → identical view-model out', () => {
    const d = dataFor('hash');
    expect(hashModel(d)).toEqual(hashModel(d));
    expect(gaugeSegments(d)).toEqual(gaugeSegments(d));
  });
});
