import { describe, expect, it } from 'vitest';
import {
  assessmentLine,
  classTag,
  composeEscalation,
  consensus,
  coverageHeadline,
  defang,
  deriveBand,
  detectPua,
  dualUseNote,
  dualUseTag,
  graywareLabel,
  hashHeadline,
  isIdentityType,
  isStale,
  leadFact,
  phraseFinding,
  predicate,
  sourceClassFor,
  sourceRank,
  toneClass,
} from '../doctrine';
import { data, src } from './fixtures';

const NOW = new Date('2026-08-12T12:00:00.000Z');

describe('sourceClassFor', () => {
  it('tags the known sources by their published class', () => {
    expect(sourceClassFor('MalwareBazaar')).toBe('catalog');
    expect(sourceClassFor('GreyNoise')).toBe('behavioral');
    expect(sourceClassFor('urlscan')).toBe('behavioral');
    expect(sourceClassFor('AbuseIPDB')).toBe('score');
    expect(sourceClassFor('VirusTotal')).toBe('score');
    // newly mapped so nothing hits the fallback in practice (item 1a)
    expect(sourceClassFor('ThreatFox')).toBe('catalog');
    expect(sourceClassFor('Spamhaus')).toBe('list');
    expect(sourceClassFor('NVD')).toBe('authoritative');
    expect(sourceClassFor('Hybrid Analysis')).toBe('behavioral');
  });
  it('falls back to unclassified for an unmapped source — never impersonates a scored source', () => {
    expect(sourceClassFor('SomeNewFeed')).toBe('unclassified');
  });
});

describe('consensus (ratio tally, contract §1–§2)', () => {
  it('greys when nothing was consulted', () => {
    expect(consensus([])).toEqual({ consulted: 0, flagged: 0, tone: 'grey' });
  });
  it('greens when consulted but nothing flagged', () => {
    const r = consensus([src({ verdict: 'benign' }), src({ verdict: 'unknown' })]);
    expect(r).toEqual({ consulted: 2, flagged: 0, tone: 'green' });
  });
  it('ambers a minority flag and reds a majority', () => {
    const minority = consensus([src({ verdict: 'suspicious' }), src(), src(), src()]);
    expect(minority.tone).toBe('amber');
    const majority = consensus([src({ verdict: 'suspicious' }), src({ verdict: 'malicious' })]);
    expect(majority.tone).toBe('red');
  });
});

describe('deriveBand (doctrine band, spec §3.1 — colour decoupled from N/M)', () => {
  it('grey when M = 0, green when N = 0', () => {
    expect(deriveBand([])).toBe('grey');
    expect(deriveBand([src({ verdict: 'benign' }), src({ verdict: 'unknown' })])).toBe('green');
  });

  it('1-of-6 KEV must NOT render green — an authoritative adverse source drives RED', () => {
    const sources = [
      src({ name: 'MalwareBazaar', class: 'catalog', kev: true, verdict: 'malicious', finding: 'listed in CISA KEV' }),
      src({ verdict: 'benign' }),
      src({ verdict: 'benign' }),
      src({ verdict: 'unknown' }),
      src({ verdict: 'unknown' }),
      src({ verdict: 'benign' }),
    ];
    const band = deriveBand(sources);
    expect(band).not.toBe('green');
    expect(band).toBe('red');
  });

  it('a single catalog hit among many quiet sources is RED (not diluted to amber)', () => {
    const sources = [
      src({ name: 'MalwareBazaar', class: 'catalog', verdict: 'malicious', finding: 'known sample' }),
      src({ verdict: 'benign' }),
      src({ verdict: 'unknown' }),
      src({ verdict: 'benign' }),
    ];
    expect(deriveBand(sources)).toBe('red');
  });

  it('a source asserting its own malicious verdict drives RED even at low N', () => {
    const sources = [src({ class: 'score', verdict: 'malicious', finding: '50% abuse' }), src(), src(), src()];
    expect(deriveBand(sources)).toBe('red');
  });

  it('score/list suspicious-only follows the ratio: minority amber, majority red', () => {
    expect(deriveBand([src({ verdict: 'suspicious' }), src(), src(), src()])).toBe('amber');
    expect(deriveBand([src({ verdict: 'suspicious' }), src({ verdict: 'suspicious' }), src()])).toBe('red');
  });

  it('PUA-only adverse findings are their own grayware band', () => {
    const sources = [
      src({ name: 'MalwareBazaar', class: 'catalog', verdict: 'malicious', pua: true, finding: 'family Adware/InstallCore' }),
      src({ verdict: 'benign' }),
    ];
    expect(deriveBand(sources)).toBe('grayware');
  });

  it('grayware does not mask a real malicious finding alongside it', () => {
    const sources = [
      src({ name: 'MalwareBazaar', class: 'catalog', verdict: 'malicious', pua: true, finding: 'adware' }),
      src({ class: 'score', verdict: 'malicious', finding: 'confirmed malware' }),
    ];
    expect(deriveBand(sources)).toBe('red');
  });
});

describe('toneClass (band → CSS ink)', () => {
  it('maps every band, grayware sharing amber ink and grey never green', () => {
    expect(toneClass('red')).toBe('red');
    expect(toneClass('amber')).toBe('orange');
    expect(toneClass('grayware')).toBe('orange');
    expect(toneClass('green')).toBe('green');
    expect(toneClass('grey')).toBe('muted');
  });
});

describe('confidence ladder (sourceRank + leadFact)', () => {
  it('publishes KEV > catalog > behavioral > score > list', () => {
    expect(sourceRank({ class: 'catalog', kev: true })).toBeLessThan(sourceRank({ class: 'catalog' }));
    expect(sourceRank({ class: 'catalog' })).toBeLessThan(sourceRank({ class: 'behavioral' }));
    expect(sourceRank({ class: 'behavioral' })).toBeLessThan(sourceRank({ class: 'score' }));
    expect(sourceRank({ class: 'score' })).toBeLessThan(sourceRank({ class: 'list' }));
  });

  it('leads with the highest-authority ADVERSE source, regardless of input order', () => {
    const sources = [
      src({ name: 'AbuseIPDB', class: 'score', verdict: 'malicious', finding: '80% abuse' }),
      src({ name: 'GreyNoise', class: 'behavioral', verdict: 'malicious', finding: 'observed scanning' }),
      src({ name: 'MalwareBazaar', class: 'catalog', verdict: 'malicious', finding: 'known sample' }),
    ];
    expect(leadFact(sources)?.source.name).toBe('MalwareBazaar');
  });

  it('a KEV source outranks a plain catalog hit for the lead', () => {
    const sources = [
      src({ name: 'MalwareBazaar', class: 'catalog', verdict: 'malicious', finding: 'known sample' }),
      src({ name: 'CISA KEV', class: 'catalog', kev: true, verdict: 'malicious', finding: 'exploited in the wild' }),
    ];
    expect(leadFact(sources)?.source.name).toBe('CISA KEV');
  });

  it('falls back to a benign lead when nothing is adverse; null when all no-record', () => {
    const benign = leadFact([src({ name: 'GreyNoise', class: 'behavioral', verdict: 'benign', finding: 'RIOT known-good' })]);
    expect(benign?.source.name).toBe('GreyNoise');
    expect(leadFact([src({ verdict: 'unknown' })])).toBeNull();
  });
});

describe('phraseFinding (source-subject-first, spec §3.1 grammatical rule)', () => {
  it('puts the source first: "MalwareBazaar catalogs…", never "… — MalwareBazaar"', () => {
    const s = src({ name: 'MalwareBazaar', class: 'catalog', verdict: 'malicious', finding: 'Known sample — family Cobalt Strike' });
    const line = phraseFinding(s);
    expect(line.startsWith('MalwareBazaar')).toBe(true);
    expect(line).toBe('MalwareBazaar catalogs known sample — family Cobalt Strike');
    expect(line).not.toMatch(/—\s*MalwareBazaar\s*$/);
  });
  it('uses the class verb, and "confirms" for a KEV source', () => {
    expect(phraseFinding(src({ name: 'AbuseIPDB', class: 'score', finding: '98% abuse confidence' }))).toContain(' reports ');
    expect(phraseFinding(src({ name: 'GreyNoise', class: 'behavioral', finding: 'Observed scanning' }))).toContain(' classifies ');
    expect(phraseFinding(src({ name: 'CISA KEV', class: 'catalog', kev: true, finding: 'Exploited in the wild' }))).toContain(' confirms ');
  });
  it('does not lowercase acronyms or identifiers', () => {
    expect(phraseFinding(src({ name: 'GreyNoise', class: 'behavioral', finding: 'RIOT known-good service' }))).toContain('RIOT');
  });
});

describe('predicate (verb-led, name-less — the ledger-row primitive)', () => {
  it('supplies the class verb WITHOUT the source name (findings are verb-less)', () => {
    const s = src({ name: 'MalwareBazaar', class: 'catalog', verdict: 'malicious', finding: '3 samples · family Cobalt Strike' });
    expect(predicate(s)).toBe('catalogs 3 samples · family Cobalt Strike');
    expect(predicate(s).startsWith('MalwareBazaar')).toBe(false);
  });
  it('uses "confirms" for a KEV source', () => {
    expect(predicate(src({ class: 'catalog', kev: true, finding: 'listing in CISA KEV' }))).toBe('confirms listing in CISA KEV');
  });
  it('is the verb-less half of phraseFinding — the verb appears exactly once', () => {
    const s = src({ name: 'MalwareBazaar', class: 'catalog', finding: '3 samples · family Cobalt Strike' });
    expect(phraseFinding(s)).toBe(`${s.name} ${predicate(s)}`);
    expect(phraseFinding(s).match(/catalogs/g)).toHaveLength(1); // no doubled verb
  });
  it('reports an honest absence for an empty finding', () => {
    expect(predicate(src({ finding: '' }))).toBe('— no finding reported');
  });
});

describe('classTag', () => {
  it('renders the human class tag, KEV taking precedence', () => {
    expect(classTag({ class: 'catalog' })).toBe('catalog/identity');
    expect(classTag({ class: 'behavioral' })).toBe('behavioral/observed');
    expect(classTag({ class: 'score' })).toBe('reputation-score');
    expect(classTag({ class: 'list' })).toBe('list-membership');
    expect(classTag({ class: 'catalog', kev: true })).toBe('KEV/authoritative');
  });
});

describe('detectPua', () => {
  it('flags PUA / grayware / adware / riskware wording', () => {
    expect(detectPua('family Adware/InstallCore')).toBe(true);
    expect(detectPua('potentially unwanted application')).toBe(true);
    expect(detectPua('riskware detected')).toBe(true);
    expect(detectPua('grayware')).toBe(true);
    expect(detectPua('Known sample — family Cobalt Strike')).toBe(false);
  });
});

describe('coverageHeadline (tally-as-coverage, spec §3.1 — never "probably fine")', () => {
  it('greys with an absence-of-data caveat when nothing was consulted', () => {
    const h = coverageHeadline([]);
    expect(h).toMatch(/absence of data is not evidence of safety/i);
    expect(h.toLowerCase()).not.toContain('probably fine');
  });

  it('reads thin coverage (not a clearance) when N = 0 with no-record sources', () => {
    const h = coverageHeadline([src({ verdict: 'benign' }), src({ verdict: 'unknown' })]);
    expect(h).toMatch(/thin coverage/i);
    expect(h).toMatch(/absence of data is not evidence of safety/i);
    expect(h).toMatch(/not a clearance/i);
    expect(h.toLowerCase()).not.toContain('probably fine');
  });

  it('a healthy clean sweep still says "not a clearance", no thin-coverage caveat', () => {
    const clean = [src({ verdict: 'benign' }), src({ verdict: 'benign' }), src({ verdict: 'benign' })];
    const h = coverageHeadline(clean);
    expect(h).toBe('0 of 3 consulted sources flagged this — no adverse findings. Not a clearance.');
  });

  it('states the plain N of M once anything is flagged', () => {
    expect(coverageHeadline([src({ verdict: 'malicious' }), src(), src(), src()])).toBe(
      '1 of 4 consulted sources flagged this as adverse.',
    );
  });
});

describe('assessmentLine (escalation register)', () => {
  it('uses "consulted sources" wording (matches the coverageHeadline noun)', () => {
    expect(assessmentLine([src({ verdict: 'malicious' }), src()])).toBe(
      '1 of 2 consulted sources flagged this as adverse.',
    );
    expect(assessmentLine([])).toMatch(/not evidence of safety/i);
  });
});

describe('isIdentityType + hashHeadline (hash carve-out, spec §3.1)', () => {
  it('marks hashes as identity types', () => {
    expect(isIdentityType('sha256')).toBe(true);
    expect(isIdentityType('md5')).toBe(true);
    expect(isIdentityType('ipv4')).toBe(false);
  });

  it('leads with the catalog fact and carries VT as a sub-fact — no N/M tally', () => {
    const sources = [
      src({ name: 'MalwareBazaar', class: 'catalog', verdict: 'malicious', finding: 'Known sample — family Cobalt Strike' }),
      src({ name: 'VirusTotal', class: 'score', verdict: 'malicious', finding: '45/70 engines flag this' }),
    ];
    const h = hashHeadline(data({ sources }));
    expect(h.startsWith('MalwareBazaar catalogs')).toBe(true);
    expect(h).toContain('VirusTotal reports 45/70 engines flag this');
    expect(h).not.toMatch(/\bof\s+\d/); // no "N of M" wrapped around the hash
  });

  it('falls back to VT when the catalog has no record, else an honest absence line', () => {
    const vtOnly = hashHeadline(data({ sources: [src({ name: 'VirusTotal', class: 'score', verdict: 'malicious', finding: '3/70 engines flag this' })] }));
    expect(vtOnly.startsWith('VirusTotal reports')).toBe(true);
    expect(hashHeadline(data({ sources: [] }))).toMatch(/absence of data is not evidence of safety/i);
  });
});

describe('dualUseNote (spec §4)', () => {
  it('surfaces a Tor-exit dual-use qualifier from the facts', () => {
    const sources = [src({ facts: [['Tor exit node', 'yes']] })];
    expect(dualUseNote(sources)).toMatch(/tor exit/i);
  });
  it('surfaces a RIOT known-good qualifier', () => {
    expect(dualUseNote([src({ facts: [['Known-good service (RIOT)', 'yes']] })])).toMatch(/riot/i);
  });
  it('returns null when nothing dual-use applies', () => {
    expect(dualUseNote([src({ facts: [['Country', 'DE']] })])).toBeNull();
  });
});

describe('dualUseTag (amber chip label, item 7)', () => {
  it('derives a short Tor-exit / known-good tag from the same facts as the note', () => {
    expect(dualUseTag([src({ facts: [['Tor exit node', 'yes']] })])).toBe('dual-use · Tor exit');
    expect(dualUseTag([src({ facts: [['Known-good service (RIOT)', 'yes']] })])).toBe(
      'dual-use · known-good',
    );
    expect(dualUseTag([src({ facts: [['Country', 'DE']] })])).toBeNull();
  });
});

describe('isStale', () => {
  it('flags data older than 90 days, tolerates non-dates', () => {
    expect(isStale('2026-01-01', NOW)).toBe(true);
    expect(isStale('2026-08-01', NOW)).toBe(false);
    expect(isStale('never', NOW)).toBe(false);
    expect(isStale(null, NOW)).toBe(false);
  });
});

describe('defang + graywareLabel', () => {
  it('defangs indicators for a ticket', () => {
    expect(defang('evil.com')).toBe('evil[.]com');
    expect(defang('http://evil.com/x')).toBe('hxxp://evil[.]com/x');
  });
  it('exposes the grayware label', () => {
    expect(graywareLabel()).toBe('grayware — flagged, not confirmed malware');
  });
});

describe('composeEscalation (plain-text §4 — travels with the image)', () => {
  const richData = () =>
    data({
      band: 'red',
      identityLed: false,
      sources: [
        src({ name: 'AbuseIPDB', class: 'score', verdict: 'malicious', finding: '98% abuse confidence', recency: '2026-08-10', facts: [['Tor exit node', 'yes']] }),
        src({ name: 'GreyNoise', class: 'behavioral', verdict: 'unknown', finding: 'Not observed scanning' }),
      ],
      context: [{ name: 'ipinfo', finding: 'Frankfurt, Germany · AS3209', url: 'https://ipinfo.io/x' }],
      errors: [{ source: 'urlscan', reason: 'not configured' }],
      flagged: 1,
      consulted: 2,
    });

  it('emits the ordered sections with attributed, class-tagged evidence', () => {
    const text = composeEscalation(richData(), NOW);
    expect(text).toContain('INDICATOR: 185[.]220[.]101[.]42  (IPV4)');
    expect(text).toContain('ASSESSMENT: 1 of 2 consulted sources flagged this as adverse.');
    expect(text).toContain('EVIDENCE (third-party reputation data — attributed, not independently verified):');
    expect(text).toContain('AbuseIPDB reports 98% abuse confidence [reputation-score] (as of 2026-08-10)');
    expect(text).toContain('CONTEXT (not a verdict):');
    expect(text).toContain('Not consulted: urlscan (not configured)');
    expect(text).toMatch(/CAVEAT: Reflects third-party reputation/);
    expect(text).toContain('Note: a source tags this a Tor exit node');
  });

  it('carries NO recommendation and NO branding', () => {
    const text = composeEscalation(richData(), NOW);
    expect(text.toLowerCase()).not.toMatch(/\b(recommend|escalate|block|monitor|quarantine)\b/);
    expect(text).not.toMatch(/socdesk/i);
  });

  it('is deterministic given a fixed `now`', () => {
    const d = richData();
    expect(composeEscalation(d, NOW)).toBe(composeEscalation(d, NOW));
    expect(composeEscalation(d, NOW)).toContain('— Generated 2026-08-12 12:00 UTC.');
  });

  it('for a hash, leads with the identity headline and does not wrap a tally', () => {
    const d = data({
      indicator: 'a'.repeat(64),
      type: 'sha256',
      identityLed: true,
      band: 'red',
      sources: [
        src({ name: 'MalwareBazaar', class: 'catalog', verdict: 'malicious', finding: 'Known sample — family Cobalt Strike' }),
        src({ name: 'VirusTotal', class: 'score', verdict: 'malicious', finding: '45/70 engines flag this' }),
      ],
    });
    const text = composeEscalation(d, NOW);
    expect(text).toContain('ASSESSMENT: MalwareBazaar catalogs known sample');
    expect(text).not.toMatch(/consulted sources flagged/);
  });

  it('keeps the "as of" date but drops "stale" for a catalog membership (item 5)', () => {
    const d = data({
      band: 'red',
      identityLed: false,
      sources: [
        src({
          name: 'MalwareBazaar',
          class: 'catalog',
          verdict: 'malicious',
          finding: 'known sample',
          recency: '2024-01-01',
        }),
        src({
          name: 'VirusTotal',
          class: 'score',
          verdict: 'malicious',
          finding: 'flagged this',
          recency: '2024-01-01',
        }),
      ],
    });
    const text = composeEscalation(d, NOW);
    // catalog membership: date kept, stale marker suppressed
    expect(text).toContain('MalwareBazaar catalogs known sample [catalog/identity] (as of 2024-01-01)');
    // a reputation-score source of the same age still shows stale
    expect(text).toContain('VirusTotal reports flagged this [reputation-score] (as of 2024-01-01, stale)');
  });
});
