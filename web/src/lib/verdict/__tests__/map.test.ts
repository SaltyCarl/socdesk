import { describe, expect, it } from 'vitest';
import { mapResponse } from '../map';
import { RAW_HASH, RAW_IP } from './fixtures';

describe('mapResponse', () => {
  it('splits scored sources from context rows and never tallies context', () => {
    const d = mapResponse(RAW_IP);
    expect(d.sources.map((s) => s.name)).toEqual(['AbuseIPDB', 'GreyNoise']);
    expect(d.context.map((c) => c.name)).toEqual(['ipinfo']);
    expect(d.consulted).toBe(2); // ipinfo excluded
    expect(d.flagged).toBe(1); // AbuseIPDB malicious
  });

  it('recomputes the tally + doctrine band from the mapped sources', () => {
    const d = mapResponse(RAW_IP);
    expect(d.tone).toBe('red'); // 1 of 2 majority → red (ratio)
    expect(d.band).toBe('red'); // AbuseIPDB asserts malicious → red
  });

  it('tags source-class, picks a recency, and preserves the verify url', () => {
    const d = mapResponse(RAW_IP);
    const abuse = d.sources.find((s) => s.name === 'AbuseIPDB')!;
    expect(abuse.class).toBe('score');
    expect(abuse.recency).toBe('2026-08-10');
    expect(abuse.url).toContain('abuseipdb.com');
    const grey = d.sources.find((s) => s.name === 'GreyNoise')!;
    expect(grey.class).toBe('behavioral');
    expect(grey.recency).toBeNull(); // "—" carries no date
  });

  it('preserves errors + partial and normalizes an odd verdict to unknown', () => {
    const d = mapResponse({
      indicator: '1.2.3.4',
      type: 'ipv4',
      sources: [{ name: 'AbuseIPDB', verdict: 'weird' as unknown as string, headline: 'x', url: 'https://x.test' }],
      errors: [{ source: 'urlscan', reason: 'not configured' }],
    });
    expect(d.sources[0].verdict).toBe('unknown');
    expect(d.errors).toHaveLength(1);
    expect(d.partial).toBe(true); // derived from errors when body omits it
  });

  it('marks a hash response identity-led and detects PUA', () => {
    const d = mapResponse(RAW_HASH);
    expect(d.identityLed).toBe(true);
    expect(d.sources.find((s) => s.name === 'MalwareBazaar')!.pua).toBe(false);

    const pua = mapResponse({
      indicator: 'b'.repeat(64),
      type: 'sha256',
      sources: [{ name: 'MalwareBazaar', verdict: 'malicious', headline: 'family Adware/InstallCore', url: 'https://x.test' }],
    });
    expect(pua.sources[0].pua).toBe(true);
    expect(pua.band).toBe('grayware');
  });
});
