import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { renderVerdictCanvas } from '../drawVerdict';
import { STUBS } from '../../verdict-cards/stubs';

// drawVerdict paints to a <canvas>; the test env is plain Node with no DOM.
// A minimal fake canvas + 2D context lets the whole measure+draw path run so
// we can prove it does not throw on the real STUBS fixtures and produces
// deterministic dimensions — without pulling in jsdom (whose canvas has no 2D
// context anyway). The context is a Proxy: every method is a no-op except
// measureText, which returns a width proportional to the string length so the
// wrap/measure logic exercises deterministically.
let lastFillText: string[] = [];

function makeContext() {
  return new Proxy(
    {},
    {
      get(_target, prop) {
        if (prop === 'measureText') return (s: string) => ({ width: String(s).length * 6 });
        if (prop === 'fillText') return (s: string) => { lastFillText.push(String(s)); };
        return () => {};
      },
      set() {
        return true;
      },
    },
  );
}

const fakeDocument = {
  createElement: () => ({ width: 0, height: 0, getContext: () => makeContext() }),
} as unknown as Document;

const NOW = new Date('2026-08-12T12:00:00.000Z');
let priorDocument: unknown;

beforeAll(() => {
  priorDocument = (globalThis as { document?: unknown }).document;
  (globalThis as { document?: unknown }).document = fakeDocument;
});

afterAll(() => {
  (globalThis as { document?: unknown }).document = priorDocument;
});

describe('renderVerdictCanvas (deterministic copy-card PNG)', () => {
  it('renders every STUBS fixture without throwing, at the fixed card width', () => {
    for (const stub of STUBS) {
      const canvas = renderVerdictCanvas(stub.data, { theme: 'dark', now: NOW });
      expect(canvas.width).toBe(880); // 440 CSS px × 2 (SCALE)
      expect(canvas.height).toBeGreaterThan(0);
    }
  });

  it('is deterministic — identical dimensions for the same input', () => {
    const ip = STUBS.find((s) => s.id === 'ip')!.data;
    const a = renderVerdictCanvas(ip, { theme: 'dark', now: NOW });
    const b = renderVerdictCanvas(ip, { theme: 'dark', now: NOW });
    expect(a.width).toBe(b.width);
    expect(a.height).toBe(b.height);
  });

  it('renders both themes for an identity-led hash card', () => {
    const hash = STUBS.find((s) => s.id === 'hash')!.data;
    expect(() => renderVerdictCanvas(hash, { theme: 'light', now: NOW })).not.toThrow();
    expect(() => renderVerdictCanvas(hash, { theme: 'dark', now: NOW })).not.toThrow();
  });

  it('paints the client-safe caveat and the sources-queried stamp on the footer', () => {
    lastFillText = [];
    const ip = STUBS.find((s) => s.id === 'ip')!.data;
    renderVerdictCanvas(ip, { theme: 'dark', now: NOW });
    expect(lastFillText.some((s) => s.includes('Reflects third-party reputation'))).toBe(true);
    expect(lastFillText.some((s) => /queried/i.test(s))).toBe(true);
  });

  it('ties the hosting/datacenter signal into the geo block when AbuseIPDB flags it', () => {
    lastFillText = [];
    const ip = STUBS.find((s) => s.id === 'ip')!.data;
    const hostingIp = {
      ...ip,
      sources: ip.sources.map((s) =>
        s.name === 'AbuseIPDB' ? { ...s, facts: [...(s.facts ?? []), ['Usage type', 'Data Center/Web Hosting/Transit'] as [string, string]] } : s,
      ),
    };
    renderVerdictCanvas(hostingIp, { theme: 'dark', now: NOW });
    expect(lastFillText.some((s) => /hosting|datacenter|announcement/i.test(s))).toBe(true);
  });

  it('attributes the geo readout to the real source, not a hard-coded "via ipinfo"', () => {
    lastFillText = [];
    const ip = STUBS.find((s) => s.id === 'ip')!.data;
    renderVerdictCanvas(ip, { theme: 'dark', now: NOW });
    expect(lastFillText).toContain('city-level · via ipinfo');
  });
});
