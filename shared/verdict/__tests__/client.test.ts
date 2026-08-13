import { describe, expect, it, vi } from 'vitest';
import { fetchEnrich, isEnrichable } from '../client';
import type { FetchLike } from '../client';
import { RAW_IP } from './fixtures';

/** A fake fetch returning a given JSON body + status. */
function fakeFetch(body: unknown, { ok = true, status = 200 }: { ok?: boolean; status?: number } = {}): FetchLike {
  return vi.fn(async () => ({ ok, status, json: async () => body }));
}

describe('isEnrichable', () => {
  it('accepts the reputation types and rejects the rest', () => {
    expect(isEnrichable('ipv4')).toBe(true);
    expect(isEnrichable('sha256')).toBe(true);
    expect(isEnrichable('cve')).toBe(false);
    expect(isEnrichable('email')).toBe(false);
  });
});

describe('fetchEnrich', () => {
  it('calls /api/enrich with the encoded type + q and returns ok + mapped data', async () => {
    const f = fakeFetch(RAW_IP);
    const out = await fetchEnrich('ipv4', '185.220.101.42', { fetchImpl: f });
    expect(f).toHaveBeenCalledWith(
      '/api/enrich?type=ipv4&q=185.220.101.42',
      expect.objectContaining({ headers: { accept: 'application/json' } }),
    );
    expect(out.status).toBe('ok');
    if (out.status === 'ok') {
      expect(out.data.indicator).toBe('185.220.101.42');
      expect(out.data.band).toBe('red');
      expect(out.data.consulted).toBe(2);
    }
  });

  it('encodes indicators that contain URL-significant characters', async () => {
    const f = fakeFetch({ indicator: 'x', type: 'url', sources: [] });
    await fetchEnrich('url', 'http://a.test/?x=1&y=2', { fetchImpl: f });
    expect(f).toHaveBeenCalledWith(
      '/api/enrich?type=url&q=http%3A%2F%2Fa.test%2F%3Fx%3D1%26y%3D2',
      expect.anything(),
    );
  });

  it('maps a 400 with an error body to a declined outcome', async () => {
    const out = await fetchEnrich('ipv4', '10.0.0.1', {
      fetchImpl: fakeFetch({ error: 'private or reserved address — not enriched' }, { ok: false, status: 400 }),
    });
    expect(out).toEqual({ status: 'declined', reason: 'private or reserved address — not enriched' });
  });

  it('maps a 5xx without a usable body to unavailable', async () => {
    const out = await fetchEnrich('ipv4', '1.2.3.4', { fetchImpl: fakeFetch(null, { ok: false, status: 502 }) });
    expect(out).toEqual({ status: 'unavailable', reason: 'HTTP 502' });
  });

  it('treats a non-JSON body as unavailable, never throwing', async () => {
    const f: FetchLike = async () => ({
      ok: true,
      status: 200,
      json: async () => {
        throw new SyntaxError('Unexpected token < in JSON');
      },
    });
    const out = await fetchEnrich('ipv4', '1.2.3.4', { fetchImpl: f });
    expect(out.status).toBe('unavailable');
  });

  it('never throws on a network error', async () => {
    const f: FetchLike = async () => {
      throw new TypeError('Failed to fetch');
    };
    const out = await fetchEnrich('ipv4', '1.2.3.4', { fetchImpl: f });
    expect(out).toEqual({ status: 'unavailable', reason: 'Failed to fetch' });
  });

  it('aborts and reports "timed out" past the timeout budget', async () => {
    // A fetch that only ever rejects when the caller aborts it.
    const f: FetchLike = (_url, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => {
          const e = new Error('aborted');
          e.name = 'AbortError';
          reject(e);
        });
      });
    const out = await fetchEnrich('ipv4', '1.2.3.4', { fetchImpl: f, timeoutMs: 10 });
    expect(out).toEqual({ status: 'unavailable', reason: 'timed out' });
  });
});
