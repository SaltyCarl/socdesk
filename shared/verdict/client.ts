// client.ts — the front-end half of the live reputation lookup.
//
// SOCDesk holds no reputation corpus by design; the live answer comes from
// `/api/enrich`, a same-origin Function that fans the indicator across the
// public sources and returns one composite (shape in lib/enrich.mjs). This
// module calls it and maps the result into the shared VerdictData.
//
// CONTRACT WITH THE REST OF THE APP:
//   * Same-origin fetch only — CSP is `connect-src 'self'`.
//   * NEVER throws, never hangs. A dead endpoint, a timeout, a validation
//     refusal (private IP) or a non-JSON body all resolve to a tagged outcome
//     the caller degrades on gracefully.

import type { IndicatorType, VerdictData } from './types';
import { ENRICHABLE_TYPES } from './types';
import type { EnrichResponse } from './map';
import { mapResponse } from './map';

/** The whole fan-out is bounded server-side (4.5s per upstream, in parallel);
 *  give the round-trip generous headroom, then stop waiting so the UI never
 *  hangs on a wedged edge. */
export const FETCH_TIMEOUT_MS = 12_000;

/** A tagged outcome — the caller switches on `status`, never try/catch. */
export type EnrichOutcome =
  | { status: 'ok'; data: VerdictData }
  | { status: 'declined'; reason: string }
  | { status: 'unavailable'; reason: string };

/** Like {@link EnrichOutcome}, but the ok arm also carries the RAW response
 *  body. One surface — the web hero — needs the untouched body (the server's
 *  own tone/consulted/flagged tally + the ipinfo `Coordinates` context fact) to
 *  land the globe, while the card consumes the mapped VerdictData; a single
 *  round-trip serves both. `fetchEnrich` is this with `raw` dropped, so the
 *  extension's contract is unchanged. */
export type EnrichRawOutcome =
  | { status: 'ok'; data: VerdictData; raw: EnrichResponse }
  | { status: 'declined'; reason: string }
  | { status: 'unavailable'; reason: string };

/** The minimal shape this client needs from fetch — injectable for tests. */
export interface FetchLike {
  (
    url: string,
    init?: { signal?: AbortSignal; headers?: Record<string, string> },
  ): Promise<{ ok: boolean; status: number; json: () => Promise<unknown> }>;
}

export interface FetchEnrichOptions {
  timeoutMs?: number;
  fetchImpl?: FetchLike;
  /** Origin to prefix the request with, for a cross-origin caller (the
   *  browser extension passes its configured origin here). Default '' keeps
   *  the same-origin `/api/enrich` request the web app relies on. */
  baseUrl?: string;
}

/** True when a type is enrichable via /api/enrich. */
export function isEnrichable(type: string): type is IndicatorType {
  return ENRICHABLE_TYPES.has(type as IndicatorType);
}

function looksLikeResponse(body: unknown): body is EnrichResponse {
  return !!body && typeof body === 'object' && Array.isArray((body as EnrichResponse).sources);
}

/**
 * Call the enrichment endpoint, keeping the RAW body on the ok arm. Resolves to
 * a tagged outcome, never throws:
 *   { status:'ok', data, raw }       the mapped VerdictData + the untouched body
 *   { status:'declined', reason }    the endpoint refused the indicator (400)
 *   { status:'unavailable', reason } network / timeout / HTTP / parse failure
 * `fetchImpl` is injectable for tests; production uses the global fetch.
 */
export async function fetchEnrichRaw(
  type: string,
  q: string,
  { timeoutMs = FETCH_TIMEOUT_MS, fetchImpl, baseUrl = '' }: FetchEnrichOptions = {},
): Promise<EnrichRawOutcome> {
  const f: FetchLike = fetchImpl ?? ((url, init) => fetch(url, init));
  const url = `${baseUrl}/api/enrich?type=${encodeURIComponent(type)}&q=${encodeURIComponent(q)}`;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await f(url, { signal: ctrl.signal, headers: { accept: 'application/json' } });
    let body: unknown = null;
    try {
      body = await r.json();
    } catch {
      /* served a non-JSON error body — treated as unavailable below */
    }
    // On ok the validated body serves BOTH consumers: mapped for the card, raw
    // for the globe (the raw carries fields map.ts deliberately ignores).
    if (r.ok && looksLikeResponse(body)) return { status: 'ok', data: mapResponse(body), raw: body };
    // A 400 from lib/enrich.mjs carries a human reason (private IP, malformed).
    const err = (body as { error?: unknown } | null)?.error;
    if (err) return { status: 'declined', reason: String(err) };
    return { status: 'unavailable', reason: `HTTP ${r.status}` };
  } catch (e) {
    const err = e as { name?: string; message?: string } | null;
    return {
      status: 'unavailable',
      reason: err?.name === 'AbortError' ? 'timed out' : err?.message || 'network error',
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Call the enrichment endpoint and resolve to a mapped VerdictData outcome. The
 * extension + the `/lookup` triptych consume this; it is {@link fetchEnrichRaw}
 * with the raw body dropped, so both paths share ONE fetch implementation.
 */
export async function fetchEnrich(
  type: string,
  q: string,
  opts: FetchEnrichOptions = {},
): Promise<EnrichOutcome> {
  const o = await fetchEnrichRaw(type, q, opts);
  return o.status === 'ok' ? { status: 'ok', data: o.data } : o;
}
