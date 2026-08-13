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
 * Call the enrichment endpoint. Resolves to a tagged outcome, never throws:
 *   { status:'ok', data }            a mapped VerdictData
 *   { status:'declined', reason }    the endpoint refused the indicator (400)
 *   { status:'unavailable', reason } network / timeout / HTTP / parse failure
 * `fetchImpl` is injectable for tests; production uses the global fetch.
 */
export async function fetchEnrich(
  type: string,
  q: string,
  { timeoutMs = FETCH_TIMEOUT_MS, fetchImpl, baseUrl = '' }: FetchEnrichOptions = {},
): Promise<EnrichOutcome> {
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
    if (r.ok && looksLikeResponse(body)) return { status: 'ok', data: mapResponse(body) };
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
