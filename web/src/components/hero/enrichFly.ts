// enrichFly — the omnibox → live enrichment → globe landing seam.
//
// Replaces the old mock GEO-table fly. An indicator typed into the hero omnibox
// is classified (shared/indicators::detectType, the SAME detector the extension
// + lookup route use), enriched through the site's OWN Pages Function
// (/api/enrich, same-origin so CSP stays connect-src 'self'), and the REAL
// result is dispatched on `socdesk:enrich-result`. The globe engine (useGlobe3)
// listens for that event, lands on the result's real coordinates, and shows the
// real sourced verdict card.
//
// Honest failure: an unclassifiable/unsupported indicator, an upstream error,
// or a result with no geolocation all resolve to a named status — never a
// fabricated landing.

import { detectType, isEnrichable, refang } from '@socdesk/shared/indicators'
import { geoPresent, type EnrichApiResult } from './heroLayers'

/** The custom event the globe engine listens for. */
export const ENRICH_EVENT = 'socdesk:enrich-result'

export type EnrichStatus =
  | { state: 'idle' }
  | { state: 'checking'; indicator: string }
  /** Not an enrichable type (CVE / email / unclassifiable) — routed nowhere. */
  | { state: 'unsupported'; indicator: string; type: string }
  /** Enriched + landed on real coordinates. */
  | { state: 'landed'; indicator: string }
  /** Enriched, but the indicator has no geolocation (hash / most domains). */
  | { state: 'no-geo'; indicator: string }
  /** The lookup itself failed (offline backend, upstream error). */
  | { state: 'error'; indicator: string; reason: string }

/** Base-aware enrich endpoint (BASE_URL is '/' in prod/preview → /api/enrich). */
function enrichEndpoint(type: string, q: string): string {
  return (
    `${import.meta.env.BASE_URL}api/enrich?type=${encodeURIComponent(type)}` +
    `&q=${encodeURIComponent(q)}`
  )
}

/**
 * Classify + enrich a typed indicator, dispatch the result for the globe to
 * land, and resolve to an honest status the omnibox can render. Never throws.
 */
export async function runEnrich(
  raw: string,
  signal?: AbortSignal,
): Promise<EnrichStatus> {
  const q = refang(raw)
  if (!q) return { state: 'idle' }
  const type = detectType(q)
  if (!isEnrichable(type)) return { state: 'unsupported', indicator: q, type: type || 'unknown' }

  try {
    const res = await fetch(enrichEndpoint(type, q), { cache: 'no-cache', signal })
    const result = (await res.json()) as EnrichApiResult
    if (!res.ok || result?.error) {
      return { state: 'error', indicator: q, reason: result?.error || `HTTP ${res.status}` }
    }
    document.dispatchEvent(new CustomEvent<EnrichApiResult>(ENRICH_EVENT, { detail: result }))
    return geoPresent(result)
      ? { state: 'landed', indicator: q }
      : { state: 'no-geo', indicator: q }
  } catch (err: unknown) {
    if (signal?.aborted) return { state: 'idle' }
    const reason = err instanceof Error ? err.message : 'lookup failed'
    return { state: 'error', indicator: q, reason }
  }
}
