// useLookup — the ONE indicator→resolution unit, shared by the /lookup triptych
// and the landing inline card so neither surface re-implements the resolver.
//
// Given a raw indicator it refangs, type-detects, and resolves to a tagged
// state the caller renders honestly:
//
//   idle          nothing submitted
//   checking      a live round-trip is in flight
//   ok            a VerdictData to render (+ the RAW enrich body for the globe)
//   declined      the enrich endpoint refused the indicator (400, human reason)
//   unavailable   the fetch failed (network / HTTP / timeout / catalog load)
//   unsupported   email / unclassifiable / a CVE absent from the snapshot
//
// Resolution by type:
//   * CVE          → the committed KEV/EPSS snapshot (cves.json) → cveToVerdict
//                    (authoritative single-source, spec §5 — never enriched).
//   * enrichable   → /api/enrich ONCE (fetchEnrichRaw): the mapped VerdictData
//                    feeds the card, the raw body feeds the globe landing.
//   * email/other  → an honest unsupported message; no fetch.
//
// Only the branch a given indicator needs runs — an IP lookup never pulls the
// ~5 MB CVE catalog, and a CVE never hits /api/enrich.

import { useEffect, useState } from 'react'
import { detectType, isEnrichable, refang } from '@socdesk/shared/indicators'
import { fetchEnrichRaw, type VerdictData } from '@socdesk/shared/verdict'
import { stateUrl } from '../views/useStateData'
import type { CvePayload } from '../views/types'
import type { EnrichApiResult } from '../hero/heroLayers'
import { cveToVerdict } from '../../routes/lookupModel'

/** Which honest inline message an `unsupported` state carries. */
export type UnsupportedVariant = 'email' | 'unrecognised' | 'cve-missing'
/** Which fetch failed on an `unavailable` state (selects the exact wording). */
export type UnavailableSource = 'enrich' | 'catalog'

export type LookupState =
  | { kind: 'idle' }
  | { kind: 'checking'; indicator: string }
  /** `raw` is the untouched /api/enrich body for the globe; null for a CVE
   *  (authoritative single-source — no geo, no globe landing). */
  | { kind: 'ok'; indicator: string; data: VerdictData; raw: EnrichApiResult | null }
  | { kind: 'declined'; indicator: string; reason: string }
  | { kind: 'unavailable'; indicator: string; reason: string; source: UnavailableSource }
  | { kind: 'unsupported'; indicator: string; variant: UnsupportedVariant }

/** Synchronous first state for an indicator: the non-async branches (idle /
 *  email / unrecognised) resolve immediately so there is no gallery/blank flash
 *  before the effect runs; the async branches (CVE / enrichable) start as
 *  `checking`. */
function initialState(indicator: string): LookupState {
  if (!indicator) return { kind: 'idle' }
  const type = detectType(indicator)
  if (type === 'cve' || isEnrichable(type)) return { kind: 'checking', indicator }
  if (type === 'email') return { kind: 'unsupported', indicator, variant: 'email' }
  return { kind: 'unsupported', indicator, variant: 'unrecognised' }
}

/**
 * Resolve a submitted indicator to a tagged {@link LookupState}. Re-runs when
 * the refanged indicator changes; the previous request is aborted so a slow
 * response can never resolve stale.
 */
export function useLookup(rawIndicator: string): LookupState {
  const indicator = rawIndicator ? refang(rawIndicator) : ''
  const [state, setState] = useState<LookupState>(() => initialState(indicator))

  useEffect(() => {
    const first = initialState(indicator)
    setState(first)
    if (first.kind !== 'checking') return // idle / unsupported — terminal, no fetch

    const type = detectType(indicator)
    let live = true

    // CVE — authoritative single-source from the committed catalog.
    if (type === 'cve') {
      const ctrl = new AbortController()
      fetch(stateUrl('cves'), { cache: 'no-cache', signal: ctrl.signal })
        .then((r) => {
          if (!r.ok) throw new Error(`HTTP ${r.status}`)
          return r.json() as Promise<CvePayload>
        })
        .then((data) => {
          if (!live) return
          const id = indicator.toUpperCase()
          const cve = (data?.cves ?? []).find((c) => c.cve.toUpperCase() === id)
          if (!cve) {
            setState({ kind: 'unsupported', indicator, variant: 'cve-missing' })
            return
          }
          setState({ kind: 'ok', indicator, data: cveToVerdict(cve, data?.generated_at), raw: null })
        })
        .catch((err: unknown) => {
          if (!live || ctrl.signal.aborted) return
          const reason = err instanceof Error ? err.message : 'fetch failed'
          setState({ kind: 'unavailable', indicator, reason, source: 'catalog' })
        })
      return () => {
        live = false
        ctrl.abort()
      }
    }

    // Enrichable — ONE /api/enrich round-trip serves both the card and the globe.
    void fetchEnrichRaw(type, indicator).then((o) => {
      if (!live) return
      if (o.status === 'ok') {
        // The raw body carries the server tone/consulted/flagged + the ipinfo
        // Coordinates fact the globe lands on. The two raw shapes differ only
        // nominally (readonly-vs-mutable fact tuples), so bridge via `unknown`.
        setState({ kind: 'ok', indicator, data: o.data, raw: o.raw as unknown as EnrichApiResult })
      } else if (o.status === 'declined') {
        setState({ kind: 'declined', indicator, reason: o.reason })
      } else {
        setState({ kind: 'unavailable', indicator, reason: o.reason, source: 'enrich' })
      }
    })
    return () => {
      live = false
    }
  }, [indicator])

  return state
}
