// useHeroPins — load the two REAL data layers and derive the hero pin set.
//
// Both sources are committed snapshots fetched same-origin (CSP connect-src
// 'self') through the shared useStateData hook — the same path every data view
// uses. Absence is honest: a missing/empty snapshot yields no pins for that
// layer (no error state on the globe, no fabricated fill).
//
//   • threat_ips.json → the reported-IP scatter (abuse.ch)
//   • feed.json       → ransomware.live claims aggregated by victim country
//
// The result is a memoised HeroPin[] the globe plots in one buffer.

import { useMemo } from 'react'
import { useStateData } from '../views/useStateData'
import type { FeedPayload } from '../views/types'
import {
  buildIpPins,
  buildRansomCountryPins,
  type HeroPin,
  type ThreatIpsPayload,
} from './heroLayers'

export interface HeroPinsResult {
  pins: HeroPin[]
  ipCount: number
  ransomCount: number
}

export function useHeroPins(): HeroPinsResult {
  const threatIps = useStateData<ThreatIpsPayload>('threat_ips')
  const feed = useStateData<FeedPayload>('feed')

  const ipPins = useMemo(() => buildIpPins(threatIps.data), [threatIps.data])
  const ransomPins = useMemo(
    () => buildRansomCountryPins(feed.data?.items ?? null),
    [feed.data],
  )

  return useMemo(
    () => ({
      pins: [...ipPins, ...ransomPins],
      ipCount: ipPins.length,
      ransomCount: ransomPins.length,
    }),
    [ipPins, ransomPins],
  )
}
