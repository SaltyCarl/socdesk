import { describe, it, expect } from 'vitest'
import { hasRankableVolume, topNetworks } from './aggregations'
import type { AsnLeaderboardPayload, AsnNetwork } from '../views/types'

describe('topNetworks', () => {
  const networks: AsnNetwork[] = [
    { asn: 'AS1', ip_count: 5 },
    { asn: 'AS2', ip_count: 4 },
    { asn: 'AS3', ip_count: 3 },
    { asn: 'AS4', ip_count: 2 },
    { asn: 'AS5', ip_count: 1 },
    { asn: 'AS6', ip_count: 1 },
  ]

  it('takes the first N networks without re-sorting (the pipeline already ranks them)', () => {
    expect(topNetworks(networks, 3)).toEqual([networks[0], networks[1], networks[2]])
  })

  it('defaults to a top-5 cut', () => {
    expect(topNetworks(networks)).toHaveLength(5)
    expect(topNetworks(networks)[4]).toEqual(networks[4])
  })

  it('degrades to whatever is available when there are fewer networks than the limit', () => {
    expect(topNetworks(networks.slice(0, 2), 5)).toEqual(networks.slice(0, 2))
    expect(topNetworks([], 5)).toEqual([])
  })
})

describe('hasRankableVolume (OPEN-WORK §3: gate the leaderboard treatment on data volume)', () => {
  const payload = (total_abusive_ips: number): AsnLeaderboardPayload =>
    ({ networks: [], total_abusive_ips }) as AsnLeaderboardPayload

  it('is false below the 20-abusive-IP threshold — today\'s live 8 does not rank', () => {
    expect(hasRankableVolume(payload(8))).toBe(false)
    expect(hasRankableVolume(payload(19))).toBe(false)
  })

  it('is true at or above the threshold', () => {
    expect(hasRankableVolume(payload(20))).toBe(true)
    expect(hasRankableVolume(payload(21))).toBe(true)
  })

  it('is false for a missing/null count (honest default, not a crash)', () => {
    expect(hasRankableVolume({ networks: [] } as AsnLeaderboardPayload)).toBe(false)
    expect(hasRankableVolume(null)).toBe(false)
  })
})
