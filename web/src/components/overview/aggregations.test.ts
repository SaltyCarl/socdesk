import { describe, it, expect } from 'vitest'
import { topNetworks } from './aggregations'
import type { AsnNetwork } from '../views/types'

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
