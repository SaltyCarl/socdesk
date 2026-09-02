import { describe, expect, it } from 'vitest'
import { attackDetectionUrl, buildHuntPack, sigmaSearchUrl } from '../huntpack'
import type { HuntRule, TechniqueTacticsPayload } from '../types'

const R = (id: string, techniques: string[], kind: 'sentinel' | 'sigma' | 'socdesk' = 'sentinel', modified?: string): HuntRule => ({
  id,
  title: id,
  kql: 'SecurityEvent | take 1',
  techniques,
  dialect: 'log_analytics',
  source: { kind, url: 'https://x', license: 'MIT', ...(modified ? { modified } : {}) },
})

const CATALOG: TechniqueTacticsPayload = {
  tactics: {
    T1490: ['impact'],
    T1558: ['credential-access'],
    'T1558.003': ['credential-access'],
    T1059: ['execution'],
    'T1059.001': ['execution'],
    T1595: ['reconnaissance'],
  },
  order: [
    { slug: 'reconnaissance', name: 'Reconnaissance' },
    { slug: 'execution', name: 'Execution' },
    { slug: 'credential-access', name: 'Credential Access' },
    { slug: 'impact', name: 'Impact' },
  ],
}

describe('buildHuntPack — join, ranking, caps', () => {
  it('parent-normalizes: a profile parent id matches a sub-technique rule (family)', () => {
    // the live Akira case: profile lists T1558, the corpus tags T1558.003
    const pack = buildHuntPack(['T1558'], [R('kerb', ['T1558.003'])], CATALOG)
    expect(pack.totalMatched).toBe(1)
    expect(pack.sections[0].slug).toBe('credential-access')
    expect(pack.sections[0].rows[0].exact).toBe(false)
    expect(pack.uncovered).toEqual([])
  })

  it('ranks exact-id matches above family matches within a technique', () => {
    const rules = [R('family', ['T1059.003']), R('exact', ['T1059.001'])]
    const pack = buildHuntPack(['T1059.001'], rules, CATALOG)
    expect(pack.sections[0].rows.map((r) => r.rule.id)).toEqual(['exact', 'family'])
  })

  it('caps at 3 per technique with kind priority then recency', () => {
    const rules = [
      R('sen-old', ['T1059.001'], 'sentinel', '2025-01-01'),
      R('sen-new', ['T1059.001'], 'sentinel', '2026-01-01'),
      R('sig', ['T1059.001'], 'sigma', '2026-06-01'),
      R('own', ['T1059.001'], 'socdesk', '2024-01-01'),
      R('sen-mid', ['T1059.001'], 'sentinel', '2025-06-01'),
    ]
    const pack = buildHuntPack(['T1059.001'], rules, CATALOG)
    const ids = pack.sections[0].rows.map((r) => r.rule.id)
    expect(ids).toEqual(['own', 'sen-new', 'sen-mid']) // socdesk first, then sentinel by recency
    expect(ids).toHaveLength(3)
  })

  it('dedupes globally: one rule matching two techniques renders once, under the earliest tactic', () => {
    const rule = R('multi', ['T1059.001', 'T1490'])
    const pack = buildHuntPack(['T1059.001', 'T1490'], [rule], CATALOG)
    expect(pack.totalMatched).toBe(1)
    expect(pack.sections).toHaveLength(1)
    expect(pack.sections[0].slug).toBe('execution') // earlier than impact
    expect(pack.sections[0].rows[0].matched.sort()).toEqual(['T1059.001', 'T1490'])
  })

  it('separates uncovered techniques and omits pure pre-compromise ones with a count', () => {
    const pack = buildHuntPack(['T1490', 'T1595'], [], CATALOG)
    expect(pack.totalMatched).toBe(0)
    expect(pack.uncovered).toEqual(['T1490'])
    expect(pack.preCompromiseOmitted).toBe(1)
  })

  it('falls back to a single flat section without a catalog', () => {
    const pack = buildHuntPack(['T1490'], [R('r', ['T1490'])])
    expect(pack.sections).toHaveLength(1)
    expect(pack.sections[0].slug).toBe('other')
  })

  it('counts overflow past the 50-row panel cap', () => {
    const techniques = Array.from({ length: 60 }, (_, i) => `T2${String(i).padStart(3, '0')}`)
    const rules = techniques.map((t) => R(`r-${t}`, [t]))
    const pack = buildHuntPack(techniques, rules)
    expect(pack.overflow).toBe(10)
    expect(pack.sections.reduce((s, x) => s + x.rows.length, 0)).toBe(50)
  })
})

describe('floor link targets', () => {
  it('builds the live-verified ATT&CK detection anchor, sub-techniques as Txxxx/yyy', () => {
    expect(attackDetectionUrl('T1486')).toBe('https://attack.mitre.org/techniques/T1486/#detection')
    expect(attackDetectionUrl('T1059.001')).toBe(
      'https://attack.mitre.org/techniques/T1059/001/#detection',
    )
  })
  it('builds the SigmaHQ code-search url with the lowercase tag form', () => {
    expect(sigmaSearchUrl('T1486')).toContain('attack.t1486')
  })
})
