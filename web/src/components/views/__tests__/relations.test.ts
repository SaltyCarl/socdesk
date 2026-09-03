import { describe, expect, it } from 'vitest'
import { relatedMinusUsedBy } from '../relations'
import type { RelatedRow } from '../relations'

/** Minimal RelatedRow — the helper reads only node.type + node.name; the edge is
 *  shape-filler so the rows type-check. */
const row = (type: string, name: string): RelatedRow => ({
  node: { id: `n:${name}`, type, name },
  edge: { type: 'uses', src: 'a', dst: 'b', weight: 1, evidence: ['ATTACK'] },
})

describe('relatedMinusUsedBy — N2 malware reverse-index de-dup', () => {
  const related = [
    row('actor', 'APT29'), // also in usedBy → drop
    row('actor', 'FIN7'), // NOT in usedBy → keep (extra co-occurrence signal)
    row('technique', 'T1059'), // non-actor → always keep
    row('cve', 'CVE-2023-4966'), // non-actor → always keep
  ]
  const usedBy = [{ slug: 'apt29' }, { slug: 'mustang panda' }] // lowercased slugs

  it('drops actor rows already in the reverse-index (case-insensitive)', () => {
    const out = relatedMinusUsedBy(related, usedBy).map((r) => r.node.name)
    expect(out).not.toContain('APT29')
  })

  it('keeps actor rows NOT in the reverse-index', () => {
    expect(relatedMinusUsedBy(related, usedBy).map((r) => r.node.name)).toContain('FIN7')
  })

  it('never drops non-actor rows (techniques / CVEs are context, not duplicates)', () => {
    const out = relatedMinusUsedBy(related, usedBy).map((r) => r.node.name)
    expect(out).toEqual(expect.arrayContaining(['T1059', 'CVE-2023-4966']))
  })

  it('is a pass-through no-op when usedBy is empty (actor pages)', () => {
    expect(relatedMinusUsedBy(related, [])).toBe(related)
  })

  it('empties the list when every related row is an actor already in the reverse-index', () => {
    // the observed real case: malware related-actors are a 100% subset of usedBy
    const allInIndex = [row('actor', 'APT29'), row('actor', 'FIN7')]
    const out = relatedMinusUsedBy(allInIndex, [{ slug: 'apt29' }, { slug: 'fin7' }])
    expect(out).toHaveLength(0)
  })
})
