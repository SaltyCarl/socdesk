import { describe, expect, it } from 'vitest'
import {
  distinctiveSplit,
  seededToolCounts,
  techniqueOverlap,
  techniquePrevalence,
  usedByCounts,
  usedByGroups,
} from '../derived'
import type { Profile } from '../types'

const P = (name: string, techniques: string[], software: string[] = [], attack_id = ''): Profile => ({
  name,
  attack_id,
  aliases: [],
  techniques,
  software,
})

const ACTORS: Profile[] = [
  P('Self', ['T1', 'T2', 'T3', 'T4', 'T5'], ['Mimikatz', 'PsExec'], 'G0001'),
  P('CloseTwin', ['T1', 'T2', 'T3', 'T4'], ['Mimikatz'], 'G0002'),          // 4 shared / min 4 → 1.0
  P('MegaActor', ['T1', 'T2', 'T3', 'X1', 'X2', 'X3', 'X4', 'X5', 'X6', 'X7'], [], 'G0003'), // 3 / min 5 → .6
  P('TooFew', ['T1', 'T2'], [], 'G0004'),                                    // shared 2 < min → out
  P('NoOverlap', ['Z1', 'Z2', 'Z3', 'Z4', 'Z5'], ['Mimikatz'], 'G0005'),
]

describe('techniqueOverlap', () => {
  it('ranks by overlap coefficient (not raw size), min shared ≥ 3, self excluded', () => {
    const rows = techniqueOverlap({ attack_id: 'G0001', name: 'Self', techniques: ACTORS[0].techniques! }, ACTORS)
    expect(rows.map((r) => r.name)).toEqual(['CloseTwin', 'MegaActor'])
    expect(rows[0]).toMatchObject({ shared: 4, total: 4 })
    expect(rows.some((r) => r.name === 'Self')).toBe(false)
    expect(rows.some((r) => r.name === 'TooFew')).toBe(false)
  })
  it('suppresses entirely for a thin fingerprint (<5 techniques)', () => {
    expect(techniqueOverlap({ name: 'TooFew', techniques: ['T1', 'T2'] }, ACTORS)).toEqual([])
  })
  it('excludes self by attack_id even when reached under a different name (alias page)', () => {
    const rows = techniqueOverlap(
      { attack_id: 'G0001', name: 'Some Alias', techniques: ACTORS[0].techniques! },
      ACTORS,
    )
    expect(rows.some((r) => r.name === 'Self')).toBe(false)
  })
})

describe('techniquePrevalence + distinctiveSplit', () => {
  const prev = techniquePrevalence(ACTORS)
  it('counts actors per technique', () => {
    expect(prev.get('T1')).toBe(4)
    expect(prev.get('Z1')).toBe(1)
  })
  it('splits at prevalence ≤ 3, and treats actor-unknown techniques as common', () => {
    const { distinctive, common } = distinctiveSplit(['T1', 'Z1', 'NEVER-SEEN'], prev)
    expect(distinctive).toEqual(['Z1'])           // prevalence 1
    expect(common).toEqual(['T1', 'NEVER-SEEN'])  // 4 actors / zero actors
  })
  it('partition is exact — distinctive + common re-compose the input', () => {
    const input = ACTORS[0].techniques!
    const { distinctive, common } = distinctiveSplit(input, prev)
    expect([...distinctive, ...common].sort()).toEqual([...input].sort())
  })
})

describe('seededToolCounts', () => {
  it('counts case-insensitively across seed variants (Rclone/RClone are one tool)', () => {
    const intel = [
      { tools: ['PsExec', 'Rclone'] },
      { tools: ['psexec', 'RClone', 'Mimikatz'] },
      { tools: ['PsExec'] },
      {},
    ]
    const m = seededToolCounts(intel)
    expect(m.get('psexec')).toBe(3)
    expect(m.get('rclone')).toBe(2)
    expect(m.get('mimikatz')).toBe(1)
  })
})

describe('usedByGroups + usedByCounts (the reverse index)', () => {
  it('lists every group whose fingerprint carries the family, case-insensitively', () => {
    const rows = usedByGroups('mimikatz', ACTORS)
    expect(rows.map((r) => r.name)).toEqual(['CloseTwin', 'NoOverlap', 'Self'])
  })
  it('is ATT&CK-only arithmetic: zero for an unlisted family', () => {
    expect(usedByGroups('GhostRAT', ACTORS)).toEqual([])
  })
  it('directory counts match', () => {
    const counts = usedByCounts(ACTORS)
    expect(counts.get('mimikatz')).toBe(3)
    expect(counts.get('psexec')).toBe(1)
  })
})
