import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { SynthesisBand } from '../SynthesisBand'
import type { MitreFingerprint, ProfileActivity } from '../profiles'
import type { HuntPack } from '../huntpack'

const fp = (techniques: string[]): MitreFingerprint => ({
  kind: 'actor', name: 'APT29', attack_id: 'G0016', attackUrl: '', aliases: [],
  description: '', techniques, software: [],
})

// T1 is rare (prevalence 2 ≤ 3 → distinctive), T2 is commodity (50)
const prevalence = new Map<string, number>([['T1', 2], ['T2', 50]])

const pack = (totalMatched: number): HuntPack => ({
  sections: totalMatched
    ? [{ slug: 'exec', name: 'Execution', rows: [
        { rule: { id: 'r1', title: 'PowerShell Encoded Command', kql: '', techniques: ['T1'], dialect: 'advanced_hunting', source: { kind: 'sigma', url: 'x', license: 'DRL' } }, exact: true, matched: ['T1'] },
      ] }]
    : [],
  uncovered: [], preCompromiseOmitted: 0, totalMatched, overflow: 0,
})

const activity = (n: number): ProfileActivity => ({
  sectors: [], countries: [], timeline: [], victimCount: n, hasDigest: false,
  daily: [{ date: '2026-08-13', count: n }, { date: '2026-08-14', count: 0 }],
  lastClaimAt: '2026-08-13T00:00:00Z', hasLegacyDigest: false, sectorCounts: [], countryCounts: [],
})

describe('SynthesisBand', () => {
  it('promotes distinctive TTPs to the lead with a stated denominator', () => {
    const html = renderToStaticMarkup(
      <SynthesisBand fingerprint={fp(['T1', 'T2'])} prevalence={prevalence} actorCount={176}
        huntPack={undefined} activity={null} intel={null} techniqueNames={{ T1: 'Rare Tech' }} />,
    )
    expect(html).toContain('Distinctive TTPs')
    expect(html).toContain('T1') // the rare technique chip
    expect(html).not.toContain('T2') // the commodity one is not distinctive
    expect(html).toContain('176 tracked groups')
    // routes to its section via a hash-safe button, never an #id anchor
    expect(html).toContain('<button')
    expect(html).not.toContain('href="#')
  })

  it('shows the hunt count + titles when the pack has matches', () => {
    const html = renderToStaticMarkup(
      <SynthesisBand fingerprint={fp(['T1'])} prevalence={prevalence} huntPack={pack(7)}
        activity={null} intel={null} />,
    )
    expect(html).toContain('Top hunts · 7')
    expect(html).toContain('PowerShell Encoded Command')
  })

  it('omits the hunts cell for a floor-only pack (totalMatched 0)', () => {
    const html = renderToStaticMarkup(
      <SynthesisBand fingerprint={fp(['T1'])} prevalence={prevalence} huntPack={pack(0)}
        activity={null} intel={null} />,
    )
    expect(html).not.toContain('Top hunts')
  })

  it('renders the activity spark + cadence when the group is claiming', () => {
    const html = renderToStaticMarkup(
      <SynthesisBand fingerprint={null} activity={activity(4)} intel={null} />,
    )
    expect(html).toContain('Recent activity')
    expect(html).toContain('4 claims')
  })

  it('teases the initial-access CVE count + KEV pressure (no chip duplicate of the always-open panel)', () => {
    const html = renderToStaticMarkup(
      <SynthesisBand fingerprint={null} activity={null}
        intel={{ slug: 'akira', name: 'Akira', initial_access_cves: ['CVE-2023-20269', 'CVE-2020-3259'] }}
        cveContext={{ 'CVE-2023-20269': { kev: true } }} />,
    )
    expect(html).toContain('Initial access')
    expect(html).toContain('2 initial-access CVEs')
    expect(html).toContain('1 in CISA KEV')
    // must NOT duplicate the exact CVE-id chips — those live in the open panel below
    expect(html).not.toContain('CVE-2023-20269')
  })

  it('returns null for a bare actor with none of the four signals', () => {
    const html = renderToStaticMarkup(
      <SynthesisBand fingerprint={fp([])} prevalence={new Map()} activity={null} intel={null} />,
    )
    expect(html).toBe('')
  })
})
