import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { ActorProfile } from '../ActorProfile'
import type { ProfileResult } from '../profiles'

/** Minimal fused profile: just an ATT&CK fingerprint carrying one technique id,
 *  everything else an honest empty. Enough to exercise the technique chip. */
const profile: ProfileResult = {
  slug: 'apt9999',
  name: 'APT9999',
  fingerprint: {
    kind: 'actor',
    name: 'APT9999',
    attack_id: 'G9999',
    attackUrl: 'https://attack.mitre.org/groups/G9999/',
    aliases: [],
    description: '',
    techniques: ['T1566'],
    software: [],
  },
  ransomware: null,
  reporting: [],
  related: [],
  intel: null,
  claimedVictims: [],
  activity: null,
  associatedMalware: [],
}

/** Variant helper: the base profile with overrides. */
const withOverrides = (over: Partial<ProfileResult>): ProfileResult => ({ ...profile, ...over })

const INTEL_BASE = {
  slug: 'apt9999',
  name: 'APT9999',
  advisory: { id: 'AA99-001A', url: 'https://www.cisa.gov/x' },
}

describe('ActorProfile — RaaS fact is tri-state (stated only when known)', () => {
  it('renders nothing for an ABSENT raas flag (no false "No")', () => {
    const html = renderToStaticMarkup(
      <ActorProfile profile={withOverrides({ intel: INTEL_BASE })} slugSet={new Set()} />,
    )
    expect(html).not.toContain('RaaS')
  })
  it('renders Yes for explicit true and No for explicit false', () => {
    const yes = renderToStaticMarkup(
      <ActorProfile
        profile={withOverrides({ intel: { ...INTEL_BASE, raas: true } })}
        slugSet={new Set()}
      />,
    )
    expect(yes).toContain('Yes · affiliate model')
    const no = renderToStaticMarkup(
      <ActorProfile
        profile={withOverrides({ intel: { ...INTEL_BASE, raas: false } })}
        slugSet={new Set()}
      />,
    )
    expect(no).toMatch(/RaaS/)
    expect(no).not.toContain('Yes · affiliate model')
  })
})

describe('ActorProfile — de-duplicated software & aliases (occurrence counts)', () => {
  it('renders a fingerprint software name exactly ONCE (no Associated-malware echo)', () => {
    const p = withOverrides({
      fingerprint: { ...profile.fingerprint!, software: ['Sliver'] },
      associatedMalware: ['Sliver'], // the fusion's union includes it
    })
    const html = renderToStaticMarkup(<ActorProfile profile={p} slugSet={new Set()} />)
    expect((html.match(/Sliver/g) ?? []).length).toBe(1)
    // and the panel hides entirely rather than rendering prose over zero chips
    expect(html).not.toContain('Associated malware')
  })
  it('keeps a genuinely feed-only name in the Associated-malware rail', () => {
    const p = withOverrides({
      fingerprint: { ...profile.fingerprint!, software: ['Sliver'] },
      associatedMalware: ['Sliver', 'FeedOnlyRAT'],
    })
    const html = renderToStaticMarkup(<ActorProfile profile={p} slugSet={new Set()} />)
    expect(html).toContain('FeedOnlyRAT')
    expect((html.match(/Sliver/g) ?? []).length).toBe(1)
  })
  it('renders an alias exactly once (header chips; no "Also tracked as" echo)', () => {
    const p = withOverrides({
      fingerprint: { ...profile.fingerprint!, aliases: ['Cozy Bear'] },
    })
    const html = renderToStaticMarkup(<ActorProfile profile={p} slugSet={new Set()} />)
    expect((html.match(/Cozy Bear/g) ?? []).length).toBe(1)
  })
  it('renders no facts divider for a pure-ATT&CK profile with no facts', () => {
    // no intel, no aliases: the rail (and its border) must be absent entirely
    const html = renderToStaticMarkup(<ActorProfile profile={profile} slugSet={new Set()} />)
    expect(html).not.toContain('First seen')
    expect(html).not.toContain('Aliases')
  })
})

describe('ActorProfile — seeded-intel depth (cve_context + tool counts)', () => {
  const intel = {
    ...INTEL_BASE,
    initial_access_cves: ['CVE-2020-1111', 'CVE-2023-2222', 'CVE-2021-3333'],
    tools: ['PsExec', 'RareTool'],
  }
  const ctx = {
    'CVE-2020-1111': { kev: true, epss: 0.18 },
    'CVE-2023-2222': { kev: true, kev_ransomware: true, epss: 0.94 },
    // CVE-2021-3333 deliberately absent — the unmarked case
  }

  it('orders CVE chips by EPSS desc, unknowns last', () => {
    const html = renderToStaticMarkup(
      <ActorProfile
        profile={withOverrides({ intel })}
        slugSet={new Set()}
        cveContext={ctx}
      />,
    )
    const i22 = html.indexOf('CVE-2023-2222')
    const i11 = html.indexOf('CVE-2020-1111')
    const i33 = html.indexOf('CVE-2021-3333')
    expect(i22).toBeGreaterThan(-1)
    expect(i22).toBeLessThan(i11)
    expect(i11).toBeLessThan(i33)
    expect(html).toContain('94%')
    // mixed panel (one CVE unmarked): the honesty caveat renders
    expect(html).toContain('isn’t in the KEV catalog')
  })

  it('hoists KEV to one panel line when EVERY chip is KEV (the live reality)', () => {
    const allKevCtx = {
      'CVE-2020-1111': { kev: true, epss: 0.18 },
      'CVE-2023-2222': { kev: true, kev_ransomware: true, epss: 0.94 },
      'CVE-2021-3333': { kev: true, epss: 0.5 },
    }
    const html = renderToStaticMarkup(
      <ActorProfile
        profile={withOverrides({ intel })}
        slugSet={new Set()}
        cveContext={allKevCtx}
      />,
    )
    expect(html).toContain('All 3 are in CISA’s KEV catalog')
    expect(html).not.toContain('isn’t in the KEV catalog')
  })

  it('degrades to plain chips with no context (pre-refresh deploys)', () => {
    const html = renderToStaticMarkup(
      <ActorProfile profile={withOverrides({ intel })} slugSet={new Set()} />,
    )
    expect(html).toContain('CVE-2020-1111')
    expect(html).not.toContain('%')
    expect(html).not.toContain('KEV catalog')
  })

  it('shows a seeded-crew count on shared tools only (n ≥ 2), never on singles', () => {
    const counts = new Map([
      ['psexec', 8],
      ['raretool', 1],
    ])
    const html = renderToStaticMarkup(
      <ActorProfile
        profile={withOverrides({ intel })}
        slugSet={new Set()}
        toolCounts={counts}
        seedCount={16}
      />,
    )
    expect(html).toContain('8/16')
    expect(html).not.toContain('1/16')
  })
})

describe('ActorProfile — hunt pack panel', () => {
  const pack = {
    sections: [
      {
        slug: 'impact',
        name: 'Impact',
        rows: [
          {
            rule: {
              id: 'shadow', title: 'Shadow copy deletion', kql: 'SecurityEvent | take 1',
              techniques: ['T1490'], dialect: 'log_analytics' as const,
              source: { kind: 'sentinel' as const, url: 'https://github.com/x', license: 'MIT', modified: '2026-06-01' },
            },
            exact: true,
            matched: ['T1490'],
          },
        ],
      },
    ],
    uncovered: ['T1486'],
    preCompromiseOmitted: 2,
    totalMatched: 1,
    overflow: 0,
  }
  const html = renderToStaticMarkup(
    <ActorProfile profile={profile} slugSet={new Set()} huntPack={pack} />,
  )

  it('renders the row with provenance, dialect tag, and collapsed KQL', () => {
    expect(html).toContain('Shadow copy deletion')
    expect(html).toContain('Microsoft Sentinel community · MIT · modified 2026-06-01')
    expect(html).toContain('Sentinel LA')
    expect(html).toContain('View KQL')
    expect(html).toContain('SecurityEvent | take 1')
  })

  it('renders the honesty framing and exactly one dialect caveat', () => {
    expect(html).toContain('not a detection guarantee')
    expect((html.match(/swap TimeGenerated/g) ?? []).length).toBe(1)
    // no sigma rules -> no DRL link
    expect(html).not.toContain('Detection Rule License')
  })

  it('renders the floor with both link targets and the pre-compromise note', () => {
    expect(html).toContain('techniques with no curated query')
    expect(html).toContain('https://attack.mitre.org/techniques/T1486/#detection')
    expect(html).toContain('SigmaHQ search (GitHub sign-in)')
    expect(html).toContain('2 pre-compromise techniques')
  })

  it('renders the explicit 0-match state (floor-only pack)', () => {
    const emptyPack = { ...pack, sections: [], totalMatched: 0 }
    const h = renderToStaticMarkup(
      <ActorProfile profile={profile} slugSet={new Set()} huntPack={emptyPack} />,
    )
    expect(h).toContain('No curated queries match this fingerprint yet')
  })

  it('is absent entirely without a huntPack (pre-deploy degrade)', () => {
    const h = renderToStaticMarkup(<ActorProfile profile={profile} slugSet={new Set()} />)
    expect(h).not.toContain('Hunt pack')
  })
})

describe('ActorProfile — tactic matrix', () => {
  const catalog = {
    tactics: {
      T1566: ['initial-access'],
      T1486: ['impact', 'defense-impairment'],
      T9999: ['not-in-order-list'],
    },
    order: [
      { slug: 'initial-access', name: 'Initial Access' },
      { slug: 'defense-impairment', name: 'Defense Impairment' },
      { slug: 'impact', name: 'Impact' },
    ],
  }
  const fp = {
    ...profile.fingerprint!,
    techniques: ['T1566', 'T1486', 'T9999', 'T0000'], // T0000 has no catalog entry
  }
  const html = renderToStaticMarkup(
    <ActorProfile
      profile={{ ...profile, fingerprint: fp }}
      slugSet={new Set()}
      tacticsCatalog={catalog}
    />,
  )

  it('groups techniques under their tactic headers, in the catalog order', () => {
    expect(html).toContain('Initial Access')
    expect(html).toContain('Defense Impairment')
    expect(html).toContain('Impact')
    expect(html.indexOf('Initial Access')).toBeLessThan(html.indexOf('Defense Impairment'))
    expect(html.indexOf('Defense Impairment')).toBeLessThan(html.indexOf('Impact'))
  })

  it('renders a multi-tactic technique under EACH tactic and states the fan-out', () => {
    // count rendered chip TEXT (>id<) — the id also echoes in href/title
    expect((html.match(/>T1486</g) ?? []).length).toBe(2)
    expect(html).toContain('4 techniques')
    expect(html).toContain('cells across')
  })

  it('never drops a technique: unknown phases + uncatalogued ids land in Other', () => {
    expect(html).toContain('Other')
    expect(html).toContain('T9999')
    expect(html).toContain('T0000')
  })

  it('falls back to the flat layout when no catalog is provided', () => {
    const flat = renderToStaticMarkup(
      <ActorProfile profile={{ ...profile, fingerprint: fp }} slugSet={new Set()} />,
    )
    expect(flat).not.toContain('Initial Access')
    expect(flat).toContain('T1566')
  })
})

describe('ActorProfile — technique names', () => {
  it('labels a technique id with its name when the catalog has it', () => {
    const html = renderToStaticMarkup(
      <ActorProfile profile={profile} slugSet={new Set()} techniqueNames={{ T1566: 'Phishing' }} />,
    )
    expect(html).toContain('T1566')
    expect(html).toContain('Phishing')
  })

  it('falls back to the bare id when no catalog (or no match) is available', () => {
    const html = renderToStaticMarkup(<ActorProfile profile={profile} slugSet={new Set()} />)
    expect(html).toContain('T1566')
    expect(html).not.toContain('Phishing')
  })
})

describe('ActorProfile — progressive disclosure restructure (N1 + N4)', () => {
  const claiming = withOverrides({
    activity: {
      sectors: [], countries: [], timeline: [], victimCount: 3, hasDigest: false,
      daily: [{ date: '2026-08-13', count: 3 }, { date: '2026-08-14', count: 0 }],
      lastClaimAt: '2026-08-13T00:00:00Z', hasLegacyDigest: false, sectorCounts: [], countryCounts: [],
    },
  })

  it('renders the jump-nav with landmark buttons for the present sections (hash-safe)', () => {
    const html = renderToStaticMarkup(<ActorProfile profile={profile} slugSet={new Set()} />)
    expect(html).toContain('aria-label="Profile sections"')
    expect(html).toContain('Fingerprint')
    // buttons, NOT #id anchors — the app is hash-routed (#g=<slug>)
    expect(html).not.toContain('href="#')
  })

  it('collapses the ATT&CK fingerprint into a <details> yet keeps its content in the DOM (SEO)', () => {
    const html = renderToStaticMarkup(<ActorProfile profile={profile} slugSet={new Set()} />)
    expect(html).toMatch(/<details[^>]*id="fingerprint"[^>]*data-collapsible/)
    // collapsed by default → no open attribute…
    expect(html).not.toMatch(/<details[^>]*id="fingerprint"[^>]*\sopen[=\s>]/)
    // …but the technique still ships to crawlers/print
    expect(html).toContain('T1566')
  })

  it('keeps leak-site activity OPEN (decision layer) — anchored, not wrapped in a <details>', () => {
    const html = renderToStaticMarkup(<ActorProfile profile={claiming} slugSet={new Set()} />)
    expect(html).toContain('id="activity"')
    expect(html).not.toMatch(/<details[^>]*id="activity"/)
    expect(html).toContain('Activity') // nav landmark label present
  })

  it('hoists the distinctive-TTP lead into the synthesis band (N4), above the collapsed matrix', () => {
    // T1566 as the sole technique with prevalence 1 → distinctive (≤3 groups)
    const html = renderToStaticMarkup(
      <ActorProfile
        profile={claiming}
        slugSet={new Set()}
        prevalence={new Map([['T1566', 1]])}
        actorCount={176}
      />,
    )
    expect(html).toContain('Distinctive TTPs')
    // the synthesis spark also renders for the claiming group
    expect(html).toContain('Recent activity')
    // the distinctive lead precedes the collapsed fingerprint section in the DOM
    expect(html.indexOf('Distinctive TTPs')).toBeLessThan(html.indexOf('id="fingerprint"'))
  })
})
