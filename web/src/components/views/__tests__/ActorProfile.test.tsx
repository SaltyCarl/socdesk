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
