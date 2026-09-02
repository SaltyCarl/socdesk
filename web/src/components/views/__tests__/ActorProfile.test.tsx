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
