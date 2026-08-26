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
