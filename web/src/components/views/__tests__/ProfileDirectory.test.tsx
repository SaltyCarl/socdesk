import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { ProfileDirectory } from '../ProfileDirectory'
import type { ProfileIndexEntry } from '../profiles'

/** Three density tiers: a fully-enriched MITRE actor, a claims-only ransomware
 *  group with recency, and a bare entry that must render NO filler. */
const entries: ProfileIndexEntry[] = [
  {
    slug: 'axiom',
    name: 'Axiom',
    kind: 'actor',
    hasMitre: true,
    attack_id: 'G0001',
    aliases: ['Group 72'],
    blurb: 'Axiom is a suspected Chinese espionage group.',
    techniqueCount: 130,
    softwareCount: 19,
  },
  {
    slug: 'kairos',
    name: 'kairos',
    kind: 'ransomware',
    hasMitre: false,
    claimCount: 7,
    hasClaims: true,
    lastClaimAt: '2026-08-13T00:00:00Z',
  },
  { slug: 'barebones', name: 'Barebones', kind: 'malware', hasMitre: true, attack_id: 'S9999' },
]

describe('ProfileDirectory — enriched cards', () => {
  const html = renderToStaticMarkup(<ProfileDirectory entries={entries} />)

  it('renders the blurb and the technique/tool counts on an enriched card', () => {
    expect(html).toContain('Axiom is a suspected Chinese espionage group.')
    expect(html).toContain('130 techniques')
    expect(html).toContain('19 tools')
  })

  it('renders claim recency for an actively-claiming group', () => {
    expect(html).toContain('last claim')
  })

  it('renders NO filler on a bare card — no zero counts, no placeholder text', () => {
    // \b so "130 techniques" (a REAL count) can't substring-match a bare zero
    expect(html).not.toMatch(/\b0 techniques/)
    expect(html).not.toMatch(/\b0 tools/)
    // the bare card still renders its identity
    expect(html).toContain('Barebones')
  })
})
