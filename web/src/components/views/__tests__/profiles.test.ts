import { describe, expect, it } from 'vitest'
import {
  blurbOf,
  buildProfileIndex,
  busiestDay,
  cleanDescription,
  compareEntries,
  dailyClaimsFor,
  matchesFilter,
  profileFor,
  rankedCounts,
  sortComparator,
} from '../profiles'
import type { ProfileIndexEntry } from '../profiles'
import type { FeedItem, Profile, RansomIntel, RelationsPayload } from '../types'

// em-dash (U+2014) is the real separator ransomware.live uses in a single-claim
// summary ("Sector: X — Country: YY."). Written as an escape so file encoding
// can never corrupt the fixture.
const EMDASH = '—'
const single = (sector: string, country: string) =>
  `Sector: ${sector} ${EMDASH} Country: ${country}. Claim detail at the source; victim names are not republished here.`

/* ---------------- fixtures (verbatim shapes from the state files) --------- */

const actors: Profile[] = [
  {
    name: 'Axiom',
    attack_id: 'G0001',
    aliases: ['Axiom', 'Group 72'],
    description:
      '[Axiom](https://attack.mitre.org/groups/G0001) is a suspected Chinese espionage group. (Citation: Novetta 2014)',
    techniques: ['T1003', 'T1071.001'],
    software: ['Derusbi', 'Hikit'],
  },
  { name: 'Akira', attack_id: 'G1024', aliases: ['Akira'], techniques: ['T1486'], software: [] },
  {
    name: 'APT29',
    attack_id: 'G0016',
    aliases: ['APT29', 'Midnight Blizzard', 'Cozy Bear'],
    description: 'APT29 is a Russian state-sponsored group.',
    techniques: ['T1566'],
    software: ['Sliver'],
  },
  { name: 'Kimsuky', attack_id: 'G0094', aliases: ['Kimsuky'], techniques: [], software: [] },
]

const malware: Profile[] = [
  { name: 'Clop', attack_id: 'S0611', aliases: ['Clop', 'Cl0p'], techniques: ['T1486'], software: [] },
]

const feed: FeedItem[] = [
  // kairos — ransomware-only group: two singles + one digest.
  {
    id: 'r1', source: 'ransomwarelive', category: 'ransomware',
    title: 'kairos posted a new victim claim', summary: single('Manufacturing', 'US'),
    url: 'http://abcxyz.onion/claim-1', entities: { actors: ['kairos'] },
    why: ['actor: kairos'], published_at: '2026-08-12T20:00:00Z',
  },
  {
    id: 'r2', source: 'ransomwarelive', category: 'ransomware',
    title: 'kairos posted a new victim claim', summary: single('Not Found', '?'),
    url: 'https://ransomware.live', entities: { actors: ['kairos'] },
    why: ['actor: kairos'], published_at: '2026-08-12T18:00:00Z',
  },
  {
    id: 'r3', source: 'ransomwarelive', category: 'ransomware',
    title: 'kairos posted 5 victim claims', summary: 'Grouped: Healthcare, Technology, Not Found',
    url: 'http://abcxyz.onion/digest', entities: { actors: ['kairos'] },
    why: ['5 claims in window'], grouped: 5, published_at: '2026-08-13T00:00:00Z',
  },
  // akira — BOTH a MITRE actor AND an active ransomware group.
  {
    id: 'r4', source: 'ransomwarelive', category: 'ransomware',
    title: 'akira posted a new victim claim', summary: single('Energy & Utilities', 'IT'),
    url: 'http://abcxyz.onion/claim-a', entities: { actors: ['akira'] },
    why: ['actor: akira'], published_at: '2026-08-12T10:00:00Z',
  },
  // clop — a MITRE software name that ALSO posts leak-site claims.
  {
    id: 'r5', source: 'ransomwarelive', category: 'ransomware',
    title: 'clop posted a new victim claim', summary: single('Professional Services', 'DE'),
    url: 'http://abcxyz.onion/claim-c', entities: { actors: ['clop'] },
    why: ['actor: clop'], published_at: '2026-08-12T09:00:00Z',
  },
  // Sandworm — a named APT with reporting but NO ATT&CK profile / alias match.
  {
    id: 'a1', source: 'rss', category: 'apt',
    title: '[BleepingComputer] Sandworm hackers target IT pros with trojanized software',
    summary: 'Real ingested prose about the Sandworm campaign.',
    url: 'https://bleepingcomputer.com/sandworm', entities: { actors: ['Sandworm'] },
    published_at: '2026-08-11T12:00:00Z',
  },
  // Midnight Blizzard — reported by its ALIAS; resolves to APT29's fingerprint.
  {
    id: 'a2', source: 'rss', category: 'apt',
    title: '[The Hacker News] Midnight Blizzard targets diplomats',
    summary: 'Real ingested prose about Midnight Blizzard.',
    url: 'https://thehackernews.com/mb', entities: { actors: ['Midnight Blizzard'] },
    published_at: '2026-08-10T12:00:00Z',
  },
]

const relations: RelationsPayload = {
  nodes: [
    { id: 'actor:Axiom', type: 'actor', name: 'Axiom', degree: 1 },
    { id: 'malware:Hikit', type: 'malware', name: 'Hikit', degree: 1 },
    { id: 'actor:APT29', type: 'actor', name: 'APT29', degree: 1 },
    { id: 'malware:Sliver', type: 'malware', name: 'Sliver', degree: 1 },
  ],
  edges: [
    { type: 'uses', src: 'actor:Axiom', dst: 'malware:Hikit', weight: 3, evidence: ['attack'] },
    { type: 'uses', src: 'actor:APT29', dst: 'malware:Sliver', weight: 2, evidence: ['attack'] },
  ],
}

const data = { actors, malware, feed, relations, intel: [] as RansomIntel[] }

/* ---------------- profileFor: the fusion ---------------------------------- */

describe('profileFor — MITRE-only actor', () => {
  const p = profileFor('axiom', data)
  it('resolves the ATT&CK fingerprint with a groups deep-link', () => {
    expect(p.name).toBe('Axiom')
    expect(p.fingerprint).not.toBeNull()
    expect(p.fingerprint?.kind).toBe('actor')
    expect(p.fingerprint?.attack_id).toBe('G0001')
    expect(p.fingerprint?.attackUrl).toBe('https://attack.mitre.org/groups/G0001/')
  })
  it('strips ATT&CK markdown from the description and drops the self-alias', () => {
    expect(p.fingerprint?.description).toBe('Axiom is a suspected Chinese espionage group.')
    expect(p.fingerprint?.description).not.toContain('Citation')
    expect(p.fingerprint?.description).not.toContain('](')
    expect(p.fingerprint?.aliases).toEqual(['Group 72'])
  })
  it('has no ransomware / reporting, but resolves ATT&CK relations', () => {
    expect(p.ransomware).toBeNull()
    expect(p.reporting).toEqual([])
    expect(p.related.map((r) => r.node.name)).toContain('Hikit')
  })
})

describe('profileFor — ransomware-only group (honest null fingerprint)', () => {
  const p = profileFor('kairos', data)
  it('has NO ATT&CK fingerprint and NO relations node (not synthesised)', () => {
    expect(p.fingerprint).toBeNull()
    expect(p.related).toEqual([])
    expect(p.name).toBe('kairos')
  })
  it('sums claims with the board parser (1 + 1 + 5 = 7)', () => {
    expect(p.ransomware?.totalClaims).toBe(7)
    expect(p.ransomware?.items).toHaveLength(3)
  })
  it('parses sectors across singles + digest, dropping the "Not Found" sentinel', () => {
    const s = p.ransomware?.sectors ?? []
    expect(s).toContain('Manufacturing')
    expect(s).toContain('Healthcare')
    expect(s).toContain('Technology')
    expect(s).not.toContain('Not Found')
  })
  it('digest DROPS country: only the single-claim country survives, "?" excluded', () => {
    expect(p.ransomware?.countries).toEqual(['US'])
  })
  it('orders claim items newest-first and keeps the raw .onion url', () => {
    expect(p.ransomware?.items[0].id).toBe('r3') // 2026-08-13
    expect(p.ransomware?.items[0].grouped).toBe(5)
    expect(p.ransomware?.items[0].country).toBeUndefined() // digest → no country
    // newest-first: r3 (08-13) · r1 (08-12 20:00) · r2 (08-12 18:00)
    expect(p.ransomware?.items[1].url).toBe('http://abcxyz.onion/claim-1')
    expect(p.ransomware?.items[1].country).toBe('US')
  })
})

describe('profileFor — both kinds merged (Akira: actor + ransomware)', () => {
  const p = profileFor('akira', data)
  it('carries the actor fingerprint AND the leak-site activity together', () => {
    expect(p.name).toBe('Akira')
    expect(p.fingerprint?.attack_id).toBe('G1024')
    expect(p.ransomware?.totalClaims).toBe(1)
    expect(p.ransomware?.sectors).toEqual(['Energy & Utilities'])
    expect(p.ransomware?.countries).toEqual(['IT'])
  })
  it('activity.hasDigest is false for a group with only single claims', () => {
    // Akira has one single claim, no digest → the "digest omits country"
    // caveat must NOT render (gated on hasDigest).
    expect(p.activity?.hasDigest).toBe(false)
  })
})

describe('cleanDescription — strips ATT&CK citation noise', () => {
  it('strips a whole (Citation: …) marker', () => {
    expect(cleanDescription('Foo bar. (Citation: Novetta 2014) Baz.')).toBe('Foo bar. Baz.')
  })
  it('strips a trailing citation truncated mid-token (no closing paren)', () => {
    // ATT&CK descriptions are length-truncated at ingest, which can cut mid
    // citation and leak a dangling "(Citation: Tren" the closed-paren rule can't
    // match — the scraper artifact the design review flagged as an AI-slop tell.
    expect(cleanDescription('…healthcare sectors.(Citation: Tren')).toBe('…healthcare sectors.')
  })
  it('strips a citation cut one char BEFORE the colon (live APT38 shape)', () => {
    expect(cleanDescription('…have been destructive.(Citation')).toBe('…have been destructive.')
  })
  it('keeps the alias text of a link cut mid-url (live APT29 shape)', () => {
    expect(
      cleanDescription('…the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C'),
    ).toBe('…the SolarWinds Compromise')
  })
  it('keeps the alias text of a link cut between ] and (', () => {
    expect(cleanDescription('…used [Cobalt Strike]')).toBe('…used Cobalt Strike')
  })
  it('drops a bare "[text" stub opened just before the cut', () => {
    expect(cleanDescription('…deployed tooling including [Mimika')).toBe(
      '…deployed tooling including',
    )
  })
})

describe('profileFor — activity.hasDigest true when a digest is present', () => {
  it('kairos (2 singles + 1 digest) flags hasDigest', () => {
    // Gates the country caveat on a REAL digest, so the honesty note is never false.
    expect(profileFor('kairos', data).activity?.hasDigest).toBe(true)
  })
})

describe('profileFor — malware-name group (Clop: software + ransomware)', () => {
  const p = profileFor('clop', data)
  it('resolves the software fingerprint with a software deep-link', () => {
    expect(p.fingerprint?.kind).toBe('malware')
    expect(p.fingerprint?.attackUrl).toBe('https://attack.mitre.org/software/S0611/')
    expect(p.ransomware?.totalClaims).toBe(1)
  })
})

describe('profileFor — reporting-only APT (Sandworm)', () => {
  it('has no fingerprint / ransomware / relations, and reportsFor GATES its reporting: not an established entity, not trackedActors', () => {
    const p = profileFor('sandworm', data)
    expect(p.fingerprint).toBeNull()
    expect(p.ransomware).toBeNull()
    expect(p.related).toEqual([])
    expect(p.reporting).toEqual([])
  })
  it('surfaces reporting once the caller opts it in via trackedActors, preserving [Outlet]-strip + real summary', () => {
    const p = profileFor('sandworm', { ...data, trackedActors: new Set(['sandworm']) })
    expect(p.reporting).toHaveLength(1)
    expect(p.reporting[0].outlet).toBe('BleepingComputer')
    expect(p.reporting[0].title).toBe('Sandworm hackers target IT pros with trojanized software')
    expect(p.reporting[0].summary).toBe('Real ingested prose about the Sandworm campaign.')
  })
})

describe('profileFor — alias-reported actor (Midnight Blizzard → APT29)', () => {
  const p = profileFor('midnight blizzard', data)
  it('resolves the fingerprint by alias and relations by the canonical name', () => {
    expect(p.name).toBe('APT29')
    expect(p.fingerprint?.attack_id).toBe('G0016')
    expect(p.reporting).toHaveLength(1)
    expect(p.related.map((r) => r.node.name)).toContain('Sliver')
  })
})

describe('profileFor — empty slug (directory sentinel)', () => {
  it('returns an all-empty result, never a fabricated one', () => {
    const p = profileFor('', data)
    expect(p).toEqual({
      slug: '', name: '', fingerprint: null, ransomware: null, reporting: [], related: [], intel: null,
      claimedVictims: [], activity: null, associatedMalware: [],
    })
  })
})

/* ---------------- associatedMalware: ATT&CK software + feed co-occurrence -- */

describe('profileFor — associatedMalware: ATT&CK software + feed co-occurrence, deduped', () => {
  it('unions ATT&CK software with feed-entity malware, deduping case-insensitively with ATT&CK casing preferred, sorted', () => {
    const coOccur: FeedItem[] = [
      {
        id: 'm1', source: 'ransomwarelive', category: 'ransomware',
        title: 'axiom posted a new victim claim', summary: 'n/a', url: 'http://x.onion/m1',
        entities: { actors: ['Axiom'], malware: ['derusbi', 'Cobalt Strike'] },
        published_at: '2026-08-20T00:00:00Z',
      },
    ]
    const p = profileFor('axiom', { ...data, feed: [...data.feed, ...coOccur] })
    // ATT&CK software (Axiom fixture): Derusbi, Hikit. Feed adds a lowercase
    // 'derusbi' dupe (ATT&CK casing wins) + a genuinely new 'Cobalt Strike'.
    expect(p.associatedMalware).toEqual(['Cobalt Strike', 'Derusbi', 'Hikit'])
  })

  it('is honest-empty when neither ATT&CK software nor feed co-occurrence names anything', () => {
    const p = profileFor('kimsuky', data)
    expect(p.associatedMalware).toEqual([])
  })

  it('does not surface feed-co-occurrence malware for a common-word slug not established', () => {
    // Same doctrine as reportsFor: a bare feed mention of an unestablished slug
    // (no fingerprint/intel/claims) must NOT manufacture malware chips, even when
    // the item carries entities.malware. "Play" (a "Google Play" mention) is the
    // canonical false-positive.
    const feed: FeedItem[] = [
      { id: 'p'.repeat(40), source: 'rss', category: 'apt', title: 'Google Play update',
        summary: '', url: '', entities: { actors: ['Play'], malware: ['Cobalt Strike'] },
        published_at: '2026-08-24T00:00:00Z' },
    ]
    const p = profileFor('play', { actors: [], malware: [], feed, relations: null, intel: [], trackedActors: new Set() })
    expect(p.associatedMalware).toEqual([])
  })
})

/* ---------------- buildProfileIndex: the directory ------------------------ */

describe('buildProfileIndex — union + dedup + merged flags', () => {
  const index = buildProfileIndex(actors, malware, feed, [])
  const by = (slug: string) => index.find((e) => e.slug === slug)

  it('unions MITRE actors, MITRE software, ransomware groups + named actors', () => {
    expect(by('axiom')?.kind).toBe('actor')
    expect(by('clop')?.kind).toBe('malware')
    expect(by('kairos')?.kind).toBe('ransomware')
    expect(by('sandworm')?.kind).toBe('actor')
  })

  it('merges flags for a both-kinds group (Akira keeps actor id + gains claims)', () => {
    const akira = by('akira')
    expect(akira?.kind).toBe('actor')
    expect(akira?.hasMitre).toBe(true)
    expect(akira?.attack_id).toBe('G1024')
    expect(akira?.claimCount).toBe(1)
  })

  it('a malware-name group keeps kind=malware but gains its claim tally', () => {
    const clop = by('clop')
    expect(clop?.hasMitre).toBe(true)
    expect(clop?.claimCount).toBe(1)
  })

  it('a leak-site-only group carries its summed claims and hasMitre=false', () => {
    expect(by('kairos')?.claimCount).toBe(7)
    expect(by('kairos')?.hasMitre).toBe(false)
  })

  it('resolves hasMitre via ALIAS for a reported handle (Midnight Blizzard)', () => {
    const mb = by('midnight blizzard')
    expect(mb?.hasMitre).toBe(true)
    expect(mb?.attack_id).toBe('G0016')
  })

  it('a named APT with no ATT&CK match is honestly hasMitre=false (Sandworm)', () => {
    expect(by('sandworm')?.hasMitre).toBe(false)
    expect(by('sandworm')?.attack_id).toBeUndefined()
  })

  it('does not duplicate a slug', () => {
    const slugs = index.map((e) => e.slug)
    expect(new Set(slugs).size).toBe(slugs.length)
  })
})

describe('buildProfileIndex — card enrichment (blurb / counts / recency)', () => {
  const index = buildProfileIndex(actors, malware, feed, [])
  const by = (slug: string) => index.find((e) => e.slug === slug)

  it('carries a cleaned blurb + technique/software counts from the backing profile', () => {
    const axiom = by('axiom')
    expect(axiom?.blurb).toBe('Axiom is a suspected Chinese espionage group.')
    expect(axiom?.techniqueCount).toBe(2)
    expect(axiom?.softwareCount).toBe(2)
  })

  it('omits blurb and counts when the profile has none (no filler, no zeros)', () => {
    const kimsuky = by('kimsuky')
    expect(kimsuky?.blurb).toBeUndefined()
    expect(kimsuky?.techniqueCount).toBeUndefined()
    expect(kimsuky?.softwareCount).toBeUndefined()
  })

  it('carries the NEWEST claim timestamp for an actively-claiming group', () => {
    // kairos posts r1 (12T20), r2 (12T18), r3 (13T00) — newest wins.
    expect(by('kairos')?.lastClaimAt).toBe('2026-08-13T00:00:00Z')
  })

  it('threads enrichment through the alias-resolved reporting pass (Midnight Blizzard → APT29)', () => {
    const mb = by('midnight blizzard')
    expect(mb?.blurb).toBe('APT29 is a Russian state-sponsored group.')
    expect(mb?.techniqueCount).toBe(1)
    expect(mb?.softwareCount).toBe(1)
  })
})

describe('buildProfileIndex — name-only coverage layer', () => {
  const index = buildProfileIndex(actors, malware, feed, [], ['Nitrogen', 'kairos', 'Akira', ''])

  it('adds an unlisted tracked group as a nameOnly ransomware entry', () => {
    const n = index.find((e) => e.slug === 'nitrogen')
    expect(n).toMatchObject({ name: 'Nitrogen', kind: 'ransomware', hasMitre: false, nameOnly: true })
  })

  it('never overrides a substantive entry (active group / MITRE actor win)', () => {
    // kairos posts claims; akira is a MITRE actor — neither becomes nameOnly.
    expect(index.find((e) => e.slug === 'kairos')?.nameOnly).toBeUndefined()
    expect(index.find((e) => e.slug === 'kairos')?.claimCount).toBe(7)
    expect(index.find((e) => e.slug === 'akira')?.kind).toBe('actor')
    expect(index.find((e) => e.slug === 'akira')?.nameOnly).toBeUndefined()
  })

  it('skips empty names and never duplicates a slug', () => {
    const slugs = index.map((e) => e.slug)
    expect(new Set(slugs).size).toBe(slugs.length)
    expect(slugs).not.toContain('')
  })
})

describe('compareEntries + matchesFilter — coverage-layer ranking & visibility', () => {
  const nameOnly: ProfileIndexEntry = {
    slug: 'aaa-crew', name: 'AAA Crew', kind: 'ransomware', hasMitre: false, nameOnly: true,
  }
  const active: ProfileIndexEntry = {
    slug: 'kairos', name: 'kairos', kind: 'ransomware', hasMitre: false, claimCount: 7,
  }
  const seededQuiet: ProfileIndexEntry = {
    slug: 'quiet', name: 'Quiet', kind: 'ransomware', hasMitre: false, hasIntel: true,
  }
  const actor: ProfileIndexEntry = { slug: 'apt1', name: 'APT1', kind: 'actor', hasMitre: true }

  it('ranks the nameOnly tier LAST despite alphabetical advantage', () => {
    const sorted = [nameOnly, active, seededQuiet, actor].sort(compareEntries)
    expect(sorted[0].slug).toBe('kairos') // claims outrank all
    expect(sorted[sorted.length - 1].slug).toBe('aaa-crew') // nameOnly last
  })

  it('the Ransomware chip shows kind=ransomware entries even without claims', () => {
    // Regression: the old predicate (claimCount != null) hid seeded-quiet
    // groups and would have hidden the whole coverage layer.
    expect(matchesFilter(nameOnly, 'ransomware')).toBe(true)
    expect(matchesFilter(seededQuiet, 'ransomware')).toBe(true)
    expect(matchesFilter(active, 'ransomware')).toBe(true)
    expect(matchesFilter(actor, 'ransomware')).toBe(false)
  })
})

describe('sortComparator — directory triage sorts (nulls-last, stable)', () => {
  const e = (over: Partial<ProfileIndexEntry> & { slug: string; name: string }): ProfileIndexEntry => ({
    kind: 'ransomware', hasMitre: false, ...over,
  })
  const hi = e({ slug: 'hi', name: 'Hi', claimCount: 7, techniqueCount: 130, lastClaimAt: '2026-08-13T00:00:00Z', usedByCount: 51 })
  const mid = e({ slug: 'mid', name: 'Mid', claimCount: 2, techniqueCount: 2, lastClaimAt: '2026-07-01T00:00:00Z', usedByCount: 4 })
  const bare = e({ slug: 'bare', name: 'Bare' }) // no claimCount / techniqueCount / lastClaimAt

  const order = (sort: Parameters<typeof sortComparator>[0], filter: Parameters<typeof sortComparator>[1] = 'all') =>
    [bare, mid, hi].sort(sortComparator(sort, filter)).map((x) => x.slug)

  it('claims: higher claimCount first, absent count LAST', () => {
    expect(order('claims')).toEqual(['hi', 'mid', 'bare'])
  })

  it('recent: newer lastClaimAt first, no-date entry LAST', () => {
    expect(order('recent')).toEqual(['hi', 'mid', 'bare'])
  })

  it('techniques: higher techniqueCount first, absent count LAST', () => {
    expect(order('techniques')).toEqual(['hi', 'mid', 'bare'])
  })

  it('name: pure alphabetical, independent of every count', () => {
    expect(order('name')).toEqual(['bare', 'hi', 'mid'])
  })

  it('claims ties break by name (stable, total order)', () => {
    const zed = e({ slug: 'zed', name: 'Zed', claimCount: 5 })
    const abe = e({ slug: 'abe', name: 'Abe', claimCount: 5 })
    expect([zed, abe].sort(sortComparator('claims', 'all')).map((x) => x.slug)).toEqual(['abe', 'zed'])
  })

  it('relevance + malware filter reproduces the used-by reverse-index rank', () => {
    // hi(51) > mid(4) > bare(0) — matches the directory malware lens default.
    expect(order('relevance', 'malware')).toEqual(['hi', 'mid', 'bare'])
  })

  it('relevance + non-malware filter is identical to compareEntries', () => {
    const set = [bare, mid, hi]
    const viaRelevance = [...set].sort(sortComparator('relevance', 'all')).map((x) => x.slug)
    const viaCompare = [...set].sort(compareEntries).map((x) => x.slug)
    expect(viaRelevance).toEqual(viaCompare)
  })
})

describe('dailyClaimsFor — the 31-day daily claim model', () => {
  const ANCHOR = '2026-08-14T12:00:00Z' // window = 2026-07-15 .. 2026-08-14

  it('distributes a digest by its carried claims[].date, not the digest date', () => {
    const digest: FeedItem = {
      id: 'd1', source: 'ransomwarelive', category: 'ransomware',
      title: 'g posted 3 victim claims', summary: 'Grouped: X', url: 'https://x',
      entities: { actors: ['g'] }, grouped: 3, published_at: '2026-08-14T00:00:00Z',
      claims: [
        { victim: 'A', date: '2026-08-10T05:00:00Z' },
        { victim: 'B', date: '2026-08-10T09:00:00Z' },
        { victim: 'C', date: '2026-08-12T09:00:00Z' },
      ],
    }
    const { daily } = dailyClaimsFor('g', [digest], ANCHOR)
    const by = Object.fromEntries(daily.map((d) => [d.date, d.count]))
    expect(by['2026-08-10']).toBe(2)
    expect(by['2026-08-12']).toBe(1)
    expect(by['2026-08-14']).toBe(0) // nothing dumped on the digest's own day
    expect(daily).toHaveLength(31)
    expect(daily[0].date).toBe('2026-07-15')
  })

  it('puts the remainder (tally − ALL carried claims) on the digest day — undated claims never double-count', () => {
    const digest: FeedItem = {
      id: 'd2', source: 'ransomwarelive', category: 'ransomware',
      title: 'g posted 4 victim claims', summary: 'Grouped: X', url: 'https://x',
      entities: { actors: ['g'] }, grouped: 4, published_at: '2026-08-13T00:00:00Z',
      claims: [
        { victim: 'A', date: '2026-08-11T00:00:00Z' },
        { victim: 'B' }, // undated — rides the digest day via the claims loop
      ],
    }
    const { daily } = dailyClaimsFor('g', [digest], ANCHOR)
    const total = daily.reduce((s, d) => s + d.count, 0)
    expect(total).toBe(4) // 1 dated + 1 undated + remainder 2, never 5
    const by = Object.fromEntries(daily.map((d) => [d.date, d.count]))
    expect(by['2026-08-11']).toBe(1)
    expect(by['2026-08-13']).toBe(3) // undated claim + remainder 2
  })

  it('clamps out-of-window claim dates into the edge cells (never lost)', () => {
    const digest: FeedItem = {
      id: 'd3', source: 'ransomwarelive', category: 'ransomware',
      title: 'g posted 2 victim claims', summary: 'Grouped: X', url: 'https://x',
      entities: { actors: ['g'] }, grouped: 2, published_at: '2026-08-14T00:00:00Z',
      claims: [
        { victim: 'Old', date: '2026-06-01T00:00:00Z' },   // far older → oldest cell
        { victim: 'Future', date: '2026-09-01T00:00:00Z' }, // future → newest cell
      ],
    }
    const { daily } = dailyClaimsFor('g', [digest], ANCHOR)
    expect(daily[0].count).toBe(1)
    expect(daily[daily.length - 1].count).toBe(1)
    expect(daily.reduce((s, d) => s + d.count, 0)).toBe(2)
  })

  it('flags a legacy claims[]-less digest and lands its tally on the digest day', () => {
    const legacy: FeedItem = {
      id: 'd4', source: 'ransomwarelive', category: 'ransomware',
      title: 'g posted 5 victim claims', summary: 'Grouped: X', url: 'https://x',
      entities: { actors: ['g'] }, grouped: 5, published_at: '2026-08-01T00:00:00Z',
    }
    const { daily, hasLegacyDigest } = dailyClaimsFor('g', [legacy], ANCHOR)
    expect(hasLegacyDigest).toBe(true)
    expect(daily.find((d) => d.date === '2026-08-01')?.count).toBe(5)
  })

  it('reconciles with the fixture group (kairos: 2 singles + a 5-digest = 7)', () => {
    const { daily, lastClaimAt } = dailyClaimsFor('kairos', feed, '2026-08-14T00:00:00Z')
    expect(daily.reduce((s, d) => s + d.count, 0)).toBe(7)
    expect(lastClaimAt).toBe('2026-08-13T00:00:00Z')
  })
})

describe('rankedCounts + busiestDay', () => {
  it('ranks desc with label tiebreak and skips empties', () => {
    expect(rankedCounts(['A', 'B', 'A', undefined, 'C', 'B', 'A'])).toEqual([
      { label: 'A', count: 3 },
      { label: 'B', count: 2 },
      { label: 'C', count: 1 },
    ])
  })
  it('busiestDay needs count ≥ 2 and resolves ties to the most recent day', () => {
    expect(busiestDay([{ date: '2026-08-01', count: 1 }])).toBeNull()
    expect(
      busiestDay([
        { date: '2026-08-01', count: 3 },
        { date: '2026-08-05', count: 3 },
        { date: '2026-08-06', count: 1 },
      ]),
    ).toEqual({ date: '2026-08-05', count: 3 })
  })
})

describe('profileFor — activity carries the daily model + singles-only counts', () => {
  const p = profileFor('kairos', { ...data, generatedAt: '2026-08-14T00:00:00Z' })
  it('daily sums to the window tally', () => {
    expect(p.activity?.daily.reduce((s, d) => s + d.count, 0)).toBe(7)
  })
  it('sectorCounts count SINGLE claims only (digest sectors stay in the coverage set)', () => {
    // kairos singles: Manufacturing ×1 (the "Not Found" single is sentinel-dropped);
    // the digest's Healthcare/Technology appear in `sectors` but never as counts.
    expect(p.activity?.sectorCounts).toEqual([{ label: 'Manufacturing', count: 1 }])
    expect(p.activity?.sectors).toContain('Healthcare')
  })
})

describe('blurbOf — word-boundary hard-cap, never a sentence cut', () => {
  it('passes a short cleaned description through unchanged', () => {
    expect(blurbOf('A short description.')).toBe('A short description.')
  })
  it('returns undefined for empty/absent text', () => {
    expect(blurbOf('')).toBeUndefined()
    expect(blurbOf(undefined)).toBeUndefined()
  })
  it('does NOT stop at an abbreviation period ("U.S.") — caps at a word boundary instead', () => {
    // Real ATT&CK failure shape: a period inside "U.S." well before char 160.
    const long =
      'APT17 is a China-based threat group that has conducted network intrusions against U.S. government entities, the defense industry, law firms, information technology companies, mining companies, and non-government organizations.'
    const b = blurbOf(long)!
    expect(b.endsWith('…')).toBe(true)
    expect(b.length).toBeLessThanOrEqual(161)
    // proof it sailed past "U.S." rather than sentence-cutting there
    expect(b.length).toBeGreaterThan('APT17 is a China-based threat group that has conducted network intrusions against U.S.'.length)
    // never cuts mid-word: the char before the ellipsis ends a whole word
    expect(long.startsWith(b.slice(0, -1))).toBe(true)
    expect(long[b.length - 1]).toBe(' ')
  })
})

/* ---------------- intel fusion: curated CISA seed ---------------------- */

const INTEL: RansomIntel[] = [
  { slug: 'akira', name: 'Akira', aliases: ['Storm-1567'],
    initial_access_cves: ['CVE-2023-20269'],
    advisory: { id: 'AA24-109A', url: 'https://www.cisa.gov/x' },
    tools: ['Rclone'], ransom_note: ['akira_readme.txt'], extensions: ['.akira'], raas: true },
]

describe('intel fusion', () => {
  it('attaches the seed entry to a matching slug', () => {
    const p = profileFor('akira', { actors: [], malware: [], feed: [], relations: null, intel: INTEL })
    expect(p.intel?.advisory?.id).toBe('AA24-109A')
    expect(p.intel?.initial_access_cves).toEqual(['CVE-2023-20269'])
  })
  it('resolves the seed by alias', () => {
    const p = profileFor('storm-1567', { actors: [], malware: [], feed: [], relations: null, intel: INTEL })
    expect(p.intel?.name).toBe('Akira')
  })
  it('is null for an unseeded group', () => {
    const p = profileFor('nitrogen', { actors: [], malware: [], feed: [], relations: null, intel: INTEL })
    expect(p.intel).toBeNull()
  })
  it('lists a seeded-but-quiet group in the directory with hasIntel', () => {
    const idx = buildProfileIndex([], [], [], INTEL)
    const akira = idx.find((e) => e.slug === 'akira')
    expect(akira?.hasIntel).toBe(true)
  })

  it('merges onto an existing actor row rather than duplicating it (existing.hasIntel branch)', () => {
    const akiraActor: Profile[] = [
      { name: 'Akira', attack_id: 'G1024', aliases: [], description: '', techniques: [], software: [] },
    ]
    const idx = buildProfileIndex(akiraActor, [], [], INTEL)
    const akiraEntries = idx.filter((e) => e.slug === 'akira')
    expect(akiraEntries).toHaveLength(1)
    expect(akiraEntries[0].kind).toBe('actor')
    expect(akiraEntries[0].hasMitre).toBe(true)
    expect(akiraEntries[0].hasIntel).toBe(true)
  })

  it('flags hasClaims for a group with leak-site posts, and leaves it unset for a claim-free group', () => {
    const idx = buildProfileIndex(actors, malware, feed, [])
    expect(idx.find((e) => e.slug === 'kairos')?.hasClaims).toBe(true)
    expect(idx.find((e) => e.slug === 'axiom')?.hasClaims).toBeUndefined()
  })
})

/* ---------------- fusion: claimed victims + activity + reportsFor gate ---- */

describe('profileFor — claimed-victim list + activity aggregates', () => {
  it('builds an attributed claimed-victim list for a ransomware group', () => {
    const feed = [{ id:'a'.repeat(40), source:'ransomwarelive', category:'ransomware',
      title:'akira posted a new victim claim', summary:'Unverified claim…', url:'http://x.onion/a',
      victim:'Furnished Quarters', domain:'furnishedquarters.com',
      entities:{actors:['akira'],malware:[],vendors:[],cves:[]}, published_at:'2026-08-24T00:00:00Z' }]
    const p = profileFor('akira', { actors:[], malware:[], feed, relations:null, intel:[] })
    expect(p.claimedVictims[0]).toMatchObject({ victim:'Furnished Quarters', domain:'furnishedquarters.com', claimUrl:'http://x.onion/a' })
    expect(p.activity?.victimCount).toBe(1)
  })
  it('does not surface reportsFor for a common-word actor not in the dictionary', () => {
    // "play" as a bare RSS mention must not become a report unless dictionary-gated
    const feed = [{ id:'b'.repeat(40), source:'rss', category:'apt', title:'Google Play update', url:'', summary:'', entities:{actors:['Play'],malware:[],vendors:[],cves:[]}, published_at:'2026-08-24T00:00:00Z' }]
    const p = profileFor('play', { actors:[], malware:[], feed, relations:null, intel:[], trackedActors:new Set() })
    expect(p.reporting.length).toBe(0)
  })
  it('expands a digest that carries claims[] to one ClaimedVictim per claim — the busy-group fix', () => {
    // A busy group's digest inherits no scalar victim/domain (Finding #1) —
    // its claims[] is what the profile must expand, newest-first.
    const digestFeed: FeedItem[] = [{
      id: 'd'.repeat(40), source: 'ransomwarelive', category: 'ransomware',
      title: 'qilin posted 17 victim claims', summary: 'Grouped: Manufacturing, Retail',
      url: 'http://abcxyz.onion/digest', entities: { actors: ['qilin'] },
      why: ['17 claims in window'], grouped: 17, published_at: '2026-08-20T00:00:00Z',
      claims: [
        { victim: 'A Corp', domain: 'acorp.example', date: '2026-08-19T00:00:00Z', url: 'http://abcxyz.onion/claim-a' },
        { victim: 'B Corp', date: '2026-08-20T00:00:00Z', url: 'http://abcxyz.onion/claim-b' },
        { victim: 'C Corp', domain: 'ccorp.example', date: '2026-08-18T00:00:00Z', url: 'http://abcxyz.onion/claim-c' },
      ],
    }]
    const p = profileFor('qilin', { actors: [], malware: [], feed: digestFeed, relations: null, intel: [] })
    expect(p.claimedVictims).toHaveLength(3)
    expect(p.claimedVictims.map((v) => v.victim)).toEqual(['B Corp', 'A Corp', 'C Corp']) // newest-first
    expect(p.claimedVictims[0]).toMatchObject({ id: `${'d'.repeat(40)}:1`, victim: 'B Corp', claimUrl: 'http://abcxyz.onion/claim-b' })
    expect(p.claimedVictims[0].domain).toBeUndefined() // per-claim domain omitted when the claim has none
    expect(p.claimedVictims[1]).toMatchObject({ victim: 'A Corp', domain: 'acorp.example', sector: undefined, country: undefined })
  })
  it('honestly excludes a digest with NO claims[] (every collapsed item lacked a victim)', () => {
    const digestFeed: FeedItem[] = [{
      id: 'e'.repeat(40), source: 'ransomwarelive', category: 'ransomware',
      title: 'nomad posted 4 victim claims', summary: 'Grouped: Retail',
      url: 'http://abcxyz.onion/digest2', entities: { actors: ['nomad'] },
      why: ['4 claims in window'], grouped: 4, published_at: '2026-08-20T00:00:00Z',
    }]
    const p = profileFor('nomad', { actors: [], malware: [], feed: digestFeed, relations: null, intel: [] })
    expect(p.claimedVictims).toEqual([])
  })
})

describe('profileFor — activity.timeline: deterministic weekly buckets', () => {
  it('buckets claims across two UTC weeks into two timeline entries with correct per-bucket counts', () => {
    const weeklyFeed: FeedItem[] = [
      // Mon 2026-08-10 and Wed 2026-08-12 both fall in the UTC week starting
      // Monday 2026-08-10 — same bucket.
      { id: 'w1', source: 'ransomwarelive', category: 'ransomware',
        title: 'nyx posted a new victim claim', summary: single('Retail', 'US'),
        url: 'http://x.onion/w1', entities: { actors: ['nyx'] }, published_at: '2026-08-10T09:00:00Z' },
      { id: 'w2', source: 'ransomwarelive', category: 'ransomware',
        title: 'nyx posted a new victim claim', summary: single('Retail', 'US'),
        url: 'http://x.onion/w2', entities: { actors: ['nyx'] }, published_at: '2026-08-12T09:00:00Z' },
      // Wed 2026-08-19 falls in the NEXT UTC week (starting 2026-08-17) —
      // a separate bucket, and it's a digest of 3 claims.
      { id: 'w3', source: 'ransomwarelive', category: 'ransomware',
        title: 'nyx posted 3 victim claims', summary: 'Grouped: Retail, Healthcare',
        url: 'http://x.onion/w3', entities: { actors: ['nyx'] }, grouped: 3,
        why: ['3 claims in window'], published_at: '2026-08-19T09:00:00Z' },
    ]
    const p = profileFor('nyx', { actors: [], malware: [], feed: weeklyFeed, relations: null, intel: [] })
    expect(p.activity?.timeline).toHaveLength(2)
    expect(p.activity?.timeline[0]).toEqual({ week: '2026-08-10', count: 2 })
    expect(p.activity?.timeline[1]).toEqual({ week: '2026-08-17', count: 3 })
    expect(p.activity?.victimCount).toBe(5)
  })
})
