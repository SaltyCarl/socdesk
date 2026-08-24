import { describe, expect, it } from 'vitest'
import { buildProfileIndex, profileFor } from '../profiles'
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
  const p = profileFor('sandworm', data)
  it('has no fingerprint / ransomware / relations, but carries real reporting', () => {
    expect(p.fingerprint).toBeNull()
    expect(p.ransomware).toBeNull()
    expect(p.related).toEqual([])
    expect(p.reporting).toHaveLength(1)
  })
  it('strips the [Outlet] prefix and preserves the real ingested summary', () => {
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
    })
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
})
