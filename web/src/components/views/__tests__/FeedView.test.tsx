import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { FeedView } from '../FeedView'
import type { FeedItem } from '../types'

/** A KEV vuln with a clearnet advisory — highest score, so it becomes the
 *  featured lead and its clearnet URL stays a live link. */
const vuln: FeedItem = {
  id: 'v1',
  source: 'kev',
  category: 'vulnerability',
  title: 'KEV: CVE-2026-9999 — Example RCE',
  summary: 'Actively exploited.',
  url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
  entities: { cves: ['CVE-2026-9999'] },
  score: 95,
  why: ['KEV-listed'],
  published_at: '2026-08-25T00:00:00Z',
}

/** A ransomware.live leak-site claim naming a victim — the .onion url must
 *  NEVER become a link; the row is victim-first with a favicon + provenance. */
const claim: FeedItem = {
  id: 'r1',
  source: 'ransomwarelive',
  category: 'ransomware',
  title: 'qilin posted a new victim claim',
  summary: 'Unverified claim by qilin, per its leak site. Sector: Manufacturing — Country: US.',
  url: 'http://ijzn3sicrqewpg.onion/site/blog?uuid=abc',
  entities: { actors: ['qilin'] },
  victim: 'Acme Corporation',
  domain: 'acme.com',
  score: 80,
  published_at: '2026-08-24T00:00:00Z',
}

/** A second, lower-scored vuln so one renders as a section ROW (the lead is
 *  excluded from its own section) — exercises the CVE left-rail. */
const vulnRow: FeedItem = {
  id: 'v2',
  source: 'kev',
  category: 'vulnerability',
  title: 'KEV: CVE-2026-1111 — Example Overflow',
  summary: 'Also exploited.',
  url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
  entities: { cves: ['CVE-2026-1111'] },
  score: 70,
  why: ['KEV-listed'],
  published_at: '2026-08-23T00:00:00Z',
}

describe('FeedView — leak-site claim rows', () => {
  const html = renderToStaticMarkup(
    <FeedView items={[vuln, vulnRow, claim]} generatedAt="2026-08-25T00:00:00Z" />,
  )

  it('never emits the .onion url as a link or a leaked string', () => {
    // the onion host + path must appear NOWHERE (not in an href, not as text)
    expect(html).not.toContain('ijzn3sicrqewpg')
    expect(html).not.toContain('/site/blog')
    // the only http:// (non-https) url in the fixtures is the onion — assert no
    // plaintext-http href leaked through
    expect(html).not.toContain('href="http://')
  })

  it('renders the claim victim-first: org name, domain, and the proxied favicon', () => {
    expect(html).toContain('Acme Corporation')
    expect(html).toContain('acme.com')
    // favicon is fetched through OUR same-origin proxy (CSP img-src 'self')
    expect(html).toContain('/api/favicon?d=acme.com')
  })

  it('shows an honest leak-site provenance line in place of the dead link', () => {
    expect(html).toContain('leak-site claim')
    expect(html).toContain('.onion (Tor)') // the label is plain text, never a link
    expect(html).toContain('unverified')
  })

  it('still renders a live link for a clearnet advisory (the lead)', () => {
    expect(html).toContain('href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"')
  })

  it("renders a row's CVE rail as the shared lookup pivot, not a dead span", () => {
    // The board and the feed share ONE CveLink idiom — a CVE is never plain
    // text in one surface and a link in another (board-ui.tsx contract).
    expect(html).toContain('href="/lookup#q=CVE-2026-1111"')
  })
})

describe('FeedView — corroborated stories strip (§3)', () => {
  const n1: FeedItem = {
    id: 'n1', source: 'rss', category: 'vulnerability',
    title: '[BleepingComputer] PAN-OS actively exploited',
    summary: 's', url: 'https://bleepingcomputer.com/x',
    entities: { cves: ['CVE-2026-3400'] }, score: 60, published_at: '2026-09-05T02:00:00Z',
  }
  const n2: FeedItem = {
    id: 'n2', source: 'rss', category: 'vulnerability',
    title: '[The Hacker News] PAN-OS RCE under attack',
    summary: 's', url: 'https://thehackernews.com/x',
    entities: { cves: ['CVE-2026-3400'] }, score: 55, published_at: '2026-09-05T01:00:00Z',
  }
  const story = {
    key: 'cve:CVE-2026-3400', entity: 'CVE-2026-3400', entity_type: 'cve' as const,
    title: 'PAN-OS actively exploited', outlets: ['BleepingComputer', 'The Hacker News'],
    member_ids: ['n1', 'n2'], member_count: 2, published_at: '2026-09-05T02:00:00Z',
    delta: { kev: true, epss: 0.94, epss_from: 0.71, epss_to: 0.94 },
  }

  it('renders the Corroborated strip with the corroboration line + EPSS shift', () => {
    const html = renderToStaticMarkup(<FeedView items={[n1, n2]} stories={[story]} />)
    expect(html).toContain('Corroborated')
    expect(html).toContain('covered by 2')
    expect(html).toContain('The Hacker News')
    expect(html).toContain('EPSS 71%→94%')
  })

  it('renders nothing extra when there are no stories (briefing unchanged)', () => {
    const html = renderToStaticMarkup(<FeedView items={[n1, n2]} />)
    expect(html).not.toContain('Corroborated')
  })

  it('does not feature a plain 2-outlet story with no delta (needs delta or ≥3 outlets)', () => {
    const plain = { ...story, delta: undefined }
    const html = renderToStaticMarkup(<FeedView items={[n1, n2]} stories={[plain]} />)
    expect(html).not.toContain('Corroborated')
  })
})
