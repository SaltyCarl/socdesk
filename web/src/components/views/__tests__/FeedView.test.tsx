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

describe('FeedView — leak-site claim rows', () => {
  const html = renderToStaticMarkup(<FeedView items={[vuln, claim]} generatedAt="2026-08-25T00:00:00Z" />)

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
})
