// lib/__tests__/community.test.mjs
// Phase 3 community layer: the shared communityKey normalizer + its parity
// fixture (this task), the category-enum parity (Task 2), and the
// SOCDESK_COMMUNITY source behaviour (Task 5). No network — pure logic.
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { communityKey } from '../enrich.mjs'

const keyParity = JSON.parse(readFileSync(
  fileURLToPath(new URL('../../tests/fixtures/community/key_parity.json', import.meta.url)),
  'utf8'))

describe('communityKey', () => {
  it('lowercases hashes and leaves already-normalized values untouched', () => {
    expect(communityKey('md5', 'D41D8CD98F00B204E9800998ECF8427E'))
      .toBe('md5|d41d8cd98f00b204e9800998ecf8427e')
    expect(communityKey('ipv4', '203.0.113.4')).toBe('ipv4|203.0.113.4')
    expect(communityKey('domain', 'evil.example')).toBe('domain|evil.example')
  })

  it('agrees with the shared parity fixture (the Python mirror reads the same file)', () => {
    for (const row of keyParity) {
      expect(communityKey(row.type, row.value)).toBe(row.key)
    }
  })
})

import { CATEGORIES } from '../reporting/validate.mjs'

const categoriesFixture = JSON.parse(readFileSync(
  fileURLToPath(new URL('../../tests/fixtures/community/categories.json', import.meta.url)), 'utf8'))
const communitySchema = JSON.parse(readFileSync(
  fileURLToPath(new URL('../../schemas/community_reports.schema.json', import.meta.url)), 'utf8'))
const schemaCategoryEnum =
  communitySchema.properties.indicators.additionalProperties.properties.categories.items.enum

describe('category enum parity', () => {
  it('validate.mjs CATEGORIES === shared fixture === schema enum', () => {
    expect(CATEGORIES).toEqual(categoriesFixture)
    expect(schemaCategoryEnum).toEqual(categoriesFixture)
  })
})

import { enrich } from '../enrich.mjs'

/** Every upstream 404s so the other sources return cleanly; the community row
 *  rides on the injected dataset only (no network). */
const miss = async () => ({ status: 404, ok: false, json: async () => ({}) })

const DATASET = {
  generated_at: '2026-08-22T14:41:00Z',
  indicators: {
    'ipv4|203.0.113.4': {
      type: 'ipv4', value: '203.0.113.4', reporters: 2,
      categories: ['brute-force', 'ssh'],
      first_reported: '2026-08-10', latest_reported: '2026-08-20',
    },
    'ipv4|198.51.100.7': {
      type: 'ipv4', value: '198.51.100.7', reporters: 1,
      categories: ['phishing'], first_reported: '2026-08-18', latest_reported: '2026-08-19',
    },
  },
}

describe('SOCDESK_COMMUNITY source', () => {
  it('emits a kind:"context" row with a distinct-contributor count on a match', async () => {
    const out = await enrich(miss, 'ipv4', '203.0.113.4', { SOCDESK_COMMUNITY_DATA: DATASET })
    const row = out.sources.find((s) => s.name === 'SOCDesk Community')
    expect(row).toBeTruthy()
    expect(row.kind).toBe('context')
    expect(row.verdict).toBe('unknown')
    expect(row.headline).toBe(
      'Reported by 2 contributors (owner-moderated) · brute-force, ssh · latest 2026-08-20')
    expect(Object.fromEntries(row.facts).Contributors).toBe('2')
    expect(row.url).toContain('/about#community-reports')
  })

  it('says "1 contributor" (singular) for a single-reporter indicator', async () => {
    const out = await enrich(miss, 'ipv4', '198.51.100.7', { SOCDESK_COMMUNITY_DATA: DATASET })
    const row = out.sources.find((s) => s.name === 'SOCDesk Community')
    expect(row.headline).toContain('Reported by 1 contributor (owner-moderated)')
    expect(row.headline).not.toContain('1 contributors')
  })

  it('stays OUT of the verdict tally (consulted/flagged/tone unchanged vs. no dataset)', async () => {
    const withData = await enrich(miss, 'ipv4', '203.0.113.4', { SOCDESK_COMMUNITY_DATA: DATASET })
    const without = await enrich(miss, 'ipv4', '203.0.113.4', {})
    expect(withData.consulted).toBe(without.consulted)
    expect(withData.flagged).toBe(without.flagged)
    expect(withData.tone).toBe(without.tone)
  })

  it('omits the row on a no-match, with no error and partial unchanged', async () => {
    // ABUSEIPDB_API_KEY/VT_API_KEY (dummy, matching `miss`'s 404s) keep those
    // two sources CONFIGURED-and-clean rather than not-configured-skipped, so
    // `partial` isolates the community source's own no-match behaviour instead
    // of pre-existing not-configured skips unrelated to this source (see
    // lib/__tests__/enrich.test.mjs's own ipv4 tests, which do the same).
    const out = await enrich(miss, 'ipv4', '8.8.8.8',
      { SOCDESK_COMMUNITY_DATA: DATASET, ABUSEIPDB_API_KEY: 'x', VT_API_KEY: 'k' })
    expect(out.sources.find((s) => s.name === 'SOCDesk Community')).toBeUndefined()
    expect(out.errors.some((e) => /SOCDesk Community/.test(e.source))).toBe(false)
    expect(out.partial).toBe(false)
  })

  it('no-ops when the dataset is absent (null injected) — no row, no error', async () => {
    const out = await enrich(miss, 'ipv4', '203.0.113.4', { SOCDESK_COMMUNITY_DATA: null })
    expect(out.sources.find((s) => s.name === 'SOCDesk Community')).toBeUndefined()
    expect(out.errors.some((e) => /SOCDesk Community/.test(e.source))).toBe(false)
  })

  it('lowercases a hash indicator to match the dataset key', async () => {
    const lower = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    const dataset = { indicators: { [`sha256|${lower}`]: {
      type: 'sha256', value: lower, reporters: 1, categories: ['malware-c2'],
      first_reported: '2026-08-01', latest_reported: '2026-08-01' } } }
    const out = await enrich(miss, 'sha256', lower.toUpperCase(), { SOCDESK_COMMUNITY_DATA: dataset })
    expect(out.sources.find((s) => s.name === 'SOCDesk Community')).toBeTruthy()
  })
})
