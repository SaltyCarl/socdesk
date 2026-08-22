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
