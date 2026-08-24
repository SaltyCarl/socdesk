// lib/enrich/__tests__/budgets.test.mjs
import { describe, expect, it } from 'vitest'
import { BUDGETS, budgetBlockedSet, dispatchedBudgetKeys, nameToKey } from '../budgets.mjs'

// Minimal stand-in for _internals.SOURCES rows (only fields these fns read).
const SOURCES = [
  { name: 'AbuseIPDB',       key: 'ABUSEIPDB_API_KEY', types: ['ipv4', 'ipv6'] },
  { name: 'VirusTotal',      key: 'VT_API_KEY',        types: ['ipv4', 'domain', 'md5'] },
  { name: 'GreyNoise',       key: 'GREYNOISE_API_KEY', types: ['ipv4'], optionalKey: true },
  { name: 'RDAP',            key: undefined,           types: ['domain'], optionalKey: true },
  { name: 'SOCDesk Community', key: 'SOCDESK_COMMUNITY_DATA', types: ['ipv4'], optionalKey: true },
]

describe('budgetBlockedSet', () => {
  it('is empty when all sources are under budget', () => {
    expect(budgetBlockedSet({ VT_API_KEY: 10, ABUSEIPDB_API_KEY: 10 }).size).toBe(0)
  })
  it('blocks only sources at/over their budget', () => {
    const s = budgetBlockedSet({ VT_API_KEY: BUDGETS.VT_API_KEY, ABUSEIPDB_API_KEY: 10 })
    expect(s.has('VT_API_KEY')).toBe(true)
    expect(s.has('ABUSEIPDB_API_KEY')).toBe(false)
  })
  it('fail-open: missing / NaN counts are treated as 0 (not blocked)', () => {
    expect(budgetBlockedSet({}).size).toBe(0)
    expect(budgetBlockedSet({ VT_API_KEY: undefined }).has('VT_API_KEY')).toBe(false)
  })
  it('ignores unbudgeted keys', () => {
    expect(budgetBlockedSet({ SOCDESK_COMMUNITY_DATA: 999999 }).size).toBe(0)
  })
})

describe('dispatchedBudgetKeys (= applicable − notConfigured − budgetBlocked, budgeted only)', () => {
  const env = { ABUSEIPDB_API_KEY: 'a', VT_API_KEY: 'v' } // GreyNoise keyless (optional)

  it('counts every dispatched budgeted source for the type', () => {
    const keys = dispatchedBudgetKeys({ type: 'ipv4', env, budgetBlocked: new Set(), sources: SOURCES })
    expect(keys.sort()).toEqual(['ABUSEIPDB_API_KEY', 'GREYNOISE_API_KEY', 'VT_API_KEY'])
  })
  it('excludes a not-configured non-optional source (no env key)', () => {
    const keys = dispatchedBudgetKeys({ type: 'ipv4', env: { VT_API_KEY: 'v' }, budgetBlocked: new Set(), sources: SOURCES })
    expect(keys).not.toContain('ABUSEIPDB_API_KEY') // not configured → not dispatched → not counted
    expect(keys).toContain('VT_API_KEY')
  })
  it('excludes a budget-blocked source (do NOT keep counting an already-blocked source)', () => {
    const keys = dispatchedBudgetKeys({ type: 'ipv4', env, budgetBlocked: new Set(['ABUSEIPDB_API_KEY']), sources: SOURCES })
    expect(keys).not.toContain('ABUSEIPDB_API_KEY')
    expect(keys).toContain('VT_API_KEY')
  })
  it('excludes unbudgeted dispatched sources (RDAP keyless, SOCDesk local map)', () => {
    const keys = dispatchedBudgetKeys({ type: 'domain', env, budgetBlocked: new Set(), sources: SOURCES })
    expect(keys).toEqual(['VT_API_KEY']) // RDAP has no budget key; nothing else applies
  })
})

describe('nameToKey', () => {
  it('maps only budgeted source names to their keys', () => {
    const m = nameToKey(SOURCES)
    expect(m.AbuseIPDB).toBe('ABUSEIPDB_API_KEY')
    expect(m.VirusTotal).toBe('VT_API_KEY')
    expect(m['SOCDesk Community']).toBeUndefined() // unbudgeted
    expect(m.RDAP).toBeUndefined()
  })
})
