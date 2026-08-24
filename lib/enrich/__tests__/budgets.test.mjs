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

// --- append to lib/enrich/__tests__/budgets.test.mjs ---
import { shouldFlush, FLUSH_EVERY, BUDGET_TTL_S, utcDayKey, budgetKey } from '../budgets.mjs'

describe('shouldFlush', () => {
  it('does not flush an empty buffer', () => {
    expect(shouldFlush({ pending: 0, base: 0, budget: 450 })).toBe(false)
  })
  it('flushes at the coalescing threshold', () => {
    expect(shouldFlush({ pending: FLUSH_EVERY - 1, base: 0, budget: 450 })).toBe(false)
    expect(shouldFlush({ pending: FLUSH_EVERY, base: 0, budget: 450 })).toBe(true)
  })
  it('flushes early when the running total reaches budget (make the block visible ASAP)', () => {
    expect(shouldFlush({ pending: 2, base: 449, budget: 450 })).toBe(true) // 449 + 2 >= 450
  })
})

describe('KV key model', () => {
  it('utcDayKey is a stable UTC YYYYMMDD', () => {
    expect(utcDayKey(new Date('2026-08-24T23:59:59Z'))).toBe('20260824')
    expect(utcDayKey(new Date('2026-08-25T00:00:00Z'))).toBe('20260825')
  })
  it('budgetKey matches budget:<sourceKey>:<utcday>', () => {
    expect(budgetKey('VT_API_KEY', new Date('2026-08-24T12:00:00Z'))).toBe('budget:VT_API_KEY:20260824')
  })
  it('BUDGET_TTL_S is 26h (self-expiring, no deletes)', () => {
    expect(BUDGET_TTL_S).toBe(93_600)
  })
})

// The wrapper's coalescing loop, exercised against a fake env.KV, proves writes
// scale ~1/FLUSH_EVERY of increments — the §Q4 free-tier guarantee. This mirrors
// the exact read-modify-write the wrapper performs (Task 6); shouldFlush is the
// only decision, and it is pure.
function fakeKV() {
  const store = new Map()
  return { puts: 0, async get(k) { return store.has(k) ? store.get(k) : null }, async put(k, v) { store.set(k, v); this.puts++ } }
}

describe('budget coalescing against a mock env.KV', () => {
  it('flushes at most once per FLUSH_EVERY increments', async () => {
    const kv = fakeKV()
    const budget = 450
    const k = budgetKey('VT_API_KEY', new Date('2026-08-24T00:00:00Z'))
    const buf = { base: 0, pending: 0 }
    const N = 60
    for (let i = 0; i < N; i++) {
      buf.pending += 1
      if (shouldFlush({ pending: buf.pending, base: buf.base, budget })) {
        const cur = Number(await kv.get(k)) || buf.base
        await kv.put(k, String(cur + buf.pending))
        buf.base = cur + buf.pending
        buf.pending = 0
      }
    }
    expect(kv.puts).toBe(Math.floor(N / FLUSH_EVERY))          // 2 writes for 60 increments
    expect(kv.puts).toBeLessThanOrEqual(Math.ceil(N / FLUSH_EVERY))
    expect(Number(await kv.get(k))).toBe(50)                   // 2 flushes × 25 persisted
  })
})
