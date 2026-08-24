# Enrich / Write-Path Abuse Hardening ("B2") Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cap upstream free-tier quota burn and cross-account report farming on the public, no-account `/api/enrich` + `/api/report` endpoints without adding one microsecond of friction to a normal anonymous lookup.

**Architecture:** Three fail-open, ship-dark layers. L1 = an in-isolate-only per-IP soft latch on `/api/enrich` (zero KV writes; the Cloudflare WAF Rate-Limiting Block rule is the real distributed-flood shield). L2 = a per-source daily KV budget on `/api/enrich` that degrades a spent source to an honest non-blocking skip while every other source still answers (the real upstream-quota guarantee). L3 = a per-IP daily KV counter on `/api/report`. Every policy decision is a pure function in `lib/` unit-tested under node-vitest; all KV I/O lives in the thin Pages Function wrappers and no-ops when `env.KV` is unbound.

**Tech Stack:** Cloudflare Pages Functions (`functions/api/*.js`), pure ESM decision modules (`lib/**/*.mjs`), Cloudflare Workers KV (new `env.KV` binding), one Cloudflare WAF Rate-Limiting Rule, node-environment Vitest (`web/vitest.config.ts`), ESLint 9 + `tsc -b && vite build`.

**Spec:** `docs/superpowers/specs/2026-08-24-enrich-abuse-hardening-design.md` (the plan argues from §§1–10 **as corrected by §11 "Review amendments (APPROVED)", which is BINDING and overrides earlier body text**).

## Global Constraints

Every task's requirements implicitly include this section. Copied verbatim from the spec / owner-locked amendments:

1. **Frictionless no-account READ path.** The no-account READ path stays frictionless — NEVER a CAPTCHA/login/cookie on a lookup; a limit is a silent 429 Block only.
2. **Fail-open.** KV unbound or throwing must NEVER take a lookup down (ships dark).
3. **Per-IP L1 is IN-ISOLATE-ONLY** — no KV write (§11.1).
4. **Budget counted only for dispatched sources** (§11.2) — `dispatched = applicable − budgetBlocked − notConfigured`, never inferred from `errors[]`.
5. **Cacheable degradation.** A budget-skipped source is `blocking:false` so `partial` stays false and the response still caches; NO change to verdict tone/band/wording or the enrich source set.
6. **Free-tier KV only** (≤1,000 writes/day — the design must stay under it regardless of IP cardinality).
7. **NO AI attribution** (SaltyCarl repo) — in any file, comment, commit message, or doc.

### Owner-locked decisions (§11.6)
- **WAF rule INCLUDED** as the primary distributed-flood shield: one Rate-Limiting Rule, `path starts_with /api/enrich`, **Block** action (bare 429, not Managed Challenge), free-plan ~10 s counting window. Code ships independently and does NOT depend on the rule existing.
- **Per-IP in-isolate L1 default:** 60 cache-misses / 10-min window / IP, 15-min soft block. Generous by design; tunable later.
- **Ships dark:** L2 (budget) and L3 (report per-IP) no-op until an `env.KV` namespace is bound in the dashboard; the in-isolate L1 works with no config.

### Verification anchors (verified against code 2026-08-24)
- `functions/api/enrich.js:42` handler `onRequestGet({ request, env })`; cache `match` `:52`, `put` (only when `!result.partial`) `:62`; `CF-Connecting-IP` is **not** read here.
- `functions/api/report.js:25` reads `CF-Connecting-IP` into `ip`, forwards to Turnstile only; per-account cap 429 at `:36-37`; dedupe `:39-40`; insert `:42-43`.
- `lib/enrich.mjs`: `planSources` `:635-643`, `enrich()` signature `:774` (`now` is the 5th param), internal `planSources` call `:779`, `collectResults` pushes every skip to `errors[]` `:715-716` and counts `partial` from blocking failures `:711/:717/:739`, `consensus()` excludes `kind:"context"` `:614`, `_internals` exports `SOURCES` + `planSources` `:785-788`. Budgeted source `.key`s: `ABUSEIPDB_API_KEY` `:172`, `VT_API_KEY` `:207`, `GREYNOISE_API_KEY` `:261` (optionalKey `:262`), `ABUSECH_API_KEY` `:302`, `IPINFO_TOKEN` `:350` (optionalKey `:351`), `URLSCAN_API_KEY` `:392` (optionalKey `:393`), `OTX_API_KEY` `:495`. Not budgeted: RDAP (keyless `:449-452`), `SOCDESK_COMMUNITY` (local map `:562`).
- `lib/reporting/policy.mjs:1` `DAILY_REPORT_CAP = 25`.
- `web/vitest.config.ts:27-28` node env, `include: [..., '../lib/**/*.test.mjs']`. `web/package.json:8-9` `build`=`tsc -b && vite build`, `lint`=`eslint .`.

### Gates (the repo's real ones)
- **Pure `lib/` logic:** `cd web && npx vitest run <path-substring>` (decision modules are `lib/**/*.test.mjs`, picked up by the config glob). On Windows PowerShell substitute `cd web; npx vitest run <substring>`; the Bash tool runs the `&&` form directly.
- **Functions / wrappers (not unit-tested — no jsdom):** `node --check functions/api/<file>.js` (syntax) + `npm --prefix web run build` (the web app still builds) + `cd web && npx eslint .` (lint the web tree). The pure coalescing/decision logic behind the wrapper is unit-tested separately with a mock `env.KV`.
- **pytest is irrelevant** to this repo — do not run it.

---

### Task 1: L1 in-isolate per-IP rate-limit decision (`lib/enrich/ratelimit.mjs`)

Pure state-transition for the in-isolate per-IP soft latch (§4.1 as corrected by §11.1 — **zero KV**). The wrapper owns the `Map`s and calls this; the latch is an in-memory timestamp, so the decision returns `newLatchedUntil` (a ms epoch) rather than the spec's original KV-era `setLatch` boolean.

**Files:**
- Create: `lib/enrich/ratelimit.mjs`
- Test: `lib/enrich/__tests__/ratelimit.test.mjs`

**Interfaces:**
- Consumes: nothing (leaf module).
- Produces:
  - `WINDOW_MS = 600_000`, `IP_LIMIT = 60`, `BLOCK_TTL_MS = 900_000` (constants).
  - `ipDecision({ now, windowStart, count, latchedUntil, windowMs?, limit?, blockTtlMs? }) -> { allow: boolean, newWindowStart: number, newCount: number, newLatchedUntil: number }` — `newLatchedUntil` is `0` when no block is active/set. Fail-open: `undefined` window/count/latch ⇒ first-sight ⇒ allow.

- [ ] **Step 1: Write the failing test**

```javascript
// lib/enrich/__tests__/ratelimit.test.mjs
import { describe, expect, it } from 'vitest'
import { ipDecision, WINDOW_MS, IP_LIMIT, BLOCK_TTL_MS } from '../ratelimit.mjs'

describe('ipDecision', () => {
  it('allows under the limit and sets no latch', () => {
    const d = ipDecision({ now: 1000, windowStart: 1000, count: 5 })
    expect(d.allow).toBe(true)
    expect(d.newCount).toBe(6)
    expect(d.newLatchedUntil).toBe(0)
  })

  it('first sight (undefined state) allows — fail-open', () => {
    const d = ipDecision({ now: 1000, windowStart: undefined, count: undefined, latchedUntil: undefined })
    expect(d.allow).toBe(true)
    expect(d.newWindowStart).toBe(1000)
    expect(d.newCount).toBe(1)
  })

  it('crossing IP_LIMIT denies and sets a block for BLOCK_TTL_MS', () => {
    const d = ipDecision({ now: 2000, windowStart: 2000, count: IP_LIMIT })
    expect(d.newCount).toBe(IP_LIMIT + 1)
    expect(d.allow).toBe(false)
    expect(d.newLatchedUntil).toBe(2000 + BLOCK_TTL_MS)
  })

  it('an active latch denies without recounting', () => {
    const d = ipDecision({ now: 3000, windowStart: 3000, count: 10, latchedUntil: 9999 })
    expect(d.allow).toBe(false)
    expect(d.newCount).toBe(10)           // unchanged — no increment while latched
    expect(d.newLatchedUntil).toBe(9999)  // latch preserved
  })

  it('rolls the window when it has expired, resetting the count', () => {
    const d = ipDecision({ now: 1000 + WINDOW_MS, windowStart: 1000, count: 59 })
    expect(d.newWindowStart).toBe(1000 + WINDOW_MS)
    expect(d.newCount).toBe(1)
    expect(d.allow).toBe(true)
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run enrich/__tests__/ratelimit`
Expected: FAIL — "Failed to resolve import '../ratelimit.mjs'".

- [ ] **Step 3: Write minimal implementation**

```javascript
// lib/enrich/ratelimit.mjs
// L1: per-IP soft latch for /api/enrich. IN-ISOLATE ONLY (§11.1) — this module
// is pure and the wrapper stores the two Maps in isolate-global memory; there
// is NO KV here. A silent 429 on a local flood; the WAF Block rule is the
// distributed-flood shield of record. Read path stays frictionless: a 429 is a
// bare status, never a challenge/cookie/login.
export const WINDOW_MS = 600_000       // 10-minute counting window
export const IP_LIMIT = 60             // cache-MISS requests per window per IP
export const BLOCK_TTL_MS = 900_000    // 15-minute soft block after crossing

// Pure per-IP state transition. Fail-open: absent state ⇒ first sight ⇒ allow.
export function ipDecision({
  now, windowStart, count, latchedUntil,
  windowMs = WINDOW_MS, limit = IP_LIMIT, blockTtlMs = BLOCK_TTL_MS,
}) {
  // Active latch → deny, do NOT recount (a flood must not extend its own block).
  if (latchedUntil && latchedUntil > now) {
    return { allow: false, newWindowStart: windowStart || now, newCount: count || 0, newLatchedUntil: latchedUntil }
  }
  // Roll the window on expiry or first sight.
  let ws = windowStart, c = count || 0
  if (!ws || now - ws >= windowMs) { ws = now; c = 0 }
  c += 1
  if (c > limit) {
    return { allow: false, newWindowStart: ws, newCount: c, newLatchedUntil: now + blockTtlMs }
  }
  return { allow: true, newWindowStart: ws, newCount: c, newLatchedUntil: 0 }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run enrich/__tests__/ratelimit`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add lib/enrich/ratelimit.mjs lib/enrich/__tests__/ratelimit.test.mjs
git commit -m "feat(enrich): in-isolate per-IP rate-limit decision (L1)"
```

---

### Task 2: L2 per-source budget decision + dispatched-set + name→key (`lib/enrich/budgets.mjs`)

The pure decision core of L2 (§4.2, §11.2, §11.4): which sources are over budget, which budget keys the wrapper must count, and the `name→key` bridge (rows carry `.name`, budgets are keyed by `.key`).

**Files:**
- Create: `lib/enrich/budgets.mjs`
- Test: `lib/enrich/__tests__/budgets.test.mjs`

**Interfaces:**
- Consumes: `_internals.SOURCES` shape from `lib/enrich.mjs` (each source has `.name`, `.key`, `.types[]`, optional `.optionalKey`) — passed in, never imported here to keep this leaf pure.
- Produces:
  - `BUDGETS` — `Record<sourceKey, number>` (daily budgets, each below the real free cap).
  - `budgetBlockedSet(counts, budgets?) -> Set<sourceKey>` — keys whose `count >= budget`; fail-open (missing/NaN count ⇒ 0 ⇒ not blocked); ignores unbudgeted keys.
  - `dispatchedBudgetKeys({ type, env, budgetBlocked, sources, budgets? }) -> string[]` — budget keys for sources that apply to `type`, are usable (`optionalKey || env[key]`), NOT in `budgetBlocked`, AND budgeted. This is `applicable − notConfigured − budgetBlocked` restricted to budgeted keys (§11.2).
  - `nameToKey(sources, budgets?) -> Record<name, sourceKey>` — only budgeted sources (§11.4).

- [ ] **Step 1: Write the failing test**

```javascript
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run enrich/__tests__/budgets`
Expected: FAIL — "Failed to resolve import '../budgets.mjs'".

- [ ] **Step 3: Write minimal implementation**

```javascript
// lib/enrich/budgets.mjs
// L2: per-source daily budget — the real upstream-quota guarantee (§4.2, §11.1).
// PURE decision core only; all KV I/O lives in the Function wrapper. Budgets are
// keyed by the source's env-var `.key` (lib/enrich.mjs) and sit BELOW the real
// free cap to absorb multi-isolate over-count / eventual-consistency slop.
// RDAP (keyless) and SOCDesk Community (local map) carry no upstream quota → not
// budgeted, so they naturally fall out of every computation below.
export const BUDGETS = {
  VT_API_KEY: 450,          // real free cap ~500/day (public API)
  ABUSEIPDB_API_KEY: 900,   // real 1,000/day
  IPINFO_TOKEN: 1500,       // real 50k/mo ≈ 1,600/day
  URLSCAN_API_KEY: 500,     // key raises a low keyless cap
  GREYNOISE_API_KEY: 300,   // ~community tier
  ABUSECH_API_KEY: 1000,    // generous/unpublished (soft)
  OTX_API_KEY: 1500,        // generous (soft)
}

// A Set of budget keys whose day-count has reached its budget. Fail-open:
// a missing/NaN count is 0 (under budget). Unbudgeted keys are ignored.
export function budgetBlockedSet(counts, budgets = BUDGETS) {
  const blocked = new Set()
  for (const key of Object.keys(budgets)) {
    const n = Number(counts?.[key]) || 0
    if (n >= budgets[key]) blocked.add(key)
  }
  return blocked
}

// The budget keys the wrapper must increment: sources that apply to `type`, are
// usable (optionalKey OR key set), are NOT budget-blocked, and ARE budgeted.
// = applicable − notConfigured − budgetBlocked, restricted to budgeted keys
// (§11.2). NEVER inferred from result.errors[] (a 429/timeout that DID call and
// a skip that did NOT both look like {source, reason}).
export function dispatchedBudgetKeys({ type, env, budgetBlocked, sources, budgets = BUDGETS }) {
  return sources
    .filter((s) => s.types.includes(type))
    .filter((s) => s.optionalKey || env[s.key])   // drops not-configured non-optional sources
    .filter((s) => !budgetBlocked.has(s.key))      // drops already-blocked sources
    .filter((s) => budgets[s.key] !== undefined)   // drops unbudgeted (RDAP/community)
    .map((s) => s.key)
}

// name → budget key. Rows in result.sources/errors carry `.name`, budgets are
// keyed by `.key` (§11.4). Only budgeted names appear.
export function nameToKey(sources, budgets = BUDGETS) {
  const map = {}
  for (const s of sources) if (budgets[s.key] !== undefined) map[s.name] = s.key
  return map
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run enrich/__tests__/budgets`
Expected: PASS (all `budgetBlockedSet` / `dispatchedBudgetKeys` / `nameToKey` cases).

- [ ] **Step 5: Commit**

```bash
git add lib/enrich/budgets.mjs lib/enrich/__tests__/budgets.test.mjs
git commit -m "feat(enrich): per-source budget decision + dispatched-set + name-to-key (L2 core)"
```

---

### Task 3: L2 coalescing + KV key format (`lib/enrich/budgets.mjs`)

Add the write-frugality primitives (§4.2 coalescing, §5 key model) to `budgets.mjs`: the pure flush predicate, the UTC day key, and the exact KV key builder. Prove the coalescing math with a mock-`env.KV` test.

**Files:**
- Modify: `lib/enrich/budgets.mjs`
- Modify: `lib/enrich/__tests__/budgets.test.mjs`

**Interfaces:**
- Consumes: `BUDGETS` from Task 2.
- Produces:
  - `FLUSH_EVERY = 25`, `BUDGET_TTL_S = 93_600` (constants).
  - `shouldFlush({ pending, base, budget, flushEvery? }) -> boolean` — pure; flush when the local buffer hit the threshold OR the running total reached budget; never flush an empty buffer.
  - `utcDayKey(now?) -> string` — `YYYYMMDD` in UTC.
  - `budgetKey(sourceKey, now?) -> string` — `budget:<sourceKey>:<YYYYMMDD_utc>`.

- [ ] **Step 1: Write the failing test (append to `budgets.test.mjs`)**

```javascript
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run enrich/__tests__/budgets`
Expected: FAIL — "shouldFlush is not a function" / import errors for the new names.

- [ ] **Step 3: Write minimal implementation (append to `budgets.mjs`)**

```javascript
// --- append to lib/enrich/budgets.mjs ---
export const FLUSH_EVERY = 25          // coalescing factor: 1 KV write per 25 upstream calls
export const BUDGET_TTL_S = 93_600     // 26h — self-expiring, ZERO deletes

// Flush when the local buffer reached the coalescing threshold OR the running
// total reached budget (surface the block cross-isolate ASAP). Never flush empty.
export function shouldFlush({ pending, base, budget, flushEvery = FLUSH_EVERY }) {
  if (pending <= 0) return false
  return pending >= flushEvery || (Number(base) || 0) + pending >= budget
}

export function utcDayKey(now = new Date()) {
  const d = now instanceof Date ? now : new Date(now)
  const y = d.getUTCFullYear()
  const m = String(d.getUTCMonth() + 1).padStart(2, '0')
  const day = String(d.getUTCDate()).padStart(2, '0')
  return `${y}${m}${day}`
}

export function budgetKey(sourceKey, now = new Date()) {
  return `budget:${sourceKey}:${utcDayKey(now)}`
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run enrich/__tests__/budgets`
Expected: PASS (Task 2 + Task 3 cases).

- [ ] **Step 5: Commit**

```bash
git add lib/enrich/budgets.mjs lib/enrich/__tests__/budgets.test.mjs
git commit -m "feat(enrich): budget coalescing + KV key model (L2 write-frugality)"
```

---

### Task 4: L3 report per-IP cap decision (`lib/reporting/ratelimit.mjs`)

Pure decision + KV key for the `/api/report` per-IP daily cap (§4.3), sitting beside the existing per-account `policy.mjs`.

**Files:**
- Create: `lib/reporting/ratelimit.mjs`
- Test: `lib/reporting/__tests__/ratelimit.test.mjs`

**Interfaces:**
- Consumes: nothing (leaf module).
- Produces:
  - `IP_DAILY_REPORT_CAP = 40`, `REPORT_IP_TTL_S = 93_600` (constants).
  - `overIpDailyCap(count) -> boolean` — `Number(count) >= 40`; fail-open (NaN ⇒ 0 ⇒ under cap).
  - `reportIpKey(ip, now?) -> string` — `rl:report:<ip>:<YYYYMMDD_utc>`.

- [ ] **Step 1: Write the failing test**

```javascript
// lib/reporting/__tests__/ratelimit.test.mjs
import { describe, expect, it } from 'vitest'
import { overIpDailyCap, reportIpKey, IP_DAILY_REPORT_CAP, REPORT_IP_TTL_S } from '../ratelimit.mjs'

describe('overIpDailyCap', () => {
  it('is false below the cap, true at/above it (boundary at 40)', () => {
    expect(overIpDailyCap(IP_DAILY_REPORT_CAP - 1)).toBe(false)
    expect(overIpDailyCap(IP_DAILY_REPORT_CAP)).toBe(true)
    expect(overIpDailyCap(IP_DAILY_REPORT_CAP + 5)).toBe(true)
  })
  it('sits above the per-account cap (25) so an honest single account is never blocked', () => {
    expect(IP_DAILY_REPORT_CAP).toBeGreaterThan(25)
  })
  it('fail-open: NaN/undefined count is under cap', () => {
    expect(overIpDailyCap(undefined)).toBe(false)
    expect(overIpDailyCap(NaN)).toBe(false)
  })
})

describe('reportIpKey', () => {
  it('is rl:report:<ip>:<utcday> and stable across a UTC day', () => {
    const a = reportIpKey('203.0.113.7', new Date('2026-08-24T00:00:01Z'))
    const b = reportIpKey('203.0.113.7', new Date('2026-08-24T23:59:59Z'))
    expect(a).toBe('rl:report:203.0.113.7:20260824')
    expect(b).toBe(a)
  })
  it('TTL is 26h (self-expiring, no deletes)', () => {
    expect(REPORT_IP_TTL_S).toBe(93_600)
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run reporting/__tests__/ratelimit`
Expected: FAIL — "Failed to resolve import '../ratelimit.mjs'".

- [ ] **Step 3: Write minimal implementation**

```javascript
// lib/reporting/ratelimit.mjs
// L3: per-IP daily cap for /api/report. Defense-in-depth ON TOP of the existing
// auth + Turnstile + per-account cap (policy.mjs) so one IP cannot farm many
// accounts. PURE decision + key; the Function wrapper owns the KV I/O and
// fails open (a KV outage must not block legitimate reporting).
export const IP_DAILY_REPORT_CAP = 40   // above the 25/account cap: only bites cross-account farming
export const REPORT_IP_TTL_S = 93_600   // 26h — self-expiring, ZERO deletes

export const overIpDailyCap = (count) => (Number(count) || 0) >= IP_DAILY_REPORT_CAP

export function reportIpKey(ip, now = new Date()) {
  const d = now instanceof Date ? now : new Date(now)
  const y = d.getUTCFullYear()
  const m = String(d.getUTCMonth() + 1).padStart(2, '0')
  const day = String(d.getUTCDate()).padStart(2, '0')
  return `rl:report:${ip}:${y}${m}${day}`
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run reporting/__tests__/ratelimit`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/reporting/ratelimit.mjs lib/reporting/__tests__/ratelimit.test.mjs
git commit -m "feat(report): per-IP daily cap decision (L3 core)"
```

---

### Task 5: Thread `budgetBlocked` through `planSources` + `enrich()` (`lib/enrich.mjs`)

The one additive, pure change to the assembler (§4.2, §11.3 option (a)): a budget-blocked source moves to `skipped` with `reason:"daily budget reached"` and **`blocking:false`**, so `partial` stays false and the degraded answer caches. `enrich()` gains a 6th `budgetBlocked` param that forwards to `planSources`. Empty/omitted set ⇒ today's behavior byte-for-byte.

**Files:**
- Modify: `lib/enrich.mjs:635-643` (`planSources`), `lib/enrich.mjs:774` (`enrich` signature), `lib/enrich.mjs:779` (internal `planSources` call)
- Modify: `lib/__tests__/enrich.test.mjs` (extend)

**Interfaces:**
- Consumes: `budgetBlocked: Set<sourceKey>` produced by the wrapper (Task 6) from `budgetBlockedSet` (Task 2).
- Produces:
  - `planSources(type, env = {}, budgetBlocked = new Set()) -> { usable, blocking, nonBlocking, skipped }` — `skipped` now includes `{ source, reason:"daily budget reached", blocking:false }` rows; existing not-configured rows unchanged.
  - `enrich(fetchImpl, type, q, env = {}, now = new Date(), budgetBlocked = new Set()) -> <unchanged response shape>`.

- [ ] **Step 1: Write the failing test (append to `lib/__tests__/enrich.test.mjs`)**

```javascript
// --- append to lib/__tests__/enrich.test.mjs ---
import { planSources } from '../enrich.mjs'

describe('planSources budget threading (§11.3)', () => {
  const env = { ABUSEIPDB_API_KEY: 'a', VT_API_KEY: 'v', GREYNOISE_API_KEY: 'g', IPINFO_TOKEN: 'i', OTX_API_KEY: 'o' }

  it('omitted budgetBlocked = today: no budget skips, source still usable (regression guard)', () => {
    const p = planSources('ipv4', env)
    expect(p.skipped.some((s) => s.reason === 'daily budget reached')).toBe(false)
    expect(p.usable.some((s) => s.name === 'AbuseIPDB')).toBe(true)
  })

  it('a budget-blocked source moves to skipped(blocking:false) and out of usable; others stay', () => {
    const p = planSources('ipv4', env, new Set(['ABUSEIPDB_API_KEY']))
    expect(p.skipped).toContainEqual({ source: 'AbuseIPDB', reason: 'daily budget reached', blocking: false })
    expect(p.usable.some((s) => s.name === 'AbuseIPDB')).toBe(false)
    expect(p.usable.some((s) => s.name === 'VirusTotal')).toBe(true)
  })

  it('not-configured skip still fires (regression) when its key is absent', () => {
    const p = planSources('ipv4', { VT_API_KEY: 'v' }, new Set())
    expect(p.skipped.find((s) => s.source === 'AbuseIPDB').reason).toBe('not configured')
  })
})

describe('enrich() budget skip keeps the answer cacheable (§4.2)', () => {
  it('budget-blocked BLOCKING source → errors[], partial stays FALSE', async () => {
    const mock = async () => ({ status: 404, ok: false, json: async () => ({}) }) // sources return "unknown", never throw
    const out = await enrich(mock, 'ipv4', '8.8.8.8', { ABUSEIPDB_API_KEY: 'a', VT_API_KEY: 'v' }, new Date(), new Set(['ABUSEIPDB_API_KEY']))
    expect(out.errors.some((e) => e.source === 'AbuseIPDB' && e.reason === 'daily budget reached')).toBe(true)
    expect(out.partial).toBe(false) // blocking:false → not partial → edge-cacheable
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run lib/__tests__/enrich`
Expected: FAIL — `planSources` ignores the 3rd arg, so the budget-skip assertions fail (no `"daily budget reached"` row; `AbuseIPDB` still usable; `enrich` ignores the 6th arg).

- [ ] **Step 3: Write minimal implementation**

Replace `planSources` (`lib/enrich.mjs:635-643`):

```javascript
export function planSources(type, env = {}, budgetBlocked = new Set()) {
  const applicable = SOURCES.filter(s => s.types.includes(type));
  const configured = applicable.filter(s => s.optionalKey || env[s.key]);
  const usable = configured.filter(s => !budgetBlocked.has(s.key));
  const blocking = usable.filter(s => s.blocking !== false);
  const nonBlocking = usable.filter(s => s.blocking === false);
  const notConfigured = applicable
    .filter(s => !s.optionalKey && !env[s.key])
    .map(s => ({ source: s.name, reason: "not configured", blocking: s.blocking !== false }));
  // A budget-blocked source degrades to a NON-blocking named skip (§4.2): it
  // lands in errors[] for honesty but never sets `partial`, so the degraded
  // answer stays cacheable and we do not re-run the other sources uncached.
  // A spent budget is a deliberate, stable degradation (like being
  // unconfigured), not a transient failure — and `partial` exists only to keep
  // transient failures out of the edge cache (enrich.js:60-62).
  const budgetSkipped = configured
    .filter(s => budgetBlocked.has(s.key))
    .map(s => ({ source: s.name, reason: "daily budget reached", blocking: false }));
  const skipped = [...notConfigured, ...budgetSkipped];
  return { usable, blocking, nonBlocking, skipped };
}
```

Update `enrich` (`lib/enrich.mjs:774` signature + `:779` call):

```javascript
export async function enrich(fetchImpl, type, q, env = {}, now = new Date(), budgetBlocked = new Set()) {
  const check = validate(type, q);
  if (!check.ok) return { error: check.reason, status: 400 };

  const ind = { type, value: check.value };
  const plan = planSources(type, env, budgetBlocked);
  const dispatched = dispatchSources(fetchImpl, ind, env, plan);
  const collected = await collectResults(dispatched, plan);
  return assemble(ind, type, now, collected);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd web && npx vitest run` (full suite — confirms the new cases pass AND the existing `enrich`/OTX/planSources tests still pass, i.e. the default-arg path is byte-for-byte unchanged)
Expected: PASS, zero regressions.

- [ ] **Step 5: Commit**

```bash
git add lib/enrich.mjs lib/__tests__/enrich.test.mjs
git commit -m "feat(enrich): thread budgetBlocked through planSources + enrich (additive, cacheable degradation)"
```

---

### Task 6: `/api/enrich` wrapper — L1 latch + L2 read/inject/count/flush (`functions/api/enrich.js`)

Wire L1 (in-isolate, zero KV) and L2 (KV budget: read → inject `budgetBlocked` → dispatched-only counting → coalesced flush) into the existing cache-aware flow. Additive: with `env.KV` unbound and no offending IP, the happy path is byte-identical to today. Not unit-tested (no jsdom); gated by `node --check` + build + eslint. The coalescing/decision logic it calls is already unit-proven (Tasks 1–3, 5).

**Files:**
- Modify: `functions/api/enrich.js`

**Interfaces:**
- Consumes: `ipDecision` (Task 1); `BUDGETS`, `budgetBlockedSet`, `dispatchedBudgetKeys`, `shouldFlush`, `budgetKey`, `BUDGET_TTL_S` (Tasks 2–3); `enrich`, `_internals.SOURCES` (Task 5).
- Produces: hardened `onRequestGet` (no new response shape; a rate-limited IP gets a bare `429` with `cache-control: no-store`).

- [ ] **Step 1: Add imports + isolate-global state**

At the top of `functions/api/enrich.js`, extend the imports and add the module-global maps (same isolate-memo idiom as `_communityCache` at `enrich.js:18`):

```javascript
import { enrich, _internals } from "../../lib/enrich.mjs";
import { ipDecision } from "../../lib/enrich/ratelimit.mjs";
import {
  BUDGETS, budgetBlockedSet, dispatchedBudgetKeys, shouldFlush, budgetKey, BUDGET_TTL_S,
} from "../../lib/enrich/budgets.mjs";

// L1 — in-isolate per-IP soft latch (§11.1). ZERO KV: these live only in this
// isolate's memory; the WAF Block rule is the distributed-flood shield.
const ipWindow = new Map();   // ip -> { windowStart, count }
const ipLatched = new Map();  // ip -> latchedUntilMs

// L2 — per-isolate budget buffer for coalesced KV writes.
// `budget:<key>:<utcday>` -> { base, pending }
const budgetBuf = new Map();
```

- [ ] **Step 2: Add the L1 + L2 helpers (above `onRequestGet`)**

```javascript
// L1: pure decision + isolate Maps. Returns true when the IP is rate-limited.
// No attributable IP → never limited.
function rateLimited(ip, nowMs) {
  if (!ip) return false;
  const st = ipWindow.get(ip) || { windowStart: 0, count: 0 };
  const d = ipDecision({ now: nowMs, windowStart: st.windowStart, count: st.count, latchedUntil: ipLatched.get(ip) || 0 });
  ipWindow.set(ip, { windowStart: d.newWindowStart, count: d.newCount });
  if (d.newLatchedUntil) ipLatched.set(ip, d.newLatchedUntil);
  return !d.allow;
}

// L2 read: build the budgetBlocked Set from in-isolate effective counts
// (base = last KV read, refreshed at flush; + pending). One KV read per budgeted
// key per isolate per day. Ships dark + fail-open: no KV, or a throwing get, ⇒
// empty set ⇒ every source eligible.
async function readBudgetBlocked(env, type, now) {
  if (!env.KV) return new Set();
  const counts = {};
  for (const s of _internals.SOURCES) {
    if (BUDGETS[s.key] === undefined || !s.types.includes(type)) continue;
    const k = budgetKey(s.key, now);
    let buf = budgetBuf.get(k);
    if (!buf) {
      let base = 0;
      try { base = Number(await env.KV.get(k)) || 0; } catch { base = 0; }
      buf = { base, pending: 0 };
      budgetBuf.set(k, buf);
    }
    counts[s.key] = buf.base + buf.pending;
  }
  return budgetBlockedSet(counts, BUDGETS);
}

// L2 flush: read-modify-write ONE key (§4.2 "read → put(current + pending) →
// reset"). Fail-open: on error keep the delta for a later attempt, never throw.
async function flushBudgetKey(env, k, buf) {
  const pending = buf.pending;
  buf.pending = 0;                                     // reset first: concurrent requests won't double-count
  try {
    const cur = Number(await env.KV.get(k)) || buf.base;
    const next = cur + pending;
    await env.KV.put(k, String(next), { expirationTtl: BUDGET_TTL_S });
    buf.base = next;
  } catch {
    buf.pending += pending;                            // restore the unflushed delta
  }
}

// L2 count: increment ONLY dispatched budgeted sources (§11.2), coalesced. The
// flush never blocks the response (waitUntil when available).
async function countBudgets(env, type, envForPlan, budgetBlocked, now, waitUntil) {
  if (!env.KV) return;
  const keys = dispatchedBudgetKeys({ type, env: envForPlan, budgetBlocked, sources: _internals.SOURCES, budgets: BUDGETS });
  for (const key of keys) {
    const k = budgetKey(key, now);
    const buf = budgetBuf.get(k) || { base: 0, pending: 0 };
    buf.pending += 1;
    budgetBuf.set(k, buf);
    if (shouldFlush({ pending: buf.pending, base: buf.base, budget: BUDGETS[key] })) {
      const p = flushBudgetKey(env, k, buf);
      if (waitUntil) waitUntil(p); else await p;
    }
  }
}
```

- [ ] **Step 3: Rewrite `onRequestGet` to weave L1/L2 into the cache-aware flow**

```javascript
export async function onRequestGet({ request, env, waitUntil }) {
  const url = new URL(request.url);
  const type = (url.searchParams.get("type") || "").toLowerCase();
  const q = url.searchParams.get("q") || "";

  const cache = caches.default;
  const key = new Request(`${url.origin}/api/enrich?type=${encodeURIComponent(type)}` +
                          `&q=${encodeURIComponent(q)}`, request);
  const hit = await cache.match(key);
  if (hit) return hit;                       // cache hit → makes no upstream call → never rate-limited/budgeted

  // L1: in-isolate per-IP latch, applied ONLY after a cache miss (§4.1, §11.1).
  const ip = request.headers.get("CF-Connecting-IP") || "";
  const nowMs = Date.now();
  if (rateLimited(ip, nowMs))
    return json({ error: "rate", reason: "slow down" }, 429, { "cache-control": "no-store" });

  const now = new Date(nowMs);
  const community = await loadCommunity(env, url.origin);
  const envForPlan = { ...env, SOCDESK_COMMUNITY_DATA: community };

  // L2: read budget state → blocked set → inject into the pure assembler.
  const budgetBlocked = await readBudgetBlocked(env, type, now);
  const result = await enrich(fetch, type, q, envForPlan, now, budgetBlocked);
  if (result.error) return json({ error: result.error }, result.status ?? 400);

  // L2: count ONLY dispatched budgeted sources, coalesced (never blocks response).
  await countBudgets(env, type, envForPlan, budgetBlocked, now, waitUntil);

  const res = json(result);
  // Never cache a partial answer (transient failure). A budget skip is
  // blocking:false → partial stays false → the degraded answer still caches.
  if (!result.partial) await cache.put(key, res.clone());
  return res;
}
```

- [ ] **Step 4: Run the wrapper gates**

Run: `node --check functions/api/enrich.js`
Expected: no output (syntax OK).

Run: `cd web && npx eslint . && npm --prefix web run build`
Expected: eslint clean; build succeeds (`tsc -b && vite build`).

Run: `cd web && npx vitest run`
Expected: full suite still green (no lib regressions from the wrapper edit).

- [ ] **Step 5: Commit**

```bash
git add functions/api/enrich.js
git commit -m "feat(enrich): wire in-isolate L1 latch + per-source KV budget (L2) into the wrapper"
```

---

### Task 7: `/api/report` wrapper — per-IP daily KV counter (`functions/api/report.js`)

Add L3 (§4.3): a per-IP daily KV counter between the existing account-cap gate and the D1 insert, so one IP cannot farm many accounts. Fail-open + ships dark. Not unit-tested; gated by `node --check` + build + eslint (the decision + key are unit-proven in Task 4).

**Files:**
- Modify: `functions/api/report.js`

**Interfaces:**
- Consumes: `overIpDailyCap`, `reportIpKey`, `REPORT_IP_TTL_S` (Task 4); existing `ip` at `report.js:25`, `env.KV`, `env.DB`.
- Produces: hardened `onRequestPost` (per-IP 429 mirrors the existing account-cap 429 at `report.js:37`).

- [ ] **Step 1: Add the import**

Add to the imports at the top of `functions/api/report.js`:

```javascript
import { overIpDailyCap, reportIpKey, REPORT_IP_TTL_S } from '../../lib/reporting/ratelimit.mjs'
```

- [ ] **Step 2: Add the per-IP read gate after the account-cap check**

Immediately AFTER the per-account cap block (`report.js:35-37`) and BEFORE the dedupe (`:39`), insert:

```javascript
  // L3: per-IP daily cap — defense-in-depth over auth + Turnstile + per-account
  // cap so one IP cannot farm many accounts. Placed after Turnstile/auth pass so
  // unsolved/unauthenticated traffic never touches KV. Ships dark (no-op when KV
  // is unbound); fail-open on any KV error (the strong gates above still hold).
  const ipKey = env.KV && ip ? reportIpKey(ip, new Date()) : null
  let ipCount = 0
  if (ipKey) {
    try { ipCount = Number(await env.KV.get(ipKey)) || 0 } catch { ipCount = 0 }
    if (overIpDailyCap(ipCount)) return json({ error: 'rate', reason: 'daily report cap reached' }, 429)
  }
```

- [ ] **Step 3: Increment only on an accepted new insert**

Replace the final insert + return (`report.js:42-44`) with:

```javascript
  const id = crypto.randomUUID()
  await insertReport(env.DB, { id, github_id: user.github_id, ...v.clean, created_at: new Date().toISOString() })
  // Count only genuinely-accepted new reports (a dedupe returns earlier and is
  // not counted). Fail-open: a failed put must not fail the accepted report.
  if (ipKey) { try { await env.KV.put(ipKey, String(ipCount + 1), { expirationTtl: REPORT_IP_TTL_S }) } catch { /* fail-open */ } }
  return json({ id, status: 'queued' }, 200)
```

- [ ] **Step 4: Run the wrapper gates**

Run: `node --check functions/api/report.js`
Expected: no output (syntax OK).

Run: `cd web && npx eslint . && npm --prefix web run build`
Expected: eslint clean; build succeeds.

Run: `cd web && npx vitest run`
Expected: full suite still green.

- [ ] **Step 5: Commit**

```bash
git add functions/api/report.js
git commit -m "feat(report): per-IP daily KV counter on the write path (L3)"
```

---

### Task 8: Owner-config + manual dogfood (`docs/OPERATIONS.md`)

Document the two inert-until-set owner steps (§7): bind one KV namespace as `env.KV`, and enable the WAF Rate-Limiting Block rule (§11.6). Fold in the manual dogfood acceptance pass — the real gate for external-behavior features in this repo (`docs/OPERATIONS.md:301-304`).

**Files:**
- Modify: `docs/OPERATIONS.md`

**Interfaces:**
- Consumes: nothing (docs). Describes the runtime contract Tasks 6–7 depend on (`env.KV`).
- Produces: a new "Abuse hardening (B2)" subsection; the dogfood checklist below is the acceptance evidence.

- [ ] **Step 1: Add the owner-config subsection**

Append this new subsection to `docs/OPERATIONS.md` alongside the existing enrich-keys / D1 / Turnstile setup:

```markdown
### Owner one-time setup — abuse hardening (B2)

Both endpoints **ship dark**: with none of the below done, `/api/enrich` and
`/api/report` behave exactly as before. The in-isolate per-IP latch on
`/api/enrich` works with no config; everything else no-ops until `env.KV` is
bound. All of this is fail-open — a KV outage never takes a lookup down.

1. **Create a KV namespace and bind it as `KV`.** Cloudflare dashboard →
   Workers & Pages → **socdesk** → Settings → Functions → **KV namespace
   bindings** → create `socdesk_hardening`, bind it as variable name **`KV`**
   (Production). Same dashboard-only pattern as the `DB` binding — there is no
   `wrangler.toml` to edit. Until this binding exists, the per-source budget
   (L2) and the per-IP report cap (L3) no-op.

2. **Enable the WAF Rate-Limiting Rule (primary flood shield).** Security → WAF
   → **Rate limiting rules** → create a rule:
   - **Match:** `URI Path` **starts with** `/api/enrich`
   - **Counting:** requests per client IP over the free-plan window (~10 s)
   - **Action:** **Block** (returns a bare HTTP 429) — **NOT** Managed
     Challenge (a challenge would break the frictionless no-account read path).
   Verify the current free-plan rate-limiting allowances in the dashboard; the
   shipped code does not depend on this rule existing, but it is the designated
   distributed/volumetric shield (§11.1/§11.6). Optionally add a second Block
   rule for `/api/report`.

3. **No new secrets.** Budgets (`lib/enrich/budgets.mjs`), the per-IP window /
   limit (`lib/enrich/ratelimit.mjs`), and the report cap
   (`lib/reporting/ratelimit.mjs`) are code constants. `KV` is a binding, not a
   secret.

**KV budget:** all keys self-expire via `expirationTtl` — zero deletes, zero
lists. Worst-case writes/day ≈ L2 (~250, coalesced 25×) + L3 (tens) « the free
1,000/day, **independent of IP cardinality** (L1 does no KV writes, §11.1).
```

- [ ] **Step 2: Add the manual dogfood checklist**

Append the acceptance dogfood (run after deploy; the automated suites do not cover Function runtime behavior):

```markdown
#### Dogfood acceptance (manual — the real gate)

Run against the deployed site once `env.KV` is bound and the WAF rule is on.

- [ ] **Dark-ship regression (KV unbound):** temporarily with no `KV` binding, a
      normal `/api/enrich` lookup and a normal `/api/report` submit behave
      exactly as before. No CAPTCHA/login/cookie ever appears on a lookup.
- [ ] **Normal lookup unaffected (KV bound):** a burst of a few dozen distinct
      lookups in a few minutes all return 200; the card is byte-identical and no
      slower.
- [ ] **Abusive IP → silent 429:** a script exceeding the per-IP miss limit on
      `/api/enrich` from one client gets a **bare 429** — assert no `Set-Cookie`,
      no challenge HTML, no login redirect (`cache-control: no-store`).
- [ ] **Spent source degrades honestly:** force a source's `budget:<key>:<utcday>`
      counter to its budget in KV; that source shows a named
      "daily budget reached" skip in `errors[]` while every other source renders
      normally, the tone/band/wording is unchanged, and the answer is cacheable
      (a second identical lookup is a cache hit).
- [ ] **Report per-IP cap:** a normal report still succeeds; exceeding the
      per-IP daily cap from one IP across multiple accounts yields the 429.
- [ ] **Fail-open:** with `KV` bound but made to error, a lookup and a report
      still serve.
- [ ] **KV write budget sanity:** after a day of normal traffic, KV Analytics
      shows writes far under 1,000/day.
```

- [ ] **Step 3: Commit**

```bash
git add docs/OPERATIONS.md
git commit -m "docs(ops): abuse-hardening owner setup (KV binding + WAF rule) + dogfood gate"
```

---

## Self-Review

**1. Spec coverage** (every section + every §11 amendment mapped to a task):

- §0 In scope — per-IP enrich budget → Task 1 + Task 6; per-source daily budget → Tasks 2/3/5/6; per-IP report cap → Tasks 4/7; KV model + write math → Tasks 3/8; fail-open → encoded in Tasks 1/2/4 (allow-on-absent) + Tasks 6/7 (try/catch, `!env.KV`); owner-config inert-until-set → Task 8; pure testable decisions → Tasks 1–4.
- §0 Out of scope (verdict doctrine / no-account model / source set / `lib/enrich.mjs` purity) — Task 5 makes exactly the two additive signature changes and touches nothing in `consensus()`/tone/band; no challenge/login added (Task 6 returns a bare 429); no KV in `lib/enrich.mjs` (all KV lives in Task 6/7 wrappers).
- §4.1 L1 → Task 1 (pure) + Task 6 (wrapper). §4.2 L2 → Tasks 2/3/5/6. §4.3 L3 → Tasks 4/7.
- §5 KV model (key patterns, TTLs, zero deletes/lists) → `budgetKey`/`BUDGET_TTL_S` (Task 3), `reportIpKey`/`REPORT_IP_TTL_S` (Task 4), documented in Task 8. §6 fail-open → Tasks 1/2/4/6/7. §7 owner-config → Task 8. §8 testing split → pure vitest (Tasks 1–5) + build-gated wrappers + manual dogfood (Tasks 6–8).
- **§11.1** (L1 in-isolate-only, zero KV; WAF primary) → Task 1 returns an in-memory `newLatchedUntil`, Task 6 stores it in `ipLatched` Map with NO KV, Task 8 documents the WAF Block rule as primary. ✓
- **§11.2** (count only dispatched = applicable − budgetBlocked − notConfigured, never from `errors[]`) → `dispatchedBudgetKeys` (Task 2) + `countBudgets` (Task 6). ✓
- **§11.3** (option (a): `budgetBlocked` through `enrich()`→`planSources`) → Task 5. ✓
- **§11.4** (name→key from `_internals.SOURCES`) → `nameToKey` (Task 2). ✓
- **§11.5** (NAT/shared-egress caveat; cache-miss-only counting) → L1 runs only after a cache miss (Task 6); generous default (Task 1). ✓
- **§11.6** (WAF included, in-isolate default 60/10-min, ships dark) → Global Constraints + Task 1 constants + Task 8. ✓

**2. Placeholder scan:** No TODO/TKTK/"add error handling"/"similar to Task N". Every code + test step is concrete. The only `<...>` are intentional KV **key patterns** (`budget:<sourceKey>:<utcday>`, `rl:report:<ip>:<utcday>`) and dashboard placeholders in the docs task — matching the spec's §5/§10 intentional-pattern exception.

**3. Type consistency (cross-task):**
- `ipDecision` returns `{ allow, newWindowStart, newCount, newLatchedUntil }` in Task 1 and is consumed with exactly those fields in Task 6. (Deviation from the spec's original `{ allow, setLatch, ... }` is required by §11.1: an in-isolate latch stores a timestamp, so `newLatchedUntil` replaces the KV-era `setLatch` boolean — noted in Task 1.)
- `budgetBlockedSet` / `dispatchedBudgetKeys` / `shouldFlush` / `budgetKey` / `BUDGET_TTL_S` / `BUDGETS` signatures defined in Tasks 2–3 match their calls in Task 6 verbatim (`dispatchedBudgetKeys({ type, env, budgetBlocked, sources, budgets })`).
- `planSources(type, env, budgetBlocked)` and `enrich(..., now, budgetBlocked)` defined in Task 5 match Task 6's `enrich(fetch, type, q, envForPlan, now, budgetBlocked)` call.
- `overIpDailyCap` / `reportIpKey` / `REPORT_IP_TTL_S` defined in Task 4 match Task 7's usage.
- Budget keys in `BUDGETS` (Task 2) are the real `.key` env-var names verified against `lib/enrich.mjs` (`VT_API_KEY`, `ABUSEIPDB_API_KEY`, `IPINFO_TOKEN`, `URLSCAN_API_KEY`, `GREYNOISE_API_KEY`, `ABUSECH_API_KEY`, `OTX_API_KEY`); RDAP/community deliberately absent.

No inconsistencies found.
