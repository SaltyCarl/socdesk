# Enrich / Write-Path Abuse Hardening — Design Spec ("B2")

**Date:** 2026-08-24 · **Status:** design, pre-implementation · **Author:** SaltyCarl
**Scope target:** `functions/api/enrich.js` + `functions/api/report.js` (Function wrappers) · new pure `lib/enrich/*` + `lib/reporting/*` decision modules · Cloudflare **KV** (new binding) · one optional Cloudflare **Rate Limiting Rule** (WAF) · `docs/OPERATIONS.md` owner-config.

---

## 0. SCOPE BOUNDARY

### Goal
The crowdsourced reporting write path is LIVE and public, and `/api/enrich` is a public keyed proxy protected **only** by a ~15-minute edge cache (`functions/api/enrich.js:62` — `if (!result.partial) await cache.put(key, res.clone())`). A script over novel indicators bypasses that cache on every request and can burn each upstream's free-tier quota (AbuseIPDB / VirusTotal / GreyNoise / ipinfo / urlscan / OTX / RDAP) or trip a key's ToS revocation. Harden the exposed endpoints **before** the surface scales — without adding one microsecond of friction to a normal anonymous lookup.

### In scope
- A **per-IP request budget** on `/api/enrich` that quietly 429s an abusive flood and is invisible to a normal analyst (design questions §Q1).
- A **per-source daily budget** (KV) on `/api/enrich` that caps upstream calls per source per UTC day and degrades that source honestly when spent, while every other source still answers (§Q2).
- A **per-IP daily cap** (KV) on the `/api/report` write path, on top of the existing Turnstile + per-account cap + dedupe, so one IP cannot farm accounts (§Q3).
- The KV data model, TTLs, and **write-frequency math proving the design fits the free KV tier** (§Q4).
- **Fail-open** behavior when KV is unavailable (§Q5).
- Owner-config for the new KV binding + optional WAF rule, all **inert-until-set** (§Q6).
- Pure, node-vitest-testable decision functions for every policy call.

### Out of scope (hard boundary — do NOT touch)
- **The verdict doctrine.** No change to banding, tone thresholds, consensus wording, or the `consulted/flagged/tone` tally (`lib/enrich.mjs:613-624`, `docs/VERDICT-LANGUAGE.md`). Hardening changes *whether* a source is consulted, never *how its answer is scored*.
- **The no-account read model.** `/api/enrich` and the analyzer stay 100% no-account and client-served. **NEVER add a Turnstile/CAPTCHA/login/challenge to a lookup.** Rate-limiting on the read path is a silent 429 on abuse only; a normal analyst never sees it (`docs/OPERATIONS.md:303-304`, BACKLOG.md:238 — "rate-limiting must NOT hamper real UX").
- **The enrich source set.** No source added, removed, or reordered. `SOURCES` (`lib/enrich.mjs:593`) is unchanged. The `SOCDESK_COMMUNITY` context source, the `kind:"context"` exclusion from the tally, and the `partial`/`skipped_context` honesty fields keep their current meaning.
- **The pure/binding-free contract of `lib/enrich.mjs`.** That module is testable offline with an injected `fetchImpl` and **no Cloudflare bindings** (`lib/enrich.mjs:8-9`). All KV I/O lives in the Function wrapper; the assembler learns about budgets only through an **injected plain set**, never a binding.
- Magic-link/second auth method; broader read-side accounts (BACKLOG.md:276-283 — explicitly a separate doctrine decision).

### Owned files
| File | Change |
|---|---|
| `functions/api/enrich.js` | Wrap the existing flow: per-IP latch check → per-source budget read → inject blocked set into `enrich()` → coalesced budget writes. Additive; the happy path is byte-identical when KV is unbound. |
| `functions/api/report.js` | Add a per-IP daily KV check between the existing Turnstile/auth gates and the D1 insert. |
| `lib/enrich.mjs` | **One additive, pure change:** `planSources(type, env, budgetBlocked)` skips budget-blocked sources exactly like "not configured". No other edit. |
| `lib/enrich/budgets.mjs` *(new, pure data + logic)* | Per-source daily budget config (keyed by source `.key`) + `budgetBlockedSet(counts, budgets)`. |
| `lib/enrich/ratelimit.mjs` *(new, pure logic)* | `ipDecision(...)`, `dayKey/windowKey(...)`, `shouldFlush(...)` — pure decision helpers, no KV, no DOM. |
| `lib/reporting/ratelimit.mjs` *(new, pure logic)* | `overIpDailyCap(count)` + key helper for the write-path per-IP cap. |
| `lib/enrich/__tests__/*.test.mjs`, `lib/reporting/__tests__/*.test.mjs` *(new)* | Vitest node-env unit tests (picked up by `web/vitest.config.ts:28` — `'../lib/**/*.test.mjs'`). |
| `docs/OPERATIONS.md` | New "Abuse hardening" subsection: KV binding + optional WAF rule, inert-until-set. |

### Interfaces (contracts that must not drift)
- `enrich(fetchImpl, type, q, env, now)` return shape is **unchanged** (`lib/enrich.mjs:774`). Budget skips reuse the existing `errors[]` honesty channel; no new top-level field on the response.
- `planSources` gains an optional third arg defaulting to an empty set — existing callers and tests keep working unchanged.
- The KV binding is read as `env.KV`; when absent, every hardening path no-ops and the endpoints behave exactly as today (ships dark).

### Acceptance criteria
See §8. Headline: a normal lookup is byte-identical and no slower; an abusive IP gets a quiet 429; a spent source is reported as a named skip while the rest answer; with `env.KV` unbound everything behaves as it does today; every policy decision has a passing node-vitest test.

### Anti-drift guardrails
1. If a change touches tone/band/wording or `consensus()` (`lib/enrich.mjs:613`), it is out of scope — stop.
2. If a change adds any interactive challenge, login, or cookie to `/api/enrich`, it violates the read-path invariant — stop.
3. If KV I/O appears anywhere in `lib/enrich.mjs`, the purity contract is broken — move it to the wrapper.
4. If a design step would exceed **1,000 KV writes/day** at realistic traffic, it is wrong — the whole point of §Q4 is that writes scale with *distinct abusers and budget-saturation*, never 1:1 with requests.
5. No AI attribution in any file, comment, commit, or doc (SaltyCarl public repo).

---

## 1. What exists today (verified against code)

**Read path — `functions/api/enrich.js`:**
- Sole protection is `caches.default` keyed by normalized `type`+`q` (`enrich.js:49-53`); a hit returns immediately.
- On a miss it loads the committed community dataset (`enrich.js:55`, memoized per-isolate at `enrich.js:18-27`) and calls the pure assembler `enrich(fetch, type, q, {...env, SOCDESK_COMMUNITY_DATA})` (`enrich.js:56`).
- **Only non-partial answers are cached** (`enrich.js:62`) — a transient failure is never frozen as truth.
- **No per-IP limit, no per-source budget.** Every cache miss fans out to every configured upstream. `CF-Connecting-IP` is not read here at all.

**Assembler — `lib/enrich.mjs`:**
- `planSources(type, env)` (`:635-643`) partitions applicable sources into `usable`/`blocking`/`nonBlocking` and emits `skipped` for any non-optional source whose key is missing, with `reason:"not configured"` and a `blocking` flag (`:640-641`).
- `collectResults` (`:704-740`) pushes every `skipped` entry into `errors[]` (honesty) and increments `blockingFailures` only for *blocking* skips (`:715-718`); `partial = blockingFailures > 0` (`:739`).
- `consensus()` excludes `kind:"context"` rows from the tally (`:613-614`). Context sources (ipinfo/RDAP/OTX/SOCDesk Community) never vote.
- Budgeted network sources each carry a `.key` env-var name: `ABUSEIPDB_API_KEY`, `VT_API_KEY`, `GREYNOISE_API_KEY`, `ABUSECH_API_KEY`, `IPINFO_TOKEN`, `URLSCAN_API_KEY`, `OTX_API_KEY` (`lib/enrich.mjs:172,207,261,302,350,392,494`). RDAP is keyless (`:452`); `SOCDESK_COMMUNITY` reads an injected in-memory map, no network (`:566-569`).

**Write path — `functions/api/report.js`:** already has, in order:
- session/auth (`report.js:19-20`, `functions/_lib/session.mjs:5-10`),
- JSON parse (`:22-23`), reads `CF-Connecting-IP` into `ip` (`:25`) but **only forwards it to Turnstile** (`:26`), never rate-limits on it,
- Turnstile verify (`:26-27`),
- `validateReport` (`:29-30`, `lib/reporting/validate.mjs`),
- banned-account check (`:32-33`),
- **per-account** daily cap (`:35-37`) — `DAILY_REPORT_CAP = 25` (`lib/reporting/policy.mjs:1-2`) counted via `countReportsSince` (`lib/reporting/db.mjs:17-22`),
- queued-duplicate dedupe (`:39-40`), then D1 insert (`:42-43`).
- **Missing: a per-IP cap.** One IP can create N GitHub accounts and get N×25 reports/day.

**Bindings / config:**
- There is **no `wrangler.toml`/`.dev.vars`** in the repo — every binding is configured in the Cloudflare dashboard. Confirmed present bindings: `env.DB` (D1), `env.ASSETS` (Pages static assets, `enrich.js:23`), and secrets `SESSION_SECRET`, `TURNSTILE_SECRET`, `GITHUB_CLIENT_ID/SECRET`, `OWNER_GITHUB_ID` (`functions/**`, `docs/OPERATIONS.md:264-354`). **No KV namespace is bound today.**
- Turnstile is already wired: `env.TURNSTILE_SECRET` server-side (`report.js:26`) and `VITE_TURNSTILE_SITEKEY` build-time (`docs/OPERATIONS.md:349-354`). It gates **only** the write path — do not extend it to reads.

**Test harness:** `web/vitest.config.ts` runs node-env vitest over `src/**`, `../shared/**`, and **`../lib/**/*.test.mjs`** (`:26-29`). Pure `lib/` logic is unit-tested there (e.g. `lib/__tests__/enrich.test.mjs`, `lib/reporting/__tests__/policy.test.mjs`). Pages Functions are build-gated + covered by Playwright, not unit-tested. So **every decision this spec adds is written as a pure function in `lib/` and unit-tested; the wrappers stay thin.**

---

## 2. Free-tier KV limits (the binding constraint)

Cloudflare Workers KV, **free plan**, per day per account:

| Operation | Free limit | Relevance |
|---|---|---|
| **Writes** | **1,000 / day** | The scarce resource. The entire §Q4 design exists to keep writes far under this. |
| Reads | 100,000 / day | Ample, but not infinite — a sustained flood at >~1.15 req/s could approach it, so reads are also short-circuited in-isolate (§4.1). |
| Deletes | 1,000 / day | Not used — every key uses `expirationTtl` to self-expire. **Zero deletes.** |
| Lists | 1,000 / day | Not used — every access is a direct `get`/`put` by exact key. **Zero lists.** |
| Storage | 1 GB; value ≤ 25 MiB; key ≤ 512 B | Trivially met — a few dozen tiny integer values. |
| Min TTL | 60 s | All windows are ≥ 60 s. |
| Same-key writes | ~1 / s | Respected by coalescing; no key is written more than a few times/minute even under load. |

> These numbers have been stable for years; treat them as the design contract. The one genuinely-uncertain external fact — the **free-plan WAF Rate Limiting Rule** parameters (§4.1 Option A) — is flagged for owner verification, and the design does **not** depend on it.

**Core consequence:** *No scheme that performs a KV write proportional to request volume survives an unbounded flood within 1,000 writes/day.* Therefore every write in this design is **volume-independent** — writes scale with the number of *distinct abusing IPs* (per-IP latch) and with *budget saturation ÷ a coalescing factor* (per-source budget), never 1:1 with requests. Cache hits and normal low traffic produce **≈ zero** writes.

---

## 3. Architecture overview

Three independent layers, each of which fails open and ships dark:

```
                       ┌─────────────────────────────────────────────┐
   request ──▶ (edge)  │  Option A: CF Rate Limiting Rule (WAF)       │  ← owner-config, recommended
                       │  by IP · action = Block (429) · zero KV/code │     primary flood shield
                       └───────────────┬─────────────────────────────┘
                                       ▼
                       ┌─────────────────────────────────────────────┐
  /api/enrich          │  L1  per-IP soft-latch  (in-isolate + KV)    │  ← §4.1  quiet 429 on abuse only
   (read, no account)  │  L2  per-source daily budget (KV, coalesced) │  ← §4.2  honest per-source skip
                       └─────────────────────────────────────────────┘
                       ┌─────────────────────────────────────────────┐
  /api/report          │  existing: auth + Turnstile + per-account    │
   (write, gated)      │  NEW: L3 per-IP daily cap (KV)               │  ← §4.3
                       └─────────────────────────────────────────────┘
```

The layers are complementary: L1 stops a single noisy IP cheaply; L2 is the **hard aggregate guarantee** that upstream quotas are never exceeded even under a distributed flood L1 can't see; Option A (if the owner enables it) absorbs floods at the edge before a Function even runs. L2 is the most important layer — if only one thing ships, it is L2.

---

## 4. Per-endpoint design

### 4.1 `/api/enrich` — per-IP request budget (Q1)

**Hard constraint restated:** the read path stays 100% no-account and frictionless. The mechanism is a silent `429 Too Many Requests` for an abusive IP only — **never** a challenge, cookie, or login. A normal analyst doing rapid triage (a few dozen lookups in ten minutes) never approaches the limit.

**Two mechanisms; recommendation below.**

**Option A — Cloudflare Rate Limiting Rule (WAF), RECOMMENDED as the primary shield.**
A dashboard rule: *when request path starts with `/api/enrich` and requests-per-IP exceed the threshold over the window → **Block** (HTTP 429).* Action is **Block, not Managed Challenge** — Block returns a bare 429 with no CAPTCHA, satisfying the frictionless-read invariant. This runs at the edge before the Function executes, so a flood consumes **zero KV, zero Function invocations, zero upstream calls**. It is the only mechanism that truly holds under a large flood.
- *Owner decision + flag:* the free plan's rate-limiting-rule capabilities (available rule count, minimum counting window, whether "Block" action is offered on free) have shifted over time and must be **verified in the current dashboard**. If the free rule is too coarse, L1's in-code latch is the fallback. This is why the shipped deliverable does **not** depend on Option A.

**Option B — in-code per-IP soft-latch (KV + in-isolate memory), the SHIPPED deliverable.**
Write-frugal by construction: **writes scale with distinct offending IPs, not requests.**

Per-isolate module-global state (same idiom as the community memo at `enrich.js:18`):
```
const ipWindow  = new Map();   // ip -> { windowStart, count }   sliding count
const ipLatched = new Map();   // ip -> blockedUntilEpochMs      remembered block
```
Config (owner-tunable constants): `WINDOW_MS = 600_000` (10 min), `IP_LIMIT = 60` **cache-miss** requests/window/IP, `BLOCK_TTL_S = 900` (15 min).

Flow, applied **only after an edge-cache miss** (a cache hit makes no upstream call, so it is never rate-limited — this is the cache-aware bypass):
1. **In-memory latch first (free):** if `ipLatched.get(ip) > now`, return 429 — **no KV op**. Under a flood, hot isolates learn the latch and 429 with zero KV, bounding reads too.
2. **KV latch read:** `get('rl:enrich:'+ip)`. If present, memo it into `ipLatched` and return 429. (1 read, no write.)
3. **In-memory count:** roll/increment `ipWindow` for `ip` in the current window.
4. If `count > IP_LIMIT` → **one** `put('rl:enrich:'+ip, '1', { expirationTtl: BLOCK_TTL_S })`, memo `ipLatched`, return 429. *This is the only write, once per offending IP per 15-min block.*
5. Otherwise allow → proceed to `enrich()`.

**Pure, testable core** (`lib/enrich/ratelimit.mjs`):
```
ipDecision({ now, windowStart, count, windowMs, limit, latchedUntil })
  -> { allow, setLatch, newWindowStart, newCount }
```
The wrapper owns the Maps and the KV calls; `ipDecision` is a pure state-transition tested in node vitest.

**Recommendation:** enable **Option A** as the real edge shield **and** ship **Option B** as portable, self-contained defense-in-depth. If forced to pick one for v1, ship **B** (it is fully in our control and provably free-tier-safe); add A when convenient. *Owner input needed on `IP_LIMIT`/`WINDOW_MS` aggressiveness — see §9.*

**Write math (Option B):** legit IPs → 0 writes. Each distinct abusing IP → ≤ 1 write per 15-min block ⇒ ≤ 96/day. You would need **>10 simultaneously-abusing distinct IPs, all day** to reach even ~1,000 writes — and at that scale Option A / L2 are already absorbing it. Comfortably within 1,000/day.

### 4.2 `/api/enrich` — per-source daily budget (Q2)

**This is the hard guarantee that a free-tier upstream key is never exhausted**, independent of how the flood is distributed.

**Budget config** (`lib/enrich/budgets.mjs`), keyed by source `.key`, each set **below** the real free cap to absorb eventual-consistency slop:

| Source (`.key`) | Real free cap (`docs/OPERATIONS.md:285-290`) | Daily budget |
|---|---|---|
| `VT_API_KEY` | 500/day (public API) | **450** |
| `ABUSEIPDB_API_KEY` | 1,000/day | **900** |
| `IPINFO_TOKEN` | 50k/mo ≈ 1,600/day | **1,500** |
| `URLSCAN_API_KEY` | key raises a low keyless cap | **500** |
| `GREYNOISE_API_KEY` | ~community tier | **300** |
| `ABUSECH_API_KEY` (MalwareBazaar) | generous/unpublished | **1,000** (soft) |
| `OTX_API_KEY` | generous | **1,500** (soft) |

RDAP (keyless public infra, non-blocking context, `lib/enrich.mjs:452`) and `SOCDESK_COMMUNITY` (local map, no network, `:566`) are **not budgeted**.

**Where it sits — wrapper reads/writes; assembler stays pure.**
- **Read (decide):** on a cache miss, before calling `enrich()`, the wrapper reads today's per-source counters and builds `budgetBlocked = budgetBlockedSet(counts, budgets)` — a plain `Set<sourceKey>`.
- **Inject:** call `enrich(fetch, type, q, { ...env, SOCDESK_COMMUNITY_DATA }, now, budgetBlocked)` — the set is passed through to `planSources`.
- **`planSources(type, env, budgetBlocked = new Set())`** (`lib/enrich.mjs:635`) — the one additive change: a source with `budgetBlocked.has(s.key)` is moved into `skipped` with `reason:"daily budget reached"` and, deliberately, **`blocking:false`**.
- **Write (count):** *after* `enrich()` returns, the wrapper increments the counter for each source that actually made a network call (present in `result.sources` **or** `result.errors` and carries a budgeted `.key`), using in-isolate coalescing (below).

**Interaction with the existing honesty fields + edge cache — the key subtlety:**
A "not configured" skip that is *blocking* sets `partial:true` today (`lib/enrich.mjs:717`), which makes the answer **uncacheable** (`enrich.js:62`). For a budget skip that would be wrong: it would force every lookup to re-run the *other* sources with no caching, *increasing* load exactly when we're trying to shed it. So budget skips are tagged **`blocking:false`** → they land in `errors[]` (honest: "AbuseIPDB — daily budget reached") but do **not** set `partial`, so the degraded answer is **cacheable** for 15 min. Rationale, stated for the reviewer: a spent budget is a *deliberate, stable* degradation (like being unconfigured), not a *transient upstream failure* — and `partial` exists only to keep transient failures out of the cache (`enrich.js:60-62`). Context sources (`kind:"context"`) that get budget-skipped never affected the tally anyway (`:613-614`), so banding is untouched. **No new response field; the client already renders `errors[]`.**

**Pure, testable core** (`lib/enrich/budgets.mjs`):
```
budgetBlockedSet(counts, budgets) -> Set<sourceKey>   // counts[k] >= budgets[k]
```
Plus the additive `planSources` branch, covered by extending `lib/__tests__/enrich.test.mjs`.

**Write frugality — coalescing:** a naive "1 write per source per miss" blows the budget under flood (450 VT + 900 AbuseIPDB misses ⇒ >1,000 writes). Fix: each isolate buffers `pendingDelta[sourceKey]` in memory and flushes (read → `put(current + pending)` → reset) only every `FLUSH_EVERY = 25` local increments, or when the running total nears budget. Decisions in between use `kvValueAtLastRead + pendingDelta`. This cuts writes ~25×: even at full saturation across all 7 sources, worst-case ≈ (450+900+1500+500+300+1000+1500)/25 ≈ **250 writes/day** — under 1,000 with headroom, and effectively **0** at normal traffic. The imprecision (isolates flushing independently, eventual consistency) is *absorbed by design*: budgets sit below the real caps, and over/under-counting only shifts the honest degrade point slightly. `shouldFlush(pending, sinceLastFlushMs, config)` is pure and tested.

### 4.3 `/api/report` — per-IP daily cap (Q3)

Confirmed already present (do **not** duplicate): auth (`report.js:19`), Turnstile (`:26`), banned (`:32`), **per-account** cap 25/day (`:35-37`, `policy.mjs:1`), dedupe (`:39`). Missing: a **per-IP** cap so one IP cannot farm many accounts.

**Add** a KV per-IP daily counter, placed **after** Turnstile+auth pass (so unauthenticated/unsolved traffic never touches KV) and **before** the D1 insert:
- Key `rl:report:<ip>:<yyyymmdd_utc>`, `expirationTtl ≈ 93_600` (26 h — covers the day + slop, self-expiring; **no deletes**).
- Cap `IP_DAILY_REPORT_CAP = 40` (above the 25/account cap so a single honest account/IP is never blocked; it only bites cross-account farming from one IP).
- Flow: read counter; if `overIpDailyCap(count)` → `429 { error:'rate', reason:'daily report cap reached' }` (mirrors the existing account-cap 429 at `report.js:37`); else on a successful accepted insert, `put(count+1)`.

**Write frugality here is a non-issue:** every write on this path is gated by a solved Turnstile **and** a signed-in session, so attempts are naturally tiny (tens/day). A straight read-increment-write per accepted report stays far under 1,000/day — no coalescing needed.

**Pure core** (`lib/reporting/ratelimit.mjs`): `overIpDailyCap(count)` + `reportIpKey(ip, now)`, unit-tested next to `policy.test.mjs`.

---

## 5. KV data model

Single namespace, bound as **`env.KV`**. Every key is a direct `get`/`put` by exact key with `expirationTtl` — **no lists, no deletes.**

| Key pattern | Value | TTL | Written when | Write frequency |
|---|---|---|---|---|
| `rl:enrich:<ip>` | `"1"` (latch marker) | `BLOCK_TTL_S` = 900 s | an IP crosses `IP_LIMIT` misses in-window | ≤ 1 per offending IP per 15 min (≈ 0 for legit IPs) |
| `budget:<sourceKey>:<yyyymmdd_utc>` | integer count | ~93,600 s (26 h) | coalesced flush every `FLUSH_EVERY`=25 upstream calls | ≈ Σ(budget)/25 ≈ ≤ 250/day at full saturation; ≈ 0 normally |
| `rl:report:<ip>:<yyyymmdd_utc>` | integer count | ~93,600 s (26 h) | per accepted report | ≤ total accepted reports/day (tens) |

**Daily worst-case total writes** ≈ 96 (per-IP latch, ≥10 all-day attackers) + 250 (budgets, full saturation) + ~40 (report path) ≈ **≤ 400/day**, versus the **1,000/day** free limit — and a realistic day is a small fraction of that. Reads (a handful per cache-miss, short-circuited in-isolate under flood) stay far below 100,000/day. Storage is a few dozen tiny values.

---

## 6. Fail-open behavior (Q5)

**The read path fails open. A hardening layer must never take the tool down.**

- **KV unbound (`!env.KV`):** the entire hardening layer no-ops — L1 allows, L2 blocks nothing, L3 skips. `/api/enrich` and `/api/report` behave exactly as today. This is how the feature **ships dark** (identical to how `SOCDESK_COMMUNITY` no-ops when its data is absent, `lib/enrich.mjs:567`).
- **KV throws / times out mid-request:** every KV call is wrapped in `try/catch`. On failure — L1 read → treat as *not latched* (allow); L2 read → treat as *budget not reached* (all sources eligible); any write → swallow. The lookup always proceeds. This mirrors the existing "transient miss returns null without poisoning" pattern (`enrich.js:24-26`) and the assembler doctrine that a dead dependency is a named non-event, never a 500 (`lib/enrich.mjs:16-17`).
- **Write path (`/api/report`) on KV failure:** also fail-open (allow the report). The per-IP cap is defense-in-depth on top of Turnstile + auth + per-account cap; a KV outage must not block legitimate reporting. The strong gates remain in force.
- The per-source budget is the only layer that *reduces* upstream calls, and it too fails open — an aggregate flood during a KV outage is still bounded by L1/Option A and by the upstreams' own 429s, which the assembler already surfaces honestly (`lib/enrich.mjs:121`).

---

## 7. Owner-config (Q6) — all inert-until-set

Added to `docs/OPERATIONS.md` alongside the existing enrich-keys / D1 / Turnstile setup. **The feature ships dark: with none of this done, both endpoints behave exactly as today.**

1. **Create a KV namespace and bind it as `KV`.** Cloudflare dashboard → Workers & Pages → **socdesk** → Settings → Functions → **KV namespace bindings** → create `socdesk_hardening`, bind as variable name `KV` (Production). Same dashboard-only pattern as the `DB` binding (`docs/OPERATIONS.md:319`); no `wrangler.toml` exists to edit. **Until this binding exists, all hardening no-ops.**
2. **(Recommended) Add one WAF Rate Limiting Rule.** Security → WAF → Rate limiting rules → path `starts with /api/enrich`, threshold-per-IP over a short window, **action = Block (429)** — *not* Managed Challenge. Optionally a second rule for `/api/report`. *Verify the free plan's current rule allowances in the dashboard* (§4.1 flag).
3. **No new secrets.** Budgets, windows, and caps are code constants (optionally overridable via plain Pages env vars later). KV is a binding, not a secret.

---

## 8. Testing strategy

Matches the repo split — **pure logic in node-vitest, Functions build-gated + Playwright** (`web/vitest.config.ts:26-29`, `docs/OPERATIONS.md:62-89`).

**Unit (node vitest, new `lib/**/*.test.mjs`):**
- `ipDecision(...)` — under limit → allow, no latch; crossing `IP_LIMIT` → `setLatch:true`; window roll resets count; an in-future `latchedUntil` → deny without recount.
- `budgetBlockedSet(counts, budgets)` — empty when all under; includes only sources at/over budget; ignores unbudgeted keys (RDAP/community).
- `planSources(type, env, budgetBlocked)` (extend `lib/__tests__/enrich.test.mjs`) — a budgeted source in the set moves to `skipped` with `reason:"daily budget reached"` and `blocking:false`; **`partial` stays false** and the other sources still plan in; empty/omitted set = today's behavior byte-for-byte (regression guard on the default arg).
- `shouldFlush(...)` — flush at `FLUSH_EVERY` and at the near-budget boundary, not before.
- `overIpDailyCap(count)` + `reportIpKey(ip, now)` — boundary at 40; key format stable across a UTC day.
- **Fail-open contract:** a decision helper given `undefined`/thrown KV inputs returns the *allow* result (encode "no data ⇒ allow" in the pure functions so it's unit-provable).

**Integration / E2E (Playwright + manual dogfood — the real acceptance gate, per `docs/OPERATIONS.md:301-304`, BACKLOG.md feedback on live checkpoints):**
- With `env.KV` **unbound**: `/api/enrich` and `/api/report` behave identically to pre-change (dark-ship regression).
- With `env.KV` bound: a burst past `IP_LIMIT` from one client yields a quiet **429** on `/api/enrich` (no challenge, no cookie, no login prompt — assert the response is a bare 429); a normal lookup is unaffected and no slower.
- Forcing a source's counter to budget yields a card where that source shows a named "daily budget reached" skip while the others render normally, the tone/band is unchanged, and the answer is cacheable.
- `/api/report`: a normal report still succeeds; exceeding the per-IP cap from one IP across accounts yields the 429.

**Acceptance criteria (all must hold):**
1. A normal anonymous lookup is byte-identical in output and no slower than today. **No CAPTCHA/login/cookie ever appears on `/api/enrich`.**
2. An abusive IP receives a silent 429 on `/api/enrich`; a normal analyst never does.
3. When a source's daily budget is spent, that source degrades to an honest named skip while every other source still answers; verdict tone/band/wording is unchanged.
4. One IP cannot exceed the per-IP daily report cap even across multiple accounts.
5. With `env.KV` unbound, both endpoints behave exactly as today (ships dark).
6. If KV errors mid-request, the lookup still serves (fail-open).
7. Projected KV writes stay well under 1,000/day at realistic traffic (§5 math).
8. Every policy decision has a passing node-vitest test; `lib/enrich.mjs` gains no Cloudflare binding.
9. No AI attribution anywhere.

---

## 9. Open question needing owner input

**How aggressive should the per-IP enrich limit be?** The defaults proposed — `IP_LIMIT = 60` cache-**misses** per **10-minute** window per IP, `BLOCK_TTL_S = 900` — are set generously so a human doing rapid triage never trips them, with the per-source budget as the real quota backstop. This is a genuine product/risk trade-off (tighter = better key protection but a small chance of clipping a power user on a shared/NAT'd egress IP; looser = safer UX, more reliance on L2 + Option A). Recommend shipping the generous defaults and tightening only if telemetry shows abuse slipping through. **Please confirm the window/limit, and whether to enable the Option A WAF rule as the primary edge shield** (which also needs a quick dashboard check of the current free-plan rate-limiting allowances — the one external fact this spec does not assume).

---

## 10. Self-review

- **Placeholder scan:** none — no TODO/TKTK/`<...>` left except intentional key *patterns* in §5.
- **Internal consistency:** write-frugality claim (§2) is honored by all three layers (§4.1/4.2/4.3) and totaled in §5 (≤ ~400/day « 1,000). `blocking:false` on budget skips is stated once as the mechanism (§4.2) and its cache consequence traced to `enrich.js:62`. Fail-open (§6) is asserted for every KV touchpoint introduced.
- **Scope:** no change to verdict doctrine, the no-account read model, or the source set — restated as anti-drift guardrails (§0) and re-checked against each per-endpoint change. `lib/enrich.mjs` gets exactly one additive, pure signature change.
- **Ambiguity:** the one real owner decision (limit aggressiveness + WAF-rule enablement) is isolated in §9 and not guessed; the uncertain external fact (free-plan WAF params) is flagged, and the shipped deliverable is designed not to depend on it.
- **Citations:** every load-bearing claim about current behavior cites `file:line`.

---

## 11. Review amendments (APPROVED 2026-08-24)

Infra/security spec review returned REVISE-THEN-PLAN. These corrections are BINDING and override any earlier body text they touch. The plan argues from §§1–10 as corrected here.

### 11.1 [BLOCKER fix] The per-IP limit (L1) is IN-ISOLATE-ONLY — no KV write. The WAF rule is the DESIGNATED primary distributed-flood shield.
The original L1 KV latch wrote one key per distinct offending IP. Under the exact IP-rotation/botnet flood the layer exists to stop, distinct IPs = thousands → L1 alone exhausts the shared 1,000/day KV **write** pool → the L2 per-source budget counter's `put`s then fail → L2 fails open → every free-tier upstream key is exposed. The write-frugal shield disabled the aggregate guarantee. **Fix (owner-approved):**
- **L1 becomes an in-isolate soft latch ONLY** — an in-memory per-IP cache-miss counter/latch within the Worker isolate, **zero KV writes**. It still returns a silent 429 on a local flood; its lost cross-isolate persistence is near-worthless against rotating IPs and was the sole source of the write-quota blow-up.
- **The Cloudflare WAF Rate-Limiting Rule (Block) on `path starts_with /api/enrich` is the designated PRIMARY distributed/volumetric shield** (owner approved to enable it — §11.6). It is no longer "optional/recommended"; it is the flood layer of record. Block returns a bare 429 (frictionless — NOT Managed Challenge).
- **L2 (per-source daily KV budget) is the real upstream-quota guarantee.** With L1 off the KV write pool, total KV writes = L2 (~250/day coalesced) + L3 report per-IP counter (tens/day) « 1,000/day **regardless of IP cardinality**. The §5 math is corrected accordingly: the ≤~400/day figure now holds for ALL flood shapes, not only low-IP-cardinality ones.

### 11.2 [MAJOR fix] L2 budget write-count predicate = only sources ACTUALLY DISPATCHED.
Counting "each source present in `result.sources` OR `result.errors`" over-counts: budget-blocked AND not-configured skips both land in `errors[]` (collectResults pushes all skips there, enrich.mjs:715-716), so a budget-blocked source keeps incrementing → coalesced flush every 25 → volume-proportional writes on an already-blocked source under a novel-indicator flood. **Fix:** the wrapper increments the budget counter ONLY for sources it actually dispatched an upstream call for — i.e. `dispatched = applicable − budgetBlocked − notConfigured`, both computable in the wrapper. Never infer "did we call it" from `errors[]` (a 429/timeout that DID call and a budget/not-configured skip that did NOT both look like `{source, reason}`).

### 11.3 [minor] `enrich()` signature changes too — not "one additive change".
Threading `budgetBlocked` into `planSources` requires editing `enrich()`'s signature (enrich.mjs:774) + its internal `planSources(type, env)` call (enrich.mjs:779) to accept/forward the arg. The plan MUST pick one: (a) add the 6th `budgetBlocked` param through `enrich()`→`planSources`; OR (b) have the Function wrapper orchestrate the phases via the exported `_internals` and never touch `enrich()`. Recommend (a) — smaller, keeps one entry point. The §0 "exactly one additive, pure signature change" is corrected to "additive changes to `planSources` + `enrich()` signatures; behavior additive."

### 11.4 [minor] Budgets keyed by source `.key`, but rows carry `.name`.
`result.sources`/`errors` rows carry `.name` ("AbuseIPDB"), not `.key`. The wrapper builds a `name→key` map from `_internals.SOURCES` to attribute a dispatched source to its budget key.

### 11.5 [minor] NAT/shared-egress caveat + cite fix.
A SOC behind one corporate NAT triaging many DISTINCT novel indicators in a burst could approach `IP_LIMIT` on one IP. Mitigated by cache-miss-only counting (re-checking the same IOC is a cache hit, uncounted) + the generous default + WAF-primary (the in-isolate L1 is a soft backstop, not the main gate). Keep the default generous; tune from telemetry, never pre-emptively. Cite fix: OTX `key` is enrich.mjs:495 (not :494).

### 11.6 Owner decisions (LOCKED)
- **WAF rule: INCLUDED** as the primary flood shield. Owner enables it in the Cloudflare dashboard: a single Rate-Limiting Rule, `path starts_with /api/enrich`, **Block** action (bare 429, not Managed Challenge), the free-plan ~10s counting window. Code ships independently and does NOT depend on the rule existing (ships dark).
- **Per-IP in-isolate limit default:** 60 cache-misses / 10-min window / IP, 15-min soft block. Generous by design; tunable later.
- **Ships dark:** the KV-dependent layers (L2 budget, L3 report per-IP) no-op until an `env.KV` namespace is bound in the dashboard; the in-isolate L1 works with no config. New owner-config: bind one KV namespace as `env.KV` + enable the WAF rule.
