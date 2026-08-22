# Enrich — Non-Blocking Context Sources Design Spec

**Track:** B1 · **Status:** proposed (2026-08-22) · **Author:** spec-author (design only — no implementation)
**Reviewers:** SOC-Analyst + Infrastructure panel → then a written plan.
**Supersedes:** the stopgap in `c432a82` (capped OTX/RDAP timeouts to 1500ms). This makes context *non-gating*, not merely *faster-gating*.

---

## 0. SCOPE BOUNDARY (anti-drift — read before touching anything)

**Goal (one sentence).** Make the two throttled *context* sources (OTX, RDAP) ride along in the `/api/enrich` JSON **only if they have already resolved by the time the critical-path sources settle**, so the card returns at verdict-source speed (~0.3–0.8s typical) and a slow context source is silently omitted rather than gating the response.

**In scope.**
- Re-architect the `Promise.allSettled` response assembler in `enrich()` (`lib/enrich.mjs` ~lines 587–617) into a phased assembler that (a) awaits only the *blocking* set and (b) attaches non-blocking context sources only when they are ready within a short bounded grace.
- Introduce a per-source **`blocking`** axis (scheduling), orthogonal to the existing **`kind`** axis (semantics), and set `blocking:false` on **OTX and RDAP only**.
- Decouple `partial` (and therefore the edge-cache decision) from non-blocking context outcomes.
- New unit tests against the existing vitest harness proving verdict-speed return with a slow context source absent.

**Explicitly OUT of scope.**
- **Abuse-hardening** — Turnstile, rate-limiting, KV request budgets. That is **Track B2**. This spec must not add any auth/limit/budget logic; it only leaves clean seams for it (see §6).
- **Own-OSINT-dataset / check-first** — a local corpus consulted before upstreams. That is **Track B3**. No dataset, no cache-warming, no persistence here.
- **Removing any source.** OTX and RDAP stay wired and configured; they merely stop *blocking*. ipinfo/urlscan/etc. are untouched.
- **Reporting / admin / web-route code** — owned by **Track A**. Do not touch.
- **Client / card-render changes.** None are required (see §5, verified against `web/src/components/hero/heroLayers.ts` and `shared/verdict/map.ts`). If a reviewer believes one is unavoidable, it must be justified in the plan, not assumed here. The *one* contract nuance — `partial` no longer equals `errors.length > 0` — is already tolerated by the client (`shared/verdict/map.ts:147` reads `body.partial` first); no client edit follows from it.
- **Retuning verdict-source timeouts** (`UPSTREAM_TIMEOUT_MS`). Untouched — changing it risks dropping *verdict* sources, which is forbidden.

**Files this track OWNS.**
- `lib/enrich.mjs` — the assembler, the `blocking` axis, the `partial` rule. Primary and (expected) sole edit.
- `functions/api/enrich.js` — **owned but expected UNCHANGED.** The cache key, headers, and `if (!result.partial)` gate all keep working as-is (§5). Touch only if the plan proves it unavoidable, with justification.
- `lib/__tests__/enrich.test.mjs` — new tests appended.

**Downstream note — B2/B3 build on this assembler.** The new assembler is defined in §4 as a **clean, phased interface** (`plan → dispatch → collect → assemble`) with named internal seams exported via `_internals`, precisely so Track B2 (budget/limit at `plan`/`dispatch`) and Track B3 (check-first + warm-fill at `plan`/`collect`) can extend it without a rewrite. Preserving these seams is a hard requirement of this track, called out again in §6.

---

## 1. Problem, grounded in the code

`/api/enrich` fans out to every applicable source and awaits them **together** before returning one JSON body:

- `lib/enrich.mjs:591–592` — `const settled = await Promise.allSettled(usable.map(s => s.run(...)))`. The whole response cannot resolve until the *slowest* member of `usable` settles.
- `SOURCES` (`lib/enrich.mjs:535`) = `[ABUSEIPDB, VIRUSTOTAL, GREYNOISE, MALWAREBAZAAR, IPINFO, URLSCAN, RDAP, OTX]`.
- Two members are throttled from Cloudflare egress and are **context** (`kind:"context"`, never a verdict): **RDAP** (`:441`, `RDAP_TIMEOUT_MS=1500` at `:31`) and **OTX** (`:486`, `OTX_TIMEOUT_MS=1500` at `:36`). `c432a82` capped both to 1500ms, cutting worst case from ~9s to ~1.5s — but they **still sit inside `Promise.allSettled`**, so they still add up to 1.5s to every uncached lookup.
- The north star (`BACKLOG.md:8`) is that this loop be "as painless and efficient as possible." 1.5s of avoidable latency on the product's core interaction is the miss this track closes.

**The critical distinction the code already half-encodes.** `kind:"context"` is a *semantic* label — "not a verdict, excluded from the consensus tally" (`consensus()` at `lib/enrich.mjs:556` filters `r.kind !== "context"`). It is **not** a latency label. Proof: **ipinfo is also `kind:"context"`** (`:343`) yet it is fast *and* load-bearing — it is the sole carrier of the globe-pin coordinates the UI lands on (`web/src/components/hero/heroLayers.ts:276–294`; `coordsFrom` does `sources.find(s => s.kind === "context")` and reads the `Coordinates` fact). Dropping ipinfo would break the pin. So **"non-blocking" cannot mean "every `kind:context` source."** It must be a new, deliberately narrow flag applied to the two throttled sources only.

---

## 2. Design axes

Two **orthogonal** per-source properties:

| Axis | Field | Meaning | Values today |
|---|---|---|---|
| Semantic | `kind` | Does it vote in the consensus tally? | `"context"` on ipinfo, RDAP, OTX; absent (⇒ verdict) on the rest |
| Scheduling | **`blocking`** *(new)* | Must the response wait for it? | default `true`; **`false` on RDAP and OTX only** |

The blocking partition:

- **Blocking / critical-path** (`blocking !== false`): AbuseIPDB, VirusTotal, GreyNoise, MalwareBazaar, **ipinfo**, urlscan. The response awaits these. ipinfo stays here because it is fast and feeds the pin.
- **Non-blocking / ride-along** (`blocking === false`): **RDAP, OTX**. Attached only if ready within the grace window; otherwise silently omitted.

Per-indicator-type breakdown (for reviewer sanity):

| Type | Blocking (awaited) | Non-blocking (ride-along) |
|---|---|---|
| ipv4 / ipv6 | AbuseIPDB, VirusTotal, GreyNoise, ipinfo | OTX |
| domain | VirusTotal, urlscan | RDAP, OTX |
| url | VirusTotal, urlscan | OTX |
| md5 / sha1 / sha256 | VirusTotal, MalwareBazaar | OTX |

---

## 3. Options considered

**(a) Attach-if-already-settled** (settled-flag wrapper, or race each context promise against the verdict-settle signal). Context data is included only if its promise has resolved by the moment the blocking set settles. **Zero added latency**, but brittle at the microtask boundary: a context promise that resolves in the *same tick* as the verdicts may not have flushed its `.then` when we synchronously read a flag, so it would be dropped even though it was effectively ready.

**(b) Short bounded grace after verdicts settle.** Await the blocking set, then give the non-blocking set a small fixed window (`GRACE_MS`) measured *from the verdict-settle moment*; take whatever settles within it, drop the rest. Adds **at most `GRACE_MS`** to a cache-miss floor, and only when context is close-but-not-done.

**(c) Strict total deadline** across all sources. **Rejected** — a single wall-clock cap risks dropping a *verdict* source that is merely slow, violating the "must not drop or mis-order verdict sources" invariant. Verdict-source latency is bounded separately and unchanged (`UPSTREAM_TIMEOUT_MS=4500`).

### Recommendation — (a)+(b) hybrid: **grace-race, verdict-anchored**

Start every source promise at once (verdict + context, exactly as today). Await `Promise.allSettled` of the **blocking** set. Then race each **non-blocking** promise against a `setTimeout(GRACE_MS)` sentinel; attach the winners, drop the losers.

This hybrid gets the best of both and is **deterministic by JS event-loop semantics**, which is what makes it clean to test:

- A context source that is *genuinely ready* — resolved, or resolvable purely through queued microtasks (e.g. a test mock with no delay) — **always beats** even `setTimeout(0)`, because the entire microtask queue drains before any macrotask/timer fires. So fast context rides along, reliably, with no microtask-boundary flakiness (this is why every existing OTX test in `enrich.test.mjs` stays green — see §7).
- A context source blocked on **real network I/O** that takes longer than `GRACE_MS` loses the race and is dropped. That is precisely the throttled-OTX/RDAP-from-a-Worker case.

`GRACE_MS` is the single tuning knob. Recommended default **`250`** as a conservative near-miss catch; **`0`** collapses the mechanism to pure "attach only if already microtask-ready" (strictest no-gate). The panel picks the number; the mechanism is identical either way. Whatever the value, the *maximum* latency this adds over a verdict-only response is `GRACE_MS`, bounded and predictable.

**Accepted tradeoff (explicit).** Because OTX/RDAP are throttled from the Worker, on a cache-miss they will *usually* lose the grace race and be absent — and the fast, context-less response is what gets cached for the next 15 minutes (`max-age=900`). So slow-but-eventually-successful context is dropped, and often stays dropped until the cache entry expires. **This is the intended behavior per the speed mandate** (`BACKLOG.md:8`; task brief). If the owner later wants context reliably present, that is a warm-fill/own-dataset approach — **Track B3**, not this track — and §6 leaves the seam for it.

---

## 4. The new assembler (clean, phased interface)

Replace the monolithic block at `lib/enrich.mjs:587–617` with four named phases. `enrich()`'s **public signature is unchanged** (`enrich(fetchImpl, type, q, env, now)`), and the response shape is unchanged except the `partial` rule (§4.3). All phase functions are pure/injectable and exported via `_internals` for tests and for B2/B3 to compose.

### 4.1 `planSources(type, env) → Plan`

Pure. Resolves applicability, key-usability, and the blocking partition. No I/O.

```
Plan = {
  blocking:    Source[],   // awaited
  nonBlocking: Source[],   // ride-along (blocking === false)
  skipped:     { source, reason }[],   // not-configured, split by blocking-ness (see §4.3)
}
```

- `applicable = SOURCES.filter(s => s.types.includes(type))` (unchanged, `:582`).
- `usable = applicable.filter(s => s.optionalKey || env[s.key])` (unchanged, `:587`).
- Partition `usable` by `s.blocking !== false`.
- `skipped` retains today's not-configured accounting (`:588–589`) but is tagged with whether each skipped source was blocking, so §4.3 can compute `partial` correctly.

*B2/B3 seam:* B3's check-first and B2's budget both hook here (drop/replace sources before dispatch).

### 4.2 `dispatchSources(fetchImpl, ind, env, plan) → { blockingPromises, contextRaces }`

Starts all promises immediately (identical fan-out timing to today — nothing is serialized).

- `blockingPromises = plan.blocking.map(s => s.run(fetchImpl, ind, env[s.key]))`
- Each non-blocking promise is wrapped in the **grace-race** helper so it is *always terminally handled* (no unhandled-rejection noise in the Worker even when dropped):

```js
const PENDING = Symbol("pending");

// Resolves to { source, ok:true, value } | { source, ok:false } | PENDING.
// The .then(...) attaches a rejection handler, so a later reject (e.g. the
// source's own AbortSignal.timeout firing after we've moved on) is swallowed.
function graceRace(source, promise, ms) {
  const tagged = promise.then(
    (value) => ({ source, ok: true, value }),
    ()      => ({ source, ok: false }),
  );
  const timer = new Promise((res) => setTimeout(() => res(PENDING), ms));
  return Promise.race([tagged, timer]);
}
```

- `contextRaces = plan.nonBlocking.map(s => graceRace(s, s.run(...), GRACE_MS))`.

*Note:* the timer starts at dispatch, but every non-blocking `run()` is fired in the same tick as the blocking ones, so effectively the grace runs *concurrently* with the blocking await. If the blocking await alone already exceeds `GRACE_MS` (the common case), the timers have long since fired and `collect` never stalls — the grace is a *ceiling on extra wait past verdict-settle*, never an added floor. (If a reviewer prefers the grace to be measured strictly *from verdict-settle*, start the timers in `collect` instead — functionally near-identical because context is either already-microtask-ready or slow-network; called out as a plan-time decision.)

*B2 seam:* a KV budget can wrap `dispatchSources` to cap concurrent subrequests.

### 4.3 `collectResults(blockingPromises, contextRaces, plan) → { sources, errors, partial }`

```js
const blockingSettled = await Promise.allSettled(blockingPromises);
const contextSettled  = await Promise.all(contextRaces); // each already race-bounded
```

Assembly rules:

- **Order preservation (invariant).** Build `sources` by placing each result back into its original position within `usable`, then compacting out empty slots (dropped context). Verdict sources never move; a ride-along context source appears in its original slot or not at all. This satisfies "must not drop or mis-order verdict sources."
- **Blocking results:** fulfilled → push to `sources`; rejected → push `{ source, reason }` to `errors` (unchanged from `:596–601`).
- **Non-blocking results:** `ok:true` → push `value` to `sources` (rides along). `PENDING` (dropped-slow) or `ok:false` (errored in-grace) → **silently omitted**: not in `sources`, **not in `errors`**. Their absence is the honest "no record / blank" state the card already renders (§5).
- **`skipped` (not-configured):**
  - Blocking source not configured → into `errors` (unchanged; contributes to `partial`).
  - Non-blocking source not configured → into `errors` for honesty (per the doctrine at `lib/enrich.mjs:584–586`, an unconsulted source is named, never silent), **but excluded from `partial`**.
- **`partial` (new rule — the crux for caching):**
  ```
  partial = (# blocking sources that failed OR were not-configured) > 0
  ```
  i.e. `partial` reflects **critical-path health only**. A dropped/errored/unconfigured *non-blocking context* source never sets `partial`. This is what preserves — and slightly improves — the edge-cache behavior (§5).

### 4.4 `assemble(ind, type, now, collected) → response`

`consensus()` is called on `sources` **unchanged** (`:603`). Because context sources never vote (`consensus` filters `kind:"context"` at `:556`), **`consulted`, `flagged`, and `tone` are byte-identical whether or not context rode along** — a strong card-correctness guarantee: the verdict tally is invariant under context omission. Return object is unchanged in shape (`:604–617`), with `partial` now per §4.3.

---

## 5. Why `functions/api/enrich.js` and the client need no change

- **Edge cache (`functions/api/enrich.js:33–46`).** The cache key (normalized URL) is unchanged. The gate `if (!result.partial) await cache.put(...)` (`:45`) still holds — and now behaves *better*: a slow context source no longer forces `partial:true`, so a fast, correct, context-less card **gets cached** instead of being re-fetched every time. We are never caching a *blocking* partial (that rule is intact). Headers/`max-age=900` unchanged.
- **Client tally (`shared/verdict/map.ts:126–149`).** `mapResponse` splits `rows.filter(r => r.kind === "context")` into a separate `context` list (`:132`); fewer context rows ⇒ a shorter `context` list ⇒ honest omission, no error. It reads `body.partial` first (`:147`), so the decoupled `partial` is already honored; the `?? errors.length > 0` fallback never triggers because the server always sends `partial`.
- **Globe pin (`web/src/components/hero/heroLayers.ts:276–294`).** `coordsFrom` reads the *first* `kind:"context"` row for coordinates. ipinfo is **blocking** and always awaited, so for IPs the pin is unaffected. For domains there are no coordinates anyway (`no-geo` path in `enrichFly.ts:29,63`), so dropping RDAP/OTX changes nothing there.
- **`errors` rendering (`FreshnessStrip.tsx`, `TipCard.tsx:185`).** `TipCard` shows "Some sources were unavailable" only on `partial`; with the new rule a dropped context source won't trigger it (correct — it wasn't *unavailable*, it just didn't ride along). A not-configured context source still lists in `errors` (honest) without the scary sentence.

---

## 6. Extension seams for B2 / B3 (preserve these)

| Track | Hooks | What it will do |
|---|---|---|
| **B2** (abuse-hardening) | wrap `dispatchSources`; extend `planSources` | Cap concurrent subrequests / enforce a per-caller KV budget by trimming `plan.blocking`/`plan.nonBlocking` before dispatch. Turnstile/rate-limit live in `functions/api/enrich.js`, upstream of `enrich()`. |
| **B3** (own dataset / check-first) | extend `planSources`; extend `collectResults` | Consult a local corpus in `planSources` and short-circuit sources already answered; optionally `ctx.waitUntil()` a warm-fill in the Pages function so a dropped context source populates the cache for the *next* request. |

Hard requirement of B1: keep the four phases as separately-exported, side-effect-light functions (via `_internals`) so neither downstream track needs to re-open the monolith. Do **not** implement any B2/B3 behavior now.

---

## 7. Testing approach (against the existing mocked harness)

The harness (`lib/__tests__/enrich.test.mjs`) injects a mock `fetch` (no network). Extend it — do not replace it.

**Backward compatibility (must stay green as-is).** Every existing OTX test mocks OTX resolving with *no delay* (`mockFetch(PULSES)`, `:10–17`). Under the grace-race, a zero-delay mock is microtask-ready and wins against any `GRACE_MS ≥ 0`, so OTX still rides along and those assertions (`:29–74`) pass unchanged. This is the regression guardrail.

**New tests to add:**

1. **Slow context is dropped at verdict speed (deterministic, no timers — primary).**
   Use a manually-gated deferred so the assertion is timing-independent:
   ```js
   function deferred() { let resolve; const promise = new Promise(r => (resolve = r)); return { promise, resolve }; }

   it('returns without a slow context source; it does not gate the response', async () => {
     const gate = deferred();
     let enrichReturned = false, otxSettledAfterReturn = null;
     const fetchImpl = async (url) => {
       if (String(url).includes('otx.alienvault.com')) {
         await gate.promise;                    // OTX blocks until we release it
         otxSettledAfterReturn = enrichReturned;
         return { status: 200, ok: true, json: async () => PULSES };
       }
       if (String(url).includes('abuseipdb.com'))
         return { status: 200, ok: true, json: async () => ({ data: { abuseConfidenceScore: 0, totalReports: 0 } }) };
       return { status: 404, ok: false, json: async () => ({}) }; // GreyNoise/ipinfo resolve fast
     };
     const out = await enrich(fetchImpl, 'ipv4', '1.2.3.4', { ABUSEIPDB_API_KEY: 'x', OTX_API_KEY: 't' });
     enrichReturned = true;

     expect(out.sources.find(s => s.name === 'AlienVault OTX')).toBeUndefined(); // dropped
     expect(out.sources.find(s => s.name === 'AbuseIPDB')).toBeTruthy();          // verdicts present
     expect(out.partial).toBe(false);                                            // ⇒ cacheable
     expect(out.errors.some(e => e.source === 'AlienVault OTX')).toBe(false);     // silent, not an error

     gate.resolve();                                                             // let OTX finish late
     await gate.promise;
     expect(otxSettledAfterReturn).toBe(true); // proves enrich returned BEFORE OTX settled
   });
   ```
   This *proves* the response resolved before the context source settled, with no reliance on wall-clock timing.

2. **Wall-clock latency assertion (secondary, belt-and-suspenders).** Same slow-OTX shape, but delay OTX with a real `setTimeout(1500)` inside the mock; assert `performance.now()` delta for `enrich(...)` is `< 500ms` (well under 1500ms). Generous threshold to avoid CI flakiness; the deterministic test above is the real proof.

3. **Fast context still rides along.** OTX mocked with no delay ⇒ present in `sources` (guards the ride-along path; overlaps the existing tests but asserts the new partition explicitly).

4. **`partial`/cache invariant.** With a slow (dropped) OTX and all blocking sources succeeding, `out.partial === false`. With a *blocking* source rejecting (mock AbuseIPDB → `status:500`), `out.partial === true`. Locks the decoupling: only blocking health drives `partial`.

5. **Tally invariance.** Assert `consulted`/`flagged`/`tone` are identical between a run where OTX rides along (fast mock) and one where it is dropped (gated mock). Proves context omission never moves the verdict.

6. **Order preserved.** Assert the `sources` array order matches `usable` order with the dropped context slot compacted out (verdict sources in their original relative order).

*Optional:* a `vi.useFakeTimers()` variant of test 1 is possible but the deferred-gate pattern is preferred — it removes timer/microtask interleaving entirely.

---

## 8. Acceptance criteria

| # | Criterion | How to measure |
|---|---|---|
| A1 | On a cache-miss, the response resolves at **verdict-source speed** — target **~0.3–0.8s typical**, and never waits on OTX/RDAP. | Deterministic test 1 (returns before context settles) + latency test 2 (`< 500ms` with a 1500ms context source). Live: dev-tools timing on a fresh (uncached) IP and domain, compared against the pre-change ~1.5s floor. |
| A2 | A slow OTX/RDAP is **silently omitted** — absent from `sources`, absent from `errors`, not flagged `partial`. | Test 1 assertions. |
| A3 | A **fast** OTX/RDAP still **rides along** (present in `sources`). | Test 3 + all existing OTX tests green. |
| A4 | **Verdict tally unchanged** by context omission (`consulted`/`flagged`/`tone` invariant). | Test 5. |
| A5 | **Verdict sources never dropped or mis-ordered.** | Test 6 + existing AbuseIPDB/VT assertions. |
| A6 | **Edge cache preserved/improved:** blocking-partial still not cached; a fast context-less card IS cached. | Test 4; `functions/api/enrich.js:45` unchanged; live: second lookup of the same indicator served from edge cache (fast, no upstream calls). |
| A7 | **Globe pin unaffected** for IPs (ipinfo still awaited). | Manual: live IP lookup lands the pin; `heroLayers` coordsFrom still finds ipinfo. |
| A8 | `enrich()` public signature and response shape unchanged (except the `partial` rule). | Existing tests compile/pass; no client edit required. |
| A9 | **No client, reporting, admin, or web-route files changed.** No B2/B3 behavior added. | Diff review: only `lib/enrich.mjs` (+ tests) touched. |

---

## 9. Anti-drift guardrails

- **Do not** treat `kind:"context"` as the non-blocking selector. Only `blocking:false` (OTX, RDAP) is. ipinfo stays blocking.
- **Do not** let any non-blocking outcome set `partial` — it silently breaks the edge cache and makes the loop slower, the opposite of the goal.
- **Do not** retune or remove `UPSTREAM_TIMEOUT_MS`, verdict sources, or the cache key/headers.
- **Do not** add Turnstile, rate-limits, KV budgets (B2), a local dataset, or cache warm-fill (B3). Leave the seams; build nothing.
- **Do not** touch reporting/admin/web-route code (Track A) or any client file.
- Keep the four assembler phases separately exported via `_internals` so B2/B3 extend rather than rewrite.
- Every non-blocking promise MUST carry a terminal rejection handler (the `graceRace` wrapper) — a dropped source that later rejects must not surface as an unhandled rejection in the Worker.
```
