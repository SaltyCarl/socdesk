# Enrich Non-Blocking Context Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the two throttled *context* sources (OTX, RDAP) ride along in the `/api/enrich` JSON **only if they have already resolved by the time the blocking (critical-path) sources settle**, so a cache-miss card returns at verdict-source speed (~0.3–0.8s typical) instead of eating the ~1.5s OTX/RDAP floor. A slow context source is silently omitted (surfaced observably via a new additive `skipped_context` field), never gating the response and never forcing `partial`/uncacheable.

**Architecture:** Replace the monolithic `Promise.allSettled` assembler in `enrich()` (`lib/enrich.mjs:591–617`) with four separately-exported, side-effect-light phases — `planSources → dispatchSources → collectResults → assemble` — that Track B2 (budget/limit) and Track B3 (check-first/warm-fill) extend without re-opening the monolith. A new per-source **`blocking`** axis (scheduling), orthogonal to the existing **`kind`** axis (semantics), is set `blocking:false` on **OTX and RDAP only**. `collectResults` awaits only the blocking set, then grace-races each non-blocking source against a **collect-anchored** timer with the shipped default **`GRACE_MS = 0`** (ride along only if already microtask-ready at verdict-settle). `partial` is recomputed from the **blocking axis** alone, decoupling the edge-cache decision (`functions/api/enrich.js:45`) from context health.

**Tech Stack:** Node ESM (`lib/enrich.mjs`, pure logic, no Cloudflare bindings — `fetchImpl` injected). Tests: vitest in a plain `node` environment (`web/vitest.config.ts:27–28` globs `../lib/**/*.test.mjs`; run from `web/`). Consumer regression: Playwright `site-tests/specs/enrich.spec.js` imports the real assembler with a fake fetch (no network, no keys). No React/TS/DOM touched.

**Spec:** `C:\Users\Carl\Desktop\Projects\VIGIL\docs\superpowers\specs\2026-08-22-enrich-nonblocking-context-design.md` — **its trailing "Panel review amendments (APPROVED 2026-08-22)" section is binding and OVERRIDES any earlier spec text it conflicts with.** This plan folds ALL amendments (GRACE_MS=0 collect-anchored; additive `skipped_context`; fast-fail→`errors` without `partial`; `partial` from the blocking axis never `kind`; ipinfo emitted before OTX).

---

## Global Constraints

Transcribed from the binding Panel amendments; do not deviate.

- **GRACE_MS = 0 (OWNER-APPROVED), collect-anchored.** Start the grace timer AFTER `await Promise.allSettled(blocking)`. With grace 0, a context source rides along ONLY if already resolved by verdict-settle (free, no dead wait); everything else drops. The mechanism keeps a tunable `GRACE_MS` knob (`collectResults(..., grace)`), but the SHIPPED default is `0` (OTX/RDAP are reliably >1s from Cloudflare, so any positive grace is mostly dead wait — the speed mandate wins).
- **Additive `skipped_context: string[]`.** Lists non-blocking sources dropped for *slowness* (PENDING past grace). It MUST NOT touch `errors` or `partial`, and needs NO client change (the client ignores unknown fields; verified `shared/verdict/map.ts` reads only `sources`/`errors`/`partial`). It makes a speed-drop measurable and honors the enrich.mjs "don't lie by omission" doctrine (`lib/enrich.mjs:584–586`).
- **Fast-fail honesty.** An in-grace `ok:false` — a FAST, real error (e.g. a fat-fingered OTX key → 401 via `getJson` throwing "rejected the API key", `lib/enrich.mjs:107–108`) — is routed into `errors` WITHOUT setting `partial` (mirrors the not-configured case). Do NOT silently cache-clean a broken key. Only genuinely-slow (PENDING) drops stay silent → `skipped_context`.
- **`partial` from the `blocking` axis, NEVER `kind`.** `partial = (# blocking sources that failed OR were not-configured) > 0`. A dropped/errored/not-configured *non-blocking context* source never sets `partial`. ipinfo is `kind:"context"` but **blocking**, so it still contributes to `partial` — this is exactly why the axis, not `kind`, drives it.
- **ipinfo emitted BEFORE OTX in `sources` (order preservation is load-bearing).** The globe pin reads the FIRST `kind:"context"` row via `parseCoords` (`web/src/components/hero/heroLayers.ts`). Build `sources` in `usable` (SOURCES) order and compact out dropped slots; verdict sources never move.
- **Four-phase assembler as a clean interface B2/B3 extend.** Keep `planSources`/`dispatchSources`/`collectResults`/`assemble` separately exported via `_internals` (B2 hooks `plan`/`dispatch`; B3 hooks `plan`/`collect`). Do NOT implement any B2/B3 behavior (Turnstile, rate-limit, KV budget, local dataset, warm-fill) now — leave the seams, build nothing.
- **MUST NOT drop or mis-order verdict sources.** MUST NOT retune or remove `UPSTREAM_TIMEOUT_MS` (`lib/enrich.mjs:23`), any verdict source, or the cache key/headers. OTX and RDAP stay wired and configured; they merely stop *blocking*.
- **Every non-blocking promise MUST carry a terminal rejection handler** (the `tagContext` wrapper) — a dropped source that later rejects (its own `AbortSignal.timeout` firing after we moved on) must not surface as an unhandled rejection in the Worker.
- **Scope = `lib/enrich.mjs`** (assembler, `blocking` axis, `partial` rule) + `lib/__tests__/enrich.test.mjs` (new tests) + a test-only pre-flight correction to `site-tests/specs/enrich.spec.js` (see Task 0). `functions/api/enrich.js` is **owned but expected UNCHANGED**. No client, reporting, admin, or web-route file changes.
- **NO AI attribution.** All commits authored as SaltyCarl; no `Co-Authored-By`, no Claude/AI references in commits, comments, or docs (`github.com/SaltyCarl/*` policy).
- **Node-only vitest, DETERMINISTIC.** Pure assembler logic TDD'd against the existing mock-fetch harness using microtask-ready mocks + the deferred-gate technique. No real timers where avoidable (the grace timer `setTimeout(0)` is the one unavoidable macrotask; the SLOW-source proof uses a manually-gated deferred, not a wall clock). The final gate MUST also run `site-tests/specs/enrich.spec.js`.

---

## File Structure

- **Modify `lib/enrich.mjs`** — add `blocking:false` to the `OTX` (`:478`) and `RDAP` (`:437`) source objects; add module consts `GRACE_MS`/`PENDING` and helpers `tagContext`/`settleWithin`; replace the assembler body (`:577–618`) with the four phases; extend the `_internals` export (`:620`).
- **Modify `lib/__tests__/enrich.test.mjs`** — append a new `describe('non-blocking context (Track B1)')` block with the deterministic deferred-gate drop test, fast ride-along, fast-fail→errors, `skipped_context`, the `partial`/cache matrix, tally-invariance, and order-preservation tests. Do not alter the existing OTX/AbuseIPDB blocks (they are the backward-compat guardrail).
- **Modify `site-tests/specs/enrich.spec.js`** (Task 0, test-only) — correct two PRE-EXISTING stale assertions (`:141`, `:215`) that predate OTX's addition to `SOURCES`, so the mandated Playwright gate is green. No behavior change.
- **UNCHANGED (verify in diff):** `functions/api/enrich.js`, `shared/verdict/map.ts`, `shared/card/model.ts`, `web/src/components/hero/heroLayers.ts`, and every other file.

### Target assembler shape (end state, for reference — built incrementally by Tasks 1–4)

```js
const GRACE_MS = 0; // SHIPPED default (panel-approved). Collect-anchored: the grace
                    // starts AFTER the blocking set settles. 0 ⇒ a context source
                    // rides along only if already resolved by verdict-settle. Knob
                    // stays tunable via collectResults(..., grace) for Track B3.

const PENDING = Symbol("pending");

/** Terminal-handle a non-blocking source promise so it NEVER rejects. A dropped
 *  source that later rejects (its AbortSignal.timeout firing after we've moved
 *  on) must not surface as an unhandled rejection in the Worker. */
function tagContext(source, promise) {
  return promise.then(
    (value) => ({ source, ok: true, value }),
    (err)   => ({ source, ok: false, reason: String(err?.message ?? err).slice(0, 120) }),
  );
}

/** Race an already terminal-handled context result against a grace timer.
 *  Deterministic by event-loop semantics: an already-microtask-ready `tagged`
 *  always beats even setTimeout(0) (the microtask queue drains before any timer
 *  fires), so a zero-delay mock rides along and a real-network laggard drops. */
function settleWithin(tagged, ms) {
  let t;
  const timer = new Promise((res) => { t = setTimeout(() => res(PENDING), ms); });
  return Promise.race([tagged, timer]).finally(() => clearTimeout(t));
}

/* ---- phase 1: plan (pure, no I/O) ---- */
export function planSources(type, env = {}) {
  const applicable = SOURCES.filter((s) => s.types.includes(type));
  const usable = applicable.filter((s) => s.optionalKey || env[s.key]);
  const blocking = usable.filter((s) => s.blocking !== false);
  const nonBlocking = usable.filter((s) => s.blocking === false);
  const skipped = applicable
    .filter((s) => !s.optionalKey && !env[s.key])
    .map((s) => ({ source: s.name, reason: "not configured", blocking: s.blocking !== false }));
  return { usable, blocking, nonBlocking, skipped };
}

/* ---- phase 2: dispatch (starts ALL I/O in one tick) ---- */
export function dispatchSources(fetchImpl, ind, env, plan) {
  const blocking = plan.blocking.map((s) => ({ source: s, promise: s.run(fetchImpl, ind, env[s.key]) }));
  // Fire the non-blocking run()s NOW (identical fan-out timing to today) and
  // terminal-handle each immediately. The grace TIMER is started later, in
  // collectResults, so the grace is measured from verdict-settle (collect-anchored).
  const context = plan.nonBlocking.map((s) => ({ source: s, tagged: tagContext(s, s.run(fetchImpl, ind, env[s.key])) }));
  return { blocking, context };
}

/* ---- phase 3: collect (await blocking, then grace-race context) ---- */
export async function collectResults(dispatched, plan, grace = GRACE_MS) {
  const blockingSettled = await Promise.allSettled(dispatched.blocking.map((b) => b.promise));
  // Grace starts HERE — after the blocking set settled (collect-anchored).
  const contextResults = await Promise.all(dispatched.context.map((c) => settleWithin(c.tagged, grace)));

  const slots = new Array(plan.usable.length).fill(null); // order-preserving assembly
  const errors = [];
  let blockingFailures = 0;

  // not-configured skips: ALL named in `errors` (honesty); only blocking ones
  // count toward `partial`.
  for (const sk of plan.skipped) {
    errors.push({ source: sk.source, reason: sk.reason });
    if (sk.blocking) blockingFailures++;
  }

  dispatched.blocking.forEach((b, i) => {
    const r = blockingSettled[i];
    const idx = plan.usable.indexOf(b.source);
    if (r.status === "fulfilled") slots[idx] = r.value;
    else {
      errors.push({ source: b.source.name, reason: String(r.reason?.message ?? r.reason).slice(0, 120) });
      blockingFailures++;
    }
  });

  const skipped_context = [];
  dispatched.context.forEach((c, i) => {
    const r = contextResults[i];
    const idx = plan.usable.indexOf(c.source);
    if (r === PENDING) skipped_context.push(c.source.name);          // slow drop — silent + observable
    else if (r.ok) slots[idx] = r.value;                            // rides along
    else errors.push({ source: r.source.name, reason: r.reason });  // FAST fail — honest, NOT partial
  });

  return { sources: slots.filter(Boolean), errors, partial: blockingFailures > 0, skipped_context };
}

/* ---- phase 4: assemble (shape unchanged + additive skipped_context) ---- */
export function assemble(ind, type, now, collected) {
  const { consulted, flagged, tone } = consensus(collected.sources);
  return {
    indicator: ind.value, type, checked_at: now.toISOString(),
    consulted, flagged, tone,
    sources: collected.sources,
    partial: collected.partial,
    errors: collected.errors,
    skipped_context: collected.skipped_context, // additive; client ignores unknown fields
  };
}

export async function enrich(fetchImpl, type, q, env = {}, now = new Date()) {
  const check = validate(type, q);
  if (!check.ok) return { error: check.reason, status: 400 };
  const ind = { type, value: check.value };
  const plan = planSources(type, env);
  const dispatched = dispatchSources(fetchImpl, ind, env, plan);
  const collected = await collectResults(dispatched, plan);
  return assemble(ind, type, now, collected);
}

export const _internals = {
  SOURCES, b64url, GRACE_MS, PENDING,
  planSources, dispatchSources, collectResults, assemble, tagContext, settleWithin,
};
```

**Grounding note (why the deterministic tests below key VirusTotal):** for an ipv4 lookup the applicable set is `[AbuseIPDB, VirusTotal, GreyNoise, ipinfo, OTX]` (`lib/enrich.mjs:535` filtered by `types`). VirusTotal is a **blocking** source; if it is left unkeyed it becomes a blocking not-configured skip and forces `partial:true`. Spec §7 Test 1 omits `VT_API_KEY` — this plan corrects that so `partial:false` isolates the OTX-drop effect. GreyNoise and ipinfo are `optionalKey:true` (`:250`,`:339`) so they stay usable keyless and a `404`/`unrouted` mock resolves them to a fulfilled "unknown" row, never an error.

---

### Task 0: Pre-flight — correct two stale `enrich.spec.js` assertions (test-only)

**Why:** `site-tests/specs/enrich.spec.js` is **already 2-red on main**, independent of B1. OTX was added to `SOURCES` (`133a460`, 2026-08-20) with `types` covering all hashes (`lib/enrich.mjs:480`), but the two hash tests were last edited 2026-08-10 (`bfde39c`) and never updated. An unkeyed hash lookup therefore names `AlienVault OTX` as "not configured" in `errors` — correct, already-shipped honesty behavior. B1 preserves it, so the mandated Playwright gate cannot be green until these assertions match reality. This is a test-only correction, not a behavior change.

**Files:** Modify `site-tests/specs/enrich.spec.js`.

- [ ] **Step 1: Confirm the two current failures** (RED baseline that is NOT ours to introduce)

```
cd C:\Users\Carl\Desktop\Projects\VIGIL\site-tests
npx playwright test specs/enrich.spec.js --reporter=line
```
Expect exactly two failures: `:141` ("nothing consulted returns…") and `:215` ("'nothing on record' is a finding…"), both because `errors` now includes `{ source: "AlienVault OTX", reason: "not configured" }`.

- [ ] **Step 2: Correct `:149`** — the errors list for an unkeyed `sha256` lookup now includes OTX:

```js
    // VirusTotal + MalwareBazaar are key-gated; OTX (a context source that also
    // applies to hashes) is likewise not configured — all three are named, never
    // silently omitted.
    expect(r.errors.map(e => e.source).sort()).toEqual(["AlienVault OTX", "MalwareBazaar", "VirusTotal"]);
```
(`r.sources`, `consulted`, `flagged`, `tone`, `partial` assertions are unchanged and still hold: `partial` is `true` because VirusTotal + MalwareBazaar are *blocking* not-configured.)

- [ ] **Step 3: Correct `:221`** — the `sha256` "nothing on record" case (keys = AbuseIPDB/VT/GreyNoise/AbuseCH, no OTX key) now names OTX not-configured:

```js
    expect(r.errors).toEqual([{ source: "AlienVault OTX", reason: "not configured" }]); // OTX applies to hashes, key absent
    expect(r.sources.length).toBe(2);
```
Leave the surrounding `flagged`/`consulted`/`tone`/headline assertions untouched (VT `404` and MalwareBazaar `hash_not_found` both resolve to fulfilled "no record" rows, so `2` consulted → green).

- [ ] **Step 4: GREEN** — `npx playwright test specs/enrich.spec.js --reporter=line` → **17 passed**.

- [ ] **Step 5: Commit** — `git add site-tests/specs/enrich.spec.js && git commit` with message:
  `test(enrich): account for OTX not-configured on unkeyed hash lookups`
  Body: one line noting this corrects pre-existing drift from OTX's addition to SOURCES (`133a460`); no behavior change. NO attribution.

---

### Task 1: Introduce the `blocking` axis + the `planSources` phase

**Files:** Modify `lib/enrich.mjs`; Test `lib/__tests__/enrich.test.mjs`.

**Interfaces:**
- Add `blocking: false` to `OTX` and `RDAP` (data only; scheduling axis, orthogonal to `kind`).
- Add `export function planSources(type, env)` returning `{ usable, blocking, nonBlocking, skipped }` where `skipped[i] = { source, reason, blocking }`.
- `enrich()` calls `planSources` but STILL assembles the old way over `plan.usable` this task — **zero behavior change** (all existing tests stay green).
- Extend `_internals` with `planSources`.

- [ ] **Step 1: Write the failing tests** — append to `lib/__tests__/enrich.test.mjs`:

```js
import { enrich, _internals } from '../enrich.mjs'
// (the existing top-of-file import is `{ describe, expect, it }` + `{ enrich }`;
//  widen the enrich import to also pull `_internals`.)

describe('blocking axis + planSources (Track B1)', () => {
  const byName = (n) => _internals.SOURCES.find((s) => s.name === n)

  it('marks ONLY OTX and RDAP as non-blocking', () => {
    expect(byName('AlienVault OTX').blocking).toBe(false)
    expect(byName('RDAP').blocking).toBe(false)
    // ipinfo is context-but-BLOCKING (feeds the globe pin) — must stay blocking.
    expect(byName('ipinfo').blocking).toBeUndefined()
    for (const n of ['AbuseIPDB', 'VirusTotal', 'GreyNoise', 'MalwareBazaar', 'urlscan'])
      expect(byName(n).blocking, `${n} must block`).toBeUndefined()
  })

  it('partitions ipv4 sources: ipinfo blocking, OTX non-blocking', () => {
    const plan = _internals.planSources('ipv4', { ABUSEIPDB_API_KEY: 'x', VT_API_KEY: 'k', OTX_API_KEY: 't' })
    expect(plan.blocking.map((s) => s.name)).toEqual(['AbuseIPDB', 'VirusTotal', 'GreyNoise', 'ipinfo'])
    expect(plan.nonBlocking.map((s) => s.name)).toEqual(['AlienVault OTX'])
  })

  it('partitions domain sources: RDAP + OTX non-blocking, in SOURCES order', () => {
    const plan = _internals.planSources('domain', { VT_API_KEY: 'k' })
    expect(plan.nonBlocking.map((s) => s.name)).toEqual(['RDAP', 'AlienVault OTX'])
    expect(plan.usable.map((s) => s.name)).toEqual(['VirusTotal', 'urlscan', 'RDAP', 'AlienVault OTX'])
  })

  it('tags each not-configured skip with its blocking-ness', () => {
    // sha256, no keys: VT + MalwareBazaar are blocking; OTX is non-blocking.
    const plan = _internals.planSources('sha256', {})
    const skip = Object.fromEntries(plan.skipped.map((s) => [s.source, s.blocking]))
    expect(skip).toEqual({ VirusTotal: true, MalwareBazaar: true, 'AlienVault OTX': false })
  })
})
```

- [ ] **Step 2: RED** — `cd web && npx vitest run ../lib/__tests__/enrich.test.mjs` fails (`planSources` undefined; `blocking` unset).

- [ ] **Step 3: Minimal impl** in `lib/enrich.mjs`:
  - Add `blocking: false,` to the `RDAP` object (beside `kind: "context",` at `:441`) and the `OTX` object (beside `kind: "context",` at `:486`).
  - Add `export function planSources(type, env = {})` per the target-shape block above, placed just above `enrich()`.
  - In `enrich()`, replace the `applicable`/`usable`/`skipped` locals (`:582–589`) with `const plan = planSources(type, env);` and keep the OLD assembler running over `plan.usable`:

    ```js
    const plan = planSources(type, env);
    const settled = await Promise.allSettled(plan.usable.map((s) => s.run(fetchImpl, ind, env[s.key])));
    const sources = [], errors = plan.skipped.map(({ source, reason }) => ({ source, reason }));
    settled.forEach((r, i) => {
      if (r.status === "fulfilled") sources.push(r.value);
      else errors.push({ source: plan.usable[i].name, reason: String(r.reason?.message ?? r.reason).slice(0, 120) });
    });
    const { consulted, flagged, tone } = consensus(sources);
    return { indicator: ind.value, type, checked_at: now.toISOString(), consulted, flagged, tone, sources, partial: errors.length > 0, errors };
    ```
  - Add `planSources` to `_internals`.

- [ ] **Step 4: GREEN** — `cd web && npx vitest run` passes (new block + all existing lib/shared/src tests).

- [ ] **Step 5: Gate** — from `web/`: `npx vitest run` ✅, `npm run build` ✅, `npm run lint` ✅. (eslint's flat config globs `**/*.{ts,tsx}` only, so the `.mjs` change adds no lint surface; the gate confirms no TS/TSX regression.)

- [ ] **Step 6: Commit** — `feat(enrich): add non-blocking scheduling axis + planSources phase`. NO attribution.

---

### Task 2: Extract `dispatchSources` / `collectResults` / `assemble` (behavior-preserving)

**Files:** Modify `lib/enrich.mjs`; Test `lib/__tests__/enrich.test.mjs`.

**Interfaces:** `enrich()` becomes `plan → dispatch → collect → assemble`. In THIS task the four phases reproduce today's behavior **byte-for-byte**: every source (blocking AND non-blocking) is awaited to completion, `partial = errors.length > 0`, no grace, no `skipped_context` yet. This isolates the refactor from the semantic change (Tasks 3–4).

- [ ] **Step 1: Write the failing tests** — append:

```js
describe('phased assembler — behavior-preserving extraction (Track B1)', () => {
  const mockFetchOTX = (payload) => async (url) =>
    String(url).includes('otx.alienvault.com')
      ? { status: 200, ok: true, json: async () => payload }
      : { status: 404, ok: false, json: async () => ({}) }

  it('exports the four phases via _internals', () => {
    for (const k of ['planSources', 'dispatchSources', 'collectResults', 'assemble'])
      expect(typeof _internals[k]).toBe('function')
  })

  it('dispatch starts every source (blocking + non-blocking) and collect awaits them', async () => {
    const plan = _internals.planSources('domain', { VT_API_KEY: 'k', OTX_API_KEY: 't' })
    const dispatched = _internals.dispatchSources(mockFetchOTX({ pulse_info: { count: 3, pulses: [] } }),
      { type: 'domain', value: 'evil.test' }, { VT_API_KEY: 'k', OTX_API_KEY: 't' }, plan)
    expect(dispatched.blocking.length + dispatched.context.length).toBe(plan.usable.length)
    const collected = await _internals.collectResults(dispatched, plan)
    // zero-delay OTX mock is microtask-ready, so it rides along even at grace 0
    expect(collected.sources.find((s) => s.name === 'AlienVault OTX')).toBeTruthy()
  })

  it('is byte-identical to the pre-extraction response for a fully-mocked run', async () => {
    const out = await enrich(mockFetchOTX({ pulse_info: { count: 2, pulses: [
      { name: 'x', tags: ['t'], adversary: 'A', malware_families: [] }] } }),
      'domain', 'evil.test', { VT_API_KEY: 'k', OTX_API_KEY: 't' }, new Date('2026-08-22T00:00:00Z'))
    expect(out.type).toBe('domain')
    expect(out.checked_at).toBe('2026-08-22T00:00:00.000Z')
    expect(out.sources.map((s) => s.name)).toEqual(['VirusTotal', 'urlscan', 'RDAP', 'AlienVault OTX'])
    expect(out.consulted).toBe(2)   // VT + urlscan; RDAP + OTX are context, excluded
    expect(out.flagged).toBe(0)
  })
})
```

- [ ] **Step 2: RED** — phases not yet exported / `enrich` not yet phased.

- [ ] **Step 3: Minimal impl** — add `GRACE_MS`, `PENDING`, `tagContext`, `settleWithin`, and the four phase functions from the target-shape block, EXCEPT temporarily make `collectResults` behavior-preserving (no grace split): treat every non-blocking result as fully awaited and route it exactly like a blocking result.

  Interim `collectResults` for THIS task (grace race + skipped_context arrive in Tasks 3–4):
  ```js
  export async function collectResults(dispatched, plan) {
    const blockingSettled = await Promise.allSettled(dispatched.blocking.map((b) => b.promise));
    const contextSettled  = await Promise.all(dispatched.context.map((c) => c.tagged)); // await fully, no grace yet
    const slots = new Array(plan.usable.length).fill(null);
    const errors = plan.skipped.map(({ source, reason }) => ({ source, reason }));
    dispatched.blocking.forEach((b, i) => {
      const r = blockingSettled[i], idx = plan.usable.indexOf(b.source);
      if (r.status === "fulfilled") slots[idx] = r.value;
      else errors.push({ source: b.source.name, reason: String(r.reason?.message ?? r.reason).slice(0, 120) });
    });
    dispatched.context.forEach((c, i) => {
      const r = contextSettled[i], idx = plan.usable.indexOf(c.source);
      if (r.ok) slots[idx] = r.value;
      else errors.push({ source: r.source.name, reason: r.reason });
    });
    return { sources: slots.filter(Boolean), errors, partial: errors.length > 0 };
  }
  ```
  `assemble` this task returns the current shape **without** `skipped_context` (added in Task 4). Rewrite `enrich()` to the phased body. Extend `_internals` with `dispatchSources`, `collectResults`, `assemble`, `tagContext`, `settleWithin`, `GRACE_MS`, `PENDING`.

- [ ] **Step 4: GREEN** — `cd web && npx vitest run` passes; the existing OTX/AbuseIPDB blocks and all `shared`/`src` tests stay green (order-preserving slot assembly reproduces the old `usable`-order push).

- [ ] **Step 5: Gate** — `npx vitest run` ✅, `npm run build` ✅, `npm run lint` ✅ (from `web/`).

- [ ] **Step 6: Commit** — `refactor(enrich): extract plan/dispatch/collect/assemble phases (no behavior change)`. NO attribution.

---

### Task 3: Collect-anchored grace-race (GRACE_MS = 0) — verdict-speed return + slow-context drop

**Files:** Modify `lib/enrich.mjs` (`collectResults` only); Test `lib/__tests__/enrich.test.mjs`.

**Interfaces:** `collectResults(dispatched, plan, grace = GRACE_MS)` now starts the grace timer AFTER awaiting the blocking set, and races each `c.tagged` via `settleWithin`. A non-blocking result that is not microtask-ready by verdict-settle resolves to `PENDING` and is **omitted from `sources`**. In THIS task, both `PENDING` and an in-grace `ok:false` are omitted (interim); Task 4 splits them into `skipped_context` vs `errors`. `partial` stays `errors.length > 0` until Task 4.

- [ ] **Step 1: Write the failing tests** — append. The deferred-gate test is the primary, timing-independent proof:

```js
function deferred() { let resolve; const promise = new Promise((r) => (resolve = r)); return { promise, resolve } }

describe('non-blocking grace-race — verdict-speed return (Track B1)', () => {
  it('returns before a slow context source settles; it does not gate the response', async () => {
    const gate = deferred()
    let enrichReturned = false, otxSettledAfterReturn = null
    const fetchImpl = async (url) => {
      const u = String(url)
      if (u.includes('otx.alienvault.com')) {
        await gate.promise                       // OTX blocks until released
        otxSettledAfterReturn = enrichReturned
        return { status: 200, ok: true, json: async () => ({ pulse_info: { count: 1, pulses: [] } }) }
      }
      if (u.includes('abuseipdb.com'))
        return { status: 200, ok: true, json: async () => ({ data: { abuseConfidenceScore: 0, totalReports: 0 } }) }
      return { status: 404, ok: false, json: async () => ({}) } // VT/GreyNoise/ipinfo resolve fast
    }
    // VT keyed so it is NOT a blocking not-configured skip (would force partial).
    const out = await enrich(fetchImpl, 'ipv4', '1.2.3.4',
      { ABUSEIPDB_API_KEY: 'x', VT_API_KEY: 'k', OTX_API_KEY: 't' })
    enrichReturned = true

    expect(out.sources.find((s) => s.name === 'AlienVault OTX')).toBeUndefined() // dropped
    expect(out.sources.find((s) => s.name === 'AbuseIPDB')).toBeTruthy()          // verdicts present
    expect(out.errors.some((e) => e.source === 'AlienVault OTX')).toBe(false)     // silent (not a fast error)

    gate.resolve()
    await gate.promise
    expect(otxSettledAfterReturn).toBe(true) // enrich RETURNED before OTX settled
  })

  it('a fast (microtask-ready) context source still rides along', async () => {
    const fetchImpl = async (url) =>
      String(url).includes('otx.alienvault.com')
        ? { status: 200, ok: true, json: async () => ({ pulse_info: { count: 4, pulses: [] } }) }
        : { status: 404, ok: false, json: async () => ({}) }
    const out = await enrich(fetchImpl, 'ipv4', '1.2.3.4',
      { ABUSEIPDB_API_KEY: 'x', VT_API_KEY: 'k', OTX_API_KEY: 't' })
    const otx = out.sources.find((s) => s.name === 'AlienVault OTX')
    expect(otx).toBeTruthy()
    expect(otx.headline).toContain('4 pulses')
  })

  it('latency: a 1500ms context source does not delay the response (belt-and-suspenders)', async () => {
    const fetchImpl = async (url) => {
      if (String(url).includes('otx.alienvault.com'))
        return new Promise((res) => setTimeout(() => res({ status: 200, ok: true, json: async () => ({ pulse_info: { count: 1, pulses: [] } }) }), 1500))
      if (String(url).includes('abuseipdb.com'))
        return { status: 200, ok: true, json: async () => ({ data: { abuseConfidenceScore: 0, totalReports: 0 } }) }
      return { status: 404, ok: false, json: async () => ({}) }
    }
    const t0 = performance.now()
    const out = await enrich(fetchImpl, 'ipv4', '1.2.3.4',
      { ABUSEIPDB_API_KEY: 'x', VT_API_KEY: 'k', OTX_API_KEY: 't' })
    expect(performance.now() - t0).toBeLessThan(500) // well under the 1500ms context source
    expect(out.sources.find((s) => s.name === 'AlienVault OTX')).toBeUndefined()
  })
})
```

- [ ] **Step 2: RED** — the interim `collectResults` awaits context fully, so the deferred-gate test hangs/fails (OTX gates the return) and the drop assertions fail.

- [ ] **Step 3: Minimal impl** — change `collectResults` to the grace-race form: start the timer after the blocking await and race each `c.tagged` via `settleWithin(c.tagged, grace)`; omit both `PENDING` and `ok:false` for now (Task 4 splits them):

  ```js
  const contextResults = await Promise.all(dispatched.context.map((c) => settleWithin(c.tagged, grace)));
  ...
  dispatched.context.forEach((c, i) => {
    const r = contextResults[i], idx = plan.usable.indexOf(c.source);
    if (r === PENDING) { /* dropped-slow — omitted (Task 4: → skipped_context) */ }
    else if (r.ok) slots[idx] = r.value;
    else { /* fast fail — omitted (Task 4: → errors) */ }
  });
  ```
  Keep `partial = errors.length > 0` for now. (`settleWithin`/`tagContext` already added in Task 2.)

- [ ] **Step 4: GREEN** — `cd web && npx vitest run`. All three new tests pass; the existing zero-delay OTX block (backward-compat guardrail) stays green because a microtask-ready mock beats `setTimeout(0)`.

- [ ] **Step 5: Gate** — `npx vitest run` ✅, `npm run build` ✅, `npm run lint` ✅ (from `web/`).

- [ ] **Step 6: Commit** — `feat(enrich): grace-race non-blocking context (GRACE_MS=0, collect-anchored)`. NO attribution.

---

### Task 4: `skipped_context` + fast-fail → `errors` + `partial` = blocking-health

**Files:** Modify `lib/enrich.mjs` (`collectResults` + `assemble`); Test `lib/__tests__/enrich.test.mjs`.

**Interfaces:** Split the two dropped outcomes — `PENDING` (slow) → `skipped_context: string[]`; in-grace `ok:false` (fast, real error) → `errors` (with reason). Recompute `partial` from the **blocking axis** (`blockingFailures > 0`, where `blockingFailures` = blocking rejections + blocking not-configured skips). `assemble` emits the additive `skipped_context`.

- [ ] **Step 1: Write the failing tests** — append:

```js
describe('skipped_context + fast-fail + partial decoupling (Track B1)', () => {
  const gnIpinfo404 = (u) => ({ status: 404, ok: false, json: async () => ({}) })

  it('a slow context drop is listed in skipped_context, not errors, and never partial', async () => {
    const gate = deferred()
    const fetchImpl = async (url) => {
      const u = String(url)
      if (u.includes('otx.alienvault.com')) { await gate.promise; return { status: 200, ok: true, json: async () => ({ pulse_info: { count: 1, pulses: [] } }) } }
      if (u.includes('abuseipdb.com')) return { status: 200, ok: true, json: async () => ({ data: { abuseConfidenceScore: 0, totalReports: 0 } }) }
      return gnIpinfo404(u)
    }
    const out = await enrich(fetchImpl, 'ipv4', '1.2.3.4', { ABUSEIPDB_API_KEY: 'x', VT_API_KEY: 'k', OTX_API_KEY: 't' })
    expect(out.skipped_context).toEqual(['AlienVault OTX'])
    expect(out.errors.some((e) => e.source === 'AlienVault OTX')).toBe(false)
    expect(out.partial).toBe(false) // ⇒ cacheable
    gate.resolve(); await gate.promise
  })

  it('a FAST context failure (bad key → 401) is named in errors WITHOUT setting partial', async () => {
    const fetchImpl = async (url) => {
      const u = String(url)
      if (u.includes('otx.alienvault.com')) return { status: 401, ok: false, json: async () => ({}) } // fast, real error
      if (u.includes('abuseipdb.com')) return { status: 200, ok: true, json: async () => ({ data: { abuseConfidenceScore: 0, totalReports: 0 } }) }
      return gnIpinfo404(u)
    }
    const out = await enrich(fetchImpl, 'ipv4', '1.2.3.4', { ABUSEIPDB_API_KEY: 'x', VT_API_KEY: 'k', OTX_API_KEY: 't' })
    const err = out.errors.find((e) => e.source === 'AlienVault OTX')
    expect(err).toBeTruthy()
    expect(err.reason).toMatch(/API key/i)
    expect(out.skipped_context).toEqual([])
    expect(out.partial).toBe(false) // OTX is non-blocking — a fast fail must not gate the cache
  })

  it('partial reflects blocking health only (the cache invariant)', async () => {
    // (a) slow OTX dropped, all blocking OK → partial false
    const gate = deferred()
    const slowOtx = async (url) => {
      const u = String(url)
      if (u.includes('otx.alienvault.com')) { await gate.promise; return { status: 200, ok: true, json: async () => ({ pulse_info: { count: 0, pulses: [] } }) } }
      if (u.includes('abuseipdb.com')) return { status: 200, ok: true, json: async () => ({ data: { abuseConfidenceScore: 0, totalReports: 0 } }) }
      return gnIpinfo404(u)
    }
    const ok = await enrich(slowOtx, 'ipv4', '1.2.3.4', { ABUSEIPDB_API_KEY: 'x', VT_API_KEY: 'k', OTX_API_KEY: 't' })
    expect(ok.partial).toBe(false)
    gate.resolve(); await gate.promise

    // (b) a BLOCKING source rejects (AbuseIPDB 500) → partial true
    const badBlocking = async (url) => {
      const u = String(url)
      if (u.includes('abuseipdb.com')) return { status: 500, ok: false, json: async () => ({}) }
      if (u.includes('otx.alienvault.com')) return { status: 200, ok: true, json: async () => ({ pulse_info: { count: 0, pulses: [] } }) }
      return gnIpinfo404(u)
    }
    const bad = await enrich(badBlocking, 'ipv4', '1.2.3.4', { ABUSEIPDB_API_KEY: 'x', VT_API_KEY: 'k', OTX_API_KEY: 't' })
    expect(bad.partial).toBe(true)

    // (c) ONLY a non-blocking source not-configured (no OTX key) → partial false, OTX still named
    const noOtxKey = await enrich(async (url) =>
      String(url).includes('abuseipdb.com')
        ? { status: 200, ok: true, json: async () => ({ data: { abuseConfidenceScore: 0, totalReports: 0 } }) }
        : gnIpinfo404(String(url)),
      'ipv4', '1.2.3.4', { ABUSEIPDB_API_KEY: 'x', VT_API_KEY: 'k' })
    expect(noOtxKey.partial).toBe(false)
    expect(noOtxKey.errors.some((e) => e.source === 'AlienVault OTX' && /not configured/i.test(e.reason))).toBe(true)
  })
})
```

- [ ] **Step 2: RED** — `skipped_context` undefined; fast-fail currently omitted; case (c) currently `partial:true` under the old rule.

- [ ] **Step 3: Minimal impl** — finalize `collectResults` to the target shape: `blockingFailures` counter; `skipped.push`/`blockingFailures++` per blocking-ness; `PENDING → skipped_context.push`; `ok:false → errors.push`; `partial = blockingFailures > 0`. `assemble` adds `skipped_context: collected.skipped_context`.

- [ ] **Step 4: GREEN** — `cd web && npx vitest run` passes all new + existing tests.

- [ ] **Step 5: Gate** — `npx vitest run` ✅, `npm run build` ✅, `npm run lint` ✅ (from `web/`).

- [ ] **Step 6: Commit** — `feat(enrich): skipped_context + fast-fail honesty + partial from blocking health`. NO attribution.

---

### Task 5: Invariance guards — tally-invariance, order (ipinfo-before-OTX), cache matrix + Playwright gate

**Files:** Test `lib/__tests__/enrich.test.mjs`; run `site-tests/specs/enrich.spec.js`. No `lib/enrich.mjs` change expected (these lock invariants already satisfied; add a slot-order assertion only if a defect surfaces).

- [ ] **Step 1: Write the guard tests** — append:

```js
describe('invariants under context omission (Track B1)', () => {
  const blocking404 = (u) =>
    String(u).includes('abuseipdb.com')
      ? { status: 200, ok: true, json: async () => ({ data: { abuseConfidenceScore: 60, totalReports: 5 } }) }
      : { status: 404, ok: false, json: async () => ({}) }

  it('tally (consulted/flagged/tone) is identical whether OTX rides along or is dropped', async () => {
    const env = { ABUSEIPDB_API_KEY: 'x', VT_API_KEY: 'k', OTX_API_KEY: 't' }
    const fast = await enrich(async (url) =>
      String(url).includes('otx.alienvault.com')
        ? { status: 200, ok: true, json: async () => ({ pulse_info: { count: 9, pulses: [] } }) }
        : blocking404(String(url)), 'ipv4', '1.2.3.4', env)

    const gate = deferred()
    const dropped = await enrich(async (url) => {
      const u = String(url)
      if (u.includes('otx.alienvault.com')) { await gate.promise; return { status: 200, ok: true, json: async () => ({ pulse_info: { count: 9, pulses: [] } }) } }
      return blocking404(u)
    }, 'ipv4', '1.2.3.4', env)
    gate.resolve(); await gate.promise

    expect(dropped.consulted).toBe(fast.consulted)
    expect(dropped.flagged).toBe(fast.flagged)
    expect(dropped.tone).toBe(fast.tone)
  })

  it('preserves SOURCES order and keeps ipinfo before OTX (globe-pin invariant)', async () => {
    const env = { ABUSEIPDB_API_KEY: 'x', VT_API_KEY: 'k', OTX_API_KEY: 't' }
    const out = await enrich(async (url) =>
      String(url).includes('otx.alienvault.com')
        ? { status: 200, ok: true, json: async () => ({ pulse_info: { count: 1, pulses: [] } }) }
        : { status: 404, ok: false, json: async () => ({}) }, 'ipv4', '1.2.3.4', env)
    expect(out.sources.map((s) => s.name)).toEqual(['AbuseIPDB', 'VirusTotal', 'GreyNoise', 'ipinfo', 'AlienVault OTX'])
    const ipinfoIdx = out.sources.findIndex((s) => s.kind === 'context')       // FIRST context row
    expect(out.sources[ipinfoIdx].name).toBe('ipinfo')
    expect(ipinfoIdx).toBeLessThan(out.sources.findIndex((s) => s.name === 'AlienVault OTX'))

    // dropped OTX: ipinfo still the (only) context row, verdicts in order
    const gate = deferred()
    const dropped = await enrich(async (url) => {
      const u = String(url)
      if (u.includes('otx.alienvault.com')) { await gate.promise; return { status: 200, ok: true, json: async () => ({ pulse_info: { count: 1, pulses: [] } }) } }
      return { status: 404, ok: false, json: async () => ({}) }
    }, 'ipv4', '1.2.3.4', env)
    gate.resolve(); await gate.promise
    expect(dropped.sources.map((s) => s.name)).toEqual(['AbuseIPDB', 'VirusTotal', 'GreyNoise', 'ipinfo'])
  })
})
```

- [ ] **Step 2: RED/GREEN** — run `cd web && npx vitest run`. If order or tally fails, the defect is in the slot-index assembly (`plan.usable.indexOf`) — fix `collectResults`, do not weaken the test. (Expected: green immediately; a green first run here is acceptable because these lock already-built behavior — note this explicitly in the commit.)

- [ ] **Step 3: Full unit gate** — from `web/`: `npx vitest run` (entire suite, not just the lib file) ✅, `npm run build` ✅, `npm run lint` ✅.

- [ ] **Step 4: Consumer/Playwright gate (MANDATORY per amendment)**:
  ```
  cd C:\Users\Carl\Desktop\Projects\VIGIL\site-tests
  npx playwright test specs/enrich.spec.js --reporter=line
  ```
  Expect **17 passed** (Task 0 corrected the two stale hash assertions; B1 does not change the ipv4/url/sha256 outcomes those tests assert — OTX/RDAP are either not-configured or inapplicable there, so the fake fetch is never hit for them and never throws `unrouted`). **If a NEW domain-shaped test is ever added to this spec, it MUST route `rdap.org` and `otx.alienvault.com`** (and key OTX), or `fakeFetch` throws `unrouted fetch` — which the grace-race turns into an in-grace `ok:false` → `errors`, not a `skipped_context` drop.

- [ ] **Step 5: Commit** — `test(enrich): lock tally-invariance + ipinfo-before-OTX order under context omission`. NO attribution.

---

### Task 6: Live-dogfood acceptance — cold lookups return at verdict speed

**Files:** none (measurement + acceptance only). Requires the branch deployed to a Pages preview or `socdesk.io`.

- [ ] **Step 1: Cold-miss latency (IP and domain).** Pick indicators unlikely to be edge-cached (unique, or wait >15min / `max-age=900`). Measure end-to-end time with curl:
  ```
  curl -s -o NUL -w "ipv4    total=%{time_total}s http=%{http_code}\n"  "https://socdesk.io/api/enrich?type=ipv4&q=45.9.148.20"
  curl -s -o NUL -w "domain  total=%{time_total}s http=%{http_code}\n"  "https://socdesk.io/api/enrich?type=domain&q=some-fresh-domain.example"
  ```
  **Pass:** cold `total` ~0.3–0.8s typical, and always well under the pre-change ~1.5s OTX/RDAP floor. (PowerShell: `curl.exe` is the same binary; keep `-o NUL`.)

- [ ] **Step 2: Prove the drop is observable + non-gating.** Inspect the body of a cold lookup:
  ```
  curl -s "https://socdesk.io/api/enrich?type=domain&q=some-fresh-domain.example" | jq "{partial, skipped_context, sources: (.sources|length), context: [.sources[]|select(.kind==\"context\")|.name]}"
  ```
  **Pass:** on a cold miss, `partial:false`; `skipped_context` typically lists `"RDAP"` and/or `"AlienVault OTX"` (the real CF drop rate — this is the dogfood metric); the card still carries its verdict sources. For an IP, `ipinfo` remains in the context rows (blocking → globe pin intact).

- [ ] **Step 3: Cache confirmation.** Immediately re-request the SAME indicator:
  ```
  curl -s -o NUL -w "warm    total=%{time_total}s cf-cache=%{header_json}\n" "https://socdesk.io/api/enrich?type=ipv4&q=45.9.148.20"
  ```
  **Pass:** the second call is near-instant (edge-cache hit), confirming the fast context-less card WAS cached (`functions/api/enrich.js:45` gate now sees `partial:false`).

- [ ] **Step 4: Globe-pin sanity (A7).** Live IP lookup on the site lands the locator pin (ipinfo still awaited). Record the observed cold latencies and the measured `skipped_context` drop rate in the branch's `docs/HANDOFF.md` block for this feature.

- [ ] **Step 5: Finalize** — with A1–A9 satisfied (spec §8), the branch is ready to merge per the repo's normal deploy flow (`docs/superpowers` executing-plans checkpoint + `git pull --rebase origin main` before push).

---

## Acceptance criteria (spec §8, restated for the gate)

| # | Criterion | Verified by |
|---|---|---|
| A1 | Cache-miss resolves at verdict speed, never waits on OTX/RDAP | Task 3 deferred-gate + latency test; Task 6 curl |
| A2 | Slow OTX/RDAP silently omitted — absent from `sources` + `errors`, not `partial`; listed in `skipped_context` | Task 3 + Task 4 |
| A3 | Fast OTX/RDAP still rides along | Task 3 ride-along + existing OTX block green |
| A4 | Verdict tally unchanged by context omission | Task 5 tally-invariance |
| A5 | Verdict sources never dropped/mis-ordered; ipinfo before OTX | Task 5 order guard |
| A6 | Edge cache preserved/improved: blocking-partial still not cached, fast context-less card IS cached | Task 4 partial matrix; `functions/api/enrich.js:45` unchanged; Task 6 warm curl |
| A7 | Globe pin unaffected for IPs | Task 6 Step 4 |
| A8 | `enrich()` signature + response shape unchanged except `partial` rule + additive `skipped_context` | All existing tests green; no client edit |
| A9 | No client/reporting/admin/web-route change; no B2/B3 behavior | Final `git diff` review: only `lib/enrich.mjs`, `lib/__tests__/enrich.test.mjs`, `site-tests/specs/enrich.spec.js` |

## Notes carried from grounding (do not re-litigate)

- **`shared/card/model.ts` consequence (OWNER-ACCEPTED, no code change):** a dropped RDAP no longer lands in `errors`, so `rdapFailed` (`model.ts:191`) → `false`, and the domain card shows "Registration age **unknown**" instead of "unavailable / Registry lookup timed out" (`model.ts:193–207`). Accepted per the speed mandate; `skipped_context` preserves observability; a future "+RDAP pending" affordance is left open. Do NOT edit `model.ts`.
- **`shared/verdict/map.ts:143`** reads `body.partial` first (`partial: body.partial ?? errors.length > 0`), so the decoupled `partial` is already honored and the `?? errors.length > 0` fallback never triggers (the server always sends `partial`). No client edit.
- **`functions/api/enrich.js` stays UNCHANGED.** JSON-stringifying the extra `skipped_context` field is transparent; the `if (!result.partial)` cache gate (`:45`) now caches a fast context-less card (the intended improvement).
