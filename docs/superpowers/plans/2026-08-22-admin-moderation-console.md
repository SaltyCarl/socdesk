# /admin Owner Moderation Console Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the SOCDesk owner a `/admin` console that lists the D1 `reports` queue (`status = 'queued'`) and lets them approve or reject each row, gated so only the owner's numeric GitHub id can reach it — with zero change to the no-account lookup/analyzer read path.

**Architecture:** Two new pure/unit-tested modules (`lib/reporting/admin.mjs` — owner gate + moderation vocabulary + report-id shape guard; `web/src/routes/adminModel.ts` — optimistic queue update) drive two new Cloudflare Pages Functions (`functions/api/admin/reports.js` GET, `functions/api/admin/moderate.js` POST) that mirror the shipped `functions/api/report/mine.js` / `functions/api/report.js` guard-order shape exactly, plus two new parameterized D1 queries appended to `lib/reporting/db.mjs`. A new `web/src/routes/Admin.tsx` route (registered `nav:false` in `App.tsx`, absent from the command palette) composes only the shared design primitives (`Panel`, `Chip variant="neutral"`, `MicroLabel`, `Button`, `Notice`, `ViewHeader`) to render sign-in / not-authorized / error / empty / loaded states and drive Approve/Reject. No migration: `migrations/0001_init.sql`'s `status` column + `idx_reports_status` already cover this phase.

**Tech Stack:** Cloudflare Pages Functions (plain ESM `.js`, no build step) + Cloudflare D1 (prepared statements, positional `?N` bindings only) + React 19 (`web/`, Tailwind v4 via `shared/tokens.css`) + vitest (node environment, no DOM). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-08-22-admin-moderation-console-design.md` (its trailing "Panel review amendments (APPROVED 2026-08-22)" section is binding and is folded into every task below — do not implement the pre-amendment snippets in §3 of the spec verbatim; the deltas are called out per-task).

## Global Constraints

- **Owner gate fails closed on the NUMERIC `github_id`, never the login string** (GitHub logins are mutable/reclaimable — `docs/superpowers/specs/2026-08-20-ioc-reporting-phase01-design.md:224-229`). `isOwner` must reject: a non-owner id, a non-number `github_id`, AND an unset/`null`/blank/**whitespace-only** `OWNER_GITHUB_ID` (`Number('   ') === 0` is a real trap — trim and shape-check with `/^\d+$/` *before* `Number()`, per the AppSec hardening amendment). An unconfigured `OWNER_GITHUB_ID` — the state every fresh deploy starts in — must 403 *everyone*, including a legitimately signed-in analyst.
- **UUID-shape validate the report `id`** in `POST /api/admin/moderate` — `/^[0-9a-f-]{36}$/i` — before the D1 call, returning 400 on a malformed id. Unit-tested (AppSec amendment).
- **Guard order, both Functions:** `requireSession` (401) → `isOwner` (403) → body/id-shape validate (400) → D1 write/read → response. No branch skips ahead of an earlier one.
- **Parameterized `?N` SQL only.** No string-built SQL touching `ioc_value`, `id`, `status`, or any other request-derived value. No new migration — `migrations/0001_init.sql`'s `status` column and `idx_reports_status` (`:16`, `:21`) already cover this phase.
- **Reserved-colour law: a report `status` is NEVER a verdict hue.** No `malicious`/`suspicious`/`grayware`/`benign` Chip variant on `queued`/`approved`/`rejected`. The category chip uses `variant="neutral"` only; no status chip is rendered at all (every row in the queue is `queued` by construction).
- **Legibility (Panel amendment, must-fix):** the row meta caption (`ioc_type · reported by · date`) and the reporter `comment` use `text-muted`, **NEVER** `text-faint` — meaning-bearing text, per `docs/DESIGN-TOKENS.md`'s Part E legibility rule (`--faint` = 3.61:1, AA fail) and matching `MyReports.tsx`'s own precedent.
- **Transient row-error uses `text-muted`, NOT `text-verdict-amber`** (amber is reserved for persistent policy states, not a one-off action failure), inside a `role="status" aria-live="polite"` region (Panel amendment).
- **Contextual `aria-label`s** on the Approve/Reject buttons: `` `Approve ${ioc_value}` `` / `` `Reject ${ioc_value}` `` (Panel amendment, a11y).
- **Per-row deep-link** to the indicator's live reputation (`/lookup#q=<ioc_value>`, the app's existing `#q=` deep-link convention — `web/src/components/palette/commands.ts:98-100`, `web/src/components/cockpit/ResultRegion.tsx:66`) so the owner can check an indicator without leaving `/admin`. No enrich/read-path edit (Panel amendment, in-scope navigation only).
- **Compose only from existing primitives** (`Panel`, `Chip`, `MicroLabel`, `Button`, `Notice`, `ViewHeader`) — no hand-rolled surface styling, no new UI primitive.
- **`/admin` is `nav:false`** (hidden from the top-nav tab bar, `web/src/App.tsx:77` filters `nav !== false`) **and is NOT added to the command palette** (`web/src/components/palette/commands.ts`'s `DEFAULT_VIEWS`) — reachable only by direct URL, the same precedent as `/reports`.
- **NO AI attribution in any commit** (SaltyCarl public repo policy) — every `git commit` message below is a plain conventional-commit message, no `Co-Authored-By`, no `Claude-Session`, no Claude/Anthropic reference.
- **Node-only vitest harness, no DOM.** `web/vitest.config.ts:26-29` runs `environment: 'node'` over `src/**/*.test.ts`, `../shared/**/*.test.ts`, `../lib/**/*.test.mjs` — no jsdom, no React render-testing. **Pure logic** (`isOwner`, `statusForAction`, `isValidReportId`, `removeFromQueue`) is TDD'd with real vitest RED→GREEN cycles. **Functions and JSX** (`functions/api/admin/*.js`, `web/src/routes/Admin.tsx`, the `App.tsx` route registration) have no extractable logic beyond what's already pulled into the pure modules — their gate is `node --check` (Functions) / `npm --prefix web run build` (tsc, JSX) + the full vitest suite staying green + `cd web && npx eslint .` clean, plus the live dogfood pass in Task 9. This is the same posture the shipped Phase 0+1 and reporting-UX-polish work already used.
- **No edits to `lib/enrich.mjs` or `functions/api/enrich.js`** — Track B's files, off-limits.
- **No `SOCDESK_COMMUNITY` source, no wiring `reports.status` into any enrich response, no touching `web/src/components/lookup/` or `web/src/components/verdict-cards/`** — that's Phase 3, out of scope.
- **Files this track owns** (nothing outside this list is touched): `lib/reporting/admin.mjs` (new), `lib/reporting/__tests__/admin.test.mjs` (new), `lib/reporting/db.mjs` (modified — additive), `functions/api/admin/reports.js` (new), `functions/api/admin/moderate.js` (new), `web/src/routes/Admin.tsx` (new), `web/src/routes/adminModel.ts` (new), `web/src/routes/adminModel.test.ts` (new), `web/src/App.tsx` (modified — one import + one `ROUTES` entry), `docs/OPERATIONS.md` (modified — the `OWNER_GITHUB_ID` setup step).

---

## File Structure

**Create**
- `lib/reporting/admin.mjs` — pure `isOwner(github_id, ownerGithubIdRaw)`, `statusForAction(action)`, `isValidReportId(id)`.
- `lib/reporting/__tests__/admin.test.mjs` — unit tests for all three.
- `functions/api/admin/reports.js` — `GET /api/admin/reports`, owner-gated queue list.
- `functions/api/admin/moderate.js` — `POST /api/admin/moderate`, owner-gated approve/reject.
- `web/src/routes/adminModel.ts` — `type QueuedReport`, pure `removeFromQueue(rows, id)`.
- `web/src/routes/adminModel.test.ts` — unit tests for `removeFromQueue`.
- `web/src/routes/Admin.tsx` — the `/admin` route component.

**Modify**
- `lib/reporting/db.mjs` — append `listQueuedReports(DB, limit)`, `updateReportStatus(DB, id, status)`.
- `web/src/App.tsx` — import `Admin`, add the `/admin` `ROUTES` entry (`nav: false`).
- `docs/OPERATIONS.md` — replace the deferred `OWNER_GITHUB_ID` note (`:336-338`) with a real setup step; extend the step-6 dogfood checklist (`:356-360`).

No other file is touched. In particular: no changes to `functions/api/report.js`, `functions/api/report/mine.js`, `functions/_lib/session.mjs`, `lib/reporting/session.mjs`, `lib/reporting/validate.mjs`, `lib/reporting/policy.mjs`, `web/src/routes/MyReports.tsx`, `web/src/routes/myReportsModel.ts`, `migrations/0001_init.sql`, `web/src/components/palette/commands.ts`, or anything under `shared/`, `web/public/_headers`, `lib/enrich.mjs`, or `functions/api/enrich.js`.

---

### Task 1: `lib/reporting/admin.mjs` — owner gate, action vocabulary, report-id shape guard

**Files:**
- Create: `lib/reporting/admin.mjs`
- Test: `lib/reporting/__tests__/admin.test.mjs`

**Interfaces:**
- Produces: `isOwner(github_id: number|unknown, ownerGithubIdRaw: string|unknown): boolean`; `statusForAction(action: string|unknown): 'approved'|'rejected'|null`; `isValidReportId(id: string|unknown): boolean`. Task 3 and Task 4 import all three from `../../../lib/reporting/admin.mjs`.
- Consumes: nothing (pure, no D1, no `fetch`) — mirrors `lib/reporting/policy.mjs`'s `overDailyCap` pattern.

- [ ] **Step 1: Write the failing test** — create `lib/reporting/__tests__/admin.test.mjs`:

```js
import { describe, expect, it } from 'vitest'
import { isOwner, isValidReportId, statusForAction } from '../admin.mjs'

describe('isOwner — fail-closed owner gate on the numeric github_id', () => {
  it('matches on equal numeric id (env vars arrive as numeric strings)', () => {
    expect(isOwner(12345, '12345')).toBe(true)
  })
  it('is false on a mismatched id', () => {
    expect(isOwner(12345, '99999')).toBe(false)
  })
  it('is false when github_id is not a number', () => {
    expect(isOwner('12345', '12345')).toBe(false)
    expect(isOwner(undefined, '12345')).toBe(false)
  })
  it('fails closed when OWNER_GITHUB_ID is unset (undefined)', () => {
    expect(isOwner(12345, undefined)).toBe(false)
  })
  it('fails closed when OWNER_GITHUB_ID is null', () => {
    expect(isOwner(12345, null)).toBe(false)
  })
  it('fails closed when OWNER_GITHUB_ID is an empty string', () => {
    expect(isOwner(12345, '')).toBe(false)
  })
  it('fails closed when OWNER_GITHUB_ID is a non-numeric string', () => {
    expect(isOwner(12345, 'not-a-number')).toBe(false)
  })
  it('fails closed on a whitespace-only OWNER_GITHUB_ID (the Number("   ")===0 trap)', () => {
    expect(isOwner(0, '   ')).toBe(false)
  })
  it('tolerates surrounding whitespace on an otherwise-numeric value', () => {
    expect(isOwner(12345, '  12345  ')).toBe(true)
  })
})

describe('statusForAction — moderation action vocabulary', () => {
  it('approve maps to approved', () => {
    expect(statusForAction('approve')).toBe('approved')
  })
  it('reject maps to rejected', () => {
    expect(statusForAction('reject')).toBe('rejected')
  })
  it('any other action maps to null', () => {
    expect(statusForAction(undefined)).toBe(null)
    expect(statusForAction('')).toBe(null)
    expect(statusForAction('delete')).toBe(null)
  })
})

describe('isValidReportId — UUID-shape guard before the D1 write', () => {
  it('accepts a real crypto.randomUUID() shape', () => {
    expect(isValidReportId('3fa85f64-5717-4562-b3fc-2c963f66afa6')).toBe(true)
  })
  it('rejects a non-UUID string', () => {
    expect(isValidReportId('not-a-uuid')).toBe(false)
    expect(isValidReportId('1; DROP TABLE reports;--')).toBe(false)
  })
  it('rejects the wrong length', () => {
    expect(isValidReportId('3fa85f64-5717-4562-b3fc-2c963f66afa')).toBe(false)
    expect(isValidReportId('3fa85f64-5717-4562-b3fc-2c963f66afa66')).toBe(false)
  })
  it('rejects a non-string', () => {
    expect(isValidReportId(undefined)).toBe(false)
    expect(isValidReportId(null)).toBe(false)
  })
})
```

- [ ] **Step 2: Run it, expect FAIL:**

Run: `cd web && npx vitest run ../lib/reporting/__tests__/admin.test.mjs`
Expected: FAIL — `Cannot find module '../admin.mjs'` (or similar resolution error; the file doesn't exist yet).

- [ ] **Step 3: Write the minimal implementation** — create `lib/reporting/admin.mjs`:

```js
// lib/reporting/admin.mjs
// Pure owner-identity check + moderation-action vocabulary + report-id shape
// guard for the /admin console. Kept out of the Functions so they're
// node-testable (mirrors policy.mjs's overDailyCap).

/** True only when `github_id` is a number and matches OWNER_GITHUB_ID
 *  exactly. An unset, blank, whitespace-only, or non-numeric OWNER_GITHUB_ID
 *  always resolves false — the gate fails closed, never open-by-default.
 *  `ownerGithubIdRaw` is trimmed and shape-checked against /^\d+$/ BEFORE
 *  Number() so a whitespace-only value (Number('   ') === 0) can never
 *  coerce into a false match against a github_id of 0. Login/handle is
 *  never part of this check (see the 2026-08-21 security ruling). */
export function isOwner(github_id, ownerGithubIdRaw) {
  if (typeof github_id !== 'number') return false
  const trimmed = typeof ownerGithubIdRaw === 'string' ? ownerGithubIdRaw.trim() : ''
  if (!/^\d+$/.test(trimmed)) return false
  return github_id === Number(trimmed)
}

/** action -> the status write it produces, or null for an unrecognized
 *  action. The only two transitions this phase allows are queued->approved
 *  and queued->rejected (enforced again at the SQL layer — see
 *  updateReportStatus's `WHERE status = 'queued'` guard). */
export function statusForAction(action) {
  if (action === 'approve') return 'approved'
  if (action === 'reject') return 'rejected'
  return null
}

const REPORT_ID_SHAPE = /^[0-9a-f-]{36}$/i

/** Shape-only guard on a report id before it reaches a D1 statement.
 *  insertReport always writes crypto.randomUUID() (functions/api/report.js),
 *  so any id that doesn't look like one is rejected before the query runs —
 *  belt-and-suspenders alongside the parameterized bind (the real injection
 *  defense), not a replacement for it. */
export function isValidReportId(id) {
  return typeof id === 'string' && REPORT_ID_SHAPE.test(id)
}
```

- [ ] **Step 4: Run it, expect PASS:**

Run: `cd web && npx vitest run ../lib/reporting/__tests__/admin.test.mjs`
Expected: PASS — 3 describe blocks, 16 tests, all green.

- [ ] **Step 5: Full suite, expect PASS (no regressions):**

Run: `cd web && npx vitest run`
Expected: all pre-existing test files stay green, plus the new `admin.test.mjs` file.

- [ ] **Step 6: Commit:**

```bash
git add lib/reporting/admin.mjs lib/reporting/__tests__/admin.test.mjs
git commit -m "feat(admin): pure owner gate, action vocabulary, report-id shape guard"
```

---

### Task 2: `lib/reporting/db.mjs` — moderation queries

**Files:**
- Modify: `lib/reporting/db.mjs` (append after `listMyReports`, `:37-43`)

**Interfaces:**
- Produces: `listQueuedReports(DB, limit = 200): Promise<Array<{id, github_id, login, ioc_type, ioc_value, category, evidence, comment, status, created_at}>>`; `updateReportStatus(DB, id, status): Promise<boolean>`. Task 3 imports `listQueuedReports`; Task 4 imports `updateReportStatus`.
- Consumes: `env.DB` (the D1 binding, unchanged — same binding `listMyReports`/`insertReport` already use).

**Note (harness):** these are thin D1 wrappers — `lib/reporting/db.mjs` has no test file at all today (`listMyReports`/`insertReport`/etc. are un-unit-tested; correctness is covered by the manual local-D1 pass, spec §6). This task adds no new test file, matching that existing posture exactly. The gate is the pre-existing suite staying green (nothing here is imported by any test yet) plus Task 9's live dogfood pass, which is where these two queries are actually exercised against real D1.

- [ ] **Step 1: Append the two queries** to `lib/reporting/db.mjs`, directly after `listMyReports` (after line 43):

```js

/** The moderation queue, oldest-first (FIFO — nothing should go stale)
 *  unlike listMyReports' newest-first (an author wants their latest report
 *  on top). Joins accounts for the reporter's handle; LEFT JOIN so a report
 *  never disappears from the queue if its account row is ever missing. */
export async function listQueuedReports(DB, limit = 200) {
  const { results } = await DB.prepare(
    `SELECT r.id, r.github_id, a.login, r.ioc_type, r.ioc_value, r.category,
            r.evidence, r.comment, r.status, r.created_at
     FROM reports r LEFT JOIN accounts a ON a.github_id = r.github_id
     WHERE r.status = 'queued' ORDER BY r.created_at ASC LIMIT ?1`,
  ).bind(limit).all()
  return results ?? []
}

/** Transition a report's status. The `AND status = 'queued'` guard makes
 *  this race-safe: a double-click, two open admin tabs, or a retry after a
 *  dropped response can only ever produce one write — the second call
 *  returns `changes: 0` rather than clobbering an already-decided report.
 *  Returns true iff a row was actually changed. */
export async function updateReportStatus(DB, id, status) {
  const res = await DB.prepare(
    `UPDATE reports SET status = ?1 WHERE id = ?2 AND status = 'queued'`,
  ).bind(status, id).run()
  return (res.meta?.changes ?? 0) > 0
}
```

Both follow the file's own house rule (`lib/reporting/db.mjs:1-3`): positional `?N` bindings only, no string-built SQL. `idx_reports_status` on `(status, created_at)` (`migrations/0001_init.sql:21`) covers `listQueuedReports`'s `WHERE status = 'queued' ORDER BY created_at` directly — confirmed no migration is needed.

- [ ] **Step 2: `node --check` the file for a syntax sanity check:**

Run: `node --check lib/reporting/db.mjs`
Expected: no output (clean parse).

- [ ] **Step 3: Full suite, expect PASS (no regressions — nothing imports these two functions yet):**

Run: `cd web && npx vitest run`
Expected: unchanged pass count from Task 1's baseline (all pre-existing files + `admin.test.mjs` green).

- [ ] **Step 4: Commit:**

```bash
git add lib/reporting/db.mjs
git commit -m "feat(admin): listQueuedReports + updateReportStatus D1 queries"
```

---

### Task 3: `GET /api/admin/reports` — owner-gated queue list

**Files:**
- Create: `functions/api/admin/reports.js`

**Interfaces:**
- Consumes: `requireSession(request, env)` (`../../_lib/session.mjs`, re-exports `functions/_lib/session.mjs`); `isOwner` (`../../../lib/reporting/admin.mjs`, Task 1); `listQueuedReports` (`../../../lib/reporting/db.mjs`, Task 2).
- Produces: `onRequestGet({request, env})` — the Cloudflare Pages Functions entry point Wrangler dispatches `GET /api/admin/reports` to. Response shape `{reports: QueuedReport[]}` on 200; `{error: 'auth'}` on 401; `{error: 'forbidden'}` on 403. Task 6's `Admin.tsx` fetches this route directly.

**Note (harness):** Functions run in the Cloudflare Pages runtime, not under vitest (no D1/fetch mocking layer exists in this repo — same posture as `functions/api/report/mine.js`, which also has no test file). The gate here is `node --check` (syntax) + the full vitest suite staying green (nothing here is imported by a test) + Task 9's live dogfood pass, which is the actual correctness check (401/403/200 against a real D1).

- [ ] **Step 1: Implement** `functions/api/admin/reports.js`:

```js
import { requireSession } from '../../_lib/session.mjs'
import { isOwner } from '../../../lib/reporting/admin.mjs'
import { listQueuedReports } from '../../../lib/reporting/db.mjs'

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } })

export async function onRequestGet({ request, env }) {
  const user = await requireSession(request, env)
  if (!user) return json({ error: 'auth' }, 401)
  if (!isOwner(user.github_id, env.OWNER_GITHUB_ID)) return json({ error: 'forbidden' }, 403)
  const reports = await listQueuedReports(env.DB)
  return json({ reports }, 200)
}
```

Guard order mirrors `functions/api/report/mine.js:4-8`: 401 (no session) before 403 (wrong session) before the D1 read, so an anonymous caller learns nothing about whether an owner is even configured. The relative import depth (`../../_lib/...`, `../../../lib/...`) matches `functions/api/admin/`'s position one level deeper than `functions/api/report/` sits relative to `functions/api/` — same two-level-up (`_lib`) and three-level-up (`lib/reporting`) resolution `functions/api/report/mine.js` already uses.

- [ ] **Step 2: `node --check` the file:**

Run: `node --check functions/api/admin/reports.js`
Expected: no output (clean parse — confirms the import graph resolves as plain ESM, matching the verified working precedent at `functions/api/report.js`).

- [ ] **Step 3: Full suite, expect PASS (no regressions):**

Run: `cd web && npx vitest run`
Expected: unchanged pass count.

- [ ] **Step 4: Commit:**

```bash
git add functions/api/admin/reports.js
git commit -m "feat(admin): GET /api/admin/reports — owner-gated queue list"
```

---

### Task 4: `POST /api/admin/moderate` — owner-gated approve/reject, UUID-validated

**Files:**
- Create: `functions/api/admin/moderate.js`

**Interfaces:**
- Consumes: `requireSession` (`../../_lib/session.mjs`); `isOwner`, `isValidReportId`, `statusForAction` (`../../../lib/reporting/admin.mjs`, Task 1); `updateReportStatus` (`../../../lib/reporting/db.mjs`, Task 2).
- Produces: `onRequestPost({request, env})` for `POST /api/admin/moderate`. Request body `{id: string, action: 'approve'|'reject'}`. Response `{id, status}` on 200; `{error:'auth'}` 401; `{error:'forbidden'}` 403; `{error:'body', reason}` 400 (malformed body or non-UUID-shaped id); `{error:'not_found', reason}` 404 (unknown id or already-actioned report). Task 6's `Admin.tsx` posts here from the Approve/Reject handlers.

**Note (harness):** same posture as Task 3 — `node --check` + full suite + Task 9's live dogfood pass is where the 401/403/400/404/200 flow is actually exercised end-to-end.

- [ ] **Step 1: Implement** `functions/api/admin/moderate.js` — this is the spec's §3.3 snippet with the AppSec amendment folded in: `isValidReportId(id)` is checked, and rejected with 400, *before* `updateReportStatus` ever reaches D1:

```js
import { requireSession } from '../../_lib/session.mjs'
import { isOwner, isValidReportId, statusForAction } from '../../../lib/reporting/admin.mjs'
import { updateReportStatus } from '../../../lib/reporting/db.mjs'

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } })

export async function onRequestPost({ request, env }) {
  const user = await requireSession(request, env)
  if (!user) return json({ error: 'auth' }, 401)
  if (!isOwner(user.github_id, env.OWNER_GITHUB_ID)) return json({ error: 'forbidden' }, 403)

  const body = await request.json().catch(() => null)
  const id = body && typeof body.id === 'string' ? body.id : null
  const status = body && statusForAction(body.action)
  if (!id || !status) return json({ error: 'body', reason: 'expected { id, action: "approve"|"reject" }' }, 400)
  if (!isValidReportId(id)) return json({ error: 'body', reason: 'id is not a valid report id' }, 400)

  const changed = await updateReportStatus(env.DB, id, status)
  if (!changed) return json({ error: 'not_found', reason: 'no queued report with that id' }, 404)
  return json({ id, status }, 200)
}
```

Guard order: 401 → 403 → 400 (malformed body / missing action) → 400 (id not UUID-shaped) → 404 (already-actioned / unknown id) → 200. No Turnstile — unlike `functions/api/report.js:26-27`, Turnstile defends an *anonymous-writeable* endpoint from bot spam; this endpoint is already closed to one numeric `github_id`, so a second bot-defense layer adds nothing. **CSRF:** the session cookie is `SameSite=Lax` (`lib/reporting/session.mjs:46`, unchanged), the same posture every other write endpoint in this codebase relies on — Lax cookies aren't attached to cross-site POSTs. No new CSRF token introduced.

- [ ] **Step 2: `node --check` the file:**

Run: `node --check functions/api/admin/moderate.js`
Expected: no output (clean parse).

- [ ] **Step 3: Full suite, expect PASS (no regressions):**

Run: `cd web && npx vitest run`
Expected: unchanged pass count.

- [ ] **Step 4: Commit:**

```bash
git add functions/api/admin/moderate.js
git commit -m "feat(admin): POST /api/admin/moderate — owner-gated approve/reject, UUID-validated"
```

---

### Task 5: `web/src/routes/adminModel.ts` — pure optimistic queue update

**Files:**
- Create: `web/src/routes/adminModel.ts`
- Test: `web/src/routes/adminModel.test.ts`

**Interfaces:**
- Produces: `type QueuedReport = {id, github_id, login, ioc_type, ioc_value, category, evidence, comment, status, created_at}`; `removeFromQueue(rows: QueuedReport[], id: string): QueuedReport[]`. Task 6's `Admin.tsx` imports both.
- Consumes: nothing (pure) — mirrors `web/src/routes/myReportsModel.ts`'s "kept out of the component so it exports no non-component values — react-refresh discipline, and so it is node-testable" rationale.

- [ ] **Step 1: Write the failing test** — create `web/src/routes/adminModel.test.ts`:

```ts
import { describe, expect, it } from 'vitest'
import { removeFromQueue, type QueuedReport } from './adminModel'

function row(id: string): QueuedReport {
  return {
    id,
    github_id: 1,
    login: 'octocat',
    ioc_type: 'ipv4',
    ioc_value: '1.2.3.4',
    category: 'scanner',
    evidence: 'evidence text',
    comment: null,
    status: 'queued',
    created_at: '2026-08-22T00:00:00.000Z',
  }
}

describe('removeFromQueue — optimistic queue update after a moderation POST', () => {
  it('drops the matching row', () => {
    const rows = [row('a'), row('b'), row('c')]
    expect(removeFromQueue(rows, 'b').map((r) => r.id)).toEqual(['a', 'c'])
  })
  it('leaves order and the other rows untouched', () => {
    const rows = [row('a'), row('b')]
    expect(removeFromQueue(rows, 'a')).toEqual([row('b')])
  })
  it('no-ops on an unknown id', () => {
    const rows = [row('a'), row('b')]
    expect(removeFromQueue(rows, 'zzz')).toEqual(rows)
  })
  it('handles an empty array', () => {
    expect(removeFromQueue([], 'a')).toEqual([])
  })
})
```

- [ ] **Step 2: Run it, expect FAIL:**

Run: `cd web && npx vitest run src/routes/adminModel.test.ts`
Expected: FAIL — `Cannot find module './adminModel'`.

- [ ] **Step 3: Write the minimal implementation** — create `web/src/routes/adminModel.ts`:

```ts
// adminModel — pure view logic for the /admin moderation console (kept out
// of the component so it exports no non-component values — react-refresh
// discipline — and so it is node-testable, mirroring myReportsModel.ts).

export type QueuedReport = {
  id: string
  github_id: number
  login: string | null
  ioc_type: string
  ioc_value: string
  category: string
  evidence: string
  comment: string | null
  status: string
  created_at: string
}

/** Optimistic queue update after a successful moderation POST — drops the
 *  actioned row so the list always reflects "still needs a decision." */
export function removeFromQueue(rows: QueuedReport[], id: string): QueuedReport[] {
  return rows.filter((r) => r.id !== id)
}
```

- [ ] **Step 4: Run it, expect PASS:**

Run: `cd web && npx vitest run src/routes/adminModel.test.ts`
Expected: PASS — 4 tests green.

- [ ] **Step 5: Full suite + build:**

Run: `cd web && npx vitest run` — expect all pre-existing tests plus `admin.test.mjs` and `adminModel.test.ts` green.
Run: `npm --prefix web run build` — expect a clean `tsc -b && vite build` (no type errors; `adminModel.ts` isn't imported by any component yet, so this only proves it type-checks standalone).

- [ ] **Step 6: Commit:**

```bash
git add web/src/routes/adminModel.ts web/src/routes/adminModel.test.ts
git commit -m "feat(admin): adminModel — QueuedReport type + removeFromQueue"
```

---

### Task 6: `web/src/routes/Admin.tsx` — the moderation console route

**Files:**
- Create: `web/src/routes/Admin.tsx`

**Interfaces:**
- Consumes: `Button`, `Chip`, `MicroLabel`, `Panel` (`../components/ui`); `ViewHeader` (`../components/views/ViewFrame`); `Notice` (`../components/lookup/LookupStates`); `removeFromQueue`, `QueuedReport` (`./adminModel`, Task 5). Fetches `GET /api/admin/reports` (Task 3) and `POST /api/admin/moderate` (Task 4).
- Produces: `export function Admin()`. Task 7's `App.tsx` imports it and mounts it at `/admin`.

**Note (harness):** pure JSX composition — no extractable logic beyond what Task 5 already pulled into `adminModel.ts`. No render test exists in this repo's harness (node-only vitest, no jsdom). The gate is `npm --prefix web run build` (tsc) + the full vitest suite staying green + `cd web && npx eslint .` clean, plus visual confirmation in Task 9's live dogfood pass.

This is the spec's §3.4 `Admin.tsx` snippet with every Panel-review amendment folded in: the row meta caption and the `comment` line use `text-muted` (not `text-faint`); the row error is `text-muted` inside a `role="status" aria-live="polite"` region (not `text-verdict-amber`); Approve/Reject carry contextual `aria-label`s; each row has a `/lookup#q=<ioc_value>` deep-link.

- [ ] **Step 1: Implement** `web/src/routes/Admin.tsx`:

```tsx
// Admin — the owner-only moderation console (routable, hidden from the top
// nav and the command palette; reached by direct URL — docs/OPERATIONS.md
// documents the OWNER_GITHUB_ID setup this route depends on). Mirrors
// MyReports.tsx's fetch-and-branch shape, plus the 403 branch MyReports
// doesn't need. React escapes all text — no HTML rendering of report fields
// (evidence/comment/login are attacker-influenced free text from a
// signed-in-but-otherwise-untrusted analyst).

import { useEffect, useState } from 'react'
import { Button, Chip, MicroLabel, Panel } from '../components/ui'
import { ViewHeader } from '../components/views/ViewFrame'
import { Notice } from '../components/lookup/LookupStates'
import { removeFromQueue, type QueuedReport } from './adminModel'

export function Admin() {
  const [rows, setRows] = useState<QueuedReport[] | null>(null)
  const [authState, setAuthState] = useState<'ok' | 'signedout' | 'forbidden' | 'error'>('ok')
  const [pending, setPending] = useState<Set<string>>(new Set())
  const [rowError, setRowError] = useState<Record<string, string>>({})

  useEffect(() => {
    fetch('/api/admin/reports', { credentials: 'same-origin' })
      .then(async (r) => {
        if (r.status === 401) return setAuthState('signedout')
        if (r.status === 403) return setAuthState('forbidden')
        if (!r.ok) return setAuthState('error')
        const b = await r.json()
        setRows(b.reports ?? [])
      })
      .catch(() => setAuthState('error'))
  }, [])

  const act = async (id: string, action: 'approve' | 'reject') => {
    setPending((s) => new Set(s).add(id))
    setRowError((e) => ({ ...e, [id]: '' }))
    try {
      const r = await fetch('/api/admin/moderate', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ id, action }),
      })
      if (!r.ok) throw new Error(String(r.status))
      setRows((rs) => (rs ? removeFromQueue(rs, id) : rs))
    } catch {
      setRowError((e) => ({ ...e, [id]: 'Action failed — try again.' }))
    } finally {
      setPending((s) => {
        const n = new Set(s)
        n.delete(id)
        return n
      })
    }
  }

  return (
    <div className="flex flex-col gap-8">
      <ViewHeader
        eyebrow="Owner console"
        title="Report moderation queue"
        intro="Reports waiting for a decision. Approving or rejecting here only changes the report's status — nothing here publishes to a lookup card."
        aside={rows && <MicroLabel tone="muted">{rows.length} queued</MicroLabel>}
      />

      {authState === 'signedout' ? (
        <Notice eyebrow="Sign in" title="Sign in to view the moderation queue">
          This console needs a GitHub sign-in.{' '}
          <a href="/api/auth/github/start?return=/admin" className="text-accent underline">
            Sign in with GitHub
          </a>
          .
        </Notice>
      ) : authState === 'forbidden' ? (
        <Notice eyebrow="Not authorized" title="This console is owner-only">
          Your account isn&rsquo;t the configured SOCDesk owner.
        </Notice>
      ) : authState === 'error' ? (
        <Notice eyebrow="Error" title="Couldn't load the queue">
          Something went wrong reaching the report store — try again.
        </Notice>
      ) : !rows ? (
        <p className="text-xs text-muted">Loading the queue…</p>
      ) : rows.length === 0 ? (
        <Notice eyebrow="Empty" title="Nothing waiting for review">
          The moderation queue is empty.
        </Notice>
      ) : (
        <Panel padding="none">
          <ul className="overflow-hidden rounded-lg">
            {rows.map((r) => (
              <li
                key={r.id}
                className="flex flex-col gap-3 border-b border-line px-4 py-3 last:border-0 even:bg-panel-soft/40"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                    <span className="break-all font-mono text-xs font-semibold text-paper">
                      {r.ioc_value}
                    </span>
                    <span className="font-mono text-micro text-muted">
                      {r.ioc_type} · reported by {r.login ? `@${r.login}` : `#${r.github_id}`} ·{' '}
                      {r.created_at.slice(0, 10)}
                    </span>
                  </div>
                  <div className="flex shrink-0 items-center gap-3">
                    <a
                      href={`/lookup#q=${encodeURIComponent(r.ioc_value)}`}
                      className="font-mono text-micro text-accent underline underline-offset-2 hover:no-underline"
                    >
                      Check reputation <span aria-hidden="true">→</span>
                    </a>
                    <Chip variant="neutral">{r.category}</Chip>
                  </div>
                </div>
                <p className="whitespace-pre-wrap text-xs leading-relaxed text-muted">{r.evidence}</p>
                {r.comment && <p className="whitespace-pre-wrap text-micro text-muted">{r.comment}</p>}
                <div className="flex items-center gap-2">
                  <Button
                    variant="primary"
                    size="sm"
                    disabled={pending.has(r.id)}
                    aria-label={`Approve ${r.ioc_value}`}
                    onClick={() => act(r.id, 'approve')}
                  >
                    Approve
                  </Button>
                  <Button
                    variant="danger"
                    size="sm"
                    disabled={pending.has(r.id)}
                    aria-label={`Reject ${r.ioc_value}`}
                    onClick={() => act(r.id, 'reject')}
                  >
                    Reject
                  </Button>
                  {rowError[r.id] && (
                    <span role="status" aria-live="polite" className="text-micro text-muted">
                      {rowError[r.id]}
                    </span>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </Panel>
      )}
    </div>
  )
}
```

Design notes tying this back to the doctrine in the Global Constraints:

- **Reserved-colour compliance:** the category chip uses `variant="neutral"` (`shared/ui/Chip.tsx:52-53`), *not* `catalog`/`technique`/any verdict variant — a report's category is a claim the *reporter* made, not a confirmed verdict on the indicator. No status chip is rendered at all (every row here is `queued` by construction — a redundant chip would be pure decoration, exactly what the reserved-colour law forbids).
- **`Button variant="danger"` for Reject** is a genuine, meaning-bearing destructive UI action per `shared/ui/buttonClasses.ts:12-13`'s own doctrine comment ("DESTRUCTIVE actions only, meaning-bearing, never decorative") — rejecting a queued report is exactly that: a UI-action semantic, not an indicator-verdict claim, so it doesn't conflict with the reserved-colour law (which governs hues asserting something about an *indicator*, not a *button*).
- **No confirmation modal before Reject** (deliberate MVP scope, per spec §3.4): the action isn't destructive to data (recoverable via an owner D1-console edit, same recovery path `accounts.banned` already relies on) and `updateReportStatus`'s `WHERE status = 'queued'` guard makes a double-click a no-op (404), not a double-write.
- **No `markContributorSeen()` call** (unlike `MyReports.tsx:27`) — that call exists to reveal the `AccountControl` "Sign in" affordance to a visitor who just engaged the *public* reporting flow; `/admin` isn't part of that discoverability funnel, since the owner already knows their own auth state.
- **`evidence`/`comment` render as plain JSX text nodes** (React-escaped), never `dangerouslySetInnerHTML`.
- **Legibility:** the meta caption and `comment` line both use `text-muted` (not `text-faint`), matching `evidence`'s existing `text-muted` treatment and `MyReports.tsx`'s own precedent.
- **Row error:** `text-muted`, not `text-verdict-amber`, inside `role="status" aria-live="polite"` — a transient action failure is not a persistent policy state.
- **a11y:** Approve/Reject carry `` aria-label={`Approve ${r.ioc_value}`} `` / `` aria-label={`Reject ${r.ioc_value}`} ``, giving each button an unambiguous accessible name even though multiple rows repeat the visible "Approve"/"Reject" text.
- **Deep-link:** `` `/lookup#q=${encodeURIComponent(r.ioc_value)}` `` reuses the app's existing `#q=` hash convention (`web/src/components/palette/commands.ts:98-100`'s `lookupHash`, `web/src/components/cockpit/ResultRegion.tsx:66`'s literal `` `/lookup${lookupHash(indicator)}` `` usage) — a plain anchor, no SPA `pushState` wiring needed since `Lookup.tsx` already reads `#q=` on mount regardless of how the page was loaded.

- [ ] **Step 2: Typecheck + build:**

Run: `npm --prefix web run build`
Expected: clean `tsc -b && vite build` — `Admin.tsx` isn't imported by `App.tsx` yet (Task 7), so this only proves the file type-checks and Vite can bundle it as dead code; no runtime behavior to verify yet.

- [ ] **Step 3: Lint:**

Run: `cd web && npx eslint .`
Expected: clean — no `react/forbid-dom-props` (no inline `style=`), no unused imports, no `react-hooks` violations.

- [ ] **Step 4: Full suite, expect PASS (no regressions):**

Run: `cd web && npx vitest run`
Expected: unchanged pass count (this file has no test — see the harness note above).

- [ ] **Step 5: Commit:**

```bash
git add web/src/routes/Admin.tsx
git commit -m "feat(admin): /admin moderation console route"
```

---

### Task 7: `web/src/App.tsx` — register `/admin`

**Files:**
- Modify: `web/src/App.tsx:9` (import), `web/src/App.tsx:57-58` (route entry)

**Interfaces:**
- Consumes: `Admin` (`./routes/Admin`, Task 6).
- Produces: `/admin` resolves through the existing `useRoute`/`ROUTES.find` pathname match (`web/src/App.tsx:61-75`) — no router dependency, matching every other route.

**Note (harness):** one import line + one array entry — no extractable logic. Gate is `npm --prefix web run build` (tsc catches a bad import path) + full suite + `eslint` clean + Task 9's live dogfood pass (which is the only way to actually observe `/admin` rendering in a browser, since there's no jsdom render harness here).

- [ ] **Step 1: Add the import** to `web/src/App.tsx`, after the `MyReports` import at line 9:

```tsx
import { Admin } from './routes/Admin'
```

- [ ] **Step 2: Add the route entry** to the `ROUTES` array (`web/src/App.tsx:37-59`), after the `/reports` row (line 57):

```tsx
  { path: '/reports', label: 'My reports', size: 'default', el: <MyReports />, nav: false },
  { path: '/admin', label: 'Admin', size: 'default', el: <Admin />, nav: false },
  { path: '/privacy', label: 'Privacy', size: 'default', el: <Privacy />, nav: false },
```

(Only the middle line is new — `/reports` and `/privacy` are shown for placement context; `/admin` goes between them, keeping the routable-but-hidden rows grouped.) `nav: false` matches `/gallery`, `/reports`, `/privacy` — hidden from the top-nav tab bar (`web/src/App.tsx:77` filters `r.nav !== false`). `/admin` is deliberately **not** added to `web/src/components/palette/commands.ts`'s `DEFAULT_VIEWS` — the same precedent `/reports` already set (relevant to exactly one person; reached by typing/bookmarking the URL, not discovery).

- [ ] **Step 3: Typecheck + build:**

Run: `npm --prefix web run build`
Expected: clean — confirms the import resolves and the `Route`/`ROUTES` types are satisfied.

- [ ] **Step 4: Lint:**

Run: `cd web && npx eslint .`
Expected: clean.

- [ ] **Step 5: Full suite, expect PASS (no regressions):**

Run: `cd web && npx vitest run`
Expected: unchanged pass count.

- [ ] **Step 6: Commit:**

```bash
git add web/src/App.tsx
git commit -m "feat(admin): register /admin route, nav:false"
```

---

### Task 8: `docs/OPERATIONS.md` — real `OWNER_GITHUB_ID` setup step

**Files:**
- Modify: `docs/OPERATIONS.md:336-338` (replace the deferral note), `docs/OPERATIONS.md:356-360` (extend the step-6 dogfood checklist)

**Interfaces:** none (documentation only).

**Note (harness):** prose-only change, no code gate. Verification is a re-read of the rendered section for accuracy against Task 1-7's actual shipped shape.

- [ ] **Step 1: Replace the deferral note.** In `docs/OPERATIONS.md`, the secrets table's `OWNER_GITHUB_ID` paragraph currently reads (lines 336-338):

```
   `OWNER_GITHUB_ID` (your numeric GitHub id, never the login — logins are
   reclaimable) is **not needed for Phase 0+1** — only the Phase 2 moderation
   console (`/admin`) reads it. Set it when Phase 2 lands.
```

Replace it with a real, non-deferred step:

```
   `OWNER_GITHUB_ID` — your numeric GitHub id (never the login; logins are
   reclaimable). Find it via `https://api.github.com/users/<your-login>` →
   the `id` field, or from the GitHub OAuth debug/callback logs. Add it as a
   Pages Function secret alongside `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET`
   / `SESSION_SECRET` / `TURNSTILE_SECRET` (Cloudflare → Workers & Pages →
   **socdesk** → Settings → Environment variables → Production). `/admin`
   403s for every account, including the owner's, until this is set — the
   gate fails closed on purpose (`lib/reporting/admin.mjs`'s `isOwner`).
```

- [ ] **Step 2: Extend the step-6 dogfood checklist.** In `docs/OPERATIONS.md`, step 6 (lines 356-360) currently ends with:

```
6. **Dogfood it.** With `wrangler pages dev` (or the deployed site) and all of
   the above in place: `/api/auth/github/start` redirects to GitHub; the
   callback upserts an `accounts` row and sets an `sd_session` cookie; a
   submitted report lands as `queued` and shows up at `/reports`. Confirm the
   lookup/analyzer flow is unaffected while doing this.
```

Append one more sentence to the same step (do not renumber; this stays step 6):

```
6. **Dogfood it.** With `wrangler pages dev` (or the deployed site) and all of
   the above in place: `/api/auth/github/start` redirects to GitHub; the
   callback upserts an `accounts` row and sets an `sd_session` cookie; a
   submitted report lands as `queued` and shows up at `/reports`. Confirm the
   lookup/analyzer flow is unaffected while doing this. Then, signed in as the
   owner (`OWNER_GITHUB_ID` set to your account's numeric id), open `/admin`:
   confirm the report appears in the queue, approve or reject it, confirm it
   disappears from the queue, and confirm `/reports` shows the updated status
   for the reporting account.
```

- [ ] **Step 3: Re-read the two edited sections** to confirm the surrounding table/numbering wasn't disturbed (the `OWNER_GITHUB_ID` paragraph stays inside the existing secrets table under step 4; step 6 stays step 6).

- [ ] **Step 4: Commit:**

```bash
git add docs/OPERATIONS.md
git commit -m "docs(admin): turn the deferred OWNER_GITHUB_ID note into a real setup step"
```

---

### Task 9: Live dogfood pass — `wrangler pages dev`, including the fail-closed unset-owner case

**Files:** none created/modified — this is a manual verification pass against a real local D1, run after Tasks 1-8 are all committed. Its outcome (pass/fail per numbered check) is recorded in the commit body of Step 9's commit below.

**Prerequisites:** `wrangler` on PATH (`npm i -g wrangler` if not already — `docs/OPERATIONS.md:311-317` notes it wasn't installed on this machine as of 2026-08-21); a Cloudflare account with a `socdesk_reports` D1 database created and migrated (`docs/OPERATIONS.md`'s Owner one-time setup, steps 1-5 — already done if Phase 0+1 was dogfooded); the built site (`npm --prefix web run build`, output `web/dist`).

- [ ] **Step 1: Build the site:**

Run: `npm --prefix web run build`
Expected: clean build, `web/dist` populated.

- [ ] **Step 2: Start `wrangler pages dev` with the local D1 binding, `OWNER_GITHUB_ID` left UNSET:**

Run: `wrangler pages dev web/dist --d1=DB=socdesk_reports --compatibility-date=2026-08-01`

(If a `.dev.vars` file already carries `GITHUB_CLIENT_ID`/`GITHUB_CLIENT_SECRET`/`SESSION_SECRET`/`TURNSTILE_SECRET` from the Phase 0+1 dogfood, leave it as-is but confirm it does NOT set `OWNER_GITHUB_ID` for this first pass — that omission is the point of Step 5 below.)

- [ ] **Step 3: Seed a queued report directly in the local D1** (bypasses the OAuth/Turnstile flow so this pass doesn't depend on live GitHub credentials being configured in this terminal):

Run:

```
wrangler d1 execute socdesk_reports --local --command "INSERT INTO accounts(github_id,login,created_at,last_seen) VALUES (424242,'dogfood-reporter','2026-08-22T00:00:00.000Z','2026-08-22T00:00:00.000Z'); INSERT INTO reports(id,github_id,ioc_type,ioc_value,category,evidence,comment,status,created_at) VALUES ('3fa85f64-5717-4562-b3fc-2c963f66afa6',424242,'ipv4','198.51.100.7','scanner','Repeated SSH brute-force attempts from this host over 3 days.',NULL,'queued','2026-08-22T00:00:00.000Z'); SELECT id, status FROM reports;"
```

Expected output: one row, `id = 3fa85f64-5717-4562-b3fc-2c963f66afa6`, `status = queued`.

- [ ] **Step 4: Unauthenticated request → 401:**

Run: `curl.exe -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8788/api/admin/reports`
Expected: `401`

- [ ] **Step 5: Fail-closed check — `OWNER_GITHUB_ID` still unset, sign in as ANY account (including what will become the owner) → still 403.** Sign in via `http://127.0.0.1:8788/api/auth/github/start` in a browser (this needs `GITHUB_CLIENT_ID`/`GITHUB_CLIENT_SECRET` configured for local dev — the same OAuth App from `docs/OPERATIONS.md` step 1, with a callback URL that also covers `http://127.0.0.1:8788/api/auth/github/callback`). After the cookie is set, hit `/api/admin/reports` from the same browser session (or copy the `sd_session` cookie into a `curl.exe -b "sd_session=<value>"` call).

Expected: `403 {"error":"forbidden"}` — this is the single most important check in this pass: an unconfigured `OWNER_GITHUB_ID` must reject a real, valid, signed-in session, not silently admit the first person who asks.

- [ ] **Step 6: Set `OWNER_GITHUB_ID` to the signed-in account's numeric id, restart `wrangler pages dev`:**

Find the numeric id: `curl.exe -s https://api.github.com/users/<your-github-login>` → the `id` field. Add it to `.dev.vars` (`OWNER_GITHUB_ID=<numeric id>`) and restart `wrangler pages dev web/dist --d1=DB=socdesk_reports --compatibility-date=2026-08-01`.

Run (same signed-in session as Step 5): `curl.exe -s -b "sd_session=<value>" http://127.0.0.1:8788/api/admin/reports`
Expected: `200`, body `{"reports":[{"id":"3fa85f64-5717-4562-b3fc-2c963f66afa6","github_id":424242,"login":"dogfood-reporter","ioc_type":"ipv4","ioc_value":"198.51.100.7","category":"scanner","evidence":"Repeated SSH brute-force attempts from this host over 3 days.","comment":null,"status":"queued","created_at":"2026-08-22T00:00:00.000Z"}]}`

- [ ] **Step 7: Open `/admin` in the browser** (`http://127.0.0.1:8788/admin`, same signed-in session): confirm the seeded row renders — indicator value, `ipv4 · reported by @dogfood-reporter · 2026-08-22` caption in `text-muted` (not visibly dimmer than the evidence line), the evidence paragraph, a `scanner` neutral chip (no red/amber/green), a "Check reputation →" link, and Approve/Reject buttons. Click "Check reputation →" and confirm it opens `/lookup#q=198.51.100.7` with the lookup form pre-filled. Return to `/admin`.

- [ ] **Step 8: Approve the report via the UI.** Click **Approve**. Expected: the row disappears from the list without a full page reload (React state update via `removeFromQueue`), the queue count in the header updates, no console errors.

- [ ] **Step 9: Confirm the D1 write and the reporter-facing status:**

Run: `wrangler d1 execute socdesk_reports --local --command "SELECT status FROM reports WHERE id='3fa85f64-5717-4562-b3fc-2c963f66afa6';"`
Expected: `status = approved`.

Then, as the `dogfood-reporter` account (or via `curl.exe` with that account's session cookie if you have one), hit `GET /api/report/mine` and confirm the same report now shows `"status":"approved"`.

- [ ] **Step 10: Double-action idempotency — re-POST the same id:**

Run: `curl.exe -s -o /dev/null -w "%{http_code}\n" -b "sd_session=<owner value>" -X POST -H "content-type: application/json" -d "{\"id\":\"3fa85f64-5717-4562-b3fc-2c963f66afa6\",\"action\":\"approve\"}" http://127.0.0.1:8788/api/admin/moderate`
Expected: `404` (not a silent `200` — `updateReportStatus`'s `AND status = 'queued'` guard means the already-approved row can't be re-written).

- [ ] **Step 11: Malformed-id guard — POST a non-UUID id:**

Run: `curl.exe -s -o /dev/null -w "%{http_code}\n" -b "sd_session=<owner value>" -X POST -H "content-type: application/json" -d "{\"id\":\"1 OR 1=1\",\"action\":\"approve\"}" http://127.0.0.1:8788/api/admin/moderate`
Expected: `400` (rejected by `isValidReportId` before D1 is ever touched).

- [ ] **Step 12: Reject flow.** Seed a second queued row (repeat Step 3's `INSERT` with a different id, e.g. `3fa85f64-5717-4562-b3fc-2c963f66afa7`, and `ioc_value = '198.51.100.8'`), reload `/admin`, click **Reject** on it, and repeat Step 9's D1 check expecting `status = rejected`.

- [ ] **Step 13: Confirm the read/lookup/analyzer path is unaffected.** With `wrangler pages dev` still running, visit `/lookup`, `/analyzer`, and the landing page cockpit — confirm they load and behave exactly as before this track's changes (no new network calls to `/api/admin/*` from any read-path surface, no CSP violations in the browser devtools network/console tabs).

- [ ] **Step 14: Non-owner check.** Sign in as a second GitHub account whose numeric id does NOT match `OWNER_GITHUB_ID` (or clear `OWNER_GITHUB_ID` again and restart, then sign in as the same account used in Step 5) and confirm `/admin` renders the "This console is owner-only" `Notice` (the `forbidden` branch), not the queue.

- [ ] **Step 15: Commit the dogfood record** (documents the pass in the commit body, matching the phase01/reporting-UX-polish convention of recording manual checks in commit history):

```bash
git commit --allow-empty -m "$(cat <<'EOF'
test(admin): live dogfood pass — wrangler pages dev + local D1

Verified against a local D1 (socdesk_reports, --local):
- GET /api/admin/reports: 401 signed-out, 403 signed-in-non-owner,
  403 signed-in-as-future-owner while OWNER_GITHUB_ID is unset (fail-closed),
  200 + queue once OWNER_GITHUB_ID is set to the signed-in account's id.
- POST /api/admin/moderate: approve and reject both write the correct
  status; a repeat POST on an already-actioned id returns 404, not a
  second write; a non-UUID id returns 400 before touching D1.
- /admin renders sign-in / not-authorized / loaded states via the shared
  primitives only; Approve/Reject remove the row without a reload; the
  per-row "Check reputation" link opens /lookup#q=<value>.
- /lookup, /analyzer, and the landing cockpit are unaffected; no CSP
  violations observed.
EOF
)"
```

---

## Self-review notes

- **Spec coverage:** every in-scope item from spec §0's "In-scope" list has a task — the owner gate (Task 1), `GET /api/admin/reports` (Task 3), `POST /api/admin/moderate` (Task 4), `Admin.tsx` + `adminModel.ts` (Tasks 5-6), the two `db.mjs` queries (Task 2), and the `docs/OPERATIONS.md` flip (Task 8). All four Panel-review amendments (legibility, UUID validation, whitespace-only `OWNER_GITHUB_ID` hardening, row-error colour + `aria-live`, contextual `aria-label`s, the deep-link) are folded into Tasks 1, 4, and 6 rather than left as follow-ups. The live-dogfood requirement (spec §6, including the fail-closed unset-owner case) is Task 9, explicit and command-complete. Every explicitly-OUT-of-scope item from spec §0 (publishing to enrich, the ISP/ASN leaderboard, `lib/enrich.mjs`/`functions/api/enrich.js`, rejection-reason fields, a confirm-before-reject modal, palette/nav registration) has a corresponding "do not do this" line in Global Constraints or a task's design notes.
- **Placeholder scan:** no `TBD`/`TODO`/"add appropriate handling" anywhere above; every step that touches code shows the exact code; every git commit is a real, complete command.
- **Type/name consistency:** `QueuedReport` (Task 5) matches the shape `listQueuedReports` (Task 2) actually returns and what `Admin.tsx` (Task 6) destructures (`id`, `github_id`, `login`, `ioc_type`, `ioc_value`, `category`, `evidence`, `comment`, `status`, `created_at`) field-for-field. `isOwner`/`statusForAction`/`isValidReportId` (Task 1) are imported with identical names in Tasks 3-4. `removeFromQueue` (Task 5) is imported with the identical name and signature in Task 6.
