# IOC Reporting — Phase 0+1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A signed-in analyst can report an IOC from a lookup card and it lands in a Cloudflare D1 moderation queue as `queued`, visible to its author — the write substrate (D1 + GitHub OAuth) plus the report path.

**Architecture:** New Cloudflare Pages Functions (`/api/auth/github/*`, `/api/report`, `/api/report/mine`) back a Cloudflare **D1** store. Auth is hand-rolled GitHub OAuth with a stateless HMAC-signed session cookie (default scope, only `github_id`+`login` stored). The lookup/analyzer read path is UNCHANGED and stays no-account; D1 is touched only by the auth + report Functions. Pure logic (session crypto, validation, policy) is unit-tested in the node vitest suite; the Functions/D1/OAuth are integration- + build-gated + a manual owner pass.

**Tech Stack:** Cloudflare Pages Functions (JS, Web Crypto), Cloudflare D1 (SQLite), GitHub OAuth, Cloudflare Turnstile, React 19 (`web/`), vitest (node env).

**Spec:** `docs/superpowers/specs/2026-08-20-ioc-reporting-phase01-design.md`

## Global Constraints

- **Read path stays no-account + client-served.** No lookup/analyzer flow gains a login. D1 is touched ONLY by the auth + report Functions. (spec §2)
- **Minimal identity, no PII:** store `github_id` (numeric), `login`, timestamps. Never request/store email/name/avatar — default OAuth scope. (spec §2, §3.2)
- **Evidence-required; "reported activity," never a bare verdict.** A report MUST carry non-empty evidence; report copy never asserts "malicious". (spec §2)
- **Nothing is published this phase.** A `queued` report is visible only to its author (`/reports`). It never reaches the lookup card. (spec §2)
- **Admin is gated on the numeric `OWNER_GITHUB_ID`, never a login string** (GitHub logins are reclaimable). (spec §7 — applies in Phase 2, but the id is what the session carries.)
- **User text is attacker-influenced:** parameterized D1 queries only (never string-built SQL); never render report text as HTML (React default escaping; no `dangerouslySetInnerHTML`). (spec §4)
- **Free-tier only** (D1 free, GitHub OAuth free, Turnstile free). **No AI attribution** anywhere. Author identity **SaltyCarl**.
- **Pages-Function code is self-contained** — it does NOT import `@socdesk/shared/*` (that alias is Vite-only; the Functions bundle can't resolve it). Reuse `lib/enrich.mjs`'s already-exported `validate(type, q)` for IOC validation. Web/React code MAY use `@socdesk/shared/*`.
- Verification gate per task: `cd web && npx vitest run ../shared ../lib src` green + `npm --prefix web run build` clean. Function/D1 tasks add a documented `wrangler`/manual check.

---

## Owner one-time setup (manual prerequisite — NOT a code task; code is inert until done)

Document these in `docs/OPERATIONS.md` (Task 7) — the implementer does NOT perform them:
1. Create a **GitHub OAuth App** (Settings → Developer settings → OAuth Apps): homepage `https://socdesk.io`, callback `https://socdesk.io/api/auth/github/callback`. Copy client id/secret.
2. Create a **D1 database**: `wrangler d1 create socdesk_reports`; bind it to the Pages project as `DB` (dashboard → the Pages project → Settings → Functions → D1 bindings, OR `wrangler.toml`).
3. Create a **Turnstile** widget (managed) → site key + secret key.
4. Set Pages **Function secrets** (runtime): `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `SESSION_SECRET` (32+ random bytes), `TURNSTILE_SECRET`, `OWNER_GITHUB_ID` (your numeric id). And ONE **build-time public var** for the web build: `VITE_TURNSTILE_SITEKEY` (the Turnstile *site* key — public, embedded in the bundle; the GitHub client id is NOT needed client-side since `/api/auth/github/start` is a server Function).
5. Apply migrations: `wrangler d1 migrations apply socdesk_reports` (local) / `--remote` (prod).

---

## File Structure

- `lib/reporting/session.mjs` — NEW. Pure HMAC sign/verify for the session cookie AND the OAuth `state` (Web Crypto). Reused by all auth/report Functions.
- `lib/reporting/validate.mjs` — NEW. `CATEGORIES` vocab + `validateReport(body)` (reuses `enrich.mjs` `validate`); pure.
- `lib/reporting/policy.mjs` — NEW. Pure decisions: `overDailyCap`, pick a de-dupe match. (Small; kept separate so the report Function has no inline policy.)
- `lib/reporting/db.mjs` — NEW. Thin D1 data-access (parameterized). Integration-tested.
- `lib/reporting/__tests__/{session,validate,policy}.test.mjs` — NEW unit tests (node vitest).
- `migrations/0001_init.sql` — NEW. The `accounts` + `reports` schema.
- `functions/api/auth/github/start.js`, `functions/api/auth/github/callback.js`, `functions/api/auth/logout.js` — NEW.
- `functions/api/report.js` (POST) + `functions/api/report/mine.js` (GET) — NEW.
- `functions/_lib/session.mjs` — NEW thin re-export shim so Functions import session via a relative path (`../../_lib/session.mjs`) → `../../../lib/reporting/session.mjs`. (Keeps Function imports relative + the logic in `lib/`.)
- `web/src/components/report/ReportButton.tsx`, `ReportForm.tsx`, `useSession.ts` — NEW.
- `web/src/routes/MyReports.tsx` — NEW; registered `nav:false` in `web/src/App.tsx`.
- `web/public/_headers` + `web/index.html` — MODIFY (CSP: Turnstile allowance).
- `CLAUDE.md`, `docs/competitive-landscape.md`, `docs/INFRASTRUCTURE-OPTIONS.md`, `docs/OPERATIONS.md` — MODIFY (identity reframe + owner setup).

---

### Task 1: Session cookie sign/verify (pure Web-Crypto core)

**Files:**
- Create: `lib/reporting/session.mjs`
- Test: `lib/reporting/__tests__/session.test.mjs`

**Interfaces:**
- Produces: `signPayload(payload: object, secret: string): Promise<string>` → `"<b64url body>.<b64url hmac>"`; `verifyPayload(token: string, secret: string, nowSec: number): Promise<object|null>` (null on bad-sig/malformed/expired — expiry read from `payload.exp` epoch-seconds); `SESSION_COOKIE = 'sd_session'`; `sessionCookie(value, maxAgeSec)` / `clearCookie()` header strings; `readCookie(request, name): string|null`.

- [ ] **Step 1: Write the failing test** (`lib/reporting/__tests__/session.test.mjs`):

```js
import { describe, expect, it } from 'vitest'
import { signPayload, verifyPayload } from '../session.mjs'

const secret = 'unit-test-secret-please-rotate-0123456789'

describe('signPayload/verifyPayload', () => {
  it('round-trips a valid payload', async () => {
    const t = await signPayload({ github_id: 42, login: 'alice', exp: 9_999_999_999 }, secret)
    expect(await verifyPayload(t, secret, 1000)).toMatchObject({ github_id: 42, login: 'alice' })
  })
  it('rejects a tampered body', async () => {
    const t = await signPayload({ github_id: 42, exp: 9_999_999_999 }, secret)
    const [b, s] = t.split('.')
    const forged = `${b.slice(0, -1)}${b.slice(-1) === 'A' ? 'B' : 'A'}.${s}`
    expect(await verifyPayload(forged, secret, 1000)).toBeNull()
  })
  it('rejects the wrong secret', async () => {
    const t = await signPayload({ github_id: 42, exp: 9_999_999_999 }, secret)
    expect(await verifyPayload(t, 'other-secret', 1000)).toBeNull()
  })
  it('rejects an expired payload', async () => {
    const t = await signPayload({ github_id: 42, exp: 500 }, secret)
    expect(await verifyPayload(t, secret, 1000)).toBeNull()
  })
  it('rejects malformed input', async () => {
    expect(await verifyPayload('', secret, 1000)).toBeNull()
    expect(await verifyPayload('nodot', secret, 1000)).toBeNull()
    expect(await verifyPayload('a.b.c', secret, 1000)).toBeNull()
  })
})
```

- [ ] **Step 2: Run it, expect FAIL**: `cd web && npx vitest run ../lib/reporting/__tests__/session.test.mjs` → "Cannot find module '../session.mjs'".

- [ ] **Step 3: Implement `lib/reporting/session.mjs`:**

```js
// Pure HMAC-SHA256 sign/verify over base64url(JSON) — used for both the session
// cookie and the OAuth `state`. Web Crypto (crypto.subtle) exists in the Pages
// Functions runtime AND in node 20+, so this is unit-testable.
const enc = new TextEncoder()
export const SESSION_COOKIE = 'sd_session'

function b64urlEncode(bytes) {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
function b64urlDecode(s) {
  const pad = s.length % 4 ? '='.repeat(4 - (s.length % 4)) : ''
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}
async function hmacKey(secret) {
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify'])
}

export async function signPayload(payload, secret) {
  const body = b64urlEncode(enc.encode(JSON.stringify(payload)))
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(body)))
  return `${body}.${b64urlEncode(sig)}`
}

export async function verifyPayload(token, secret, nowSec) {
  if (typeof token !== 'string') return null
  const parts = token.split('.')
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null
  let ok
  try {
    ok = await crypto.subtle.verify('HMAC', await hmacKey(secret), b64urlDecode(parts[1]), enc.encode(parts[0]))
  } catch { return null }
  if (!ok) return null
  let payload
  try { payload = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[0]))) } catch { return null }
  if (typeof payload?.exp === 'number' && nowSec >= payload.exp) return null
  return payload
}

/** Cookie header helpers. HttpOnly + Secure + Lax; ~30d. */
export function sessionCookie(value, maxAgeSec) {
  return `${SESSION_COOKIE}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAgeSec}`
}
export function clearCookie() {
  return `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`
}
export function readCookie(request, name) {
  const raw = request.headers.get('Cookie') || ''
  const m = raw.match(new RegExp(`(?:^|; )${name}=([^;]+)`))
  return m ? m[1] : null
}
```

- [ ] **Step 4: Run it, expect PASS** (same command). Then the gate: `cd web && npx vitest run ../lib`.

- [ ] **Step 5: Commit** — `git add lib/reporting/session.mjs lib/reporting/__tests__/session.test.mjs && git commit -m "feat(reporting): HMAC session cookie sign/verify"`

---

### Task 2: Report validation + policy (pure)

**Files:**
- Create: `lib/reporting/validate.mjs`, `lib/reporting/policy.mjs`
- Test: `lib/reporting/__tests__/validate.test.mjs`, `lib/reporting/__tests__/policy.test.mjs`
- Modify: none (`lib/enrich.mjs` already `export`s `validate`).

**Interfaces:**
- Consumes: `validate(type, q)` from `../enrich.mjs` (returns `{ ok, value } | { ok:false, reason }`).
- Produces: `CATEGORIES: string[]`; `validateReport(body): { ok:true, clean } | { ok:false, error, reason }` where `clean = { ioc_type, ioc_value, category, evidence, comment }`; `EVIDENCE_MAX=2000`, `COMMENT_MAX=1000`, `DAILY_REPORT_CAP=25`. `overDailyCap(recentCount): boolean`.

- [ ] **Step 1: Write the failing tests** (`validate.test.mjs`):

```js
import { describe, expect, it } from 'vitest'
import { validateReport, CATEGORIES } from '../validate.mjs'

const base = { ioc_type: 'ipv4', ioc_value: '45.9.148.20', category: 'scanner', evidence: 'hit my honeypot on 22/tcp' }

describe('validateReport', () => {
  it('accepts a well-formed report (ioc arrives already-clean from the card)', () => {
    const r = validateReport({ ...base, comment: 'x' })
    expect(r.ok).toBe(true)
    expect(r.clean.ioc_value).toBe('45.9.148.20')
    expect(r.clean.category).toBe('scanner')
  })
  it('rejects an ioc that does not match its type', () => {
    expect(validateReport({ ...base, ioc_value: 'not-an-ip' }).ok).toBe(false)
  })
  it('rejects a defanged ioc — validate does not refang; the card supplies clean values', () => {
    expect(validateReport({ ...base, ioc_value: '45[.]9[.]148[.]20' }).ok).toBe(false)
  })
  it('rejects a private/reserved ip (enrich validate)', () => {
    expect(validateReport({ ...base, ioc_value: '10.0.0.1' }).ok).toBe(false)
  })
  it('rejects an unknown category', () => {
    const r = validateReport({ ...base, category: 'not-a-category' })
    expect(r.ok).toBe(false); expect(r.error).toBe('category')
  })
  it('requires non-empty evidence', () => {
    const r = validateReport({ ...base, evidence: '   ' })
    expect(r.ok).toBe(false); expect(r.error).toBe('evidence')
  })
  it('rejects over-length evidence', () => {
    expect(validateReport({ ...base, evidence: 'x'.repeat(3000) }).ok).toBe(false)
  })
  it('CATEGORIES includes the AbuseIPDB-aligned set', () => {
    expect(CATEGORIES).toContain('brute-force'); expect(CATEGORIES).toContain('phishing')
  })
})
```

and `policy.test.mjs`:

```js
import { describe, expect, it } from 'vitest'
import { overDailyCap, DAILY_REPORT_CAP } from '../policy.mjs'
describe('overDailyCap', () => {
  it('is false below the cap, true at/above it', () => {
    expect(overDailyCap(DAILY_REPORT_CAP - 1)).toBe(false)
    expect(overDailyCap(DAILY_REPORT_CAP)).toBe(true)
    expect(overDailyCap(DAILY_REPORT_CAP + 5)).toBe(true)
  })
})
```

- [ ] **Step 2: Run them, expect FAIL** (`cd web && npx vitest run ../lib/reporting/__tests__/validate.test.mjs ../lib/reporting/__tests__/policy.test.mjs`).

- [ ] **Step 3: Implement `lib/reporting/policy.mjs`:**

```js
export const DAILY_REPORT_CAP = 25
export const overDailyCap = (recentCount) => Number(recentCount) >= DAILY_REPORT_CAP
```

- [ ] **Step 4: Implement `lib/reporting/validate.mjs`:**

```js
import { validate } from '../enrich.mjs'

// AbuseIPDB-aligned controlled vocab (eases a future upstream push).
export const CATEGORIES = [
  'brute-force', 'ssh', 'port-scan', 'web-app-attack', 'phishing',
  'malware-c2', 'scanner', 'spam', 'exploited-host', 'other',
]
export const EVIDENCE_MAX = 2000
export const COMMENT_MAX = 1000
const TYPES = ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256']

/** Validate + normalize a report submission. IOC type/value (+ private-IP
 *  rejection) reuse enrich.mjs's validate; category is controlled; evidence is
 *  required. Never trusts client-sent normalization. */
export function validateReport(body) {
  const b = body ?? {}
  if (!TYPES.includes(b.ioc_type)) return { ok: false, error: 'ioc_type', reason: 'unsupported type' }
  const v = validate(b.ioc_type, String(b.ioc_value ?? ''))
  if (!v.ok) return { ok: false, error: 'ioc_value', reason: v.reason }
  if (!CATEGORIES.includes(b.category)) return { ok: false, error: 'category', reason: 'unknown category' }
  const evidence = String(b.evidence ?? '').trim()
  if (!evidence) return { ok: false, error: 'evidence', reason: 'evidence is required' }
  if (evidence.length > EVIDENCE_MAX) return { ok: false, error: 'evidence', reason: 'evidence too long' }
  const comment = String(b.comment ?? '').trim().slice(0, COMMENT_MAX) || null
  return { ok: true, clean: { ioc_type: b.ioc_type, ioc_value: v.value, category: b.category, evidence, comment } }
}
```

- [ ] **Step 5: Run the tests, expect PASS**, then `cd web && npx vitest run ../lib`.

- [ ] **Step 6: Commit** — `git add lib/reporting/validate.mjs lib/reporting/policy.mjs lib/reporting/__tests__/validate.test.mjs lib/reporting/__tests__/policy.test.mjs && git commit -m "feat(reporting): report validation + daily-cap policy"`

---

### Task 3: D1 schema + data-access module

**Files:**
- Create: `migrations/0001_init.sql`, `lib/reporting/db.mjs`
- Test: documented `wrangler` integration check (no node unit test — D1 binding).

**Interfaces:**
- Produces (all take a D1 binding `DB` first): `upsertAccount(DB, github_id, login, nowIso)`; `getAccount(DB, github_id): Promise<{banned:number}|null>`; `countReportsSince(DB, github_id, sinceIso): Promise<number>`; `findQueuedDuplicate(DB, github_id, ioc_type, ioc_value): Promise<{id:string}|null>`; `insertReport(DB, report): Promise<void>` where `report = { id, github_id, ioc_type, ioc_value, category, evidence, comment, created_at }`; `listMyReports(DB, github_id): Promise<row[]>`.

- [ ] **Step 1: Create `migrations/0001_init.sql`** (verbatim from spec §3.1):

```sql
CREATE TABLE accounts (
  github_id   INTEGER PRIMARY KEY,
  login       TEXT    NOT NULL,
  created_at  TEXT    NOT NULL,
  last_seen   TEXT    NOT NULL,
  banned      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE reports (
  id           TEXT    PRIMARY KEY,
  github_id    INTEGER NOT NULL REFERENCES accounts(github_id),
  ioc_type     TEXT    NOT NULL,
  ioc_value    TEXT    NOT NULL,
  category     TEXT    NOT NULL,
  evidence     TEXT    NOT NULL,
  comment      TEXT,
  status       TEXT    NOT NULL DEFAULT 'queued',
  created_at   TEXT    NOT NULL
);
CREATE INDEX idx_reports_ioc    ON reports(ioc_type, ioc_value);
CREATE INDEX idx_reports_author ON reports(github_id, created_at);
CREATE INDEX idx_reports_status ON reports(status, created_at);
```

- [ ] **Step 2: Implement `lib/reporting/db.mjs`** (parameterized only — never string-build SQL):

```js
export async function upsertAccount(DB, github_id, login, nowIso) {
  await DB.prepare(
    `INSERT INTO accounts (github_id, login, created_at, last_seen)
     VALUES (?1, ?2, ?3, ?3)
     ON CONFLICT(github_id) DO UPDATE SET login = ?2, last_seen = ?3`,
  ).bind(github_id, login, nowIso).run()
}
export async function getAccount(DB, github_id) {
  return DB.prepare(`SELECT banned FROM accounts WHERE github_id = ?1`).bind(github_id).first()
}
export async function countReportsSince(DB, github_id, sinceIso) {
  const row = await DB.prepare(
    `SELECT COUNT(*) AS n FROM reports WHERE github_id = ?1 AND created_at >= ?2`,
  ).bind(github_id, sinceIso).first()
  return Number(row?.n ?? 0)
}
export async function findQueuedDuplicate(DB, github_id, ioc_type, ioc_value) {
  return DB.prepare(
    `SELECT id FROM reports WHERE github_id = ?1 AND ioc_type = ?2 AND ioc_value = ?3 AND status = 'queued' LIMIT 1`,
  ).bind(github_id, ioc_type, ioc_value).first()
}
export async function insertReport(DB, r) {
  await DB.prepare(
    `INSERT INTO reports (id, github_id, ioc_type, ioc_value, category, evidence, comment, status, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'queued', ?8)`,
  ).bind(r.id, r.github_id, r.ioc_type, r.ioc_value, r.category, r.evidence, r.comment, r.created_at).run()
}
export async function listMyReports(DB, github_id) {
  const { results } = await DB.prepare(
    `SELECT id, ioc_type, ioc_value, category, status, created_at
     FROM reports WHERE github_id = ?1 ORDER BY created_at DESC LIMIT 200`,
  ).bind(github_id).all()
  return results ?? []
}
```

- [ ] **Step 3: Documented integration check** (record the commands in the commit body — the implementer runs them locally with a local D1; NOT part of the node suite):

```
wrangler d1 create socdesk_reports        # once
wrangler d1 migrations apply socdesk_reports --local
wrangler d1 execute socdesk_reports --local --command \
  "INSERT INTO accounts(github_id,login,created_at,last_seen) VALUES (1,'t','2026-01-01','2026-01-01'); \
   INSERT INTO reports(id,github_id,ioc_type,ioc_value,category,evidence,created_at) \
   VALUES ('r1',1,'ipv4','1.2.3.4','scanner','ev','2026-01-01'); SELECT status FROM reports;"
# expect: status = queued
```

- [ ] **Step 4: Commit** — `git add migrations/0001_init.sql lib/reporting/db.mjs && git commit -m "feat(reporting): D1 schema + parameterized data-access"`

---

### Task 4: GitHub OAuth Functions + requireSession

**Files:**
- Create: `functions/_lib/session.mjs` (re-export shim), `functions/api/auth/github/start.js`, `functions/api/auth/github/callback.js`, `functions/api/auth/logout.js`
- Test: documented `wrangler pages dev` manual check.

**Interfaces:**
- Consumes: `signPayload`/`verifyPayload`/`sessionCookie`/`clearCookie`/`readCookie`/`SESSION_COOKIE` (Task 1); `upsertAccount` (Task 3).
- Produces: `requireSession(request, env): Promise<{github_id, login}|null>` (in `functions/_lib/session.mjs`), reused by Task 5.

- [ ] **Step 1: Create `functions/_lib/session.mjs`** (relative re-export + the requireSession helper — Functions can't use the `@socdesk/shared` alias, so import the lib by relative path):

```js
export * from '../../lib/reporting/session.mjs'
import { verifyPayload, readCookie, SESSION_COOKIE } from '../../lib/reporting/session.mjs'

/** Resolve the signed-in user from the session cookie, or null. */
export async function requireSession(request, env) {
  const raw = readCookie(request, SESSION_COOKIE)
  if (!raw) return null
  const p = await verifyPayload(raw, env.SESSION_SECRET, Math.floor(Date.now() / 1000))
  return p && typeof p.github_id === 'number' ? { github_id: p.github_id, login: p.login } : null
}
```

- [ ] **Step 2: Implement `functions/api/auth/github/start.js`:**

```js
import { signPayload } from '../../../_lib/session.mjs'

export async function onRequestGet({ request, env }) {
  const url = new URL(request.url)
  const ret = url.searchParams.get('return') || '/'
  // Signed state carries the return path + a short expiry (CSRF protection).
  const state = await signPayload({ return: ret, exp: Math.floor(Date.now() / 1000) + 600 }, env.SESSION_SECRET)
  const authorize = new URL('https://github.com/login/oauth/authorize')
  authorize.searchParams.set('client_id', env.GITHUB_CLIENT_ID)
  authorize.searchParams.set('redirect_uri', `${url.origin}/api/auth/github/callback`)
  authorize.searchParams.set('scope', '') // default scope: public profile only
  authorize.searchParams.set('state', state)
  authorize.searchParams.set('allow_signup', 'true')
  return Response.redirect(authorize.toString(), 302)
}
```

- [ ] **Step 3: Implement `functions/api/auth/github/callback.js`:**

```js
import { signPayload, verifyPayload, sessionCookie } from '../../../_lib/session.mjs'
import { upsertAccount } from '../../../../lib/reporting/db.mjs'

const SESSION_TTL = 30 * 24 * 3600 // ~30 days

export async function onRequestGet({ request, env }) {
  const url = new URL(request.url)
  const code = url.searchParams.get('code')
  const state = url.searchParams.get('state')
  const st = state && (await verifyPayload(state, env.SESSION_SECRET, Math.floor(Date.now() / 1000)))
  if (!code || !st) return new Response('bad oauth state', { status: 400 })

  const tok = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { accept: 'application/json', 'content-type': 'application/json' },
    body: JSON.stringify({
      client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET,
      code, redirect_uri: `${url.origin}/api/auth/github/callback`,
    }),
  }).then((r) => r.json()).catch(() => null)
  if (!tok?.access_token) return new Response('token exchange failed', { status: 502 })

  const gh = await fetch('https://api.github.com/user', {
    headers: { authorization: `Bearer ${tok.access_token}`, 'user-agent': 'SOCDesk', accept: 'application/vnd.github+json' },
  }).then((r) => r.json()).catch(() => null)
  if (!gh?.id || !gh?.login) return new Response('profile fetch failed', { status: 502 })

  const nowIso = new Date().toISOString()
  await upsertAccount(env.DB, gh.id, gh.login, nowIso)
  const session = await signPayload(
    { github_id: gh.id, login: gh.login, exp: Math.floor(Date.now() / 1000) + SESSION_TTL }, env.SESSION_SECRET)

  // Same-origin path only: one leading '/', not '//' or '/\' (both of which
  // browsers normalize to an absolute off-site URL). Else fall back to '/'.
  const dest = /^\/($|[^/\\])/.test(st.return || '') ? st.return : '/'
  return new Response(null, {
    status: 302,
    headers: { location: dest, 'set-cookie': sessionCookie(session, SESSION_TTL) },
  })
}
```

- [ ] **Step 4: Implement `functions/api/auth/logout.js`:**

```js
import { clearCookie } from '../../_lib/session.mjs'
export async function onRequestPost() {
  return new Response(JSON.stringify({ ok: true }), {
    status: 200, headers: { 'content-type': 'application/json', 'set-cookie': clearCookie() },
  })
}
```

- [ ] **Step 5: Manual check (documented in the commit body):** with `wrangler pages dev` + the OAuth App + a local D1, hitting `/api/auth/github/start` redirects to GitHub; the callback upserts an `accounts` row and sets an `sd_session` cookie. (Owner performs at dogfood.)

- [ ] **Step 6: Verify the build compiles the Functions:** `npm --prefix web run build` stays clean (Functions aren't part of the web build, but confirm no import breakage by `node --check` on each new `.js`): `for f in functions/api/auth/github/start.js functions/api/auth/github/callback.js functions/api/auth/logout.js functions/_lib/session.mjs; do node --check "$f"; done`.

- [ ] **Step 7: Commit** — `git add functions/_lib/session.mjs functions/api/auth && git commit -m "feat(reporting): GitHub OAuth start/callback + requireSession"`

---

### Task 5: Report Functions (`POST /api/report`, `GET /api/report/mine`)

**Files:**
- Create: `functions/api/report.js`, `functions/api/report/mine.js`
- Test: documented `wrangler` manual check + `node --check`.

**Interfaces:**
- Consumes: `requireSession` (Task 4); `validateReport` (Task 2); `overDailyCap` (Task 2/policy); `getAccount`/`countReportsSince`/`findQueuedDuplicate`/`insertReport`/`listMyReports` (Task 3).

- [ ] **Step 1: Implement `functions/api/report.js`** (POST — the full guarded write path):

```js
import { requireSession } from '../_lib/session.mjs'
import { validateReport } from '../../lib/reporting/validate.mjs'
import { overDailyCap } from '../../lib/reporting/policy.mjs'
import { getAccount, countReportsSince, findQueuedDuplicate, insertReport } from '../../lib/reporting/db.mjs'

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } })

async function turnstileOk(token, secret, ip) {
  if (!token) return false
  const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ secret, response: token, remoteip: ip }),
  }).then((x) => x.json()).catch(() => null)
  return !!r?.success
}

export async function onRequestPost({ request, env }) {
  const user = await requireSession(request, env)
  if (!user) return json({ error: 'auth', reason: 'sign in to report' }, 401)

  const body = await request.json().catch(() => null)
  if (!body) return json({ error: 'body', reason: 'invalid JSON' }, 400)

  const ip = request.headers.get('CF-Connecting-IP') || ''
  if (!(await turnstileOk(body.turnstileToken, env.TURNSTILE_SECRET, ip)))
    return json({ error: 'turnstile', reason: 'challenge failed' }, 400)

  const v = validateReport(body)
  if (!v.ok) return json({ error: v.error, reason: v.reason }, 400)

  const acct = await getAccount(env.DB, user.github_id)
  if (acct?.banned) return json({ error: 'banned', reason: 'account cannot report' }, 403)

  const sinceIso = new Date(Date.now() - 24 * 3600 * 1000).toISOString()
  if (overDailyCap(await countReportsSince(env.DB, user.github_id, sinceIso)))
    return json({ error: 'rate', reason: 'daily report cap reached' }, 429)

  const dup = await findQueuedDuplicate(env.DB, user.github_id, v.clean.ioc_type, v.clean.ioc_value)
  if (dup) return json({ id: dup.id, status: 'queued', deduped: true }, 200)

  const id = crypto.randomUUID()
  await insertReport(env.DB, { id, github_id: user.github_id, ...v.clean, created_at: new Date().toISOString() })
  return json({ id, status: 'queued' }, 200)
}
```

- [ ] **Step 2: Implement `functions/api/report/mine.js`** (GET the caller's own reports):

```js
import { requireSession } from '../../_lib/session.mjs'
import { listMyReports } from '../../../lib/reporting/db.mjs'

export async function onRequestGet({ request, env }) {
  const user = await requireSession(request, env)
  if (!user) return new Response(JSON.stringify({ error: 'auth' }), { status: 401, headers: { 'content-type': 'application/json' } })
  const reports = await listMyReports(env.DB, user.github_id)
  return new Response(JSON.stringify({ reports }), { status: 200, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } })
}
```

- [ ] **Step 3: `node --check` both files:** `node --check functions/api/report.js && node --check functions/api/report/mine.js`.

- [ ] **Step 4: Documented manual check (commit body):** `wrangler pages dev` + a session cookie → `POST /api/report` with a valid body + Turnstile test token writes a `queued` row; a 26th report in 24h → 429; a duplicate → `deduped:true`; unauthenticated → 401. `GET /api/report/mine` returns the row.

- [ ] **Step 5: Commit** — `git add functions/api/report.js functions/api/report/mine.js && git commit -m "feat(reporting): POST /api/report (guarded write) + GET /api/report/mine"`

---

### Task 6: Web UX — Report affordance, form, `/reports`, CSP

**Files:**
- Create: `web/src/components/report/useSession.ts`, `ReportButton.tsx`, `ReportForm.tsx`; `web/src/routes/MyReports.tsx`
- Modify: `web/src/App.tsx` (register `/reports` `nav:false`), `web/public/_headers` + `web/index.html` (CSP: Turnstile), the escalation-card/lookup surface to mount `<ReportButton>`.

**Interfaces:**
- Consumes: `POST /api/report`, `GET /api/report/mine`, `GET /api/auth/github/start?return=…` (Tasks 4–5). Env: `import.meta.env.VITE_TURNSTILE_SITEKEY`.

- [ ] **Step 1: CSP — allow Turnstile** in BOTH `web/public/_headers` and `web/index.html`. Add `https://challenges.cloudflare.com` to `script-src`, and add a `frame-src https://challenges.cloudflare.com` directive (currently none → defaults to `default-src 'none'`). Leave everything else unchanged. Example new `script-src`/`frame-src` in `web/public/_headers`:

```
  Content-Security-Policy: default-src 'none'; script-src 'self' https://challenges.cloudflare.com; style-src 'self'; font-src 'self'; img-src 'self' data: https://urlscan.io; connect-src 'self'; frame-src https://challenges.cloudflare.com; worker-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; upgrade-insecure-requests
```

Mirror the same two additions in the `web/index.html` `<meta http-equiv="Content-Security-Policy">`.

- [ ] **Step 2: `useSession.ts`** — a tiny hook that reports whether the user is signed in (by probing `/api/report/mine`; 401 = signed out):

```tsx
import { useEffect, useState } from 'react'
export type SessionState = { status: 'loading' | 'in' | 'out' }
export function useSession(): SessionState {
  const [s, setS] = useState<SessionState>({ status: 'loading' })
  useEffect(() => {
    let live = true
    fetch('/api/report/mine', { credentials: 'same-origin' })
      .then((r) => { if (live) setS({ status: r.ok ? 'in' : 'out' }) })
      .catch(() => { if (live) setS({ status: 'out' }) })
    return () => { live = false }
  }, [])
  return s
}
```

- [ ] **Step 3: `ReportButton.tsx`** — the low-key affordance; opens the form (or routes to sign-in). Copy is NON-accusatory:

```tsx
import { useState } from 'react'
import type { IndicatorType } from '@socdesk/shared/indicators'
import { ReportForm } from './ReportForm'

export function ReportButton({ iocType, iocValue }: { iocType: IndicatorType; iocValue: string }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <button type="button" onClick={() => setOpen(true)}
        className="font-mono text-micro text-faint transition-colors hover:text-paper">
        Report this indicator
      </button>
      {open && <ReportForm iocType={iocType} iocValue={iocValue} onClose={() => setOpen(false)} />}
    </>
  )
}
```

- [ ] **Step 4: `ReportForm.tsx`** — sign-in gate + the form + invisible Turnstile. (Renders the Turnstile widget by injecting its script; on submit POSTs to `/api/report`.) Full component:

```tsx
import { useEffect, useRef, useState } from 'react'
import type { IndicatorType } from '@socdesk/shared/indicators'
import { useSession } from './useSession'

const CATEGORIES = ['brute-force','ssh','port-scan','web-app-attack','phishing','malware-c2','scanner','spam','exploited-host','other']

export function ReportForm({ iocType, iocValue, onClose }: { iocType: IndicatorType; iocValue: string; onClose: () => void }) {
  const session = useSession()
  const [category, setCategory] = useState('scanner')
  const [evidence, setEvidence] = useState('')
  const [comment, setComment] = useState('')
  const [state, setState] = useState<'idle' | 'sending' | 'done' | string>('idle')
  const tokenRef = useRef<string>('')
  const widgetRef = useRef<HTMLDivElement>(null)

  // Load Turnstile + render the (invisible/managed) widget once signed in.
  useEffect(() => {
    if (session.status !== 'in' || !widgetRef.current) return
    const s = document.createElement('script')
    s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js'; s.async = true
    document.head.appendChild(s)
    const id = setInterval(() => {
      // @ts-expect-error injected global
      if (window.turnstile && widgetRef.current && !widgetRef.current.dataset.rendered) {
        widgetRef.current.dataset.rendered = '1'
        // @ts-expect-error injected global
        window.turnstile.render(widgetRef.current, {
          sitekey: import.meta.env.VITE_TURNSTILE_SITEKEY,
          callback: (t: string) => { tokenRef.current = t },
        })
        clearInterval(id)
      }
    }, 200)
    return () => clearInterval(id)
  }, [session.status])

  const submit = async () => {
    setState('sending')
    const r = await fetch('/api/report', {
      method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ioc_type: iocType, ioc_value: iocValue, category, evidence, comment, turnstileToken: tokenRef.current }),
    })
    if (r.ok) setState('done')
    else { const b = await r.json().catch(() => ({})); setState(b.reason || `error ${r.status}`) }
  }

  return (
    <div className="mt-3 rounded-md border border-line bg-panel p-3 text-xs">
      {session.status === 'loading' && <p className="text-faint">…</p>}
      {session.status === 'out' && (
        <div className="flex flex-col gap-2">
          <p className="text-muted">Reporting needs a quick GitHub sign-in (so reports are attributable). Look-ups never do.</p>
          <a href={`/api/auth/github/start?return=${encodeURIComponent(location.pathname + location.hash)}`}
            className="self-start rounded-md border border-line px-2 py-1 font-mono text-micro text-paper hover:border-line-bright">
            Sign in with GitHub
          </a>
        </div>
      )}
      {session.status === 'in' && state !== 'done' && (
        <div className="flex flex-col gap-2">
          <span className="font-mono text-micro text-faint">Reporting {iocValue}</span>
          <select value={category} onChange={(e) => setCategory(e.target.value)} className="rounded-md border border-line bg-field px-2 py-1">
            {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
          <textarea value={evidence} onChange={(e) => setEvidence(e.target.value)} required maxLength={2000} rows={3}
            placeholder="Evidence (what you observed) — don't paste sensitive/internal data"
            className="rounded-md border border-line bg-field px-2 py-1 font-mono" />
          <input value={comment} onChange={(e) => setComment(e.target.value)} maxLength={1000}
            placeholder="Optional comment" className="rounded-md border border-line bg-field px-2 py-1" />
          <div ref={widgetRef} />
          {typeof state === 'string' && state !== 'idle' && state !== 'sending' && <p className="text-verdict-amber">{state}</p>}
          <div className="flex gap-2">
            <button type="button" disabled={!evidence.trim() || state === 'sending'} onClick={submit}
              className="rounded-md border border-line px-2 py-1 text-paper disabled:opacity-50">Submit report</button>
            <button type="button" onClick={onClose} className="text-faint hover:text-paper">Cancel</button>
          </div>
        </div>
      )}
      {state === 'done' && (
        <p className="text-verdict-green">Queued for review — thanks. Track it in <a href="/reports" className="underline">My reports</a>.</p>
      )}
    </div>
  )
}
```

- [ ] **Step 5: `MyReports.tsx`** — the author's status view (React escapes all text; no HTML rendering):

```tsx
import { useEffect, useState } from 'react'
type Row = { id: string; ioc_type: string; ioc_value: string; category: string; status: string; created_at: string }
export function MyReports() {
  const [rows, setRows] = useState<Row[] | null>(null)
  const [auth, setAuth] = useState(true)
  useEffect(() => {
    fetch('/api/report/mine', { credentials: 'same-origin' }).then(async (r) => {
      if (r.status === 401) { setAuth(false); return }
      const b = await r.json(); setRows(b.reports ?? [])
    }).catch(() => setRows([]))
  }, [])
  if (!auth) return <p className="p-4 text-xs text-muted">Sign in to see your reports. <a href="/api/auth/github/start?return=/reports" className="underline">Sign in with GitHub</a>.</p>
  if (!rows) return <p className="p-4 text-xs text-faint">…</p>
  if (!rows.length) return <p className="p-4 text-xs text-muted">No reports yet.</p>
  return (
    <ul className="flex flex-col gap-1 p-4">
      {rows.map((r) => (
        <li key={r.id} className="flex items-center gap-2 font-mono text-xs">
          <span className="w-14 text-faint">{r.status}</span>
          <span className="text-paper">{r.ioc_value}</span>
          <span className="text-muted">{r.category}</span>
          <span className="ml-auto text-faint">{r.created_at.slice(0, 10)}</span>
        </li>
      ))}
    </ul>
  )
}
```

- [ ] **Step 6: Register `/reports`** in `web/src/App.tsx` ROUTES (mirror the `/gallery` `nav:false` entry): `{ path: '/reports', label: 'My reports', size: 'default', el: <MyReports />, nav: false },` and import `MyReports`.

- [ ] **Step 7: Mount `<ReportButton>`** on the lookup/escalation surface — add it near the escalation card footer (e.g. in `web/src/routes/Lookup.tsx` where the card renders, passing the resolved indicator's type+value). Keep it low-key (the `text-faint` styling above).

- [ ] **Step 8: Gate:** `npm --prefix web run build` clean; `cd web && npx vitest run src` green (no src regressions — these are additive files). CSP note: confirm the built `web/dist/_headers` carries the Turnstile allowance.

- [ ] **Step 9: Commit** — `git add web/src/components/report web/src/routes/MyReports.tsx web/src/App.tsx web/public/_headers web/index.html web/src/routes/Lookup.tsx && git commit -m "feat(reporting): report button + form + /reports view + Turnstile CSP"`

---

### Task 7: Docs identity reframe + owner setup

**Files:**
- Modify: `CLAUDE.md`, `docs/competitive-landscape.md`, `docs/INFRASTRUCTURE-OPTIONS.md`, `docs/OPERATIONS.md`

- [ ] **Step 1: `CLAUDE.md`** — where it asserts the databaseless/no-secrets/no-account posture, add the read-vs-write distinction: the **lookup/read path stays no-account + client-served**; a **D1 store + GitHub OAuth back the write/report path only**. Keep the "collectors are keyless" rule (that's the public pipeline, unchanged).

- [ ] **Step 2: `docs/competitive-landscape.md`** — soften the "zero-account" differentiator to **"zero-account *lookup*; opt-in GitHub sign-in only to *contribute* a report."** (One-line edit where the differentiator is claimed.)

- [ ] **Step 3: `docs/INFRASTRUCTURE-OPTIONS.md`** — record the conscious reversal of the "separate auth-gated deployment" ruling → bolt-on with disciplined read/write separation (auth-gated Functions + a `nav:false /admin` later; the public read path untouched), with the reasons (portfolio scale, one deploy, clean seam).

- [ ] **Step 4: `docs/OPERATIONS.md`** — add the **owner one-time setup** section verbatim from this plan's "Owner one-time setup" block (OAuth App, D1 create+bind+migrate, Turnstile, the five secrets). This is what makes the code live.

- [ ] **Step 5: Commit** — `git add CLAUDE.md docs/competitive-landscape.md docs/INFRASTRUCTURE-OPTIONS.md docs/OPERATIONS.md && git commit -m "docs: reframe identity to no-account read path + auth-gated write path; owner setup"`

---

## Notes for the executor

- **Do not touch the lookup/analyzer read path or `/api/enrich`.** This phase only adds the auth + report Functions and the report UI. If a change would alter a read-path file's behavior, stop — it's out of scope.
- **The node test env has `crypto.subtle`, `btoa`/`atob`, `TextEncoder`, `crypto.randomUUID`** (node 20+) — Task 1's session tests run without mocks. D1 and `fetch`-to-GitHub/Turnstile are integration, not unit — do not try to unit-test the Functions; the pure helpers they call are the tested surface (repo convention).
- **`@socdesk/shared` is a Vite-only alias.** Function/`lib/` code imports by relative path and reuses `lib/enrich.mjs`. Only `web/src` may use the `@socdesk/shared/*` specifier.
- **Everything is inert until the owner setup (OAuth App, D1 binding, Turnstile, secrets) exists** — the manual dogfood is the acceptance gate, documented in `docs/OPERATIONS.md`.
