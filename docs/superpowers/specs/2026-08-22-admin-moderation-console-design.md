# Owner Moderation Console (`/admin`) — Phase 2 Design Spec

**Date:** 2026-08-22 · **Status:** design, pre-implementation · **Track:** A (of a two-track split; Track B owns `/api/enrich` work in parallel — see §8) · **Scope target:** `functions/api/admin/*` (new Pages Functions) + `lib/reporting/db.mjs` (new queries) + `lib/reporting/admin.mjs` (new, pure) + `web/src/routes/Admin.tsx` (new) + `web/src/App.tsx` (route registration) + docs.

---

## 0. Scope Boundary

**Goal:** give the SOCDesk owner a `/admin` console to review the D1 `reports`
queue (`status = 'queued'`, `migrations/0001_init.sql:16`) and approve or
reject each report, gated so only the owner can reach it.

**In-scope:**
- `GET /api/admin/reports` — owner-gated list of queued reports.
- `POST /api/admin/moderate` — owner-gated approve/reject, writing
  `reports.status`.
- The owner gate: `requireSession` (existing) + a new pure `isOwner()` check
  against `env.OWNER_GITHUB_ID`, applied to both Functions above.
- `web/src/routes/Admin.tsx` — the `/admin` web route (`nav:false`), listing
  the queue with Approve/Reject actions, built from the existing design
  primitives.
- Two new pure/unit-tested modules: `lib/reporting/admin.mjs` (owner check +
  moderation-action vocabulary) and `web/src/routes/adminModel.ts` (optimistic
  list update).
- Two new parameterized queries in `lib/reporting/db.mjs`:
  `listQueuedReports`, `updateReportStatus`.
- Docs: flip `docs/OPERATIONS.md`'s existing "not needed for Phase 0+1... Set
  it when Phase 2 lands" `OWNER_GITHUB_ID` note (`docs/OPERATIONS.md:336-338`)
  into a real setup step.

**Explicitly OUT of scope (name the boundary, don't drift into it):**
- **Publishing approved reports onto the lookup card / `/api/enrich`.** That's
  Phase 3 (`docs/superpowers/specs/2026-08-20-ioc-reporting-phase01-design.md:42`).
  Approving a report here only flips a `status` column — it never becomes
  visible on a lookup, and nothing this track builds reads `reports.status`
  from the enrich path.
- **The ISP/ASN abuse-leaderboard.** That's Phase 4 (same spec, line 44).
- **Any change to the read/lookup/enrich path.** The lookup and analyzer
  surfaces stay 100% no-account, exactly as today.
- **Any edit to `lib/enrich.mjs` or `functions/api/enrich.js`.** Track B owns
  those files for parallel, unrelated work — do not touch them, do not import
  new things from them, do not re-export from them. (`lib/reporting/validate.mjs:1`
  already imports `validate` from `lib/enrich.mjs` for IOC-shape checks on the
  *write* path — that pre-existing import is untouched or reused as-is if
  needed; this track adds no new call into `enrich.mjs` because moderation
  never re-validates the IOC value, it only transitions a status.)
- Rejection-reason / audit-trail fields, a resolved-reports history view,
  pagination beyond a flat cap, and a ban-account UI (`accounts.banned` stays
  owner-set-in-D1-console, unchanged from Phase 0+1 — see
  `docs/superpowers/specs/2026-08-20-ioc-reporting-phase01-design.md:190`).
  All future/Phase-2.x nice-to-haves, not this spec.
- A confirmation modal before Reject. See §3.4 for the reasoning.
- Adding `/admin` to the command palette (`web/src/components/palette/commands.ts`)
  or the top nav. See §3.4.

**Files this track OWNS (create/modify — nothing outside this list):**
| File | Action |
|---|---|
| `lib/reporting/admin.mjs` | create — pure `isOwner`, `statusForAction` |
| `lib/reporting/__tests__/admin.test.mjs` | create |
| `lib/reporting/db.mjs` | modify — add `listQueuedReports`, `updateReportStatus` |
| `functions/api/admin/reports.js` | create — `GET` |
| `functions/api/admin/moderate.js` | create — `POST` |
| `web/src/routes/Admin.tsx` | create |
| `web/src/routes/adminModel.ts` | create — pure optimistic-update helper |
| `web/src/routes/adminModel.test.ts` | create |
| `web/src/App.tsx` | modify — one import + one `ROUTES` entry (`/admin`, `nav:false`) |
| `docs/OPERATIONS.md` | modify — turn the deferred `OWNER_GITHUB_ID` note into a setup step |

No other file is touched. In particular: no changes to `functions/api/report.js`,
`functions/api/report/mine.js`, `functions/_lib/session.mjs`,
`lib/reporting/session.mjs`, `lib/reporting/validate.mjs`,
`lib/reporting/policy.mjs`, `web/src/routes/MyReports.tsx`,
`web/src/routes/myReportsModel.ts`, `migrations/0001_init.sql` (the schema
already has everything this phase needs — see §1), or anything under
`shared/` or `web/public/_headers` (§4 explains why the CSP needs no change).

---

## 1. Context (what already exists, cited)

- `migrations/0001_init.sql:8-18` — `reports.status TEXT NOT NULL DEFAULT
  'queued'` with `idx_reports_status ON reports(status, created_at)`
  (`:21`). No migration needed: the index this phase's list query wants
  already exists.
- `lib/reporting/db.mjs:1-3` — every query goes through D1 prepared
  statements with positional `?N` bindings; this is the load-bearing house
  rule and the new queries below follow it exactly.
- `functions/_lib/session.mjs:5-10` — `requireSession(request, env)` decodes
  the signed cookie and resolves `{ github_id, login } | null`. `github_id`
  is always a `number` when non-null (`:9`), which is what makes the owner
  check a plain `===` comparison.
- `functions/api/report/mine.js:1-9` — the exact session-gated-GET-reading-D1
  shape this track's `GET /api/admin/reports` mirrors: `requireSession` →
  401 JSON on no session → query → 200 JSON, `cache-control: no-store`.
- `functions/api/report.js:18-45` — the guard-order convention (auth → body
  parse → anti-abuse → validate → business rule → write) this track's `POST
  /api/admin/moderate` mirrors, minus the anti-abuse/Turnstile step (not
  needed — see §3.3).
- `docs/superpowers/specs/2026-08-20-ioc-reporting-phase01-design.md:224-229`
  — the security-reviewed ruling this spec inherits verbatim: **admin
  identity is gated on the numeric `OWNER_GITHUB_ID`, never the login
  string**, because GitHub logins are mutable/reclaimable. The session
  cookie already carries `github_id`, so the check is `github_id ===
  Number(env.OWNER_GITHUB_ID)`.
- `docs/OPERATIONS.md:336-338` — `OWNER_GITHUB_ID` is documented as an
  existing, expected-but-unset Pages secret, explicitly deferred to "when
  Phase 2 lands." That's now.

---

## 2. Doctrine this track inherits (binding, unchanged)

- **Minimal identity, no PII** — this track reads `github_id` + `login`
  (already stored, `migrations/0001_init.sql:2-3`) and nothing else. No new
  column, no email/name/avatar.
- **Evidence stays owner-only until approved** — a `queued` report's
  `evidence`/`comment` text is visible to its author and, as of this phase,
  the owner. `GET /api/admin/reports` is the first code that reads those
  fields for anyone other than the author — gate it correctly (§3.2).
- **A report status is NOT a verdict** (`web/src/routes/myReportsModel.ts:5-7`,
  the reserved-colour law in `docs/DESIGN-TOKENS.md:36-39`). The admin UI
  reuses this rule: no `malicious`/`benign`/red/green `Chip` variant for
  `queued`/`approved`/`rejected`. See §3.4.
- **All user text is attacker-influenced** — `evidence`/`comment`/`login`
  render through React's default text interpolation only. No
  `dangerouslySetInnerHTML`, ever, on these fields (same rule as
  `docs/superpowers/specs/2026-08-20-ioc-reporting-phase01-design.md:187-189`).
- **Free-tier only, no new deps.** D1 + the existing session/cookie
  machinery cover everything this phase needs.
- **No AI attribution** in commits/comments/docs (SaltyCarl public repo).

---

## 3. Design

### 3.1 The owner gate — `lib/reporting/admin.mjs` (new, pure)

Pulled out as pure functions so they're node-testable without D1 or `fetch`,
matching the existing `lib/reporting/policy.mjs` pattern (`overDailyCap`).

```js
// lib/reporting/admin.mjs
// Pure owner-identity check + moderation-action vocabulary for the /admin
// console. Kept out of the Functions so they're node-testable (mirrors
// policy.mjs's overDailyCap).

/** True only when `github_id` is a number and matches OWNER_GITHUB_ID
 *  exactly. An unset, blank, or non-numeric OWNER_GITHUB_ID always resolves
 *  false — the gate fails closed, never open-by-default. Login/handle is
 *  never part of this check (see the 2026-08-21 security ruling). */
export function isOwner(github_id, ownerGithubIdRaw) {
  if (typeof github_id !== 'number') return false
  if (ownerGithubIdRaw === undefined || ownerGithubIdRaw === null || ownerGithubIdRaw === '') return false
  const owner = Number(ownerGithubIdRaw)
  if (!Number.isFinite(owner)) return false
  return github_id === owner
}

/** action → the status write it produces, or null for an unrecognized
 *  action. The only two transitions this phase allows are queued→approved
 *  and queued→rejected (enforced again at the SQL layer — see
 *  updateReportStatus's `WHERE status = 'queued'` guard). */
export function statusForAction(action) {
  if (action === 'approve') return 'approved'
  if (action === 'reject') return 'rejected'
  return null
}
```

`isOwner`'s fail-closed shape is the point: an unconfigured `OWNER_GITHUB_ID`
(the state every fresh deploy starts in, per `docs/OPERATIONS.md:336-338`)
must 403 every caller, including a legitimately signed-in analyst — not
silently admit the first person who asks.

### 3.2 `GET /api/admin/reports` (new)

```js
// functions/api/admin/reports.js
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

Guard order mirrors `functions/api/report/mine.js`: 401 (no session) before
403 (wrong session) before the D1 read, so an anonymous caller learns nothing
about whether an owner is even configured.

### 3.3 `POST /api/admin/moderate` (new)

```js
// functions/api/admin/moderate.js
import { requireSession } from '../../_lib/session.mjs'
import { isOwner, statusForAction } from '../../../lib/reporting/admin.mjs'
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

  const changed = await updateReportStatus(env.DB, id, status)
  if (!changed) return json({ error: 'not_found', reason: 'no queued report with that id' }, 404)
  return json({ id, status }, 200)
}
```

Guard order: 401 → 403 → 400 (bad body) → 404 (already actioned / unknown
id) → 200. No Turnstile here, unlike `functions/api/report.js:26-27` —
Turnstile defends an *anonymous-writeable* endpoint from bot spam; this
endpoint is already closed to everyone except one numeric `github_id`, so a
second bot-defense layer adds nothing. **CSRF:** the session cookie is
`SameSite=Lax` (`lib/reporting/session.mjs:46`, unchanged, same posture as
`/api/report`) — Lax cookies aren't attached to cross-site POSTs, which is
the same protection every other write endpoint in this codebase already
relies on. No new CSRF token introduced.

### 3.4 `web/src/routes/Admin.tsx` (new) + `adminModel.ts` (new, pure)

**Route registration** — `web/src/App.tsx`: import `Admin` from
`./routes/Admin` and add one `ROUTES` entry after the `/reports` row
(`web/src/App.tsx:57`):

```ts
{ path: '/admin', label: 'Admin', size: 'default', el: <Admin />, nav: false },
```

`nav: false` matches `/gallery`, `/reports`, `/privacy` — hidden from the
top-nav tab bar (`web/src/App.tsx:77`, filters `nav !== false`).

**Not added to the command palette.** `web/src/components/palette/commands.ts`'s
`DEFAULT_VIEWS` (`:17-74`) lists `/gallery` and `/privacy` but *not*
`/reports` — `/reports` is reachable only through the signed-in
`AccountControl` menu (`web/src/components/ui/AccountControl.tsx:129-141`).
`/admin` follows the `/reports` precedent, not the `/gallery`/`/privacy`
one: it is relevant to exactly one person, so it stays out of `commands.ts`
entirely. The owner reaches it by typing/bookmarking the URL. This is a
named guardrail, not an oversight — do not add an `/admin` row to
`DEFAULT_VIEWS`.

**Auth/authorization states**, mirroring `web/src/routes/MyReports.tsx`'s
fetch-and-branch shape exactly, but with a 403 branch `MyReports` doesn't
need:

```tsx
// web/src/routes/Admin.tsx
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
        method: 'POST', credentials: 'same-origin',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ id, action }),
      })
      if (!r.ok) throw new Error(String(r.status))
      setRows((rs) => (rs ? removeFromQueue(rs, id) : rs))
    } catch {
      setRowError((e) => ({ ...e, [id]: 'Action failed — try again.' }))
    } finally {
      setPending((s) => { const n = new Set(s); n.delete(id); return n })
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
          </a>.
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
              <li key={r.id} className="flex flex-col gap-3 border-b border-line px-4 py-3 last:border-0 even:bg-panel-soft/40">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                    <span className="break-all font-mono text-xs font-semibold text-paper">{r.ioc_value}</span>
                    <span className="font-mono text-micro text-faint">
                      {r.ioc_type} · reported by {r.login ? `@${r.login}` : `#${r.github_id}`} · {r.created_at.slice(0, 10)}
                    </span>
                  </div>
                  <Chip variant="neutral">{r.category}</Chip>
                </div>
                <p className="whitespace-pre-wrap text-xs leading-relaxed text-muted">{r.evidence}</p>
                {r.comment && <p className="whitespace-pre-wrap text-micro text-faint">{r.comment}</p>}
                <div className="flex items-center gap-2">
                  <Button variant="primary" size="sm" disabled={pending.has(r.id)} onClick={() => act(r.id, 'approve')}>
                    Approve
                  </Button>
                  <Button variant="danger" size="sm" disabled={pending.has(r.id)} onClick={() => act(r.id, 'reject')}>
                    Reject
                  </Button>
                  {rowError[r.id] && <span className="text-micro text-verdict-amber">{rowError[r.id]}</span>}
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

Design notes tying this back to the doctrine in §2:

- **Reserved-colour compliance:** the category chip uses `variant="neutral"`
  (`shared/ui/Chip.tsx:52-53`), *not* `catalog`/`technique`/any verdict
  variant — a report's category is a claim about what the *reporter*
  alleged, not a confirmed verdict on the indicator. No status chip is
  rendered at all here (every row in this list is, by construction,
  `queued` — a redundant chip would just be decoration, the thing the
  reserved-colour law explicitly forbids).
- **`Button variant="danger"` for Reject** is the same precedent already in
  the codebase for a real, consequential UI action —
  `web/src/routes/Gallery.tsx:411` ("Purge cache") — per
  `shared/ui/buttonClasses.ts:12-13`'s own doctrine comment: *"DESTRUCTIVE
  actions only (meaning-bearing, never decorative)."* Rejecting a queued
  report is exactly that: a UI-action semantic, not an indicator-verdict
  claim, so it does not conflict with the reserved-colour law (which governs
  hues that assert something about an *indicator*, not hues that assert
  something about a *button*).
- **No confirmation modal before Reject.** Two reasons to keep this out of
  MVP rather than treat it as an oversight: (1) the action is not
  destructive to data — a mis-click is recoverable by an owner D1-console
  edit, same recovery path the existing `banned` flag already relies on
  (`docs/superpowers/specs/2026-08-20-ioc-reporting-phase01-design.md:190`);
  (2) the SQL guard in `updateReportStatus` (§3.5) makes a double-click a
  no-op rather than a double-write. A confirm step is a trivial follow-up if
  the owner finds mis-clicks happen in practice — call it out to the review
  panel as an open question, not a silent gap.
- **No `markContributorSeen()` call** (unlike `MyReports.tsx:27`). That call
  exists to reveal the `AccountControl` "Sign in" affordance to a visitor
  who has just engaged with the *public* reporting flow. `/admin` is not
  part of that discoverability funnel — the owner already knows their own
  auth state — so this route deliberately omits it.
- **`evidence`/`comment` render as plain JSX text nodes** (`{r.evidence}`,
  React-escaped), never through `dangerouslySetInnerHTML`, matching the rule
  in §2.

`web/src/routes/adminModel.ts` — the one piece of pure, extracted logic
(mirrors `myReportsModel.ts`'s "kept out of the component so it exports no
non-component values — react-refresh discipline, and so it is node-testable"
rationale, `web/src/routes/myReportsModel.ts:1-3`):

```ts
// web/src/routes/adminModel.ts
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

### 3.5 `lib/reporting/db.mjs` additions (new queries, appended)

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

Both follow the file's own house rule (`lib/reporting/db.mjs:1-3`):
positional `?N` bindings only, no string-built SQL. `idx_reports_status` on
`(status, created_at)` (`migrations/0001_init.sql:21`) covers
`listQueuedReports`'s `WHERE status = 'queued' ORDER BY created_at` directly
— no migration needed for this phase, confirming the schema note at
`docs/superpowers/specs/2026-08-20-ioc-reporting-phase01-design.md:102-103`
("the `status` column ships now... so Phase 2 adds no migration to the hot
table").

---

## 4. Security review checklist (for the AppSec pass)

- **Authorization, not just authentication:** every branch of both new
  Functions checks `isOwner()` after `requireSession()` — a valid,
  non-owner session gets 403, never a partial response. `isOwner` fails
  closed on an unset `OWNER_GITHUB_ID` (§3.1) — verify this with a unit test
  asserting `isOwner(anyNumber, undefined) === false`.
- **IDOR:** `updateReportStatus`'s `WHERE id = ?2 AND status = 'queued'`
  means an attacker (or a stale UI) can't resurrect an already-approved or
  already-rejected report by resubmitting its id — every write is scoped to
  "still queued."
- **CSRF:** covered in §3.3 — `SameSite=Lax`, same posture as every other
  write endpoint in this repo, no new exposure introduced.
- **XSS:** `evidence`/`comment`/`login` are free text from a signed-in but
  otherwise untrusted analyst. They render as JSX text interpolation only
  (§3.4) — never HTML, never a template string injected into the DOM.
- **CSP:** `web/public/_headers:2` already has `connect-src 'self'`, which
  covers same-origin fetches to `/api/admin/*`. No CSP change is needed —
  confirm this holds by checking the deployed console's network tab for CSP
  violations during the manual dogfood pass (§6).
- **Information leak via status codes:** the 401-before-403 ordering means an
  anonymous caller can't distinguish "no owner configured" from "you're not
  the owner" from "you're not signed in" — they all read the same to a
  probe until a valid session exists. Acceptable; matches the rest of the
  reporting surface's error-shape discipline
  (`docs/superpowers/specs/2026-08-20-ioc-reporting-phase01-design.md:181-182`).

---

## 5. Owner setup step

Update `docs/OPERATIONS.md`'s "Owner one-time setup" section
(`:298-360`) where `OWNER_GITHUB_ID` is currently documented as deferred
(`:336-338`). Replace the deferral note with a real step (numbered after the
existing step 4, alongside the other four Function secrets in that table):

> Set `OWNER_GITHUB_ID` — your numeric GitHub id (never the login; logins are
> reclaimable). Find it via `https://api.github.com/users/<your-login>` →
> the `id` field, or from the GitHub OAuth debug/callback logs. Add it as a
> Pages Function secret alongside `GITHUB_CLIENT_ID` /
> `GITHUB_CLIENT_SECRET` / `SESSION_SECRET` / `TURNSTILE_SECRET`
> (Cloudflare → Workers & Pages → **socdesk** → Settings → Environment
> variables → Production). `/admin` 403s for every account, including the
> owner's, until this is set.

Also fold into the existing step-6 dogfood checklist
(`docs/OPERATIONS.md:356-360`): after submitting a test report, sign in as
the owner at `/admin`, confirm it appears in the queue, approve or reject it,
and confirm it disappears from the queue and `/reports` shows the updated
status for the reporting account.

---

## 6. Testing

Per the repo's established convention (`docs/superpowers/specs/2026-08-20-ioc-reporting-phase01-design.md:193-196`
and `web/vitest.config.ts:26-29`, which already globs
`../lib/**/*.test.mjs`): **pure logic is unit-tested with vitest; Functions +
D1 are build-gated + a manual pass**, not integration-tested in CI.

- **Pure, unit-tested (new):**
  - `lib/reporting/__tests__/admin.test.mjs` — `isOwner`: matches on equal
    numeric id; false on mismatched id; false on non-number `github_id`
    (string/undefined); false when `OWNER_GITHUB_ID` is `undefined`, `null`,
    `''`, or a non-numeric string (`'not-a-number'`); true/false boundary
    with `OWNER_GITHUB_ID` as a numeric-looking string (`env` vars are always
    strings, so this is the realistic input shape — assert
    `isOwner(12345, '12345') === true`). `statusForAction`: `'approve'` →
    `'approved'`, `'reject'` → `'rejected'`, anything else (`undefined`,
    `''`, `'delete'`) → `null`.
  - `web/src/routes/adminModel.test.ts` — `removeFromQueue`: drops the
    matching row, leaves others + order untouched, no-ops on an unknown id,
    handles an empty array.
  - Mirrors the existing style exactly — see
    `lib/reporting/__tests__/policy.test.mjs` and
    `web/src/routes/myReportsModel.test.ts` as the templates.
- **Not unit-tested (thin D1 wrappers, same posture as `listMyReports` /
  `insertReport` today — `lib/reporting/db.mjs` has no test file at all
  currently):** `listQueuedReports`, `updateReportStatus`. Correctness here
  is covered by the manual local-D1 pass below, not vitest.
- **Manual / local-D1 pass (documented, not automated — same posture as
  Phase 0+1, `docs/superpowers/specs/2026-08-20-ioc-reporting-phase01-design.md:202-205`):**
  run `wrangler pages dev` with a local `--d1` binding, seed a `queued` row
  (via `/api/report` or a direct `INSERT`), then:
  1. Hit `/api/admin/reports` unauthenticated → 401.
  2. Sign in as a non-owner GitHub account → `/api/admin/reports` → 403.
  3. Leave `OWNER_GITHUB_ID` unset entirely → sign in as *any* account,
     including what will become the owner → still 403 (the fail-closed
     case — the one most worth actually running, not just asserting in a
     unit test).
  4. Set `OWNER_GITHUB_ID` to the signed-in account's numeric id → `/api/admin/reports`
     → 200 with the seeded row.
  5. `POST /api/admin/moderate {id, action:'approve'}` → 200 → row no longer
     appears in a fresh `GET /api/admin/reports` → `GET /api/report/mine`
     for the original reporter shows `status: 'approved'`.
  6. Repeat for `reject`.
  7. Re-POST the same `{id, action:'approve'}` a second time (simulating a
     double-click / stale tab) → 404, not a silent 200 (`updateReportStatus`'s
     `changes: 0` guard from §3.5).
  8. Confirm the lookup/analyzer/`/reports` flows are visibly unaffected —
     same "don't break the read path" acceptance gate every prior phase used.
- **Build gate:** `npm --prefix web run build` and
  `cd web && npx vitest run ../shared src` (which now also runs `../lib`
  per `web/vitest.config.ts:28`) both stay green — additive only, no
  existing test is touched.

---

## 7. Acceptance criteria

1. `isOwner` and `statusForAction` are pure, unit-tested, and fail closed
   (unset/malformed `OWNER_GITHUB_ID` → always `false`/`null`).
2. `GET /api/admin/reports` returns 401 signed-out, 403 signed-in-non-owner,
   200 + the queued list (oldest-first, reporter handle joined) for the
   owner.
3. `POST /api/admin/moderate` returns 401/403 identically; 400 on a
   malformed body; 404 on an unknown or already-actioned report id; 200 +
   the new status on success; the underlying row's `status` is
   `approved`/`rejected` accordingly and a repeat call no-ops (404, not a
   second write).
4. `/admin` renders sign-in / not-authorized / error / empty / loaded states
   using only the shared design primitives (`Panel`, `Chip variant="neutral"`,
   `MicroLabel`, `Button`, `Notice`, `ViewHeader`) — no bespoke styling, no
   verdict-hued chip on a report's status.
5. Approving or rejecting a row removes it from the visible queue without a
   full reload and surfaces a per-row error (not a page-level crash) if the
   POST fails.
6. `/admin` is `nav:false`, absent from the top nav and absent from
   `commands.ts`'s `DEFAULT_VIEWS` — reachable only by direct URL.
7. The read/lookup/analyzer path is unchanged — confirmed in the manual pass
   (§6, step 8), not just asserted.
8. `docs/OPERATIONS.md` documents the `OWNER_GITHUB_ID` setup step as a real,
   non-deferred instruction.
9. `npm --prefix web run build` and the vitest suite (`../shared`, `src`,
   `../lib`) are green.

---

## 8. Anti-drift guardrails

- **If a task under this spec finds itself editing `lib/enrich.mjs` or
  `functions/api/enrich.js`, stop.** That's Track B's file — a merge
  conflict or a "just this one line" urge here means the task has drifted
  outside this spec's boundary. Re-read §0.
- **If a task finds itself adding a `SOCDESK_COMMUNITY` source, wiring
  `reports.status = 'approved'` into any enrich response, or touching
  anything under `web/src/components/lookup/` or
  `web/src/components/verdict-cards/`, stop.** That's Phase 3, not this
  spec.
- **If a task finds itself designing an ISP/ASN rollup, a trends chart, or
  any aggregate query across `reports`, stop.** That's Phase 4/5.
- **If a task adds a red/green/verdict-hued `Chip` variant to represent
  `queued`/`approved`/`rejected`, stop and re-read §2/§3.4.** A report
  status is a lifecycle state, not a confirmed verdict on an indicator —
  the existing `neutral`/`accent` split in `myReportsModel.ts` is the
  pattern to extend, not override, if a future phase needs richer status
  display.
- **If a task adds `/admin` to `web/src/components/palette/commands.ts` or
  the `Topbar` nav, stop.** §3.4 names this a deliberate omission, not a gap
  to fill.
- **If a task introduces a new D1 table, a `sessions` table, or any schema
  change beyond what `migrations/0001_init.sql` already has, stop.** This
  phase needs zero migrations (§3.5) — a new migration file is a sign the
  design has drifted.
- **Every new SQL string in `db.mjs` must use positional `?N` bindings.** No
  exceptions, no "just this once" string interpolation of a value that
  touches `ioc_value`, `id`, `status`, or anything else request-derived.
