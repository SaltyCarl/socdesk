# IOC Reporting — Phase 0+1 Design Spec (foundation + report write path)

**Date:** 2026-08-20 · **Status:** design, pre-implementation · **Scope target:** `functions/` (new Pages Functions) + Cloudflare **D1** + `web/` (report UX) + docs reframe.

## 0. Summary

Add the foundation for crowdsourced **IOC reporting** to SOCDesk: a signed-in
analyst can report an IP/domain/etc. as abusive, and the report lands in a
**moderation queue** (not live). This spec covers **Phase 0** (the write
substrate — Cloudflare D1 + GitHub OAuth) and **Phase 1** (the report write path
+ minimal reporter status view). It deliberately stops before moderation
(Phase 2), publishing to the lookup card (Phase 3), and the abuse-leaderboard
(Phase 4+).

Success = a signed-in analyst submits a report from a lookup card, it is written
to D1 with status `queued`, and they can see it in a "my reports" list.

**This is the first time SOCDesk gains a database and accounts.** That is a
deliberate, owner-approved departure (see §2, §3.5) — the *lookup/read path
stays 100% no-account and client-served*; only the *report/write path* is gated.

## 1. Scope

**In (Phase 0+1):**
- Cloudflare D1 store bound to the Pages project; the `accounts` + `reports`
  schema (with a `status` column already present for later moderation).
- GitHub OAuth sign-in (start/callback Pages Functions; stateless HMAC-signed
  session cookie; default scope — stores only `github_id` + `login`, no PII).
- `POST /api/report` — validate, rate-limit, write a `queued` report.
- Web UX: a "Report this IOC" affordance on the lookup card → sign-in if needed
  → a small form (category + mandatory evidence + optional comment) → "queued
  for review"; and a minimal **`/reports` "my reports"** view (nav:false) showing
  the signed-in user's submissions and their status.
- Anti-abuse on the write path: Turnstile on the report form + a per-account
  daily report cap.
- The **docs reframe** (§3.5): update the identity claim from "no database, no
  accounts" to "no-account read path, auth-gated write path" across the docs
  that assert it — deliberately, not silently.

**Out (later phases — named so the boundary is explicit):**
- **Phase 2:** the owner moderation console (`/admin`, approve/reject).
- **Phase 3:** publishing approved reports as the live `SOCDESK_COMMUNITY`
  context source inside `/api/enrich`.
- **Phase 4:** the aggregate dataset + ISP/ASN abuse-leaderboard (committed-JSON
  pipeline; ASN/network-level, count-language, attributed).
- **Phase 5:** trends/analytics. **Phase 6:** optional upstream push.
- Magic-link auth (add only if a GitHub-less analyst asks).

## 2. Doctrine / invariants (binding)

- **The read/lookup path stays no-account and client-served.** No lookup or
  analyzer flow gains a login. The client still only calls `/api/enrich` as it
  does today; D1 is touched ONLY by the report/auth Functions.
- **Minimal identity, no PII.** Store `github_id` (stable), `login` (handle),
  and timestamps. Never request or store email/name/avatar (default OAuth scope).
- **Evidence-required + "reported activity", never a bare verdict.** A report
  MUST carry an evidence field; report copy says "reported for <category>",
  never "this is malicious". This is the anti-defamation posture (moderation
  before any publish is Phase 2+; nothing this phase makes public).
- **Nothing published this phase.** A `queued` report is visible only to its
  author (`/reports`) and, later, the owner. It never reaches the lookup card
  until Phase 3, after moderation.
- **Free-tier only** (D1 free tier, GitHub OAuth free, Turnstile free). No paid
  dependency.
- **No AI attribution** anywhere (commit messages, comments, docs — SaltyCarl
  public repo).
- Author identity is **SaltyCarl** for commits.

## 3. Architecture

### 3.1 Store — Cloudflare D1

A single D1 database `socdesk_reports`, bound to the Pages project as `DB`
(owner configures the binding in the CF dashboard / wrangler, same way the
enrich API keys are Pages secrets). Schema (migration `0001_init.sql`):

```sql
CREATE TABLE accounts (
  github_id   INTEGER PRIMARY KEY,      -- stable numeric GitHub id
  login       TEXT    NOT NULL,         -- @handle at last sign-in
  created_at  TEXT    NOT NULL,         -- ISO8601
  last_seen   TEXT    NOT NULL,
  banned      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE reports (
  id           TEXT    PRIMARY KEY,     -- uuid
  github_id    INTEGER NOT NULL REFERENCES accounts(github_id),
  ioc_type     TEXT    NOT NULL,        -- ipv4|ipv6|domain|url|md5|sha1|sha256
  ioc_value    TEXT    NOT NULL,        -- normalized (refanged, lowercased where apt)
  category     TEXT    NOT NULL,        -- controlled vocab (see §3.3)
  evidence     TEXT    NOT NULL,        -- REQUIRED free-text / URL evidence
  comment      TEXT,                    -- optional
  status       TEXT    NOT NULL DEFAULT 'queued',  -- queued|approved|rejected (moderation = Phase 2)
  created_at   TEXT    NOT NULL
);
CREATE INDEX idx_reports_ioc    ON reports(ioc_type, ioc_value);
CREATE INDEX idx_reports_author ON reports(github_id, created_at);
CREATE INDEX idx_reports_status ON reports(status, created_at);
```

The `status` column ships now (default `queued`) so Phase 2 adds no migration to
the hot table. Aggregation-by-IOC (Phase 3/4) is served by `idx_reports_ioc`.

### 3.2 Auth — GitHub OAuth (hand-rolled)

An OAuth App (owner-created; `GITHUB_CLIENT_ID` + `GITHUB_CLIENT_SECRET` in Pages
secrets). Two Functions + a stateless session:

- `GET /api/auth/github/start` — redirects to GitHub's authorize URL with a
  signed, short-TTL `state` (CSRF) and `redirect_uri` back to the callback.
- `GET /api/auth/github/callback` — verifies `state`, exchanges `code` for a
  token (server-side, secret never in the browser), calls `GET /user` with the
  token to read `id` + `login` (default scope only), upserts `accounts`, sets a
  **stateless session cookie** = `base64url(payload).hmac`, where payload =
  `{ github_id, login, iat, exp }` signed with `SESSION_SECRET` (HMAC-SHA256).
  `HttpOnly; Secure; SameSite=Lax; Max-Age=<~30d>`. No sessions table.
- A shared `requireSession(request, env)` helper verifies the cookie HMAC + exp
  and returns `{ github_id, login }` or 401. Reused by `/api/report` and (later)
  `/api/moderate`.
- `POST /api/auth/logout` clears the cookie.

No refresh tokens, no server session store — the signed cookie IS the session;
expiry forces a cheap re-auth.

### 3.3 Report write path — `POST /api/report`

1. `requireSession` → 401 if not signed in; 403 if `banned`.
2. **Turnstile** token in the body → verify with `TURNSTILE_SECRET` → 400 on fail.
3. Validate: `ioc_type`/`ioc_value` via the shared `detectType` (reuse
   `@socdesk/shared/indicators`; reject if the value doesn't match the type);
   `category` in the controlled vocab; `evidence` non-empty (trim, min length,
   max length); lengths bounded (evidence ≤ 2000, comment ≤ 1000).
4. **Rate limit:** reject if this `github_id` has ≥ `DAILY_REPORT_CAP` (e.g. 25)
   reports in the last 24h (count query on `idx_reports_author`).
5. **De-dupe:** if the same `github_id` already has a `queued` report for the
   same `(ioc_type, ioc_value)`, return the existing one (idempotent) rather than
   stacking duplicates.
6. Insert `status='queued'`; return `{ id, status: 'queued' }`.

**Category controlled vocab** (align with AbuseIPDB's set for future upstream
push): `brute-force, ssh, port-scan, web-app-attack, phishing, malware-c2,
scanner, spam, exploited-host, other`. Rendered as friendly labels client-side.

`GET /api/report/mine` — `requireSession` → the caller's own reports
(id, ioc, category, status, created_at), newest first, for the `/reports` view.

### 3.4 Web UX (`web/`)

- **Report affordance:** on the escalation card (and/or the lookup result), a
  low-key "Report this IOC" action. It is NOT a verdict claim — copy: "Seen this
  indicator abusing something? Report it (sign-in required)."
- **Sign-in:** if no session, the action routes through `/api/auth/github/start`
  (returns to the same indicator). If signed in, opens the report form.
- **Report form** (a small modal/inline panel): the IOC (prefilled, read-only),
  a **category** select, a **required evidence** field, an optional comment, the
  invisible Turnstile widget, submit → "Queued for review — thanks." Honest
  states for 401/403/429/400.
- **`/reports` (nav:false)** — the signed-in user's submissions with status
  chips (`queued` for now; `approved`/`rejected` become meaningful in Phase 2).
  This is the "reporters need to see their status" mitigation both reviewers
  flagged — shipped early so the moderator-silence problem never appears.
- The lookup/analyzer surfaces are otherwise **unchanged** — no login, no D1.

### 3.5 Docs reframe (own the identity shift)

Update the identity claim deliberately (part of the Phase 0 deliverable):
- `CLAUDE.md` "No secrets"/architecture notes — add the read-path-vs-write-path
  distinction; note D1 + OAuth are write-path only.
- `docs/competitive-landscape.md` — the "zero-account" differentiator is now
  "zero-account **lookup**; opt-in auth only to **contribute**."
- `docs/INFRASTRUCTURE-OPTIONS.md` — record the conscious reversal of the
  "separate auth-gated deployment" ruling → bolt-on with disciplined
  read/write separation, with the reasons.

## 4. Error handling / anti-abuse

- Every Function returns JSON errors with a stable shape `{ error, reason }` and
  correct status (400/401/403/429/500). No stack leakage.
- Turnstile + the per-account daily cap + the de-dupe are the write-path abuse
  controls this phase. (Site-wide `/api/enrich` hardening — Turnstile + KV budget
  — is the SEPARATE abuse-hardening backlog item; this spec only guards the new
  write endpoints.)
- All user text is treated as attacker-influenced: parameterized D1 queries
  (never string-built SQL); the client escapes on render (React); evidence/comment
  are never rendered as HTML.
- Ban path: `banned=1` blocks `/api/report` (owner sets it directly in Phase 1;
  a UI is Phase 2).

## 5. Testing

Per the repo convention (node test env, no DOM/React render): **pure logic is
unit-tested; Functions + OAuth + D1 are integration/build-gated + a manual pass.**
- **Pure, unit-tested:** the session cookie sign/verify (HMAC round-trip, expiry,
  tamper rejection); report validation (type/value match via `detectType`,
  category vocab, evidence-required, length bounds); the rate-limit + de-dupe
  decision functions (pure, given a row set). Extract these as pure helpers so
  they test without a live D1/fetch.
- **Integration (local):** run the Functions against a local D1 via
  `wrangler pages dev` with `--d1`; assert the OAuth callback upserts an account
  and `/api/report` writes a `queued` row and enforces the cap/de-dupe. Documented
  as a scripted local check (not the node suite).
- **Manual acceptance (owner):** create the OAuth App + D1 binding + Turnstile
  keys in Cloudflare, sign in, submit a report, see it in `/reports`, confirm the
  lookup path still works logged-out.
- Builds: `npm --prefix web run build` + `cd web && npx vitest run ../shared src`
  stay green (the web changes are additive).

## 6. Non-goals (restate)

No moderation console, no publishing to the lookup card, no leaderboard, no
consensus verdict, no upstream push, no magic-link — all later phases. This spec
ends when a `queued` report exists in D1 and its author can see it.

## 7. Risks / open owner-config

- **Owner one-time setup** (documented, not automatable): a GitHub OAuth App
  (client id/secret), a D1 database + Pages binding, Turnstile site/secret keys,
  and the `SESSION_SECRET`/`OWNER_GITHUB_LOGIN` Pages secrets. The spec's
  implementation is inert until these exist — same posture as the enrich API keys.
- **D1 + Pages Functions binding** must be confirmed working on a preview deploy
  before the write path is trusted (a bad binding fails only at runtime).
- **Session-secret rotation** invalidates all cookies (acceptable — users re-auth).
- The **moderator bottleneck** (both specialists) is a Phase 2 concern, pre-empted
  here only by the `/reports` status view.
