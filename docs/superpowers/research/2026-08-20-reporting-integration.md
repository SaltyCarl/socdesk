# SOCDesk — Crowdsourced IOC Reporting: Integration Assessment

Scope: one dimension of a design decision — how a write-subsystem (report →
moderate → publish) bolts onto SOCDesk without compromising the read path's
zero-account, 100%-client-side identity. Grounded in the current repo
(`functions/api/enrich.js`, `lib/enrich.mjs`, `run_pipeline.py`,
`pipeline/validate.py`, `docs/ARCHITECTURE.md`, `docs/COMPLIANCE.md`,
`docs/INFRASTRUCTURE-OPTIONS.md`, `docs/VERDICT-LANGUAGE.md`,
`docs/competitive-landscape.md`) plus current (2026-08) Cloudflare pricing.

## 0. The precedent this collides with, stated up front

`docs/INFRASTRUCTURE-OPTIONS.md` §2 already ruled on "stateful serverless +
accounts": *"only if the team actually asks for it, and only as a second
auth-gated deployment. Do not merge it into the public site."* That ruling was
about **shared analyst state** (reviewed marks, a team watchlist) — a
different feature. IOC reporting is narrower: a public write path feeding a
public artifact, not private analyst notes. But it is the same *family* of
shift — first database, first accounts, first authenticated write surface —
and `COMPLIANCE.md`'s parked item exists for a reason. This assessment
proceeds on the instruction as given, but Carl should read this section as a
deliberate departure from a documented prior verdict, not a free pass the
architecture already granted.

`docs/VERDICT-LANGUAGE.md` §0 is the second load-bearing constraint:
**"SOCDesk does not pronounce a verdict — it counts what independent public
sources reported."** A crowdsourced report is not an independent public
source — it is SOCDesk's own users. This has a direct, mechanical
consequence in §2 below.

## 1. The clean seam

### 1a. New Pages Functions

All under `functions/api/`, same directory `functions/api/enrich.js` already
lives in, same "keys live in Pages secrets, nothing in the browser" posture:

- **`functions/api/auth/github/start.js`** — redirects to GitHub's OAuth
  authorize URL.
- **`functions/api/auth/github/callback.js`** — exchanges the code, reads the
  GitHub user (id + login only — no email, no scopes beyond `read:user`),
  sets a signed, `HttpOnly`, `Secure` cookie (HMAC over `{id, login, exp}`,
  secret in a Pages env var). **No sessions table.** This mirrors the
  stateless, no-KV-binding choice `/api/enrich` already made for its edge
  cache (`functions/api/enrich.js:31`) — cheapest correct answer, one less
  moving part.
- **`functions/api/report.js`** (`POST`) — requires a valid session cookie,
  validates `{indicator, type, category, comment, evidence_url?}` server-side
  (reuse `validate()` from `lib/enrich.mjs:74` for the indicator itself — it
  already does exactly this job), Turnstile-verifies the request, writes one
  row to D1 with `status='pending'`. Returns `{queued: true}`.
- **`functions/api/moderate/list.js`** / **`functions/api/moderate/decide.js`**
  — require a valid session cookie **and** `session.login === env.OWNER_GITHUB_LOGIN`.
  `list` returns pending reports grouped by indicator; `decide` flips a
  group's status to `approved`/`rejected` and (on approve) fires the publish
  trigger — see §3.

One auth system, not two. Gating the moderation functions by comparing the
already-authenticated GitHub identity against a single owner login is simpler
than standing up Cloudflare Access as a second layer in front of `/admin` —
though Access (free to 50 users, confirmed current) is a reasonable
belt-and-suspenders addition later if the owner login check alone feels thin.
It is not required to ship.

### 1b. Where the moderation console lives

**A gated route inside the existing `web/` app: `/admin`.** Added to
`ROUTES` in `web/src/App.tsx:37` exactly like `/gallery` and `/privacy` —
`nav: false` so it never appears in the topbar (`App.tsx:59`, `:74`) and the
public read-path UI is visually untouched. Client-side the route redirects to
sign-in if there is no session or the wrong identity; server-side every
`/api/moderate/*` call re-checks identity independently, because a client
redirect is UX, never a security boundary.

Not a separate app, not a CLI. A separate app would mean a second build, a
second deploy target, and a second design system to maintain for a feature
one person uses. A CLI (`wrangler d1 execute` by hand) works for Phase 0 but
does not scale to "glance at ten pending reports and batch-approve" — build
the `/admin` UI once real moderation volume exists (Phase 2, §4).

### 1c. Regenerate-vs-live-serve — the two publish targets need different answers

This is the part worth getting right, and the two consumers genuinely want
different mechanisms:

**Per-indicator lookup card → live D1 read, inside the existing `/api/enrich` seam.**
Add a `SOCDESK_COMMUNITY` entry to the `SOURCES` array in `lib/enrich.mjs:533`,
same shape as `ABUSEIPDB`/`GREYNOISE`/etc: a `run(fetchImpl, ind, env)` that
queries D1 (bound to the Function) for approved reports on that exact
indicator and returns `{name, verdict, headline, facts, url}`. This reuses
100% of the existing machinery for free: `Promise.allSettled` fan-out
(`enrich.mjs:589`), per-source error isolation, the same edge-cache layer
(`enrich.js:33`, though this source's cache entry needs a short TTL or a
cache-bypass on the community row specifically, since approval must show up
fast — see §3).

**Critical constraint from §0: this source must NOT enter the `N/M` consensus
tally.** `consensus()` (`enrich.mjs:553`) already excludes `kind: "context"`
rows — that's the exact mechanism `ipinfo`, `RDAP`, and (tellingly) `OTX` use,
and OTX's own comment (`enrich.mjs:483`) makes the identical argument for the
identical reason: *"OTX pulses are community-submitted... a raw pulse count is
attribution, not a malicious/benign call."* SOCDesk's own reports are exactly
that, one degree more so — give `SOCDESK_COMMUNITY` `kind: "context"` and
render it as its own attributed, clearly-labeled block ("SOCDesk community: N
reports, reviewed and published by SOCDesk — not a third-party source"),
never blended into the tally. Anything else means SOCDesk starts grading its
own homework, which directly contradicts the one-sentence governing principle
`VERDICT-LANGUAGE.md` opens with and that `competitive-landscape.md` §4.3
just finished citing as a genuine, rare differentiator ("refusing to say
'malicious' in its own voice at all, ever"). This is the single easiest way
to accidentally spend that differentiator.

**Aggregate abuse-leaderboard + trends → regenerate the committed dataset, via the existing pipeline.**
This is not latency-sensitive the way a reporter's own submission is, and it
is exactly the shape `data/state/` already exists for. Add:
- `schemas/community.schema.json` (bounded — `maxLength`/`maxItems`/
  `additionalProperties: false`, same discipline as every other schema in
  `schemas/`) and a `community.json: "community.schema.json"` row in
  `SCHEMA_FOR` (`pipeline/validate.py:8`).
- A small export step — most naturally a `wrangler d1 execute --remote
  --json` call added to `.github/workflows/collect-and-deploy.yml` (the
  Python pipeline has no Cloudflare access today; the workflow already runs
  Node for the Vite build, so a D1 export step slots in next to it) —
  producing candidate JSON that flows through `pipeline.validate.gate()`
  (`pipeline/validate.py:34`) exactly like every collector's output: valid →
  publish, invalid → fall back to last-known-good. Same dual-write to
  `data/state/` (committed) and `web/public/data/state/` (deployed) as
  everything else (`run_pipeline.py`'s pattern).
- Trend/velocity treatment reuses `pipeline/history.py`'s day-over-day
  snapshot diffing rather than inventing a second mechanism.

The client never talks to D1 and never knows it exists for this part — it
fetches `community.json` the same way it fetches `feed.json` today. This is
the concrete answer to "keep the lookup/analyzer 100% client-side": the
*aggregate* view stays exactly as static as everything else; only the
*live per-indicator* enrichment call (which is already not purely static —
`/api/enrich` exists precisely because it isn't) gains one more source.

## 2. Reporter UX and moderation UX

**Reporter flow.** Escalation card → "Report this IOC" button (new, next to
the existing pivot row) → if no session, redirect to `/api/auth/github/start`
and back → a small form: category (dropdown — matches the existing
`AIPDB_CATEGORY` taxonomy shape at `enrich.mjs:135` rather than inventing a
new one, so "abuse category" means the same thing everywhere in the app) +
free-text comment (bounded length) + optional evidence URL → Turnstile
(invisible, no user-facing challenge in the common case) → `POST
/api/report` → replace the button with "Queued for review" (no promise of a
timeline — the honest equivalent of the freshness-disclosure pattern
`ARCHITECTURE.md` already uses everywhere else in this app).

**Moderation flow.** `/admin` lists pending reports **grouped by indicator**,
not one row per report — the queue's unit of work is "this IP has 3 reports
from 3 people," not three separate line items. Each group shows: the
indicator + type, reporter count, the category breakdown, every comment and
evidence link inline (no click-through needed to decide), and — reusing
`/api/enrich` itself — the existing third-party consensus card for that same
indicator rendered alongside, so the owner is not deciding blind; "3 reports
say phishing AND VirusTotal already flags it 8/70" is a five-second approve.
Approve / reject are the only two actions; no edit-in-place, no partial
approval of one report in a group — the group publishes or it doesn't, kept
deliberately binary so the moderation function stays small.

## 3. Publish/serve loop and latency

Approve in `/api/moderate/decide` does two things: flips the D1 row(s) to
`approved`, and fires a `workflow_dispatch` (or `repository_dispatch`) call
against `collect-and-deploy.yml`, authenticated with a deploy key held as a
Pages secret — the same asymmetric-trigger pattern the workflow already uses
deliberately for the Framework's `brief.json` push (`collect-and-deploy.yml`
comment, `run_pipeline.py`/`OPERATIONS.md` "why the cron does not loop"
section): `GITHUB_TOKEN` pushes don't retrigger, a deploy key does.

Two different latencies follow from the two publish targets in §1c:

- **Per-indicator community context is live the instant the D1 row flips** —
  the very next `/api/enrich` call for that indicator reads the approved row
  directly. No pipeline run, no deploy, no wait.
- **The leaderboard/trends view** waits for one workflow run: pytest gate →
  D1 export → schema gate → Vite build → `wrangler pages deploy`. The
  existing twice-hourly cron already completes this whole sequence
  routinely; triggering it directly on approval instead of waiting for the
  next `:11`/`:41` tick means the leaderboard goes live in roughly the time
  one normal deploy takes — a few minutes — not up to 30.

## 4. Phased decomposition

**Phase 0 — Foundation.** D1 database + `reports` schema (indicator, type,
category, comment, evidence_url, reporter github id/login, status,
timestamps), GitHub OAuth Functions + stateless signed-cookie session helper,
`OWNER_GITHUB_LOGIN` env var. No UI change anywhere. Fully isolated, fully
testable (miniflare/local D1 for dev, matching the fixture-stub pattern
`collectors/base.py`'s `fetch` injection already uses for offline tests).

**Phase 1 — Reporting (write path).** The button, the form, `POST
/api/report`, Turnstile. Reports accumulate in D1; nothing else in the app
changes yet. Ships and is testable in isolation from moderation.

**Phase 2 — Moderation.** `/admin` route, the grouped batch-review UI,
approve/reject. This is where a report first becomes *actionable* — the
first phase with a human decision loop closed.

**Phase 3 — Publish, per-indicator (live).** The `SOCDESK_COMMUNITY` source
in `enrich.mjs`, `kind:"context"`, rendered as its own labeled block.

**Phases 0–3 together are the minimum first slice that delivers real value**:
a reporter flags an IP, the owner approves it, the next analyst who looks up
that exact IP sees "SOCDesk community: 1 report — phishing" on the next
lookup. That is a complete, demoable, valuable loop with no leaderboard
required.

**Phase 4 — Publish, aggregate (committed dataset).** `community.schema.json`,
the D1-export workflow step, the schema-gated `community.json`, a new
`/leaderboard` route or a panel added to `/desk` (`DataDeskRoute`).

**Phase 5 — Analytics polish.** Velocity/"new this week" chips reusing
`history.py`'s diff mechanism; category trend lines. Deliberately keep this
about ranking **infrastructure** (ASNs/ISPs), never ranking or naming
**reporters** publicly — there is no product reason to build a public
leaderboard of humans, and doing so would be a new and needless privacy
surface next to a feature already adding its first-ever accounts.

**Phase 6 — optional, deferred: upstream push.** SOCDesk republishes its own
moderated reports as a keyless public feed, closing the loop so other tools
could aggregate SOCDesk the way SOCDesk aggregates everyone else — a strong
portfolio narrative beat ("aggregator becomes a source"), but it reopens
exactly the public-accusation/liability class of risk `COMPLIANCE.md`
R3/R5 already fought through once for ransomware-victim naming (resolved
there by dropping victim names to group-level only). Needs its own
compliance pass before it is scoped at all — do not bundle it into this
decomposition's early phases.

## 5. Portfolio-credibility and scale check

**Does the shape read as well-architected to a sharp technical reviewer?**
Yes, conditionally — the regenerate/live-serve split in §1c is the kind of
detail that reads as considered rather than bolted-on, and reusing
`/api/enrich`'s existing source-fan-out pattern instead of inventing a
second lookup mechanism is a real point in its favor. Two places a sharp
reviewer pokes holes:

1. **"No database, no accounts" stops being literally true.**
   `README.md`/`ARCHITECTURE.md`/`competitive-landscape.md` all lean hard on
   zero-infrastructure as an identity trait, and this feature adds a real
   database and a real OAuth flow. The fix is precision, not retreat: the
   docs need to say **read path** has no database and no accounts (still
   true, unchanged, and provably so — the write subsystem is fully optional
   and the 99% of visitors who never sign in touch none of it), rather than
   letting the blanket claim stand unqualified. A reviewer who reads the
   confident zero-infra pitch and then finds D1 + OAuth without that
   qualifier will read it as walked-back, which is corrosive to exactly the
   credibility story `competitive-landscape.md` was just written to
   establish.
2. **A one-person moderation queue is not what "crowdsourced" usually
   implies**, and an "abuse leaderboard" naming real ASNs/ISPs is SOCDesk's
   *first* public accusation made in its own voice rather than aggregated
   or linked from someone else's — a new liability class, same shape as the
   ransomware-victim-naming problem `COMPLIANCE.md` R3 already resolved
   once. The fix is the same discipline applied there: count-language only
   ("N SOCDesk-reviewed reports reference this ASN"), never "malicious
   ASN"; name infrastructure, not organizations by inference; keep the
   moderation gate as the real backstop (nothing publishes without explicit
   approval) and say so plainly rather than implying community-scale review
   infrastructure that doesn't exist. Honestly scoped, this reads as
   *appropriately* small for a non-commercial portfolio project — the same
   register `COMPLIANCE.md`'s "personal showcase, not institutional
   shadow-IT" framing already uses successfully elsewhere in this repo.

**Top risks:**
1. Messaging/identity dilution of the "zero-account, zero-database" pitch —
   mitigated by strict read-path/write-path framing in the docs, not by
   avoiding the feature.
2. The leaderboard makes SOCDesk a primary source of public accusation for
   the first time — mitigated by VERDICT-LANGUAGE.md-style count-language,
   ASN/ISP-not-organization framing, and treating Phase 4's leaderboard as
   its own compliance-reviewed sub-decision, not an automatic follow-on to
   shipping the reporting pipe itself.

**One-line recommendation:** build it — the seam is genuinely clean (D1 as a
live source inside the existing enrich fan-out for per-indicator, the
existing schema-gated pipeline for aggregates) — but ship Phases 0–3 first as
the complete, demoable, minimum-value slice, hold the leaderboard (Phase 4+)
for a separate go/no-go once its count-language and ASN-naming discipline is
written down, and update the zero-infrastructure messaging to be read-path-
scoped before, not after, this ships.
