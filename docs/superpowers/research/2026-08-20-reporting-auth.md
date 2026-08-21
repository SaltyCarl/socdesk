# IOC Reporting: Auth & Trust-and-Safety Assessment

Scope: the write-only "report an IOC" feature. The analyzer/lookup path stays 100% client-side and account-free — nothing here should touch it. This document covers auth choice, reporter trust model, anti-defamation posture, and abuse-of-auth resistance for the report-submission gate only.

## TL;DR

Roll a plain **GitHub OAuth App** (Authorization Code flow), token exchange and verification done server-side in a **Cloudflare Pages Function**, session as a **stateless signed cookie** (no KV/session-store dependency). Gate only `/api/report`. Store reports in **D1** with `status = pending` until the owner approves. Add **Turnstile** on the report form. This costs nothing, has no seat/user ceiling, stores the minimum possible identity (GitHub numeric id + login, no email/password), and matches the existing habits of the analyst audience.

---

## 1. Auth choice

### Candidates compared

| Option | Free-tier ceiling | What it stores | Fit for "sign-in gates one write endpoint" |
|---|---|---|---|
| **GitHub OAuth (rolled by hand)** | None — GitHub OAuth Apps are unlimited/free; rate limit is 5,000 req/hr *per authenticated user*, which for a one-time profile fetch at login is not a real constraint at SOCDesk's volume | GitHub numeric `id` + `login` (+ avatar if wanted); no password, no email required | Very good — a few Pages Functions, no platform to adopt |
| **Cloudflare Access / Zero Trust** | **50 seats, free plan.** A seat is consumed by any authentication event and is held until removed or auto-expired (2mo–1yr configurable). Beyond 50 seats, further sign-ins are blocked until upgrade | Identity lives in Cloudflare's Zero Trust org, sourced from an IdP (GitHub or others) | Poor fit here — Access is built for gating a small, known set of trusted users into internal/self-hosted apps, not an open "anyone with a GitHub account can try to report" audience. It *can* be wired to allow "any GitHub user" via GitHub-as-IdP + an Allow-everyone policy, but every distinct authenticator burns a seat forever (until manually/auto expired), which is a scaling ceiling that will bite exactly when the portfolio traffic that justifies the feature shows up. It also requires standing up a full Zero Trust org/team-domain, which is heavier operational surface than a single write endpoint needs, and its hosted login page reads as an internal-admin surface, not a public "sign in to report abuse" affordance |
| **Managed provider (Clerk)** | 50,000 MRU free (raised Feb 2026) — generous | Clerk becomes the custodian of reporter PII (email, profile) in a third-party system | Overkill — full identity platform (hosted UI, SDK, user database) for gating one button. Adds a vendor and a PII custodian SOCDesk explicitly doesn't want |
| **Managed provider (Auth0)** | 25,000 MAU free (raised from 7,500) | Same category as Clerk — third-party PII custodian | Same objection as Clerk, plus Auth0's free tier has been cut before (Okta-era history) and MFA/RBAC/support sit behind paid tiers |
| **Email magic link** | Needs a sender. Cloudflare's own Email Service (launched Apr 2026) only sends free to *verified* destinations on the Workers Free plan — sending to arbitrary strangers needs the Workers Paid plan. Resend's free tier (3,000/mo, 100/day) covers volume but is a third vendor | Raw email addresses (PII) plus token/session bookkeeping | Weakest option here: no real identity/accountability (throwaway addresses are trivial, unlike a GitHub account with history), and it either requires a paid Cloudflare tier or a bolted-on third-party emailer |

### Recommended flow (concrete)

1. Report form shows "Sign in with GitHub to report" — only touches the write path, analyzer stays open.
2. Browser redirects to `https://github.com/login/oauth/authorize?client_id=…&redirect_uri=/api/auth/callback&state=<random>`. `state` is also set as a short-lived HttpOnly cookie for CSRF binding. **No scope requested** — an empty-scope token is enough to read the public profile (`id`, `login`, `avatar_url`) from `GET /user`; deliberately not requesting `user:email` keeps the PII footprint at zero.
3. GitHub redirects back to a Pages Function at `/api/auth/callback?code=…&state=…`.
4. The Function verifies `state` against the cookie, then does the code→token exchange server-side: `POST https://github.com/login/oauth/access_token` with `client_id` + `client_secret` (stored as a Cloudflare secret via `wrangler secret put`, never shipped to the browser).
5. The Function calls `GET https://api.github.com/user` with the short-lived access token, reads `id`/`login`, and **discards the GitHub token immediately** — no need to hold ongoing GitHub API access.
6. The Function mints its own session: an HMAC-signed, short-lived (7–30 day) token containing `github_id`, `login`, `iat`/`exp`, set as an `HttpOnly; Secure; SameSite=Lax` cookie. This is **stateless** — verification is just a signature+expiry check in the `/api/report` Function, no KV/D1 lookup needed per request, so it doesn't compete with Workers KV's 1,000-writes/day free-tier ceiling (the one Cloudflare number that could realistically be hit if sessions were instead written to KV per login).
7. `/api/report` requires a valid session cookie, checks the reporter isn't rate-limited or blocked (D1 lookup keyed on `github_id`), and inserts the report row: `ioc, category, comment/evidence, reporter_github_id, reporter_login, created_at, status='pending'`.

### Why this beats the alternatives here

No seat cap (unlike Access), no third-party PII custodian (unlike Clerk/Auth0), no paid tier or extra vendor to send mail (unlike magic-link), and it's a flow the exact target audience — SOC analysts, security-adjacent GitHub users — already has muscle memory for. The cost is honest: it's a few hours of hand-rolled OAuth code instead of a policy toggle, and *you* own CSRF-state handling and token exchange. That's a reasonable one-time build cost against Access's structural 50-seat ceiling or Clerk/Auth0's ongoing vendor dependency.

**D1** (moderation queue storage) comfortably absorbs any realistic SOCDesk volume on the free tier: 5M rows read/day, 100K rows written/day, 5GB storage.

---

## 2. Trust & anti-abuse model (owner moderates every report)

Because **nothing publishes without the owner reviewing it**, the account's job in v1 is narrow and should stay narrow (YAGNI):

- **Accountability / attribution.** Every report is durably tied to a `github_id`. The moderation view shows "@handle, GitHub account since <created_at>, N submitted / N approved / N rejected" — turning an anonymous block of text into a person with a visible track record. This is the actual lever at v1 scale, more than any automated check.
- **Per-identity rate limiting.** Cap submissions per `github_id` per day (e.g., 5/day) with a simple `COUNT(*) WHERE reporter_github_id=? AND created_at > now-24h` in the same Pages Function — no separate service, and it protects the *moderator's* time independent of whether moderation review keeps pace.
- **Banning.** A `blocked` boolean on the reporter row in D1, checked before insert. Instant, no session revocation machinery needed since sessions are stateless and short-lived by design (a ban takes effect on the reporter's next report attempt without needing to invalidate an existing cookie mid-flight — acceptable given the short session lifetime).
- **Reporter reputation — kept deliberately light.** Don't build a separate reputation table/service for v1. `submitted / approved / rejected` counts are just aggregates over the existing `reports` table, computed on read. That's enough scaffolding that "auto-approve reporters with N approved and 0 rejected" is a single `WHERE` clause to add later, not a redesign — the lightweight version *is* the extensible version here.
- **What the account does *not* buy:** it doesn't verify the reporter is who they claim, and it doesn't verify the report is accurate. It buys friction plus a paper trail. Given 100% human pre-publish moderation, that's the right amount of investment — anything heavier (KYC, phone verification, paid identity checks) is solving a problem the moderation gate already solves, and would undercut the "no account friction beyond what's needed" posture.

---

## 3. Anti-poisoning + anti-defamation posture (general practice, not legal advice)

**The exposure:** publishing "IP X is malicious" is a factual assertion about something that may map to a real business, a residential ISP customer, or a dynamic/reassigned address. If false and damaging, that has the shape of a defamation claim; pushing it further upstream to AbuseIPDB compounds the reach.

**Why moderation-before-publish is the load-bearing mitigant:** nothing goes live or upstream without a human decision, so it's SOCDesk (specifically, the owner, after review) asserting anything — not an anonymous crowd. This converts "wiki-style abuse democracy" risk into something closer to an editorial process.

**Concrete competitive comparison, worth citing:** AbuseIPDB — the platform this feature would eventually feed — publishes community reports live/reactively with no human-in-the-loop pre-publish review, and its dispute mechanism is widely described by users as a thin contact form with a hard character limit and unreliable response (per user complaints on Trustpilot and its own community). SOCDesk's moderate-before-publish design is already stricter than the incumbent it would report into. That's a legitimate, honest selling point, not just a defensive posture.

**Minimum responsible posture for a public tool:**

- **Framing over verdicts.** Publish as "reported activity" with category + evidence + timestamp + reporter status ("community-reported, moderator-verified"), never a bare "malicious" label. This is both anti-poisoning (raises the cost of a frivolous report — you can't just click a button, you have to substantiate it) and anti-defamation (an observation with evidence reads very differently, legally and socially, than an unqualified accusation).
- **Evidence requirement, enforced at submission.** Comment/evidence field is mandatory and shown in full to the moderator before approve — never allow a bare vote-only report.
- **Attribution, handled in two layers.** Keep the reporter identity attached internally, always — needed for accountability and if a real dispute ever escalates. For the *public*-facing card, default to "community-reported, moderator-verified" rather than the raw handle, unless the reporter opts in to public credit. This keeps the accountability benefit without exposing individual reporters to retaliation or their own defamation exposure for a report SOCDesk chose to publish.
- **A visible dispute/removal path**, no login required, on every published IOC page — routed to the owner, with a stated (even loose) response-time expectation. This is the concrete evidence of good-faith process that matters most if a dispute ever escalates, and mirrors standard takedown-request norms.
- **A short, plain-language notice** on the report form and every published report: reports are user-submitted, reviewed by a human before publication, represent observed activity rather than a legal verdict, accuracy isn't warranted, and disputes/removal requests go to a stated contact. This is standard-of-care for a small non-commercial community tool — not a substitute for real legal review if volume or stakes grow materially.

---

## 4. Abuse of the auth itself

GitHub accounts are cheap to create (email + GitHub's own signup captcha), so a motivated actor can mint several to try to flood the queue or make a specific IOC look corroborated by multiple "independent" reporters. Because **moderation gates everything**, the ceiling on damage from this is "wastes the owner's review time," not "gets a fake report live" — so the right response is cheap *triage* signals, not trying to make the auth itself unbeatable:

- **Account age.** GitHub's `GET /user` response includes `created_at`. Flag or soft-throttle accounts created in the last 24–48 hours in the moderation view — a one-line check, no extra service, and it's the single highest-signal-per-line-of-code control available.
- **Per-identity *and* per-IP caps**, since one attacker can multi-account from one machine. Both are cheap `COUNT` queries against D1 already needed for rate limiting.
- **Turnstile on the report form itself** (not the OAuth login — GitHub already runs its own bot defenses at account-creation time). Cloudflare Turnstile's free tier is effectively unlimited at this volume (up to 1M solves/month, unlimited sitekeys/hostnames, no cost) and is a natural fit since SOCDesk is already Cloudflare-hosted: add the widget to the `/report` POST, verify server-side via the `siteverify` API in the same Pages Function. This blocks scripted/automated submission floods without adding friction beyond the GitHub sign-in that's already there.
- **Reframe the goal:** invest in signals that help the owner triage a queue quickly (new-account flag, submission velocity, prior rejection rate), not in trying to make the account layer itself impossible to abuse. The moderation gate already absorbs the actual risk (a fake report going live); the auth layer's job is just to keep the queue reviewable.

---

## 5. Top risks + recommendation

**Risk 1 — moderator bottleneck / process erosion.** The entire trust model rests on the owner actually reviewing batches on schedule. If reviews lapse, the safety property (nothing publishes without a human) holds, but reporters get silence — no visible status on their own submissions erodes trust in the feature. Mitigate cheaply: give reporters a personal "your reports: pending / approved / rejected" view so a slow queue reads as "in review," not "ignored."

**Risk 2 — the anti-defamation posture weakening under its own success.** The evidence requirement, framing-as-observation, and dispute path are cheap to hold to at low volume. The exact moment they're most likely to get shortcut is when volume grows and a "trusted reporter auto-approve" tier gets added for convenience — that's precisely when the "a human verified this" story needs to stay true, or the whole posture erodes with the first shortcut. Any future auto-approve tier should keep the evidence requirement and dispute path non-negotiable, even if the human-review step becomes spot-check rather than 100%.

**One-line recommendation:** hand-roll GitHub OAuth (Authorization Code flow, verified server-side in a Cloudflare Pages Function, stateless signed-cookie session) gating only `/api/report`, paired with Turnstile on the form and D1-backed per-identity rate limits/account-age checks — it is genuinely free with no seat ceiling, holds no third-party-custodied PII, fits the analyst audience's existing habits, and sits entirely inside Cloudflare's free tiers at SOCDesk's realistic volume.

---

## Sources consulted

- [Cloudflare Zero Trust free plan limits (2026)](https://zerometric.net/research/cloudflare-zero-trust-free-plan-limits-2026/)
- [Cloudflare Zero Trust pricing breakdown](https://controld.com/blog/cloudflare-zero-trust-pricing/)
- [Cloudflare Turnstile pricing (2026)](https://prosopo.io/tools/cloudflare-turnstile-pricing/)
- [Cloudflare Turnstile free pricing explainer](https://blog.rcaptcha.app/articles/cloudflare-turnstile-free-pricing)
- [Clerk free plan change — 50k MRU](https://saasprices.net/blog/clerk-free-plan-changes)
- [Clerk pricing](https://clerk.com/pricing)
- [Auth0 free tier 2026 — 25K MAU](https://freetier.co/directory/products/auth0)
- [Cloudflare GitHub OAuth + Pages Functions tutorial (PR)](https://github.com/cloudflare/cloudflare-docs/pull/4108)
- [GitHub OAuth for a static site using Cloudflare Workers (Simon Willison)](https://til.simonwillison.net/cloudflare/workers-github-oauth)
- [GitHub rate limits for OAuth apps](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)
- [Cloudflare Workers KV free tier limits (2026)](https://basekv.com/articles/cloudflare-workers-kv-limits-2026)
- [Cloudflare D1 pricing](https://developers.cloudflare.com/d1/platform/pricing/)
- [Cloudflare Access self-hosted app publishing docs](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/self-hosted-public-app/)
- [Cloudflare Email Service pricing (launched Apr 2026)](https://developers.cloudflare.com/email-service/platform/pricing/)
- [Resend pricing 2026](https://nuntly.com/resend-pricing)
- [AbuseIPDB FAQ](https://www.abuseipdb.com/faq.html)
- [AbuseIPDB Trustpilot reviews (dispute-process complaints)](https://www.trustpilot.com/review/abuseipdb.com)
