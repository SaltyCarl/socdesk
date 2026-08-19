# SOCDESK — What More Capable Infrastructure Would Unlock

Written 2026-08-07. An honest map of what each step up the infrastructure
ladder buys, what it costs, and what it takes away. Read §0 first — several
things that *sound* like they need a backend do not.

## 0. Things you can have WITHOUT leaving static

Do these before paying any infrastructure cost. They are the cheapest wins on
this page.

- **Historical trend data.** Commit a daily rolled-up snapshot
  (`data/history/2026-08-07.json`, a few KB). Then "this CVE's EPSS went 0.31 →
  0.87 in six days" is a static file diff. Genuinely decision-useful, zero
  infra. Git already gives you the storage and the audit trail.
- **Trending / velocity.** Same mechanism — deltas between snapshots surface
  "what is accelerating," which is more interesting than "what is big."
- **A full CVE corpus.** Sharded JSON + client-side index (e.g. one file per
  year) handles hundreds of thousands of rows fine at 30-min freshness.
- **Client-side fuzzy search** over everything published (MiniSearch/Fuse).
- **A PWA / offline mode.** Service worker → SOCDESK works on a plane or during
  an outage, off the last cached pull.
- **Scheduled digest generation.** The Framework already commits `brief.json`;
  the same pattern produces any recurring artifact.

## 1. Tier 2 — Stateless Worker (Phase C½) — CHOSEN AND SHIPPED

**Infra:** shipped not as a standalone Worker + KV but as a **same-origin
Cloudflare Pages Function** (`functions/api/enrich.js` + `lib/enrich.mjs`), using
Cloudflare's edge cache — no KV binding. Still $0. Still no user data at rest.

Delivered: live reputation enrichment, urlscan screenshot previews, a shared
indicator-level cache, API keys held safely server-side.

Costs: per-source terms review; the site is no longer *provably* incapable of
transmitting. It stays same-origin — no new CSP origin, `connect-src 'self'`
unchanged — so an analyst lookup sends the indicator to the site's own
`/api/enrich`, and that Function fans out to the reputation sources server-side.
Nothing is stored.

**Verdict: done — chosen and shipped.** Best value-per-complexity on the whole
list.

## 2. Tier 3 — Stateful serverless (Workers + D1/KV + Cloudflare Access)

**Infra:** still Cloudflare, still ~$0 (Access is free to 50 users). Adds a
real database and authenticated users.

Unlocks:
- **Shared team state** — one analyst's "reviewed" and "notable" marks visible
  to the next shift; a team watchlist instead of per-browser.
- **Saved searches and standing watches** with a real notification path
  (email/webhook when a watchlist vendor lands in KEV).
- **Team-level metrics** — what got looked up, what got escalated. Useful for
  demonstrating value; also the most sensitive thing on this page.

Costs — and these are the real ones: **the moment investigation metadata sits
on a server, COMPLIANCE.md's parked item activates.** The compliance review was
explicit that shared team state must be a *separate, authenticated deployment*,
never bolted onto the public site. It also ends the "no accounts, nothing
stored" story that is currently a genuine differentiator.

**Verdict: only if the team actually asks for it, and only as a second
auth-gated deployment.** Do not merge it into the public site.

## 3. Tier 4 — Real compute (Framework Desktop, or a VPS)

**Infra:** the Framework (128GB, already running LiteLLM/Ollama, reachable via
Tailscale or Cloudflare Tunnel + Access). Effectively $0 since the hardware
exists; a Hetzner/Oracle box is the alternative.

This is where the genuinely differentiated features live:

### 3a. Local-LLM analysis — the standout
The hardware and the model gateway already exist. With compute in the loop:
- **"Explain this"** on any PowerShell blob, command line, or obfuscated
  script — plain-English breakdown for junior analysts and for client-facing
  writeups.
- **Natural-language search**: "ransomware hitting manufacturing in the last
  week" → a filtered feed, no query syntax.
- **Actor-to-watchlist reasoning**: "which of my watchlist vendors show up in
  this actor's tooling?"
- **Better daily briefs** — the current Phase C brief is a summary; with
  retrieval over the full corpus it becomes analysis.
This is the single biggest capability jump available, and it costs nothing new
because the Framework is already doing local inference for other projects.

### 3b. Static file analysis (NOT detonation)
Drag a sample in → strings, PE/ELF headers, entropy, embedded URLs, YARA
matches. Real triage value, and it stays clear of the delisting/liability
problems that come with *executing* anything. Requires an upload path, so it
requires auth and a retention policy.

### 3c. Sandbox orchestration
Submit to ANY.RUN/Tria.ge APIs and poll for results — needs long-running jobs,
which serverless makes awkward. Note this still routes to real sandboxes; SOCDESK
never detonates. See MalwareViz for actual detonation.

### 3d. Semantic search over the report corpus
Embeddings + a vector store (Qdrant is already in the agentic-platform stack)
over years of vendor research. "Find reports describing this TTP chain."

### 3e. The honeypot sensor
Original telemetry nobody else has (BACKLOG.md) — **gated on COMPLIANCE R2**.

Costs: uptime is now yours. Backups, patching, and a machine at home that the
team depends on. Tailscale doesn't reach colleagues, so team access means
Cloudflare Tunnel + Access — which is fine, but it's another moving part. And
when the Framework is off, features vanish.

**Verdict: 3a is worth it and nearly free. 3b/3d are strong if the tool gets
real daily use. 3c belongs in MalwareViz. 3e is gated.**

## 4. What you lose by leaving static — state it plainly

1. **The privacy guarantee becomes a promise instead of a property.** Right now
   "nothing you paste leaves your browser" is enforced by the absence of a
   backend. With one, it becomes a policy you're asserting.
2. **The zero-infrastructure story.** "A real CTI console with no servers, no
   database, no accounts, and no bill" is currently one of the most impressive
   things about the project.
3. **Uptime for free.** Static on a CDN is effectively unbreakable. Every tier
   above adds something that can be down at 2am.
4. **Compliance simplicity.** Every tier above re-opens questions the current
   architecture answers by construction.

## 5. Recommended path

1. **Ship static.** (Done pending secrets.)
2. **Tier 2 enrichment** — shipped as the same-origin `/api/enrich` Pages
   Function. Biggest gain, smallest cost.
3. **Static-tier wins from §0** — history/trends and offline mode, both cheap.
4. **Tier 4a local-LLM analysis on the Framework** — the real differentiator,
   using hardware that already exists. Treat it as an *optional enhancement
   layer*: when the Framework is reachable the site gets smarter; when it
   isn't, the site is exactly what it is today.
5. Everything else on demand, and only when something is actually painful.

The discipline that matters: **each tier should be additive and independently
degradable**, exactly like the collector pipeline. No feature may make the
static core stop working.
