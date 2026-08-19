# SOCDesk

The analyst's first stop for any indicator. Paste an IP, domain, hash, URL,
CVE or email and get one screen back: a live multi-source reputation read on
the indicator (or, for a CVE, a verdict grounded in public vulnerability data),
an escalation card you can drop into a ticket, and a row of one-click pivots to
every public reputation service worth checking. Alongside it, a threat feed
ranked by what deserves attention first rather than by what happened most
recently.

A React app (Vite + Tailwind + Motion) under a strict Content-Security-Policy.
Scheduled collectors publish the feed and CVE data as JSON; a single
same-origin serverless function (`/api/enrich`) queries public reputation
services on demand for the indicator you paste. No database, no accounts, no
bill.

**Live:** https://socdesk.io — a lookup "cockpit": start typing an indicator and
the marketing intro folds away, the omnibox pins, and the escalation card docks
beside a 3D globe.

<!-- SCREENSHOT: 1440px-wide capture of the console with a KEV CVE looked up —
     verdict gauge, escalation docket, and pivot row visible. Save to
     docs/img/console-1440.png and replace this comment with the <img>. -->

*Personal project by Carlos Sanchez ([SaltyCarl](https://github.com/SaltyCarl),
[Sanchez on Security](https://sanchezonsecurity.com)) — not affiliated with or
endorsed by any employer, and not an official tool of any organization.*

---

## Who it is for

Working SOC and IR analysts doing open-source triage. The tool assumes you
already know what a CVE and an EPSS score are, and that your problem is not
*understanding* the data — it is that the data lives in six browser tabs and
the write-up at the end is manual.

It is also a portfolio piece: a real pipeline, a real schema gate, and a real
failure-isolation story, all of it readable in this repo.

## What it actually does today

The live app is the **`web/`** React app with **`shared/`** components and the
**`lib/enrich.mjs`** / `/api/enrich` function; it supersedes the legacy vanilla
`site/` app. The `site/js` paths below are the legacy locations — several
capabilities now live in `web/`, `shared/`, and `lib/`.

| Capability | Where it lives |
|---|---|
| Indicator lookup with type auto-detection (IPv4, **IPv6**, domain, URL, MD5/SHA-1/SHA-256, CVE, email) | `shared/indicators.ts`, `lib/enrich.mjs` |
| Live multi-source reputation — the escalation card: N-of-M consensus tally, honest per-source **class labels** + recency, mitigating signals as **chips** (IPv4, IPv6, domain, URL, hash) | `lib/enrich.mjs`, `shared/verdict-cards/` |
| **IPv6** enrichment — AbuseIPDB + VirusTotal + ipinfo (GreyNoise is IPv4-only); private/reserved v6 rejected | `lib/enrich.mjs` |
| Domain **registration age** via keyless RDAP — Registered / Registrar / Expires | `lib/enrich.mjs` |
| **URL safe-view** — urlscan existing-scan screenshot preview (click to expand) + a **Browserling** disposable-browser pivot; existing scans only, never submits | `shared/verdict-cards/heroes.tsx` |
| **Compare-IP / impossible-travel** — great-circle miles + implied mph + an honest plausibility read + a map arc, from real coordinates only | `shared/card/travel.ts`, `shared/verdict-cards/CompareIp.tsx` |
| Copy-out — clean factual **"Copy card"** (PNG) + **"Copy text"**, no branding, no disclaimer prose | `shared/verdict-cards/copy.ts`, `shared/card/drawVerdict.ts` |
| Browser extension — the toolbar popup renders the **same full escalation card** (manifest v0.2.0), sharing detection + the enrich pipeline | `extension/` |
| Authoritative CVE verdict — CISA KEV × NVD CVSS × FIRST EPSS | `site/js/verdict.js` |
| Honest "not in corpus" for a CVE outside the corpus, plus type-aware pivots | `site/js/verdict.js` |
| Escalation write-up (markdown / plain text / `.md` download) | `site/js/verdict.js` |
| Bulk lookup — paste up to 200 indicators, export CSV / JSON / defanged TXT | `site/js/verdict.js`, `site/js/app.js` |
| In-context lookup bookmarklet — select an indicator on any page, get the verdict, no install | `site/js/bookmarklet.js` |
| Threat feed scored 0–100 with an explainable `why` per item | `pipeline/relevance.py`, `site/js/views.js` |
| Vulnerability triage table with watchlist, KEV filter, sortable columns | `site/js/views.js` |
| Trends — biggest EPSS rises and new KEV entries, from committed daily snapshots | `pipeline/history.py`, `site/js/views.js` |
| ATT&CK actor and malware profiles, resolvable by name or alias | `collectors/attack.py`, `site/js/views.js` |
| Collection health per source, with last-known-good retention | `pipeline/validate.py`, `site/js/views.js` |
| Analyst toolbelt — defang/refang, IOC extract, UTF-16LE Base64 decode, PowerShell parser, LOLBin lookup | `site/js/toolbelt/` |
| Shift handoff digest from items you flagged notable | `site/js/app.js` |
| Offline capability via service worker (data network-first, never stale-as-fresh) | `site/sw.js` |

For how to *use* these as an analyst, read
[docs/ANALYST-GUIDE.md](docs/ANALYST-GUIDE.md).

## Aggregator, not mirror

SOCDesk publishes only data it may clearly redistribute — CISA KEV, NVD, FIRST
EPSS, MITRE ATT&CK, and headline-plus-link RSS. Reputation corpora
(VirusTotal, AbuseIPDB, GreyNoise, urlscan, abuse.ch, Shodan) are never
mirrored or stored locally: they are reached through links you click, or queried
on demand — for the single indicator you paste — by SOCDesk's own same-origin
enrichment function, never fetched in the background and never persisted. That
is a licensing decision before it is an architectural one; the reasoning is in
[COMPLIANCE.md](COMPLIANCE.md) and the per-source consequences are in
[docs/DATA-SOURCES.md](docs/DATA-SOURCES.md).

> **Privacy.** There are no accounts and no analytics. Anything you mark or save
> stays in your browser's localStorage and is never transmitted — the
> Content-Security-Policy sets `connect-src 'self'`, so the page itself cannot
> call a third party. Looking up an indicator does send that one indicator to
> SOCDesk's own same-origin enrichment function, which queries the public
> reputation services on your behalf and stores nothing.
>
> **Disclosure.** Enriching or clicking a pivot for an indicator discloses it —
> to SOCDesk's enrichment function and, on a click, to the third-party service
> you clicked; urlscan publishes public scans. Use public indicators only.

## Three tiers, each independently degradable

Nothing upstream can take the page down; it can only make the page emptier and
say so.

1. **Collection** — GitHub Actions cron runs the Python collectors. Each one is
   fault-isolated: an exception is caught, recorded as a health entry, and the
   others carry on (`collectors/base.py`).
2. **Pipeline** — normalises, joins, scores, and validates every payload
   against a JSON Schema. A payload that fails the gate is replaced by the last
   known good copy and the failure is published as a warning, not a blank page
   (`pipeline/validate.py`).
3. **Site** — vanilla ES modules, no framework, no build step. Every payload is
   fetched independently, so a missing file degrades that one panel. The
   animation layer is a CDN script that the page works perfectly without.

The full mechanism, including the state/publish split and the schema gate, is
in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quickstart

Requires Python 3.12 and (for the browser tests) Node 20+.

```
git clone https://github.com/SaltyCarl/socdesk.git
cd socdesk

python -m venv .venv
.venv\Scripts\pip install -r requirements.txt

.venv\Scripts\python -m pytest tests/ -q      # fixture-backed, no network
.venv\Scripts\python run_pipeline.py          # live fetch -> site/data/
```

`run_pipeline.py` is the only thing that touches the network. It writes the
published payloads to `site/data/` (gitignored) and the rolling last-known-good
copies to `data/state/` (committed). It prints
`published [...]; problems=[]` and always exits 0 — upstream trouble is health
data, never a build failure.

Then serve the site and run the browser suite:

```
cd site-tests
npm install
npx playwright test                            # boots its own server on :8123
```

To just look at it, serve `site/` over HTTP — `file://` will not work, because
ES modules and the service worker both require an origin:

```
.venv\Scripts\python -m http.server 8080 -d site
```

No API keys are needed anywhere. Every collector uses a keyless public
endpoint.

## Deployment

Push to `main`. The `collect-and-deploy` workflow runs the tests, runs the
collectors, commits refreshed state snapshots, builds the `web/` app (Vite), and
direct-uploads `web/dist` to Cloudflare Pages. It also runs on cron at `:11` and
`:41` past every hour.

Because the cron commits refreshed snapshots constantly, `origin/main` diverges
from your local `HEAD` between edits — a plain `git push` is non-fast-forward.
**Always `git pull --rebase origin main` before pushing.**

Deployment is a `wrangler pages deploy` direct upload rather than Cloudflare's
Git integration, for two reasons: free-plan Git builds are capped at 500 a
month and this workflow deploys about 1,440, and direct upload means Cloudflare
never needs read access to the repository. Two secrets are required —
`CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`.

Serving from Cloudflare also means `site/_headers` is applied for real. On a
host that cannot send custom headers the policy has to degrade to a `<meta>`
tag, where `frame-ancestors` and the other header-only directives are ignored.
The site ships both copies and `csp.spec.js` fails if they drift apart.

The runbook — how to read `health.json`, what to do when a collector goes red,
how to roll back, and the service-worker version bump that has masked shipped
changes more than once — is [docs/OPERATIONS.md](docs/OPERATIONS.md).

## Repository map

```
collectors/     one module per upstream source; each exposes SOURCE + collect()
pipeline/       join, score, relate, snapshot, validate, publish
schemas/        JSON Schema per published payload — the data contract
run_pipeline.py the entry point that wires collectors to pipeline to output
data/state/     committed last-known-good payloads + daily history snapshots
data/entities/  actor / malware / vendor dictionaries for entity extraction
data/sources.json  the source registry rendered on the site
web/            the deployed React app (Vite + Tailwind + Motion); web/dist is the build
shared/         cross-surface UI + logic shared by web/ and extension/ (escalation card, verdict, compare-IP)
lib/            enrich.mjs — the source fan-out behind the /api/enrich function
functions/      Cloudflare Pages Functions (/api/enrich)
extension/      MV3 browser extension (manifest v0.2.0) — same escalation card as the web app
site/           the legacy vanilla site, superseded by web/ (kept for history)
site-tests/     Playwright suite driven off the real published payloads
tests/          pytest suite, fixture-backed, offline
design/         brand book, approved mockups, visual reference
.github/workflows/collect-and-deploy.yml
```

## Documentation

| Document | What it holds |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | The system end to end: tiers, data contracts, schema gate, failure isolation, what static costs |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Runbook — local runs, cron, reading health, collector failures, deploy, rollback, service-worker versioning |
| [docs/DATA-SOURCES.md](docs/DATA-SOURCES.md) | Every source: what it gives, its terms, why it is redistributed or link-only, cadence, governing finding |
| [docs/ANALYST-GUIDE.md](docs/ANALYST-GUIDE.md) | How to use the tool, what a verdict does and does not mean, and the tool's limits |
| [COMPLIANCE.md](COMPLIANCE.md) | Licensing and legal findings, risk register, launch gates. Read before adding any data source |
| [docs/RELATIONSHIPS.md](docs/RELATIONSHIPS.md) | The entity relationship index and the reasoning behind not drawing a node-link graph |
| [docs/INFRASTRUCTURE-OPTIONS.md](docs/INFRASTRUCTURE-OPTIONS.md) | What each step up the infrastructure ladder would unlock, cost, and take away |
| [design-system.md](design-system.md) | Chart Room v4 — the binding visual system |
| [design/brand.md](design/brand.md) | Brand book: positioning, voice, marks, applications |
| [BACKLOG.md](BACKLOG.md) | Queued collectors, reviewed-and-rejected sources, future phases |
| [docs/HANDOFF.md](docs/HANDOFF.md) | Working session state: what just landed, what is next, environment gotchas |

## Attribution and terms

All intelligence is aggregated from public sources; every item links back to
its origin, and the Source Registry on the site documents the full set.

- ATT&CK® content: © 2026 The MITRE Corporation. This work is reproduced and
  distributed with the permission of The MITRE Corporation. ATT&CK is a
  registered trademark of The MITRE Corporation.
- Exploit Prediction Scoring System (EPSS) scores provided by FIRST
  (https://www.first.org/epss/). No endorsement by FIRST is implied.
- CISA KEV data is U.S. Government work in the public domain. NVD data is a
  work of the U.S. Government; embedded CVE® records are provided by MITRE.
- Ransomware group activity via Ransomware.live, published at group level only.
- Botnet C2 / blocklist IPs via abuse.ch Feodo Tracker and ThreatFox,
  republished as blockable indicators with abuse.ch attribution (these are
  indicators published expressly to be blocked, unlike the withheld reputation
  corpora). Geolocation is by IPinfo (https://ipinfo.io) at city level, cached
  per IP, with a public-domain country-centroid fallback. It is approximate and
  reflects hosting/registrar, not operator location.
- Headlines and summaries are excerpted with attribution and link to the
  original publishers; full text is never reproduced.

This is an informational aggregation tool. No warranty is made about the
accuracy or completeness of third-party data — verify independently before
acting on any indicator. Code is MIT licensed ([LICENSE](LICENSE)); that
licence covers the code, not the aggregated data.
