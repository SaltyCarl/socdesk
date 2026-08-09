# SOCDesk — Operations Runbook

Everything you need to run, deploy, diagnose and roll back this system. For
*why* it is shaped this way, read [ARCHITECTURE.md](ARCHITECTURE.md) first.

## Environment

| | |
|---|---|
| Python | 3.12 — there is no `python` on PATH on the development machine; use `.venv\Scripts\python.exe` |
| Node | 20+, only for the Playwright suite |
| Dependencies | `requirements.txt` — httpx, feedparser, jsonschema, pytest |
| Secrets | **None.** Every collector uses a keyless public endpoint |

```
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
```

## Running the pipeline locally

```
.venv\Scripts\python -m pytest tests/ -q      # first: offline, fixture-backed
.venv\Scripts\python run_pipeline.py          # then: live network fetch
```

A clean run prints:

```
published ['actors.json', 'cves.json', 'feed.json', 'health.json',
           'malware.json', 'relations.json', 'sources.json',
           'trends.json']; problems=[]
```

Read that line carefully every time:

- **`problems=[]`** is the goal. A non-empty list means one or more payloads
  failed schema validation and were replaced by the last known good copy (or
  skipped, if there was no prior). The same list is written into
  `health.json` as `pipeline_warnings` and shows as a warning strip on the site.
- **A missing filename** in `published` means that payload failed validation
  *and* had no prior snapshot. That panel will render its empty state.

The run writes to two places (see the state/publish split in
[ARCHITECTURE.md](ARCHITECTURE.md#the-state--publish-split)):

- `site/data/*.json` — the deployable artifact, gitignored.
- `data/state/*.json` plus `data/state/history/YYYY-MM-DD.json` — committed
  last-known-good, and the input to the *next* run's fallback.

`run_pipeline.py` always exits 0. Upstream failures are health data, not build
failures — a flaky third-party API must never block a deploy that would ship
perfectly good cached data.

Then look at it. `file://` will not work — ES modules and the service worker
both require a real origin:

```
.venv\Scripts\python -m http.server 8080 -d site
```

## Test suites

| Suite | Command | Scope |
|---|---|---|
| pytest | `.venv\Scripts\python -m pytest tests/ -q` | Collectors, pipeline, schema gate. Fully offline — `fetch` is a fixture stub |
| Playwright | `cd site-tests && npx playwright test` | The real site against the real `site/data/` payloads |

Measured 2026-08-09: **58 pytest** tests and **49 Playwright** tests across 8
spec files.

Two things to know about the browser suite:

- It boots its own static server on `:8123` (`site-tests/serve.js`) and reuses
  an existing one if the port is taken. The Content-Type map in that file is
  load-bearing: Chromium refuses to evaluate an ES module served with the wrong
  MIME type, and the whole app dies silently.
- Expected values are computed from the published payloads at run time
  (`site-tests/lib/real.js`), never hardcoded — the pipeline refreshes twice an
  hour and a frozen count would rot within the day. **Consequence: run the
  pipeline before the browser suite**, or it asserts against whatever
  `site/data/` currently holds.

**The suite is currently flaky under parallel workers.** On 2026-08-09 a full
run reported 47 passed / 2 failed (`csp.spec.js:29`, `degrade.spec.js:13`);
both passed in isolation, and a second full run passed 49/49.
`site-tests/playwright.config.js` sets `retries: 0`, so a flake reads as a
failure. Re-run the two specs alone before believing a red result — and treat
the flakiness itself as a bug to fix, not a fact of life.

## The scheduled run

`.github/workflows/collect-and-deploy.yml` is the only automation.

**Triggers**

- `schedule: "11,41 * * * *"` — twice hourly, offset from the top of the hour
  to avoid the global Actions load spike. GitHub cron is best-effort and can
  run late under load; the site never claims otherwise, and the masthead's
  next-pull countdown is derived from the same `:11`/`:41` constants in
  `site/js/data.js:74`. **If you change the cron, change that function too.**
- `workflow_dispatch` — manual run, from the Actions tab.
- `push` to `main` limited to `paths: ["data/brief.json"]` — the Tier 2 brief
  writer redeploys the site when it publishes a brief.

**Steps, in order:** checkout → set up Python 3.12 with pip cache → install
requirements → `pytest tests/ -q` → `run_pipeline.py` → commit `data/state` →
configure Pages → upload `site/` as the Pages artifact → deploy.

Note the ordering consequence: **pytest gates the scheduled run.** A broken
unit test stops collection and deployment entirely, so the site freezes on the
last successful deploy rather than shipping bad data. That is the intended
behaviour.

**Why the cron does not loop.** The state commit uses `GITHUB_TOKEN`, and
pushes made with it cannot retrigger workflows. The brief writer uses a deploy
key, and those pushes *do* retrigger. The asymmetry is deliberate and is
commented in the workflow file.

`concurrency: collect-and-deploy` with `cancel-in-progress: false` means a
long run delays the next one rather than being killed mid-commit.

## Reading `health.json`

The payload is one row per source plus an optional `pipeline_warnings` array.
The site renders it under the **Health** view (`site/js/views.js:463`); the raw
file is at `site/data/health.json` in a deploy and `data/state/health.json` in
the repo.

```json
{"source": "kev", "ok": true, "error": "", "items": 1689,
 "last_success_at": "2026-08-09T03:41:46Z"}
```

| Field | Meaning |
|---|---|
| `source` | Collector slug — `kev`, `nvd`, `ransomwarelive`, `rss`, `attack`, plus `epss` from the enrichment step |
| `ok` | The collector returned without raising |
| `error` | Truncated exception text, or partial-failure detail |
| `items` | Feed items plus every list in `extra` — a rough volume signal, not a row count |
| `last_success_at` | Timestamp of this run if it succeeded; otherwise **carried forward** from prior state (`pipeline/publish.py:57`) so you can see how long a source has been down |
| `pipeline_warnings` | Present only when the schema gate rejected something |

Three things this file will not tell you, and you should know about:

1. **`attack` is usually absent.** It is a cached collector and only runs when
   state is older than 7 days, so on most runs there is no ATT&CK health row at
   all. That is normal, not a failure.
2. **`epss` is not a collector.** It is the enrichment step in
   `pipeline/cves.py:53`, which is why the health grid shows one more row than
   there are collector modules and why the "N collectors online" chip counts it.
3. **Partial RSS failure hides.** If some feeds in the pool die but not all,
   `ok` stays `true` with a populated `error`, and the site only renders
   `error` when `ok` is false. Check the raw JSON, not the grid, when the feed
   looks thin.

## When a collector goes red

Work down this list. Every collector is fault-isolated, so a red row is never
an emergency — the site keeps serving last-known-good.

**1. Confirm it is upstream, not us.** Re-run locally:

```
.venv\Scripts\python run_pipeline.py
```

If the local run is clean, it was a transient Actions network failure. The next
cron run self-heals; nothing to do.

**2. Read the error string** in `health.json`. Common shapes:

| Symptom | Likely cause | Action |
|---|---|---|
| HTTP 403 / 429 from `nvd` | NVD rate limiting the keyless endpoint | Wait. The paging loop is already capped at `MAX_PAGES = 5` (`collectors/nvd.py:10`). If sustained, an NVD API key raises the limit — but that adds a secret, which is a design change, not a fix |
| HTTP 404 / schema shift from `kev` | CISA moved or reshaped the feed | Check the URL in `collectors/kev.py:6`, then fix the field mapping and add a fixture test |
| `rss` error listing several feeds | Individual publishers changed or blocked their feed | Drop or replace the entry in `collectors/rss.py:10`. One dead feed is survivable; the collector only raises when *all* fail |
| `ransomwarelive` timeout | Upstream API unavailable | Wait; group-level activity is not time-critical |
| `epss` red with a batching error | FIRST API shape or limit change | Check `pipeline/cves.py:49` and the `BATCH = 100` size |
| `attack` red | The STIX bundle URL moved | `collectors/attack.py:4`. Site keeps serving cached profiles from state meanwhile |

**3. If the fix is a code change**, add or update a fixture in
`tests/fixtures/` and a test that fails without the fix. That rule exists
because sanitisation was once committed, declared safe, and shipped with two
working XSS bypasses.

**4. If the payload itself is malformed** rather than the fetch failing, the
schema gate has already protected the site. Look for the `pipeline_warnings`
entry naming the file, and fix either the collector or the schema — never
loosen the schema just to make a warning go away.

## Deploying

Push to `main`. The workflow uploads `site/` to Cloudflare Pages on every run,
scheduled or manual.

To deploy without waiting for cron: Actions → **collect-and-deploy** → Run
workflow.

Because `site/data/` is gitignored, a deploy always ships payloads generated
*in that run*. You cannot deploy a stale local `site/data/` by accident, and
you cannot deploy shell changes without also refreshing data.

### Why direct upload rather than the Git integration

Cloudflare can build from the repository itself, but the free plan caps that at
500 builds a month and this workflow deploys roughly 1,440 times a month.
Direct uploads via `wrangler pages deploy` are not counted against that cap.
The arrangement also means Cloudflare never needs read access to the
repository, so the source can stay private.

The one sharp edge: `--branch` must match the project's production branch. Get
it wrong and the upload succeeds, lands as a *preview* deployment on a
`*.pages.dev` URL, and the live site keeps serving the previous build with no
error anywhere.

### Secrets

Two, both set under Settings → Secrets and variables → Actions:

| Secret | Where it comes from |
|---|---|
| `CLOUDFLARE_API_TOKEN` | Cloudflare → My Profile → API Tokens → Create Token, template **Edit Cloudflare Workers**, or a custom token with `Account → Cloudflare Pages → Edit` |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare dashboard → Workers & Pages → the account ID in the right-hand sidebar |

Scope the token to Pages only. It can deploy the site; it should not be able to
do anything else.

### Custom domain

`socdesk.io` is registered at Cloudflare, which is also where the site is
hosted, so this is simpler than the split-provider setup it replaced — there is
no CNAME file, no grey-cloud caveat, and no certificate dance.

1. Cloudflare → Workers & Pages → **socdesk** → Custom domains → **Set up a
   domain** → `socdesk.io`. The DNS record and certificate are created for you.
2. Add `www.socdesk.io` the same way if you want it, and redirect one to the
   other with a Bulk Redirect or a Page Rule.
3. Bump `VERSION` in `site/sw.js` — see below.

The absolute `og:image` and `og:url` in `site/index.html` already point at
`https://socdesk.io/`, and `csp.spec.js` asserts it, so a future host change
cannot leave them stale the way the last one did.

When checking domain availability, use `https://rdap.org/domain/<name>`
(404 means available). Consumer ISP resolvers hijack NXDOMAIN, so a plain
`nslookup` makes every name look registered.

## Rolling back

Three different things can be wrong, and they roll back differently.

**Bad shell (HTML/CSS/JS).** Fastest path is Cloudflare → Workers & Pages →
**socdesk** → Deployments → the last good one → **Rollback to this deployment**.
That is live in seconds and needs no build. Then revert the commit and push, or
the next scheduled run redeploys the broken shell straight over your rollback.
Either way, bump `VERSION` in `site/sw.js` — *without that bump, returning
visitors keep the broken shell from their cache and your rollback appears not
to have worked.*

**Bad data.** You cannot roll back `site/data/` directly — it is generated. Fix
the collector or the schema and re-run. If the bad payload came from upstream
and the schema did not catch it, tighten the schema so the gate falls back to
last-known-good next time; that is the gate doing its job.

**Corrupt `data/state/`.** State is committed, so `git checkout <good-sha> --
data/state` restores it, and the next run rebuilds forward from there. Rebase
conflicts inside `data/state/*.json` are generated data — take either side and
re-run the pipeline rather than trying to merge JSON by hand.

**Deleting state entirely** is survivable but costly: the feed loses its 30-day
merged window, the CVE table loses everything outside the current fetch, and
trends lose their comparison baseline until the snapshot series rebuilds
(`data/state/history/` holds up to 90 daily files).

## The service worker VERSION bump

`site/sw.js` holds a single `const VERSION = "socdesk-vN"` near the top, with a
trailing comment naming what that revision changed. Keep the comment habit —
it is the only changelog the cache has.

The shell — HTML, CSS, JS, fonts — is cached **cache-first**, because it only
changes on deploy. Data is network-first, so intel is never served stale as
fresh. The price of cache-first is that a returning visitor keeps the old shell
until the cache key changes.

**Bump `VERSION` on every change to `site/index.html`, `site/css/*` or
`site/js/*`.** The `activate` handler deletes every cache whose key does not
start with the new `VERSION`, which is what forces the refetch.

This has bitten the project repeatedly: the file's own comment records two
changes masked during development, and the session handoff notes a third. The
failure mode is nasty precisely because it is invisible to you — a hard reload
or a fresh incognito window shows the new UI perfectly while every returning
visitor still sees the old one. If a change "did not deploy", check `VERSION`
before you check anything else.

Two related traps in the same file: `SHELL_ASSETS` (`site/sw.js:19`) is an
explicit list, so a **new** JS or CSS file must be added there or it will not
be precached; and assets are added individually rather than with `addAll`
because `addAll` is atomic and one 404 would fail the entire install.

## Other traps worth knowing

- **The CSP has no `unsafe-inline`.** A single `style=""` attribute or inline
  `<script>` breaks the page. Use classes, or `el.style.setProperty()` — CSSOM
  writes are allowed. `site-tests/specs/csp.spec.js` catches violations.
- **`<use href="#symbol">` renders into shadow DOM.** Outer CSS cannot style
  non-inheritable properties such as opacity or animation there. Inline the SVG
  if it needs to animate.
- **`IntersectionObserver` with `threshold > 0` never fires** on elements taller
  than the viewport. Use `threshold: 0`. This once left 18 elements permanently
  invisible.
- **Playwright browser lock.** If it reports the browser is already in use,
  kill the leftover Chrome processes and retry.
- **`data/state` vs `site/data` drift.** After a local run that you did not
  commit, the two directories can hold different `generated_at` values. That is
  cosmetic locally, but remember the gate reads `data/state` — it is the
  fallback, so an old state directory means an old fallback.
