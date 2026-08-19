# SOCDesk — Architecture

How the system is put together, why it is shaped this way, and what the shape
costs. Read [COMPLIANCE.md](../COMPLIANCE.md) alongside this: several
architectural decisions here are licensing decisions wearing engineering
clothes.

**A note on scope.** Everything from here through *Tier 3 — the site* below
describes the original zero-infrastructure pipeline, and most of it is still
exactly how data gets collected and published today. What has moved: the
deployed frontend is no longer the vanilla `site/` app that section describes
— it's `web/` (Vite + React 19 + Tailwind v4 + Motion), built and shipped by
the same `collect-and-deploy.yml` workflow to the same Cloudflare Pages
target; `run_pipeline.py` now dual-writes into `web/public/data/state`
instead of `site/data`. `site/` is kept in-repo for history but is not what
deploys. `shared/` is a framework-free library layer, consumed by both `web/`
and the browser extension, holding logic too load-bearing to duplicate —
including the two subsystems documented in their own sections below, added
after *Tier 3*. Reconciling the rest of `site/`'s vanilla-ES-modules framing
against `web/` — module-by-module — is real doc-debt, tracked but not
attempted in this pass.

## The constraint that produced the design

Zero infrastructure. No server, no database, no accounts, no bill. Everything
downstream follows from that:

- Collection has to happen somewhere that is free and scheduled — GitHub
  Actions cron.
- The output has to be a file, because a file is the only thing a static host
  can serve — JSON payloads under `site/data/`.
- Anything analyst-specific has to live in the browser, because there is
  nowhere else to put it — `localStorage`, via `site/js/state.js`.
- Freshness is bounded by the cron interval, not by request time. The UI is
  therefore obliged to always say how old the data is rather than imply live.

The second constraint is the aggregator rule: SOCDesk holds only data it may
clearly redistribute. Reputation corpora are reached by user-clicked deep links
at render time and never fetched by the page. This is enforced structurally by
the Content-Security-Policy (`connect-src 'self'`), not by convention.

Per-indicator reputation is a separate path from that rule: rather than holding
a corpus, the browser calls its own origin at `/api/enrich` — still within
`connect-src 'self'` — and that Cloudflare Pages Function fans out to the public
reputation sources server-side; nothing is stored (see *What static costs* §2).

## End to end

```mermaid
flowchart TB
  subgraph up[Upstream, public and keyless]
    KEV[CISA KEV]
    NVD[NVD 2.0 API]
    EPSS[FIRST EPSS]
    RL[Ransomware.live]
    RSS[9 vendor and researcher RSS feeds]
    ATK["MITRE ATT&CK STIX bundle"]
  end

  subgraph t1[Tier 1 — collection, GitHub Actions cron :11 and :41]
    C[collectors/*.py<br/>SOURCE + collect fetch, now]
    RA[run_all — one failure never affects the others]
    C --> RA
  end

  subgraph t2[Tier 2 — pipeline]
    JOIN[cves.py — KEV x NVD join, then EPSS enrichment]
    SCORE[relevance.py — score 0-100 plus why, group repetitive]
    REL[relations.py — evidence-backed entity edges]
    HIST[history.py — daily snapshot, derived trends]
    PUB[publish.py — envelope and merge]
    GATE[validate.py — JSON Schema gate<br/>fail returns last known good]
    JOIN --> PUB --> GATE
    SCORE --> PUB
    REL --> PUB
    HIST --> PUB
  end

  subgraph out[Outputs]
    STATE[(data/state/*.json<br/>committed, last known good)]
    HISTD[(data/state/history/YYYY-MM-DD.json<br/>committed, 90 day window)]
    SITE[(site/data/*.json<br/>gitignored, regenerated every run)]
  end

  subgraph t3[Tier 3 — static site, Cloudflare Pages]
    APP[vanilla ES modules, no build step]
    SW[service worker: shell cache-first, data network-first]
    LS[(localStorage — analyst state, never transmitted)]
    APP --- SW
    APP --- LS
  end

  PIV[[Third-party reputation services<br/>reached ONLY by user-clicked links]]

  up --> C
  RA --> JOIN
  RA --> SCORE
  RA --> REL
  GATE --> STATE
  GATE --> SITE
  GATE --> HISTD
  STATE -. prior run feeds the next .-> GATE
  SITE --> APP
  APP -. user clicks .-> PIV
```

## Tier 1 — collection

`run_pipeline.py:50` is the orchestrator. It loads prior state, decides which
collectors to run, runs them, and hands the results to the pipeline.

**The collector contract.** A collector module exposes `SOURCE` (a short slug)
and `collect(fetch, now)` returning a `CollectorResult`
(`collectors/base.py:52`). `items` are normalised feed rows; `extra` is a
dict of side payloads the pipeline consumes by key (KEV rows, NVD rows, ATT&CK
profiles). `fetch` is injected — production passes `pipeline/http.py:6`, tests
pass a fixture stub, which is why the pytest suite runs offline.

**Fault isolation is the mechanism, not an aspiration.** `run_all`
(`collectors/base.py:78`) wraps every module in a try/except, converts a raised
exception into `ok=False` plus a truncated error string, and continues. A
collector cannot take down a sibling, the pipeline, or the deploy. Every run
produces one health entry per module regardless of outcome.

RSS goes one level further (`collectors/rss.py:51`): a single dead feed is
caught inside the loop and recorded in `error`, and the collector only raises
if *every* feed in the pool failed.

**ATT&CK is cached, not fetched every run.** The STIX bundle is large and
changes on a quarterly cadence, so `run_pipeline.py:45` skips it while
`actors.json` in state is newer than `attack.CACHE_DAYS` (7 days). It is listed
separately as `CACHED_COLLECTORS` in `collectors/__init__.py:10`.

**Normalisation and sanitisation happen at collection.**
`collectors/base.py:61` builds every feed item through one function: a SHA-1 id
derived from `source:native_id` (stable across runs, so dedup and analyst
"reviewed" marks survive), text reduced to inert plain text by `clean_text`,
and URLs filtered by `safe_url`. Both of those functions exist because upstream
strings are attacker-influenced and both previously shipped with working
bypasses — the comments at `collectors/base.py:16` and `:37` name them
specifically. The site escapes again at render time anyway
(`site/js/data.js:8`); the pipeline sanitising is not a licence to trust the
data downstream.

## Tier 2 — pipeline

Ordered by what depends on what:

1. **CVE join** (`pipeline/cves.py:22`). Merges prior rows, NVD rows, and KEV
   rows into one table keyed by CVE, retaining anything modified inside a
   180-day window plus every KEV row regardless of age. The NVD collector
   deliberately issues two queries — a recent-modified window *and* the whole
   KEV catalogue via `hasKev` (`collectors/nvd.py:21`) — because KEV spans
   2014 onward while the modified window is two days, and without the second
   query the KEV × CVSS join is a fiction.
2. **EPSS enrichment** (`pipeline/cves.py:53`). Batched 100 CVEs per request,
   mutating rows in place. It returns its own health entry, which is why
   `health.json` carries one more row than there are collector modules.
3. **Feed merge** (`pipeline/publish.py:26`). Prior items plus new items keyed
   by id, fresh wins, trimmed to a 30-day window, newest first. Timestamps are
   repaired on every merge, not only at collection (`publish.py:15`), because
   items already carried in state keep whatever malformed value they arrived
   with.
4. **Relevance scoring** (`pipeline/relevance.py:25`). Every item scored 0–100
   from signals the pipeline already holds — KEV linkage, EPSS, CVSS, severity,
   named actor or malware, recency — and each item carries a `why` array of the
   reasons that fired. Pure and deterministic: it takes `now` as a string and
   never reads the clock.
5. **Repetition grouping** (`pipeline/relevance.py:98`). Four or more
   ransomware victim-claim stubs from the same group collapse into one digest
   row. Without it those stubs dominate the feed and drown everything else.
6. **Relations index** (`pipeline/relations.py:71`). A typed, evidence-carrying
   edge list derived only from data already published alongside it. Every edge
   cites its evidence; nothing is inferred. Full derivation rules and the
   presentation verdict are in [RELATIONSHIPS.md](RELATIONSHIPS.md).
7. **History and trends** (`pipeline/history.py`). One compact snapshot per day
   committed into `data/state/history/`, pruned to 90 days. Trends are then a
   diff between two files — which is how a site with no database answers "what
   changed this week". New-to-KEV comes from CISA's own `dateAdded`, never from
   snapshot diffing, because on a first run diffing would report the entire
   back catalogue as new today (`pipeline/history.py:74`).

## The schema gate and last-known-good

`pipeline/validate.py:34` is the single point where a bad upstream day becomes
a warning instead of an outage.

For each candidate payload: validate against its schema in `schemas/`, and
reject anything over an 8 MB hard cap. Then

- valid → publish it;
- invalid, prior snapshot exists → **publish the prior snapshot** and append a
  `problems` entry describing the failure;
- invalid, no prior snapshot → skip the file entirely and record the problem.

Any problems collected are written into `health.json` as `pipeline_warnings`
(`run_pipeline.py:74`) and rendered as a warning strip on the site
(`site/js/views.js:475`). `run_pipeline.py:108` then exits 0 unconditionally.
That is deliberate: upstream trouble is health data, and failing CI on it would
mean one flaky third-party API blocks a deploy that would otherwise ship
perfectly good last-known-good data.

The schemas are bounded on purpose — `maxLength`, `maxItems`, and
`additionalProperties: false` throughout — so that one runaway or adversarial
upstream string cannot blow up the build or the browser.

## The state / publish split

Two directories, different jobs, and mixing them up is the most common way to
get confused here.

| | `data/state/` | `site/data/` |
|---|---|---|
| In git | **Committed** | **Gitignored** (`.gitignore`) |
| Role | Last-known-good input to the next run | The deployed artifact |
| Lifetime | Persists across runs; the gate reads it | Overwritten every run |
| Also holds | `history/YYYY-MM-DD.json` daily snapshots | nothing else |

Both are written from the same `published` dict in the same loop
(`run_pipeline.py:81`), so a successful run leaves them byte-identical. State
is what makes the pipeline resilient: it is the "prior" argument to the gate,
the source of merged feed items, and the reason a collector can be down for a
day without the site emptying out. Git is the datastore, and the commit history
is the audit trail.

The workflow commits `data/state` with `GITHUB_TOKEN`, whose pushes cannot
retrigger workflows — that is what stops the cron job from looping on itself.
The Tier 2 brief writer, when it exists, will push with a deploy key, which
*does* retrigger. The asymmetry is intentional and is documented in the
workflow itself (`.github/workflows/collect-and-deploy.yml:49`).

## Data contracts

Every published payload carries `generated_at` and `schema_version` in its
envelope (`pipeline/publish.py:11`) and is validated by the map in
`pipeline/validate.py:8`.

| Payload | Schema | Shape | Notes |
|---|---|---|---|
| `feed.json` | `feed.schema.json` | `items[]` | 30-day window; `score`, `why`, optional `grouped` |
| `cves.json` | `cves.schema.json` | `cves[]` | 180-day window plus all KEV; the largest payload by far |
| `actors.json` | `actors.schema.json` | `profiles[]` | ATT&CK intrusion sets |
| `malware.json` | `actors.schema.json` | `profiles[]` | ATT&CK malware and tools; shares the actors schema |
| `health.json` | `health.schema.json` | `sources[]`, optional `pipeline_warnings` | One row per collector plus one for EPSS |
| `sources.json` | `sources.schema.json` | `sources[]` | Copied from `data/sources.json` with a fresh timestamp |
| `trends.json` | `trends.schema.json` | `epss_movers`, `new_kev`, `volume`, `totals` | Derived from the snapshot series |
| `relations.json` | `relations.schema.json` | `nodes[]`, `edges[]` | Built and gated; **not currently consumed by the site** — see Known gaps |
| `brief.json` | *(none)* | — | Tier 2 output, passed through untouched if `data/brief.json` exists (`run_pipeline.py:96`) |

Measured on the 2026-08-09T03:41:46Z run: 5.46 MB raw across eight payloads,
824 KB gzipped, of which `cves.json` is 3.19 MB raw / 540 KB gzipped and
`relations.json` is 1.47 MB raw / 101 KB gzipped. The budget in
[AUTOMATION.md](AUTOMATION.md) is 10 MB gzipped, so there is a wide margin, but
`cves.json` is the one to watch — sharding it is the queued fix.

## Tier 3 — the site

*Superseded — see the scope note at the top of this document. `web/` is the
live frontend; this section is kept for history and is not what deploys.*

Vanilla ES modules served as files. No framework, no bundler, no build step;
what is in `site/` is what deploys.

| Module | Responsibility |
|---|---|
| `js/app.js` | Boot order and wiring. Owns the DOM/module contract and the single `runLookup` entry point |
| `js/data.js` | Payload loading, escaping, type detection, refang, freshness and staleness |
| `js/verdict.js` | Indicator verdicts, type-aware pivots, escalation write-up, bulk mode |
| `js/views.js` | Chrome, feed work queue, rail detail, vulnerability table, trends, health, registry, profiles |
| `js/state.js` | localStorage-backed analyst state, every read guarded |
| `js/motion.js` | Animation primitives; every one falls through to the correct final state when GSAP is absent |
| `js/toolbelt/` | Dependency-free client-side utilities, dynamically imported so a failure there cannot take down the app |

**Payloads load independently.** `loadAll` (`site/js/data.js:18`) fetches each
file in parallel and stores `null` on any failure. A missing `feed.json` renders
a designed offline row rather than a blank page (`site/js/views.js:90`); an
absent `brief.json` renders a designed empty state and hides its nav entry.

**The animation layer is optional by construction.** GSAP loads from
`cdn.jsdelivr.net` as classic scripts. `site/js/motion.js:6` sets `g` to `null`
if the CDN failed *or* the reader prefers reduced motion, and every primitive
below that line falls through to its final state. GSAP's Flip plugin was
removed rather than loosening the CSP for it — the note at
`site/js/motion.js:102` is the reasoning.

**Content-Security-Policy.** `default-src 'none'`, no `unsafe-inline`, no
`unsafe-eval`, `connect-src 'self'`. `site/_headers` is authoritative — it is
served as a real header and can express `frame-ancestors` and
`upgrade-insecure-requests`, which a meta tag cannot. A `<meta>` copy in
`site/index.html` is the fallback for when the header does not apply: a
misconfigured project, a preview deployment, or a plain file server in
development. A browser given both enforces the *intersection*, so drift between
them would silently block something in production; `csp.spec.js` compares the
two and fails if they diverge on any directive both can express.

**Service worker.** `site/sw.js` splits its strategy deliberately: the shell is
cache-first because it only changes on deploy; `data/*.json` is network-first
with cache fallback, because stale intel presented as fresh is the one failure
mode this project cannot have. The cost of cache-first is that `VERSION` must
be bumped on every shell change — see
[OPERATIONS.md](OPERATIONS.md#the-service-worker-version-bump).

**Analyst state never leaves the browser.** Reviewed marks, notable flags,
watchlist, and lookup history live under the `socdesk:v1:` localStorage prefix
(`site/js/state.js:4`), and `clearAll()` wipes exactly that prefix. There is no
endpoint to transmit them to.

## The PowerShell analyzer (`shared/analyzer/`)

Lives in `shared/`, not `web/` — a framework-free library consumed by the
standalone `/analyzer` route, the cockpit below, and (via the same
`@socdesk/shared/analyzer` alias) the browser extension. **Deterministic,
client-side, and it never executes the input.** `analyze()` (`report.ts:9`)
is a pure function from a string to an `AnalysisResult`; its only browser
APIs are `atob` (`fold.ts:1`) and `DecompressionStream` (`fold.ts:27`) — both
local, both operating on already-in-memory bytes. Nothing in the module
touches `eval`, `Function()`, or the network.

**Pipeline**, one module per stage:

1. **`preprocess.ts:14`** strips a leading `powershell(.exe)`/`pwsh` wrapper,
   pulls the `-Command` body if present, and extracts the outer evasion flags
   (`-enc`, `-nop`, `-w hidden`, `-ep bypass`, `-noni`, `-sta`) via a small
   `FLAG_RULES` table (`:5`) — each flag carries its own ATT&CK
   `techniqueIds`, matched on PowerShell's unambiguous-prefix rule (`-e`,
   `-ec`, `-enc`, `-encodedcommand` all resolve to the same flag).
2. **`lex.ts:15`** `tokenize()` is a hand-rolled, literal-safe PowerShell
   lexer: a string token's `value` is its resolved payload (backtick escapes
   decoded, doubled quotes un-escaped) kept separate from its `raw` source
   slice, so every later stage matches against resolved values — a signature
   check can't be defeated by backtick obfuscation the way a raw-text regex
   would be.
3. **`fold.ts`** decodes the two payload shapes PowerShell attackers actually
   use: `decodeEnc` (`:11`) is Base64 → UTF-16LE (an `-EncodedCommand`
   payload is UTF-16LE, not UTF-8 — the #1 gotcha the comment names
   directly), and `inflate()` (`:39`) handles both gzip (magic `1F 8B`) and
   PowerShell's raw-DEFLATE `DeflateStream`. A decompressed layer is only
   accepted if `isMostlyPrintable` (`report.ts:209`) passes — raw-DEFLATE
   "succeeds" on roughly 0.4% of arbitrary Base64, and that binary garbage
   must never be presented as a decoded layer.
4. **`resolve.ts`** is the static-deobfuscation core: `foldConcat` (`:25`)
   collapses `'a'+'b'+…` literal-only runs; `resolveVars` (`:51`) substitutes
   single-assignment `$var = 'literal'` bindings and leaves anything assigned
   more than once, or to a non-literal, untouched and "poisoned" rather than
   guessed; `resolve` (`:91`) iterates both to a fixpoint, capped at 12
   passes and 1 MiB of output so hostile input can't spin the analyzer.
   `report.ts`'s `analyze()` drives up to 6 rounds of this plus IEX/`&`/
   `.Invoke()` recursion (`iexStringTarget`, `report.ts:154`) — chasing what
   a resolved string literal would hand the interpreter next.
5. **`extract.ts:11`** `extractIocs()` scans every decoded layer's text with
   one candidate regex (URLs, IPv4, domains, 32/40/64-hex hashes) and hands
   each candidate to the app's own `detectType` as the arbiter — the same
   classifier `/lookup` and the cockpit's data boundary use, so the analyzer
   can't drift into a second, disagreeing notion of "what's an IOC."
   PascalCase `.NET` member-access tokens like `Net.WebClient` are filtered
   back out (`:25`) because they collide with the domain regex.
6. **`techniques.ts` + `lolbins.ts`** — the signature layer. A
   `SignatureRule` (`techniques.ts:12`) is `{ id, label, techniqueIds,
   baseSpecificity: 'weak'|'strong'|'near-dispositive', upgradesWith:
   string[], test(ctx) }`, matched against a `RuleContext` built once per
   analysis (`buildContext`, `:24`: decoded corpus text/lowercased text,
   tokenized words, evasion flags). 12 rules (`:70`–`247`): download cradle,
   evasion-flag cluster, AMSI bypass via reflection, AMSI memory patch, ETW
   tampering, Defender tampering, ClickFix/paste-and-run, beaconing, reverse
   shell, in-memory loader/shellcode, persistence, and a data-driven LOLBins
   rule backed by a 9-binary table in `lolbins.ts:14` (certutil, bitsadmin,
   mshta, regsvr32, rundll32, msiexec, wmic, installutil, conhost — each
   needs the binary name **and** a discriminating context token; a bare
   mention never fires). `classify()` (`techniques.ts:277`) applies the
   **co-occurrence upgrade**: after every rule runs once, a rule whose
   `upgradesWith` names a companion that also fired is bumped one
   specificity tier (capped at `near-dispositive`) — every individual token
   has a benign twin, so corroboration is the accuracy mechanism.
7. **`report.ts`** ties it together: `analyze()` (`:9`) is the orchestrator
   above; `composeCopyText` (`:173`) builds the deterministic clipboard
   export.

**Specificity-gated characterization** — `deriveCharacterization`
(`report.ts:125`). Two tiers, both hedged against a synthesized score:

- **Tier 1, "High-confidence malicious behaviour"** (red) fires only when a
  fired signal's rule has `baseSpecificity === 'near-dispositive'` — AMSI
  reflection, AMSI memory patch, or reverse shell, techniques the code
  comment states plainly have "no legitimate use." This is gated on the
  rule's **base** specificity, never the post-co-occurrence-upgraded one, so
  a merely-strong signal that corroboration bumped up can never borrow a
  "no legitimate use" claim it hasn't intrinsically earned.
- **Tier 2, "Suspicious — review"** (amber) fires when no near-dispositive
  base signal exists, but a strong signal was corroborated up to
  near-dispositive by its co-occurring companions — the evasion-cluster +
  download-cradle beacon shape. Language stays hedged ("elevated by
  co-occurring signals"), never "malicious."
- Anything short of that — weak/strong signals with no corroboration — earns
  no characterization at all: just the periwinkle technique tally, captioned
  "not a synthesized verdict" (`TechniqueTally.tsx:52`).

**Reserved-colour evolution (owner-approved).** `TechniqueTally.tsx:12`
(`CALLOUT`) is the one place the analyzer spends a verdict-severity hue: the
gated characterization box is red (`--edge-red`/`--tint-red`,
`text-verdict-red`) or amber (`--edge-gold`/`--tint-gold`,
`text-verdict-amber`). Every individual technique **chip** stays periwinkle
(`variant="technique"`), tier-tagged and sorted strongest-first, each citing
the literal substring that fired it. This deliberately relaxes the earlier
"analyzer output is periwinkle-only" rule — scoped to that one gated
callout; red/amber remain reserved for a real severity read everywhere else,
never decoration.

**UI.** `web/src/routes/PowerShellAnalyzer.tsx` is the standalone `/analyzer`
view (a bare textarea over `usePsAnalysis`); `web/src/components/analyzer/
AnalyzerResult.tsx` is the prop-driven, stateless result composition (flag
chips + `TechniqueTally` + `DecodeLadder` + `IocTable`) shared verbatim
between that route and the cockpit's inline result — one render path, two
callers, per `AnalyzerResult.tsx:8`. `IocTable`'s "Look up →" button
(`IocTable.tsx:17`) pivots an extracted indicator into `submitLookup`, which
re-runs the same data-boundary classifier before routing (see below), so a
pivot can't reopen the leak the classifier exists to close.

86 vitest specs across `shared/analyzer/__tests__/` (preprocess, lex, fold,
resolve, extract, techniques, lolbins, characterization, and an end-to-end
integration file).

## The polymorphic cockpit (`/`, `web/` + `shared/intent.ts`)

The landing omnibox (`web/src/routes/Overview.tsx`) used to accept only an
indicator, routed straight to `/api/enrich`. It is now polymorphic: one
input classifies what was pasted and renders either an escalation card
(indicator) or the local analyzer's result (command) inline, in the same
docked slot beside the globe — no tab-switch, no navigation. `/analyzer`
remains as the standalone deep view, sharing `AnalyzerResult` with it
verbatim.

**`classifyCockpitInput` (`shared/intent.ts:87`) is the data-boundary gate**
— the single function every submit path in the app calls *before*
`detectType` (`shared/indicators.ts`) ever sees a raw value. `detectType`
alone is not safe here: its URL regex is prefix-only, not end-anchored
(`indicators.ts:61`), so a multi-line paste whose first line is a download
URL would classify as `'url'` under `detectType` alone, and the entire blob
would go to the third-party `/api/enrich` as `?q=<full text>`.
`looksLikeCommand` (`intent.ts:67`) fires on: any newline; a `powershell`/
`pwsh`/`iex`/`new-object` token (`COMMAND_TOKEN_RE`, `:35` — deliberately
also matches inside `powershell.exe` as a bareword, so that filename can't
be misread as a domain); an `Invoke-<cmdlet>` form (`INVOKE_RE`, `:47`,
lookahead-gated so it doesn't false-positive on a hyphenated domain like
`invoke-example.com`); the `-e`/`-enc`/`-encodedcommand` flag
(`ENC_FLAG_RE`, `:57`, anchored to a token boundary so it can't fire
mid-word inside `site-enc.com`); or two-or-more shell-punctuation tokens
(`;`, `|`, backtick, `` $( `` — `SHELL_PUNCT_RE`, `:65`). `classifyCockpitInput`
(`:87`) returns `'command'` the moment `looksLikeCommand` is true, before
`detectType` runs at all; **command wins any tie** — a value that is both
command- and indicator-shaped (`powershell.exe`) still resolves `'command'`.

**`useCockpitInput`** (`web/src/components/cockpit/useCockpitInput.ts:68`)
composes both downstream hooks unconditionally, per the rules of hooks:
classify first, then call both `useLookup` and `usePsAnalysis`, feeding the
*unselected* one `''` — which each hook already short-circuits to its own
`idle` state for free (`:5`), so only the selected path's fetch or analysis
actually runs. `resolveCockpitArgs` (`:40`) is the pure, unit-tested routing
step; `resolveKind` (`:54`) applies a ModeChip correction **monotonically**
— a value auto-detected as `'command'` can never be overridden back to
`'indicator'`, because that would feed a raw script to `useLookup` →
`/api/enrich`.

**`ResultRegion`** (`web/src/components/cockpit/ResultRegion.tsx:44`)
dispatches purely on `cockpit.kind`: `indicator` → `EscalationCard` (ok) or
`LookupStatus` (checking/declined/unavailable/unsupported) plus a "Full
analyst view →" link into `/lookup`; `command` → the same `AnalyzerResult`
`/analyzer` renders, or an "Analyzing…"/error line; `unclassified` → an
honest one-line hint naming both accepted input kinds, never a fabricated
result. The caller keys the result wrapper on the *composite*
`` `${cockpit.kind}:${submitted}` `` (`Overview.tsx:210`), not `submitted`
alone — a ModeChip override can flip `kind` on the same committed string,
and a key on `submitted` alone would fail to remount, which is what stops a
stale `EscalationCard` compare-fetch from surviving a switch to the
analyzer.

**`CockpitOmnibox`** (`web/src/components/cockpit/CockpitOmnibox.tsx:38`)
morphs a single-line `<input>` into an auto-growing, monospace `<textarea>`
the moment the *live* (pre-submit) value becomes command-shaped, focus
following the morph in both directions and height synced in a
`useLayoutEffect` (`:63`) so a multi-line paste is sized correctly on the
same paint. `ModeChip` (`web/src/components/cockpit/ModeChip.tsx:12`) shows
the detected kind as a fact, not a verdict — `Chip variant="catalog"`
(periwinkle), deliberately not `"neutral"` (which renders identically to the
gray "unknown" verdict badge) — and is click-correctable, feeding
`resolveKind`'s override under the same monotonic guard.

**The globe suspend/resume yield.** `Overview.tsx`'s `isGeolessResult`
(`:45`) is true for every `command` result, a non-empty `unclassified`
submission, or an indicator resolved past `checking` with no geo. Two
effects follow it: one flies the globe home or lands it on a pin
(`:92`, keyed on `cockpit.kind`/`cockpit.state`); the other (`:110`) calls
`GlobeApi.suspend()`/`.resume()` (`web/src/components/hero/
useGlobe3.ts:878`/`885`) — not merely a CSS dim. The reason, per the code
comment at `Overview.tsx:106`: IntersectionObserver-based render-loop
gating doesn't see a CSS opacity change, so without an explicit suspend the
WebGL loop would keep burning GPU behind the `.is-geoless` dim
(`web/src/components/hero/globe.css:529`).

**⚠ DATA BOUNDARY, verified live: a pasted command never reaches
`/api/enrich`.** `classifyCockpitInput` guards every entry point, not just
the cockpit's own submit:

- the cockpit's auto-path (`useCockpitInput`, above);
- the ModeChip override, monotonic in the command direction (`resolveKind`);
- `palette/commands.ts::submitLookup` (`:111`) — the route every other
  surface (the palette, `IocTable`'s pivot) uses to reach `/lookup` — checks
  `classifyCockpitInput` first and redirects a command-shaped value to
  `/analyzer` instead of writing the lookup hash;
- `Lookup.tsx::runLookup` (`:170`), the form-submit handler, carries the
  identical guard;
- and `Lookup.tsx`'s own **hash reads** — both the initial-mount value
  (`rawQuery`, `:132`, guarded at `:143`) and the `hashchange`/`popstate`
  sync effect (`:153`, which re-derives `rawQuery`/`text` from the hash on
  every navigation) — route a command-shaped `#q=` value to `/analyzer`
  (`:150`) rather than ever constructing the query fed to `useLookup`. A
  bookmarked or shared `/lookup#q=<command>` link therefore redirects to
  `/analyzer` with zero calls to `/api/enrich`.

`palette/classify.ts` was also consolidated in this pass: it now delegates
all shape-detection to the shared `detectType` (`:26`) instead of carrying
its own drifted copy, so the palette's live badge can't disagree with the
data-boundary check or `useLookup` again.

**Unified submit.** Every hook above receives only the *committed*
(post-Enter) value, never the live-typed one — `useLookup` has no debounce
of its own, so this is what stops `/api/enrich` (or the analyzer) firing on
every keystroke (`useCockpitInput.ts:10`).

## Failure isolation, by layer

| What fails | What the analyst sees | Mechanism |
|---|---|---|
| One collector raises | That source red on the health grid with its error; every other panel normal | `collectors/base.py:84` |
| One RSS feed in the pool dies | Feed slightly thinner; error recorded on the health row | `collectors/rss.py:51` |
| A payload fails schema validation | Yesterday's copy of that payload, plus a warning strip | `pipeline/validate.py:34` |
| A payload fails and has no prior | That panel's designed empty state | `validate.py:47`, `views.js:90` |
| The CDN is blocked or down | Everything renders, statically, with no animation | `site/js/motion.js:6` |
| The network is gone | Last cached pull, labelled with its true age | `site/sw.js:51` |
| The toolbelt module fails to parse | Console warning; the rest of the app is untouched | `site/js/app.js:234` |
| The PowerShell analyzer throws on malformed input | "Could not analyze: `<message>`" inline; the rest of the route/cockpit is untouched | `usePsAnalysis.ts:22` |

## What static costs

Stated plainly, because the alternative is pretending it is free:

1. **Freshness is bounded by cron.** Twice an hour, not on demand. Everything
   in the UI that looks live — the elapsed counter, the next-pull countdown —
   measures our own clock, and says so.
2. **Live reputation — the static cost that got bought back.** A CVE gets a real
   verdict because the corpus is public-domain and can be held. An IP, domain,
   hash or URL cannot be held — that is a licensing problem, not a technical one.
   Rather than hold those corpora, the browser calls its OWN origin at
   `/api/enrich` (`functions/api/enrich.js` + `lib/enrich.mjs`, a Cloudflare
   Pages Function), which fans out to public reputation sources server-side and
   returns a source-consensus tally; keys live in Pages secrets, never in the
   browser, and nothing is stored. This shipped what was the queued fix
   (`superpowers/specs/2026-08-07-enrichment-worker-spec.md`).
3. **No shared state.** One analyst's marks are invisible to the next shift.
   Fixing that means a server and authentication, which
   [COMPLIANCE.md](../COMPLIANCE.md) parks as a separate authenticated
   deployment, never a bolt-on to the public site.
4. **Payload size is the scaling limit.** Every client downloads the whole CVE
   table. Sharding is the answer, not a database.

What it buys: the privacy guarantee is a *property* rather than a promise,
uptime is a CDN's problem, and there is nothing to patch at 2am.
[INFRASTRUCTURE-OPTIONS.md](INFRASTRUCTURE-OPTIONS.md) prices each step away
from this.

## Known gaps

Documented because they are real today, not because they are planned:

- **`relations.json` is published but never read.** The pipeline builds, gates,
  and deploys it (1.47 MB raw), but `site/js/data.js:6` does not list
  `relations` among the files it fetches, so the ranked "related entities"
  panel [RELATIONSHIPS.md](RELATIONSHIPS.md) specifies does not exist yet.
- **The watchlist scoring weight never fires.** `pipeline/relevance.py:17`
  defines a `watchlist` weight of 30, but `pipeline/publish.py:51` calls
  `apply_scores` without one — the pipeline cannot know a browser's watchlist.
  The site uses the watchlist for display chips and filtering only
  (`site/js/views.js:205`, `:366`); it never re-scores. The weight is reachable
  only from tests.
- **Partial RSS failures are invisible on the health grid.** A dead feed leaves
  `ok=True` with a populated `error`, and `site/js/views.js:471` only renders
  the error when `ok` is false.
