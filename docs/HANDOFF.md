# SOCDesk — Session Handoff

**Written:** 2026-08-08 · **Updated:** 2026-09-04 (session — Hunt Playbooks Plan 1 (backend) SHIPPED + live in state: schema/loader/fresh-publish/Kustainer CI lane + 2 exemplar identity playbooks; `data/state/playbooks.json` LIVE via green CI) · **Read §0 first.**

---

## 0. LATEST — 2026-09-04 (session — Hunt Playbooks Plan 1 (backend) SHIPPED + live in state)

**Context:** first plan of the new **Hunt Playbooks** feature — KQL at the *enrichment*
stage: analyst enriches an IOC, picks the triggering alert, gets an ordered,
IOC-parameterized, Kustainer-validated KQL playbook. Provenance: brainstormed → owner
chose **"B with a touch of A"** (pick the alert → playbook of queries incl. a general IP
pivot), curated catalog, **identity-first v1**. Spec
`docs/superpowers/specs/2026-09-03-hunt-playbooks-design.md` (adversarially vetted →
revised: v1 **log_analytics-ONLY** because the AH sign-in table has no DDL; injectIoc maps
`ipv4`/`ipv6`→`ip`; publish fresh, no keep-prior; deep-link + full-width route deferred to
v2; decomposed into 2 plans). Plan
`docs/superpowers/plans/2026-09-04-hunt-playbooks-backend.md` (vetted → revised: real
warnings sink at `run_pipeline.py:216`, CI fail-open guard on surviving `{{placeholder}}`,
per-playbook schema isolation, workflow paths).

**Shipped (Plan 1 = backend):**
- **Schema + validator wiring.** NEW `schemas/hunt_playbooks.schema.json` +
  `pipeline/validate.py` `SCHEMA_FOR` entry for `playbooks.json`. (`801041b`)
- **Loader.** NEW `pipeline/hunt.py::load_playbooks` (sibling of `load_authored_rules`;
  strips `rationale`; `source.url` = the file's GitHub blob; SOCDesk · MIT). (`801041b`)
- **Fresh publish + real warnings sink.** `run_pipeline.py` publishes `playbooks.json`
  **FRESH every run** (no keep-prior — authored-local), with **per-playbook schema
  isolation** so one bad file can't revert the whole catalog via `gate()`; warnings appended
  to the real sink (`warnings = problems + stale + authored_warnings + playbook_warnings`).
  (`801041b`)
- **Kustainer CI lane.** `tools/validate_hunt_kql.py` playbook lane — `substitute_samples`
  (canonical IOC per param) folds each step in as a pseudo-rule and **HARD-FAILS on any
  surviving `{{placeholder}}`** (the fail-open the vet caught); `.github/workflows/hunt-kql.yml`
  triggers on the new schema. (`801041b`)
- **2 exemplar playbooks.** NEW `data/hunt/playbooks/socdesk-unfamiliar-signin-properties.yaml`
  + `socdesk-password-spray.yaml` — each opens with the **general SigninLogs IP pivot**
  (surfaces the accounts), then a `{{upn}}`/IP-scoped scenario step adapted from the authored
  identity rules. (`a39fd81`)

**Verified:** 194 pytest green; local Kustainer 65/65 (all 4 playbook steps bind);
**hunt-kql CI run 33881687866 GREEN** (KQL validated in the emulator in CI);
**collect-and-deploy run 33881715556 GREEN** → `data/state/playbooks.json` **LIVE**
(2 playbooks, `rationale` stripped, published by the pipeline).

**DECISION:** v1 is **log_analytics (Sentinel) ONLY**; `advanced_hunting` is **v2** (needs an
`AADSignInEventsBeta` DDL sourced into `kusto_ddl/advanced_hunting/` first). Placeholder
syntax `{{ip}}` / `{{upn}}`; CI substitutes canonical samples.

**Open / next:**
- **Plan 1 fast-follow** — the remaining **4 v1 playbooks** (impossible-travel, mfa-fatigue,
  malicious-inbox-rule, risky-oauth-consent), data-only same shape, each Kustainer-validated.
- **Plan 2 (client)** — extract shared **HuntRow** renderer; **injectIoc**
  (ipv4/ipv6→ip family map + KQL-literal escaping); **HuntPlaybookPanel** under `EscalationCard`
  in `ResultRegion` (scenario chips filtered by IOC type, zero-click IP pivot, local-state
  selection).
- **v2** — AH dialect + toggle; `alert=` deep-link + full-width lookup route; domain/hash
  scenarios.

---

## 0-RECENT — 2026-09-03 (session — N3 remainder SHIPPED + live: directory facets + card-height normalization — CLOSES Adversaries re-run N1-N4)

**Context:** ships the last piece of the 2026-09-03 Adversaries RE-RUN
(`SOCDesk-Adversaries-Rerun-2026-09-03.pdf`): N1 progressive disclosure · N2 reverse-index
de-dup · N3 lockbit5 seed + facets + heights · N4 distinctive-TTP lead. With this the
**entire re-run is CLOSED** — scorecard **N1 ✅ · N2 ✅ · N3 ✅ · N4 ✅**. Adversarially
vetted before code: reviewer confirmed the load-bearing risk (sector vocabulary) is safe —
it's a clean **13-value ransomware.live taxonomy** — and caught a real **useMemo-deps bug**
+ that the aggregation is **two-stage**; both corrected before ship.

**Shipped:**
- **Directory sector/country/seeded facets.** New optional `ProfileIndexEntry.sectors?` /
  `countries?`, aggregated in `buildProfileIndex`: stage-1 claims Map gains sector/country
  Sets via `parseSectors` / `parseCountry` (sectors from **singles + digests**; countries
  from **SINGLES only** = honest-partial), attached in BOTH `bySlug` branches.
  `ProfileDirectory` adds a facet row — **Seeded** toggle + **Sector** `<select>` (13 clean
  ransomware.live options) + **Country** `<select>` (36 ISO-2 codes → readable names via
  `Intl.DisplayNames`); facet state wired into the `filtered` useMemo **and its deps array**.
  Files: `web/src/components/views/profiles.ts`,
  `web/src/components/views/ProfileDirectory.tsx` (+ their tests).
  (`1dbe232` stage-1 aggregation · `b548580` facets)
- **Card-height normalization.** Grid `items-start` (kills the stretched empty bordered
  boxes when a rich card shares a row with bare crews) + `min-h-[7rem]` floor; blurb clamped
  `line-clamp-1`; meta `mt-auto` bottom-anchored. File: `ProfileDirectory.tsx`. (`b548580`)
- **Backlog close-out** — 2026-09-03 Adversaries re-run marked fully closed (N1-N4).
  (`553a968`)

**Verified:** 937 vitest + lint + build all green. Deployed via collect-and-deploy run
33821267751. Live-dogfooded on socdesk.pages.dev — **Healthcare** sector facet narrowed
1,361 → 18 ransomware crews; country facet shows "AR · Argentina" etc.; grid renders clean
(no empty boxes — screenshot confirmed).

**Open / next (non-re-run — the re-run itself is CLOSED):**
- **`?s=` section deep-link channel** — the hash router reserves `#g=<slug>`, so `#section`
  fragments can't be used (DEFERRED from N1); needs a non-hash channel.
- **Owner activation gates (×2)** — `IPINFO_TOKEN` secret; KV bind + `/api/enrich` WAF rule.

---

## 0-RECENT — 2026-09-03 (session — N1+N4 progressive-disclosure profile rebuild SHIPPED + live)

**Context:** builds the N1 decision locked earlier today (see the demoted 0-RECENT block
below) from the 2026-09-03 Adversaries RE-RUN critique. Closes **N1** (profile density /
7,200px scroll) + **N4** (distinctive-TTP lead). Plan was adversarially vetted before code —
the reviewer caught a factually-wrong "distinctive block below the matrix" premise that
would have been a `noUnusedLocals` build error; corrected before implementation.

**Shipped:**
- **ActorProfile restructured** into an always-open **decision layer** (identity + NEW
  SynthesisBand + Initial-access panel + Leak-site activity) over native `<details>`
  **collapsed reference sections** (Claimed victims · ATT&CK matrix · Hunt pack · Reporting),
  oriented by a sticky scrollspy **jump-nav** (ProfileNav). Collapsed content stays in the
  DOM (SEO / print / Ctrl-F preserved). File: `web/src/components/views/ActorProfile.tsx`.
  (`ae5abce`)
- **BoardPanel** gained `collapsible` / `defaultOpen` / `id` — renders as
  `<details data-collapsible>` with the SAME shell (header→summary + CSS-only `group-open`
  chevron); backward-compatible with every existing call site. File:
  `web/src/components/overview/board-ui.tsx`. (`ae5abce`)
- **New components/hook:** `SynthesisBand.tsx` (4 honest-empty router cells: **Distinctive
  TTPs** [hoisted from the existing `distinctiveSplit`, N4] · Top hunts · activity spark ·
  KEV tease), `ProfileNav.tsx`, `useProfileNav.ts` (navSections + `openAndScrollTo` +
  SSR-safe print-open + IntersectionObserver scrollspy). (`ae5abce`)
- **Extracted** (react-refresh, no behaviour change): `TechniqueChip.tsx`, `HeatStrip.tsx`
  (+compact), `activity-ui.ts`. **`MitreFingerprintPanel` LEFT UNTOUCHED** — its in-matrix
  distinctive tint stays. (`ae5abce`)

**⚠️ DECISION / load-bearing gotcha — SOCDesk is HASH-ROUTED (`/actor#g=<slug>`).** The
first cut used `href="#fingerprint"` nav/synthesis anchors, which **wiped the `g=<slug>`
route param on click and broke the page** — caught ONLY in live dogfood (SSR tests were
green). Fix: jump-nav + synthesis links are **BUTTONS calling `openAndScrollTo(id)`**
(scroll + open by id, never touch the URL hash). Consequence: **deep-linking a section via a
shareable URL is NOT supported** (needs a non-hash channel like `?s=`) — **DEFERRED**.
Files: `web/src/components/views/ProfileNav.tsx`, `SynthesisBand.tsx`, `useProfileNav.ts`.
(`07317be`)

**Verified:** 934 vitest + lint + build all green. Deployed via collect-and-deploy run
33811321802. Live-dogfooded on socdesk.pages.dev / APT29 — decision layer + Distinctive
TTPs·18 + Top hunts·34 render; collapsed Fingerprint(66) / Hunt pack(34); nav scroll+open
works.

**Open / next:**
- **Deep-link `?s=` channel** — deferred non-hash section deep-link (hash router can't
  coexist with `#section` anchors).
- **N3 remainder** — directory sector/country/seeded facets + card-height normalization.
  (N2 + N3-LockBit already shipped earlier today — see demoted block.)

---

## 0-RECENT — 2026-09-03 (session — Adversaries RE-RUN Batch 1: N3 LockBit slug-alias + N2 reverse-index de-dup shipped; N1 IA decision locked)

**Context:** responds to the 2026-09-03 Adversaries RE-RUN critique
(`SOCDesk-Adversaries-Rerun-2026-09-03.pdf`). The re-run confirmed the AAA content
transformation LANDED and raised 4 new findings N1–N4; one-line takeaway — "the content
is now premium; the work left is make the substance consumable." This block records
Batch 1 (2 of 4 findings, shipped + live) and the locked-but-unbuilt N1 decision.

**Shipped (Batch 1 — each adversarially vetted, reviewer caught 5 load-bearing issues all
corrected before code; verified 913 vitest + lint + build + 186 pytest green):**
- **N3 (partial) — LockBit seed-slug aliasing.** The LockBit CISA seed was keyed to slug
  `lockbit` while the active leak-site slug is `lockbit5` (`lockbit2`/`3`/`3_fs` are bare
  names), so the most-documented crew rendered as a name-only stub. Added a **match-only
  `slug_aliases`** schema field (kept OUT of display `aliases` so no lowercase-slug chips
  leak), made `intelFor` resolve it, and added a **final `buildProfileIndex` reconciliation
  pass** (after the name-only layer) to light the directory `seeded` badge on variant rows
  without minting phantoms. Curated, NOT auto-generalized — explicitly avoided the
  Medusa↔MedusaLocker (3 live claims) and Play↔Playboy misattributions the reviewer flagged.
  Files: `schemas/ransomware_intel.schema.json`, `data/ransomware_intel.json`,
  `web/src/components/views/types.ts`, `web/src/components/views/profiles.ts`,
  `web/src/components/views/__tests__/profiles.test.ts`. (`d57d1c4`)
- **N2 — malware reverse-index vs Related-entities de-dup.** On malware pages the
  "Used by tracked groups" reverse-index and "Related entities" listed the same actors
  twice. New pure helper `relatedMinusUsedBy` (`relations.ts`) drops actor rows already in
  the reverse-index (case-safe; keeps non-actor rows + actors not in the index); the panel
  is gated to **OMIT** rather than render a now-false "no related entities recorded" empty —
  but only when a reverse-index is present, so actor/ransomware pages keep their
  honest-empty. Files: `web/src/components/views/relations.ts`,
  `web/src/components/views/ActorProfile.tsx`,
  `web/src/components/views/__tests__/relations.test.ts`. (`a2821ea`)

**Verified:** 913 vitest + lint + build + 186 pytest all green. Deployed via
collect-and-deploy run 33754987398 (green). Live-dogfooded on socdesk.io: `lockbit5` now
shows the `seeded` badge + CISA AA23-325A intel panel; Cobalt Strike shows the reverse-index
with NO duplicate Related-entities panel; APT29 (actor page) unchanged (regression check
passed).

**DECISION locked — N1 progressive disclosure (NOT built, spec pending).** Carl ruled the
profile-IA rebuild: **defer + orient, never hide.**
- **Always-on decision layer** — identity + synthesis band (incl. the N4 "Distinctive
  TTPs · N" lead + activity heat-strip). Never collapsed.
- **Native `<details>/<summary>` accordions for the heavy reference sections ONLY**
  (hunt-pack, full ATT&CK matrix, victim ledger, related/reporting) so collapsed content
  **stays in the DOM** — SEO / print / Ctrl-F preserved.
- **Sticky scrollspy jump-nav** — Overview · Fingerprint · Activity · Hunt pack · Related;
  mobile "Jump to ▾".
- **Deep-link + print force sections open.** Impl note: CSS has no `open` property, so the
  "pure-CSS :target/print open" is done with a few lines of the app's own JS
  (hashchange→open, beforeprint→open-all, IntersectionObserver scrollspy) + CSS
  `scroll-margin`.
- **Guardrail:** NO "accordion soup." **Rejected tabs** (hide content from crawl/Ctrl-F).
- **NEXT STEP:** write the N1+N4 spec for Carl's review **before** building.

**Open / next:**
- **N1 + N4** — spec pending (write for review before building; decision above).
- **N3 remainder** — directory sector/country/seeded facets + card-height normalization.

---

## 0-RECENT — 2026-09-02 (session — Adversaries directory triage sort + BACKLOG close-out refresh)

**Shipped:**
- **Directory triage sort** — closes the last unaddressed Adversaries-critique priority
  ("the directory can't answer analyst questions — no sort, no way to rank by activity").
  Added a sort `<select>` to the Adversaries directory (`/actor`). The `Relevance` default
  reproduces the prior shipped order byte-for-byte (malware lens → used-by reverse-index
  desc; every other lens → `compareEntries` tier). Four explicit nulls-last, name-tie-broken
  single-key sorts: Most claims, Recently active, Most techniques, Name (A–Z). All fields
  already rode on `ProfileIndexEntry`; comparators live in the pure `profiles.ts` module
  (react-refresh-safe). Files: `web/src/components/views/profiles.ts` (DirectorySort type,
  SORT_OPTIONS, sortComparator), `web/src/components/views/ProfileDirectory.tsx` (sort state
  + select), `web/src/components/views/__tests__/profiles.test.ts`,
  `web/src/components/views/__tests__/ProfileDirectory.test.tsx`. (`47a32e0`)
- **BACKLOG refresh** — `BACKLOG.md` refreshed for the Adversaries-critique + hunt-pack-program
  close-out; the new 2026-09-02 header lists Adversaries batches A–E, seeded-intel depth, the
  hunt-pack program H0→H4 + H2 + H3 = 61 emulator-validated rules, the cached-collector
  `collected_at` freshness fix, and the `-X theirs` snapshot-race deploy fix. (`ed89bee`)

**Verified:** sort adversarially vetted (verdict APPROVE, no load-bearing defects); 8 new
comparator unit tests + 1 control-presence test; 905 vitest + lint + build green. Deployed via
collect-and-deploy run 33712771429 (green, 3m46s). Live-dogfooded on socdesk.io: sort reorders
correctly (Name→alphabetical, Most techniques→Kimsuky/APT28/Lazarus,
Relevance→krybit/incransom/Akira).

**Open / next:** owner activation gates still open in `BACKLOG.md` — IPINFO_TOKEN + KV/WAF;
COMPLIANCE.md reconciliation pending.

---

## 0-RECENT — 2026-08-25 (session — vendor-reported Tier-3 depth, 5 crews, compliance-reviewed, shipped + deployed live)

**Shipped:**
- **Vendor-reported Tier-3 depth** (owner-approved, resolves the (a) backlog decision from
  the prior block) — 5 active ransomware crews with no public-domain (CISA/HHS-HC3/FBI)
  profile now get an intel panel sourced from reputable vendor threat-reports: DragonForce,
  INC Ransom, The Gentlemen, Kazu, Coinbase Cartel. MetaEncryptor checked but **omitted**
  (conflicting IOCs across sources). Compliance model: atomic facts only (CVE /
  ATT&CK-technique / alias / tool ids, dates) with per-source attribution — no
  prose/paraphrase/wholesale-list; a vendor entry omits the gov `advisory` field (host-lock
  `(cisa|hhs).gov` stays gov-only) and carries reports in `sources[]` instead. Render:
  `web/src/components/views/intelSource.ts` (`isVendorSourced`/`vendorLabel`, + test) +
  `ActorProfile.tsx` — distinct "Vendor-reported" badge (not "seeded"), "Reported TTPs"
  panel, unverified/not-a-government-advisory copy with named+linked sources, no
  `note_image` on the vendor path, CISA/#StopRansomware wording structurally isolated to the
  gov path. CVE-less vendor entries (Kazu, Coinbase Cartel) render honest-empty. Seed:
  `data/ransomware_intel.json` now 16 groups (11 gov + 5 vendor). Files also touch
  `types.ts`, `tests/test_validate.py`. (`3207beb`)
- **Post-review honesty fix** — dropped Coinbase Cartel's `shinysp1d3r` from tools: an
  in-development, never-deployed encryptor, not a telemetry hunt-target. (`784969d`)
- **Backlog cleanup** — vendor-blog Tier-3 decision marked done in `BACKLOG.md` (`6ef8462`);
  separately, the two CI backlog items (Node-20→24 bump, `concurrency:` group on
  `collect-and-deploy`) verified **already present** in
  `.github/workflows/collect-and-deploy.yml` — stale backlog notes, no code change, marked
  done (`991d126`).

**Verified:** independent compliance reviewer fetched primary vendor pages (Check Point,
MITRE ATT&CK G1032, Group-IB, FortiGuard, Halcyon, Red Piranha, Securelist) and confirmed
every shipped fact real + atomic; the two large tool lists (INC Ransom 8, The Gentlemen 7)
are genuine cross-corroborated reordered subsets, not wholesale copies (The Gentlemen: only
1 of 7 items even overlaps Check Point's 26-item list) — approved. Gates: pytest 153, vitest
809, build/lint/tsc clean. Deployed live and live-verified on socdesk.io.

**Open / next:** taste call on renaming the "Overview" tab (candidates: Cockpit/Surface,
tied to the "Live threat surface" kicker) still open in `BACKLOG.md`.

---

## 0-RECENT — 2026-08-25 (session — nav/IA simplification, 3-lens profile polish, HC3 2nd intel source, copy audit — all shipped + deployed live)

**Shipped:**
- **Monogram fallback fix** — `web/src/components/views/ActorProfile.tsx`. The favicon
  proxy answers "no icon" with a 1x1 transparent PNG — a SUCCESSFUL image load, so the
  client's onError→monogram fallback never fired and victim rows showed a blank square
  (live-observed: 8/17 Qilin victim rows). Fixed via onLoad naturalWidth≤1 → monogram.
  (`ea68e90`)
- **Nav/IA simplification** — dropped the Analyzer top-nav tab (route kept deep-linkable —
  the omnibar IS the analyzer, verified byte-identical), added a sample-command omnibar
  chip (`Overview.tsx`; `GlobeHero3.tsx` is now dead code) + an "Expand →" link on the
  inline analyzer result to `/analyzer#q=`; renamed Profiles→**Threat Intelligence**;
  retired the Desk→Actors tab (ProfileDirectory is its superset — deleted
  `ActorsView.tsx`/`ActorsRoute.tsx`); renamed Networks→**ISP Abuse Leaderboard**; dropped
  the Toolbelt tab (deleted `ToolbeltView.tsx`/`ToolbeltRoute.tsx`). Final nav: **Overview ·
  Desk · Threat Intelligence**. Driven by an external UX PDF
  (`SOCDesk-Analyzer-Retest-and-UX-2026-08-25.pdf` §4) whose regression scorecard was pure
  verification (all 2026-08-24 analyzer fixes confirmed live); its 2 "residual nits"
  (vssadmin evidence 'v'-clip, cmd-var 'text luck') were already fixed by the prior
  analyzer-hardening session (`shared/analyzer/techniques.ts` look-back, `314a91b`) — cut
  from scope, vssadmin clip re-confirmed fixed live. Files: `web/src/App.tsx`,
  `components/cockpit/ResultRegion.tsx`, `components/palette/commands.ts`,
  `components/views/ProfileDirectory.tsx`, `components/views/profiles.ts`,
  `routes/ActorProfileRoute.tsx`, `routes/DataDeskRoute.tsx`, `routes/Overview.tsx`.
  (`b5582e2`)
- **3-lens profile refinements** — actor-name as page H1 (+ "Threat profile" kicker),
  ATT&CK-id badge dedup, timeline de-stretch + single reserved-accent bar, RaaS inline note
  (was button-like pill), Initial-Access panel promoted above Activity, hero-claim-count
  dedup, "ON-HOST SIGNATURES" copy. `ActorProfile.tsx`, `ActorProfileRoute.tsx`,
  `ViewFrame.tsx`. (`1a23a88`)
- **Landing + cleanup** — daily-summary climbing/KEV CVEs now clickable into `/lookup`
  (`CveLink` promoted to shared `overview/board-ui.tsx`); new **ISP Abuse Leaderboard**
  Overview landing section (`overview/NetworkAbuseLeaderboard.tsx` + `aggregations.ts`
  `topNetworks` + test, mirrors the RansomwareActivity idiom, non-flagship,
  abuse.ch·community attributed); README/`docs/REPO-MAP.md` doc-staleness fixed;
  `TimelineChart` overflow guard (`.slice(-26)`). (`08780db`)
- **HC3 active-crew depth** — added **HHS HC3** as a 2nd public-domain intel source; schema
  `advisory.url`/`note_image` widened from CISA-only to gov-only
  `^https://([a-z0-9-]+\.)*(cisa|hhs)\.gov/`. Seeded **Qilin** (aliases Agenda, first_seen
  2022-07, RaaS, tools Cobalt Strike·PsExec·SecureShell) from the TLP:CLEAR HC3 Qilin
  threat profile (ID 202406181500, 2024-06-18) — an active RaaS crew CISA has no dedicated
  #StopRansomware advisory for. Render made source-aware (`web/src/components/views/
  intelSource.ts` + test): badge ("HHS HC3 seeded" vs "CISA seeded"), attribution, and
  advisory-link all derive from the advisory host. Seed now 11 (10 CISA + 1 HC3).
  Independently review-verified against the real HC3 PDF (AHA mirror — hhs.gov PDFs 403 to
  bots) — no fabrication. Spike: `docs/research/vendor-sourcing-spike.md`. (`eb4eff8`)
- **Copy audit + polish** — opus audit verdict: site copy clean/analyst-grade, zero
  slop-word hits in shipped UI. 4 tweaks shipped: de-redundant daily-summary header
  (`SituationalBoard.tsx`), trimmed hero "watch it land live" flourish (`Overview.tsx`) +
  feed "security intelligence, organized" throat-clear (`FeedRoute.tsx`), palette "Data
  desk"→"Desk" (`commands.ts`). Audit: `.superpowers/sdd/copy-audit.md`. (`32477d5`)

**Context:** preceded same session by the RANSOMWARE PROFILE REBUILD (attributed
named-victim layer w/ logos via same-origin favicon proxy, digest-carries-claims coverage
fix, re-seed by activity + provenance, associated-malware, staleness guard, 3-lens
SOC/Data/UX review — commits `6fabcb5`..`2d82809`; no dedicated HANDOFF block exists for it,
referenced here rather than duplicated).

**Deploy:** each item pulled+pushed individually (`git pull --rebase origin main` → push →
`gh workflow run collect-and-deploy`; the workflow is schedule-triggered, NOT on-push — note
local commit hashes above differ from any hashes cited mid-session, since the rebase
rewrites them against interleaved cron `data: refresh snapshots` commits) and live-verified
on socdesk.io, except the copy-polish tweak (`32477d5`) — deploy in flight at session-report
time.

**Verified (per session report):** pytest 150, vitest 804, build/lint/tsc clean on the
shipped tree.

**Open / next:** two owner decisions recorded in `BACKLOG.md` — (a) vendor-blog Tier-3 depth
for crews with no HC3/CISA profile (DragonForce, INC Ransom, Coinbase Cartel, Kazu, The
Gentlemen, MetaEncryptor — needs explicit yes, pushes past public-domain); (b) taste call on
renaming the "Overview" tab (candidates: Cockpit/Surface, tied to the "Live threat surface"
kicker).

---

## 0-RECENT — 2026-08-25 (session — analyzer-hardening Phase 4: cmd half + robustness + IOC hygiene, branch built, NOT merged)

**Lane:** analyzer hardening per the external analyzer review (2026-08-24), final phase.
Phase 4 goal: the cmd half + robustness + IOC hygiene (review 2.5, 2.6, 2.7). Branch
`feat/analyzer-hardening`, commits `149f59e..fcd819f`, **NOT merged**.

**Shipped:**
- **cmd `set`/`%var%` reassembly** — `shared/analyzer/cmdvars.ts` (new) + `preprocess.ts`.
  Resolves `set`/`%var%` reassembly, `%COMSPEC:~n,m%` substring (incl. negative offsets),
  and `!VAR!` delayed expansion, invoked only from the cmd branch after caret
  de-obfuscation. Bounded (≤64 vars, depth-1, no recursion). Resolves
  `set x=power&&set y=shell&&%x%%y%` → `powershell` — review's "biggest scope gap" (2.5).
  (`25c8f62`, test coverage for delayed-expansion/unset-var guarantees `e0e7f00`)
- **`cmd-var-obfuscation` signal** — `shared/analyzer/techniques.ts` + `bullets.ts`. Weak
  signal (T1140/T1027): fires on a `set X=` + `%X%`/`!X!` reference, scanning ALL set
  declarations (not just the first, closing a chained-decoy miss), paired with an
  opaque-tier honesty bullet mirroring `wsh-not-resolved` so the obfuscation surfaces even
  when reassembly only half-resolves. Bare `%PATH%` stays silent. (`b5210aa`, all-declarations
  fix `d5b3e00`)
- **Debounced input + honest size cap** — `shared/analyzer-ui/useDebounced.ts` (new) +
  `web/src/routes/PowerShellAnalyzer.tsx` + `shared/analyzer/report.ts`. Input debounced
  ~200ms (the `usePsAnalysis` "debounced-by-caller" contract is now true); `analyze()` caps
  raw input at 64 KB, surfacing an opaque "input truncated" notice + partial state rather
  than silently truncating or blocking the main thread (2.6). (`7bd9674`)
- **Bounded `inflate()` output** — `shared/analyzer/fold.ts`. Reads the decompressed stream
  incrementally with a 2 MiB output cap (cancels the reader past the cap, returns null),
  guarding against a gzip-bomb literal that previously expanded unbounded (2.6). (`8449847`)
- **IOC-extraction hygiene** — `shared/analyzer/extract.ts` (2.7). Widened the binary/data
  denylist (json/xml/txt/log/csv/…) so `-OutFile data.json` no longer yields a bogus domain
  IOC; added a .NET-member shape guard gated on the leaf label not being a common TLD, so
  `system.io.memorystream` is excluded while real domains (`io.adafruit.com`,
  `microsoft.fake-support.ru`) still extract. (`7adc72d`, TLD-gate fix `d41eb6b`)
- **Intent-classification boundary fix** — `shared/intent.ts` (2.7). A lone malware filename
  (`mimikatz.exe`, `kernel32.dll`) now classifies as `command` → local analyzer, never
  `/api/enrich`; TLD-lookalike domains (`finger.io`, `wmic.io`, `certutil.info`) still
  classify as `indicator`. (`fcd819f`)

**Headline:** all 8 findings of the 2026-08-24 external review are addressed across 4
phases — failure legibility (no more blank on unprocessable input), decode-ladder
expansion, detection-gap closure (review CRITICAL 2.1 closed end-to-end on sample 6), and
now the cmd half + robustness + IOC hygiene.

**Verified:** Phase-4 gate green — `npm --prefix web run build` PASS, `cd web && npx
vitest run ../shared` 514/514, `cd web && npx vitest run src` 152/152 (all three re-run
and confirmed this session at branch HEAD `fcd819f`).

**Open / next:** whole-branch final review of `feat/analyzer-hardening` (owner), then merge
decision. Not deployed — branch unmerged.

---

## 0-RECENT — 2026-08-25 (session — analyzer-hardening Phase 3: detection-gap closure, branch built, NOT merged)

**Lane:** analyzer hardening per the external analyzer review (2026-08-24), continuing
Phase 2 (below). Phase 3 goal: close the detection gaps the review found missing (2.2,
2.4) and fix the ClickFix over-fire (2.4), holding the anti-cry-wolf/specificity doctrine.
Branch `feat/analyzer-hardening`, commits `8c10662..cbec78e`, **NOT merged**.

**Shipped:**
- **`shadow-recovery-tamper` rule (T1490)** — `shared/analyzer/techniques.ts` +
  `bullets.ts`, baseSpecificity near-dispositive (`8c10662`, trigger-fabrication/bullet
  slash-hedge fix `c970b78`). Fires on vssadmin delete shadows / resize shadowstorage,
  wmic shadowcopy delete, wbadmin delete catalog|systemstatebackup, bcdedit
  recoveryenabled no / bootstatuspolicy ignoreallfailures — destructive verb must
  co-occur with its object (bare `vssadmin list` stays silent). Emits split,
  sub-fact-specific bullets (shadow-copy-delete vs recovery-disable, no slash-hedge).
  Review sample 3 (AMSI + vssadmin) now flags shadow destruction too.
- **`disk-dropper` rule** — `shared/analyzer/techniques.ts` + `bullets.ts`,
  baseSpecificity strong (`3569b28`, exec-sink false-positive fix `73b42e4`). A to-disk
  fetch (DownloadFile / -OutFile / Start-BitsTransfer / curl -o /
  certutil -urlcache+-split) co-occurring with a local-exec sink (Start-Process / saps /
  Invoke-Item / separator-anchored `& payload.exe`) now flags — a staple dropper that
  previously read as benign (review 2.2). Discriminator bounded: a fully-qualified fetch
  tool name at corpus start (certutil.exe/powershell.exe) and the "ascii" substring do
  NOT false-fire.
- **ClickFix trait-gating (review 2.4)** — `shared/analyzer/techniques.ts` (`4b60ee0`). A
  plain -enc/hidden fetch+IEX cradle no longer gets a ClickFix / paste-and-run verdict —
  ClickFix now requires a real paste-and-run trait (fake-CAPTCHA decoy phrase, --verify
  decoy, conhost --headless, or an mshta lure). Review samples 1 & 4 now read as
  download-cradle only, no misdirecting ClickFix label. The -w/-nop cluster still
  contributes to evasion-cluster.
- **`offensive-tool` rule** — `shared/analyzer/techniques.ts` + `bullets.ts`,
  baseSpecificity near-dispositive (`cbec78e`). Fires on named offensive tooling
  (invoke-mimikatz, sekurlsa::, dumpcreds, rubeus, invoke-kerberoast, safetykatz). Closes
  the loop on review sample 6: after Phase 2 it DECODED to `Invoke-Mimikatz -DumpCreds;
  net user hacker /add` but had no signal — it now ALSO characterizes as
  high-confidence-malicious.

**Headline:** review CRITICAL finding 2.1 (malicious ≡ blank ≡ benign) is now closed
end-to-end — sample 6, which originally rendered completely blank, both fully decodes
(Phase 2) and flags red high-confidence-malicious (Phase 3).

**Doctrine note:** all new detections hold the specificity/anti-cry-wolf rules —
near-dispositive tiers only where there's no legitimate use, benign-twin discriminators
on every rule, and every `Signal.trigger` cites a real matched substring (three separate
trigger-fabrication risks caught and fixed in review before merge, see `c970b78`).

**Verified:** Phase-3 gate green — `npm --prefix web run build` PASS; `cd web && npx
vitest run ../shared` 469/469; `cd web && npx vitest run src` 152/152 (all three re-run
and confirmed this session at branch HEAD `cbec78e`).

**Contributor note:** a Windows Defender exclusion for the repo path is required — the
analyzer's own test fixtures contain live malware signatures and get quarantined
otherwise. Follow-up: document this fully in `docs/OPERATIONS.md` (not yet done).

**Open / next:** Phase 4 (cmd reassembly + robustness + IOC hygiene), then merge decision
on `feat/analyzer-hardening` (owner). Not deployed — branch unmerged.

---

## 0-RECENT — 2026-08-24 (session — analyzer-hardening Phase 2: decode-ladder expansion, branch built, NOT merged)

**Lane:** analyzer hardening per the external analyzer review (2026-08-24), continuing
Phase 1 (below). Phase 2 goal: convert the opaque residues Phase 1 made honest into real
decode layers, so the analyzer actually reads the common obfuscated second stages. Branch
`feat/analyzer-hardening`, commits `20bc8b1..0c201cb`, **NOT merged**.

**Shipped:**
- **Plain base64 → text decode** — `shared/analyzer/report.ts` (`20bc8b1`). Decodes
  non-compressed base64 in the embedded-literal loop (UTF-16LE/UTF-8 sniff, gated on
  decode-API co-occurrence or length ≥32; non-printable results fall through to the residue
  detector). Core review-2.1 fix: review sample 6 (an `IEX([Convert]::FromBase64String(...))`
  Mimikatz stager) now fully decodes instead of rendering blank/opaque
  (`shared/analyzer/__tests__/review-samples.test.ts:13`, "#6 plain-base64 inner stage: now
  DECODED (Phase 2)").
- **Four constant-folds chained into `resolve()`'s fixpoint** — `shared/analyzer/resolve.ts`,
  all token-aware (a construct's text inside a quoted string literal is never reinterpreted
  as code):
  - `foldCharArray`: `[char]73` / `([char]73,...) -join ''` → literal (`0242c06`, literal-safety
    fix `d15f736`).
  - `foldFormat`: `'{0}{1}' -f 'a','b'` → `'ab'`, plain `{N}` only, format-spec/variable-arg
    left untouched (`257d874`).
  - `foldReplace`: `'IqqEqqX' -replace 'qq',''` → `'IEX'` and `.Replace()`, ReDoS-guarded —
    folds only metacharacter-free patterns via split/join, never `new RegExp` on attacker text
    (`0c50c29`); guard-rejected clauses consumed atomically so a chained clause is never
    dropped (`2de5d17`).
  - `foldReverse`: `'XEI'[-1..-3] -join ''` → `'IEX'`; full-reversal guard rejects partial
    ranges (N must equal the subject's exact length) rather than mis-folding a slice
    (`0c201cb`).
  - Not folded (deferred, both still caught opaque by the residue detector): `[array]::Reverse`
    and computed-bound reversal `$s[-1..-($s.Length)]` — need variable-mutation tracking
    outside resolve.ts's straight-line/literal-only doctrine.

**Design note:** every fold matches on the lexer token stream, not raw text — preserves the
literal-safety guarantee (a `-replace`/`[char]` construct inside a quoted string is data,
never code). Two early raw-regex attempts were caught in review and rewritten token-aware
(one injected a NUL byte into a decoy string; one silently dropped a chained `-replace`
clause) — see the `d15f736` and `2de5d17` fix commits above.

**Verified:** Phase-2 gate green — `npm --prefix web run build` PASS; `cd web && npx vitest
run ../shared` 422/422; `cd web && npx vitest run src` 152/152 (all three re-run and confirmed
this session at branch HEAD `0c201cb`). Not deployed — branch not merged, Phases 3-4 of the
hardening plan still to come.

**Open / next:** Phase 3-4 of the hardening plan, then merge decision on
`feat/analyzer-hardening` (owner).

---

## 0-RECENT — 2026-08-24 (session — analyzer-hardening Phase 1: failure legibility + honest narratives, branch built, NOT merged)

**Lane:** analyzer hardening per the external analyzer review (2026-08-24) — spec
`docs/superpowers/specs/2026-08-24-analyzer-hardening-design.md`, plan
`docs/superpowers/plans/2026-08-24-analyzer-hardening.md`. Phase 1 goal: the
analyzer must never render blank on input it couldn't fully process, and must
never fabricate behavior. Branch `feat/analyzer-hardening`, 6 tasks / commits
`3740555..476ddad`, **NOT merged**.

**Shipped:**
- **Opaque-residue detector** — new `shared/analyzer/residue.ts` (`3740555`,
  tightened `a5dc80d`). Scans the deepest decoded text for encoding constructs
  that produced no decode layer: unresolved base64+decode-API, dynamic-exec
  over `[char]`/`-join`/`-replace`/`GetString`, cmd `%VAR:~n,m%` incl. negative
  offsets. Reuses the canonical FETCH vocab from `techniques.ts` to avoid
  over-firing.
- **Never-blank rendering** — `shared/analyzer/report.ts` `analyze()` wired
  each residue finding into an opaque `DecodedLayer` (flips
  `confidence.state` to `'partial'` via existing count logic) + an opaque
  "Could not resolve" bullet (`09abae1`). Review sample 6 (plain-base64
  Mimikatz stager) now renders an opaque partial instead of blank.
- **Partial-decode escalation notice** — new
  `shared/analyzer-ui/PartialDecodeNotice.tsx`, neutral/periwinkle band shown
  when `state === 'partial'`, wired into the shared `AnalyzerResult` surface
  (reaches web `/analyzer`, cockpit, extension) (`6eac498`). No verdict hue —
  reserved-colour law honored. Same commit additively extends
  `web/vitest.config.ts` to discover `.tsx` tests.
- **Abuse-only LOLBin gating** — `shared/analyzer/lolbins.ts` tightened
  regsvr32/rundll32/msiexec/installutil context tokens to real abuse-only
  discriminators, dropping bare `/u`, `shell32.dll`, `/q`, `.exe` (`a9861d3`).
  Stops matching benign admin invocations.
- **Honest bullets** — `shared/analyzer/bullets.ts` regsvr32/rundll32 bullets
  are now variant-aware: "Squiblydoo" only renders when `/i:http` or `scrobj`
  matched, otherwise a plain line (`0299f66`). Kills the fabricated narrative
  on benign `regsvr32 /u` (review finding 2.3, sample 7).
- **Ratcheting fixture** — new
  `shared/analyzer/__tests__/review-samples.test.ts` pins the review's 7
  samples as an integration fixture whose expected values are deliberately
  updated as later phases land (sample 6 flips to fully-decoded in Phase 2)
  (`bff4059`, strengthened `476ddad`).

**Verified:** Phase-1 gate green at HEAD `476ddad` — `npm --prefix web run
build` PASS; `cd web && npx vitest run ../shared` 395/395; `cd web && npx
vitest run src` 152/152. Not yet deployed — branch not merged, Phases 2-4 of
the hardening plan still to come.

**Open / next:** Phase 2 (full decode of sample 6 + remaining plan phases),
then merge decision on `feat/analyzer-hardening` (owner).

---

## 0-RECENT — 2026-08-24 (session — TI-uplift Track A: 5 cheap decoupled TI-parity wins, branch built, NOT merged)

**Lane:** TI-analytics uplift toward MS Threat Intel parity — **Track A** = 5 cheap,
decoupled, owner-approved wins (see memory `socdesk-ti-uplift`). Branch
`feat/ti-uplift-track-a` (base `main`), **5 commits, NOT merged**. Extension analyzer
parity re-verified (dist rebuilt this session — bundles the same shared
`@socdesk/shared` analyzer + the updated shared `EscalationCard`).

**Shipped (branch `feat/ti-uplift-track-a`, not merged):**
- **Overview "what changed" panel** — `c17684e`. `pipeline/history.py` already emitted
  `epss_movers`/`new_kev` but only totals/volume rendered. New `WhatChanged.tsx` (two
  `BoardPanel`s) on the Overview/`SituationalBoard` under the stat strip; `trendRows.ts`
  pure helpers (+test). Fixed the WRONG `EpssMover` type in `web/src/components/views/types.ts`
  (declared `{epss,prev}` + stale "emits empty array" comment; producer actually emits
  `{from,to,delta,kev}`). Files: `web/src/components/overview/{WhatChanged.tsx,trendRows.ts,trendRows.test.ts,SituationalBoard.tsx}`,
  `web/src/components/views/types.ts`.
- **KEV due-date + required-action → overdue flag** — `4a018eb`. `collectors/kev.py` now
  carries `dueDate`/`requiredAction` → `pipeline/cves.py` → `schemas/cves.schema.json` →
  `Cve` type. `cveToVerdict` (`web/src/routes/lookupModel.ts`) decides "overdue"
  deterministically vs the snapshot date, emits `['Remediation due',…]`/`['Status','Overdue']`/
  `['Required action',…]` facts + an overdue clause on CISA's finding; `EscalationCard` renders
  an amber "KEV remediation overdue" chip (`kevOverdue` helper). Lit up PRE-BUILT dead slots:
  CVE hero "Action due" cell (`heroes.tsx:511`, `cardModel.due` = pick `'action due'|'due'|'remediation due'`,
  `model.ts:287`) and copy-card PNG "ACTION DUE" (`drawVerdict.ts:904`). Closes the KEV
  due-date gap open in `BACKLOG.md` since 2026-08-18. Files: `collectors/kev.py`,
  `pipeline/cves.py`, `schemas/cves.schema.json`, `tests/fixtures/kev/feed.json`,
  `tests/test_kev.py`, `tests/test_cves.py`, `web/src/components/views/types.ts`,
  `web/src/routes/lookupModel.ts`, `web/src/routes/lookupModel.test.ts`,
  `shared/verdict-cards/EscalationCard.tsx`.
- **Gate the "tracked adversary" bonus on the curated dict** — `250ae72`. `relevance.py`
  awarded +8 for ANY non-empty `entities.actors`; `ransomwarelive.py` injects every leak-site
  group there (kept — digest grouping in `publish.py:61` depends on it), so ~half the feed
  inflated by 8 + the why-row mislabelled unknown groups as tracked. Now `score_item`/`apply_scores`
  take a `tracked_actors` set (new `pipeline/entities.py::tracked_actor_set`, lowercased
  `data/entities/actors.json`, 30 names); `publish.py` passes it. Text-extracted actors
  unaffected (already dictionary-sourced); only untracked ransomware groups lose the boost;
  majors in the dict (Akira/ALPHV) keep it. Files: `pipeline/relevance.py`,
  `pipeline/entities.py`, `pipeline/publish.py`, `tests/test_relevance.py`.
- **Per-browser vuln watchlist** — `d1dfe18`. `localStorage` vendor/product list on
  `VulnsView`: periwinkle marker on matching rows, "Watchlist only" filter, inline
  removable-chip editor, SSR-safe (mirrors `lib/contributorSeen.ts`), never re-ranks, no
  PII/never transmitted (COMPLIANCE bars server-side SHARED watchlists only). Pure helpers
  unit-tested. Files: `web/src/components/views/{watchlist.ts,watchlist.test.ts,VulnsView.tsx}`.
- **Analyst-guide drift fix** — `9095aa4`. Reframed "The feed" around the live briefing
  `FeedView` (was described as the legacy `site/` keyboard-triage work queue); Legacy-bannered
  the removed interactions (Newest toggle + "N new since last visit", j/k/r/n triage, right
  detail panel, Export JSON) and the shift-handoff section; watchlist paragraph now true via
  `d1dfe18`; relocated the "what changed"/trends description to the Overview per `c17684e`.
  File: `docs/ANALYST-GUIDE.md`.

**Verified:** full suite green at HEAD `9095aa4` — pytest **122**, vitest **614** (52→53
files), `npm --prefix web run build` + lint OK, extension build OK. Per-commit file lists
cross-checked against `git show --stat` (all match). Working tree clean.

**Decisions worth recording:**
- Extension is at analyzer parity **by construction** (renders the same shared
  `AnalyzerResult`/`usePsAnalysis` as web `/analyzer` + cockpit); dist rebuilt this session.
- Overdue is computed **at assembly** (`cveToVerdict`, which has the snapshot as the honest
  as-of ref), **never in the card** (no clock); the card only reads the fact → renders the
  chip. Copy-card PNG intentionally omits the chip cluster (surfaces the date via its
  ACTION DUE fact cell) — no parity gap.
- **Track B** (ransomware coverage — e.g. Nitrogen missing in `ransomwarelive.py` — richer
  profiles, the campaign-report/TI-parity page, and the CARL-KQL vetting prerequisite) is
  **NOT started**; needs its own brainstorm→spec. See memory `socdesk-ti-uplift`.

**Open / next:** merge decision on `feat/ti-uplift-track-a` (owner). Then Track B (above).

---

## 0-RECENT — 2026-08-24 (session — program complete: B2 + Phase 4 merged, deployed, activated + verified live)

**Supersedes** the `## 0-RECENT` B2/Phase 4 blocks below, which described them as
"BUILT, NOT merged" — that is now stale. Both merged to `main`, deployed, and
owner-activated this session.

**Shipped, all on `main`:**
- **Node 20→24 CI bump** — `checkout`/`setup-node`/`setup-python@v7`,
  `wrangler-action@v4` (CLI pinned v3), build on Node 24. `0536a90`. Live.
- **B2 enrich/write-path abuse-hardening** — merged to `main` (linear/
  fast-forward from `feat/enrich-abuse-hardening`, base `7a19730`; see
  `## 0-RECENT` below for the L1/L2/L3 design). Deployed, then **fully
  ACTIVATED**: owner bound a Cloudflare KV namespace as `env.KV` (redeployed)
  and added a WAF Rate-Limiting **Block** rule on `path starts_with
  /api/enrich` at **40/window**. Verified live: normal `/api/enrich` lookups
  return 200 with `Cache-Control: public, max-age=900`; an 8-request burst all
  200 (under the 40 cap).
- **IOC-reporting Phase 4 — ISP/ASN abuse leaderboard** — merged via
  `053f97f` ("Merge feat/asn-abuse-leaderboard"). Deployed, then **LIVE +
  POPULATED**: owner added `IPINFO_TOKEN` as a **GitHub Actions** secret (it
  was previously only a Cloudflare Function secret, so the pipeline had been
  calling ipinfo unauthenticated and getting no `org`/ASN back). Served
  `data/state/asn_leaderboard.json` now has **5 networks, 8 abusive IPs, 0
  unattributed**: AS14061 DigitalOcean, AS14618 Amazon, AS60729 Stiftung
  Erneuerbare Freiheit (community/Tor), AS57269 DIGI SPAIN, AS9370 SAKURA.
  Networks tab at `/desk#networks`.
- **Domain→IP pivot (reputation fix)** — `85520e3`. VT `last_dns_records`
  A-record surfaces a "Hosting IP `<ip>` — check reputation" accent link on
  domain cards, linking to `/#q=<ip>`. Live. (The other planned reputation
  fix, MalwareBazaar-on-IP, was confirmed a no-op — that source is hash-only,
  nothing to wire.)

**CI incident + fix (recurring trap, log prominently):** the "committed-
dataset is-empty" test trap bit again in Phase 4 —
`test_committed_empty_seed_is_valid` asserted the live committed
`asn_leaderboard.json` was empty; broke every deploy/cron once the pipeline
started populating it for real. Fixed in `5bc0e44`: assert schema-validity via
`validate_payload(...)`, not emptiness; test the empty shape via the
builder's own output instead. Same class of bug as the earlier Phase 3
`test_community` fix (`1cd72de`). **Rule going forward:** any committed-
dataset feature's tests must never assert the live committed file's exact/
empty content — only that it validates against its schema.

**Known ops fragility (non-blocking, not fixed this session):** the deploy
workflow's "Commit state snapshots" step does `git pull --rebase` and can
CONFLICT on `data/state/*.json` when a manual run overlaps a cron run — one
run fails, the next recovers, last-known-good data is preserved throughout.
Harden candidate: `concurrency: cancel-in-progress` on the workflow, or
`-X theirs` on that rebase.

**Verified:** live HTTP checks on `/api/enrich` (200 + cache header, burst
under cap) and on the served `asn_leaderboard.json` (5 networks / 8 IPs / 0
unattributed) as above. Build/test gates from the pre-merge sessions (vitest
592, pytest 118, `npm --prefix web run build` clean, eslint 0) carried
forward unchanged by the merges.

**Open / next:** nothing pending on the build side. Candidates: Phase 5
trends, Phase 6 upstream push, enrich B3 own-OSINT dataset, give-back
honeypot, the workflow ops-harden above.

**Docs:** close-out spec/plan context in
`docs/superpowers/specs/2026-08-24-*` and
`docs/superpowers/plans/2026-08-24-*` (see `## 0-RECENT` blocks below for the
per-feature design detail this block summarizes).

---

## 0-RECENT — 2026-08-24 (session — B2 enrich abuse-hardening BUILT, NOT merged)

> Branch `feat/enrich-abuse-hardening` (base `7a19730`), built via 8-task SDD +
> a clean whole-branch review (opus) = SHIP. **NOT merged** — owner finish-menu
> decision pending. Ships dark until owner activates KV binding + WAF rule.

**Shipped (branch, not merged):** three defense layers on the enrich/report
write paths, everything fail-open (KV unbound/throws → serves normally).
- **L1** — in-isolate per-IP rate-limit on `/api/enrich`. Module-scope `Map`s,
  zero KV writes, bare 429 on flood; cache-hits bypass the limiter entirely.
  `lib/enrich/ratelimit.mjs`.
- **L2** — per-source daily KV write budget. Writes coalesced (~1 per 25
  calls); a spent source degrades to `blocking:false` (cacheable) rather than
  failing; counted only for sources actually dispatched, not from `errors[]`.
  `lib/enrich/budgets.mjs`; threaded through `planSources`/`enrich()` in
  `lib/enrich.mjs` as an additive `budgetBlocked` field.
- **L3** — per-IP daily report cap on `/api/report`, defense-in-depth atop
  existing Turnstile + account-cap + dedupe; counts only genuine inserts.
  `lib/reporting/ratelimit.mjs`.
- Wrappers: `functions/api/enrich.js`, `functions/api/report.js`.
- Docs: `docs/OPERATIONS.md` — owner KV + WAF setup and dogfood steps.

**Key decision (caught in spec review, `fc019df`):** original design used a
per-IP KV latch, which is self-defeating — a rotating-IP botnet would exhaust
the shared free-tier KV write quota (1,000/day) via per-distinct-IP writes,
fail-opening the L2 budget counter and exposing every upstream API key. Fixed:
**L1 moved in-isolate-only**, a **Cloudflare WAF Block rule** on
`/api/enrich` added as the primary distributed-flood shield, **L2 as the real
upstream guarantee**. Total KV writes now bounded (~250-300/day) regardless of
IP cardinality.

**Owner-config required to activate (currently dark):** bind a Cloudflare KV
namespace as `env.KV`; add a WAF Rate-Limiting Block rule on
`path starts_with /api/enrich` (Block, ~10s window). Both steps documented in
`docs/OPERATIONS.md`.

**Deferred minors (non-blocking, whole-branch review):** dead `nameToKey`
helper; unbounded in-isolate maps in `ratelimit.mjs` (opportunistic-prune is a
future tune, not a leak at current traffic).

**Verified:** vitest 592 green, `npm --prefix web run build` clean, eslint 0,
wrapper files pass `node --check`.

**Commits (base `7a19730`):** `0241b64`, `93aba6f`, `680ef07`, `64b9667`,
`2cbd35b`, `449515a`, `2f138cc`, `36970f0`.

**Spec/plan:**
`docs/superpowers/specs/2026-08-24-enrich-abuse-hardening-design.md` (§11
amendments), `docs/superpowers/plans/2026-08-24-enrich-abuse-hardening.md`.

**Open / next:** NOT merged — owner finish-menu decision pending on
`feat/enrich-abuse-hardening`. Once merged: bind KV + add WAF rule per
`docs/OPERATIONS.md` to take it live.

---

**Also shipped 2026-08-24 (branch `feat/asn-abuse-leaderboard`, base
`0556790`) — IOC-reporting Phase 4: ISP/ASN abuse-leaderboard.** Built via SDD
(7 tasks) + clean whole-branch review = SHIP. **NOT merged** — owner
finish-menu decision pending. Goes LIVE-visible on the first pipeline run
after deploy (no owner-config required).

**Shipped:**
- `pipeline/asn.py` — resolves ASN+ISP per abusive IP from IPinfo's `org`
  field, **reusing the geolocation call the pipeline already makes**
  (`geo.py` fetched `org` and discarded it — no new API cost beyond new-IP
  cache misses). Cache-first via committed `data/state/asn_cache.json`
  (mirrors `geo_cache.json`).
- Aggregates the UNION of `community_reports.json` ∪ `threat_ips.json`
  abusive IPs into committed `data/state/asn_leaderboard.json` (networks
  ranked by distinct-abusive-IP count; per-row asn/isp/country/ip_count/
  report_count/categories/sources/examples).
- Read-only **"Networks" tab** in the Data Desk (`/desk#networks`) —
  `AsnLeaderboardView.tsx` + `AsnLeaderboardRoute.tsx`, static-asset via
  `useStateData`, no D1/API/account.
- Wiring: `run_pipeline.py` builds the leaderboard after community+threat,
  before the gate; asn_cache load/persist. Schema registration:
  `pipeline/validate.py`.
- Hard no-PII: twice-fenced — `asn.py` never touches D1/github_id; inputs are
  already PII-stripped; schema `additionalProperties:false` at both envelope
  and row levels.
- OSINT framing: "reported/blocklisted abuse volume hosted on a network, NOT
  a verdict on the operator"; per-network `sources[]` keeps a community
  allegation distinguishable from an abuse.ch published blocklist.
- Free-tier: reuses `IPINFO_TOKEN`, no new secret; cost bounded to new
  distinct IPs.
- Honest degradation: unresolvable IP → `unattributed`, never a fabricated
  ASN; builder returns `None` → gate keeps last-known-good, re-stamped.

**Files created:** `pipeline/asn.py`, `schemas/asn_leaderboard.schema.json`,
`data/state/asn_leaderboard.json` (empty seed), `data/state/asn_cache.json`
(`{}`), `tests/test_asn_leaderboard.py`, `tests/fixtures/asn/org_parity.json`,
`web/src/components/views/AsnLeaderboardView.tsx`,
`web/src/routes/AsnLeaderboardRoute.tsx`.
**Modified:** `run_pipeline.py`, `pipeline/validate.py`,
`web/src/components/views/types.ts`, `web/src/routes/DataDeskRoute.tsx`
(Networks tab), `README.md`.

**Commits (base `0556790`):** `8a4e52c`, `5e72310`, `603e3ed`, `cbed940`,
`e4d7238`, `7f4d8bf`, `6a971b6`.

**Verified:** pytest 118 · `npm --prefix web run build` clean · eslint 0 ·
vitest 592.

**Deferred minor (non-blocking):** schema `sources.maxItems` is 3
(intentional; values drawn from a 2-item enum via a set, non-exploitable);
optional `uniqueItems` hardening on sources/categories.

**Spec/plan:**
`docs/superpowers/specs/2026-08-24-asn-abuse-leaderboard-design.md`,
`docs/superpowers/plans/2026-08-24-asn-abuse-leaderboard.md`.

**Open / next:** NOT merged — owner finish-menu decision pending on
`feat/asn-abuse-leaderboard`.

## 0-RECENT — 2026-08-23 (session — Lookup↔Cockpit consolidation BUILT, NOT merged)

> Branch `feat/lookup-cockpit-consolidation` (base `1ec1c70`), built via 8-task
> SDD + a whole-branch review. The `/` Overview cockpit is now the single lookup
> surface; `/lookup` is retired. **NOT merged** — owner finish-menu decision
> pending.

**Shipped (branch, not merged):**
- Cockpit honors `#q=` deep-links: `useState(readLookupQuery)` seed + a
  hashchange/popstate sync effect. `Overview.tsx`, `0986bbf`.
- `/lookup` is now a **hard-redirect stub** — `LookupRedirect.tsx` →
  `window.location.replace('/'+hash)`, registered `nav:false` in `App.tsx`.
  `17db7798`. Hardened in `8436359` after a synthetic-popstate SPA redirect
  proved broken at cold mount (child `useLayoutEffect` fires before App's
  parent `useEffect` popstate listener attaches → blank page); the hard
  redirect reduces the cold-load path to the proven direct-`/#q=` load.
- Every `/lookup` referrer repointed to `/#q=` (Admin moderation pivot, palette
  `submitLookup`; removed the `view:lookup` palette row, folded its keywords
  into `view:overview`) or removed (the "Full analyst view →" link +
  `Overview.openFullView`). `09c0513`.
- Examples gallery folded into a collapsed `<details>` "See a sample card"
  disclosure in the cockpit idle state. `CockpitExamples.tsx`, `18e1a09`.
- Deleted `Lookup.tsx` (redundant three-register triptych, `09d041a`) and
  `AnalystVerdict.tsx` (strict subset of `EscalationCard`) + its `index.ts`
  export (`c9c9193`).
- `parseQ` extracted from `readLookupQuery` as a pure, unit-tested function
  (`5e58b1c`).
- **Also this session, already LIVE on `main`:** the cockpit Report button fix
  (`ResultRegion` gained `reportSlot`, commit `271a7fd`, deployed) — preserved
  by the consolidation.

**Key decisions:** analyst console + copy-card PNG preview dropped from web as
redundant (the escalation card is their superset); `CardCanvasPreview` kept for
the extension. Examples gallery collapsed on an owner call so it never
out-ranks the live SituationalBoard. `/lookup` retired behind a **hard**
redirect, not a synthetic-popstate SPA redirect (broken at cold mount, above).

**Verified:** whole-branch review (opus, browser-dogfooded) → FIX-THEN-SHIP:
the one blocker (cold-load blank) fixed in `8436359` and re-dogfooded live in a
browser (cold `/lookup#q=8.8.8.8` → `/#q=8.8.8.8`, full cockpit render,
innerText 2624). Now SHIP-clean. Confirmed: cockpit Report button survived;
data-boundary held (command `#q=` → zero `/api/enrich` calls); no
doctrine/colour/extension/analyzer-logic drift. Gates: vitest 562,
`npm --prefix web run build` clean, eslint 0.

**Commits (base `1ec1c70`):** `5e58b1c`, `0986bbf`, `17db7798`, `09c0513`,
`18e1a09`, `09d041a`, `c9c9193`, `8436359`.

**Spec/plan:**
`docs/superpowers/specs/2026-08-23-lookup-cockpit-consolidation-design.md`,
`docs/superpowers/plans/2026-08-23-lookup-cockpit-consolidation.md`.

**Open / next:** NOT merged — owner finish-menu decision pending on
`feat/lookup-cockpit-consolidation`.

## 0-RECENT — 2026-08-22 (session — IOC reporting UX polish MERGED + DEPLOYED live)

> Newest block. One unit shipped to `main`/live since session 8: the IOC-reporting
> UX-polish surface. Built via a 12-task subagent-driven-development run on branch
> `feat/reporting-ux-polish` (14 commits), rebased → fast-forwarded → pushed to
> `main`, branch deleted. `main` = `origin/main` = **`824054d`**. Whole-branch
> review (Opus) = CLEAN. 508 unit tests + `tsc` build + eslint green throughout.
> Deploy run `32566011115` succeeded; live bundle `index-yNquSVOS.js`.

### Shipped surfaces (`main`, LIVE)
- **AccountControl** — quiet-until-relevant contributor nav chip. Anonymous users
  render zero account DOM AND fire no `/api/report/mine` probe (gated on a
  `sd_contributor` localStorage bit). Signed-out returning contributor sees a
  "Sign in" link; signed-in sees an @handle chip + menu (My reports + Sign out →
  `POST /api/auth/logout`). Commits: `c415de8` (AccountControl + menu), `f32b2d6`
  (`contributorSeen` bit + three set-sites), `ca3418a` (focus return on
  outside-click dismiss + shared-primitive imports).
- **Real tertiary Report button** in the EscalationCard header action row (was a
  near-invisible micro text-link): `81c4262`; `9834513` added the card's optional
  `reportSlot`; `f33fbe9` added the `tertiary` Button variant.
- **ReportDialog** — native `<dialog>` modal on the CommandPalette pattern, full
  terminal state machine (queued/deduped/expired→gate/turnstile/invalid/banned/
  capped/error; reserved-colour success = accent ✓, **not** verdict-green),
  Turnstile reset on all resubmit paths, explicit category (dropped silent
  `'scanner'`), evidence counter; replaces `ReportForm`. Commits: `353d9c0`
  (dialog shell), `edce291` (fields + terminal state machine), `8447ab5`
  (Turnstile reset on validation failure too — plan defect caught + fixed).
- **OAuth draft preservation** — stash typed draft in `sessionStorage` before
  sign-in, auto-reopen + restore on return (`39445aa`).
- **My reports redesign** — ViewHeader / Panel / ledger rows / status Chip /
  Notice (`e9af2b0`).
- **Legibility** — `web/src/lib/contrast.ts` WCAG helper + AA matrix test
  (muted/paper/accent pass, faint fails) + reserved-colour guard (`d672e54`).
- **`docs/DESIGN-TOKENS.md`** web-scoped token reference (`824054d`).

### Shared changes
- `useSession` relocated to `web/src/lib` (SessionState gained `login`); `mine.js`
  echoes `login`; EscalationCard gained optional `reportSlot`; new `tertiary`
  Button variant. Base refactor commit `b688289`.

### Verified
- 508 unit tests + `tsc` build + eslint green throughout the run; whole-branch
  Opus review CLEAN. HEAD/`origin/main` = `824054d` (confirmed).
- **From-here live:** socdesk.io 200; bundle contains "Report this indicator" /
  "Signed in with GitHub" / "Report indicator" / "Select a category";
  `/api/auth/github/start` 302; `/api/report` + `/api/report/mine` 401.
- **Not yet run:** interactive OAuth auto-reopen dogfood (needs owner GitHub
  sign-in).

### Rulings recorded
- `CATEGORIES` hardcoded in ReportDialog vs `lib/reporting/validate.mjs`
  (byte-identical today, accepted).
- Turnstile reset extended to the `'invalid'` outcome (plan defect caught + fixed).

### Follow-ups (backlog)
- Shared `CATEGORIES` import + equality-guard test.
- Two Task-8 cosmetics: redundant `aria-label` vs `<label>`; generic `'invalid'`
  copy.
- Node-20 → 24 CI deprecation bump.

### Open / next
- **Phase 2 owner moderation console** (`/admin`, gated on numeric
  `OWNER_GITHUB_ID`) to action the queued reports — recommended next.
- Or abuse-hardening on `/api/enrich` (Turnstile + rate-limit + KV budget) before
  a public share.

### APPENDED — TWO parallel features shipped via first PM-orchestrated dual-worktree SDD pipeline

> Second unit this session. `main` = `origin/main` = **`1c8095f`** (confirmed via
> `git log`); deploy run **`32571347054`**. 543 unit tests + Playwright 17 green on
> merged main; build clean. Zero branch-level fix waves.

**Pipeline (first time):** brainstorm → design spec → 6-specialist panel review
(SOC Analyst, Infra, AppSec, Frontend) + owner gate → writing-plans → TWO
concurrent subagent-driven-development swarms in isolated git worktrees
(file-ownership boundary enforced at the filesystem; `4bf130b` gitignores
`.worktrees/`) → per-track whole-branch Opus review → merge. Plans:
`c674ea5` (/admin, 9-task), `d9658c7` (enrich, 7-task); panel amendments folded
into both specs `abb6822`.

**Track A — `/admin` owner moderation console — MERGED + DEPLOYED.** Owner-gated
queue console for the crowdsourced reports (Phase 2). Commits `6c245d5` (pure
owner gate + action vocab + report-id shape guard), `6424314`
(listQueuedReports/updateReportStatus D1), `b41df24` (GET /api/admin/reports),
`2c621a9` (POST /api/admin/moderate), `9ac60f6` (adminModel QueuedReport +
removeFromQueue), `b4b6ac5` (Admin route), `75a4823` (register /admin nav:false),
`bccfbd2` (OWNER_GITHUB_ID setup doc). Files: `lib/reporting/admin.mjs` (pure
isOwner fail-closed + whitespace-hardened / statusForAction / isValidReportId),
`lib/reporting/db.mjs` (+listQueuedReports/updateReportStatus, atomic race-safe
UPDATE), `functions/api/admin/{reports,moderate}.js`
(401→403→[400 UUID/action]→200/404, cache-control:no-store),
`web/src/routes/{Admin.tsx,adminModel.ts}` (design-system primitives,
reserved-colour, legibility text-muted, aria-labels, `/lookup#q=` deep-link),
`web/src/App.tsx` (/admin nav:false), `docs/OPERATIONS.md` (OWNER_GITHUB_ID
setup). Gated on numeric `OWNER_GITHUB_ID` (Function secret). From-here verified:
`/api/admin/*` → 401 fail-closed.

**Track B1 — enrich non-blocking context — MERGED + DEPLOYED (same run).** OTX/RDAP
pulled off the `/api/enrich` blocking path via a 4-phase assembler
(plan/dispatch/collect/assemble) + collect-anchored grace-race (GRACE_MS=0);
`partial` recomputed from the BLOCKING axis (cache-safe, `.kind` read nowhere in
collect); additive `skipped_context` honesty field; fast-fail `ok:false`→errors.
Commits `18078fb` (non-blocking scheduling axis + planSources), `629847f`
(OTX-not-configured on unkeyed hash), `94bc956` (extract plan/dispatch/collect/
assemble — no behavior change), `44c16d6` (grace-race GRACE_MS=0 collect-anchored),
`39c530a` (skipped_context + fast-fail + partial-from-blocking-health), `1c8095f`
(tally-invariance + ipinfo-before-OTX order lock). Files: `lib/enrich.mjs`,
`lib/__tests__/enrich.test.mjs`, `site-tests/specs/enrich.spec.js`.
`functions/api/enrich.js` / `shared/verdict/map.ts` UNCHANGED (additive). From-here
verified LIVE: cold lookups now verdict-gated (~0.78s IP / 1.0s domain, warm cache
0.11s) — down from the ~1.5s stopgap floor; `skipped_context` field present.

**Remaining acceptance:** (1) owner sets `OWNER_GITHUB_ID` + runs the `/admin`
interactive dogfood (activates moderation) — checklist in `docs/OPERATIONS.md`;
(2) B1 latency dogfood = DONE (verified from here).

**Acceptance CLOSED (2026-08-22) — `/admin` interactive dogfood PASSED; both
features fully accepted.** Owner set `OWNER_GITHUB_ID` + a deploy bound it (run
`32571697164`), then ran the live loop end-to-end: sign in as owner → queued
report visible → approve/reject → status flip. Flips acceptance item (1) above →
DONE. Track A `/admin` moderation console + Track B1 non-blocking enrich context
now both fully accepted (owner-reported dogfood; not a git-visible artifact).

**Deferred (non-blocking):** the "Check reputation" deep-link aria-label; an
inaccurate OPERATIONS "callback logs" doc line; owner-accepted B1 behaviors
(dropped-RDAP shows "Registration age unknown"; fast-fail context error caches
≤15min).

**Open / next (this unit):** Phase 3 — publish approved reports as the live
`SOCDESK_COMMUNITY` context source (out of the independent-sources tally) once
moderation is dogfooded; enrich cluster B2 (abuse-hardening: Turnstile +
rate-limit + KV budget) then B3 (own-OSINT dataset check-first); the deferred
a11y/doc minors; Node-20→24 CI bump.

### APPENDED — Phase 3 community-reports-publish (branch, NOT merged)

> Separate work item, same day. Built on branch `feat/community-reports-publish`
> (base `dc0cf44`) via 7-task subagent-driven development + per-task reviews + a
> clean whole-branch Opus review (verdict SHIP). **NOT merged** — owner
> finish-menu decision pending.

**What it does:** approved D1 reports (`status='approved'`) are exported by a new
Python pipeline step to a committed static JSON
(`data/state/community_reports.json`), consulted by the enrich read path via a
synchronous in-memory lookup, emitting one attributed `kind:"context"`
`SOCDESK_COMMUNITY` row (out of the verdict tally) on a match. Option A: no
per-lookup D1, no `DB` binding on `/api/enrich` — reads the committed asset via
`env.ASSETS.fetch`.

**Key decision (owner-approved):** rendered metric is `COUNT(DISTINCT github_id)`
→ "Reported by N contributor(s)" — **never** raw `COUNT(*)` (one re-reporting
accuser could otherwise read as N independent corroborations; no
`(github_id,ioc_value)` unique constraint, dedup only fires on still-queued
same-author rows). Raw volume kept only in the non-rendered envelope
`report_count`. No minimum-reporter threshold.

**Privacy fence (twice-enforced):** SQL projects no `id`/`evidence`/`comment`/
`login`, reads `github_id` only inside `COUNT(DISTINCT …)`; builder whitelists
exactly 6 keys/indicator; schema `additionalProperties:false` (both levels) fails
closed. No reporter PII in the published dataset.

**Files:** created `pipeline/community.py`, `schemas/community_reports.schema.json`,
`data/state/community_reports.json` (empty seed),
`tests/fixtures/community/{key_parity,categories}.json`,
`lib/__tests__/{community,community_loader}.test.mjs`. Modified `lib/enrich.mjs`
(`communityKey` + `SOCDESK_COMMUNITY` source), `functions/api/enrich.js`
(`loadCommunity` memoize-successes-only + derived-env inject), `run_pipeline.py`
(import os, thread env, payload before gate + last-known-good re-stamp on None),
`pipeline/validate.py` (`SCHEMA_FOR` reg), `.github/workflows/collect-and-deploy.yml`
(D1 secrets into "Run collectors" step), `tests/{test_community,test_pipeline}.py`,
`README.md`, `lib/__tests__/enrich.test.mjs` (planSources expectation update).
(`CLAUDE.md` is gitignored — not committed.)

**Commits (base `dc0cf44`):** `75c3e10`, `2a7ee17`, `58d37c6`, `ad0a953`,
`83d70c1`, `db17a37`, `70569c2`, `bd79174`.

**Verified:** pytest 90 · vitest 553 · `npm --prefix web run build` green.

**Open / next:** NOT merged — owner-config still needed to activate (inert until
set — ships dark): Actions secrets `CLOUDFLARE_D1_DATABASE_ID` +
`CF_D1_READ_TOKEN` (D1 Read-only); confirm `CLOUDFLARE_ACCOUNT_ID` reaches the
collectors step; publish the `/about#community-reports` transparency page
(count-not-verdict framing + dispute/removal contact). Spec:
`docs/superpowers/specs/2026-08-22-community-reports-publish-design.md` (§10
amendments); plan:
`docs/superpowers/plans/2026-08-22-community-reports-publish.md`. Local dev
note: pytest needs `./.venv/Scripts/python.exe -m pytest` (bare python/py lack
deps).

---

## 0-RECENT — 2026-08-21 (session 8 — escalation-card + enrich sources LIVE, analyzer-in-extension MERGED, IOC-reporting Phase 0+1 MERGED + DEPLOYED live)

> Newest block. Two units shipped to `main`/live since session 7 (escalation-card
> redesign + three enrich-source changes; the analyzer lifted into the browser
> extension), plus a third **built but not merged**: the IOC-reporting Phase 0+1
> crowdsourced-abuse write path on branch `feat/ioc-reporting-p01` (12 commits
> ahead of `main`). `main` = `origin/main` = `043601a` (reporting spec/plan/
> research docs only, not the implementation); branch HEAD `23d6a22`.

### 1. Escalation-card redesign + enrich sources (`main`, LIVE)
- GreyNoise honesty: an *observed* source is no longer treated as a no-record
  coverage gap (`eda8ed1`).
- AbuseIPDB attack-category chips on the IP card (`31f053f`, dogfooded live).
- AlienVault OTX added as an enrich source — `kind:context`, **excluded from the
  independent-sources tally** (`133a460`; 9s timeout for its Cloudflare-egress
  throttling `b7f1e84`; backlog marked shipped `2a631ea`).
- `coverageState` terse "show, don't tell" assessment + OTX attention chip
  (`98f7dc4`); redundant source verb dropped + OTX deduped to the chip
  (`41053c2`); `splitLead` evidence-lead-figure highlight + **Context section
  removed** (`0b0c708`). Supporting run: risk-graduated signal chips + declutter
  (`b147fe5`), IP-literal URL hosts as their own IOC (`eb7ffd9`), RDAP reg-age
  honesty + blank-state (`cb1d9e0`), technique-signal trigger labeled an audit
  fact (`52c3d38`), inline-expand IOC lookup (`f794ac4`), `-enc` whitespace
  tolerance (`8cef3e1`), cockpit routes cmd/mshta/wscript/LOLBin to the analyzer
  (`3964b4c`).

### 2. Analyzer lifted into the browser extension (`main`, MERGED + deployed)
- Analyzer now runs in the extension side panel with right-click routing to
  analyze / lookup / report. Built via a 5-task SDD (spec `2151aab`, plan
  `14d75e0`); **7 impl commits**: shared card-theme hook + inline-enrich resolver
  (`1786a60`), analyzer UI lifted into `shared/analyzer-ui` decoupled from inline
  lookup (`aaf3a7c`), right-click selection routing (`a139e3e`), side-panel
  analyzer surface (`fecb48f`), side panel + v0.3.0 bump (`ec8f458`), README
  fallback-gate fix (`0e85a45`), panel-handoff/effect cleanup + type tightening
  (`7d563af`). Whole-branch review clean; merged to `main`.

### 3. IOC-reporting Phase 0+1 — crowdsourced abuse-report write path (branch `feat/ioc-reporting-p01`, 12 commits, NOT merged)
- Foundation + write path for authenticated abuse reporting. Stack: Cloudflare D1
  (`socdesk_reports`, bind `DB`) + hand-rolled GitHub OAuth (write-path only, no
  PII, HMAC-signed session cookie) + `POST /api/report` (guard order:
  session→turnstile→validate→ban→daily-cap→dedupe→queued) + `GET /api/report/mine`
  + web report form + `/reports` view (`nav:false`) + docs reframe (no-account
  READ path, auth-gated WRITE path). Read path / `/api/enrich` / analyzer
  unchanged.
- Commits: HMAC session sign/verify (`96a7310`), validation + daily-cap policy
  (`d2786f6`), D1 schema + parameterized DAL (`a5d5b83`), GitHub OAuth
  start/callback + `requireSession` (`2494b5c`), open-redirect guards (`776309b`,
  `bdb3752`), `POST /api/report` + `/mine` (`f70c184`), report button + form +
  `/reports` + Turnstile CSP (`03cd0ad`), identity reframe (`68b27df`),
  report-button type gate + Turnstile retry/dedup + list error state (`d5ca902`),
  OPERATIONS owner-setup correction (`23d6a22`); plan-test correction (`b816c1a`).
  Branch HEAD `23d6a22`.
- Key files: `lib/reporting/{session,validate,policy,db}.mjs`;
  `functions/_lib/session.mjs`; `functions/api/auth/github/{start,callback}.js` +
  `functions/api/auth/logout.js`; `functions/api/report.js`;
  `functions/api/report/mine.js`; `migrations/0001_init.sql`;
  `web/src/components/report/{useSession,ReportButton,ReportForm}.tsx`;
  `web/src/routes/MyReports.tsx`; `web/src/routes/Lookup.tsx`;
  `web/public/_headers` + `web/index.html` (CSP adds `challenges.cloudflare.com`);
  `docs/OPERATIONS.md`.
- Artifacts already on `main` (`f70b571`, `c47b14e`, `043601a`):
  `docs/superpowers/specs/2026-08-20-ioc-reporting-phase01-design.md`;
  `docs/superpowers/plans/2026-08-21-ioc-reporting-phase01.md`;
  `docs/superpowers/research/2026-08-20-reporting-{storage,auth,integration}.md`;
  `docs/competitive-landscape.md`.

### 4. IOC-reporting Phase 0+1 — MERGED to `main` + DEPLOYED live (supersedes §3's branch/unmerged status)
- **Merged + deployed** (2026-08-21). `feat/ioc-reporting-p01` rebased onto
  `origin/main`, fast-forwarded, pushed — `main` tip `e72760d` (= `origin/main`,
  git-confirmed). Deploy run **32473705287** (collect-and-deploy,
  `workflow_dispatch`) green per invoker: pytest → collectors → Vite build →
  Cloudflare Pages direct-upload.
- **Deploy fix** (`704c51b`, on `main`): `VITE_TURNSTILE_SITEKEY` is a build-time
  Vite inline and the prod build runs in **GitHub Actions** (direct-upload), NOT on
  Cloudflare — so it must be a GitHub **Actions variable** fed into the workflow's
  Vite step (added), not a Cloudflare Pages var. `docs/OPERATIONS.md` corrected.
- **From-here live verification** (per invoker; no account needed): socdesk.io →
  200; `GET /api/auth/github/start` → 302 to github.com/login/oauth/authorize with
  `client_id=Ov23li3sw0imGDGok8Gx`, exact `redirect_uri`
  `/api/auth/github/callback`, empty scope, signed HMAC `state` (⇒ `GITHUB_CLIENT_ID`
  + `SESSION_SECRET` live); `POST /api/report` + `GET /api/report/mine` with no
  session → 401 (Functions deployed, auth guard live); deployed bundle
  `index-CJ63pfQI.js` has the Turnstile sitekey inlined (`0x4AAAAAAE…`) ⇒ build-var
  chain confirmed end-to-end.
- Owner created a **GitHub App** (`Ov23li…`-format client_id), not a classic OAuth
  App — works identically with the standard OAuth web flow.
- **Reporting Open / next:** interactive dogfood is the only remaining acceptance
  gate — GitHub sign-in → submit report → lands `queued` in D1 → shows on
  `/reports`; needs owner GitHub login, not yet run. (Supersedes §-block Open/next
  "merge decision" + "owner Cloudflare setup" — both now done.)

### 5. Interactive dogfood PASSED — reporting acceptance gate met; next = UX polish (this session; no code commits, brainstorming only)
- **Interactive dogfood PASSED (acceptance gate met).** Owner signed in via GitHub
  on socdesk.io and submitted a test report; the report form confirmed a successful
  submission. IOC-reporting Phase 0+1 is now fully live and accepted end-to-end
  (sign in → submit → queued). **Supersedes §4's "interactive dogfood is the only
  remaining acceptance gate"** Open/next — that gate is now met.
- **UX gap identified → next phase = reporting UX polish.** Write path is functional
  but under-discoverable by design of the Phase 0+1 spec: the "Report this indicator"
  affordance is mounted ONLY on the `/lookup` resolved card (`web/src/routes/Lookup.tsx`
  + `ReportButton.tsx`), not the home cockpit, and styled as a faint micro text-link;
  sign-in has no top-nav entry (`/reports` is `nav:false`, per §3). Next work: a
  design-system-driven UX pass — visible account/sign-in entry in the top nav, a
  discoverable report affordance in the card action row, and a polished report form.
  Brainstorming started this session (no code commits yet).

**Verified:** escalation-card + enrich and analyzer-in-extension are on `main`/live
— all cited commits are ancestors of `origin/main` `043601a` (confirmed via
`git merge-base --is-ancestor`); AbuseIPDB chips dogfooded live per invoker.
IOC-reporting branch confirmed **12 commits ahead of `main`** (`git rev-list
--count`); cited key files spot-checked present on disk. Whole-branch review =
APPROVE-WITH-FOLLOW-UPS (all 8 invariants held); final gate green per invoker (web
build + 434 shared/lib/src tests + all Functions `node --check`) — gate not
re-run here. Working tree on branch: only
`docs/superpowers/plans/2026-08-21-ioc-reporting-phase01.md` modified + untracked
`node_modules/`.

**Open / next:**
- Merge decision on `feat/ioc-reporting-p01` (merge-local / push+PR / keep).
- Optional ship-dark gate: hide report button until `VITE_TURNSTILE_SITEKEY` set.
- Owner Cloudflare setup then dogfood-verify (`docs/OPERATIONS.md`): GitHub OAuth
  App; D1 create + bind `DB` + run `migrations/0001_init.sql` (wrangler NOT
  installed → dashboard D1 Console); Turnstile widget; 4 Function secrets
  (`GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `SESSION_SECRET`,
  `TURNSTILE_SECRET`) + build var `VITE_TURNSTILE_SITEKEY`. `OWNER_GITHUB_ID` =
  Phase 2 only.
- Parked branch minors (non-blocking): cap→dedupe→insert TOCTOU; OAuth state has
  no single-use nonce + `SESSION_SECRET` reused for state+session; `readCookie`
  unescaped regex (const-only); no comment-truncation test; banned-check ordering.
- Deferred: abuse-hardening (Turnstile + rate-limit + KV budget on `/api/enrich`),
  own OSINT dataset, ISP/ASN abuse-leaderboard (Phase 4), P1.5c domain→IP hero
  pivot.

---

## 0-RECENT. 2026-08-19 (session 7 — multi-interpreter analyzer, doc-scoping, kill-chain bullets — all SHIPPED LIVE)

> Newest block. Supersedes §0-RECENT (session 6) — three more units shipped
> and verified live since: the analyzer's multi-interpreter increment, a
> documentation-scoping pass, and the kill-chain "EXPLAINED" action-bullets
> (the analyzer's headline output, previously `bullets:[]`). `origin/main` =
> local `main` = `36ce3cb`, working tree clean.

**Three units shipped and verified live since the last checkpoint.**

### 1. Multi-interpreter analyzer increment (`/analyzer`, LIVE)
- cmd.exe, mshta, and wscript/cscript are now first-class interpreters, not
  just PowerShell: `detectInterpreter()` (`fd6389d`) + per-interpreter body
  extraction (`extractCmdBody`/`extractMshtaBody`/`extractWshBody`,
  `6c6d384`) + recursive depth-capped nested re-entry that decodes a
  cmd/mshta wrapper's inner `powershell -enc` payload (`c3d57a0`).
- `shared/analyzer/cmdlex.ts::deobfuscateCaret` — cmd caret deobfuscation,
  cmd-gated (`b3ff7c8`). `shared/analyzer/wsh.ts` — WSH/HTA numeric
  char-code decode + honesty signals (`f0e6353`).
- Interpreter-aware signature rules (`8c8c927`): `cmd-cradle` (`for /f` +
  finger/curl/certutil/bitsadmin/powershell co-occurrence — closes the
  finger-cradle gap flagged at the end of session 6 — T1059.003/T1105),
  `mshta-interpreter` (T1218.005, +T1059.005 when an inline script is
  present), `wsh-script-exec` (T1059.005 for VBS / T1059.007 for JS). Fixed
  the ClickFix `--Verify` decoy false-positive against `gpg --verify`
  (`82e902d`).
- `extract.ts` binary-filename→domain IOC-leak fix (`abde7d9`).
- 8-task SDD (`docs/superpowers/plans/2026-08-19-multi-interpreter-analyzer.md`,
  `.superpowers/sdd/2026-08-19-multi-interpreter-analyzer/`) + whole-branch
  review caught 2 cross-task defects, both fixed in `1db775e`
  (`fix(analyzer): non-anchored nested launcher detection + dedupe evasion
  flags`): the non-anchored nested-launcher fallback was truncating corpus
  text a signal rule depended on (the `for /f`+`finger` cradle), and evasion
  flags could duplicate. End-to-end integration + determinism tests:
  `f6bcffc`. 264/264 `shared/analyzer` tests green post-fix.

### 2. Documentation-scoping pass (`3e049c8`, `aff3063`, `e9740d9`)
- `docs/OPERATIONS.md`: Deploying section rewritten for the real `web/dist`
  Vite build + `wrangler pages deploy` (previously still described `site/`
  uploads).
- `docs/AUTOMATION.md`: scope note; historical markers on the old `site/`
  Definition-of-Done bullets (process doctrine §2-6 unchanged).
- `docs/ARCHITECTURE.md`: reordered so the live `web/` analyzer + cockpit
  land right after "End to end" (not seventh); diagram gets a `web/` node +
  a Tier-3 skip pointer; analyzer section updated for the multi-interpreter
  increment.
- `docs/HANDOFF.md` itself trimmed (847→732 lines per the commit message,
  pre-this-edit) — stale §2/§3/§5/§9/§10 reduced to pointers; `## 0` session
  history untouched.
- `README.md`: capability table split into Live-in-`web/` vs
  Legacy-`site/`-only, correcting stale `site/js/*` paths for the 7
  capabilities rebuilt in `web/`.
- `docs/BUILD-JOURNAL.md` marked deprecated in favor of `docs/HANDOFF.md`
  (the `nt` agent definition already points here, not there).
- New `docs/REPO-MAP.md` — canonical `web/src` + `shared/` module map;
  `CLAUDE.md` and `README.md` now point to it instead of duplicating it.
- `web/src/App.tsx`: Gallery dropped from the public top-nav — routable-only
  internal design ref, matching `/privacy` (`e9740d9`).
- `docs/SOCDesk-Overview.{html,pdf}` regenerated for `web/`-live state
  (analyzer block, `/desk` pillars, real deploy steps).
- `BACKLOG.md` synced: command-line deobfuscator marked SHIPPED, Analyzer
  roadmap section added.

### 3. Kill-chain / "EXPLAINED" action-bullets (`/analyzer`, LIVE)
- The analyzer's headline output (spec §7 `ActionBullet`, previously
  `bullets:[]`): `shared/analyzer/bullets.ts` — 28 execution-ordered
  `ActionRule`s → `ActionBullet[]` (`aa67f20`), wired into `analyze()` and
  `copyText` (`de72496`), rendered by
  `web/src/components/analyzer/ActionBullets.tsx` between the technique
  tally and the decode ladder, plus a copyText "What it did" section
  (`b4e3db2`).
- Verb-first plain-English actions; three-tier honesty (resolved ● /
  inferred ~ / opaque ○ quarantined); never invents intent (machine-guarded
  banned-word sweep, tested in `dfe2cb0`); per-behavior IOC attribution — no
  cross-behavior misattribution (`abdbd4c`; `d53cc8c` scoped the
  beacon-loop host to its own loop body to fix a cross-brace
  misattribution). `4ff4f25`: mshta/WSH entry-vector bullet surfaced,
  raw-socket beacon host named, clearer evasion wording.
- Built via 5-task SDD (`.superpowers/sdd/2026-08-19-analyzer-bullets/`) +
  whole-branch review (4 findings fixed, re-reviewed APPROVED) + a SOC
  output-quality pass on real samples (3 must-fixes, follow-ups logged in
  `BACKLOG.md` by `36ce3cb`). **375 tests green.**

**All three verified live on socdesk.io** — `origin/main` = local `main` =
`36ce3cb`, working tree clean; live bundle `index-CS8J7t-q.js` fetched
directly from socdesk.io matches this build.

### Analyzer roadmap follow-ups (logged in `BACKLOG.md`, not yet built)
- `clickfix` "paste-and-run" label leaks into the top-line characterization
  on the generic hidden+nop+fetch+IEX branch when no decoy text is present
  (the bullets themselves stay correctly silent — it's a `techniques.ts`
  label issue on that branch).
- `EMBEDDED_LAUNCHER_RE` `WScript.Shell` false-match burns depth-cap hops
  (mislabels an `mshta→wscript` decode-layer transition).
- Deep WSH deobfuscation (VBScript/JScript concat-fold + `Execute`/`eval`
  recursion); cmd env-var obfuscation (`%COMSPEC:~x,y%`, `set`/`%a%`
  reassembly).
- Broader gaps: PowerShell deobfusc breadth (`-join`/`-f`/`[char]`/
  `-replace`/`FromBase64String`/`.Invoke()` sink); technique-family
  expansion (credential-access/LSASS, ransomware shadow-delete, UAC bypass,
  lateral, DNS exfil); LOLBin table (9 of ~200 LOLBAS); honesty layer (real
  entropy/`wall`/`fractionAccounted`).

---

## 0-RECENT. 2026-08-19 (session 6 — analyzer Phase 3 + polymorphic cockpit SHIPPED LIVE)

> Newest block. Supersedes §0-RECENT (session 5) on analyzer status — Phase 3
> interpretation now IS built, tested, and live, not just the Phase 1/2a
> decoder. Also ships an entirely new capability, the polymorphic cockpit, not
> covered by any block below. Both verified live on socdesk.io, `origin/main`
> ≈ `a62ac2f`.

**Two features shipped and verified live since the last checkpoint.**

### 1. PowerShell analyzer Phase 3 — signatures + characterization (`/analyzer`, LIVE)
- The Phase 1/2a decoder core (lex → fold → resolve → extract, §0-PRIOR) now
  feeds a **signature catalog**: 12 MITRE-ATT&CK-mapped `SignatureRule`s
  across download cradle, evasion-flag cluster, AMSI reflection/memory-patch,
  ETW tamper, Defender tamper, ClickFix/paste-and-run, beaconing, reverse
  shell, fileless loader, persistence, and LOLBins (certutil/bitsadmin/mshta/
  regsvr32/rundll32/msiexec/wmic/installutil/conhost), with co-occurrence
  upgrade.
- **Specificity-gated characterization** (the analyst payoff Carl asked for):
  `analyze()` emits a **RED** "High-confidence malicious behaviour" callout
  ONLY for intrinsically near-dispositive signals (amsi-reflection,
  amsi-memory-patch, reverse-shell — "no legitimate use"); an **AMBER**
  "Suspicious — review" tier fires when a strong signal is corroborated to
  near-dispositive by co-occurrence (the CS-beacon shape); otherwise just the
  periwinkle technique tally. **Never a synthesized score/verdict.**
- **⚠ RESERVED-COLOUR EVOLUTION (owner-approved):** the ONE gated
  characterization callout carries a verdict-severity hue (red/amber);
  technique CHIPS stay periwinkle facts, tier-tagged, sorted strongest-first.
  This relaxes the old "analyzer is periwinkle-only" rule for the gated read
  only — red/amber/green stay reserved for a real severity read elsewhere,
  never decoration.
- Files: `shared/analyzer/{types,lex,preprocess,fold,extract,resolve,report,index}.ts`,
  `web/src/routes/PowerShellAnalyzer.tsx`,
  `web/src/components/analyzer/{AnalyzerResult,TechniqueTally,DecodeLadder,IocTable}.tsx`.
  `AnalyzerResult` is a shared component, reused by the cockpit (below). Each
  extracted IOC has a one-click "Look up →" into the reputation/enrich card.
  **86 vitest** for `shared/analyzer`.

### 2. Polymorphic cockpit — one omnibox, two paths (`/` = `Overview.tsx`, LIVE)
- `shared/intent.ts::classifyCockpitInput(raw)` classifies a paste as
  `'indicator'|'command'|'unclassified'` and routes it. An **indicator** →
  enrichment (`useLookup` → `/api/enrich`) → `EscalationCard` inline + the 3D
  globe lands the geo pin. A **PowerShell command** → the local analyzer
  (`usePsAnalysis`) → `AnalyzerResult` inline in the SAME docked slot, and the
  globe YIELDS — dims/steps back AND suspends its WebGL render loop
  (`GlobeApi.suspend/resume` + `.is-geoless` CSS). One screen, no tab-switch.
  `/analyzer` stays as the deep/standalone view sharing `AnalyzerResult`.
- Key pieces: `web/src/components/cockpit/{useCockpitInput,ResultRegion,
  CockpitOmnibox,ModeChip}.tsx`. `useCockpitInput(submitted, override)`
  composes both `useLookup` + `usePsAnalysis` (the unselected path fed `''`);
  `ResultRegion` dispatches by kind; `CockpitOmnibox` morphs a single-line
  `<input>` ↔ an auto-growing `<textarea>` for scripts; `ModeChip` shows the
  detected kind (periwinkle catalog), correctable to escalate to command
  (monotonic — see below).
- **⚠ DATA BOUNDARY (load-bearing, verified live):** a pasted command NEVER
  reaches the third-party `/api/enrich`. `classifyCockpitInput` runs before
  `detectType` at EVERY entry point: the cockpit auto-path; the mode-chip
  override (`resolveKind` is MONOTONIC — a detected command can't be
  overridden back to indicator); `palette/commands.ts::submitLookup` +
  `Lookup.tsx::runLookup` (submit); and `Lookup.tsx`'s hash mount /
  `hashchange` / `popstate` reads — a `/lookup#q=<command>` link redirects to
  `/analyzer`, zero enrich calls. Also consolidated the two drifted
  classifiers (`palette/classify.ts` now delegates to `detectType`).
- Submit is unified — only the committed value runs, never live-typed, so no
  per-keystroke `/api/enrich`.

**Both verified live on socdesk.io — `origin/main` ≈ `a62ac2f`.**

### Deferred fast-follows (not yet built)
- `/analyzer#q=` deep-link prefill — a command routed from the palette/
  `/lookup` currently lands on the BARE `/analyzer` (loses the paste). Add a
  `#q=` consumer mirroring `Lookup.tsx`'s hash reader.
- `IocTable` "Look up →" → in-place cockpit kind-flip, instead of navigating
  away.

### Roadmap (owner-set, unbuilt)
1. **cmd-family / multi-interpreter increment** — cmd `^`/`^^` caret
   deobfusc, `finger`/`for /f`/`start` LOLBin+cradle, broader ClickFix decoys,
   HTA/WSH awareness; fix the lowercase-filename→domain IOC leak. Motivated
   by a live test: a ClickFix `cmd /c … for /f … in ('finger user@host') do
   %e` finger download-exec cradle the analyzer under-detected.
2. The **"explained"/kill-chain breakdown** — spec §7 `ActionBullet` /
   `bullets.ts`, currently `bullets:[]` — the numbered, execution-ordered
   plain-English "what did it do" narrative.
3. **PowerShell deobfusc breadth** (`-join`/`-f`/`[char]`/`-replace`/
   `[Convert]::FromBase64String`/`.Invoke()` sink); **technique-family
   expansion** (credential-access, ransomware shadow-delete, UAC bypass,
   lateral, DNS exfil); LOLBin table expansion; **honesty layer** (real
   entropy/`wall`/`fractionAccounted`).

---

## 0-RECENT. 2026-08-19 (session 5 — PowerShell analyzer: decoder core merged, interpretation layer next)

> Newest block. For **analyzer build-state and what to do next**, this
> supersedes the session-4 block below. Everything about the live IOC-lookup
> cockpit in session 4 is unchanged and still current — this block only adds the
> `/analyzer` route's status.

**The `/analyzer` route now has a real deobfuscation core, but it is a DECODER, not yet an ANALYZER.**

### Shipped to LOCAL main (UNPUSHED / NOT live)
- **Phase 1** (merge `6eade54`) + **Phase 2a** (merge `ff8fada`) of the PowerShell
  analyzer are merged to **local `main`**. Local `main` is **~32 commits ahead of
  `origin/main`** and **nothing analyzer is deployed** — the live socdesk.io
  `/analyzer` route does NOT yet have this. Deploy is deliberately held for an
  explicit `deploy` (rebase-guard first: `git pull --rebase origin main`, then
  trigger collect-and-deploy — see `[[socdesk-deploy]]` memory).
- What the core does: lexer + `-enc` Base64→UTF-16LE decode + gzip/raw-DEFLATE
  inflate (U+FFFD-aware plausibility guard) + **string-concat folding** +
  **position-aware single-assignment variable substitution** (fixpoint-capped) +
  **`IEX`/`&`-sink recursion** + IOC extraction across **every** decode layer with
  true `layerIndex` provenance + one-click bridge into the reputation card.
  Deterministic, client-side, **NEVER executes input** (strict CSP, no eval).
- Files: `shared/analyzer/{types,lex,preprocess,fold,extract,resolve,report,index}.ts`,
  `web/src/routes/PowerShellAnalyzer.tsx`, `web/src/components/analyzer/*`. Tests:
  `shared/analyzer/__tests__/*` — **40/40**, `tsc` clean. Run from `web/`:
  `npx vitest run ../shared/analyzer`.

### NEXT: Phase 3 — the interpretation layer (the actual analyst value)
- Phase 1+2a is *decode + IOC extraction*. The payoff Carl asked for —
  the bulleted **"what did it do"** breakdown, **behavioral signatures**
  (beaconing, clickfix, download-cradle, AMSI/ETW tampering, etc.), and the
  **specificity-gated characterization** (near-dispositive signals earn an
  attributed high-confidence read; weak/strong-only stay a descriptive tally) —
  is **Phase 3/4** and is **not built yet**.
- **⚠️ Phase 3 is SAFEGUARD-SENSITIVE:** the signature-catalog content trips the
  API cyber-safeguard. Carl was added to the **Cyber Verification Program**;
  Phase 3 was deferred until he **restarts the session** so verification is
  active. **Before building Phase 3, confirm verification is active** (no
  safeguard blocks on a signature-authoring probe), then brainstorm/plan →
  build via **subagent-driven-development**.
- Design refs (authority): `docs/superpowers/specs/2026-08-19-powershell-analyzer-design.md`
  **§6** (signatures), **§7** (breakdown), **§14** (open questions + the
  specificity-gated characterization decision + Phase-2 carry-forward findings).

### Also queued — Phase 2b (deobfuscation breadth, safe to build anytime, lower value)
`-join` / `-f` format / `[char]` / `-replace` / string-reversal / inline-AES
folding; lexer-token domain extraction (fixes the lowercase `.dll` IOC leak);
full wall/opaque layer states + real `fractionAccounted` (resolve layers are
currently hardcoded `fully-decoded`, so `fractionAccounted` can overstate);
`.Invoke()` sink (needs `.`-member lexer support) + its comment trim;
`preprocess` max-input-length (rest of §11); pure-script decode-ladder
surfacing; `&`-sink recursion test.

---

## 0-PRIOR. 2026-08-18 (session 4 — the modern-stack app is LIVE)

> Newest block. It **supersedes §0-RECENT (session 3) and everything below it**
> for anything about *what is live and shipped.* The historical design/logo
> record below stays for context; where it conflicts with this block on shipped
> state, **this block wins.** Palette + the SD-monogram logo decision are
> unchanged — no re-skin.

**Read this first. SOCDesk is live and the loop works end to end.**

### The AAA modern-stack app is LIVE at socdesk.io ✅
- The production site is now the **`web/` app** — **Vite + React + Tailwind v4 +
  Motion**, under the **strict CSP** — deployed to socdesk.io. The **legacy
  `site/` vanilla app is SUPERSEDED** (kept in-repo for history; no longer the
  deploy target).
- The landing is a lookup **"cockpit":** typing an indicator **folds the
  marketing intro, pins the omnibox, and docks the escalation card beside a 3D
  globe** (the globe lands the geo pin). IOC in → OSINT out, in one screen.
- **Favicon = the SD monogram** (periwinkle `#7C8AFF`), cut from the approved
  master. The logo saga (§0-RECENT / §0-PRIOR) is closed.

### The escalation card — honest by STRUCTURE
- **Source-class labels** on every source: `catalog/identity`, `authoritative`,
  `behavioral/observed`, `reputation-score`, `list-membership`, and an
  `unclassified` fallback. The **evidence ledger** stacks the source name over
  its class chip with **per-source recency** ("as of DATE"). **EPSS is
  attributed to FIRST.org** on CVE cards.
- **Signals are CHIPS, not prose:** dual-use / Tor, grayware, and
  hosting/datacenter render as chips.

### ⚠️ DE-WORDIFY (2026-08-18) — a doctrine change (see `docs/VERDICT-LANGUAGE.md`)
The escalation card **and its copy-out** (the **"Copy card"** PNG + **"Copy
text"**) are now a **CLEAN, FACTUAL artifact** the analyst annotates in the
email body. **Removed** from the card, the PNG, and the copy-text: the
disclaimer **CAVEAT** ("Reflects third-party reputation … not independently
confirmed") and the prose **"Note:"** lines (dual-use, grayware). **Honesty is
now STRUCTURE**, not disclaimer prose — every claim attributed to a named source
+ class, the coverage tally (never a synthesized score), honest empties ("not a
clearance"), geo-as-context. The signals became chips. **The analyst owns the
nuance in the escalation email.** `docs/VERDICT-LANGUAGE.md` §4 is the binding
copy.

### Shipped this session — the loop's reach
- **IPv6 lookups** — detected + enriched (**AbuseIPDB + VirusTotal + ipinfo**;
  **GreyNoise stays IPv4-only** — its community API 400s on v6). Private/reserved
  v6 (`::1`, `fc00::/7`, `fe80::/10`, `ff00::/8`) is rejected.
- **URL workflow** — the urlscan **existing-scan screenshot** renders on-card
  (CSP allows `https://urlscan.io` images) with a **click-to-expand lightbox**,
  plus a **Browserling** safe-view pivot (opens the URL in a disposable remote
  browser). **Existing-scans only — SOCDesk never submits to urlscan.**
- **Domain** — the registration-age hero is populated by a new **keyless RDAP**
  source (`rdap.org`, requires a User-Agent; `kind:"context"` so it is excluded
  from the tally) carrying **Registered / Registrar / Expires**. The urlscan
  domain search uses **`page.domain:`** (a scan *of* the domain, not any scan
  that merely contacted it); domains also show the scanned-page screenshot.
- **Compare-IP / impossible-travel** — after an IP lookup, a collapsed **"Compare
  to a previous IP"** panel takes a second IP + optional minutes → **great-circle
  distance in miles + implied speed in mph** with an honest plausibility read
  (**plausible ≤600 mph / implausible / impossible >2200 mph**) + a copyable
  one-liner. Computed **only from real coordinates** (both IPs `precise`), never
  country centroids; an amber caution chip, **never a red "compromised" verdict.**
  Shows **distance, velocity, and a map arc** (the arc + second pin also draw in
  the copy-card PNG).
- **Browser extension → full-card parity (manifest `v0.2.0`)** — the toolbar
  popup now renders the shared `EscalationCard` (heroes, chips, Compare-IP, copy
  actions), the **same card the web app shows.** It already shares indicator
  detection + the enrich pipeline, so IPv6 / RDAP / URL all flow through.

### Deploy — the rebase guard
- CI (`collect-and-deploy.yml`) **builds `web/dist` and direct-uploads to
  Cloudflare Pages.** The cron commits **"data: refresh snapshots"** constantly,
  so a plain `git push` is **non-fast-forward** — **always
  `git pull --rebase origin main` before pushing.**

### Next / pending
- **Compare-IP globe arc** — the great-circle arc on the 3D globe is **landing
  now** (the shared-card SVG arc + PNG arc are in).
- **Per-source metric / icon visual** — a small per-source metric or icon on each
  evidence line (visual pass, not yet built).
- **Same-origin `/api/shot` proxy** — so the copied PNG can include the urlscan
  screenshot (cross-origin urlscan images currently taint the copy canvas; a
  same-origin proxy fixes it). Not built.

---

## 0-RECENT. 2026-08-12 (session 3 — logo RESOLVED + segmented)

> Second-newest block. **Superseded by §0 for shipped state** (the segmented
> next-session tasks below — wire the logo, ship the rebuild — have since landed
> in the `web/` app). Kept for the logo/palette decision record, which still
> holds. Everything in §0-PRIOR — verdict graphic, palette, the working-tree
> guard — still stands as history.

**The logo saga is over.** The next session was a set of **segmented,
mostly-independent tasks** (only #4 is a sequence). **Palette is unchanged — no
re-skin.**

### LOGO — RESOLVED (locked) ✅
- **Primary mark = "SD Monogram" (brand-sheet Option 1)** — interlocking S/D
  built from clean geometry, with periwinkle **signal-bars.** The **coffee mug is
  demoted to a SECONDARY brand motif** (warmth / community / merch — shift-start,
  daily-brief, physical mug), **NOT** the primary logo. This dissolved the mug's
  16px-favicon problem in one move.
- **Palette UNCHANGED** — the brand sheet sits on our already-shipped
  **warm-espresso / warm-paper + periwinkle** tokens
  (`#15100A / #F2E6D0 / #A6612F / #7C8AFF`). **NO re-skin.**
- **Rejected: the "System Mug" alternative sheet** (VOID `#080C10` +
  electric-blue `#5A78FF` + copper + **paid Aeonik** font). Void = the cold-cyber
  slop we left; copper collides with the reserved **verdict-gold**; Aeonik is a
  paid font (breaks no-paid-tools + CSP self-host). A System-Mug preview was built
  (`design/mockups/brand-systemmug-preview.*`) then **discarded.**
- **Asset — `design/mockups/sd_logo.svg`:** the monogram **traced to clean,
  scalable SVG** from the brand sheet (`suggestions.png`) and recolored to exact
  tokens. **Theme-aware:** monogram `fill="currentColor"` (cream on dark, espresso
  on light); bars `fill="var(--sd-bar,#7C8AFF)"` (`#4A4FD0` on light). Crisp
  200 → 32px; at 16px the **SD holds but the 4 bars compress** → a **2-bar 16px
  favicon cut** is still needed.
- **Preview — `design/mockups/hero-sd-preview.*`:** the warm globe hero with the
  SD monogram in the topbar + an added hero lockup, both themes, verified
  **CSP-clean.**
- **NOT yet wired into `site/`.** The logo lives **only in mockups.**
  `site/favicon.svg` still holds a **non-approved experimental mark** (revert
  pending).
- **Committed design-only at `c4cd6fd`** (`design/` — `sd_logo.svg` +
  hero/brand mockups + `UX-DIRECTION.md` + `REFERENCES.md` + brand explorations).

### Memory rules added/strengthened this session (so the saga can't repeat)
- **`feedback-visual-asset-generation`** — polished raster/brand visuals come
  **ONLY** from an image generator or an approved master; **never** hand-authored
  SVG / raster-recolor / agent-redraw ("it's just a flat icon" is the trap).
  **Converge the instant the user approves one; no variant fan-out.**
- **`framework-local-dev`** — **READ the Stack Bible**
  (`Desktop\Projects\stack-bible\`) **before touching the Framework box;** the
  memory was marked stale (Bible §A is source of truth).
- **`feedback-no-personable-filler`** — task-focused communication only.

### Next-session tasks — SEGMENTED (also logged in the task tracker)
1. **Wire the SD logo into `site/`** — topbar + favicon (+ the **2-bar 16px cut**)
   + hero lockup; theme-aware; **palette unchanged.**
2. **Fix the light-theme globe** — dark-sphere-on-cream → warm-greige instrument
   (isolated tweak; **gates nothing**).
3. **Globe elevations** — depth / rim-light, denser dots, node emphasis, dot
   richness (the **4 palette-independent wins** from the globe review).
4. **Finish the RADAR rebuild → commit + ship** (the one sequence) — verdict
   **Core + companion** into `verdict.js` / `evidence.js` (decide **EPSS% vs
   composite** center number), **globe Phase 3** (self-host **cobe**), then
   **commit the `site/` rebuild** + make the **ship call.**
5. **Revert the experimental `site/favicon.svg`.**
6. **Leg 2 build** (already tracked — see §0-EARLIER; build **only after** the
   rebuild lands, shared files).

### Still-open owner actions (carry forward, unchanged)
- **Upload Extension v1** — Chrome Web Store, **Unlisted**; zip on Carl's Desktop.
- **Tailscale SSH ACL flip** (`check` → `accept`) for headless box automation.
- **Leg-2 source decisions** — ransomware.live license, abuse.ch key.
- **Deferred fix for future asset generation:** local image-gen on the Framework
  box (**ComfyUI + FLUX** via the kyuz0 ROCm toolbox, Stack Bible §D/§H).

### Working tree (standing guard — unchanged)
- `site/` (**12 files, the RADAR rebuild**) remains **uncommitted + incomplete**
  since commit `f029b26`. Keep the standing rule: **no `git add -A` / rebase /
  checkout** — this handoff commits **`docs/` only.**
- `design/` is **now committed** (`c4cd6fd`).

---

## 0-PRIOR. 2026-08-11 (session 2 — brand/logo · logo now RESOLVED in §0)

> This is the **later** of two 2026-08-11 sessions. The **session 1** block (RADAR
> rebuild / extension / copy-card) is directly below, kept for context. Where the
> two conflict, **THIS block wins** — specifically it **supersedes** session 1's
> verdict-graphic pick ("B · Severity Spine") and the "logo-v2, owner picking"
> line.

**Honest framing:** this whole session went to the **logo** and produced **NO
shippable logo** — ~5 hours in failure loops. Recorded plainly so next session
starts from the correct approach, **not the loop.** The real design decisions
that DID get made are below and must not be lost.

### Design decisions LOCKED this session (preserve)
- **Verdict graphic — DECIDED** (this replaces session 1's "Severity Spine" rec):
  **Core radar** — filled polygon + a bold central number on a faceted hex plate
  — for **CVEs**; plus a **range-gate companion** — discrete count "blips," the
  benign source shown **hollow** — for the **enrich consensus tally.** Mockups
  (uncommitted): `design/mockups/verdict-graphic-explore.html`,
  `design/mockups/verdict-graphic-radar-round2.html`. **Build note:** before
  wiring into `verdict.js` / `evidence.js`, decide whether the big center number
  is **EPSS%** (current) or a **labeled composite** (KEV+CVSS+EPSS).
- **Palette — CONFIRMED #1 "warm + periwinkle"** (the current RADAR-rebuild
  scheme) after a 3-way comparison (`design/mockups/palette-explore.html`).
  Graphite-ground and gold-mono were **rejected** — gold collides with the
  reserved **verdict-amber.** Mug/ceramic = caramel **`#C68B5B`**; do **NOT**
  drift to pale-latte tones (a mid-session color error, corrected).
- **Lockup orientation:** mug → **thin vertical rule** (sized to the text block,
  not stretched) → **SOCDESK** (Archivo 800, −0.02em) over **"THREAT
  INTELLIGENCE, FASTER."** (FASTER. in periwinkle), **no wordmark underline.**
  (The topbar "underline" was an accidental `<a>` default; `site/css/base.css`
  already ships `a{text-decoration:none}`, so the live site is fine.)

### LOGO — ⚠️ SUPERSEDED by §0 (session 3): RESOLVED as the SD Monogram
> Historical — kept to show why the mug-as-primary path was abandoned. The logo
> is now the **SD Monogram** (mug demoted to a secondary motif); do **not**
> resume the image-gen-the-mug plan below. See §0.

- **Definitive reference = the ChatGPT brand sheet** (Carl's file
  `chatgptbrandsheet.png`): a **dimensional caramel MUG** with a rounded
  **D-handle**, periwinkle **PIXEL steam**, **no saucer**; tagline "Good intel,
  hot coffee"; palette `#F5F1EB` text / `#C68B5B` mug / `#6B8AFF` steam /
  `#1A150F` bg. **This is the target.**
- **Dead ends — DO NOT resume:** cup-and-saucer silhouette, **wavy** steam,
  pale-latte ceramic, and the flat-geometric "UI icon" register — all detours
  (assistant-led). Steam is **PIXEL** per the sheet, not wavy.
- **Why it failed (root cause):** the mug is **AI-image-generated** — fidelity
  **cannot be hand-authored or recovered from a screenshot.** Two wrong
  approaches were burned: (a) sub-agents hand-coding SVG from *text descriptions*
  of the reference → clipart (the agent can't see the image; telephone game);
  (b) cropping the 928px brand-sheet *screenshot* + background-keying → a lossy
  ~107px raster with a dark handle-eye artifact, not portfolio-grade.
- **Correct path for next session — EITHER:**
  1. **Carl exports the actual full-resolution generated master** from ChatGPT —
     isolated icon, transparent, **1024px+**, the **real file (NOT a
     screenshot)**; OR
  2. **Stand up local image generation on the Framework box** — ComfyUI +
     **FLUX.1-schnell / SDXL** over the tailnet, **reference-conditioned**
     (img2img / IP-Adapter) to match the sheet, driven from Claude Code via
     SSH/HTTP — then **`rembg`** for a clean alpha + **`vtracer`** for an optional
     scalable SVG. Then wire the logo in. (See memory `feedback-logo-asset-generation`.)
- **Tooling installed on Carl's Windows box this session (reuse):** Python
  **Pillow** + **vtracer**. **cairosvg / svglib FAILED** (no native cairo on
  Windows). **Headless-Chrome screenshotting FAILED** (collides with the
  already-open Chrome profile + flag quirks) — next time pass a **fresh
  `--user-data-dir`**, or render on the Framework box.

### ⚠️ Working tree / cleanup (flag prominently)
- **The LIVE `site/favicon.svg` was overwritten** by a failed logo attempt
  (uncommitted) — it currently holds a **non-approved cup/caramel experiment.**
  **Revert or replace it before any deploy.**
- Uncommitted logo explorations: `design/mockups/logo-v2.html`,
  `design/mockups/logo-v3.html`, `design/mockups/favicon-v3.svg` (+ the
  verdict/palette mockups above).
- **The entire RADAR visual rebuild is STILL uncommitted** (`site/index.html`,
  `site/css/*`, `site/js/*`, `sw.js` at **v15**) — **unchanged from session 1.**
  Nothing has been committed since the docs-only commit **`6b68393`** (session
  1's handoff). Keep the standing rule: **do NOT `git add -A` / rebase / checkout
  blindly** — this handoff commits `docs/` only.

### Next-session sequence
1. **Resolve the logo** via image generation (path above) — the first real step.
2. **Wire the locked set into the rebuild in ONE pass:** the logo asset (topbar +
   favicon + lockup), the verdict **Core + range-gate companion** into
   `verdict.js` / `evidence.js` (decide **EPSS vs composite** center number), and
   the **palette #1** tokens.
3. **Revert/replace** the experimental `site/favicon.svg`.
4. **Commit the rebuild;** then the **ship decision** (with-globe vs ship-now);
   then **Leg 2** (build plan + `brief.json` contract still to be persisted from
   the earlier architect log; `summarize-local` / Qwen3-Next-80B verified).

### Still-open owner actions (unchanged)
- **Upload Extension v1** — Chrome Web Store, **Unlisted**; zip on Carl's Desktop.
- **Tailscale SSH ACL flip** (`check` → `accept`) for durable headless automation.
- **Leg-2 source decisions** — ransomware.live license, abuse.ch key.

---

## 0-EARLIER. 2026-08-11 (session 1 — RADAR rebuild built [UNCOMMITTED] · extension v1 ready · copy-card)

Read this whole section. Two things gate the next session: **an uncommitted
working tree** and a **reversed stack decision.** These supersede the stale body
below (especially §5 "Design law" and any "React + shadcn / teal" phrasing).

### ⚠️ CRITICAL — the RADAR visual rebuild is BUILT but UNCOMMITTED

The RADAR rebuild lives in the working tree, **not committed and not deployed.**
Do NOT `git pull --rebase`, do NOT `git checkout`/`reset` these files, and do NOT
let a stray `git add -A` sweep them into an unrelated commit. This docs handoff
commits **`docs/` only** for exactly this reason.

**Decision: EVOLVE the vanilla site — NOT a framework rewrite.** The site was
restyled in place (still vanilla ES modules, no build step):
- Palette **warm-espresso** (dark) / **warm-paper** (light) + **periwinkle**
  accent + the **coffee-mug** mark. **Light / Dark / System** toggle added.
- Compact RADAR header — the old giant "SOC DESK" masthead was **deleted.**
- Search-hero: H1 stacked **"IOC in." / "OSINT out."** ("OSINT" in periwinkle).
- The broken score gauge is **fixed** (value now centered in the ring).
- Feed rows + actor cards brought to the escalation-card visual language.
- Stat band restrained (periwinkle slab removed); hero decluttered — Live-Wire
  ticker + TRY chips cut, disclosure collapsed to one line, "Escalation summary"
  renamed **"Intelligence summary."**
- `site/sw.js` bumped to **v15.**
- Files (all uncommitted): `site/index.html`,
  `site/css/{tokens,base,chrome,panels}.css`,
  `site/js/{verdict,views,app,motion,state}.js`, `site/favicon.svg`,
  `site/sw.js`, `site-tests/specs/*`. Tests **~108–110 green.** Not deployed.

### ⚠️ STALE DECISION REVERSED (it was in the old §0)

The previous §0 said the production rebuild moves to **React + Vite + Tailwind +
shadcn, teal accent, Bricolage/Geist fonts.** **That is reversed.** We evolved
the vanilla site (no framework); accent = **periwinkle** (not teal); fonts =
self-hosted **Archivo + IBM Plex Mono** (Red Hat / Bricolage were only mockup
stand-ins). `ui-ux-pro-max` / Watermelon-UI / React-shadcn are no longer the
plan. Ignore any surviving "React + shadcn" phrasing elsewhere in this doc.

### Committed this session
- **Escalation "Copy card"** — the evidence card is drawn to canvas and copied
  to the clipboard as a **PNG image,** from byte-identical code shared across
  `site/js/evidence.js` and `extension/lib/evidence.js`. The popup now offers
  **Copy card** (image) + **Copy text.** `lib/enrich.mjs` surfaces ipinfo `loc`
  → a city-level pin. Card cleanups: `GEOLOCATION` header; not-consulted/footer
  lines removed; single timestamp; clean/negative sources retained (honest
  "5 of 6"); **no SOCDesk branding in the copied image;** dual-use note promoted
  under the tally; jargon glossed.
- **`docs/VERDICT-LANGUAGE.md` §4** updated to match (no branding in the copied
  artifact, reworded caveat, named sources retained, dual-use promoted,
  plain-text ships alongside the image).
- **Extension v1** finished and ready to ship — final pixel-coffee-mug icons;
  popup/options restyled to the warm/periwinkle brand (self-hosted Archivo +
  IBM Plex Mono); escalation copy-out fixed (button `COPY`, no recommendation
  line, neutral provenance). Submission **zip is on Carl's Desktop**
  (`socdesk-extension-v1.zip`). Store upload (Unlisted, `privacy.html` as the
  policy URL) is **Carl's action.**
- **`BACKLOG.md`** — added the analyst-utility expansion lane (highlight→engine
  dispatcher, ACCURACY-FIRST) and the public-vs-private data boundary. See §9.

### In flight — design explorations (mockups UNCOMMITTED in `design/mockups/`)

> ⚠ The **verdict-graphic** and **logo** items below are **SUPERSEDED by §0
> (session 2)** — the verdict graphic is now decided (**Core radar + range-gate
> companion**, not Severity Spine), and the logo direction changed to an
> **image-generated asset** (ref = `chatgptbrandsheet.png`). Kept for context.

- **RADAR globe hero (Phase 3)** — NOT built. Plan: self-host GSAP + globe.gl
  locally, a local/embedded earth texture (CSP-safe), a self-drawn dot-matrix
  fallback, tighten CSP `script-src` to `'self'`. On hold until the foundation +
  logo + verdict-graphic settle.
- **Verdict graphic** (`design/mockups/verdict-graphic-explore.html`) —
  replacing the VT-donut score ring. Recommended: **B · Severity Spine**
  (segmented bullet meter unifying the CVE score + the N-of-M tally, animated)
  as the primary mark; **A · Threat Radar** (spider-scope, on-brand) as a
  secondary CVE-page view. **Owner picking.**
- **Logo redesign** (`design/mockups/logo-v2.html`, being built) — the pixel mug
  had a tonal mismatch; refining a dimensional coffee mug + periwinkle pixel
  steam (owner-provided reference), glow-free, in our tokens, proven at 16px.
  **Owner picking.**

### Leg 2 (Threat-Intel bulletins) — PLANNED, not built
- The full build plan + the **`brief.json` contract** (`schemas/brief.schema.json`
  + `tests/fixtures/brief/example.json`) were produced **inline** by the
  architect (Write was disabled) and are **NOT yet persisted to disk** — the
  exact content is in this session's task logs. **Next session: persist them
  first,** then dispatch the two lanes. Shape: `pipeline/cluster.py` (dedup) +
  rank (reuse `relevance.py`) + trending (extend `history.py`) + register
  `brief.json` in `validate.py`'s gate + a stubbable local-LLM summarizer
  (`pipeline/llm.py` + `pipeline/summarize.py`) + extend `renderBrief`. CI never
  calls the LLM; the box writes `brief.stories.json`.
- **Summarizer model (empirically verified on the Framework box):** target
  LiteLLM **`summarize-local` (Qwen3-Next-80B-A3B)** — 3–4 s / ~150 tokens,
  grounded. The paper pick "reuse GLM-4.7-Flash" was **rejected** by the box
  test (verbose/slow: 25 s / ~1,300 tokens). Optional: re-probe GLM with
  thinking off; add `Qwen3.6-35B-A3B` (~21 GB, Apache) as `brief-local` for half
  the memory.
- **Sequencing:** build Leg 2 **only AFTER the RADAR rebuild lands** — both touch
  `site/js/views.js` + `index.html`; never run them concurrently.
- **One structural decision pending owner:** trending is pipeline-owned (free,
  every run) and `brief.json` publishes even with empty stories → the Brief tab
  would appear on trending-only (a behavior change). Confirm before building.

### Infra (from the Framework Stack Bible, reviewed)
- LiteLLM live on `framework:4444` (tailnet): `summarize-local` (Qwen3-Next-80B),
  `agent-fast` (GLM-4.7-Flash), gemma; n8n on `:5678`. **SSH `carl@framework`
  works** from Carl's Windows box via Tailscale — **but** Tailscale-SSH
  check-mode needs interactive browser re-approval; flip the ACL
  **`check` → `accept`** (or add a raw key) for durable headless automation.
  No Anthropic key on the box (cloud lane blocked; the local summarizer is
  unaffected).
- Automation: Mode 1 (drive the box via SSH from here) + Mode 2 (delegate to the
  box's local Aider/Claude, plan-then-build). Production brief job = a user
  systemd timer or n8n workflow on the box → `generate_brief.py` → push → deploy.

### Concurrency caution
Background implementation agents edit the working tree. Don't `git pull --rebase`
on a dirty tree; commit only your own files explicitly and let each agent commit
its own.

---

## 1. What this is

**SOCDesk** — a free, public, static threat-intelligence console. An analyst
pastes any indicator (IP, domain, hash, URL, CVE, email) and gets:

1. **A verdict** — authoritative for CVEs (CISA KEV + NVD CVSS + FIRST EPSS);
   for other types an honest "not in corpus" plus type-aware deep links to the
   right public reputation services.
2. **A ticket-ready escalation summary** — the differentiator. No other public
   tool writes the write-up.
3. A ranked threat feed, KEV/EPSS vulnerability triage, ATT&CK actor and
   malware profiles, collection health, source registry, and an analyst
   toolbelt (defang, UTF-16LE Base64 decode, PowerShell parser, IOC extract,
   LOLBin lookup).

Personal project by Carlos Sanchez (SaltyCarl), sibling to his portfolio
**SanchezOnSecurity.com**. Used by his MSSP SOC team; also a portfolio piece.

**North star (owner-set 2026-08-10, governs all prioritization):** 99% of the
analyst workflow is IP/hash → AbuseIPDB/VirusTotal → screenshot the
reputation → paste into the escalation email (URLs: same, via a safe viewer).
SOCDesk exists to make THAT loop painless. Everything else — CVE features
included, for now — is secondary until the loop is excellent. See
`BACKLOG.md` for the loop-to-feature map and the parked list.

**Live:** https://socdesk.io — **DEPLOYED & VERIFIED 2026-08-10.** Cloudflare
Pages project up, custom domain attached (200), deploys green. `/api/enrich`
confirmed live returning real multi-source verdicts (AbuseIPDB, VirusTotal,
ipinfo, MalwareBazaar keyed; GreyNoise keyless by choice). The core Leg-1
lookup loop is in production.
**Repo:** https://github.com/SaltyCarl/socdesk
**Local path:** `C:\Users\Carl\Desktop\Projects\VIGIL\` ⚠️ *folder is still named
VIGIL; the product was renamed to SOCDesk on 2026-08-08. Do not be confused.*
**Domain:** `socdesk.io` — **live** (Cloudflare Pages, custom domain attached,
serving the `web/` app). See §0.

---

## 2. Architecture

See docs/ARCHITECTURE.md — superseded restatement removed 2026-08-19.

---

## 3. Current state

See docs/ARCHITECTURE.md — superseded restatement removed 2026-08-19.

---

## 4. Recently landed (both workstreams are IN, commit `a59a4d9`)

1. **Front-end console rebuild** — `site/index.html`, `site/css/*`,
   `site/js/*`. The editorial scroll-page is now an operational console:
   verdict has its own full-width region under the search (no scroll jump),
   escalation summary renders as a docket instead of raw markdown, hash
   deep-linking (`#q=<indicator>`), topbar nav switches views in place, feed is
   a score-sorted work queue, masthead collapses after the first visit, mobile
   breakpoint added, status dot green.
2. **Relationship index** — `pipeline/relations.py`, `schemas/relations.schema.json`,
   `tests/test_relations.py`, `docs/RELATIONSHIPS.md`. Evidence-backed entity
   edges (ATT&CK actor→technique→software + feed co-occurrence + CVE→vendor/
   product), with the verdict: **no node-link graph**, build the ranked
   "related entities" panel.

**Open item from #2:** `relations.json` is built, schema-gated and deployed
(1.47 MB raw / 101 KB gzipped), but `site/js/data.js` does not fetch it — the
`FILES` array omits `relations`. The RELATED panel does not exist yet, so the
payload currently ships unread. Wiring it is the cheapest remaining win.

---

## 5. Design law — ⚠️ SUPERSEDED (see §0)

See `CLAUDE.md` (binding design law — periwinkle/warm for `web/`) and
`design-system.md` (Chart Room v4 — historical, `site/` only).

---

## 6. Environment gotchas (each of these cost real time)

- **Service worker masks your changes.** The shell is cached cache-first.
  **Bump `VERSION` in `site/sw.js` on every shell change** or you (and every
  returning visitor) will see the old UI. Masked three changes this session.
- **A push to `main` does NOT auto-deploy `site/` changes.** The
  `collect-and-deploy.yml` workflow only redeploys on its cron (`:11`/`:41`), a
  manual `workflow_dispatch`, or a push whose paths match **`data/brief.json`**
  (the `paths:` filter — the Framework's Tier-2 brief pushes, via a deploy key
  that can retrigger). A normal push that changes the shell / JS / CSS / `sw.js`
  just sits on `origin/main` until the next cron tick (≤30 min) or a manual run —
  the edge keeps serving the old shell. **To ship a shell change now:**
  `gh workflow run collect-and-deploy.yml -R SaltyCarl/socdesk`, then
  `gh run watch <id> --exit-status` (the run also runs pytest + collectors before
  the `wrangler pages deploy site` step, ~3 min). **Symptom of the trap:** a new
  asset returning HTTP 200 at a fixed ~16.5 KB is the Cloudflare Pages
  404-fallback page (the file isn't deployed yet), not the real file. Cost ~15 min
  of "broken deploy" diagnosis before the `paths:` filter was spotted.
- **CSP has no `unsafe-inline`** — a single `style=""` attribute or inline
  `<script>` breaks it. `csp.spec.js` catches it. Use classes or
  `el.style.setProperty()` (CSSOM writes are allowed).
- **`<use href="#symbol">` renders into shadow DOM** — outer CSS cannot style
  non-inheritable properties (opacity, animation) there. Inline the SVG if you
  need to animate it.
- **IntersectionObserver `threshold` > 0 never fires on elements taller than
  the viewport.** Use `threshold: 0`. This left 18 elements permanently
  invisible once.
- **Python:** no `python` on PATH. Use `.venv\Scripts\python.exe`.
  (Installed 3.12.10 via winget this session.)
- **Playwright MCP browser lock:** if it errors "browser is already in use",
  kill Chrome processes whose command line contains `ms-playwright-mcp`, then
  retry. `file://` is blocked — serve over HTTP.
- **Local servers:** `:8473` serves `site/`, `:8471` serves the repo root
  (mockups). Node one-liners; restart if a session ends.
- **Domain checks:** Comcast DNS hijacks NXDOMAIN so everything looks
  registered. Use `https://rdap.org/domain/<name>` (404 = available).
- **Agents die** emitting >32k output tokens — instruct chunked Write+Edit
  builds under ~15KB per call, always. Agent transcripts also expire; re-brief
  fresh rather than assuming a resume works.
- **Rebase conflicts on `data/state/*.json`** are generated data — take either
  side and re-run the pipeline.

---

## 7. Verification discipline (non-negotiable)

The cautionary tale: sanitization was committed, declared safe, and shipped
with **two working XSS bypasses** (an unterminated tag borrowing a `>` from
surrounding markup; a scheme-prefix URL check allowing attribute breakout).
Both now have regression tests.

- "Fixed" requires a test that fails without the fix.
- "Renders" requires a screenshot and a clean console.
- "Works" requires pasted command output.
- Never trust an agent's summary — re-run it yourself.
- A green first run of a new test suite is suspicious.

---

## 8. Pending — owner actions & open work

**Owner:**
- ~~Cloudflare Pages~~ **DONE.** ~~Chrome Web Store dev account~~ **DONE**
  (under `carlos@sanchezonsecurity.com`, a Cloudflare-forwarded alias — created
  the Google account via "use existing email"; publisher = SanchezOnSecurity).
- **Ship the RADAR rebuild** (built + uncommitted, see §0) — the **logo is now
  settled,** so the remaining path is the **segmented next-session plan (§0):**
  wire the SD logo, fix the light-theme globe, add the globe elevations, finish
  the verdict graphic + globe Phase 3, then **commit `site/` and make the ship
  call.**
- **Verdict graphic — DECIDED** (session 2, §0): **Core radar** for CVEs + a
  **range-gate companion** for the consensus tally (supersedes the old "Severity
  Spine" rec). Remaining: pick the center number (**EPSS%** vs **KEV+CVSS+EPSS
  composite**) at build time, then wire into `verdict.js` / `evidence.js`.
- **Logo — RESOLVED (session 3, §0).** Locked to the **SD Monogram** (brand-sheet
  Option 1); the mug is demoted to a secondary motif. Asset =
  `design/mockups/sd_logo.svg` (theme-aware, on the **existing tokens — no
  re-skin**), committed design-only at `c4cd6fd`. Remaining code work: **wire it
  into `site/`** (topbar + favicon + **2-bar 16px cut** + hero lockup) and
  **revert the experimental `site/favicon.svg`.**
- **Upload Extension v1** to the Chrome Web Store **Unlisted** — the submission
  zip is on Carl's Desktop (`socdesk-extension-v1.zip`), `socdesk.io/privacy.html`
  as the policy URL.
- **Tailscale SSH ACL flip** (`check` → `accept`) for durable headless box
  automation.
- **Leg 2 green-light:** ransomware.live license call (leans keep, non-commercial),
  abuse.ch free key (add?), and confirm the trending / Brief-tab structural
  decision (§0) before the build starts.
- Optional: employment IP-assignment clause (gates repo-private + Leg-3 sensor).

**Open code work (next):**
- **Commit + deploy the RADAR rebuild** once the owner picks the ship path
  (§0 lists the uncommitted files; bump `sw.js` is already at v15). Not done here
  because this handoff commits `docs/` only.
- **Persist the Leg-2 `brief.json` contract + build plan** — currently only in
  this session's task logs (`schemas/brief.schema.json` +
  `tests/fixtures/brief/example.json`), then dispatch the two lanes. Build Leg 2
  **only after** the RADAR rebuild lands (shared files — see §0).
- **Dogfood** — 2-3 analysts run real alerts through the live tool + extension.

---

## 9. Backlog — superseded by BACKLOG.md (updated 2026-08-11)

See `BACKLOG.md` for the current priorities, lanes, and parked-work map.

---

## 10. Key documents

See the Documentation table in README.md (the single source for the doc map).

**Attribution policy:** all commits are SaltyCarl with **no AI attribution**
anywhere, including automated ones. Non-negotiable.
