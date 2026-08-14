# SOCDesk — Build Journal

Maintained by **NT** (the note-taking agent, `.claude/agents/nt.md`). A dated,
newest-first record of feature work shipped, so context survives across sessions
and compaction. **Read this first** at the start of a SOCDesk session (a
SessionStart hook also injects it; after compaction it is re-injected).

**How NT works:** invoked at feature checkpoints and before wrapping/compaction,
NT appends one dated entry — what shipped, key files, commit hashes, deploy/verify
status. The Product Overview PDF (`docs/SOCDesk-Overview.html` → `.pdf`) carries a
human-facing mirror of these entries.

---

## 2026-08-14 — AAA modern-stack web build + three.js globe + extension parity (phases 0–2)

Execution of the 08-13 AAA stack decision. **Shipped to `main` this session** (11 commits `b8ef760`→`2a71916`); `web/` and the extension both build clean, verified in-tree. **`web/` is NOT deployed** — socdesk.io still serves the vanilla `site/`; the deploy flip is gated on Carl's explicit go.

**Shipped:**
- **AAA web rebuild — task #13** (`web/`, Vite + React + TS + Tailwind v4 + Motion under strict CSP). Phases 1–4 + a site-effects pass all integrated. Routes: `/` (Overview), `/lookup` (escalation cards), `/desk` (feed/vulns/actors/health/sources), `/gallery`. Commits `b8ef760` (phases 3–4 surfaces), `9795f37` (mobile hamburger nav + domain copy-card hero), `0dbe617` (hero entrance/ambient, stat count-ups, copy toast).
- **Globe rebuilt in three.js** (from vendored cobe) for the highest ceiling + a real **light mode** — cobe rendered an opaque dark-orb-on-cream, a persistent bug. New: 3D dot-sphere (transparent fresnel body), attack arcs (free depth-buffer occlusion), critically-damped spring fly-to, verdict range-lock landing, pointer parallax. Hand-wired `three` (NO R3F/drei/DRACO/KTX2/troika/CDN — landmask is a bundled `data:` URI) → CSP-clean; `three` code-split so other routes don't bloat. Swapped into Overview; old cobe files (`web/src/components/hero/vendor/cobe.js`, `GlobeHero.tsx`, `useGlobe.ts`) left to tree-shake. Files: `web/src/components/hero/globe3.ts`, `GlobeHero3.tsx`, `GlobeStage3.tsx`, `useGlobe3.ts`. Commits `5a31fda` (rebuild, preview at `/globe3`), `5f00607` (clarity pass — denser/higher-contrast dots, less empty sphere), `b4553ad` (attack arcs, fresnel limb, terminator, parallax).
- **Extension parity uplift — architecture A** (extension gets its own React build + reuses the web cards via a shared source package). Phases 0–2 done:
  - **Phase 0** `c6c091c` — extracted verdict lib + card components + ui primitives + design tokens into a shared `@socdesk/shared` **source** package. Mechanism: tsconfig paths + Vite `resolve.alias`/`dedupe` + Tailwind `@source` — **NOT** an npm workspace. Web restructured, verified INERT (`/lookup` + `/gallery` pixel-identical). Files: `shared/verdict/`, `shared/cards/`, `shared/ui/`, `shared/tokens/`.
  - **Phase 1** `c680aaa` — extension got its own Vite/React MV3 build; renders the shared `AnalystVerdict` under MV3's default CSP.
  - **Phase 2** `98d9428` — real popup UX (indicator input → live `AnalystVerdict` + copy-card + context-menu handoff) wired to the LIVE enrich API. Live-data dogfood caught + fixed a **doubled-verb bug** (live VirusTotal headlines "flag this as malicious" doubled through the doctrine → `normalizeFinding()` in `shared/verdict/map.ts`). Deep-link uses `#q=` (fragment), not `?q=`.
- **Brand fixes** `e7568da` — wired the real SD monogram (approved `design/mockups/sd_logo.svg`, inlined as a shared component so it theme-adapts) into the topbar (was a placeholder "SD" box); restored the slogan **"IOC in. OSINT out."** (the globe-hero swap had silently dropped it).
- **Overview redesign** `2a71916` — three.js globe + a "situational board" filling the lower half (from existing data, honest daily-batch framing).

**Reviewed (outcome, not yet built):**
- Carl critiqued the Overview redesign (CVE flood + LARPy verbiage); two adversarial critics validated. **Approved rework plan — DO NEXT SESSION:**
  - **Panels:** root cause is a **ranking artifact** — score caps (vuln maxes 85, ransomware 30, apt 8) make a global score-sort render an all-KEV wall, yet vuln is only ~16% of the feed. Fix = **per-lane selection**. New set: Overview stats (add ransomware-claims / active-groups counters) → Ransomware activity leaderboard (flagship, from feed `ransomware.live` — 268 victim claims / 52 groups was the buried "who's active" gem) → Named-actor activity (apt/campaign feed items) → ONE patch-priority CVE panel (absorbs the 3 current CVE panels) → freshness strip. Demote "severe but unexploited" to `/desk`.
  - **Voice — de-LARP:** "Situational board"→"Daily threat summary", "The judgment we bring"→"Triage", "What's hot"→"Priority", "Top of the queue"→"Highest-scoring reports", "Exploited ≠ severe"→"Exploitation vs. severity"; drop nicknames ("the sleepers", "loud scores quiet so far"); source stamps → cite upstream authority (NVD·EPSS·KEV) or drop the filename stamps.

**Corrections to stale notes:**
- The enrich API (`https://socdesk.io/api/enrich`, `functions/api/enrich.js`) is **LIVE** — returns real AbuseIPDB/VirusTotal data (NOT dormant as older notes said; `/api/health` 200).
- `actors.json` / `malware.json` are **static MITRE catalogs** (no recency) — the live activity signal lives in the **FEED**, not there.

**Strategic (forward note):** the platform is a candidate base for Carl's own threat-intel **writing / content creation** later. General-TI article ingestion already runs (RSS pool: BleepingComputer, The Hacker News, Talos, Unit 42, DFIR Report, MSTIC, GTIG, SANS ISC, Securelist). Two maturation priorities before scaling article volume: effective **DEDUP** (a single story/CVE currently renders multiple times — e.g. CVE-2026-8037 3× on the board) and real **PRIORITIZATION** (the per-lane ranking fix above).

**Verified:** in-tree — visual QA of the AAA surfaces in both themes with **0 CSP violations**; `web/` builds clean; shared-package extraction verified INERT (`/lookup` + `/gallery` pixel-identical, 76 tests at phase 0 → 81 tests at phase 2). Extension MV3 build renders the shared verdict; popup dogfooded against the live enrich API (surfaced the doubled-verb fix). Not deployed — no live verification of `web/`.

**Open / next:**
- **Board rework** (approved plan above) — build next session.
- **Deploy flip** `site/` → `web/` on Cloudflare Pages — gated on Carl's explicit go; `web/` is NOT live yet.
- **Extension Phase 3** (final parity QA) — Carl's to run: load `extension/dist` unpacked in Chrome → right-click → "Check in SOCDesk".
- **Pipeline gaps:** `trends.epss_movers` is empty; a slim pipeline-derived `overview.json` would avoid the board's ~5 MB `cves.json` fetch.

---

## 2026-08-13 — AAA modern-stack decision + verdict/escalation system design

Long design session (globe fusion → verdict system → LARP critique → market/design research → stack decision). **No code shipped; direction locked.** Authoritative spec: `docs/superpowers/specs/2026-08-12-aaa-modern-stack-design.md`.

**Decisions locked:**
- **Stack pivot → B:** rebuild the site on **Vite + React + Tailwind + Motion (motion.dev)** for AAA craft, **keeping strict CSP** (`script-src 'self'; style-src 'self'`, no unsafe-inline/eval — via Tailwind static CSS + Motion.dev/WAAPI + a no-inline-style lint rule). Lookup engine, data pipeline, canvas copy-card mark unaffected. React/Tailwind is also a portfolio asset. (CSP addendum proved B keeps the strict policy — only Framer Motion would force a style-src downgrade; use Motion.dev instead.)
- **The moat = the honest client-ready escalation artifact + catalog-fact-vs-score honesty** — NOT aggregation (commoditized: Mitaka/SOC Toolkit/Ahtapot/Pulsedive/IntelOwl) or novel glyphs. Two adversarial critics converged: *"real tool, portfolio costume."*
- **Muster glyph = LARP as a hero** → demoted (at most an inline sparkline in a multi-row analyst list). **Keep the visually-rich v3-style card** (owner call); **text always travels with the image**.
- **Verdict doctrine v2:** tally-as-**coverage** (not a threat score) · source-class tags (catalog/observed/score/list) + recency · confidence ladder w/ published precedence (KEV > hash-catalog > behavioral > score > list), source-subject-first · **hash carve-out** · colour decoupled from N/M · **PUA/grayware honesty state** · fix §0's false "no one does consensus" claim.
- **Two registers, one data object:** analyst = plain N/M + attributed table; client = literal VT-idiom fraction + word-band + ledger (self-explanatory out of context).
- **Card framework — one skeleton, type-appropriate hero:** IP=geo(v3) · hash=malware-identity · domain=reg-age timeline · URL=urlscan screenshot · CVE=exploitation banner.
- **Enrichment:** abuse.ch trio (MalwareBazaar/ThreatFox/YARAify) = free workhorse (needs free Auth-Key, task #2) · VT = tight (500/day, non-commercial, ratio+link-out only). De-cap path: self-host bulk feeds → cache → BYO-key → (later) Framework backend / Leg-3 sensor.
- **AAA toolkit:** CSS scroll-driven + WAAPI + Motion.dev + anime.js (SVG/canvas) + vendored single-shader gradient (gated: reduced-motion + IntersectionObserver + one-GL-loop) + **cmdk-pattern command palette** (highest-leverage steal — the T1/T2 lookup IS a palette). Effect catalogs (Magic UI, Aceternity, React Bits) consumed directly under B. Anti-slop: motion mechanics not glass; espresso+periwinkle; verdict-colour reserved.

**Mockups (design/mockups/):** verdict-muster.html · verdict-two-registers.html · escalation-card-hash.html · escalation-card-hash-v2.html (AAA craft pass: Archivo/IBM Plex Mono, red-verdict-only, custom C2 glyph, duration bar, left-aligned ledger, PUA state). AAA benchmark: hash v1 "competent-but-mid ~7/10" → v2 closed the mechanical gaps.

**Next:** writing-plans → phased agent-team build (scaffold → design system → parallel surfaces → review gate → integrate/ship).

---

## 2026-08-12 — Escalation card regrounding + deploy-pipeline fixes

**Shipped (live on socdesk.io, verified):**
- **Escalation card regrounded to `escalation-card-v3`.** On IP/domain/hash the
  geo-led **image card is the escalation output** (Copy card + Copy text); the
  "Intelligence summary" text docket is now **CVE-only**. The "text card" form was
  deliberately removed. Files: `site/js/verdict.js`, `site/js/enrich-client.js`,
  `site/css/panels.css`. Commit `2700ef6`.
- **Fixed the `.live` layout collision** — the live-enrich box shared the class
  `.live` with the topbar status pill (`display:flex` row), flinging the
  escalation image card ~3,000px off-screen (clipped by `overflow:hidden`), so
  only the text docket showed. Renamed to `.live-enrich`.
- **Fixed the real deploy-propagation bug (sw v19).** `sw.js` install used
  `cache.add()`, which fetches through the browser's 4h HTTP cache — so each
  deploy baked the **stale** shell into the new versioned cache and served it
  cache-first. Returning visitors got the old UI for up to 4h after every deploy.
  Install now fetches with `cache:'reload'`. Commit `a6230bd`. (Likely masked the
  earlier logo/globe ship too.)
- **Shipped the RADAR rebuild** earlier this session: SD monogram logo, cobe globe
  hero, Core-radar verdict + range-gate companion, GSAP removed, CSP tightened to
  `script-src 'self'`. Commit `be05396`, sw v17.

**Verified:** live Playwright — IP path (image card in-flow, no docket, zero
overflow, Copy card + Copy text) and CVE path (docket + radar preserved). v19 SW
cache confirmed to hold the fresh shell.

**Deploy gotcha (load-bearing):** `site/` pushes do NOT auto-deploy.
`collect-and-deploy.yml` triggers on cron (`:11`/`:41`), manual `workflow_dispatch`,
or a push touching `data/brief.json` only. Ship a shell change with
`gh workflow run collect-and-deploy.yml -R SaltyCarl/socdesk`.

**Open / next:** finish NT wiring (SessionStart hook + PDF mirror); Leg 2 gating
decisions (ransomware.live license, abuse.ch key); Extension v1 Chrome Web Store
upload (owner action).
