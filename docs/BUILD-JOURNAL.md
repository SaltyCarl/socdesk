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
