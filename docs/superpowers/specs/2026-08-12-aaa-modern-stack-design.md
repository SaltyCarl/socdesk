# SOCDesk — AAA Modern-Stack Migration + Verdict/Escalation System · Design Spec

**Date:** 2026-08-12 · **Status:** approved direction, pre-plan · **Supersedes:** the vanilla/no-build posture for the site (the lookup engine, data pipeline, and canvas copy-card mark are unaffected).

This spec captures a long design session (globe fusion → verdict system → LARP critique → market/design research → stack decision). It is the input to `writing-plans`.

---

## 0. The decision, in one line

Rebuild the **site** on **Vite + React + Tailwind + Motion (motion.dev)** to reach genuinely AAA craft, **while preserving a strict, credible CSP** (`script-src 'self'; style-src 'self'`, no `unsafe-inline`/`unsafe-eval`). The escalation **card system** is the product's differentiator and is redesigned around an honest, attributed, source-class-aware model with per-entity-type heroes.

## 1. Why (evidence trail)

- Two adversarial critics (CTI strategist + SOC lead) converged: **"real tool, portfolio costume."** The genuine moat is **the honest, attributed, client-ready escalation artifact + catalog-fact-vs-score honesty** — NOT the aggregation (commoditized: Mitaka, SOC Toolkit, Ahtapot, Pulsedive, IntelOwl) and NOT novel verdict glyphs.
- The abstract **"Muster" glyph is LARP as a hero** — it makes the reader who needs it least learn a decode key for data printed in words beside it. Demoted to (at most) analyst-console inline use; not a client artifact.
- Owner decision: **keep the visually-rich v3-style card** (portfolio value), with the honesty refinements; **text always travels alongside the image** (survives tickets/mail-filters/ToS).
- Market research: **VirusTotal's "N of M flagged" fraction IS a consensus tally** — the industry-canonical, most-legible verdict primitive. Rendered *literally* it's both honest and client-legible.
- Stack: the addendum proved **B keeps `script-src 'self'` intact** and keeps `style-src 'self'` if we use Tailwind (static CSS) + Motion.dev/WAAPI (not Framer Motion) + a no-inline-style lint rule. So B costs only a rewrite, not a security downgrade — and React/Tailwind is itself a portfolio asset.

## 2. Architecture

- **Stack:** Vite + React + TypeScript + Tailwind (static compiled CSS) + **Motion (motion.dev)** for springs, **native WAAPI** for discrete transitions, **CSS scroll-driven animations** (`animation-timeline`) for scroll choreography (progressive-enhanced, static fallback).
- **CSP posture (inviolate):** `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; …`. **No `unsafe-inline`, no `unsafe-eval`.** Enforced by: Tailwind-only styling, `build.assetsInlineLimit: 0`, a lint rule banning `style={{}}` and CSS-in-JS, Motion.dev (WAAPI-based; animates via `element.animate()`/CSSOM property setters, outside `style-src`). If any lib insists on Framer Motion's initial inline styles, either refactor to className/data-* + post-mount motion values, or scope a `style-src 'unsafe-inline'` (bounded downgrade) — **never touch `script-src`**.
- **Deployment:** Vite → static output → Cloudflare Pages (unchanged host, still static). The `collect-and-deploy.yml` workflow builds the site (add `npm ci && vite build`) then `wrangler pages deploy`. Site-shell change → still needs the deploy trigger (see [[socdesk-deploy]]).
- **Extension:** stays MV3; may share the compiled evidence/verdict modules. The **copy-card verdict mark stays a deterministic canvas draw** (byte-identical PNG), one shared `drawVerdict(ctx, data)` module for site + extension.
- **Hero WebGL:** the cobe globe stays; the optional animated gradient is a **vendored single-quad fragment shader** (ShaderGradient *technique*, MIT — not the R3F package), gated on `prefers-reduced-motion` + `IntersectionObserver` + DPR cap; **only one GL loop animates at a time** (globe OR gradient).

## 3. The verdict / escalation system

### 3.1 Doctrine refinements (VERDICT-LANGUAGE.md v2)
- **Tally = coverage, not a threat score.** Low N reads "thin coverage; N sources have no record yet — absence of data is not evidence of safety," never "probably fine."
- **Source-class tags** on every source: `catalog/identity` · `behavioral/observed` · `reputation-score` · `list-membership` (facts about the source, litmus-safe; expose correlation without SOCDesk weighting).
- **Recency** stamp per source + stale flag past ~90d.
- **Confidence ladder** with a **published deterministic precedence**: KEV > hash-catalog > behavioral-observed > reputation-score > list-membership. Lead with the highest-authority attributed fact.
- **Grammatical rule:** the source is always the sentence's subject ("MalwareBazaar catalogs…"), never "Confirmed sample — MalwareBazaar."
- **Hash carve-out:** hashes are identity, not a vote — lead with the catalog fact, show VT ratio as a sub-fact; do NOT wrap a cross-source tally around a hash (like CVEs, §5).
- **Colour decoupled from N/M:** verdict red/amber/green rides per-source ink + the classification chip; an authoritative/behavioral adverse source drives tone; no block-tone wash on the aggregate.
- **PUA/grayware honesty:** "flagged" ≠ "malware." A distinct amber "grayware — flagged, not confirmed malware" state, visually separate from red.
- **"No verdict" reframed honestly:** "we don't invent a score; we attribute each source" (a red band IS a synthesized judgment — don't claim otherwise).
- **Fix §0's false moat claim** (cross-service consensus is NOT novel).

### 3.2 Two registers (one shared data object)
`{indicator, type, flagged, total, sources[{name, verdict, class, finding, recency, url}], band, …}` drives all surfaces.
- **Analyst register** (console + extension): dense, in-context — plain `N / M` fraction + the attributed source table with class tags. (No bespoke hero glyph; the Muster is at most an optional inline sparkline in a multi-row list.)
- **Client register** (escalation card + PNG): the tally made **literal** — the VT-idiom fraction, a plain word-band + shape-icon (redundant encoding), and an evidence ledger. Self-explanatory out of context.

### 3.3 Card framework — one skeleton, a type-appropriate hero
| Type | Hero | Notes |
|---|---|---|
| IP | Geo/ASN map + pin (v3, kept) | assessment leads; geo is context, not the misread-inviting hero |
| Domain | Registration-age timeline + resolved-geo | newly-registered = the tell |
| URL | urlscan page **screenshot** | client sees the fake page |
| Hash | **Malware identity** (family + catalog fact + file facts + first→last timeline) | identity, not tally; hash-card-v2 is the reference |
| CVE | Exploitation-status banner (KEV/EPSS/CVSS) | authoritative, not a tally |

Every card: attributed ledger, client-safe caveat, no branding, **plain-text copy travels with the image**, canvas PNG for the copy-out.

### 3.4 Hash card enrichment fields (grounded in free APIs)
- **Hero:** family, catalog membership, threat-classification chip, **PUA/grayware flag**, file facts, first-seen, detection ratio.
- **Supporting (on card):** aliases/common file names, tags, last-seen/recency, prevalence band, signer status (+ `cscb_listed` revocation counterweight), delivery method.
- **Analyst-only (expand):** network IOCs (ThreatFox `search_hash`, Triage config), MITRE/behavior, YARA (name+count; bodies TLP-gated), fuzzy hashes, per-engine AV (link out, not reproduced — VT ToS).

## 4. Enrichment strategy (de-capping)
- **abuse.ch trio (MalwareBazaar + ThreatFox + YARAify) = the free workhorse** — friendly ToS, self-hostable bulk feeds. Needs the free Auth-Key ([[task #2]]).
- **VirusTotal = tight** (500/day, 4/min, non-commercial, **don't reproduce per-engine results** → ratio + verify-link, cached hard, last resort).
- **Reproduction guardrails:** VT/Hybrid-Analysis → link out; YARAify/Malpedia rule bodies → name+count only (TLP); abuse.ch → free with attribution.
- **Scaling off free tiers (down the line):** self-host bulk feeds (uncapped) → aggressive caching (Cloudflare KV/D1) → BYO-key for VT/AbuseIPDB/GreyNoise → (later) Framework backend / OSS aggregator / Leg-3 first-party sensor. Paid tiers only if the project ever goes commercial.

## 5. AAA elevation toolkit (per surface)
- **Motion:** CSS scroll-driven (hero melt/reveal, sticky timelines) · native WAAPI (card hover/press, verdict-pill morph, Sonner-style toasts) · Motion.dev mini for springs · anime.js for SVG/canvas stroke-on draw.
- **Hero:** vendored single-shader gradient (gated) behind/around the globe.
- **Command palette:** reimplement the **cmdk** pattern — the T1/T2 lookup IS a command palette (highest-leverage steal).
- **Effect catalog:** React Bits (CSS variants), Magic UI (pure-CSS subset), Aceternity (Spotlight/Lamp), Vaul/Sonner patterns — consumed directly under B (minus paywalled tiers).
- **Anti-slop guardrail:** take motion mechanics, drop frosted-glass-for-its-own-sake; espresso + periwinkle; red/amber/green verdict-only; no cream/serif "AI slop."

## 6. What we are NOT building
- The Muster as a client-facing or hero mark (LARP). The pip-row as a 4th encoding. A synthesized SOCDesk score/grade/likelihood. Any per-engine VT reproduction into a deliverable. A branded footer on the copied artifact.

## 7. Open owner actions
- Free abuse.ch Auth-Key ([[task #2]]). · Confirm the CSP style-src stance if Framer Motion is ever wanted. · Employer-IP question (gates repo-private + Leg 3).

## 8. Build phasing → agent team (feeds writing-plans)
1. **Scaffold** — Vite+React+TS+Tailwind+Motion, CSP config, lint rules, deploy pipeline update. (sequential, 1 agent)
2. **Design system** — tokens (espresso/periwinkle, type scale, spacing, radii), primitives, motion language, the shared `drawVerdict` canvas module. (1 agent, gates the rest)
3. **Parallel build** — independent surfaces: (a) shell/nav + command palette, (b) globe hero + shader, (c) verdict/escalation card system (IP/hash/domain/URL/CVE), (d) feed/vulns/actors views, (e) enrichment client + doctrine. (parallel agents, worktree isolation)
4. **Review gate** — code-review + visual-QA (Playwright screenshots) per surface; adversarial verify.
5. **Integrate + ship** — assemble, CSP verify, deploy, live-verify.
