# SOCDesk — Session Handoff

**Written:** 2026-08-08 · **Updated:** 2026-08-11 (session 2 — brand/logo) · **Read §0 first.**

---

## 0. LATEST — 2026-08-11 (session 2 — brand/logo · NO shippable logo)

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

### LOGO — UNRESOLVED (the time sink) — do NOT re-enter the loop
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
**Domain:** `socdesk.io` registered (Cloudflare), **DNS not yet pointed** — see §8.

---

## 2. Architecture

Three tiers, each independently degradable:

- **Tier 1 — collection.** GitHub Actions cron (`:11`/`:41`) runs 5 Python
  collectors → normalised JSON → schema gate with last-known-good fallback →
  deploy. `data/state/` is committed (last-known-good + daily history
  snapshots); `site/data/` is gitignored and regenerated every run.
- **Tier 2 — brief (not built).** Framework Desktop will write `data/brief.json`
  via local LLM; the pipeline already passes it through and the site already
  renders an absent-state. Deploy-key pushes retrigger the workflow;
  `GITHUB_TOKEN` state commits do not — that asymmetry is intentional.
- **Tier 3 — site.** Static, vanilla ES modules, no framework, no build step.
  GSAP (core + ScrambleText + DrawSVG) from `cdn.jsdelivr.net`; there is no d3,
  and the three tags currently carry **no `integrity`/`crossorigin` attributes**
  — adding SRI is open work, not a shipped property. Analyst state in
  localStorage only.

**Collectors (all keyless/public):** CISA KEV · NVD (recent-modified **plus the
full KEV catalogue via `hasKev`**) · FIRST EPSS · Ransomware.live (group-level
only) · RSS pool (9 feeds).

**Aggregator rule (COMPLIANCE.md):** we publish only clearly-redistributable
data. Reputation corpora (abuse.ch, VirusTotal, AbuseIPDB) are reached by
**user-clicked deep links, never mirrored**. This is why there is no
`iocs.json`.

---

## 3. Current state

- **58 pytest + 49 Playwright** as of 2026-08-09 (counts drift as work lands;
  run both). The browser suite is **flaky under parallel workers**: a full run
  reported 47/2 with `csp.spec.js:29` and `degrade.spec.js:13` failing, both of
  which pass in isolation, and the next full run passed 49/49.
  `playwright.config.js` sets `retries: 0` — treat the flakiness as a bug.
- Pipeline clean: `problems=[]`.
- CSP is strict — `default-src 'none'`, **no `unsafe-inline`, no `unsafe-eval`**.
  Served via `_headers`, with a `<meta>` copy as fallback. `csp.spec.js` fails
  if the two drift apart.
- Self-hosted fonts (no Google requests), PNG OG card, mug favicon.
- Service worker gives offline capability.

**Recently fixed, do not regress:**
- **CVE join** — was 42 of 1,662 KEV rows with CVSS (2.5%); now **1,662/1,662**.
  Root cause: NVD only fetched a 2-day modified window while KEV spans
  2014-2026. Fixed with a second `hasKev` query in `collectors/nvd.py`.
- **Feed relevance** — `pipeline/relevance.py` scores every item 0-100 with an
  explainable `why` array, and groups repetitive ransomware victim-claim stubs.
  594 items → 302.

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

**Historical.** The owner pivoted away from Chart Room to the RADAR direction on
2026-08-10; the fonts, the "settled — do not re-litigate" note, and the mug
lockup rules below are being replaced (branding pass in flight). Do NOT apply
this section to new design work — follow §0 and the RADAR mockups. Kept for
context only.

`design-system.md` v4 **"Chart Room"** — brutalist-editorial print.

- Ink `#0F161C` · panel `#141D26` · line `#263644` / `#3C566C`
- Paper/accent **bone `#E8E1CF`** (carries the brand; solid fills with dark text)
- **Vermilion `#E2513A` at stamp scale ONLY** — seal, never illumination
- Severity as desaturated print inks; **purple = AI content only**;
  **gray = unknown, never green**
- Archivo (variable, expanded caps) + IBM Plex Mono for all data values
- **Zero border-radius. No shadows. No glows. No gradients on components.**
- Motion is scarce and data-honest; the only ambient motion is the ticker,
  status pings, and the mug's steam

**The mark:** a pixel coffee mug, a deliberate sibling of the SoS logo (**no
handle** — the parent has none). Agreed lockup law: *the seal always lives at
the O.* Word ≤32px → the mug **is** the O (letter cut). Word >32px → the type O
returns and the same-size mug is struck **inside its counter**. The mug never
scales; the word does. Favicon = the seal alone.

**Direction is settled — do not re-litigate.** An art-direction review
confirmed Chart Room works and that a pivot would burn weeks. The owner's
complaints were about *information architecture and data plumbing*, not the
visual language.

---

## 6. Environment gotchas (each of these cost real time)

- **Service worker masks your changes.** The shell is cached cache-first.
  **Bump `VERSION` in `site/sw.js` on every shell change** or you (and every
  returning visitor) will see the old UI. Masked three changes this session.
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
- **Ship the RADAR rebuild** (built + uncommitted, see §0) — decide the ship
  path: **ship-with-globe** (build the Phase-3 globe hero first, then deploy the
  complete rebuild) vs **ship-now.** Lead recommendation: with-globe, after the
  logo + verdict-graphic settle.
- **Verdict graphic — DECIDED** (session 2, §0): **Core radar** for CVEs + a
  **range-gate companion** for the consensus tally (supersedes the old "Severity
  Spine" rec). Remaining: pick the center number (**EPSS%** vs **KEV+CVSS+EPSS
  composite**) at build time, then wire into `verdict.js` / `evidence.js`.
- **Logo — UNRESOLVED, still gates the ship.** No longer a mockup pick: it needs
  an **image-generated asset** — Carl exports the full-res ChatGPT master
  (`chatgptbrandsheet.png` is the reference), OR local gen on the Framework box
  (ComfyUI + FLUX, reference-conditioned). Do NOT hand-code SVG from text or crop
  the screenshot again — see §0 (session 2).
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

Priorities were re-cut around the north star (§1): **P0 DONE** (Cloudflare Pages
+ enrichment keys live); **P1** hammer the 99% loop (dogfood with real analysts,
urlscan screenshot preview, Browserling link verification); **P2** the
CVE/threat-intel feed as the second pillar. Two lanes were added on 2026-08-11
(in `BACKLOG.md`):
- **Analyst-utility expansion lane** — broaden the extension's select →
  type-detect → focused-output gesture into an L1/L2 investigation copilot
  (highlight→engine dispatcher): command-line deobfuscator (top pick), universal
  decoder, event-ID/ATT&CK lookup, IOC-from-selection, and a vetted SIEM
  table/query recommender (KQL/Sentinel first). **ACCURACY-FIRST** — deterministic
  curated content, not on-the-fly LLM; additive, must not slow the core loop.
- **Public-vs-private data boundary (HARD RULE)** — the public site's LLM only
  processes public data and user input is a bare indicator; any LLM-on-internal-
  data assist (escalation-draft, alert/log/phishing triage) is **PRIVATE-ONLY**
  (a private instance or BASTION/CARL), never socdesk.io.

Fuzzy search, CVE sharding, Phase C brief, honeypot (IP-gated), and wave-2
collectors remain **parked** — see `BACKLOG.md` for the full map. Historical
notes remain valid (enrichment worker spec:
`docs/superpowers/specs/2026-08-07-enrichment-worker-spec.md`; honeypot
non-negotiables in BACKLOG history / git).

---

## 10. Key documents

| File | What it holds |
|---|---|
| `README.md` | The front door: what SOCDesk is, capabilities, quickstart, link map |
| `CLAUDE.md` | Repository conventions, commands, load-bearing rules, commit policy |
| `docs/ARCHITECTURE.md` | The system end to end: tiers, contracts, schema gate, failure isolation, known gaps |
| `docs/OPERATIONS.md` | Runbook: local runs, cron, reading health, collector triage, deploy, rollback, SW version bump |
| `docs/DATA-SOURCES.md` | Per-source terms, cadence, republished vs link-only, governing R-numbers |
| `docs/ANALYST-GUIDE.md` | User-facing: lookups, verdict meaning, scoring, escalation, handoff, limits |
| `docs/RELATIONSHIPS.md` | The relationship index and why there is no node-link graph |
| `docs/AUTOMATION.md` | The autonomous build loop, Definition of Done, hard gates |
| `COMPLIANCE.md` | Licensing/legal findings + launch gates. **Read before adding any data source.** |
| `docs/VERDICT-LANGUAGE.md` | **BINDING** — the consensus-tally model ("N of M flagged"), per-source attribution, escalation card (no recs, COPY), CVE language |
| `docs/superpowers/specs/2026-08-10-analyst-reach-scope.md` | Bookmarklet / context-menu / MV3 extension reach roadmap |
| `docs/superpowers/specs/2026-08-02-frontend-elevation-charter.md` | Front-end elevation research (motion engines, native APIs, stack) |
| `extension/` | MV3 browser extension v1 (`README.md` = load/test/ship; `PRIVACY.md`) |
| `site/privacy.html` | Hosted privacy policy (the store submission URL) |
| `design/mockups/rebuild-radar-v{1,2,3}.html` | The RADAR direction iterations (superseded by the in-tree evolved site, §0) |
| `design/mockups/verdict-graphic-{explore,radar-round2}.html` | Verdict-graphic explorations — **DECIDED: Core radar + range-gate companion** (§0 session 2) |
| `design/mockups/palette-explore.html` | 3-way palette comparison — **CONFIRMED #1 warm + periwinkle** (§0 session 2) |
| `design/mockups/logo-v{2,3}.html`, `favicon-v3.svg` | Logo explorations — **superseded**; logo is now an image-gen task, ref = `chatgptbrandsheet.png` (§0 session 2) |
| `design-system.md` | Chart Room v4 — ⚠️ SUPERSEDED by the RADAR/periwinkle direction (see §0) |
| `design/brand.md` | Brand book — partly stale; the mug is being refined in the branding pass |
| `BACKLOG.md` | Wave-2 collectors, knock-knock review, honeypot architecture + security review, CARL port notes |
| `docs/INFRASTRUCTURE-OPTIONS.md` | What each infra tier unlocks and costs |
| `docs/superpowers/plans/` | Phase A (pipeline, done) and Phase B (site) plans |
| `design/mockups/g-chartroom.html` | The approved visual reference |
| `design/mockups/h-sensor.html` | Honeypot dashboard mockup w/ 3 globe styles |

**Attribution policy:** all commits are SaltyCarl with **no AI attribution**
anywhere, including automated ones. Non-negotiable.
