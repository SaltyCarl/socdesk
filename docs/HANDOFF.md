# SOCDesk — Session Handoff

**Written:** 2026-08-08 · **Updated:** 2026-08-10 · **Read §0 first.**

---

## 0. LATEST — 2026-08-10 (design pivot · consensus model · extension)

Major changes since the body below was written. **These supersede the stale
parts, especially §5 "Design law," which describes the abandoned look.**

**Design pivot — Chart Room is OUT; "RADAR" is the direction.** The owner
reopened the visual identity (§5's "settled, do not re-litigate" no longer
holds — do not follow it). A 3-way bake-off (RADAR / COMMAND / SIGNAL) picked
**RADAR**: dark, search-first, an interactive real-data threat globe as an
analytics hero, teal accent, a **data-table enrichment card**. Iterations:
`design/mockups/rebuild-radar-v{1,2,3}.html` (v3 = globe.gl scroll-zoom +
hover-to-reveal-TI, refined monoline mug mark, trimmed copy). In flight: a
**branding pass** (logo + wordmark + a replacement font — Bricolage isn't
landing) producing `design/mockups/brand-sheet.html`, and a reference-library
review (Watermelon UI, Motion Primitives, Haikei). Elevation research:
`docs/superpowers/specs/2026-08-02-frontend-elevation-charter.md`. Next build =
**RADAR v4** (final logo/font + hero-scale globe + rich escalation card +
consensus data), pending the owner's brand-sheet picks.

**Stack decision — production rebuild moves to React + Vite + Tailwind +
shadcn/ui + Recharts + globe.gl** (the vanilla site stays live meanwhile).
`ui-ux-pro-max` is now the design engine (skill; CLI `search.py` under its dir).
Watermelon UI (MIT, this exact stack) is a component starter kit for it.

**Verdict language — the CONSENSUS-TALLY model (`docs/VERDICT-LANGUAGE.md`,
binding).** SOCDesk NO LONGER emits a verdict word ("malicious"/etc.) in its own
voice. It leads with a source-consensus ratio — "**N of M** public sources
flagged this as adverse" (VT-style; a count, not a pronouncement). ipinfo =
context (out of the tally); no-key sources shown "not consulted." Being
implemented across `lib/enrich.mjs` (new `consensus()`; response gains
`consulted`/`flagged`/`tone`, drops top-level `verdict`), the site, and the
extension **in lockstep**. Escalation card carries **NO recommendation** (the
analyst's call), copy button is **`COPY`**, and becomes a designed artifact.

**Browser extension — v1 built (`extension/`), permission-reviewed, works.** MV3,
minimal perms (`contextMenus`, `storage`; host = socdesk.io + socdesk.pages.dev
only — NO broad host, NO content script yet). Right-click lookup + toolbar popup
over the live `/api/enrich`. v2 = inline page annotation (broad perms — later).
Publisher identity = **SanchezOnSecurity**; owner's Chrome Web Store dev account
is set up. Privacy policy hosted at **`socdesk.io/privacy.html`**. Reach roadmap:
`docs/superpowers/specs/2026-08-10-analyst-reach-scope.md`.

**Privacy stance relaxed** — the "no analytics/no tracking" promise is dropped
(owner: not essential). Cloudflare Web Analytics is fine; if its beacon
CSP-errors, ALLOW it rather than disable. `site/privacy.html` reflects this.

**Concurrency caution:** background implementation agents edit the working tree.
Don't run `git pull --rebase` on a dirty tree; commit only your own files
explicitly and let each agent commit its own.

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
- **Design picks (gates RADAR v4):** from the branding brand-sheet, choose the
  logo variant + wordmark lockup + replacement font.
- **Extension → store:** owner smoke-tested v1 (works). Remaining before submit:
  final mug icons (from the branding pass), package zip, submit **Unlisted**
  first with `socdesk.io/privacy.html` as the policy URL.
- Optional: employment IP-assignment clause (gates repo-private + Leg-3 sensor).

**Open code work (next):**
- **Escalation card fix** — the consensus-tally agent shipped it (commit
  `4221cc3`) against the *pre-feedback* spec, so it still has a recommended-action
  line and a "Copy for ticket" label. Per the updated `VERDICT-LANGUAGE.md`:
  remove the recommendation from the copy-out card (analyst's call) and rename
  the button to **`COPY`**, on both site (`verdict.js`) and extension
  (`popup.js`), updating the tests. Small but explicit.
- **RADAR v4 build** — after brand picks: React+shadcn production frontend with
  the hero-scale globe (globe.gl + Spotlight/progressive-blur so it isn't
  confined to a small circle), richer per-dot hover TI, and the escalation card
  as a designed artifact (Watermelon-UI-style). Reference adoptions in the
  reference-review (Watermelon UI / Motion Primitives / Haikei geometric-only).
- **Dogfood** — 2-3 analysts run real alerts through the live tool + extension.

---

## 9. Backlog — superseded by BACKLOG.md (2026-08-10)

Priorities were re-cut around the north star (§1): **P0** owner stands up
Cloudflare Pages + enrichment keys (unblocks public URL, green deploys, AND
the dormant `/api/enrich`); **P1** hammer the 99% loop (dogfood with real
analysts, urlscan screenshot preview, Browserling link verification);
**P2** the CVE/threat-intel feed as the second pillar. Fuzzy search, CVE
sharding, Phase C brief, honeypot (still IP-gated), and wave-2 collectors are
all **parked** — see `BACKLOG.md` for the full map. Historical notes on each
item remain valid where written (enrichment worker spec:
`docs/superpowers/specs/2026-08-07-enrichment-worker-spec.md`; honeypot
non-negotiables recorded in BACKLOG history / git).

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
| `design/mockups/rebuild-radar-v{1,2,3}.html` | The RADAR direction iterations (v3 current); `brand-sheet.html` = branding options |
| `design-system.md` | Chart Room v4 — ⚠️ SUPERSEDED by the RADAR direction (see §0) |
| `design/brand.md` | Brand book — partly stale; the mug is being refined in the branding pass |
| `BACKLOG.md` | Wave-2 collectors, knock-knock review, honeypot architecture + security review, CARL port notes |
| `docs/INFRASTRUCTURE-OPTIONS.md` | What each infra tier unlocks and costs |
| `docs/superpowers/plans/` | Phase A (pipeline, done) and Phase B (site) plans |
| `design/mockups/g-chartroom.html` | The approved visual reference |
| `design/mockups/h-sensor.html` | Honeypot dashboard mockup w/ 3 globe styles |

**Attribution policy:** all commits are SaltyCarl with **no AI attribution**
anywhere, including automated ones. Non-negotiable.
