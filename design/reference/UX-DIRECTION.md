# SOCDesk — UX Direction & Build Spec: Home Hero (globe + omnibox)

**Status:** Authoritative. Synthesis of the 4-researcher swarm; divergences resolved below.
**Scope:** The home / triage surface hero — globe showpiece, search omnibox, live-stat strip, scroll-melt, glass. Reduced-motion is first-class, both themes ship together.
**Governs over:** `design-system.md` v4 "Chart Room" **for the home hero specifically** — see the Reconciliation note. Palette source of truth remains `site/css/tokens.css`.
**Constraint:** vanilla ES-modules, **no build step**, strict CSP. RESEARCH/SPEC ONLY — this doc decides everything so the builder writes zero new design decisions.

---

## 0. Reconciliation — read before anything else (an architectural conflict was found)

`design-system.md` v4 "Chart Room" (approved 2026-07-29) describes a **Prussian-slate + bone-paper + vermilion** identity and, in §7 Hard Bans, forbids **glassmorphism, box-shadows, and border-radius > 0**. The **shipped** `tokens.css` (2026-08-11, "RADAR") has already moved past it: **warm-espresso / warm-paper + periwinkle accent**, a coffee-brown mug mark, **relaxed radius** (`--r-1..3`, `--r-list/-btn/-chip`) and a **`--shadow`** token. The task's project frame matches the shipped RADAR tokens, not v4.

**Resolution (decided):**
1. **Palette + type = shipped RADAR `tokens.css`.** Warm-espresso/warm-paper, periwinkle `--accent` (== `--mark`), Archivo + IBM Plex Mono. `design-system.md` v4's *palette* section is superseded; do not reintroduce Prussian-slate/vermilion or a serif.
2. **Carry forward v4's still-valid DNA** (these are reaffirmed, not overridden): the **anti-slop law** — "dark mode + one saturated accent" is itself the AI tell, so **saturated color covers < 2% of any viewport and only where it means something**; data-honest, scarce motion; IO scroll-reveals with 70ms sibling stagger; count-up expo-out tabular; a hard `prefers-reduced-motion` kill switch; **zero neon, zero bloom, no light-emitting color, no gradients on components**.
3. **Two v4 bans are deliberately amended for the hero, with justification** (the shipped tokens already anticipate this — `--shadow` and `--r-*` exist):
   - **Glass:** permit **exactly one** quiet, token-driven `backdrop-filter` surface — the omnibox — as a **sanctioned extension of the already-shipped topbar blur-under** (`chrome.css` `.topbar`), not a reversal into full glassmorphism. Glass stays few and small.
   - **Radius/shadow:** the omnibox uses `--r-2` + a layered `--shadow`; everything else stays hairline-flat.

Everything downstream in this doc assumes that resolution.

---

## 1. Design direction (the through-line)

**A printed intelligence chart, now with one instrument on it that turns.** The page reads as a quiet, warm, editorial SOC console — hairline grids, tight Archivo display type, wide-tracked mono micro-labels, warm paper doing the branding. Into that stillness we introduce **one** kinetic showpiece: a matte periwinkle **dot-matrix globe** that slowly turns and responds to drag — an *instrument*, not a gaming demo. The **functional hero is the search omnibox**: oversized, glass, unmistakably the thing you came to use. The globe is atmosphere and credibility; the omnibox is the job. On scroll, the hero performs **one** short, orchestrated melt — the globe recedes, the omnibox **docks** under the header and stays reachable — then the page is a calm, dense work surface.

**Reject / anti-slop list (hard nos):**
- No neon, glow, bloom, or light-emitting color. `--glow` stays ≤ ~8% alpha (it is 6% dark / 10% light today — leave it).
- No attack-arcs, no red/green "threat map" arcs, no spinning-earth-with-lasers. Globe markers are **periwinkle, sized by severity, never colored by verdict**.
- No matrix/glitch/decrypt-rain text; no scanlines/CRT/phosphor; no particle cursors, starfields, or pixel aesthetics.
- No SVG `feDisplacementMap` "liquid-glass" refraction (Safari-broken, gimmicky) — **rejected**.
- No WebGL spectacle background competing with the globe. All backgrounds stay low-contrast CSS atmosphere.
- No purple outside AI content (`--purple` is Daily-Brief only). No verdict hues (`--red/--gold/--green`) used decoratively.
- No serif, no editorial-cream-paper-magazine cosplay, no `font-stretch` masthead theatrics. One display tier per surface.
- Saturated periwinkle stays **< 2% of the viewport** at rest.

---

## 2. Chosen technical stack (divergences resolved)

| Layer | Decision | One-line justification |
|---|---|---|
| **Globe** | **cobe** (`/shuding/cobe`, ~5kB, procedural dot-matrix, built-in drag lerp), vendored to `site/js/vendor/cobe.js` | Native dot-matrix + severity-sized markers + auto-spin + **its own drag-inertia lerp**, **zero external assets** (map data is baked into the bundle, so **no `img-src` needed**), theme via `[r,g,b]` arrays. globe.gl (~200kB + a CDN earth texture = CSP violation) and raw three.js both lose on size and CSP. |
| **Scroll-melt + reveals** | **Native CSS scroll-driven animations** (`animation-timeline: view()/scroll()` + `animation-range`) as default, **IntersectionObserver fallback** for the ~10–16% without support (older Safari; Firefox flag-gated) | Compositor-threaded, zero bytes, CSP-perfect, gated by `@media (prefers-reduced-motion)`. |
| **Glass** | **Quiet token-driven `backdrop-filter: blur() saturate()`**, tint from `--panel`, hairline top border, layered `--shadow`; `contain: paint` + `isolation: isolate`; **never animate blur** | One sanctioned surface (omnibox) extending the shipped topbar precedent. SVG-refraction **rejected**. |
| **JS animation library** | **NONE.** No Motion, no anime.js, no GSAP. | See Decision 2 below. cobe supplies drag inertia; native CSS + IO supplies melt/reveals; a ~20-line rAF helper supplies count-up. Vendoring a lib buys nothing the bar requires. |

### Resolved divergences

**Divergence 1 — Globe: cobe (chosen) vs hand-authored canvas-2D dotted globe.**
**Decision: cobe**, styled matte / periwinkle / no-glow. A hand-rolled canvas-2D globe is ~150 lines we own but must debug (projection, back-face culling, DPR, drag inertia, theme), and it will look *flatter* than cobe's lit dot-matrix. cobe is 5kB, already solves lighting/culling/drag/DPR, and is trivially made matte-and-warm by (a) setting `glowColor` to the background ink so **the atmosphere halo disappears**, (b) low `diffuse`, (c) `mapBaseBrightness → 0` so the ocean vanishes and only dots read. The "instrument not gaming demo" worry is a *styling* worry, and cobe's styling knobs answer it directly. Own-code only wins if we later need a bespoke projection SOCDesk's brand demands — not now.

**Divergence 2 — JS animation library: ship with NONE (chosen) vs vendor Motion now.**
**Decision: ship the MVP with no JS animation library.** The bar is met by four zero/near-zero-cost pieces:
- **Drag inertia:** cobe's built-in phi-lerp (track pointer → target phi; `onRender` eases current→target). No spring lib needed; the `--ease` feel is already expo-out.
- **Scroll-melt + section reveals:** native `animation-timeline` where supported; **IntersectionObserver** class-toggle fallback everywhere else — which *is* the Firefox/old-Safari parity story. Motion's scroll helpers would duplicate this at 10–15kB.
- **Count-up numerals:** a ~20-line vanilla `requestAnimationFrame` tween (replaces GSAP `countUp`), CSP-safe, tabular-nums.
- **Load choreography:** pure CSS `@keyframes` + `animation-delay`.

Motion's *only* CSP-hostile path is its View-Transitions helper (injects a `<style>` → blocked by `style-src 'self'`); its core is CSP-safe, but we still don't need it. **Explicitly deferred (not built for MVP):** globe drag **spring** physics beyond a lerp, and any Firefox scroll-melt path fancier than the IO fallback. If a future dashboard needs orchestrated multi-element springs, vendor **Motion (~10–15kB)** *then* — never ship two libs.
> **Consequence for `motion.js`:** it is entirely GSAP-global-based and GSAP is being removed (see CSP). Its primitives degrade to final-state already, so nothing breaks, but the animated paths for `decode`/`countUp`/`sealStroke`/`sectionTimeline`/`onEnter` go dark. Replace `countUp` with the vanilla rAF tween; replace `sectionTimeline`/`onEnter` with the IO reveal; **retire `decode` (scramble) on the hero headline** — a decrypt effect on 4-word display type reads as slop and is on the reject list. `sealStroke` (verdict console, out of hero scope) becomes a CSS `stroke-dashoffset` draw if kept.

**Divergence 3 — Glass: confirm quiet token-driven backdrop-blur; SVG-refraction rejected.**
**Confirmed.** Both themes, token-driven, described in §5.5. `feDisplacementMap` refraction is **rejected** (Safari-broken, gimmicky, and it reads as spectacle — against the bar).

### Self-host / vendoring plan
- **cobe** → download the ESM build to `site/js/vendor/cobe.js`; import as `import createGlobe from './vendor/cobe.js'` inside a new `site/js/globe.js` module. No CSS, no assets, no network.
- **Fonts** → already self-hosted (`site/fonts/*.woff2`, `css/fonts.css`). **Keep.** No Google Fonts.
- **Remove:** the three GSAP `<script src="https://cdn.jsdelivr.net/...">` tags in `index.html` (lines 310–312) and any Google-Fonts / globe.gl / GSAP references living in experimental `rebuild-radar-v3.html`.

### Exact final CSP (state in full)
The live `index.html` (line 12) and `site/_headers` currently allow `https://cdn.jsdelivr.net` in `script-src` (for GSAP). **Tighten to self-only.** Both the `<meta>` and `_headers` must converge to (they are asserted equal by `csp.spec.js`, so they must not drift):

```
default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; worker-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; object-src 'none'
```

Notes that make this correct, not just short:
- **`script-src 'self'`** — the only change from today is dropping `https://cdn.jsdelivr.net`. Vendored `cobe.js` and all `js/*.js` load as same-origin ES modules. WebGL shader compilation is **not** `eval`/`new Function`, so no `unsafe-eval` is needed.
- **`img-src 'self' data:`** — the `data:` stays for the feTurbulence noise data-URI in `base.css` (line 16), which is a *CSS background image*. **cobe needs no `img-src`** (its map is in the JS bundle). Do not add any host here for the globe.
- **`style-src 'self'`** (no `unsafe-inline`) — governs inline `<style>` and HTML `style=""` attributes. **CSSOM writes are allowed:** `element.style.setProperty('--rx', …)` (cursor spotlight, drag) is fine — the shipped `trackPointer` already relies on this. **Guardrail:** use `element.style.setProperty(...)`, **never** `element.setAttribute('style', ...)` (that sets the inline style attribute → blocked; this is exactly what killed GSAP Flip, per `motion.js`).
- Fonts self-hosted → `font-src 'self'` unchanged.

---

## 3. Component build spec — top to bottom

Token names below are verbatim from `tokens.css` / `chrome.css`. Where a value already exists in `chrome.css`, "change" means edit that rule; otherwise it is new.

### 3.1 Nav — remove the redundant home tab
Current nav (`index.html` 39–47): `Feed · Vulnerabilities · Actors · Health · Sources · Toolbelt · [Brief hidden]`. There is **no literal "Triage" tab**; the redundant one is **`<button data-view="feed">Feed</button>`** — the triage home is already reachable via the wordmark (`.logo → #top`) and via `/` (focuses the omnibox from anywhere, `views.js:243`).
- **Remove the `data-view="feed"` nav button.** Working-surface tabs become `Vulnerabilities · Actors · Health · Sources · Toolbelt` (+ `Brief` when unhidden).
- **Wiring the builder must preserve:** the logo click must still set the app to the feed/home view and clear any active tab's `.on`; default first paint stays feed (the `body[data-view]` scoping in `chrome.css` 92–93 already hides `#hero`/`.band` on non-feed views, so returning home via the logo re-shows them). Confirm `views.js` view-switch logic doesn't assume a `feed` button exists.
- Keep `.topbar`'s existing glass exactly as shipped (`chrome.css` 4–6): `background:color-mix(in srgb,var(--panel) 92%,transparent); backdrop-filter:blur(8px) saturate(130%)`. It is the precedent the omnibox glass extends.

### 3.2 Hero — layout skeleton
Two-column composition at ≥900px (Vantage "command panel beside the headline", scaled up): **left = text + omnibox + stat strip; right = globe bleeding off the right edge behind/beside the text.** The globe is *decor behind the functional column*, never on top of the input.

```
.hero (position:relative; padding:64px 0 24px; min-height: ~clamp(520px, 72vh, 760px))
├─ .hero-atmos      (aurora + glow, position:absolute, inset:0, z-index:0, pointer-events:none)
├─ canvas#globe     (position:absolute; right:-8%; top:50%; translateY(-50%); z-index:1; pointer-events:auto for drag)
└─ .hero-copy       (position:relative; z-index:2; max-width: 58ch on desktop, sits left)
   ├─ p.hero-kicker         (eyebrow — mono, periwinkle)
   ├─ h1.hero-h1            (display headline)
   ├─ .search (#heroSearch) (the oversized glass omnibox — the functional hero)
   ├─ .hist  (#histRow)     (recent lookups; unchanged)
   ├─ .hero-stats           (NEW hairline live-stat strip)
   └─ p.disclose            (compliance banner; unchanged)
```
- **Globe sizing:** canvas CSS box `width:min(62vw,720px); aspect-ratio:1`. Position so its center sits ~right:-8% (partially off-canvas) — it reads as a large instrument peeking in, not a centered beach-ball. `offset:[x,0]` in cobe can nudge the drawn sphere further right if needed.
- **Stacking:** globe `z-index:1`, copy `z-index:2`. The omnibox must never sit over the globe's brightest dots at rest — keep the globe right-biased and the copy column left.
- **Mobile (≤760px):** globe becomes a **full-bleed backdrop** behind the copy at low opacity (`opacity:.22`) OR is hidden if it costs too much on low-end devices (ship hidden ≤560px). Copy column goes full-width, omnibox height 56px (matches existing mobile rule `chrome.css` 186–188). Stat strip collapses to 2×2.

### 3.3 Eyebrow (`.hero-kicker`)
Keep the shipped rule (`chrome.css` 97–100): IBM Plex Mono **600**, **11px** (≥11px floor for the home — do not drop to 9px), `letter-spacing:.16em`, uppercase, `color:var(--accent)`, with the 14px accent tick `::before`. Text: `Threat intelligence lookup`.

### 3.4 Display headline (`.hero-h1`) — scale it up to showpiece
- **Change** from the shipped `clamp(30px,3.6vw,44px)/-.025em` to **`font-size:clamp(40px, 5.2vw, 68px); font-weight:800; letter-spacing:-.04em; line-height:1.02; max-width:14ch`** (Archivo display, tight tracking per research; `-.04em` — not the full `-.045em` — because Archivo at 800 already reads dense).
- Keep the two-span structure and `.hl` (`color:var(--accent)`) for the one accented word. Text stays `IOC in. / OSINT out.` (`.hl` on "OSINT"). **One** accent word only — this is the single sanctioned periwinkle text moment in the hero.
- Optional Tier-2: a **text-shimmer on the one `.hl` word only** (slow periwinkle sheen, `background-clip:text`, 6s, reduced-motion → static solid `--accent`). Ship without it first; add only if the hero feels inert.

### 3.5 The omnibox (`.search` / `#heroSearch`) — the functional hero
Build on the shipped `.search` rule (`chrome.css` 105–116); the changes make it **bigger, glass, and crisper on focus.**
- **Size:** `min-height:72px` (up from 64), `padding:0 24px`, `gap:18px`, `max-width:760px`, `border-radius:var(--r-2)`.
- **Input:** `font-family:var(--mono); font-size:clamp(16px,1.4vw,20px)` (≥16px prevents iOS zoom). Placeholder unchanged (`chrome.css` 112).
- **Icon:** the search `svg` at **26px**, `stroke:var(--mark)` (periwinkle), `stroke-width:2`.
- **Glass recipe:** see §5.5 (dark + light). Replaces the flat `background:var(--panel)`.
- **Focus state — crisp, no bloom:** replace the shipped soft 4px `color-mix` ring (`chrome.css` 108–109) with `border-color:var(--accent); outline:2px solid var(--accent); outline-offset:2px`. A hard 2px offset ring reads as "focused," not "glowing." (Keeps AA focus visibility; matches `base.css` `:focus-visible`.)
- Keep the `.detect` auto-type chip (`background:var(--accent); color:var(--ink-on-accent)`) and the `/` `kbd` hint.

### 3.6 Hairline live-stat strip (`.hero-stats`) — NEW, Vantage grid discipline
A thin, **read-only** at-a-glance liveness row under the omnibox — distinct from the interactive category `.band` further down (which stays a filter). Vantage's 1px-hairline grid: the grid container paints `--line`, cells paint `--panel`, `gap:1px` lets the hairline show through — **no per-cell borders.**
```css
.hero-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;
  background:var(--line);border:1px solid var(--line);border-radius:var(--r-1);
  overflow:hidden;margin-top:20px;max-width:760px}
.hero-stats .cell{background:var(--panel);padding:14px 18px;display:flex;
  flex-direction:column;gap:4px}
.hero-stats .n{font-family:var(--mono);font-size:20px;font-weight:600;
  color:var(--paper);font-variant-numeric:tabular-nums;letter-spacing:-.01em}
.hero-stats .k{font-family:var(--mono);font-size:11px;font-weight:600;
  letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
```
- 4 cells, e.g.: `{n: indicators scored today, k: "SCORED 24H"}`, `{new KEV, k:"NEW KEV"}`, `{collectors live "5/5", k:"COLLECTORS"}`, `{"4m ago", k:"UPDATED"}`. Micro-labels **≥11px** (research floor). Numbers `tabular-nums`. Values come from the same data the `.band`/`.live` already read; no new backend.
- On the **feed rows** elsewhere, adopt Vantage's **selected-row accent spine**: selected/active row gets `box-shadow: inset 3px 0 0 var(--accent)` (no layout shift) — mirrors the shipped `.band button.on` inset technique (`chrome.css` 139–140).

### 3.7 Load choreography — one orchestrated moment
Pure CSS, fires once on first paint of the home. Staggered fade-up, `--ease` (`cubic-bezier(.16,1,.3,1)`), each step `translateY(12px)→0 + opacity 0→1`, duration `--dur-enter` (600ms), **70ms** stagger. **Nothing is ever left at opacity 0** — the keyframe's end state *is* the resting state (`from` only), matching the `viewIn` pattern in `base.css` 38.
- Order + delays: `hero-kicker` 0ms → `hero-h1` 70ms → `.search` 140ms → `.hero-stats` 210ms → `.disclose` 280ms.
- **Globe entrance:** canvas `opacity:0→1` + `scale(.98→1)` over ~800ms, starting ~150ms in (fold it into a `.hero.loaded` class the globe module sets after `createGlobe` returns, so the globe never flashes an empty canvas).
- Implement as `@keyframes heroRise{from{opacity:0;transform:translateY(12px)}}` on each element with `animation-delay`; do **not** use JS for this.

### 3.8 Scroll-melt + omnibox dock
A **short pin** (Apple technique): the hero is a sticky region ~`1.15–1.25` viewport tall; as it scrolls through its `exit` range the globe recedes and the omnibox docks.
- **Globe melt:** across the exit range animate **only compositor-cheap properties** — `scale(1→1.06)`, `translateY(0→-5%)`, `opacity(1→.30)`. **Do NOT animate `blur` on the WebGL canvas** (repaint storm next to live GL — see Risks). The recede reads through opacity+scale alone. If a hint of softness is wanted, apply a *static* `filter:blur(3px)` that cross-fades via opacity of a duplicate pre-blurred DOM layer behind — but for MVP, opacity+scale is enough and cheapest.
- **Omnibox dock (stays reachable the whole scroll):** the omnibox wrapper is `position:sticky; top:calc(var(--topbar-h,60px) + 12px)`. A scroll-driven timeline scales it `1→.94` and tightens `min-height:72→52px` / `padding` across the pin range, so it visually **shrinks and parks just under the topbar** rather than dissolving. Search never leaves the screen.
- **Section reveals** (the stacked home blocks below the fold: console area, `.band`, feed head, then feed rows): `animation-timeline:view()`, entry range `cover 0% → cover 35%`, 24px fade-up + `.rule` `scaleX(0→1)` wipe (the `.rule` element already exists, `chrome.css` 152–153), 70ms sibling stagger via a `--i` custom property on repeated children.
- **Native + fallback wiring:**
  - Native: `@supports (animation-timeline: view())` block carries the scroll-driven versions.
  - Fallback (`@supports not (animation-timeline: view())` + a JS IO): an IntersectionObserver adds `.in` at `top 85%` (once) to run the same fade-up via a plain transition; the omnibox dock degrades to plain `position:sticky` with no scale (still reachable). This is the Firefox/old-Safari path — no library.

### 3.9 Glass surfaces — keep them few
Only **two** glass surfaces on the whole page: the **topbar** (shipped, unchanged) and the **omnibox** (§5.5). No glass cards in the feed, no glass tiles. This honors "keep glass surfaces small/few" and the anti-slop `< 2%` discipline.

---

## 4. Globe module (`site/js/globe.js`) — concrete build

```
import createGlobe from './vendor/cobe.js'
```
State: `let globe=null, phi=0, targetPhi=0, dragging=false, lastX=0, rafSpin=true`.

**Create (per theme):**
```js
function palette(dark){  // [r,g,b] in 0..1, derived from tokens.css
  return dark ? {
    base:[0.42,0.46,0.78],  // matte periwinkle land dots (accent desaturated toward warm)
    marker:[0.49,0.54,1.0], // --accent #7C8AFF
    glow:[0.08,0.06,0.04],  // --ink #15100A → KILLS the halo (no bloom)
    dark:1, mapBrightness:6, mapBaseBrightness:0, diffuse:1.1
  } : {
    base:[0.29,0.31,0.78],  // periwinkle readable on cream
    marker:[0.29,0.31,0.82],// --accent #4A4FD0
    glow:[0.95,0.90,0.82],  // --ink #F2E6D0 → KILLS the halo on paper
    dark:0, mapBrightness:3, mapBaseBrightness:0.05, diffuse:1.2
  }
}
```
> These `[r,g,b]` are **calibrated starting points to tune in-browser** against the two live themes — the *rule* is fixed (matte periwinkle dots, `glowColor == background ink`, ocean near-zero), the exact decimals are tuning.

```js
function build(){
  const dark = resolveDark();          // see theme re-init below
  const p = palette(dark);
  const size = canvas.clientWidth;     // CSS px; multiply by DPR below
  globe = createGlobe(canvas, {
    devicePixelRatio: Math.min(window.devicePixelRatio, 2),  // cap DPR at 2
    width: size*2, height: size*2,     // cobe wants device px; canvas CSS box is `size`
    phi, theta: 0.18,
    dark: p.dark, diffuse: p.diffuse,
    mapSamples: 16000, mapBrightness: p.mapBrightness, mapBaseBrightness: p.mapBaseBrightness,
    baseColor: p.base, markerColor: p.marker, glowColor: p.glow,
    opacity: 0.95,
    markers: MARKERS,                  // ≤12, {location:[lat,lng], size:0.02..0.08}; size=severity, color omitted → periwinkle
    onRender(state){
      if(rafSpin && !dragging) targetPhi += 0.0035;   // slow auto-spin
      phi += (targetPhi - phi) * 0.10;                 // lerp inertia (built-in feel)
      state.phi = phi;
      state.width = canvas.clientWidth*2;
      state.height = canvas.clientWidth*2;
    }
  });
}
```
**Drag (cobe-native lerp, no lib):** `pointerdown` → `dragging=true, lastX=e.clientX`; `pointermove` → `targetPhi += (e.clientX-lastX)*0.005; lastX=e.clientX` (write nothing to `style` — mutate `targetPhi`); `pointerup/leave` → `dragging=false` (auto-spin resumes, inertia carries via the lerp). Set `canvas{cursor:grab}` / `.dragging{cursor:grabbing}` via a class, not an inline style.

**Markers (optional for MVP):** the dot-matrix globe alone is the showpiece; if markers are used, ≤12, placed at notional collection points / recent-CVE origin cities, **sized by severity** (`0.02` low → `0.08` critical), **color omitted so they inherit periwinkle `markerColor`** — never a verdict hue. If geodata is unavailable, ship **zero markers**; do not invent fake precision.

**Theme re-init (colors are baked at `createGlobe`):**
- `resolveDark()` = `document.documentElement.getAttribute('data-theme') === 'dark' ? true : data-theme==='light' ? false : matchMedia('(prefers-color-scheme:dark)').matches`.
- On theme-toggle click **and** on `matchMedia('(prefers-color-scheme:dark)')` change *when no explicit `data-theme`*: `const keep=phi; globe.destroy(); globe=null; phi=keep; build();` — **carry `phi` across** so the globe doesn't snap. Debounce so a rapid Light/Dark/System toggle doesn't thrash GL contexts.

**Lifecycle / perf:**
- Only build when the home/feed view is active and the hero is on screen. When the user switches to a non-feed view (`#hero` becomes `display:none`, `chrome.css` 92–93) **or** the hero scrolls fully out (IntersectionObserver `threshold:0`), call `globe.destroy(); globe=null` and stop; rebuild at last `phi` on return. A destroyed cobe frees its WebGL context and RAF.

**Reduced-motion:** if `matchMedia('(prefers-reduced-motion:reduce)').matches` → `rafSpin=false` and **do not attach drag**; build the globe, let it render its single frame, then `globe.destroy()` after ~2 frames to halt the loop (the last painted dot-globe remains as a static image). Net: a still periwinkle dot-globe, no motion, no GPU loop. (If a destroyed canvas clears on your target browsers, instead keep the loop but never advance `phi` — one static frame, minimal cost. Prefer destroy; fall back to frozen-phi.)

---

## 5. Type, accent, and glass recipes (token-exact)

### 5.1 Type
- **Display:** Archivo `var(--sans)`, 800, `-.04em`, `clamp(40px,5.2vw,68px)` (hero H1); section H2 stays shipped `clamp(26px,2.4vw,28px)/800/-.02em`.
- **Eyebrows / mono micro-labels:** IBM Plex Mono `var(--mono)`, 600, **≥11px** on the home, `.12–.16em` tracking, uppercase, `--accent`.
- **Data:** `var(--mono)` + `font-variant-numeric:tabular-nums` everywhere numbers change (stat strip, counts, `.band b`).

### 5.2 Accent
Periwinkle `--accent` (== `--mark`) ONLY: tabs, buttons, links, focus, the one `.hl` word, globe dots/markers, the accent tick on kickers, selected-row spine. **Never** a verdict. `--red/--gold/--green` reserved for severity/verdict. `--purple` = AI/Daily-Brief only. `--coffee*/--rim/--steam` = the mug SVG only.

### 5.3 Reduced-motion static end-state (per animated piece)
| Piece | Reduced-motion resting state |
|---|---|
| Load choreography | All hero elements at `opacity:1`, no transform. (`from`-only keyframes + the global `base.css` 42–44 kill switch already guarantee this.) |
| Globe | Single static dot-globe frame; **no auto-spin, no drag** (see §4). |
| Scroll-melt | Disabled. Hero is a normal static section; globe at full opacity; no scale/translate. |
| Omnibox dock | Plain `position:sticky` (sticky is layout, not motion) with **no** scale/height transition — stays pinned, doesn't animate. |
| Section reveals | Content visible at rest; IO adds `.in` immediately (no fade), or native timeline is gated off. |
| Aurora / `--glow` | Static — no drift. Low-opacity wash remains. |
| Text-shimmer (if used) | Static solid `--accent` fill on the `.hl` word. |
| Cursor spotlight (if used) | Disabled. |
| Mug steam (shipped) | Already handled — `opacity:.85` static (`chrome.css` 45–47). |

### 5.4 Aurora / atmosphere (`.hero-atmos`)
CSS only, behind the globe, **very** low contrast so it can't fight the GPU or the dots. **Two** periwinkle blobs max (not 3), heavy blur, slow drift — reuse rather than pile onto the existing `body` `--glow` radial (`base.css` 11) and noise overlay (`base.css` 15–16).
```css
.hero-atmos::before,.hero-atmos::after{content:'';position:absolute;border-radius:50%;
  filter:blur(100px);opacity:.45;pointer-events:none;
  background:radial-gradient(circle, color-mix(in srgb,var(--accent) 24%, transparent), transparent 70%)}
.hero-atmos::before{width:520px;height:520px;top:-10%;right:4%;animation:drift 42s var(--ease-inout) infinite alternate}
.hero-atmos::after{width:380px;height:380px;bottom:-14%;left:8%;opacity:.30;animation:drift 52s var(--ease-inout) infinite alternate-reverse}
@keyframes drift{to{transform:translate3d(4%, -3%, 0)}}
@media (prefers-reduced-motion:reduce){.hero-atmos::before,.hero-atmos::after{animation:none}}
```
Light mode: drop opacity to `.28/.18` (paper shows atmosphere more) — token-driven `color-mix` handles the hue.

### 5.5 Glass recipe — omnibox (both themes, token-driven)
```css
.search{                               /* extends chrome.css .search */
  background:color-mix(in srgb, var(--panel) 72%, transparent);
  -webkit-backdrop-filter:blur(14px) saturate(140%);
  backdrop-filter:blur(14px) saturate(140%);
  border:1px solid var(--line-bright);
  /* hairline top highlight — a lifted edge, not a glow */
  border-top-color:color-mix(in srgb, var(--paper) 16%, var(--line-bright));
  box-shadow:
    inset 0 1px 0 color-mix(in srgb, var(--paper) 8%, transparent),  /* top inner light */
    0 18px 40px -14px var(--shadow);                                  /* layered drop */
  contain:paint; isolation:isolate;    /* clip blur cost; own stacking context */
  border-radius:var(--r-2);
}
```
- **Dark** resolves warm-espresso: `--panel #1E1710`, `--line-bright #473721`, `--shadow rgba(0,0,0,.5)` — reads as smoked glass over espresso.
- **Light** resolves warm-paper: `--panel #FBF4E6`, `--line-bright #CDB183`, `--shadow rgba(70,46,16,.16)`. On paper, **soften** to `blur(12px) saturate(120%)` and `background:color-mix(... 80%, transparent)` (paper has less depth to refract) — put this in the `:root[data-theme="light"]`, `:root:not([data-theme="dark"])` light path or a `@media (prefers-color-scheme:light)` guard; token-driven so it retunes automatically otherwise.
- **Never animate `backdrop-filter`/`blur`.** The dock scales the box, not its blur.
- Topbar glass (`chrome.css` 4–6) stays as-is; the omnibox is intentionally a touch stronger (14px vs 8px) because it's the hero.

---

## 6. Build sequence (implement in this order; verify each in-browser before the next)

1. **CSP + de-GSAP (foundation).** Remove the 3 jsdelivr `<script>` tags (`index.html` 310–312); set both `<meta>` CSP and `site/_headers` to the §2 string. Replace `motion.js`'s `countUp` with a vanilla rAF tween; route `sectionTimeline`/`onEnter` callers to the new IO reveal; retire hero-headline `decode`.
   **Verify:** page loads with **zero** `securitypolicyviolation` console errors; `csp.spec.js` green; nav/feed still render; count-ups still count.
2. **Static hero layout (no globe, no motion).** Remove the `data-view="feed"` nav button + preserve logo-home wiring. Rebuild `.hero` two-column skeleton, scale the H1, resize the omnibox, add `.hero-stats`. Flat backgrounds only.
   **Verify:** at 1440 / 1024 / 768 / 375 the copy column + omnibox never overlap the (empty) globe area; omnibox is `min-height:72px`, input ≥16px (no iOS zoom); stat strip hairlines show; both themes legible; focus ring is a crisp 2px offset.
3. **Glass + atmosphere.** Apply the omnibox glass recipe (§5.5) and `.hero-atmos` (§5.4). Confirm the topbar glass still matches.
   **Verify:** DevTools Rendering → "Paint flashing": scrolling the static hero shows **no** large repaint on the omnibox; glass reads in both themes; AA contrast of input text on the glass (`--paper` on the color-mixed `--panel`) ≥ 4.5:1 in both themes.
4. **Globe (`globe.js` + vendored `cobe.js`).** Build with the §4 palette, DPR cap 2, auto-spin + drag lerp, markers optional. Wire theme re-init (destroy→rebuild carrying `phi`) and the view/IO lifecycle.
   **Verify:** matte periwinkle dots, **no halo** (glowColor==ink), no neon; drag has inertia and settles; toggling Light/Dark/System recolors the globe without a phi jump or a leaked GL context (check `about:gpu` / no context-lost warnings); switching to a non-feed view destroys the globe (no RAF in Performance timeline).
5. **Scroll choreography.** Add the sticky pin, globe recede (opacity+scale+translateY only), omnibox dock (sticky + scroll-timeline scale), section reveals; wrap native in `@supports (animation-timeline: view())`, add the IO fallback branch.
   **Verify (Chrome):** globe recedes and omnibox parks under the topbar and stays clickable through the whole scroll. **Verify (Firefox, timeline flag off):** IO fallback fades sections in and the omnibox stays sticky (no scale) — nothing is stuck at opacity 0.
6. **Reduced-motion + perf pass.** Toggle OS reduced-motion: globe static, no dock animation, choreography resolved, aurora frozen. Then the perf sweep.
   **Verify:** reduced-motion end-states match §5.3; on a mid-tier laptop the hero holds ~60fps while the globe spins (Performance panel, main thread < 16ms/frame); DPR-2 cap confirmed on a HiDPI display; Lighthouse: no CLS from the globe (canvas has a reserved `aspect-ratio` box).

---

## 7. Risks + mitigations

| Risk | Mitigation |
|---|---|
| **Blur repaint next to live WebGL** — animating `backdrop-filter`/`filter:blur` while cobe renders every frame = compositor + GPU contention, jank. | **Never animate blur.** Melt = opacity+scale+translate only (compositor-threaded). Omnibox glass blur is *static*; the dock scales the box, not the blur. `contain:paint`+`isolation:isolate` on the glass bound its repaint. Keep glass to two surfaces. |
| **`animation-timeline: view()/scroll()` browser gap** (~10–16%: older Safari, Firefox flag-gated). | Native path wrapped in `@supports`; **IntersectionObserver** fallback runs the same reveals + a plain sticky (no-scale) dock. No library, no broken scroll on unsupported browsers. Reduced-motion also routes to the static branch. |
| **CSP regression** — a stray CDN/asset re-introduces a violation; meta vs `_headers` drift. | Final CSP is `script-src 'self'` (§2), asserted equal in `csp.spec.js`. cobe needs no `img-src`; fonts self-hosted; `element.style.setProperty` (not `setAttribute('style')`) for all runtime style writes. Run the CSP spec in the step-1 gate. |
| **Globe theme re-init** — colors baked at `createGlobe`; toggling theme could snap rotation, flash, or leak GL contexts. | On toggle/`matchMedia` change: capture `phi` → `destroy()` → rebuild with new `[r,g,b]` at the kept `phi`. Debounce rapid toggles. Also listen to `prefers-color-scheme` change **only** when no explicit `[data-theme]`. Destroy on view-leave / hero-offscreen so contexts don't accumulate. |
| **GPU cost on low-end / mobile** | DPR capped at 2; `mapSamples` 16k (not 100k); globe destroyed when hero off-screen or non-feed view; hidden ≤560px; reduced-motion halts the loop. |
| **`design-system.md` v4 drift** — a future contributor "restores" the vermilion/Prussian palette or re-bans glass, undoing this. | This doc + shipped `tokens.css` are the current source of truth for the home hero; §0 records the deliberate supersession. Land a one-line pointer in `design-system.md` (Phase-B note) to this file so the amendment is discoverable. |

---

## 8. One-paragraph handoff
Ship the home hero as a **calm warm-espresso/warm-paper console with a single turning instrument**: a **cobe** dot-matrix globe (matte periwinkle, halo killed by setting `glowColor` to the background ink, DPR-capped, drag-inertia via cobe's own lerp) bleeding off the right, behind a left-hand copy column whose **oversized glass omnibox is the functional hero**. Motion is **native CSS scroll-driven + IntersectionObserver fallback + a 20-line rAF count-up — no JS animation library, GSAP removed, CSP tightened to `script-src 'self'`**. One orchestrated load, one short scroll-melt where the globe recedes (opacity+scale only, never blur) and the omnibox **docks** under the header and stays reachable; everything has a defined reduced-motion still state. Periwinkle stays under 2% of the viewport; verdict hues stay reserved; no neon, no glow, no slop.
