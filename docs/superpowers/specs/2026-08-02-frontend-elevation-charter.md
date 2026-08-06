# VIGIL Front-End Elevation Charter

**Date:** 2026-08-02 · **Status:** Proposed (synthesis of 3-agent UX team review)
**Inputs reviewed:** animejs.com · motion.dev · kokonutui.com · bklit.com, plus
ecosystem sweep (GSAP, native platform APIs, component libraries, data-display,
texture tools). Chart Room identity (design-system v4) remains non-negotiable;
this charter defines the stack and craft that elevate it.

## Verdicts on the four references

| Site | What it is | Verdict |
|---|---|---|
| **Anime.js v4** | MIT animation engine, vanilla-first, ~25KB; its own site is an Awwwards-winning brutalist-technical page | Strong candidate engine; adopted as fallback (see stack decision) |
| **Motion (motion.dev)** | Ex-Framer Motion; excellent vanilla core, MIT | **Skip** — Motion+ (paid) gates exactly VIGIL's signature moves: ScrambleText, AnimateNumber, Ticker, SplitText |
| **KokonutUI** | Free MIT React/Tailwind/shadcn component collection (57 components), marketing/AI-SaaS flavored; zero tables/grids/charts | **Port patterns, don't adopt** — action-search-bar, AI-loading states, spotlight-card mechanic, glitch/typewriter text; all restyled to Chart Room, vanilla |
| **Bklit** | Two products: discontinued analytics SaaS (archived 2026-06) + **bklit-ui**, active MIT React charts library on visx | Analytics: skip. bklit-ui: **earmarked** as the one library that would justify a future React migration if chart needs outgrow hand-rolled SVG |

## The rebuild question — answered

**No framework migration.** Every line of evidence points the same way: the
animation engines are vanilla-first and no-build; the React component
libraries (KokonutUI, Aceternity, Magic UI, ReactBits) supply decorative
components that violate Chart Room's aesthetic and none of VIGIL's data
problems; the platform now ships the rest natively. Phase B is a **full
rebuild of the presentation layer** (mockup → production site) on the
existing vanilla static stack — richer, not heavier. Revisit only if
bklit-ui-class interactive charts become a requirement.

## Stack decision

**Engine: GSAP** — core + ScrollTrigger + SplitText + ScrambleText + DrawSVG +
MotionPath. Rationale: all formerly-paid Club plugins became free for all use
(including commercial) after the Webflow acquisition (April 2025); vanilla
script-tag/ESM, no build step; ScrollTrigger's pin/scrub choreography is the
one capability class Anime.js lacks and the elevation plan uses it. GSAP's
license is free-but-not-OSI; we consume it as a dependency (CDN/npm), never
vendor its source. **Fallback:** Anime.js v4 (pure MIT, lighter) — the
choreography plan below is deliberately engine-portable if we ever swap.

**Native platform (zero bytes):** cross-document View Transitions
(feed→report navigation; graceful Firefox fallback) · CSS scroll-driven
animations behind `@supports` · `content-visibility: auto` on long feeds,
escalating to @tanstack/virtual-core only if measured necessary.

**Data display:** D3 micro-modules (`d3-scale`, `d3-shape`, `d3-array`, ISC)
for hand-rolled SVG gauges/sparklines in full Chart Room dress; Observable
Plot (ISC) if/when larger charts arrive; Unovis noted for network graphs.

**Texture:** existing feTurbulence grain, plus feComponentTransfer
posterization/dither on imagery ("printed intelligence briefing" — unique in
the CTI space). Optional, gated: ONE restrained OGL contour-field shader in
the hero, muted bone-on-slate, reduced-motion-off. No ASCII/CRT anything.

**Skipped with reasons:** Lenis (scroll smoothing fights data-honest scanning) ·
Theatre.js (AGPL Studio, momentum risk) · Aceternity/Magic UI/ReactBits/21st.dev
(React-locked, glow-native, or metered) · SplitType (GSAP SplitText covers it,
with better a11y) · Clusterize.js (unmaintained) · uiverse.io allowed as
pattern quarry only, never pasted verbatim.

## Choreography plan (the elevation itself; engine-portable)

1. Boot-sequence masthead: one master timeline cascading scramble-decodes
   through section labels in document order (Plex Mono charset, ~40ms stagger).
2. Scroll-scrubbed ink draws: gauge arcs, chart axes, rule lines drawing via
   DrawSVG bound to scroll progress; reverse on scroll-up.
3. Grid-wavefront reveals: 2D stagger from focal cell across stat tables and
   health grids.
4. Eased count-ups (outExpo) replacing linear counters, fired once on entry.
5. Vermilion seal-stroke card frames: zero-radius SVG rect stroke draw,
   sequenced after each card's label decode (replaces conic sweep).
6. Sectional master timelines: headline slab + rule-line scaleX wipe + body
   fade composed as one unit — no independent IO pops.
7. Sparkline draw + rider dot to latest datapoint (DrawSVG + MotionPath).
8. Ticker rebuilt with velocity easing and hover-decelerate.
9. Verdict sequence as the signature moment: pinned scroll scene — search →
   report assembles in directed order (verdict word decode → gauge draw →
   evidence rows cascade → pivot chips arrive).
10. FLIP/View-Transition feed filtering: rows reflow honestly when filters
    change, never teleport.
11. Ported KokonutUI patterns in Chart Room dress: action-search omnibox
    behavior, AI-brief shimmer loading, spotlight-card hover (flat, subtle).

## Craft disciplines (encoded into design-system v4.1 at build time)

1. Scroll choreography is storyboarded before coding — directed sequences,
   not stacked fade-ins.
2. Master timelines with deliberate overlap; stagger discipline.
3. FLIP for all layout change; View Transitions as its platform form.
4. Motion tokens: 2-3 durations + 2-3 easings as CSS variables, enforced like
   the type scale; `prefers-reduced-motion` a first-class variant of every
   sequence.

## Execution

Phase B implementation plan (writing-plans) to be authored against this
charter + design-system v4 + `g-chartroom.html` as visual acceptance test,
building the production site in `site/` against the real Phase A data
contract. Pipeline (Tier 1) is untouched by this charter.
