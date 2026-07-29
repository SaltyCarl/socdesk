# VIGIL Design System — v2

Build contract for all VIGIL UI work. v2 supersedes v1 after round-one mockups
were rejected as too flat/utilitarian. Derived from two research sweeps:
(1) 2026 InfoSec product design language (HTB, GreyNoise, ProjectDiscovery,
Tines, Wiz, Censys, ANY.RUN, Tria.ge), (2) React-era polish mechanics
translated to vanilla HTML/CSS/JS. Violations of **Hard bans** are rejected
without discussion.

## 1. Identity

VIGIL is a search-first threat-intelligence hub with the production quality of
a funded security startup. The reference energy: Hack The Box's tinted navy +
signature lime, GreyNoise's verdict discipline, VirusTotal's search-centered
IA, ANY.RUN's report anatomy, Linear-class motion restraint.

Core principles:

1. **Search is the product.** The hero omnibox (paste any IOC → composed
   threat report) is the center of gravity; everything else orbits it.
2. **Verdict first, evidence under it.** Every report leads with
   score + verdict word + tags + one-line summary before any table.
3. **Tinted, never default.** Navy-tinted surfaces and blue-gray text — pure
   black backgrounds and pure white text are what make pages read unstyled.
4. **Depth is layered and deniable.** Elevation = lighter surface + hairline +
   inner top light edge + soft dark shadow, all subtle enough to be felt not
   seen. Glow attaches only to meaning (search focus, verdicts, live dots).
5. **Mono = copy-pasteable.** JetBrains Mono for anything pasted into a query
   (hashes, IPs, domains, CVEs, timestamps, ports); Inter for language.
6. **Motion is scarce and fast.** 120–240ms, transform/opacity only, enters
   expo-out, exits faster than enters.

## 2. Tokens

Two selectable themes share every structural token; only the palette block
differs. Default = Theme N ("Nightwatch", navy+lime). Alt = Theme S
("Signal", charcoal+electric blue) for A/B.

```css
:root {
  /* ---- THEME N — "Nightwatch" (default): HTB-energy navy + lime ---- */
  --bg-page: #0D1420;         /* page base — tinted navy, never #000 */
  --bg-card: #151E2E;         /* raised surfaces */
  --bg-elev: #1C2740;         /* inputs, sticky headers, nested surfaces */
  --bg-pop:  #223050;         /* popovers, menus, tooltips */
  --border:  #2A3752;         /* hairlines — lighter tint of bg, not gray */
  --border-strong: #3A4A6B;
  --text-hi:  #E6EDF7;
  --text-body:#A4B1CD;        /* HTB blue-gray — the "designed" text tone */
  --text-mute:#5C6B8A;
  --accent:      #9FEF00;     /* signature lime */
  --accent-dim:  #86CC00;
  --accent-bg:   rgba(159,239,0,0.10);
  --accent-ring: rgba(159,239,0,0.18);
  --on-accent:   #0D1420;     /* dark text on lime fills */

  /* ---- Semantic verdict/severity ramp (never decorative) ---- */
  --sev-critical: #FF3E3E;  --sev-critical-bg: rgba(255,62,62,0.12);
  --sev-high:     #FF8A3D;  --sev-high-bg:     rgba(255,138,61,0.12);
  --sev-medium:   #FFAF00;  --sev-medium-bg:   rgba(255,175,0,0.12);
  --sev-low:      #9FEF00;  --sev-low-bg:      rgba(159,239,0,0.10);
  --sev-info:     #5CB2FF;  --sev-info-bg:     rgba(92,178,255,0.12);
  --sev-unknown:  #8B96A5;  --sev-unknown-bg:  rgba(139,150,165,0.10);

  /* ---- AI marker — purple is RESERVED for AI-generated content ---- */
  --ai: #B386F9;  --ai-bg: rgba(179,134,249,0.10);  --ai-bd: rgba(179,134,249,0.35);

  /* ---- Type ---- */
  --font-ui: "InterVariable", "Inter", system-ui, sans-serif;
  --font-mono: "JetBrains Mono", ui-monospace, monospace;
  --fs-body: 14px; --fs-cell: 13px; --fs-label: 11px; --fs-mono: 12px;
  --fs-h1: 22px;   --fs-hero-input: 15px;
  /* labels: UPPERCASE, +0.08em, weight 500. Headings 600, never heavier. */

  /* ---- Depth recipes ---- */
  --shadow-card:
    0 0 0 1px rgba(255,255,255,0.05),
    inset 0 1px 0 rgba(255,255,255,0.04),
    0 1px 2px rgba(0,0,0,0.40),
    0 8px 24px rgba(0,0,0,0.30);
  --shadow-pop:
    0 0 0 1px rgba(255,255,255,0.06),
    0 4px 12px rgba(0,0,0,0.45),
    0 16px 40px rgba(0,0,0,0.40);
  --glow-search: 0 0 0 1px var(--accent), 0 0 24px rgba(159,239,0,0.14);
  --focus-ring: 0 0 0 2px var(--bg-page), 0 0 0 4px var(--accent);

  /* ---- Motion ---- */
  --dur-fast: 120ms; --dur-base: 180ms; --dur-slow: 240ms;
  --ease-out: cubic-bezier(0.16, 1, 0.3, 1);
  --ease-in:  cubic-bezier(0.7, 0, 0.84, 0);
  --ease-drawer: cubic-bezier(0.32, 0.72, 0, 1);

  /* ---- Geometry ---- */
  --radius-chip: 5px; --radius-control: 8px; --radius-card: 10px; --radius-pop: 12px;
  --row-h: 40px;      /* default rows; 36px only inside explicitly dense tables */
  --header-h: 56px;
}

[data-theme="signal"] {
  /* ---- THEME S — "Signal": ProjectDiscovery-energy charcoal + blue ---- */
  --bg-page: #0B0E14; --bg-card: #12161F; --bg-elev: #181D29; --bg-pop: #1E2432;
  --border: #262D3D;  --border-strong: #364057;
  --text-hi: #EDF0F7; --text-body: #A9B1C3; --text-mute: #5E6878;
  --accent: #4D9FFF; --accent-dim: #3D86DB;
  --accent-bg: rgba(77,159,255,0.12); --accent-ring: rgba(77,159,255,0.20);
  --on-accent: #0B0E14;
  --glow-search: 0 0 0 1px var(--accent), 0 0 24px rgba(77,159,255,0.16);
  --sev-low: #3FB950; --sev-low-bg: rgba(63,185,80,0.10); /* green low when accent is blue */
}
```

Font features: global `"liga" 1, "calt" 1, "cv05" 1`; tables/metrics add
`"tnum" 1, "zero" 1`; uppercase labels add `"case" 1`; mono IOC strings set
`"liga" 0`.

## 3. Iconography (new in v2 — mandatory)

Icons are the single fastest perceived-quality upgrade; their absence was a
core v1 failure. Lucide, inlined as one hidden `<svg>` `<symbol>` sprite,
used via `<svg class="icon"><use href="#name"/></svg>`.

- 24×24 grid, `stroke-width: 2`, round caps/joins, `stroke="currentColor"`.
- Sizes: 16px inline/buttons, 20px nav. `.icon { flex-shrink: 0 }`.
- Icons inherit text color — never their own hue.
- Core set (~22): shield, shield-alert, alert-triangle, activity, radar,
  globe, server, network, terminal, search, filter, clock, eye,
  external-link, chevron-down, chevron-right, x, check, copy,
  more-horizontal, bell, trending-up.

## 4. Atmosphere & depth rules

- Every raised surface uses `--shadow-card` (shadow-as-border + inner top
  light edge + key + ambient). Popovers/menus use `--shadow-pop`.
- Hero zone only: a radial accent wash
  `radial-gradient(600px 240px at 50% -10%, <accent at 7% alpha>, transparent 70%)`
  plus an optional dot-grid texture at 2–4% opacity. Nowhere else.
- Glow whitelist: hero search focus (`--glow-search`), verdict banner accent,
  live-dot pulse. Colored glow alpha never exceeds 0.18.
- Sticky headers gain a shadow only once scrolled (IntersectionObserver
  sentinel → `.stuck`).
- Custom thin scrollbars on dark; accent-tinted `::selection`.

## 5. Hero search (the product's center)

- Centered, ~720px wide, 56–64px tall, `--bg-elev`, `--radius-card`,
  16px icon left, mono placeholder with a real example:
  `8.8.8.8 · evil-updates[.]example · SHA256…`
- Auto-detects type as you type; detected-type chip appears inline right.
- Focus: `--glow-search` + slight scale-none (no zoom) — glow only.
- Beneath: IOC-type chips (Hash / IP / Domain / URL / CVE) and clickable
  example pills; below those, a live strip (recent lookups / trending
  entities in mono) — the "tool is warm" signal.
- `/` focuses it from anywhere; Ctrl+K opens the command palette.

## 6. Threat report anatomy (search result)

Order is fixed (ANY.RUN/Tria.ge/VT synthesis):

1. **Verdict banner:** severity-colored score chip (0–100) + verdict word
   (MALICIOUS / SUSPICIOUS / CLEAN / UNKNOWN in tracked caps) + family/actor
   tags + one-line summary. Banner carries a soft severity-colored left glow.
2. **Sticky section tabs:** Overview / Network & IOCs / TTPs / Related.
3. **Evidence sections:** sources with first/last seen; every IOC a mono,
   copy-equipped, clickable pivot; MITRE technique chips linking to actor
   profiles; related feed items.
4. **Pivot row:** consistent icon-chips deep-linking the indicator into free
   external tools — VirusTotal, urlscan, ANY.RUN, Tria.ge, Censys, Shodan.
   (This is the v1 "sandboxing" story: one-click detonation/pivot handoff.)
5. Unknown-indicator result is a designed state: UNKNOWN verdict (gray, not
   green), what was searched, which sources missed, same pivot row.

## 7. Interactive-state matrix (mandatory completeness)

Every interactive component implements rest / hover / active / focus-visible
/ selected / disabled (/ loading where async). Reference values:

- Buttons: hover = one surface step up + border lighten; active =
  `translateY(1px)`; focus = `--focus-ring` (two-layer, bg-offset); loading
  swaps label for 14px spinner preserving width. Primary = accent fill with
  `--on-accent` text.
- Rows: hover `rgba(255,255,255,0.035)`; selected = accent-tinted bg +
  `inset 2px 0 0 var(--accent)`; row actions hidden at rest, revealed on
  `:hover` and `:focus-within`.
- Inputs: focus = accent border + 3px `--accent-ring` halo.
- Chips/filters: selected = accent-tinted bg + accent text.

## 8. Motion rules

- Dropdowns/popovers: scale 0.96→1 + fade, `--dur-base` `--ease-out`,
  transform-origin at trigger side. Drawer: slide+fade, 300–400ms
  `--ease-drawer`. Tab underline: translateX slide, `--dur-base`.
- Skeleton shimmer (1.8s linear) for loads >500ms; number count-up 600ms
  cubic-out with `tabular-nums`; staggered list entrance 30ms/item capped at
  8 items, first paint only.
- Never animate: keyboard-repeated actions, data refreshes, table sorts.
- Full `prefers-reduced-motion` kill switch.

## 9. Color usage rules

- Accent = interactive + brand moments only (primary CTA, focus, active nav,
  live indicators, links). Severity ramp = verdicts/severity only. Purple =
  AI-generated content only (Daily Brief marker). Gray = unknown, never
  green. Charts single-hue accent unless encoding severity.
- Severity chips: tinted bg + colored text + severity word (never
  color-alone); feed rows may add a 3px severity left-stripe.
- Solid accent fills carry `--on-accent` dark text.

## 10. Typography rules

- Body 14px/1.5 · cells 13px/1.4 · labels 11px caps +0.08em/500 · mono data
  12px/1.45 (≈0.92× surrounding Inter) · h1 22px/600 −0.014em.
- Weights: 400 body, 500 labels/emphasis, 600 headings. Nothing heavier.
- Numbers right-aligned with `tnum`; text left; never centered columns.
- kbd keycaps: 11px mono, 2px 5px pad, `--bg-elev`, hairline border,
  `inset 0 -1px 0 rgba(255,255,255,0.06)`.

## 11. Charts

Inline-SVG sparklines: 1.5px accent line + vertical gradient fill
(accent 25% → 0), no axes/gridlines/legends; hover crosshair (1px line +
3px dot + mono tooltip). KPI card = 20px `tnum` metric + colored delta
(color the delta, never the card) + sparkline. Thresholds as 4-4 dashed
lines at 30% opacity.

## 12. Hard bans

1. Editorial/display serif; cream/paper; "literary" voice.
2. Gradients ON components (buttons/cards/text). Washes live behind the hero
   section only, per §4.
3. Glassmorphism / `backdrop-filter` blur on more than the one modal overlay.
4. Colored glow above 0.18 alpha, or glow on non-interactive/non-verdict
   elements.
5. Pure #000 backgrounds; pure #FFF text; untinted gray borders.
6. Emoji in UI; bounce/elastic easing; marketing copy in-product.
7. Three identical icon-cards in a row; bento filler; cards nested in cards.
8. Zebra striping; centered numeric columns; white-on-red badges.
9. Purple anywhere except AI content.
10. CRT/Matrix cosplay: scanlines, phosphor trails, ASCII borders, rain.
    (The dot-grid at ≤4% and mono data voice are the sanctioned amount of
    "hacker".)
11. Green for "unknown" (gray owns unknown); multiple competing neon hues.

## 13. Pattern sources

| Pattern | Source |
|---|---|
| Tinted navy base + lime signature + blue-gray text | Hack The Box |
| Charcoal + electric blue alt theme | ProjectDiscovery |
| Verdict-first report; score chip; family tags | Tria.ge / ANY.RUN / VirusTotal |
| Hero search + example chips + recent-activity strip | VirusTotal / Censys / urlscan |
| Purple = AI; severity token discipline | Elastic EUI |
| Depth recipe (shadow-as-border, inner light edge) | Vercel Geist / shadcn dark |
| Motion tokens & rules | Emil Kowalski (Sonner/cmdk/Vaul) |
| Icon system | Lucide |
| KPI + sparkline | Stripe / Tremor |
| Details drawer over queue | Elastic Security |
| 90-day segment health bars | Atlassian Statuspage |
```
