# VIGIL Design System

Build contract for all VIGIL UI work — mockups, the production site, and every
iteration after. Derived from a three-lens research sweep (security-product
patterns / 2026 dashboard aesthetics / dense-dark typography+color) on
2026-07-28. Violations of the **Hard bans** section are rejected without
discussion.

## 1. Identity

VIGIL is a night-watch console: calm, near-monochrome, ruthlessly scannable.
The screen is ~95% neutral ramp; chroma is reserved for *signal* (severity,
status, one interactive accent). The strongest color on screen should always
be the threat data, never the chrome. Density is a feature; decoration is not.

Five rules that settle most arguments:

1. **Hierarchy first, depth on demand.** Verdict/summary up top, evidence
   below, detail in a drawer — never navigate away from a queue to inspect
   one row.
2. **Mono = copy-pasteable.** JetBrains Mono for anything an analyst would
   paste into a query (hashes, IPs, domains, CVE IDs, timestamps, ports).
   Inter for anything read as language. No exceptions either direction.
3. **Color is meaning.** Severity hues mean severity, green/red status means
   up/down, purple means AI-generated, the accent means interactive. Never
   use any of these decoratively.
4. **Surfaces, not shadows.** Elevation = lighter surface + 1px hairline
   border. `box-shadow` only for the focus ring and (subtle) popover lift.
5. **Keyboard is first-class.** Cmd/Ctrl+K palette, visible `<kbd>` hints,
   `/` focuses search. Portfolio-signal and analyst-speed in one move.

## 2. Tokens

```css
:root {
  /* Surfaces — blue-tinted neutral ramp (hue ~218, sat ≤10%). Never #000. */
  --bg-0: #0D1117;            /* page base */
  --bg-1: #141A22;            /* cards, panels, table body */
  --bg-2: #1B222C;            /* nested surfaces, sticky headers, inputs */
  --bg-3: #232B37;            /* popovers, menus, tooltips */
  --bg-hover: rgba(255,255,255,0.055);
  --bg-selected: rgba(76,194,255,0.10);
  --border-subtle: rgba(255,255,255,0.08);   /* row hairlines, card edges */
  --border-strong: rgba(255,255,255,0.14);   /* inputs, section dividers */

  /* Text — never #FFFFFF */
  --text-primary: #E8ECF2;
  --text-secondary: #A3AEBF;  /* metadata, timestamps, secondary cells */
  --text-muted: #5C6875;      /* placeholders, disabled, empty states */

  /* Type */
  --font-ui: "InterVariable", "Inter", system-ui, sans-serif;
  --font-mono: "JetBrains Mono", ui-monospace, monospace;
  --fs-body: 14px;   --lh-body: 1.5;
  --fs-cell: 13px;   --lh-cell: 1.4;
  --fs-label: 11px;  --lh-label: 1.2;  --ls-label: 0.08em;  /* UPPERCASE */
  --fs-mono: 12px;   --lh-mono: 1.45;  /* ≈0.92em of cell size */
  --fs-h1: 20px;     --ls-h1: -0.014em;
  --fs-micro: 11px;  /* timestamps, counts */

  /* Accent — ONE hue (cyan-blue), <5% of pixels on any screen */
  --accent: #2E9BE6;                       /* solid: primary buttons, active nav */
  --accent-hover: #4FADEF;
  --accent-text: #4CC2FF;                  /* links, interactive text */
  --accent-muted: rgba(76,194,255,0.14);   /* selected/chip backgrounds */
  --accent-border: rgba(76,194,255,0.35);
  --focus-ring: 0 0 0 2px rgba(76,194,255,0.55);

  /* AI marker — purple is RESERVED for AI-generated content (Daily Brief) */
  --ai: #B386F9;
  --ai-bg: rgba(179,134,249,0.10);
  --ai-border: rgba(179,134,249,0.35);

  /* Severity triads: text / tinted bg / border. AA on --bg-0. */
  --sev-critical: #F8615A; --sev-critical-bg: rgba(248,81,73,0.14);  --sev-critical-bd: rgba(248,81,73,0.35);
  --sev-high:     #F0883E; --sev-high-bg:     rgba(219,109,40,0.14); --sev-high-bd:     rgba(219,109,40,0.35);
  --sev-medium:   #E3B341; --sev-medium-bg:   rgba(187,128,9,0.14);  --sev-medium-bd:   rgba(187,128,9,0.35);
  --sev-low:      #57AB5A; --sev-low-bg:      rgba(70,149,74,0.14);  --sev-low-bd:      rgba(70,149,74,0.35);
  --sev-info:     #8B96A5; --sev-info-bg:     rgba(139,150,165,0.12);--sev-info-bd:     rgba(139,150,165,0.30);

  /* Status (collection health, deltas) */
  --status-up: #57AB5A;  --status-degraded: #E3B341;  --status-down: #F8615A;

  /* Geometry */
  --radius-chip: 4px;  --radius-control: 6px;  --radius-card: 8px;  --radius-popover: 10px;
  --space: 4px;        /* base unit; scale: 4/8/12/16/24/32 */
  --row-h-dense: 36px; --row-h-regular: 44px;
  --cell-pad-y: 8px;   --cell-pad-x: 12px;
  --sidebar-w: 240px;  --header-h: 56px;
}
```

Font features: globally `font-feature-settings: "liga" 1, "calt" 1, "cv05" 1;`
tables and metrics add `"tnum" 1, "zero" 1;` uppercase labels add `"case" 1;`
mono IOC strings set `font-feature-settings: "liga" 0;` (no ligature fusion in
indicators).

## 3. Typography rules

- Body 14px/1.5 · table cells 13px/1.4 · overline labels 11px UPPERCASE
  +0.08em tracking, weight 500 · mono data 12px/1.45.
- Weights: 400 body, 500 labels/emphasis/buttons, 600 headings only. Nothing
  heavier at any size — bold text blooms on dark.
- Tracking inversion rule: positive tracking only on small caps labels;
  negative tracking only at heading sizes (−0.014em at 20px); nothing between.
- Numbers in tables: right-aligned, `tnum`. Text left-aligned. Never centered.
  Header alignment matches column alignment.
- JetBrains Mono at 0.92× the surrounding Inter size, weight 400 always.

## 4. Color usage rules

- **Accent discipline:** interactive elements only — links, primary button,
  active nav item, focus ring, selection. If a screenshot is more than ~5%
  accent-colored, remove accent uses until it isn't.
- **Severity:** tinted-chip triad (colored text on 14%-alpha same-hue bg,
  35%-alpha border) for tables; 3px left border stripe in feed lists; 6px dot
  + neutral text where space is tight. Never solid saturated chip fills; if a
  solid critical treatment is ever unavoidable, dark text on the light color,
  never white-on-red.
- **Purple = AI, nowhere else.** The Daily Brief header, its "AI-generated"
  chip, and brief-sourced callouts use the `--ai` triad. No other purple
  anywhere in the product, ever. (Convention borrowed from Elastic EUI.)
- **Gray means unknown, not safe.** Unknown/unclassified gets `--sev-info`
  treatment, not green.
- Colorblind safety: severity is never color-alone — chips carry the severity
  word, stripes pair with the chip, status dots pair with text.

## 5. Core component specs

- **Buttons:** primary = `--accent` solid, dark text if luminance demands,
  6px radius; secondary = `--bg-2` + `--border-strong`; ghost for row
  actions. Height 32px (28px in dense contexts), 13px/500.
- **Chips/badges:** 4px radius, 2px 8px padding, 11–12px. Severity chips per
  §4; neutral pills are `--bg-2` bg + `--text-secondary`.
- **Tables:** sticky header on `--bg-2`; 36px dense rows (density toggle to
  44px); 1px `--border-subtle` row hairlines — **no zebra striping**; hover
  `--bg-hover`; hover-revealed cell actions (copy, filter) so resting state
  stays clean; IOC columns mono + truncate-middle.
- **Feed rows:** 3px severity left-stripe, title 13px/500, source + time in
  11px `--text-secondary`, entity chips inline. Unread indicator = 6px accent
  dot. "New since last visit" divider = 1px accent-border line + label.
- **Details drawer:** 420px right-side flyout over the table/feed (Elastic
  pattern), `--bg-1`, hairline left border. Never a route change for row
  inspection.
- **IOC lookup:** omnibox that auto-detects type (hash/IP/domain/URL) —
  verdict-first result header (big classification, colored) with evidence
  listed under it (sources, first/last seen, attribution). Paste-answer in
  one motion, no type selector.
- **Collection health:** Statuspage pattern — one row per source, 90-day
  segment bar (2px gap segments, status colors), uptime %, hover for detail.
- **KPI cards:** metric (20px, `tnum`) + delta (colored text + arrow, color
  the delta never the card) + axis-less sparkline (1.5px line, 10% area fill,
  no gridlines).
- **Command palette:** Ctrl/Cmd+K, centered 560px panel on `--bg-3`,
  fuzzy list with `<kbd>` hints. Keycaps: 11px mono, `--bg-2`, hairline
  border, 4px radius.
- **Empty/loading states:** skeletons matching final layout for >500ms loads
  (subtle shimmer, no spinners); empty states name the cause and the fix in
  text — no illustrations.
- **Toasts:** bottom-right, `--bg-3` + hairline, stacked, no icon circles.
- **Staleness honesty:** every data panel shows its `generated_at` in 11px
  mono; stale (>2h feed, >26h brief) flips the timestamp to `--sev-medium`.

## 6. Layout & density

- Desktop-first; sensible down to ~1280px, no mobile heroics in v1.
- Spacing on the 4px scale; card padding 16px; section gaps 24px; page
  gutters 24–32px; 240px sidebar / 56px header if the chosen IA uses them.
- Information architecture is NOT prescribed here — mockup directions own it.
  Whatever the IA: inspecting a row never loses queue position (drawer, not
  navigation), and the IOC omnibox is reachable from everywhere (palette
  and/or persistent affordance).

## 7. Hard bans (anti-examples)

Rejected on sight, with the tell they signal:

1. **Editorial/display serif anywhere** — italic serif headlines, cream/paper
   backgrounds, "literary" voice. (Six rounds of prior mockup rejection back
   this; the lone approved exception in past work was one brutalist cheat
   sheet, which VIGIL is not.)
2. **Indigo→purple gradients** or any gradient on components; gradient text
   on metrics. Gradients survive only as barely-perceptible radial glows
   behind hero content, if at all.
3. **Glassmorphism** / frosted floating cards / backdrop-blur decoration.
4. **Giant radii** (>12px) on in-product elements; soft ambient drop shadows
   instead of borders; cards nested inside cards.
5. **Three identical icon-cards in a row** with thin-line icons; feature-grid
   "bento" filler; widget-cramming as decoration.
6. **Emoji in headings or UI chrome**; bounce/elastic easing; marketing copy
   in the product ("Build faster. Ship smarter.").
7. **Tailwind-default look**: untinted slate surfaces + `indigo-500` accent.
8. **Pure #000 backgrounds, pure #FFF text, white-on-red badges, zebra
   striping on dark, centered numeric columns, solid saturated chip rows.**
9. **Purple used for anything but AI content** (see §4).
10. **CRT/retro-terminal cosplay** — scanlines, phosphor glow, ASCII borders.
    VIGIL is a modern console, not a costume.

## 8. Pattern sources (steal list)

| Pattern | Source |
|---|---|
| Details flyout over queue | Elastic Security |
| Severity token discipline; purple=AI | Elastic EUI |
| Verdict-first IOC lookup, auto-detect omnibox | VirusTotal / GreyNoise |
| Evidence-under-score | Recorded Future intel cards |
| 90-day segment health bars | Atlassian Statuspage |
| Surface ladder + hairlines, no shadows | Linear / Raycast |
| Neutral-ramp restraint, mono-for-identifiers | Vercel Geist |
| KPI card: metric + delta + sparkline | Stripe / Tremor |
| Blue-tinted dark neutral family | GitHub Primer dark |
| Cmd+K palette with kbd hints | Linear / Raycast / Superhuman |
```
