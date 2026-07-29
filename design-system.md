# VIGIL Design System — v3 "Vantage Law"

v3 supersedes v1 (flat product-UI) and v2 (HTB-style app chrome), both
rejected. The visual reference is now **literal law**: the Vantage CTI
reference site (`design/reference/vantage-source.html` + `vantage-styles.css`,
archived from the live site 2026-07-29). Its aesthetic — brutalist editorial,
Swiss data-sheet, acid-on-ink — is reproduced exactly; VIGIL's additional
capabilities are expressed *inside* that language, never beside it.

Screenshots of the reference: hero + operations sections captured 2026-07-29.
When in doubt, open the reference and copy what it does.

## 1. Identity

A designed intelligence document, not an app. Giant confident display type,
razor-sharp rectangles, hairline rules, tracked-out caps micro-labels, one
acid accent on a green-tinted near-black, blueprint grid texture. Editorial
sections numbered like a dossier. Zero border-radius (status dots excepted).
No shadows — depth comes from surface steps and 1px lines. Density with
poise: big type up top, dense data below.

## 2. Tokens (verbatim from the reference stylesheet)

```css
:root {
  --ink: #050908;          /* page bg — green-tinted near-black */
  --panel: #0c1210;        /* section panels */
  --panel-soft: #111a16;   /* row hover, soft fills */
  --raised: #16201b;       /* raised cells, inputs */
  --line: #26342e;         /* hairlines (green-tinted, never gray) */
  --line-bright: #3b5148;  /* emphasized borders, hover borders */
  --paper: #edf4f0;        /* primary text — off-white, green-tinted */
  --muted: #8fa198;        /* secondary text */
  --acid: #b9ff38;         /* THE accent: CTAs, active states, key numbers */
  --ink-on-acid: #050908;  /* text on acid fills */

  /* Semantic set (category + severity + status) */
  --red:    #ff6250;       /* cyber attack / critical / down */
  --amber:  #ffc75a;       /* ransomware / high / degraded */
  --blue:   #66d5ff;       /* vulnerability / info */
  --green:  #70e09d;       /* threat intel / low / up */
  --purple: #c99cff;       /* AI-generated content ONLY */

  --font-sans: "Geist", "Inter", system-ui, sans-serif;
  --font-mono: "Geist Mono", "JetBrains Mono", ui-monospace, monospace;

  /* Blueprint grid texture (hero + page bg) */
  --grid-bg:
    linear-gradient(#b9ff3806 1px, transparent 1px),
    linear-gradient(90deg, #b9ff3806 1px, transparent 1px);
  /* background-size: 64px 64px; layered over var(--ink) */
}
```

Radius: **0** on everything; `50%` only for status dots. No box-shadows
anywhere — elevation is surface color + 1px `--line`.

## 3. Typography (the core of the identity)

Geist Sans for everything; Geist Mono for numbers, timestamps, indicators,
micro-metadata. Two weights only: **400** (display + body) and **800**
(emphasis, counts, buttons, active labels). 500 permitted for nav only.

| Role | Spec |
|---|---|
| Hero display | `clamp(58px, 7.4vw, 108px)` / 400 / `-0.065em` / lh ~0.95 — sentence-cased words ending in periods ("Ransomware. Malware. APTs."), key word in `--acid` |
| Section header | `clamp(24px, 5vw, 80px)` / 400 / `-0.05em`, preceded by an acid mono section number ("01") |
| Panel display (detail titles) | `clamp(24px, 2.2vw, 34px)` / 400 / `-0.025em` |
| Body | 15-16px / 400 / lh 1.6 / `--muted` for descriptions |
| Row title | 14-15px / 800 / `--paper` |
| Caps micro-label | 10-11px / 800 / UPPERCASE / `+0.08em` to `+0.14em` / `--muted` (or `--acid` for active/labels-of-note) |
| Caps overline (page-level) | 11px / 800 / `+0.2em` / `--acid` |
| Mono data | 11-13px Geist Mono (counts, times, IOCs, stats) |
| Big stat numerals | 28-40px / 800 / mono or sans, `--acid` or `--paper` |

Tracking rule: display type negative (−0.05 to −0.065em); caps positive
(+0.08 to +0.2em); body neutral.

## 4. Component anatomy (copy the reference)

- **Topbar:** 70px, `--ink`, bottom hairline. Diamond outline logo mark
  (acid stroke) + wordmark "VIGIL" 800 + "/CTI"-style suffix in `--muted`.
  Center: plain-text nav links (13px, `--muted`, hover `--paper`). Right:
  live status — 8px dot (acid = live, amber = degraded) + tracked caps
  label ("18 COLLECTORS ONLINE").
- **Hero:** two-column grid `1.18fr 0.82fr` on the blueprint grid texture.
  Left: acid caps overline, display headline, muted lede paragraph, then the
  action row. Right: "OPERATIONAL PICTURE" panel — `--panel`, 1px `--line`,
  caps header row with status word, giant acid numeral, internal 2×2 stat
  grid divided by hairlines, caps footer row.
- **Hero search (VIGIL addition, in-language):** full-width sharp bar in the
  hero action row — `--raised`, 1px `--line-bright`, 56px tall, acid search
  glyph, mono placeholder, right-aligned mono type-detect chip. Focus: border
  flips to `--acid` (no glow, no ring — sharp state change). Below it,
  bordered example chips + a mono "recent lookups" line.
- **Stat band (section nav):** full-width row of equal cells split by
  hairlines; each cell = label left + 800-weight count right; **active cell
  = solid `--acid` with `--ink-on-acid` text**. Doubles as filter/navigation.
- **Primary button:** solid `--acid`, `--ink-on-acid` text, caps 800 tracked
  +0.06-0.09em, sharp, with a directional glyph (↘/↓). Hover: slight
  brightness shift only. Secondary: transparent, 1px `--line-bright`, caps
  muted.
- **Filter chips:** sharp bordered rectangles, caps 10-11px 800, count in
  mono; active = `--paper` border + text; category chips take their category
  color as border+text.
- **Feed rows:** inside a single bordered container with a caps header strip
  ("DAILY INTELLIGENCE · ALL" ... "SHOWING 1 TO 40 OF 304"). Row anatomy:
  left category tag (bordered, category color), then source + channel in
  caps micro-label, 800 title, 2-line muted summary (ellipsis), right mono
  relative time. Hairline between rows; hover `--panel-soft`; selected row
  gets a 3px `--acid` left edge + `--panel-soft`.
- **Detail panel (right rail):** `--panel`, 1px `--line`; caps label row
  (category color + "NOW"), panel-display title, body, then stacked metadata
  blocks (PUBLISHER / PUBLISHED ...) divided by hairlines, caps labels over
  values.
- **Threat report (VIGIL addition, in-language):** replaces the detail rail
  content after a search. Verdict = caps overline in severity color +
  giant 800 score numeral + verdict word in panel-display size + bordered
  category-colored tag chips + muted summary; evidence tables as hairline
  grids with caps column headers; pivot row = secondary-style bordered chips
  (VIRUSTOTAL ↗ / URLSCAN ↗ / ANY.RUN ↗ / TRIA.GE ↗ / CENSYS ↗ / SHODAN ↗).
  Unknown = `--muted` verdict, never green.
- **Tables (vulns/registry):** caps mono column headers, hairline rows,
  mono numerics right-aligned, severity words in their color (text, not
  chips), KEV marker as bordered acid chip.
- **Health:** stat panels per source — caps name, giant count, mono
  last-run, status dot; degraded = amber accents.
- **AI Brief (VIGIL addition):** an editorial numbered section; `--purple`
  takes the overline + section number + "AI-GENERATED" bordered chip (purple
  is reserved for AI, reinforced by the reference's own palette). Stories as
  hairline-divided editorial rows, not cards.
- **Footer strip:** 4-column caps band divided by vertical rules (the
  reference's signature bottom element).

## 5. Layout

One long scrolling page with numbered sections and anchor nav (the reference
IS a one-pager): Hero(+search) → 01 Daily Brief → 02 Threat Operations →
03 Vulnerabilities → 04 Collection Health → 05 Source Registry → Toolbelt.
Content max-width ~1360px, 40px gutters; sections separated by full-width
hairlines; generous vertical rhythm at section tops (96-128px) tightening to
dense data below. The threat report renders in-place (operations section
swaps to report mode) — no route metaphor.

## 6. Motion

Minimal and instant: 120-160ms linear/ease color+border transitions; feed
row entrance none; count-up on big stat numerals only (600ms); the live dot
may pulse. Nothing slides, scales, or bounces. `prefers-reduced-motion`
respected.

## 7. Color rules

- `--acid` = brand + interactive + key numbers. Its dominance is the brand.
- Category colors: CYBER ATTACK `--red` · RANSOMWARE `--amber` ·
  VULNERABILITY `--blue` · THREAT INTEL `--green` · APT `--paper`-bordered.
  Severity: critical `--red`, high `--amber`, medium `--amber` at 70%,
  low `--green`, info `--blue`, unknown `--muted`.
- `--purple` = AI content only. Gray/muted = unknown, never green.
- Dark text on acid fills; never white-on-red chips (bordered text-color
  chips instead).

## 8. Hard bans

1. Border-radius above 0 (dots excepted). 2. Box-shadows, glows, gradient
washes (the 64px blueprint grid is the only texture). 3. Serif anything.
4. Glassmorphism/blur. 5. Emoji in UI. 6. Rounded "app chrome" (pills,
soft cards, floating panels). 7. Purple outside AI content. 8. Zebra
striping; centered numerics. 9. Weights other than 400/800 (500 nav only).
10. More than one accent hue per element — category colors never mix with
acid on the same element.

## 9. Sources

The reference site (primary, literal). Archived at `design/reference/`.
Secondary influences preserved from v2 research where they don't conflict:
verdict-first report anatomy (ANY.RUN/Tria.ge/VT), Statuspage health bars,
Elastic purple-for-AI convention.
```
