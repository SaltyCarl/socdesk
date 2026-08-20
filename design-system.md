# SOCDESK Design System — v4 "Chart Room" (APPROVED 2026-07-29)

> **Historical** — this "Chart Room" system is binding only for the legacy `site/` app. The live `web/` app follows the periwinkle/warm direction documented in `CLAUDE.md`'s Design-law section (no standalone `web/` design doc yet).

The approved visual identity. Reference implementation (source of truth):
`design/mockups/g-chartroom.html`. Lineage: editorial-brutalist structure
derived from the Vantage reference (`design/reference/`), divergent identity
(masthead composition, Archivo/Plex Mono, Chart Room palette), showcase
motion layer from the 2026-07-29 influencer/interaction-craft research.
Superseded exploration preserved in `design/mockups/` (a–f).

## 1. Identity

A printed intelligence chart, alive. Reference world: aviation sectional
charts and banknote engraving — Prussian-slate ink, bone paper, vermilion
seal. Color behaves like ink, never like light: zero glows, zero neon,
zero border-radius (status dots excepted), no box-shadows. Depth = surface
steps + 1px tinted hairlines. Motion is scarce and data-honest.

**The anti-slop law:** "dark mode + one neon accent" is the AI tell as a
structure, regardless of hue. SOCDESK's neutrals carry the identity; the paper
tone does the branding; saturated color covers <2% of any viewport and only
where it means something.

## 2. Tokens (from g-chartroom.html, verbatim)

```css
:root{
  /* Prussian-slate ink world (blue-tinted, never neutral gray or #000) */
  --ink:#0F161C; --panel:#141D26; --panel-soft:#1A2530; --raised:#213040;
  --line:#263644; --line-bright:#3C566C;
  /* Bone paper — the identity carrier */
  --paper:#E8E1CF; --muted:#8799A6;
  /* "Accent" = paper as material. Solid bone fills w/ ink text (print inversion) */
  --amber:#E8E1CF; --amber-dim:#CFC7B2; --ink-on-amber:#10171D;
  /* Vermilion seal — stamp-scale only */
  --mark:#E2513A;
  /* Severity/category as desaturated print inks */
  --red:#FF5E49; --orange:#F09A4A; --gold:#D8C26E; --green:#7CC492;
  --blue:#6FA8DC; --purple:#B9A0E8;   /* purple = AI content ONLY */
  --sans:"Archivo",system-ui,sans-serif;
  --mono:"IBM Plex Mono",ui-monospace,monospace;
  --ease:cubic-bezier(.16,1,.3,1);
}
```

(Token name `--amber` is legacy from the f-variant; it now means "bone
accent". Rename to `--accent` during Phase B productionization.)

Page texture: 56px graticule grid, two 1px linear-gradients of
`rgba(111,168,220,.045)` over `--ink`, plus feTurbulence film grain at 5%
overlay. Hero-only radial wash: bone at 5%.

## 3. Color rules

- **Bone** = interactive/brand: solid CTAs and active cells (bone bg + ink
  text), focus borders, hover text. Never as glow.
- **Vermilion `--mark`** = seal-scale marks only: logo, the lit "I" in the
  masthead, live dot, section kickers, ticker label, KEV chips. If vermilion
  covers more than stamp-area, it's wrong.
- **Severity inks:** critical `--red` · high `--orange` · medium `--gold` ·
  low `--green` · info `--blue` · unknown `--muted` (gray = unknown, never
  green). Category tags: cyber attack red · ransomware orange · vulnerability
  blue · threat intel green · malware gold · campaign/apt paper-bordered.
- **Purple = AI-generated content only** (Daily Brief section, AI chips).
- The verdict conic border sweep is `--red` and appears only while a
  malicious verdict is displayed (semantic motion).

## 4. Typography

Archivo (variable, wdth axis) + IBM Plex Mono. Weights 400/600/800.

- Masthead: `clamp(88px,11vw,164px)` / 800 / `font-stretch:125%` /
  `-0.02em` / lh .82 / UPPERCASE.
- Section headers: `clamp(30px,4.4vw,58px)` / 800 / stretch 118% / UPPERCASE,
  with a tracked vermilion kicker above and a mono ghost numeral
  (1px `--line` text-stroke) floating right.
- Caps micro-labels: 9-11px / 800 / +0.08–0.2em. Body 15px/1.6. Row titles
  14px/600. Mono for all data values (11-13px).

## 5. Composition signatures

Masthead (giant SOCDESK + mono edition block + tagline strip) → hero search
(68px, bone focus border, type auto-detect chip, TRY chips) → LIVE WIRE
ticker → stat band (active cell solid bone) → numbered editorial sections
(01 Daily Brief [purple] · 02 Threat Operations [feed + sticky rail] ·
03 Vulnerability Triage · 04 Collection Health · 05 Source Registry ·
06 Analyst Toolbelt) → four-column footer band. One long scrolling page,
anchor nav, sticky blurred topbar with TLP:CLEAR chip. Verdict reports
render in the operations rail (gauge + scrambled verdict word + evidence
+ external pivot chips), never a route change.

## 6. Motion layer (all data-honest; full inventory in g-chartroom.html)

- Scramble/decrypt: tagline on load; verdict word on report render. Never
  looping.
- Count-up (1.1s expo-out, tabular-nums) on big numerals, IO-triggered once.
- Scroll reveals: 24px fade-up, 600-700ms `--ease`, 70ms sibling stagger via
  `--i`, IntersectionObserver.
- Ticker marquee: 46s linear loop, pause on hover.
- Gauge arc draw-in (1.1s) on verdict render; ping pulses on live/status
  dots (staggered).
- Hover: 150ms color/border transitions; feed rows get a cursor-tracked
  bone wash at 5% alpha.
- Interactions ≤200ms; nothing bounces, slides, or scales except the
  specified enters. Full `prefers-reduced-motion` kill switch + `motionOK`
  gate on all JS animation.

## 7. Hard bans

1. Neon-on-black in any hue; glows above 8% alpha; light-emitting color.
2. Border-radius >0 (dots excepted); box-shadows; glassmorphism (topbar
   blur-under is the lone sanctioned blur).
3. Serif anything; emoji in UI; rounded app chrome.
4. Gradients on components (texture washes per §2 only).
5. Purple outside AI content; green for unknown; white-on-red chips.
6. Zebra striping; centered numeric columns.
7. CRT/Matrix cosplay (scanlines, phosphor, ASCII rain).
8. Ambient motion beyond the ticker + status pings; animation on repeated
   interactions; anything animating past 1.6s except the ticker.

## 8. Phase B notes

Productionize from `g-chartroom.html`: rename `--amber`→`--accent`,
extract sample data to the real `site/data/*.json` contract, wire the
verdict flow to `iocs.json`/`cves.json` lookups, keep the motion inventory
exactly as speced. The mockup IS the visual acceptance test.
