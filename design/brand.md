# VIGIL — Brand Book v1.0

**Status:** Proposed 2026-08-06. Extends (never overrides) `design-system.md` v4 "Chart Room"
(approved 2026-07-29). Where this book and the design system disagree on a token or a ban,
the design system wins. Where the design system is silent — positioning, voice, the mark,
applications — this book is the law. Reference implementation of the visual system:
`design/mockups/g-chartroom.html`.

---

## 0 · The premise

The Chart Room identity already contains the brand strategy; it only needs to be said out loud.

A chart room does not generate its own signals. It takes bearings from every available
reference — beacons, stars, radio fixes — plots them on one table, and produces two things:
**a fix** (an authoritative position) and **a log entry** (a record fit to file). That is
exactly what VIGIL does with an indicator. VirusTotal, GreyNoise, Shodan, urlscan are
beacons. VIGIL is the chart table.

This resolves the positioning tension honestly: VIGIL never claims to out-sense the beacons.
Its claim is the **fix** — every bearing, plotted once, logged in a form you can hand to the
next watch.

Everything below is that metaphor, operationalized.

---

## 1 · Positioning

### 1.1 Positioning statement (one sentence)

> **VIGIL is the analyst's chart table: paste an indicator once and it plots every
> authoritative public source into a single verdict, one-click pivots, and an
> escalation-ready summary — free, no accounts, entirely in your browser.**

### 1.2 What it is / what it is not

- **It is** the triage desk: one paste (or a hundred) checked against CISA KEV, NVD CVSS,
  and FIRST EPSS, returned as a verdict with its evidence cited and its paperwork written.
- **It is not** a reputation database. It will not out-scan VirusTotal or out-sense
  GreyNoise, and it does not pretend to — it dispatches you to them with one click,
  context already in hand.
- **It is** the connective tissue and the log: the ten minutes of tab-juggling and
  ticket-drafting between "alert fired" and "escalation filed," collapsed into one paste.

### 1.3 Taglines

Current line: *"The night watch for open-source threat intelligence."* It is good, it is
installed (title tag, masthead strip, footer), and it carries the brand's calm. **Keep it as
the masthead line.** Add a functional line for product surfaces, where "night watch" says
who we are but not what happens when you paste.

| # | Line | Role | Verdict |
|---|------|------|---------|
| 1 | **All bearings. One verdict.** | Doctrine line — mark lockups, OG card, README | **Adopt.** Four words, chart-room native, lands on the product's own vocabulary ("verdict"). |
| 2 | The night watch for open-source threat intelligence. | Masthead / footer brand line | **Keep** where installed. |
| 3 | Paste once. Pivot everywhere. File the verdict. | Hero / product copy, three-beat | Adopt for hero-adjacent copy; pairs with the `TRACK · VERIFY · VERDICT · PIVOT` scramble. |
| 4 | One paste from alert to escalation. | Elevator line for colleagues / slide | Approved alternate. |
| 5 | Triage, plotted and filed. | Spare | Hold in reserve; "filed" is the differentiator but it's cold on its own. |

Rule: never run two taglines in the same viewport region. Masthead gets #2; the mark's
lockup and external cards get #1; long-form copy may use #3 or #4.

---

## 2 · The niche

### 2.1 The landscape (August 2026)

Two axes describe nearly every CTI/security brand: **register** (institutional polish ↔
hacker vernacular) and **volume** (bare utility ↔ full theater).

| Brand | Look | Sound | Position |
|-------|------|-------|----------|
| **Recorded Future** | Electric blue on white/navy, data-viz gloss, enterprise SaaS; explicitly rebranded *away* from "dark displays, matrix-like code animations, and ubiquitous hooded figures" | Market-leader confidence, analyst-firm prose | Institutional · polished theater |
| **Mandiant / Google Cloud** | Red-on-dark IR gravitas, now dissolving into Google Cloud's design language | Authority-by-scar-tissue, nation-state gravitas | Institutional · dark theater |
| **Intel 471** | Dark, stencil-adjacent, spy-agency cosplay ("adversary intelligence") | Tradecraft LARP, ex-agency credentialing | Institutional · dark theater |
| **Flashpoint** | Dark navy + signal red, corporate | Risk-committee reassurance | Institutional · dark theater |
| **GreyNoise** | Gray + irreverent color pops, meme-fluent | Wry, contrarian ("learn what to ignore") | Vernacular · witty theater — **the "funny one" seat is taken** |
| **Hack The Box** | Neon green on black, terminal/cyberpunk cosplay | Gamer hype | Vernacular · full theater |
| **VirusTotal** | Google-utilitarian blue/white | None — a database speaks in rows | Utility · no voice |
| **urlscan.io** | Clean light SaaS-lite | Minimal, functional | Utility · low voice |
| **abuse.ch** | Bootstrap austerity, volunteer-project plainness | Terse, community-service | Utility · anti-design (credibility *through* plainness) |

The whole industry oscillates between two poles the Hewlett/IDEO research and every
branding critique keep flagging: **threat theater** (padlocks, shields, hoods, neon,
countdown fear) and **undesigned utility**. Recorded Future's own rebrand rationale
confirms the sea-of-sameness from the inside.

Sources:
[Recorded Future — brand refresh rationale](https://www.recordedfuture.com/blog/introducing-refreshed-recorded-future-brand) ·
[Cyber Builders — Beyond Dark Mode: the visual revolution in cybersecurity branding](https://cyberbuilders.substack.com/p/from-padlocks-to-pop-art-the-new) ·
[Hiatus — six clichés to avoid in cybersecurity brands](https://www.hiatus.design/cybersecurity/what-cliches-should-you-avoid-when-designing-a-cybersecurity-brand) ·
[Creative Bloq — why security imagery needs an overhaul (Hewlett/IDEO study)](https://www.creativebloq.com/features/why-you-need-to-overhaul-the-way-you-show-cybersecurity-in-your-designs) ·
[GreyNoise — about/mission](https://www.greynoise.io/about)

### 2.2 The unoccupied position

**Nobody in security holds the *instrument* register.** Every brand signals either
*software* (SaaS gradients, electric blue) or *theater* (neon terminals, spy cosplay).
Nothing signals a **calibrated physical instrument with provenance** — the credibility
world of the sectional chart, the banknote, the survey benchmark, the ship's log. That
register is trusted precisely because it predates marketing: charts and banknotes are
designed *against* deception, dense with verifiable detail, beautiful only as a byproduct
of exactness.

VIGIL takes that seat: **the calibrated instrument, kept by a named watchstander.**

- **Visual territory nobody holds:** print-era engraving discipline on an ink field —
  bone paper as the brand color (no one in CTI owns a paper tone), hairline rules instead
  of glows, a vermilion *seal* instead of a neon *accent*, zero radius, zero shadow.
- **Verbal territory nobody holds:** the **watchstanding voice** — calm log-entry prose,
  every claim time-stamped and source-cited, understatement where the industry shouts.
  GreyNoise owns wit; the institutions own fear; *nobody owns procedure.*

### 2.3 Why this is credible for one person's free tool

An individual cannot credibly claim scale ("billions of signals") or fear-authority
("we stop nation-states"). An individual **can** credibly claim exactness, provenance, and
transparency — and the instrument register promises exactly those. Every promise the
aesthetic makes is one person can keep: sources named, timestamps shown, nothing leaves
the browser, $0 infrastructure stated in the footer like a maker's mark. abuse.ch proved
that austerity + reliability earns institutional trust from a small operation; VIGIL takes
the same trust mechanics and adds deliberate craft — which is also precisely the portfolio
argument: the site itself is evidence of the analyst's discipline.

---

## 3 · Personality & voice

### 3.1 Five adjectives

| Adjective | Meaning in practice |
|-----------|---------------------|
| **Exacting** | Numbers carry units, dates, and sources. "Flagged by ThreatFox, high confidence, 2026-07-08 → 27" — never "detected by multiple engines." |
| **Composed** | A critical verdict is rendered at the same volume as a clean one. Severity lives in the data ink, never in the prose temperature. |
| **Traceable** | Every claim can be walked back to a source. If it can't, it is labeled an absence ("not observed"), not an assurance. |
| **Economical** | Short declaratives. No filler, no throat-clearing, no exclamation points. If a sentence survives deletion, delete it. |
| **Dry** | Humor is permitted only as understatement, at most once per surface, never in error or verdict copy. ("$0 INFRASTRUCTURE" in the footer is the ceiling.) |

### 3.2 Anti-personality — what VIGIL must never sound like

- **The threat-theater vendor:** fear adjectives ("devastating," "skyrocketing"),
  countdown urgency, superlatives, "in today's evolving threat landscape."
- **The hoodie:** hacker cosplay, l33t, "pwn," terminal-green swagger, ASCII skulls.
- **The mascot startup:** cute, emoji-laced, apologetic ("Oops!"), quirky empty states.
  That seat is GreyNoise's; contesting it as a solo project reads as imitation.
- **The compliance beige:** passive-voice liability prose ("data may be processed in
  accordance with…"). VIGIL's privacy story is a *feature stated plainly*, not a disclaimer.
- **The résumé:** the site never says "portfolio," "showcase," or "check out my project."
  Craft is demonstrated, not narrated.

### 3.3 Voice rules

1. Write like a watch log: short declaratives, present tense, timestamps.
2. Every quantitative claim carries source + window. Absence of evidence is stated as
   absence: **"Absence is not clearance"** is canon vocabulary.
3. Second person for instruction ("Paste any indicator…"), first person singular only in
   the maker's credit. Never corporate "we" — there is no "we."
4. Indicators are always defanged in prose and UI copy (`evil-updates[.]example`).
5. No exclamation points, no emoji, no apology theater. When something breaks, state what
   broke, since when, and what still works.
6. Sentence case for prose; tracked caps for labels; mono for anything a ticket would quote.

### 3.4 Before / after copy

**a. Hero line**
- ✗ Before: "Your all-in-one threat intelligence platform — search millions of indicators instantly!"
- ✓ After: "Paste any indicator — IP, domain, hash, URL, or CVE — for an instant verdict."

**b. Empty state (indicator not in corpus)**
- ✗ Before: "Oops! We couldn't find anything for that. Try another search 😕"
- ✓ After: "No observations across the collected corpus in the current windows. Absence is
  not clearance — pivot to live sources below."

**c. Error / degraded state**
- ✗ Before: "Something went wrong! Don't worry — our team has been notified."
- ✓ After: "FIRST EPSS unreachable since 06:12 ET. Verdicts render without exploit
  probability until it returns. Eight of nine collectors nominal."
  (There is no team and no telemetry to notify it with; the honest sentence is also the
  more competent one.)

**d. Privacy notice**
- ✗ Before: "We take your privacy seriously. Your data is protected with enterprise-grade security."
- ✓ After: "Runs entirely in your browser. Indicators you paste are never transmitted,
  logged, or stored — there is no server to send them to. All sources TLP:CLEAR."

**e. Verdict summary (the escalation artifact — mono docket format)**
- ✗ Before: "⚠️ HIGH RISK! This IP was flagged malicious by multiple engines. Block immediately!"
- ✓ After:
  ```
  VERDICT   MALICIOUS · 87/100
  OBJECT    185.220.101[.]42 · IPV4 · AS3209 VODAFONE DE
  EVIDENCE  ThreatFox: Cobalt Strike C2, high conf, 2026-07-08→27
            URLhaus: active distribution, 2026-07-12→26
  ACTION    Block at egress. Hunt 14-day flow history for internal contact.
  LOGGED    2026-08-06 14:32 ET · 4 sources cited · vigil.example
  ```

**f. Footer credit**
- ✗ Before: "Made with ❤️ by SaltyCarl © 2026 VIGIL Inc. All rights reserved."
- ✓ After: "VIGIL is built and kept by one SOC analyst on watch — SaltyCarl. Sources are
  credited where they are used. Free, because the watch should be."

---

## 4 · The mark

The current placeholder (diamond outline + checkmark) has two problems: the checkmark is
the most saturated cliché in the category ("verified ✓"), and the diamond-check says
*approval*, not *triangulation*. The mark should encode what VIGIL actually does: fix a
position from multiple bearings. All three candidates are flat 2-color SVG, zero radius,
stroke-built, and print-honest.

### Option A — The Triangulation Station ("the Fix") · RECOMMENDED

The standard cartographic symbol for a triangulation station — a point whose position is
established by bearings from multiple references — is **a triangle inscribed in a circle
with a center point**. It is literally the map symbol for "a fix plotted from several
sources." No security brand uses survey marks; the territory is empty.

**Construction (master, viewBox 0 0 32 32):**
- Circle: cx 16, cy 16, r 12.5, stroke 2, `--paper` (#E8E1CF), no fill.
- Equilateral triangle inscribed at r 11, apex up: vertices (16, 5) · (6.47, 21.5) ·
  (25.53, 21.5). Stroke 2, `--paper`, miter joins, no fill.
- Center point: cx 16, cy 16, r 2.75, **filled `--mark` #E2513A**. The only vermilion.

**16px favicon cut (viewBox 0 0 16 16):** circle r 6.25 stroke 1.5; triangle inscribed
r 5.5 stroke 1.5; dot r 1.75. Reads clearly: ring, wedge, red point. No detail dropped.

**200px+ engraved cut:** master + four cardinal graticule ticks (2.5 units long, stroke 1,
from r 13.5 outward at N/E/S/W) + inner hairline ring r 10.75 at stroke 0.75. At ≥160px an
optional mono micro-caption `EST. 2026` may sit beneath, 9px, +0.2em. Banknote logic:
detail is *added* as scale permits, never scaled up from the small cut.

**Vermilion rule:** the center dot is the seal — the plotted position. On ink, dot is
#E2513A. Struck on bone surfaces (stamps, docket headers), the whole mark prints in
`--mark-press` #B23A28 (see §6). Never fill the triangle or circle with vermilion.

### Option B — The Cancellation ("the Postmark")

A circular datestamp: double ring (outer r 13 stroke 2, inner r 10 stroke 1) around a
chamfered V (strokes (11,11.5)→(16,21)→(21,11.5), stroke 2.5, butt caps); in horizontal
applications, three killer bars (stroke 2, lengths 10/8/10) extend right, as on a postal
cancel. Says "processed and logged" — the paperwork story. Whole mark may print in
vermilion as a true cancel. **Risk:** at 16px the double ring collapses to one; and a
circled V drifts toward certification-badge genericism (and *V for Vendetta* cosplay
readings). Strong as a *secondary* stamp device; weaker as the primary mark.

### Option C — The Chart Beacon ("the Lit Diamond")

Evolution of the existing placeholder, checkmark deleted: rotated square (vertices (16,4)
(28,16) (16,28) (4,16)), stroke 2 `--paper`; center dot r 2.75 `--mark`; four flash ticks
(length 3, stroke 1.5) extending from the vertices at N/E/S/W — the sectional-chart
beacon, lit. Reads as "the light that stays on" (night watch). **Risk:** diamond-with-dot
is close to generic waypoint/map-pin territory, and the rays cost legibility at 16px
(drop them below 24px). Best if continuity with the current placeholder is prized.

### Recommendation

**Option A.** It is the only candidate that encodes the *positioning* (a fix from many
bearings) rather than a mood; it is unclaimed territory in a category drowning in shields,
locks, eyes, and checks; it survives 16px without simplification; and it grows engraving
detail at poster scale exactly the way the Chart Room identity wants. Option B is retained
as the **docket stamp** device (§7.5, §8) — a supporting role it is perfect for.

### Lockups

- **Horizontal (topbar, README):** mark at 26px, 11px gap, then VIGIL — Archivo 800,
  `font-stretch:115%`, +0.04em, caps, `--paper`, optically centered on the circle.
- **Stacked (OG card, slide, stamp):** mark above, wordmark below at 0.6× mark width,
  gap = 0.5× circle radius.
- **One seal per impression:** when the mark is present, its center dot is the *only*
  vermilion in the lockup — the wordmark's I stays paper. When the wordmark stands alone
  (masthead), the I lights vermilion instead. Never both. (The g-chartroom mockup already
  obeys this: vermilion mark + paper VIGIL in the topbar; lit I + no mark in the masthead.)
- **Clear space:** ≥ 1× circle radius on all sides. **Minimum sizes:** mark alone 14px;
  horizontal lockup 22px tall.
- **Doctrine lockup:** horizontal lockup + `ALL BEARINGS. ONE VERDICT.` in mono 9-10px,
  +0.2em, `--muted`, set on the same baseline grid one hairline rule below.

---

## 5 · Wordmark & typography system

### 5.1 The wordmark

"VIGIL" is always set live in Archivo (variable, wdth axis) — never outlined art, so it
stays one system with the page.

| Context | Spec |
|---|---|
| Masthead | `clamp(88px, 11vw, 164px)` / 800 / stretch 125% / −0.02em / lh 0.82 / caps / `--paper`, I in `--mark` |
| Lockup / topbar | 16px / 800 / stretch 115% / +0.04em / caps / `--paper` |
| Stamp & docket header | Mono context instead: `VIGIL` in IBM Plex Mono 600, +0.14em (the wordmark quoted *by a machine* is mono — see 5.3) |

The **lit I** is the wordmark's signature: the single vermilion stroke in a paper word —
the light kept on through the night. Rules: masthead and standalone-wordmark uses only
(see "one seal per impression," §4); never light any other letter; never animate the I.

### 5.2 Sub-brands and module lockups

No slash sub-brands ("VIGIL/CTI") and no second wordmark weights. The product is VIGIL;
modules get **mono conductor labels**, middle-dot separated, 9–11px / 600 / +0.14em / caps:

- `VIGIL · TRIAGE` — the indicator cockpit
- `VIGIL · BRIEF` — the AI daily brief (label renders in `--purple` per the AI rule)
- `VIGIL · PICKET` — the honeypot sensor telemetry (a picket is the lookout vessel posted
  ahead of the fleet — chart-room native; always subtitle it in plain English on first
  use: "telemetry from my own sensor")
- `VIGIL · ESCALATION SUMMARY` — the docket header on every exported artifact

### 5.3 The two typographic voices

- **Archivo = the analyst speaking.** Prose, titles, instructions. Weights 400/600/800
  only. Stretch: 125% masthead, 118% section heads, 115% verdict words/lockups, 100% body.
- **Plex Mono = the record speaking.** Every literal: indicators, hashes, CVE IDs,
  timestamps, counts, scores, source names in evidence rows, kbd hints, edition blocks.
  **Rule of thumb: if a ticket would quote it verbatim, it is mono. If it is a sentence,
  it is Archivo. Mono never sets prose; Archivo never sets data.**
- **Caps micro-labels:** 9–11px / 800 / +0.08 to +0.2em — the engraver's lettering that
  keys every component (kickers, table headers, chip labels).
- **Section numbering:** two-digit ordinals (`01`–`06`) in kickers
  (`SECTION 03 · KEV × CVSS × EPSS`) and as ghost numerals (§7.1). New sections continue
  the sequence; never reuse a number.

---

## 6 · Color roles

Palette is locked from the design system. This section assigns roles and adds exactly one
token. (Phase B renames `--amber` → `--accent`; role names below are canonical.)

### 6.1 The ink world (surfaces & structure)

| Role | Token | Hex | Use |
|---|---|---|---|
| Canvas | `--ink` | `#0F161C` | Page field. Never pure black. |
| Plate | `--panel` | `#141D26` | Cards, rails, ticker label cell |
| Plate raised | `--panel-soft` | `#1A2530` | Hover fills, selected rows |
| Well | `--raised` | `#213040` | Input/textarea fields |
| Hairline | `--line` | `#263644` | Default 1px rules — the ledger grid |
| Rule, scored | `--line-bright` | `#3C566C` | Emphasized borders, masthead rule, pivots |

### 6.2 The paper (brand & interaction)

| Role | Token | Hex | Use |
|---|---|---|---|
| Bone | `--paper` / `--accent` | `#E8E1CF` | Body text, wordmark, **all interactive emphasis**: solid CTAs, active cells, focus borders, hover text. The brand color. Never as a glow. |
| Bone, dim | `--accent-dim` | `#CFC7B2` | Secondary bone (scramble duds, pressed states) |
| Ink on bone | `--ink-on-accent` | `#10171D` | Text on any bone plate (print inversion) |
| Ledger gray | `--muted` | `#8799A6` | Secondary text, labels, **unknown** verdicts |

### 6.3 The seal

| Role | Token | Hex | Use |
|---|---|---|---|
| Vermilion seal | `--mark` | `#E2513A` | Stamp-scale only: mark's center dot, lit I, live dot, kickers, ticker label, KEV chips. <2% of any viewport. |
| Vermilion, struck | `--mark-press` | `#B23A28` | **New token.** Vermilion printed *on bone* surfaces (docket stamps, marks on paper plates, print/export styles). `#E2513A` fails contrast on `#E8E1CF` (~2.4:1); the struck tone holds (~4.8:1) and reads as ink pressed into paper. |

**No second seal tone.** One seal is the discipline; a second dilutes it. **No light
theme:** the print inversion (bone plate + ink text) *is* the light mode, applied
component-by-component where it means "active."

### 6.4 Severity ink ramp & category inks

Severity is always colored **text or border on ink** — never a filled chip (white-on-red
is banned).

| Rank | Token | Hex |
|---|---|---|
| Critical | `--red` | `#FF5E49` |
| High | `--orange` | `#F09A4A` |
| Medium | `--gold` | `#D8C26E` |
| Low | `--green` | `#7CC492` |
| Info | `--blue` | `#6FA8DC` |
| Unknown | `--muted` | `#8799A6` — gray means unknown; green is never "we didn't find anything" |

Category inks (feed tags): cyber attack `--red` · ransomware `--orange` · vulnerability
`--blue` · threat intel `--green` · malware `--gold` · campaign/APT paper-bordered.
`--green` also serves collector-OK status dots; the dual role is accepted and documented.

### 6.5 The AI-purple rule

`--purple #B9A0E8` marks machine-generated content **only** — the Daily Brief section,
AI chips, purple kickers — and such content is always explicitly labeled
(`AI-GENERATED · LOCAL INFERENCE`). Purple is a *disclosure*, not a decoration. Nothing
human-authored or source-collected may use it.

---

## 7 · Signature motifs

Six devices that make any crop identifiable as VIGIL. Every screen should carry at least
two; the screenshot test (§9, item 10) enforces it.

### 7.1 The ghost numeral
- **What:** the section ordinal at 120px, Plex Mono 600, transparent fill,
  1px `--line` text-stroke, floating right of each section head.
- **Where:** every numbered section, once.
- **Rule:** always behind/beside the head, never overlapping body content; never filled;
  never animated. It is a watermark, and watermarks do not move.

### 7.2 The verdict stamp
- **What:** the verdict word — Archivo 800, stretch 115%, caps, +0.02em, severity ink —
  scramble-revealed once on render, beside the score gauge; its chips are 1px-bordered
  letterpress tags (colored border + text, transparent fill).
- **Where:** verdict rail, docket headers, OG card for shared verdicts.
- **Rule:** the word states rank, the prose stays composed; scramble runs once, never
  loops; `UNKNOWN` renders in `--muted` at the same size — uncertainty is stamped with
  equal ceremony.

### 7.3 Graticule and grain
- **What:** the 56px chart grid (two 1px linear-gradients of `rgba(111,168,220,.045)`)
  plus 5% feTurbulence film grain — the paper stock of the site.
- **Where:** every full-bleed surface, every application (OG cards, slides, banners).
- **Rule:** intensities are fixed; the grid is never brightened, animated, or used as a
  "tech" decoration. It is the paper, not a effect.

### 7.4 The print inversion
- **What:** interaction rendered as letterpress — active/selected/primary elements flip to
  solid bone with ink text (stat band's `.on` cell, Export button, detect chip).
- **Where:** every screen's primary action and active state.
- **Rule:** one dominant inversion per region; bone plates never carry shadows, radius, or
  vermilion text (severity chips on bone use `--mark-press` / ink). If nothing on a screen
  inverts, nothing on it is interactive — inversion *is* the affordance.

### 7.5 The docket slip
- **What:** the escalation summary as a printed receipt: 1px `--line-bright` border,
  `--panel` plate; mono header `VIGIL · ESCALATION SUMMARY · <UTC timestamp>`; ruled
  key-value rows (VERDICT / OBJECT / EVIDENCE / ACTION); a `LOGGED` footer line; bottom
  edge closed by a 1px **dashed** `--line-bright` perforation — the tear-off. Option B's
  cancellation ring may stamp the corner at 28px in `--mark` (on ink) or `--mark-press`
  (on bone/export).
- **Where:** verdict export, copy-blurb previews, bulk-triage results, the colleague slide.
  **This is the artifact that travels into tickets — the most strategically branded
  surface VIGIL has.** The plain-text copy it yields keeps the same layout in ASCII.
- **Rule:** the perforation dash is the only dashed line in the system; docket content is
  100% mono; every docket carries LOGGED + source count.

### 7.6 The live wire and the ticking counters
- **What:** the ticker (vermilion `LIVE WIRE` label cell, 46s marquee, mono items) and the
  count-up numerals (1.1s expo-out, tabular-nums, once per view) with the masthead edition
  block.
- **Where:** ticker on the front page only; counters wherever totals appear; edition block
  on masthead, OG card, README banner.
- **Rule:** counters run once (IO-triggered) and never re-animate; the ticker is the sole
  looping motion in the brand; every counter is a real number with a real refresh time —
  data-honest or absent.

---

## 8 · Applications

### 8.1 Favicon (emoji-free)

SVG, 16×16 grid: square field `#0F161C` (no radius — the corner of a chart, not an app
icon); Option A 16px cut centered — circle r 6.25 + inscribed triangle, stroke 1.5
`#E8E1CF`; center dot r 1.75 `#E2513A`. Ship as `favicon.svg` + 32/180px rasters (the
32px uses the master cut). Monochrome/pinned-tab variant: all-paper strokes, dot included.
The red point at 16px is the brand's smallest complete sentence: *a position, fixed.*

### 8.2 Social / OG card (1200×630)

Ink field `#0F161C` with graticule + grain at spec intensity. Layout:
- Top rule, 1px `--line-bright`, full width at y 64; mono edition block right-aligned
  above it (`EDITION 2026-08-06 · TRACKED OBJECTS 32,783`), 20px, `--muted`.
- `VIGIL` from x 80, baseline ~y 400: Archivo 800, stretch 125%, −0.02em, ~230px, paper,
  **lit I** (wordmark stands alone here, so the I takes the seal).
- Below: `THE NIGHT WATCH FOR OPEN-SOURCE THREAT INTELLIGENCE`, caps 800 26px +0.2em
  `--muted`; beneath it `ALL BEARINGS. ONE VERDICT.` in mono 22px `--paper`.
- Bottom edge: solid bone bar 12px tall, full width — the paper showing at the card's cut.
- Optional right column: a 380px docket slip specimen at 15° of nothing — no rotation,
  no shadow; it sits square like everything else.
A verdict-share variant swaps the tagline block for the stamped verdict word + defanged
indicator in mono.

### 8.3 GitHub

- **Repo social preview (1280×640):** the OG card art re-cut to fit; nothing rescaled
  below legibility.
- **README header:** inline SVG banner, 1280×220: ink field + graticule; horizontal
  doctrine lockup (mark 48px, VIGIL 44px, `ALL BEARINGS. ONE VERDICT.` mono beneath);
  right-aligned mono block `STATIC · NO ACCOUNTS · NO TRACKING · TLP:CLEAR`; 1px
  `--line-bright` rules top and bottom.
- **Badges:** default shields.io styling is off-brand. If used at all: `flat-square`
  style only, one row maximum, colors from the system (`0F161C` label / `E8E1CF` or
  severity inks for status / `E2513A` reserved for a KEV-related badge only).
- **Repo description line:** "Paste an indicator, get a verdict you can file. Free,
  static, in-browser OSINT triage — KEV × CVSS × EPSS, one-click pivots, escalation-ready
  summaries."

### 8.4 The colleague slide (one 16:9 board)

Ink field, graticule, single board titled by the stacked lockup top-left (mark 72px).
- **Left 55%:** `WHAT IS VIGIL` kicker (vermilion, +0.2em); three Archivo lines set large:
  `One paste — every source checked.` / `A verdict with its evidence cited.` /
  `An escalation summary, ready to file.` Each with a mono sub-line naming the mechanics
  (KEV × CVSS × EPSS; VT/GN/Shodan/urlscan pivots; bulk paste).
- **Right 45%:** one full docket slip specimen, real data, defanged.
- **Footer strip** (1px rule above): mono — `FREE · NO ACCOUNTS · NOTHING LEAVES YOUR
  BROWSER · vigil.example`.
No agenda slide, no second slide. The board is a specimen of the product, not a pitch.

---

## 9 · The 10-point brand checklist

Run against any new screen, card, or export. A miss on any bolded item is a stop-ship.

1. **Print-honest surfaces:** zero border-radius (status dots excepted), zero box-shadows,
   zero glows/gradients beyond the sanctioned washes. Depth = plates + 1px hairlines only.
2. **The seal is scarce:** vermilion under 2% of the viewport, stamp-scale, and every use
   *means* something (seal, lit I, live, kicker, KEV). On bone it is `#B23A28`.
3. **Bone carries interaction:** the primary action / active state is a print inversion
   (bone plate + ink text). No other emphasis color exists.
4. Two voices, kept apart: literals in Plex Mono, sentences in Archivo; caps labels
   tracked ≥ +0.08em; no serif, no third face.
5. One seal per impression: mark's dot *or* the lit I, never both in one lockup.
6. **Severity is ink, not alarm:** colored text/border on ink, never filled chips; gray =
   unknown, never green; prose stays composed regardless of rank.
7. **Purple = machine:** AI-generated content is purple-keyed and labeled; nothing else
   is purple.
8. Every number has a source and a time: counts, scores, and statuses show provenance or
   don't ship; degraded states say what broke, since when, what still works.
9. Motion is data-honest: enters once, ≤1.6s, `prefers-reduced-motion` respected; nothing
   loops except the ticker and status pings; nothing animates on repeat interaction.
10. **The screenshot test:** crop any region — at least two signature motifs (§7) present,
    and a colleague who has seen VIGIL once could name the site. If not, it isn't branded;
    it's just styled.

---

## Appendix A · Approved line library

| Surface | Line |
|---|---|
| Masthead strip | The night watch for open-source threat intelligence. |
| Doctrine / lockup / OG | ALL BEARINGS. ONE VERDICT. |
| Hero input placeholder | Paste any indicator — IP, domain, hash, URL, or CVE — for an instant verdict |
| Scramble tagline | TRACK · VERIFY · VERDICT · PIVOT — REFRESHED EVERY 30 MINUTES |
| Empty verdict | No observations across the collected corpus in the current windows. Absence is not clearance — pivot to live sources below. |
| Privacy | Runs entirely in your browser. Indicators you paste are never transmitted, logged, or stored — there is no server to send them to. |
| Footer | VIGIL is built and kept by one SOC analyst on watch — SaltyCarl. Free, because the watch should be. |
| Elevator (colleagues) | One paste from alert to escalation. |

## Appendix B · Open items for Phase B

1. Replace the placeholder diamond-check SVG with the Option A mark (topbar 26px cut,
   favicon 16px cut, README banner 48px cut).
2. Add `--mark-press:#B23A28` when renaming `--amber` → `--accent`.
3. Build the docket slip component (§7.5) as the canonical escalation-summary renderer —
   HTML view + ASCII clipboard twin.
4. Cut the OG card and GitHub social preview from §8.2/§8.3 specs.
5. Retire "VIGIL/CTI"-style naming anywhere it exists; adopt mono conductor labels (§5.2).
