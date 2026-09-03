# Adversary Profile — Progressive Disclosure (N1) + Distinctive-TTP Lead (N4) — Design

**Goal:** Tame the ~7,200px single-scroll `/actor` profile into a consumable, one-screen-first surface — an always-on *decision layer* over `<details>`-collapsed *reference depth*, oriented by a sticky scrollspy jump-nav — while preserving every SEO / print / Ctrl-F / deep-link guarantee the profile already earns.

**Architecture:** Pure layout/IA restructure of `ActorProfile.tsx`. No collector, pipeline, schema, or data change. No new analytic logic — the "Distinctive TTPs" lead band re-surfaces the EXISTING `distinctiveSplit` artifact (`derived.ts:76`), and the activity spark reuses `activity.daily`. Collapsibles are native `<details>/<summary>` (content stays in the DOM); a small app-JS hook adds deep-link open, print-open, and scrollspy (CSS has no `open` property, so the "pure-CSS" version isn't literally achievable — the app already ships JS under a CSP that allows its own bundle, so this costs nothing).

**Tech stack:** React 19 + Tailwind v4, native `<details>`, `IntersectionObserver`, `beforeprint`/`afterprint`, `hashchange`. Vitest (node env, `renderToStaticMarkup`).

**Spec owner ruling (locked 2026-09-03):** *defer + orient, never hide.* Tabs rejected (they hide content from crawl + Ctrl-F). Guardrail: **no "accordion soup"** — collapse ONLY the heavy reference sections; the reason-to-open-the-page content stays open.

---

## Global Constraints

- **Free-tier / no new deps.** Native `<details>` + `IntersectionObserver`; no accordion/library.
- **Honesty doctrine.** Reorders + collapses attributed facts; synthesises nothing. Every synthesis-band field is independently honest-empty (absent → renders nothing, never a zero/placeholder). Distinctive TTPs is real `distinctiveSplit` data with a stated denominator.
- **SEO / crawl / print / deep-link — non-negotiable.** Collapsed `<details>` content MUST remain in the DOM (no conditional unmount). Print MUST open every section. A `#<section>` fragment MUST land + open its section.
- **Brand system held.** Dark theme, Archivo/IBM Plex Mono, reserved periwinkle `#7C8AFF` accent; semantic colors keep their meaning. No editorial serif/cream. Visual treatment of the new band + nav goes through the design pass at build time (not over-specified here).
- **react-refresh discipline.** Pure helpers/hooks in `.ts`; component files export only components.
- **Committed-dataset tests assert shape/behaviour** on fixtures, never live-file content. Vitest env is node → presence tests via `renderToStaticMarkup`, no click/DOM-event tests.
- **Accessibility.** `<details>/<summary>` is natively keyboard-operable; jump-nav links are real anchors; scrollspy only sets an `aria-current`.

---

## Current structure (grounded)

`ActorProfile.tsx` renders `IdentityHeader` (`:144`) then a `grid lg:grid-cols-[1fr_340px]`:

**Left column (main), in order** (`:1288–1357`):
1. Initial access & detection — `IntelPanel`, `accent`, gated on `intel` (`:1291`)
2. Leak-site activity — `ActivityPanel`, gated on `activity` (`:1301`)
3. Claimed victims — ledger, gated on `claimedVictims`/`ransomware` (`:1308`)
4. ATT&CK fingerprint — `MitreFingerprintPanel` (`:1330`); **this panel already computes `distinctiveSplit` (`:771`), tints distinctive cells in `TacticMatrix` (`:736`), and renders a "Distinctive techniques · N" block (`:804`) — but buried below the 87-cell matrix, deep in the page.**
5. Hunt pack — `HuntPackPanel`, gated on `fingerprint && huntPack` (`:1346`) — the largest section (dozens of rows).
6. Reporting — `ReportingList` (`:1353`).

**Right rail (sticky, `:1358`):** Shared techniques (`:1360`), Used by tracked groups (malware, `:1366`), Related entities (`:1372`, now dedup-gated), Associated malware (`:1376`).

**Problem:** everything renders expanded → ~7,200px. The single most differentiated artifact (distinctive TTPs) is invisible until you scroll into the fingerprint panel. There's no orientation and no one-screen synthesis.

---

## Target information architecture

A sticky **jump-nav** under the app header, then a **decision layer** (always open), then **reference depth** (collapsed `<details>`). Each addressable section carries a stable `id` for anchors + deep links + scrollspy.

### Sections + open/collapsed state

| # | Section | `id` | State | Notes |
|---|---------|------|-------|-------|
| — | Identity header | `overview` | **open** | existing `IdentityHeader`; anchor target for "Overview" |
| — | **Synthesis band (NEW)** | (part of `overview`) | **open** | the one-screen read — see below |
| — | Initial access & detection | (part of `overview`) | **open** | flagship, most triage-actionable; stays open when present |
| — | Leak-site activity | `activity` | **open** | the "who now" |
| A | Claimed victims | `victims` | **collapsed** | `<details>` — "Claimed victims · N ▸" |
| B | ATT&CK fingerprint (full matrix) | `fingerprint` | **collapsed** | `<details>` — "ATT&CK fingerprint · 66 techniques ▸"; the distinctive lead is HOISTED out (below) so the collapsed body is the full 87-cell detail |
| C | Hunt pack | `huntpack` | **collapsed** | `<details>` — "Hunt pack · N queries ▸" (the reference library; the re-run's #1 ask) |
| D | Reporting | `reporting` | **collapsed** | `<details>` — "Reporting · N ▸" (only when non-empty) |
| — | Right rail (Shared / Used-by / Related) | `related` | rail; mobile-collapsed | anchor "Related" jumps here |

Guardrail honoured: only A–D (the heavy/reference sections) collapse. Identity + synthesis + intel + activity are always open.

### Synthesis band (NEW) — the decision layer's summary (N4 lives here)

A compact band directly under `IdentityHeader`, always open, each cell honest-empty independently:
- **Distinctive TTPs · N** — the top ~5 of the existing `distinctiveSplit(fingerprint.techniques, prevalence).distinctive` (≤3-tracked-groups rarity), rendered as tinted technique chips with the stated denominator. Absent when the split is empty (~42% of actors) — renders nothing. This is the re-run's N4: the differentiated artifact promoted from buried to lead.
- **Top hunts · N** — `huntPack` query count + the top 2–3 titles (link/anchor to the collapsed Hunt-pack section). Absent when no pack.
- **Activity spark** — a mini inline 31-day strip from `activity.daily` + "last claim / peak" cadence facts (anchor to Activity). Absent for non-claiming groups.
- **Flagship access** — 1-line tease of `intel` initial-access CVEs / KEV chips (anchor to the intel panel). Absent when unseeded.

The band is a *router*: each cell deep-links (anchor) to the full section, so the synthesis leads and the depth is one click away.

### Jump-nav (sticky, scrollspy)

A thin sticky sub-bar (or left rail on `lg`) with anchors: **Overview · Fingerprint · Activity · Hunt pack · Related** (each only shown when its section exists). Scrollspy sets `aria-current="true"` on the section in view. On mobile it collapses to a single **"Jump to ▾"** `<details>` disclosure. It sits below the app header (sticky `top` offset), and anchors carry `scroll-margin-top` so a jump/deep-link isn't hidden under it.

---

## Mechanism

### `CollapsibleSection` (new component, `CollapsibleSection.tsx`)
Wraps a reference section as:
```
<details id={id} open={defaultOpen} className="scroll-mt-24 …">
  <summary>…eyebrow · count · chevron…</summary>
  <div>{children}</div>
</details>
```
- Uncontrolled by default (native toggle — zero JS for normal expand/collapse).
- `<summary>` styled as the section header (brand tokens), showing the count and a rotating chevron; `list-style:none` + custom marker.
- Reference sections pass `defaultOpen={false}`; the hook (below) overrides for hash/print.

### `useProfileNav` (new hook, `useProfileNav.ts` — pure module, app JS)
One effect, CSP-clean (app bundle, not inline):
1. **Deep-link open:** on mount + on `hashchange`, `document.getElementById(hash)` → if it's a `<details>`, set `open`, then `scrollIntoView`. So `…#huntpack` and a jump-nav click both land + expand.
2. **Print-whole:** on `beforeprint`, open every `<details data-collapsible>` (record which were closed); on `afterprint`, restore. Preserves the shipped capture behaviour.
3. **Scrollspy:** `IntersectionObserver` over the section anchors → expose the active `id`; the nav marks `aria-current`. Observer disconnects on unmount.

Testable seam: the pure decisions (which sections exist → nav items; hash → target id) live as exported pure helpers unit-tested in node; the DOM wiring is the thin effect.

### CSS
- `scroll-mt-*` (scroll-margin-top) on every section anchor for the sticky-nav offset.
- `@media print` opens are handled by the hook (CSS can't force `open`); a print stylesheet still normalises spacing.
- `<summary>` marker reset + focus-visible ring (brand accent).

---

## Files

**New**
- `web/src/components/views/CollapsibleSection.tsx` — the `<details>` section wrapper.
- `web/src/components/views/SynthesisBand.tsx` — the decision-layer summary (distinctive TTPs / top hunts / activity spark / flagship access).
- `web/src/components/views/ProfileNav.tsx` — the sticky scrollspy jump-nav (+ mobile "Jump to ▾").
- `web/src/components/views/useProfileNav.ts` — hash-open + print-open + scrollspy hook (+ exported pure helpers).
- Tests: `__tests__/SynthesisBand.test.tsx`, `__tests__/CollapsibleSection.test.tsx`, `__tests__/useProfileNav.test.ts` (pure-helper unit tests).

**Modify**
- `web/src/components/views/ActorProfile.tsx` — restructure the render (decision layer + `CollapsibleSection`-wrapped reference sections + `ProfileNav`); hoist the distinctive lead into `SynthesisBand` (keep the tinting inside `TacticMatrix`); give sections stable ids.
- Possibly `MitreFingerprintPanel` — the standalone "Distinctive techniques · N" block (`:804`) may be removed if fully represented by the synthesis band (decision at build; keep the in-matrix tint regardless).

---

## Testing

- **SynthesisBand:** renders distinctive-TTP chips + count when the split is non-empty; renders the hunt count + activity spark when present; renders NOTHING for a bare actor (no distinctive, no hunts, no activity) — honest-empty, no zero cells.
- **CollapsibleSection:** renders a `<details>` with a `<summary>` carrying the eyebrow + count; reference sections are `open={false}` in static markup (collapsed by default), always-open sections are not wrapped.
- **DOM presence (SEO guard):** the collapsed sections' content IS present in `renderToStaticMarkup` output (proves content ships to crawlers even when collapsed).
- **ProfileNav:** renders an anchor per existing section; omits anchors for absent sections.
- **useProfileNav pure helpers:** section-list → nav-item derivation; hash → target-id resolution.
- No regression: full vitest + lint + build + pytest green.

## Build-time process (per the design methodology)
The IA/mechanism above is settled here. The VISUAL treatment (synthesis-band layout, nav styling, summary/chevron affordance, spacing rhythm) is produced at build time via the UI design pass + reference libraries, then run through the 3-lens (SOC-analyst / data-analytics / UX) review before ship — holding the brand system.

## Deploy
build/lint/full-vitest/pytest green → `git pull --rebase origin main` → push → `gh workflow run collect-and-deploy` → live-dogfood: one-screen synthesis renders; jump-nav scrollspy + mobile "Jump to ▾"; `…#huntpack` deep-link lands+opens; print opens all; distinctive TTPs lead; SEO (view-source shows collapsed content).

## Resolved decisions (owner-approved 2026-09-03)
1. **Intel panel placement:** ✅ KEEP always-open in the decision layer (most triage-actionable). Not collapsed.
2. **Synthesis band content:** ✅ FOUR signal cells only (Distinctive TTPs · Top hunts · Activity spark · Flagship access) — no description line; the identity header carries identity.
3. **Fingerprint default:** ✅ COLLAPSE the full 87-cell matrix by default (the distinctive lead is hoisted to the synthesis band). Collapsed reference set = Claimed victims · ATT&CK matrix · Hunt pack · Reporting.
