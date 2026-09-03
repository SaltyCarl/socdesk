# Profile Progressive Disclosure (N1) + Distinctive-TTP Lead (N4) — Implementation Plan

**Spec:** `docs/superpowers/specs/2026-09-03-profile-progressive-disclosure-design.md` (owner-approved; intel always-open · synthesis = 4 cells · full matrix collapsed).

**Goal:** Restructure `ActorProfile.tsx` into an always-on decision layer over `<details>`-collapsed reference sections, oriented by a sticky scrollspy jump-nav, and ADD a synthesis lead band that surfaces the existing distinctive-TTP data. No pipeline/schema/data change.

> **Revised after adversarial vet (2026-09-03).** Key corrections folded in: extend `BoardPanel` (not a bare `<details>`); the distinctive standalone block is a NO-CATALOG FALLBACK (not "below the matrix") and is LEFT UNTOUCHED — SynthesisBand only ADDS a new surfacing; `TechniqueChip`/`HeatStrip` are un-exported and must be extracted; HuntPack has `totalMatched` but no flat titles; SSR-safe hook; no inline-style chevron; concrete sticky offsets.

## Global Constraints
- Free-tier, no new deps (native `<details>`, `IntersectionObserver`).
- Honesty: reorder/collapse only; every synthesis cell honest-empty; distinctive = real `distinctiveSplit` with stated denominator.
- **SEO/print/deep-link:** collapsed `<details>` content stays in DOM — render `<div>{children}</div>` UNCONDITIONALLY, never `{open && children}`. Print opens all; `#<id>` lands+opens.
- **No inline styles** (`react/forbid-dom-props` bans `style`; CSP `style-src 'self'`). Chevron rotation via Tailwind `[&[open]]:`/`group-open:` variant. Spark cells sized by Tailwind classes only.
- **noUnusedLocals/noUnusedParameters = true** (`tsconfig.app.json:36-37`) — an unused var is a HARD build error, not a lint warning.
- Brand system held; visual treatment via the design pass + 3-lens review at build.
- react-refresh: pure helpers/hooks in `.ts`; component files export only components.
- Vitest env = node → `renderToStaticMarkup` presence tests + pure-helper tests only (no click/effect/IntersectionObserver/hashchange).

## Shared contracts
- **Section ids** (nav + deep-links + scrollspy): `overview` (identity + synthesis + intel) · `activity` · `victims` · `fingerprint` · `huntpack` · `reporting` · `related` (right rail). A nav item/anchor appears only when its section exists.
- **Sticky offset math (concrete):** Topbar is `sticky top-0 z-40 h-14` = 56px (`ui/Topbar.tsx:69`). ProfileNav = `sticky top-14 z-30 h-11` (44px) → sticky stack = 100px. Right rail bumps from `lg:top-20` (80px) to `lg:top-[6.5rem]` (104px) to clear header+nav. Section anchors carry `scroll-mt-[6.5rem]` (104px). ProfileNav `z-30` sits below Topbar `z-40` and clear of MobileNav.

---

### Task 1 — Extend `BoardPanel` with collapsible mode
**Files:** Modify `web/src/components/overview/board-ui.tsx` (BoardPanel `:143-199`); Test `web/src/components/overview/__tests__/board-ui.test.tsx` (create if absent).
Add optional props `collapsible?: boolean` and `defaultOpen?: boolean` (default open when not collapsible; `defaultOpen ?? false` when collapsible). When `collapsible`:
- Render the SAME styled shell but as `<details data-collapsible id={id} open={defaultOpen ?? false} className="… scroll-mt-[6.5rem]">` (keep the existing `rounded-lg border border-line bg-panel p-5` shell classes so collapsed sections are visually identical to open ones).
- Move the existing `<header>`/eyebrow (`MicroLabel`) + `aside` slot into a `<summary className="cursor-pointer select-none list-none marker:content-none …">`, append a chevron that rotates via `[&[open]]:rotate-90` (Tailwind, NOT inline style). The `aside` slot already carries counts (`ActorProfile.tsx:1311`), so "· N" rides it for free.
- Non-collapsible path unchanged (backward-compatible with every existing call site).
- Accept an optional `id` prop (used for the anchor).
**Tests:** collapsible BoardPanel static markup contains `<details` + `data-collapsible` + the id, no `open` attribute when `defaultOpen` falsy (collapsed), children present in output while collapsed (SEO guard); a normal BoardPanel still renders its `<section>` unchanged.

### Task 2 — Extract the reused primitives (no behaviour change)
**Files:** Create `web/src/components/views/TechniqueChip.tsx`; create `web/src/components/views/activity-ui.ts` (pure) + `web/src/components/views/HeatStrip.tsx`; Modify `ActorProfile.tsx` to import them.
- **TechniqueChip** — lift the module-local component (`ActorProfile.tsx:42-73`, props `{ id: string; name?: string; hint?: string; distinctive?: boolean }`, deps `techniqueUrl` from `./relations` + `cx`) into `TechniqueChip.tsx`, export it, import back into ActorProfile (TacticMatrix `:736` + fallback `:812`). Behaviour identical.
- **HeatStrip** — lift `heatClass` (`:219-224`) + `dayLabel` (`:207-211`) into `activity-ui.ts` (pure, `.ts`); lift `HeatStrip` (`:232-259`) into `HeatStrip.tsx` with an added `compact?: boolean` prop (compact swaps the cell height class `h-6`→`h-3` and can drop labels — Tailwind classes only, no inline width). Import both back into ActorProfile's `ActivityPanel`.
**Tests:** existing `ActorProfile.test.tsx` (15 tests) still green after the lift; a `<HeatStrip compact daily=… />` renders the strip; keep the `activity.daily.length > 0` guard at every call site (`HeatStrip` dereferences `daily[0]`).

### Task 3 — `useProfileNav` hook + pure helpers (SSR-safe)
**Files:** Create `web/src/components/views/useProfileNav.ts`; Test `__tests__/useProfileNav.test.ts`.
```ts
export function navSections(flags: {
  hasActivity: boolean; hasVictims: boolean; hasFingerprint: boolean
  hasHuntpack: boolean; hasReporting: boolean; hasRelated: boolean
}): { id: string; label: string }[]      // always leads with {id:'overview',label:'Overview'}
export function targetIdFromHash(hash: string): string | null   // '#huntpack' -> 'huntpack'; ''/'#' -> null
export function useProfileNav(sections: { id: string; label: string }[]): { activeId: string }
```
**SSR-safe (critical):** `ActorProfile.test.tsx` renders the whole component via `renderToStaticMarkup`, so the hook MUST NOT touch `window`/`document`/`IntersectionObserver` during render or in a `useState` initializer. Initialize `activeId` to `''` (or `sections[0]?.id`), never from `window.location`. ALL DOM wiring lives in `useEffect` (does not run in node): (1) mount + `hashchange` → `targetIdFromHash` → set the `<details>.open = true` + `scrollIntoView`; (2) `beforeprint` opens every `[data-collapsible]` (record prior-closed) + `afterprint` restores; (3) `IntersectionObserver` over section ids → `setActiveId`. Cleanup removes listeners + disconnects.
**Tests (pure helpers, node):** `navSections` includes/excludes per flags, overview always first; `targetIdFromHash` parses `#id`, null on `''`/`'#'`.

### Task 4 — `ProfileNav` component
**Files:** Create `web/src/components/views/ProfileNav.tsx`; Test `__tests__/ProfileNav.test.tsx`.
**Consumes:** `{ sections: {id,label}[]; activeId: string }`. Sticky horizontal sub-bar `sticky top-14 z-30 h-11` of anchor links `href={'#'+id}`, `aria-current="true"` on `activeId`, brand tokens (mono/micro/uppercase-label, border-line, accent active). Mobile: same anchors inside a `<details>` "Jump to ▾".
**Tests:** one `<a href="#id">` per section; `aria-current` on active; absent sections omitted.

### Task 5 — `SynthesisBand` component (N4 lead)
**Files:** Create `web/src/components/views/SynthesisBand.tsx`; Test `__tests__/SynthesisBand.test.tsx`.
**Consumes** (all in scope in the ActorProfile body — verified): `{ fingerprint: MitreFingerprint|null; prevalence?: Map<string,number>; huntPack?: HuntPack; activity: ProfileActivity|null; intel: RansomIntel|null; techniqueNames?: Record<string,string> }`.
Four cells, each honest-empty; the band returns `null` when all four are empty:
- **Distinctive TTPs · N** — `distinctiveSplit(fingerprint.techniques, prevalence).distinctive`, top ~5 as `TechniqueChip … distinctive` (the extracted component) + stated denominator; anchor `#fingerprint`. Absent when no prevalence or empty split.
- **Top hunts · N** — count = `huntPack.totalMatched` (`huntpack.ts:129`, pre-50-cap true total); top 2–3 titles via `huntPack.sections.flatMap(s => s.rows).map(r => r.rule.title)` (kill-chain order preserved); anchor `#huntpack`. **Absent when `!huntPack || huntPack.totalMatched === 0`** (a floor-only pack is defined but empty).
- **Activity spark** — `<HeatStrip compact daily={activity.daily} />` (extracted) + last-claim/peak cadence; anchor `#activity`. **Absent when `!activity || activity.daily.length === 0`** (daily can be [] even when activity is non-null).
- **Flagship access** — 1-line `intel` initial-access CVE/KEV chips; anchor `#overview`. Absent when unseeded.
**Tests:** fingerprint+prevalence with ≥1 distinctive → renders chips + "Distinctive"; huntPack `totalMatched>0` → renders the count; a floor-only pack (`totalMatched:0`) → no hunts cell; a bare actor (none of the four) → returns null (no empty band, no zero cells).

### Task 6 — Restructure `ActorProfile.tsx`
**Files:** Modify `ActorProfile.tsx`; extend `__tests__/ActorProfile.test.tsx`.
- Compute section-existence flags; `const sections = navSections(flags)`; `const { activeId } = useProfileNav(sections)`; render `<ProfileNav sections activeId />` under the header, above the grid.
- **Decision layer (open):** `IdentityHeader` (wrap the identity+synthesis region so its anchor id is `overview`) → `<SynthesisBand …/>` → Initial access & detection (`IntelPanel`, KEEP always-open BoardPanel) → Leak-site activity (`ActivityPanel`, id `activity`, open).
- **Reference depth — pass `collapsible defaultOpen={false} id=…` to the EXISTING BoardPanels:** Claimed victims (`victims`, count = N listed) · ATT&CK fingerprint (`fingerprint`, count = techniques) · Hunt pack (`huntpack`, count = `huntPack.totalMatched`) · Reporting (`reporting`, count = N). Their bodies are unchanged — only the wrapping BoardPanel gains the collapsible props.
- Give the right-rail container the `related` anchor id; bump its sticky to `lg:top-[6.5rem]`.
- **Leave `MitreFingerprintPanel` UNTOUCHED** — the standalone "Distinctive techniques" block is the no-catalog fallback (`:798-822`), never co-renders with the matrix, and `split`/`distinctiveSet`/`useSplit` are all still needed (removing anything → `noUnusedLocals` build error + breaks the degraded path). SynthesisBand ADDS the distinctive surfacing; nothing is removed.
- Batch-1 Related-entities dedup gating stays as-is.
**Tests (renderToStaticMarkup):** decision-layer sections have no wrapping `<details>` (identity/synthesis/intel/activity open); each reference section renders `<details … id=…>` collapsed (no `open`); nav renders anchors for present sections; collapsed reference content IS in the static markup (SEO); a claiming ransomware profile shows the synthesis spark; a bare MITRE actor shows no synthesis band; the 15 existing tests still pass.

### Task 7 — Design pass, 3-lens review, deploy, dogfood
Visual-quality gate ([[feedback_design_pass_and_review]], [[feedback_visual_ai_slop_pattern]]): UI design pass + reference libraries over `SynthesisBand`/`ProfileNav`/the summary+chevron affordance (brand system held; no serif/cream). 3-lens (SOC / data / UX) review. Full gate: vitest + lint + build + pytest. Deploy; live-dogfood: one-screen synthesis; scrollspy + mobile "Jump to ▾"; `…#huntpack` deep-link lands+opens; print opens all; distinctive lead; `view-source` shows collapsed content (SEO).

## Sequencing
1 (BoardPanel) → 2 (extractions) → 3 (hook) → 4 (nav) → 5 (synthesis, needs 2's chip+strip) → 6 (integrate, needs 1/3/4/5) → 7 (ship gate).

## Self-review
No placeholders. Types from `types.ts` (HuntPack/MitreFingerprint/ProfileActivity/RansomIntel), `distinctiveSplit` from `derived.ts`. `HuntPack.totalMatched`/`sections[].rows[].rule.title` confirmed. Section-id + offset contracts shared across 1/3/4/6. Every task testable. No removals in MitreFingerprintPanel (build-safe). No inline styles. SSR-safe hook.
