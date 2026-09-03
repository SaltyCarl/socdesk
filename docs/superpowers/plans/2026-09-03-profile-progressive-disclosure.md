# Profile Progressive Disclosure (N1) + Distinctive-TTP Lead (N4) — Implementation Plan

**Spec:** `docs/superpowers/specs/2026-09-03-profile-progressive-disclosure-design.md` (owner-approved 2026-09-03; 3 decisions resolved: intel panel always-open · synthesis band = 4 cells only · full matrix collapsed by default).

**Goal:** Restructure `ActorProfile.tsx` into an always-on decision layer over `<details>`-collapsed reference sections, oriented by a sticky scrollspy jump-nav, and hoist the existing distinctive-TTP artifact into a synthesis lead band. No pipeline/schema/data change.

## Global Constraints
- Free-tier, no new deps (native `<details>`, `IntersectionObserver`).
- Honesty: reorder/collapse only; every synthesis cell honest-empty; distinctive = real `distinctiveSplit` with stated denominator.
- SEO/print/deep-link: collapsed `<details>` content stays in DOM (never conditionally unmounted); print opens all; `#<id>` lands+opens.
- Brand system held; visual treatment via the design pass + 3-lens review at build.
- react-refresh: pure helpers/hooks in `.ts`; component files export only components.
- Vitest env = node → `renderToStaticMarkup` presence tests only.

## Section id contract (used by nav, deep-links, scrollspy — all tasks share this)
`overview` (identity + synthesis + intel) · `activity` · `victims` · `fingerprint` · `huntpack` · `reporting` · `related` (right rail). A nav item + anchor appears only when its section exists.

---

### Task 1 — `CollapsibleSection` component
**Files:** Create `web/src/components/views/CollapsibleSection.tsx`; Test `__tests__/CollapsibleSection.test.tsx`.
**Interface — Produces:**
```ts
function CollapsibleSection(props: {
  id: string            // anchor id (section contract)
  eyebrow: string       // summary label, e.g. "Hunt pack"
  count?: number | string // rendered after the eyebrow, e.g. 42 -> "· 42"
  defaultOpen?: boolean // default false
  children: React.ReactNode
}): JSX.Element
```
Renders `<details id={id} data-collapsible open={defaultOpen ?? false} className="scroll-mt-24 …">` with a `<summary>` (eyebrow + count + chevron; `list-none`/marker reset; focus-visible accent ring) and a body `<div>{children}</div>`. Uncontrolled — native toggle, no JS for normal use.
**Tests:** static markup contains `<details` with the id and `<summary>`; `defaultOpen` unset ⇒ no `open` attribute (collapsed); children markup IS present in output even when collapsed (SEO guard); count renders when passed, omitted when not.

### Task 2 — `useProfileNav` hook + pure helpers
**Files:** Create `web/src/components/views/useProfileNav.ts`; Test `__tests__/useProfileNav.test.ts`.
**Interface — Produces:**
```ts
// pure, unit-testable
export function navSections(flags: {
  hasActivity: boolean; hasVictims: boolean; hasFingerprint: boolean
  hasHuntpack: boolean; hasReporting: boolean; hasRelated: boolean
}): { id: string; label: string }[]      // always leads with {id:'overview',label:'Overview'}
export function targetIdFromHash(hash: string): string | null  // '#huntpack' -> 'huntpack'
// the hook
export function useProfileNav(sections: { id: string; label: string }[]): { activeId: string }
```
Hook effect (DOM, app-bundle JS — CSP-clean): (1) on mount + `hashchange`, resolve `targetIdFromHash`, if the element is a `<details>` set `open=true`, then `scrollIntoView`; (2) `beforeprint` opens every `[data-collapsible]` (record prior closed set) and `afterprint` restores; (3) `IntersectionObserver` over the section ids → set `activeId`. Cleanup removes listeners + disconnects observer.
**Tests (pure helpers only — node env):** `navSections` includes/excludes items per flags, always overview-first; `targetIdFromHash` parses `#id`, returns null for empty/`#`.

### Task 3 — `ProfileNav` component
**Files:** Create `web/src/components/views/ProfileNav.tsx`; Test `__tests__/ProfileNav.test.tsx`.
**Interface — Consumes:** `{ sections: {id,label}[]; activeId: string }`. **Produces:** a sticky sub-bar (`lg`: could be a left rail; keep a sticky top bar for v1) of anchor links `href={'#'+id}`, marking `aria-current="true"` on `activeId`. Mobile: wrap the same anchors in a `<details>` "Jump to ▾". Brand tokens (mono/micro/uppercase-label, border-line, accent active).
**Tests:** renders an `<a href="#huntpack">` per provided section; sets `aria-current` on the active one; omits sections not passed.

### Task 4 — `SynthesisBand` component (N4 lead)
**Files:** Create `web/src/components/views/SynthesisBand.tsx`; Test `__tests__/SynthesisBand.test.tsx`.
**Interface — Consumes:** the inputs ActorProfile already holds:
```ts
function SynthesisBand(props: {
  fingerprint: MitreFingerprint | null
  prevalence?: Map<string, number>       // for distinctiveSplit
  huntPack?: HuntPack                     // count + top titles (see huntpack.ts)
  activity: ProfileActivity | null        // activity.daily spark + cadence
  intel: RansomIntel | null               // flagship initial-access CVEs/KEV tease
  techniqueNames?: Record<string,string>
}): JSX.Element | null
```
Four cells, each honest-empty independently; the whole band returns `null` when all four are empty:
- **Distinctive TTPs · N** — `distinctiveSplit(fingerprint.techniques, prevalence).distinctive`, top ~5 as tinted technique chips (reuse the existing distinctive chip used at `ActorProfile.tsx:812`/`TacticMatrix:736`) + stated denominator; anchor `#fingerprint`. Absent when split empty or no prevalence.
- **Top hunts · N** — huntPack query count + top 2–3 titles; anchor `#huntpack`. Absent when no pack.
- **Activity spark** — a compact inline 31-day strip from `activity.daily` + last-claim/peak cadence; anchor `#activity`. Absent when no activity. (Reuse/extract the heat-strip renderer from `ActivityPanel` as a small `<Sparkstrip daily=…>` — keep the full one intact.)
- **Flagship access** — 1-line `intel` initial-access CVE/KEV chips; anchor `#overview` intel panel. Absent when unseeded.
**Tests:** given a fingerprint+prevalence with ≥1 distinctive, renders the chips + "Distinctive TTPs"; given huntPack, renders the count; given a bare actor (no distinctive/hunts/activity/intel) returns null (no empty band, no zero cells).

### Task 5 — Restructure `ActorProfile.tsx`
**Files:** Modify `web/src/components/views/ActorProfile.tsx`; extend `__tests__/ActorProfile.test.tsx`.
Wire the decision layer + reference accordions + nav:
- Compute section-existence flags; `const sections = navSections(flags)`; `const { activeId } = useProfileNav(sections)`; render `<ProfileNav sections activeId />` sticky under the header.
- **Decision layer (open), in order:** `IdentityHeader` (id `overview`) → `SynthesisBand` (in the overview block) → Initial access & detection (`IntelPanel`, kept always-open, part of `overview`) → Leak-site activity (`ActivityPanel`, id `activity`, open, NOT wrapped).
- **Reference depth (wrap in `CollapsibleSection defaultOpen={false}`):** Claimed victims (`victims`) · ATT&CK fingerprint (`fingerprint`) · Hunt pack (`huntpack`) · Reporting (`reporting`). Move each existing `BoardPanel` body inside the collapsible; carry the count into the summary (victims N · techniques N · queries N · reports N).
- Give the right rail the `related` anchor id.
- **Hoist distinctive:** the standalone "Distinctive techniques · N" block in `MitreFingerprintPanel` (`:804`) is now represented by the synthesis band — remove that block (keep the in-matrix tint via `distinctiveSet`). `MitreFingerprintPanel` keeps rendering the full matrix inside the collapsed fingerprint section.
- Preserve every existing honest-empty for the always-open sections; the Batch-1 Related-entities gating stays as-is.
**Tests (renderToStaticMarkup):** decision-layer sections render open (no wrapping `<details>` on identity/synthesis/intel/activity); each reference section renders as `<details id=… >` collapsed (no `open`); nav renders anchors for present sections; collapsed reference content is present in the static markup (SEO); a claiming ransomware profile shows the synthesis spark; a bare MITRE actor shows no synthesis band.

### Task 6 — Design pass, 3-lens review, deploy, dogfood
**Not a code-shape task — the visual-quality gate** ([[feedback_design_pass_and_review]], [[feedback_visual_ai_slop_pattern]]):
- Run the UI design pass + reference libraries over `SynthesisBand`, `ProfileNav`, and the `<summary>`/chevron affordance; hold the brand system (Archivo/IBM Plex Mono/periwinkle; no serif/cream).
- 3-lens review (SOC-analyst / data-analytics / UX) on the rendered result.
- Full gate: vitest + lint + build + pytest green.
- Deploy (`gh workflow run collect-and-deploy`); live-dogfood on socdesk.io: one-screen synthesis; scrollspy + mobile "Jump to ▾"; `…#huntpack` deep-link lands+opens; print opens all; distinctive TTPs lead; `view-source` shows collapsed content (SEO).

## Sequencing
1 (CollapsibleSection) → 2 (hook) → 3 (nav) → 4 (synthesis) are independent leaf components/helpers; 5 integrates them; 6 is the visual + ship gate. Build 1–4, then 5, then 6.

## Self-review
No placeholders. Types consistent (HuntPack/MitreFingerprint/ProfileActivity/RansomIntel from `types.ts`; distinctiveSplit from `derived.ts`). Section-id contract shared across tasks 2/3/5. Every task ends testable. Spec coverage: decision layer (T4/T5), accordion (T1/T5), nav+scrollspy+deep-link+print (T2/T3), distinctive hoist (T4/T5), SEO/print guards (T1/T2 tests).
