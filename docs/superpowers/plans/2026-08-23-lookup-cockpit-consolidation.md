# Lookup ↔ Cockpit Consolidation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the `/` Overview cockpit the single lookup surface, retire the redundant `/lookup` route behind a thin redirect stub, fold the examples gallery into the cockpit idle state, and delete the `/lookup`-only composition (`Lookup.tsx`, `AnalystVerdict.tsx`).

**Architecture:** A pure `parseQ` is extracted from `readLookupQuery` so it is unit-testable in the repo's node-env vitest; the cockpit (`Overview.tsx`) then seeds its omnibox from `window.location.hash` and syncs on `hashchange`/`popstate`, honoring `#q=` deep links exactly as a committed submit. `/lookup` becomes a `useLayoutEffect` redirect stub (`replaceState('/'+hash)` + synthetic `popstate`) that hands off to the cockpit; every `/lookup` referrer is repointed to `/#q=…` or removed, and the retired composition is deleted only after its replacement (`CockpitExamples`) exists and all referrers are repointed, so each task's build stays green.

**Tech Stack:** Vite 8 + React 19 + TypeScript 6 + Tailwind v4 (`web/`); shared verdict-card library (`shared/`); Vitest 3 (node environment, `.ts` only — no jsdom/RTL); ESLint 9 (typescript-eslint). Build gate: `tsc -b && vite build`.

**Spec:** `docs/superpowers/specs/2026-08-23-lookup-cockpit-consolidation-design.md`

## Global Constraints

- **Committed-value discipline:** `submitted` stays the committed / deep-link value; never feed a live-typed value into `useLookup` (no debounce exists — `useCockpitInput.ts:11-12`). The `#q=` seed is a committed value by definition.
- **Data boundary:** a command-shaped `#q=` must never reach `/api/enrich`; the existing `useCockpitInput`/`resolveKind` monotonic command lock enforces this and no path added here bypasses it.
- **OUT of scope — do not touch:** the extension tree, `useLookup.ts`/`LookupStates.tsx`/`useCockpitInput.ts`/`useEffectiveTheme.ts`/`shared/verdict/client.ts` resolution logic, `/api/enrich`, verdict doctrine/banding/wording, reserved colours, and analyzer logic (only a comment touch in `PowerShellAnalyzer.tsx`).
- **`lookupModel.ts` SURVIVES:** despite the name it hosts `cveToVerdict` (imported by `useLookup.ts`) + `readLookupQuery`/`parseQ` (imported by `PowerShellAnalyzer.tsx` + the cockpit). It is not `/lookup`; it is not deleted.
- **NO AI attribution** on any commit — this is a `github.com/SaltyCarl/*` repo. Plain conventional-commit messages only; no `Co-Authored-By`, no `Claude` references, no session trailer.
- **Static gate scope:** the "no `/lookup`" assertion is scoped to `/lookup` **navigation targets** only (`href={\`/lookup…`, `navigate('/lookup…`, a route `path` other than the stub) — NOT the literal string. Kept shared files (`components/lookup/*`, `client.ts`, `useLookup.ts`, redirect-stub comments) keep their `/lookup` comments and import paths untouched.

**Note:** pytest is irrelevant here — this is a frontend-only change. `web/package.json` has no `test` script, so the pure-logic gate is invoked directly as `cd web && npx vitest run`.

---

## File Structure

Owned files (spec §0.4). Everything else is out of scope.

**Delete:**
- `web/src/routes/Lookup.tsx` — the redundant three-register route (`CardTriptych` + `ExamplesGallery`); replaced by the cockpit + `CockpitExamples` + `LookupRedirect`.
- `shared/verdict-cards/AnalystVerdict.tsx` — a strict subset of `EscalationCard`; its only importer is `Lookup.tsx`.

**Create:**
- `web/src/routes/lookupModel.test.ts` — the one new pure unit test (`parseQ`).
- `web/src/routes/LookupRedirect.tsx` — `/lookup → /#q=<same hash>` redirect stub.
- `web/src/components/cockpit/CockpitExamples.tsx` — collapsed `<details>` idle gallery, one `EscalationCard` per stub family.

**Modify:**
- `web/src/routes/lookupModel.ts` — extract pure `parseQ`; `readLookupQuery` = `parseQ(window.location.hash)`; update header comment.
- `web/src/routes/Overview.tsx` — seed from + sync to `#q=`; drop `openFullView` + the `onFullView` prop pass + now-unused imports; render `CockpitExamples` on idle.
- `web/src/App.tsx` — swap `Lookup` import → `LookupRedirect`; route row `el` + `nav:false`; update router doc comment.
- `web/src/components/cockpit/ResultRegion.tsx` — remove the "Full analyst view →" link, the `onFullView` prop, and now-unused imports/const.
- `web/src/routes/Admin.tsx` — "Check reputation →" href `/lookup#q=` → `/#q=`.
- `web/src/components/palette/commands.ts` — remove the `view:lookup` row (fold its keywords into `view:overview`); repoint `submitLookup`'s indicator `navigate` → `/#q=…`; update its stale jsdoc.
- `web/src/routes/PowerShellAnalyzer.tsx` — correct the stale `/lookup`/`Lookup.tsx` code comment (no code change).
- `shared/verdict-cards/index.ts` — drop the `AnalystVerdict` export line.

**Keep untouched (load-bearing shared code):** `web/src/components/lookup/useLookup.ts`, `LookupStates.tsx`, `web/src/components/cockpit/useCockpitInput.ts`, `shared/verdict-cards/useEffectiveTheme.ts`, `shared/verdict/client.ts`, `shared/verdict-cards/CardActions.tsx` (`CardCanvasPreview` — still used by the extension), `shared/verdict-cards/stubs.ts` (`STUBS`), the entire `extension/` tree.

---

## Task ordering rationale (build stays green at every step)

1. `parseQ` extract (pure, unit-tested) — no consumer yet.
2. Cockpit reads `#q=` — additive; old referrers still point at `/lookup` (still live).
3. `LookupRedirect` + `App.tsx` swap — `/lookup` now redirects; `Lookup.tsx` becomes unimported but still compiles.
4. Repoint every referrer — `ResultRegion` prop removal + `Overview` prop-pass removal are coupled (must land together) so no half-removed prop breaks the build; eslint catches the freed imports.
5. `CockpitExamples` created + wired — the idle gallery's new home exists.
6. Delete `Lookup.tsx` — safe now: unimported (task 3), examples re-homed (task 5), referrers repointed (task 4).
7. Delete `AnalystVerdict.tsx` + its export — safe now: its sole importer (`Lookup.tsx`) is gone (task 6).
8. Static assertion + full green gate.

---

### Task 1: Extract pure `parseQ` (the one unit-testable deliverable)

**Files:**
- Modify: `web/src/routes/lookupModel.ts:18-29` (extract `parseQ`; header comment `:1-12`)
- Test: `web/src/routes/lookupModel.test.ts` (create)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `parseQ(hash: string): string` — pure; strips a leading `#`, matches `(?:^|&)q=([^&]*)`, `decodeURIComponent` + `.trim()`, falling back to the raw trimmed token on a decode throw; `''` when absent/empty.
  - `readLookupQuery(): string` — unchanged public signature, now `= parseQ(window.location.hash)`.

- [ ] **Step 1: Write the failing test**

Create `web/src/routes/lookupModel.test.ts`:

```ts
import { describe, expect, it } from 'vitest'
import { parseQ } from './lookupModel'

describe('parseQ', () => {
  it('decodes a plain indicator', () => {
    expect(parseQ('#q=1.1.1.1')).toBe('1.1.1.1')
  })
  it('decodes a percent-encoded command', () => {
    expect(parseQ('#q=powershell%20-enc%20AAA')).toBe('powershell -enc AAA')
  })
  it('returns empty for an empty q value', () => {
    expect(parseQ('#q=')).toBe('')
  })
  it('returns empty for no hash', () => {
    expect(parseQ('')).toBe('')
  })
  it('returns empty for a bare hash', () => {
    expect(parseQ('#')).toBe('')
  })
  it('returns empty when there is no q param', () => {
    expect(parseQ('#foo')).toBe('')
  })
  it('finds q after another param', () => {
    expect(parseQ('#a=1&q=8.8.8.8')).toBe('8.8.8.8')
  })
  it('falls back to the raw token on malformed encoding', () => {
    expect(parseQ('#q=%E0%A4%A')).toBe('%E0%A4%A')
  })
  it('trims surrounding whitespace', () => {
    expect(parseQ('#q=%20%208.8.8.8%20')).toBe('8.8.8.8')
  })
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd web && npx vitest run src/routes/lookupModel.test.ts`
Expected: FAIL — `parseQ` is not exported from `./lookupModel`.

- [ ] **Step 3: Extract `parseQ` (minimal implementation)**

In `web/src/routes/lookupModel.ts`, replace the existing `readLookupQuery` block (lines 18-29) with:

```ts
/** Pure parse of a location-hash string into the decoded `#q=<indicator>`
 *  value; '' when absent or malformed. Extracted from readLookupQuery so it is
 *  unit-testable in the repo's node-env vitest (no `window`). Mirror of the
 *  writer in palette/commands.ts::lookupHash. */
export function parseQ(hash: string): string {
  const h = hash.replace(/^#/, '')
  const m = h.match(/(?:^|&)q=([^&]*)/)
  if (!m) return ''
  try {
    return decodeURIComponent(m[1]).trim()
  } catch {
    return m[1].trim()
  }
}

/** Read the decoded `#q=<indicator>` from the current location hash; '' when
 *  absent. Mirror of the writer in palette/commands.ts::lookupHash. */
export function readLookupQuery(): string {
  return parseQ(window.location.hash)
}
```

Then update the header comment (lines 1-7) so the helper list names both parses — change the `readLookupQuery` bullet block to:

```ts
//   * parseQ          — pure parse of a hash string into the decoded `#q=` value
//                       (unit-tested; readLookupQuery is the window wrapper).
//   * readLookupQuery — decode the `#q=` deep link the omnibox + palette write.
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd web && npx vitest run src/routes/lookupModel.test.ts`
Expected: PASS (9 tests).

- [ ] **Step 5: Guard against regressing the existing pure tests**

Run: `cd web && npx vitest run`
Expected: PASS — the new test plus all existing pure tests (`classifyCockpitInput`, `resolveCockpitArgs`/`resolveKind`, card-model/geo/draw over `STUBS`, `adminModel`, `myReportsModel`) stay green. `readLookupQuery`'s public signature is unchanged, so `PowerShellAnalyzer.tsx:3` compiles verbatim.

- [ ] **Step 6: Commit**

```bash
git add web/src/routes/lookupModel.ts web/src/routes/lookupModel.test.ts
git commit -m "refactor(lookup): extract pure parseQ from readLookupQuery + unit test"
```

---

### Task 2: Cockpit `#q=` deep-link support (`Overview.tsx`)

**Files:**
- Modify: `web/src/routes/Overview.tsx` (imports `:1-2`; state seeds `:73-74`; add sync effect after `:112`)

**Interfaces:**
- Consumes: `readLookupQuery(): string` (Task 1).
- Produces: no new export. The cockpit now honors `#q=` on mount, `hashchange`, and `popstate`; `submitted` remains the only committed-value writer set. `submittedOverride` is reset to `null` on each hash sync (a fresh deep link auto-detects).

**Spec-ambiguity resolution:** Spec §2.2 shows `import { parseQ, readLookupQuery } from './lookupModel'`, but `parseQ` is never referenced inside `Overview.tsx` — importing it would trip the eslint no-unused gate (Task 2 is build+lint-gated). Import **only** `readLookupQuery`.

- [ ] **Step 1: Add the import**

In `web/src/routes/Overview.tsx`, add after the existing `../components/cockpit/CockpitOmnibox` import (line 13):

```ts
import { readLookupQuery } from './lookupModel'
```

- [ ] **Step 2: Seed both state values from the hash**

Replace lines 73-74:

```ts
  const [liveValue, setLiveValue] = useState('')
  const [submitted, setSubmitted] = useState('')
```

with:

```ts
  const [liveValue, setLiveValue] = useState(readLookupQuery)
  const [submitted, setSubmitted] = useState(readLookupQuery)
```

(`submittedOverride` on line 75 stays `useState<'indicator' | 'command' | null>(null)`.)

- [ ] **Step 3: Add the hashchange/popstate sync effect**

Immediately after the geoless-suspend effect (ends at line 112, `}, [resultIsGeoless])`), insert:

```ts
  // Honor `#q=` deep links the same way /lookup and /analyzer already do.
  //   hashchange: a raw address-bar hash edit or a same-page `location.hash =`
  //     resubmit (fires hashchange, not popstate).
  //   popstate:   a cross-route SPA deep link — commands.ts::navigate does
  //     pushState + a synthetic popstate for pathname targets, which does NOT
  //     emit hashchange (commands.ts:127-134). The redirect stub fires this too.
  useEffect(() => {
    const sync = () => {
      const q = readLookupQuery()
      setLiveValue(q)
      setSubmitted(q) // committed value — a deep link is an explicit navigation
      setSubmittedOverride(null) // a fresh deep link auto-detects; drop any stale ModeChip override
    }
    window.addEventListener('hashchange', sync)
    window.addEventListener('popstate', sync)
    return () => {
      window.removeEventListener('hashchange', sync)
      window.removeEventListener('popstate', sync)
    }
  }, [])
```

(`useEffect` is already imported on line 1; `setSubmittedOverride` already exists.) A plain in-cockpit Enter still renders in place **without** writing the hash — unchanged from today (spec §2.5); do not add a hash write.

- [ ] **Step 4: Build + lint (JSX gate — no vitest)**

Run: `npm --prefix web run build`
Expected: PASS (`tsc -b && vite build` green — the new import is used, `submitted`/`liveValue`/`submittedOverride` types unchanged).

Run: `cd web && npx eslint .`
Expected: PASS — no unused imports; `readLookupQuery` is referenced three times.

- [ ] **Step 5: Commit**

```bash
git add web/src/routes/Overview.tsx
git commit -m "feat(cockpit): seed + sync the omnibox from the #q= deep link"
```

---

### Task 3: `/lookup` redirect stub + route swap

**Files:**
- Create: `web/src/routes/LookupRedirect.tsx`
- Modify: `web/src/App.tsx` (import `:4`; route row `:53`; router doc comment `:19`)

**Interfaces:**
- Consumes: the cockpit's `#q=` sync (Task 2) — the stub relies on Overview re-reading the hash after the synthetic `popstate`.
- Produces: `LookupRedirect(): null` — on mount (`useLayoutEffect`, pre-paint) rewrites `/lookup#q=x` → `/#q=x` via `replaceState` (no history orphan) and dispatches a synthetic `popstate`.

- [ ] **Step 1: Create the redirect stub**

Create `web/src/routes/LookupRedirect.tsx`:

```tsx
// LookupRedirect — /lookup is retired; the cockpit (/) is the single lookup
// surface. Preserves bookmarked/shared `/lookup#q=<x>` links by rewriting to
// `/#q=<x>` (replaceState leaves no /lookup entry in history) and handing off
// to the cockpit, which reads the same `#q=` deep link (Overview.tsx sync).
import { useLayoutEffect } from 'react'

export function LookupRedirect(): null {
  // useLayoutEffect (not useEffect): the rewrite runs BEFORE paint, so a
  // cold-load `/lookup#q=x` bookmark never flashes a blank `default`-width main
  // frame before Overview (wide) mounts — the only time this component renders.
  useLayoutEffect(() => {
    const hash = window.location.hash // carries `#q=…` verbatim (or '')
    window.history.replaceState({}, '', '/' + hash)
    window.dispatchEvent(new PopStateEvent('popstate'))
  }, [])
  return null
}
```

StrictMode double-invocation is idempotent (replaceState to the same URL, popstate twice → harmless).

- [ ] **Step 2: Swap the App import**

In `web/src/App.tsx`, replace line 4:

```tsx
import { Lookup } from './routes/Lookup'
```

with:

```tsx
import { LookupRedirect } from './routes/LookupRedirect'
```

- [ ] **Step 3: Rewrite the route row + drop the nav tab**

Replace line 53:

```tsx
  { path: '/lookup', label: 'Lookup', size: 'default', el: <Lookup /> },
```

with:

```tsx
  { path: '/lookup', label: 'Lookup', size: 'default', el: <LookupRedirect />, nav: false },
```

`nav: false` drops the redundant top-nav "Lookup" tab (`App.tsx:79` filters `nav !== false`).

- [ ] **Step 4: Correct the router doc comment**

In the router doc block, replace line 19:

```
 *   /lookup   → the escalation-card system (IP / domain / URL / hash / CVE)
```

with:

```
 *   /lookup   → redirect stub → /#q=<same hash> (the cockpit is the lookup surface)
```

- [ ] **Step 5: Build + lint**

Run: `npm --prefix web run build`
Expected: PASS. `Lookup.tsx` still exists and still typechecks (it is simply no longer imported — an orphan module, not an error).

Run: `cd web && npx eslint .`
Expected: PASS — `Lookup` import removed, `LookupRedirect` used.

- [ ] **Step 6: Commit**

```bash
git add web/src/routes/LookupRedirect.tsx web/src/App.tsx
git commit -m "feat(routing): redirect /lookup to the cockpit via a thin stub"
```

---

### Task 4: Repoint every `/lookup` referrer

Removes the "Full analyst view →" link (spec §4 #2, §6.2), its dead `Overview` handler (§4 #3), and repoints the `Admin`, palette, and analyzer-comment referrers (§4 #4-7). The `ResultRegion` prop removal and the `Overview` prop-pass removal are coupled and MUST land together, so this is one task; eslint is the load-bearing gate for the freed imports.

**Files:**
- Modify: `web/src/components/cockpit/ResultRegion.tsx` (imports `:1,:3`; const `:10-11`; prop `:47,:52`; branch `:56-84`)
- Modify: `web/src/routes/Overview.tsx` (react type import `:2`; `submitLookup` import `:10`; `openFullView` `:134-140`; `ResultRegion` call `:214-219`)
- Modify: `web/src/routes/Admin.tsx:107`
- Modify: `web/src/components/palette/commands.ts` (`view:overview` keywords `:24`; remove `view:lookup` `:26-33`; jsdoc `:102-110`; `navigate` `:119`)
- Modify: `web/src/routes/PowerShellAnalyzer.tsx:6-9` (comment only)

**Interfaces:**
- Consumes: the redirect stub + cockpit sync (Tasks 2-3).
- Produces: `ResultRegion` prop is now `{ cockpit, theme, onCompare }` — `onFullView` REMOVED. `submitLookup(query: string): void` unchanged in signature; its indicator branch now navigates to `/#q=…`.

- [ ] **Step 1: `ResultRegion.tsx` — remove the link, prop, and freed imports**

Delete line 1 entirely: `import type { MouseEvent } from 'react'`.
Delete line 3 entirely: `import { lookupHash } from '../palette/commands'`.
Delete the `FULL_VIEW_CLS` const (lines 10-11).
In the jsdoc, drop the trailing `plus the "Full analyst view ->" deep link.` clause (lines 29-30) so it reads `... unchanged from the old LandingResult.`.
Replace the prop signature (lines 44-54):

```tsx
export function ResultRegion({
  cockpit,
  theme,
  onFullView,
  onCompare,
}: {
  cockpit: CockpitResult
  theme: EffectiveTheme
  onFullView: (e: MouseEvent<HTMLAnchorElement>, q: string) => void
  onCompare: (c: CompareResult | null) => void
}) {
```

with:

```tsx
export function ResultRegion({
  cockpit,
  theme,
  onCompare,
}: {
  cockpit: CockpitResult
  theme: EffectiveTheme
  onCompare: (c: CompareResult | null) => void
}) {
```

Replace the indicator branch (lines 55-86) — dropping the `indicator` const and the `<a>` block:

```tsx
  if (cockpit.kind === 'indicator') {
    const { state } = cockpit
    if (state.kind === 'idle') return null
    return (
      <div className="flex w-full max-w-md flex-col gap-3">
        {state.kind === 'ok' ? (
          <EscalationCard
            data={state.data}
            theme={theme}
            onCompare={onCompare}
            reportSlot={
              isEnrichable(state.data.type) ? (
                <ReportButton iocType={state.data.type} iocValue={state.data.indicator} />
              ) : undefined
            }
          />
        ) : (
          <LookupStatus state={state} />
        )}
      </div>
    )
  }
```

- [ ] **Step 2: `Overview.tsx` — remove `openFullView` + the prop pass + freed imports**

Change line 2 from:

```ts
import type { MouseEvent, ReactNode } from 'react'
```

to:

```ts
import type { ReactNode } from 'react'
```

Delete line 10 entirely: `import { submitLookup } from '../components/palette/commands'`.
Delete `openFullView` and its comment (lines 134-140):

```ts
  // The full analyst console lives at /lookup. Left-click SPA-navigates there;
  // modified clicks keep the real href so it right-clicks / opens in a new tab.
  const openFullView = (e: MouseEvent<HTMLAnchorElement>, q: string) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return
    e.preventDefault()
    submitLookup(q)
  }
```

Change the `ResultRegion` call (lines 214-219) from:

```tsx
              <ResultRegion
                cockpit={cockpit}
                theme={theme}
                onFullView={openFullView}
                onCompare={onCompareArc}
              />
```

to:

```tsx
              <ResultRegion
                cockpit={cockpit}
                theme={theme}
                onCompare={onCompareArc}
              />
```

- [ ] **Step 3: `Admin.tsx` — repoint "Check reputation →"**

Change line 107 from:

```tsx
                      href={`/lookup#q=${encodeURIComponent(r.ioc_value)}`}
```

to:

```tsx
                      href={`/#q=${encodeURIComponent(r.ioc_value)}`}
```

- [ ] **Step 4: `commands.ts` — remove `view:lookup`, fold keywords, repoint `submitLookup`**

Fold the `view:lookup` keywords into `view:overview` — change line 24 from:

```ts
    keywords: ['home', 'start', 'landing', 'globe', 'threat surface'],
```

to:

```ts
    keywords: ['home', 'start', 'landing', 'globe', 'threat surface', 'lookup', 'verdict', 'escalation', 'ip', 'domain', 'url', 'hash', 'cve'],
```

Delete the entire `view:lookup` object (lines 26-33):

```ts
  {
    id: 'view:lookup',
    kind: 'view',
    label: 'Escalation cards',
    hint: '/lookup',
    href: '/lookup',
    keywords: ['lookup', 'verdict', 'escalation', 'ip', 'domain', 'url', 'hash', 'cve'],
  },
```

Replace the `submitLookup` jsdoc (lines 102-110) with:

```ts
/**
 * Submit an indicator lookup. Records it as recent, then routes to the cockpit
 * (`/`) with the indicator on the `#q=` deep link — from ANY route; the cockpit
 * seeds its omnibox from the hash (Overview.tsx sync). A command-shaped value
 * NEVER takes the enrich path: it routes to the standalone `/analyzer` instead,
 * with the command prefilled via the same `#q=` deep link so the paste is not
 * lost.
 */
```

Change the indicator-branch navigate (line 119) from:

```ts
  navigate(`/lookup${lookupHash(q)}`)
```

to:

```ts
  navigate(`/${lookupHash(q)}`)
```

(The command branch `navigate(\`/analyzer${lookupHash(q)}\`)` on line 115 stays.)

- [ ] **Step 5: `PowerShellAnalyzer.tsx` — correct the stale comment (no code change)**

Replace the comment (lines 6-9):

```ts
  // Lazy-init from the `#q=` deep link so a command routed here from the
  // palette/`/lookup` (commands.ts::submitLookup, Lookup.tsx) arrives
  // prefilled and auto-analyzes for free — `input` already drives
  // `usePsAnalysis` reactively, so no separate trigger is needed.
```

with:

```ts
  // Lazy-init from the `#q=` deep link so a command routed here from the
  // palette or the cockpit (commands.ts::submitLookup) arrives prefilled and
  // auto-analyzes for free — `input` already drives `usePsAnalysis`
  // reactively, so no separate trigger is needed.
```

- [ ] **Step 6: Build + lint**

Run: `npm --prefix web run build`
Expected: PASS. `ResultRegion`'s prop object no longer requires `onFullView`; `Overview` no longer passes it.

Run: `cd web && npx eslint .`
Expected: PASS — this is the gate that proves the freed imports (`MouseEvent` in both files, `lookupHash` in `ResultRegion`, `submitLookup` in `Overview`) and the deleted `openFullView`/`FULL_VIEW_CLS` leave nothing unused.

- [ ] **Step 7: Commit**

```bash
git add web/src/components/cockpit/ResultRegion.tsx web/src/routes/Overview.tsx web/src/routes/Admin.tsx web/src/components/palette/commands.ts web/src/routes/PowerShellAnalyzer.tsx
git commit -m "refactor(lookup): repoint every /lookup referrer to the cockpit /#q="
```

---

### Task 5: `CockpitExamples` — collapsed idle gallery

**Files:**
- Create: `web/src/components/cockpit/CockpitExamples.tsx`
- Modify: `web/src/routes/Overview.tsx` (import; render after the hero `</section>` `:238`)

**Interfaces:**
- Consumes: `STUBS`, `EscalationCard`, `EffectiveTheme` from `@socdesk/shared/verdict-cards`; `MicroLabel` from `../ui`; `cx` from `@socdesk/shared/lib/cx`. (`Stub` shape: `{ id: string; label: string; hint: string; data: VerdictData }`.)
- Produces: `CockpitExamples(props: { theme?: EffectiveTheme }): JSX.Element` — a native `<details>` "See a sample card" disclosure, collapsed by default; when opened, a `role="tablist"` of one tab per `STUBS` family and one `<EscalationCard data={stub.data} theme={theme} />` for the selected family. No `onCompare`, no `reportSlot` → no idle network call (`CompareIp`'s fetch is gated behind a user open).

- [ ] **Step 1: Create the component**

Create `web/src/components/cockpit/CockpitExamples.tsx`:

```tsx
// CockpitExamples.tsx — the idle cockpit's reference gallery, folded in from the
// retired /lookup ExamplesGallery. Collapsed behind a native <details>
// disclosure ("See a sample card") so it never out-ranks the live board; opened,
// it shows one family tab per indicator kind and renders that stub as a single
// EscalationCard (NOT the retired triptych — no copy-card PNG, no analyst
// console). Static: CompareIp's fetch is gated behind a user open, so a stub
// card issues no network call.
import { useState } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import { EscalationCard, STUBS, type EffectiveTheme } from '@socdesk/shared/verdict-cards'
import { MicroLabel } from '../ui'

export function CockpitExamples({ theme }: { theme?: EffectiveTheme }) {
  const [sel, setSel] = useState(STUBS[0].id)
  const stub = STUBS.find((s) => s.id === sel) ?? STUBS[0]

  return (
    <details className="mx-auto w-full max-w-md">
      <summary className="cursor-pointer select-none font-mono text-xs text-muted">
        See a sample card
      </summary>
      <div className="mt-4 flex flex-col gap-4">
        <MicroLabel tone="faint" tick>
          One sample card per indicator family
        </MicroLabel>
        <div className="flex flex-wrap gap-2" role="tablist" aria-label="Example indicator type">
          {STUBS.map((s) => {
            const active = s.id === sel
            return (
              <button
                key={s.id}
                type="button"
                role="tab"
                aria-selected={active}
                onClick={() => setSel(s.id)}
                className={cx(
                  'inline-flex items-baseline gap-2 rounded-md border px-3 py-1.5 font-mono text-xs transition-colors duration-150 ease-brand',
                  'outline-offset-2 focus-visible:outline-2 focus-visible:outline-accent',
                  active
                    ? 'border-[var(--edge-accent)] bg-[var(--tint-accent)] text-accent'
                    : 'border-line bg-panel text-muted hover:border-line-bright hover:text-paper',
                )}
              >
                <span className="font-semibold">{s.label}</span>
                <span className="text-micro text-faint">{s.hint}</span>
              </button>
            )
          })}
        </div>
        <EscalationCard data={stub.data} theme={theme} />
      </div>
    </details>
  )
}
```

(The tablist markup is copied verbatim from the retired `Lookup.tsx:113-136`. `EscalationCard`'s `theme?` prop accepts an `EffectiveTheme` — the same value `ResultRegion` already forwards.)

- [ ] **Step 2: Wire it into the cockpit idle state**

In `web/src/routes/Overview.tsx`, add the import after the `readLookupQuery` import from Task 2:

```ts
import { CockpitExamples } from '../components/cockpit/CockpitExamples'
```

Then insert it between the hero `</section>` (line 238) and `<SituationalBoard />` (line 240):

```tsx
      </section>
      {!isResult && <CockpitExamples theme={theme} />}
      <SituationalBoard />
```

(`isResult` line 78 and `theme` line 76 are already in scope; the disclosure hides entirely the moment any result shows.)

- [ ] **Step 3: Build + lint**

Run: `npm --prefix web run build`
Expected: PASS.

Run: `cd web && npx eslint .`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add web/src/components/cockpit/CockpitExamples.tsx web/src/routes/Overview.tsx
git commit -m "feat(cockpit): fold the examples gallery into a collapsed idle disclosure"
```

---

### Task 6: Delete `Lookup.tsx`

**Files:**
- Delete: `web/src/routes/Lookup.tsx`

**Interfaces:**
- Consumes: nothing — `Lookup` is unimported (App swapped in Task 3), its examples re-homed (Task 5), its referrers repointed (Task 4).
- Produces: nothing. `AnalystVerdict` now has a single remaining reference (its own export in `index.ts:11`, removed next task); `CardCanvasPreview`'s only remaining consumer is the extension.

- [ ] **Step 1: Remove the file**

Run:

```bash
git rm web/src/routes/Lookup.tsx
```

- [ ] **Step 2: Build + lint**

Run: `npm --prefix web run build`
Expected: PASS. Nothing imports `Lookup`; every shared symbol it used (`useLookup`, `LookupStatus`, `readLookupQuery`, `ReportButton`, `isEnrichable`, `refang`, `classifyCockpitInput`, `lookupHash`, `navigate`, `CardCanvasPreview`, `STUBS`, `EscalationCard`) is still imported by other kept surfaces — no orphaned export breaks the build.

Run: `cd web && npx eslint .`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "refactor(lookup): delete the retired /lookup route composition"
```

---

### Task 7: Delete `AnalystVerdict` and its export

**Files:**
- Delete: `shared/verdict-cards/AnalystVerdict.tsx`
- Modify: `shared/verdict-cards/index.ts:11`

**Interfaces:**
- Consumes: nothing — `AnalystVerdict`'s sole importer (`Lookup.tsx`) is gone (Task 6). Verified: the extension's `Popup.tsx` imports `EscalationCard` + `CardCanvasPreview`, never `AnalystVerdict`.
- Produces: nothing. The web bundle no longer ships `AnalystVerdict`.

- [ ] **Step 1: Remove the component file**

Run:

```bash
git rm shared/verdict-cards/AnalystVerdict.tsx
```

- [ ] **Step 2: Remove the barrel export**

In `shared/verdict-cards/index.ts`, delete line 11:

```ts
export { AnalystVerdict } from './AnalystVerdict'
```

(`CardActions, CardCanvasPreview` on line 12 STAY — the extension still needs `CardCanvasPreview`.)

- [ ] **Step 3: Build + lint**

Run: `npm --prefix web run build`
Expected: PASS — no importer of `AnalystVerdict` remains, so removing the export breaks nothing.

Run: `cd web && npx eslint .`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor(cards): delete AnalystVerdict (subset of EscalationCard, now unused)"
```

---

### Task 8: Static assertion + full green gate

**Files:** none (verification only).

**Interfaces:**
- Consumes: the entire change set (Tasks 1-7).
- Produces: proof that no `/lookup` navigation target and no `AnalystVerdict` reference remain, and that the full build + unit + lint gates are green.

- [ ] **Step 1: Assert no `/lookup` navigation target remains**

Run (from the VIGIL repo root):

```bash
grep -rn "/lookup" web/src shared | grep -E "href|navigate\(" | grep -v "LookupRedirect"
```

Expected: **no output** (exit 1). The two-stage filter isolates navigation targets (`href=`/`navigate(` lines) from the `/lookup` string; `components/lookup/*` import paths and redirect-stub/kept comments contain `/lookup` but not `href`/`navigate(`, and `App.tsx`'s surviving `path: '/lookup'` stub row contains neither — all correctly excluded.

- [ ] **Step 2: Assert no `AnalystVerdict` reference remains in source**

Run:

```bash
grep -rn "AnalystVerdict" web/src shared
```

Expected: **no output** (exit 1) — the file is deleted and the export removed. (Historical mentions in `docs/BUILD-JOURNAL.md` and the extension's `main.tsx:5` comment are out of scope per spec §6.1 and are not searched here.)

- [ ] **Step 3: Full unit gate**

Run: `cd web && npx vitest run`
Expected: PASS — the new `parseQ` test plus every pre-existing pure test.

- [ ] **Step 4: Full build gate**

Run: `npm --prefix web run build`
Expected: PASS (`tsc -b && vite build`).

- [ ] **Step 5: Full lint gate**

Run: `cd web && npx eslint .`
Expected: PASS (0 problems).

- [ ] **Step 6: Manual dogfood (prod build — repo live-checkpoint convention; non-blocking)**

Run `npm --prefix web run build` then `npm --prefix web run preview`, and confirm:
1. `/#q=8.8.8.8` (fresh load) → escalation card docks in the cockpit, globe lands.
2. `/lookup#q=8.8.8.8` (bookmark) → URL becomes `/#q=8.8.8.8`, same card, no `/lookup` flash, no 404.
3. `/#q=` + a pasted `powershell -enc …` (or palette-submit a command) → analyzer renders inline; Network tab shows **zero** `/api/enrich`.
4. Palette "Escalation cards"/"lookup" search still finds the cockpit (folded keywords); selecting an indicator lands on `/#q=…`.
5. Admin "Check reputation →" → cockpit card.
6. Idle cockpit shows `CockpitExamples` collapsed as "See a sample card"; opening it reveals the family tabs, picking each swaps the card; the whole disclosure disappears on first lookup.
7. Top nav shows no "Lookup" tab.

- [ ] **Step 7: Commit (if any doc/journal note is added; otherwise nothing to commit)**

```bash
git status   # verification-only — expect a clean tree unless you added a journal note
```

---

## Self-Review

### 1. Spec coverage

| Spec section / requirement | Task |
|---|---|
| §0.2.1 / §2 — cockpit `#q=` seed + hashchange/popstate sync | Task 2 |
| §0.2.2 / §3 — `/lookup` retirement via redirect stub (`useLayoutEffect`, replaceState + popstate) | Task 3 |
| §3.2 — `App.tsx` route row `el` swap + `nav:false` + import + doc comment | Task 3 |
| §0.2.3 / §4 #2-3 — `ResultRegion` "Full analyst view →" removal + `Overview` `openFullView`/import cleanup | Task 4 |
| §4 #4 — `Admin.tsx` `/lookup#q=` → `/#q=` | Task 4 |
| §4 #5 — remove `view:lookup`, fold keywords into `view:overview` | Task 4 |
| §4 #6 — repoint `submitLookup` navigate + update stale jsdoc | Task 4 |
| §4 #7 — `PowerShellAnalyzer.tsx` stale comment fix | Task 4 |
| §0.2.4 / §5 — examples gallery folded into collapsed `<details>` idle disclosure, one `EscalationCard` per family | Task 5 |
| §5.2 — placement after hero `</section>`, gated on `!isResult` | Task 5 |
| §0.2.5 / §6.4 — delete `Lookup.tsx` (`CardTriptych`, `ExamplesGallery`) | Task 6 |
| §6.1 — delete `AnalystVerdict.tsx` + `index.ts` export | Task 7 |
| §6.3 — `CardCanvasPreview` kept exported, web use gone with `Lookup.tsx` | Tasks 6-7 (export retained) |
| §9 — extract pure `parseQ`; `readLookupQuery = parseQ(window.location.hash)` | Task 1 |
| §10 — `parseQ` unit test; build gate for JSX; static `/lookup` assertion; existing pure tests stay green | Tasks 1, 4, 5, 8 |
| §0.6 / §11 acceptance — command `#q=` → zero `/api/enrich` (data boundary held by existing lock, untouched) | Verified by design — no code touches `useCockpitInput`; Task 8 dogfood step 3 |
| §12 — no verdict hue / doctrine / wording / reserved-colour change | Held — no task touches doctrine, renderers, or colours |

No gaps. The data-boundary guarantee (§0.6, §8) requires *no* code because it is enforced by the untouched `useCockpitInput`/`resolveKind` lock; the plan adds no bypassing path and verifies it in Task 8's dogfood.

### 2. Placeholder scan

Searched for TBD/TODO/"implement later"/"add error handling"/"similar to Task N"/"write tests for the above" — none present. Every code step contains the actual file content; every deletion shows the exact `git rm` and the precise import/export lines removed elsewhere.

### 3. Type consistency

- `parseQ(hash: string): string` and `readLookupQuery(): string` — defined identically in Task 1, consumed by name in Task 2 (`readLookupQuery` only; `parseQ` deliberately not imported into `Overview.tsx` to satisfy the eslint gate — the resolved spec ambiguity).
- `LookupRedirect(): null` — Task 3 definition matches the `App.tsx` usage `<LookupRedirect />`.
- `ResultRegion` prop object `{ cockpit, theme, onCompare }` — Task 4 removes `onFullView` from both the type and the `Overview` call site in the same task; no window where one side has the prop and the other doesn't.
- `CockpitExamples(props: { theme?: EffectiveTheme })` — Task 5 definition matches the `Overview` call `<CockpitExamples theme={theme} />`; `theme` is `EffectiveTheme` (from `useEffectiveTheme`), which `EscalationCard`'s `theme?` prop accepts (as it already does via `ResultRegion`).
- `submitLookup(query: string): void` — signature unchanged; only its internal `navigate` target and jsdoc change (Task 4). Its command branch is untouched.
- `Stub` fields used in Task 5 (`s.id`, `s.label`, `s.hint`, `stub.data`) match `shared/verdict-cards/stubs.ts` (`export type Stub = { id, label, hint, data }`).

No inconsistencies found.
