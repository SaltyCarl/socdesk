# SOCDesk — Lookup ↔ Cockpit Consolidation: Design Spec

**Date:** 2026-08-23 · **Status:** design, owner-approved, pre-plan · **Author:** SaltyCarl · **Scope target:** `web/` (a small comment touch in `shared/verdict-cards`). Frontend consolidation only — no backend, no doctrine, no analyzer-logic changes.

---

## 0. SCOPE BOUNDARY

### 0.1 Goal
Make the **cockpit** — the `/` Overview route (`web/src/routes/Overview.tsx`), which already docks a live `EscalationCard` beside the globe (`web/src/components/cockpit/ResultRegion.tsx:60-71`) — the **single lookup surface**, and **retire the redundant `/lookup` route** (`web/src/routes/Lookup.tsx`, registered at `web/src/App.tsx:53`). `/lookup` today renders the same verdict in three redundant registers — the live `EscalationCard`, a `CardCanvasPreview` PNG of that same card, and the `AnalystVerdict` "console" (`Lookup.tsx:76-93`) — where `AnalystVerdict` is a strict SUBSET of `EscalationCard` (both render `SourceLedger` + `ContextList`; the card additionally has the seg-gauge, heroes, `CompareIp`, chips, copy actions). One surface, one card, no duplication.

### 0.2 In scope
1. **Cockpit `#q=` deep-link support** — `Overview.tsx` seeds the omnibox from `window.location.hash` on mount and reacts to `hashchange` + `popstate`, then behaves exactly as a committed submit (§2).
2. **`/lookup` retirement via a thin redirect stub** — `/lookup#q=x` keeps resolving (no 404) by rewriting to `/#q=x` and handing off to the cockpit (§3).
3. **Repointing every `/lookup` referrer** to `/#q=…` or removing it (§4).
4. **Folding the examples gallery into the cockpit idle state** — a first-time visitor still sees "what a result looks like" (§5).
5. **Deleting the `/lookup`-only composition** — `Lookup.tsx`, its `CardTriptych`, the web use of `AnalystVerdict`, the web use of `CardCanvasPreview`; and deleting `AnalystVerdict.tsx` itself (nothing else imports it — §6).

### 0.3 OUT of scope (do not touch)
- **The extension.** `extension/src/popup/Popup.tsx` renders `EscalationCard` + `CardCanvasPreview` (`Popup.tsx:36-41,324`); both STAY in `shared/`. No extension card/preview change.
- **`useLookup` / shared resolution logic.** `web/src/components/lookup/useLookup.ts`, `LookupStates.tsx`, `useCockpitInput.ts`, `useEffectiveTheme.ts`, `shared/verdict/client.ts`, `lookupHash` — all shared, all unchanged (§7).
- **`/api/enrich`, the verdict doctrine, banding, wording.** No renderer or doctrine change; this is a composition move.
- **Analyzer logic.** `/analyzer` (`web/src/routes/PowerShellAnalyzer.tsx`) and its IOC pivots stay. The analyzer's per-row "Look up →" is already an *inline* enrichment (`shared/analyzer-ui/IocTable.tsx:27-40` → `InlineLookup.tsx` → `/api/enrich` directly) — it never routed through `/lookup`, so **nothing functional changes there**; only a stale code comment (`PowerShellAnalyzer.tsx:7`) is corrected.
- **The globe, `SituationalBoard`, `ResultRegion`'s command/unclassified branches, the ModeChip, `CockpitOmnibox`.**

### 0.4 Owned files
**Delete:** `web/src/routes/Lookup.tsx`; `shared/verdict-cards/AnalystVerdict.tsx`.
**Create:** `web/src/routes/LookupRedirect.tsx`; `web/src/components/cockpit/CockpitExamples.tsx`; `web/src/routes/lookupModel.test.ts` (new pure-parse test).
**Modify:** `web/src/routes/Overview.tsx`; `web/src/App.tsx`; `web/src/components/cockpit/ResultRegion.tsx`; `web/src/routes/Admin.tsx`; `web/src/components/palette/commands.ts` (remove `view:lookup` row, repoint `submitLookup`'s `navigate`, **and update its stale jsdoc at 102-110**); `web/src/routes/lookupModel.ts` (extract a pure `parseQ`, update header comment); `shared/verdict-cards/index.ts` (drop the `AnalystVerdict` export); `web/src/routes/PowerShellAnalyzer.tsx` (stale-comment fix only).
**Keep untouched (load-bearing shared code):** `useLookup.ts`, `LookupStates.tsx`, `useCockpitInput.ts`, `useEffectiveTheme.ts`, `shared/verdict/client.ts`, `shared/verdict-cards/CardActions.tsx` (`CardCanvasPreview`), `shared/verdict-cards/stubs.ts` (`STUBS`), the whole `extension/` tree.

### 0.5 Interfaces (net-new / changed signatures)
```ts
// web/src/routes/lookupModel.ts — extract the pure parse from readLookupQuery
export function parseQ(hash: string): string            // NEW, pure, unit-tested
export function readLookupQuery(): string               // KEPT; now = parseQ(window.location.hash)

// web/src/routes/LookupRedirect.tsx — NEW
export function LookupRedirect(): null                  // /lookup → /#q=<same hash>, replaceState + popstate

// web/src/components/cockpit/CockpitExamples.tsx — NEW
export function CockpitExamples(props: { theme?: EffectiveTheme }): JSX.Element   // STUBS → one EscalationCard

// web/src/components/cockpit/ResultRegion.tsx — CHANGED (prop removed)
export function ResultRegion(props: {
  cockpit: CockpitResult
  theme: EffectiveTheme
  onCompare: (c: CompareResult | null) => void
  // onFullView REMOVED — the cockpit IS the full view
}): JSX.Element
```

### 0.6 Acceptance criteria (see §10 for the full list)
- `/#q=1.1.1.1` (fresh load) renders the escalation card in the cockpit; `/lookup#q=1.1.1.1` (bookmark) lands on the same cockpit result without a 404 and without a visible `/lookup` frame.
- A command-shaped `#q=` value renders the analyzer inline in the cockpit and issues **zero** `/api/enrich` calls (data boundary held via the existing `useCockpitInput` guard).
- No `/lookup` **navigation target** (`href={`/lookup…`}`, `navigate('/lookup…')`, or a route `path` other than the redirect stub) remains outside `LookupRedirect.tsx`. (Comments/import-paths that mention `/lookup` in kept shared files — `useLookup.ts`, `LookupStates.tsx`, `client.ts`, etc. — are NOT in scope and stay.) The top nav shows no "Lookup" tab.
- `AnalystVerdict` has no remaining importer; the web bundle no longer ships it.
- `npm --prefix web run build` is green; `npx vitest run` (from `web/`) is green including a new `parseQ` test.

### 0.7 Anti-drift guardrails
- **Committed-value discipline is inviolable.** `submitted` stays the committed (post-Enter / post-deep-link) value. Nothing added here may feed a live-typed value into `useLookup` (no debounce exists — `useCockpitInput.ts:11-12`). The `#q=` seed is a committed value by definition (an explicit navigation).
- **Data boundary held.** A command-shaped `#q=` must never reach `useLookup`/`/api/enrich`. The cockpit already guarantees this through `resolveKind`'s monotonic command lock (`useCockpitInput.ts:54-60,72`); this spec adds no path that bypasses it.
- **`lookupModel.ts` is NOT `/lookup`.** Despite the name, it hosts `cveToVerdict` (imported by the shared `useLookup.ts:30`) and `readLookupQuery` (imported by `PowerShellAnalyzer.tsx:3` and, after this change, `Overview.tsx`). It survives the route deletion.
- **No new verdict hues, no doctrine edits, no wording changes.** Reserved-colour law unchanged.
- **Attribution:** SaltyCarl, zero AI attribution anywhere (this is a `github.com/SaltyCarl/*` repo).

---

## 1. Architecture at a glance

**Before**
```
/         Overview.tsx → CockpitOmnibox + globe + ResultRegion(EscalationCard | Analyzer | hint)
                         · submitted seeded from useState('')  ← does NOT read #q=
                         · ResultRegion shows a "Full analyst view →" link to /lookup
/lookup   Lookup.tsx    → CardTriptych: EscalationCard + CardCanvasPreview + AnalystVerdict
                         · reads #q= (readLookupQuery); ExamplesGallery on idle
                         · command-shaped #q= → redirect to /analyzer
palette   view:lookup command + submitLookup() → navigate('/lookup#q=…')
Admin     "Check reputation →" → /lookup#q=…
```

**After**
```
/         Overview.tsx → (unchanged cockpit) + reads #q= on mount/hashchange/popstate
                         · ResultRegion: "Full analyst view →" link REMOVED
                         · idle: CockpitExamples (STUBS → one EscalationCard) below the hero
/lookup   LookupRedirect.tsx → replaceState('/'+hash) + popstate → cockpit reads #q=
palette   submitLookup() → navigate('/#q=…'); view:lookup command removed (keywords folded into view:overview)
Admin     "Check reputation →" → /#q=…
DELETED   Lookup.tsx, CardTriptych, AnalystVerdict.tsx, web use of CardCanvasPreview
KEPT      lookupModel.ts (cveToVerdict + readLookupQuery/parseQ), CardCanvasPreview (extension), STUBS
```

Key insight: the cockpit is strictly **more** capable than `/lookup` for deep-links. `/lookup` had to *redirect* a command-shaped `#q=` to `/analyzer` (`Lookup.tsx:162-172`) because its `useLookup` has no command guard. The cockpit's `useCockpitInput` classifies first and renders the analyzer **inline** (`ResultRegion.tsx:88-92`) with the data boundary already enforced — so consolidation removes the redirect hop, not just a route.

---

## 2. Cockpit `#q=` deep-link mechanism (`Overview.tsx`)

### 2.1 The problem
Today `Overview.tsx:73-74` seeds both `liveValue` and `submitted` from `useState('')` — the cockpit **ignores** the hash. `/lookup` is the only surface that honors `#q=` (via `readLookupQuery` at `Lookup.tsx:151-152` and its sync effect at `Lookup.tsx:174-189`). Retiring `/lookup` REQUIRES the cockpit to honor `#q=`.

### 2.2 The change (mirrors the proven `Lookup.tsx` / `PowerShellAnalyzer.tsx` pattern)
Seed from the hash and add a sync effect:
```ts
import { parseQ, readLookupQuery } from './lookupModel'          // NEW import
// ...
const [liveValue, setLiveValue] = useState(readLookupQuery)      // was useState('')
const [submitted, setSubmitted] = useState(readLookupQuery)      // was useState('')
// submittedOverride stays useState<...>(null)

useEffect(() => {
  // hashchange: a raw hash edit or a same-page (already on `/`) re-submit that
  //   assigns window.location.hash directly.
  // popstate: a cross-route SPA deep link — commands.ts::navigate pushState +
  //   synthetic popstate does NOT emit hashchange (commands.ts:127-134).
  const sync = () => {
    const q = readLookupQuery()
    setLiveValue(q)
    setSubmitted(q)          // committed value — a deep link is an explicit navigation
    setSubmittedOverride(null) // a fresh deep link auto-detects; no stale ModeChip override
  }
  window.addEventListener('hashchange', sync)
  window.addEventListener('popstate', sync)
  return () => {
    window.removeEventListener('hashchange', sync)
    window.removeEventListener('popstate', sync)
  }
}, [])
```

Why BOTH events (identical rationale to `Lookup.tsx:176-178`): `commands.ts::navigate` (`commands.ts:127-134`) uses `pushState` + a synthetic `PopStateEvent` for pathname targets, which does **not** fire `hashchange`; a user editing the hash in the address bar, or a same-page `window.location.hash =` assignment, fires `hashchange` but not `popstate`.

### 2.3 It flows straight into the existing machine
Once `submitted` is set, everything downstream is unchanged: `useCockpitInput(submitted, submittedOverride)` (`Overview.tsx:77`) classifies and resolves; `isResult` (`Overview.tsx:78`) flips true; the globe-landing / geoless effects (`Overview.tsx:91-112`) run; the result wrapper is keyed `key={`${cockpit.kind}:${submitted}`}` (`Overview.tsx:209`). **The remount contract is honored for free:** a new `#q=` value changes `submitted`, which changes the composite key, which fully unmounts the previous `ResultRegion` subtree — so a stale `CompareIp` second-fetch can never survive a deep-link change (the exact invariant the composite key exists to protect, `ResultRegion.tsx:34-42`).

### 2.4 Committed-value discipline preserved
`submitted` is only ever written by (a) the submit handler (`Overview.tsx:114-118`), (b) the clear path (`Overview.tsx:123-126`), (c) the demo chips (`Overview.tsx:129-132`), and now (d) the hash sync above — never from live typing. `useLookup` still never sees a live value; no `/api/enrich` hammering. ✔

### 2.5 Design decision — the cockpit does NOT write `#q=` on in-place submit
**Recommendation:** the cockpit *reads* `#q=` (seed + sync) but a plain Enter submit continues to render **in place without writing the hash** — exactly today's behavior (`Overview.tsx:114-118` sets state only). Rationale:
- **Preserves the ModeChip override.** If submit wrote the hash, the resulting `hashchange` would re-enter `sync`, which resets `submittedOverride` to `null` — silently dropping a user's manual indicator↔command correction. Not writing the hash sidesteps this entirely.
- **No feedback loop.** No submit→hashchange→re-seed round-trip to reason about.
- **Not a regression.** The cockpit never wrote the hash before; shareable/bookmarkable links still exist via the palette + `submitLookup` (which *do* write `#q=`, §4) and via any address-bar hash.

Deferred (noted, not built): syncing the hash on in-cockpit submit for copy-URL shareability. It must first solve override-preservation (e.g. skip the reset when the incoming hash equals the current `submitted`). Out of scope here.

---

## 3. `/lookup` retirement strategy — thin redirect stub

**Recommendation: keep a routable redirect stub, not a hard delete.** External bookmarks, shared links, and the extension's older handoffs may target `/lookup#q=x`; a hard delete would 404 them (App's matcher falls through to `ROUTES[0]` = Overview, but with the hash intact it would *accidentally* work — relying on that is fragile and undocumented). An explicit stub is self-documenting and history-clean.

### 3.1 `web/src/routes/LookupRedirect.tsx` (new)
```tsx
// LookupRedirect — /lookup is retired; the cockpit (/) is the single lookup
// surface. Preserves bookmarked/shared `/lookup#q=<x>` links by rewriting to
// `/#q=<x>` (replaceState leaves no /lookup entry in history) and handing off
// to the cockpit, which reads the same `#q=` deep link (Overview.tsx sync).
import { useLayoutEffect } from 'react'
export function LookupRedirect(): null {
  // useLayoutEffect (not useEffect): the rewrite runs BEFORE paint, so a
  // cold-load `/lookup#q=x` bookmark never shows a blank `default`-width main
  // frame before Overview (wide) mounts — the only time this component renders.
  useLayoutEffect(() => {
    const hash = window.location.hash            // carries `#q=…` verbatim (or '')
    window.history.replaceState({}, '', '/' + hash)
    window.dispatchEvent(new PopStateEvent('popstate'))
  }, [])
  return null
}
```
Flow: on `/lookup`, `App.tsx`'s matcher (`App.tsx:76-77`) selects the `/lookup` row → renders `<LookupRedirect/>` (renders nothing). Its mount effect rewrites the URL to `/#q=…` (no new history entry) and fires a synthetic `popstate`; `App.tsx`'s `useRoute` (`App.tsx:63-70`) re-reads `window.location.pathname` = `/` → `active` falls to `ROUTES[0]` (Overview). Overview **fresh-mounts** and its `useState(readLookupQuery)` seed (§2.2) reads the still-present hash. StrictMode double-invocation is idempotent (replaceState to the same URL, popstate twice → harmless).

### 3.2 `App.tsx:53` — the route row
```tsx
// before: { path: '/lookup', label: 'Lookup', size: 'default', el: <Lookup /> },
// after:
{ path: '/lookup', label: 'Lookup', size: 'default', el: <LookupRedirect />, nav: false },
```
`nav: false` drops the redundant top-nav "Lookup" tab (the cockpit `/` = "Overview" is now the lookup surface; two tabs to the same capability is confusing — `App.tsx:79-83` filters `nav !== false`). Swap the import at `App.tsx:4` (`Lookup` → `LookupRedirect`). Update the router doc comment `App.tsx:19` (`/lookup → the escalation-card system` → note it now redirects to `/`).

*Rejected alternative:* special-casing `/lookup` inside `App.tsx`'s matcher to normalize to `/`. Less explicit, buries a redirect in routing glue, and still needs hash-preservation logic — the dedicated stub is clearer.

### 3.3 What happens to each `/lookup`-named artifact
| Artifact | Fate | Why |
|---|---|---|
| `Lookup.tsx` | **DELETE** | Replaced by `LookupRedirect`; its `CardTriptych` + `ExamplesGallery` are retired/folded. |
| `CardTriptych` (in `Lookup.tsx:62-97`) | **DELETE** | The three-register layout is the redundancy being removed. |
| `ExamplesGallery` (in `Lookup.tsx:103-141`) | **REPLACE** → `CockpitExamples` (§5) | Kept as a capability, re-homed in the cockpit idle state, rendering one `EscalationCard` (not the triptych). |
| `lookupModel.ts` | **KEEP** | Hosts `cveToVerdict` (used by `useLookup.ts:30`) + `readLookupQuery`/`parseQ` (used by `PowerShellAnalyzer.tsx:3` + `Overview.tsx`). Update header comment `lookupModel.ts:1`. |
| `readLookupQuery` | **KEEP** (extract pure `parseQ`, §9) | Shared deep-link reader for analyzer + cockpit. |
| `/lookup` nav entry (`App.tsx:53`) | **REDIRECT + `nav:false`** | §3.2. |

---

## 4. Deep-link repointing inventory

Every confirmed referrer to `/lookup`, with its exact new target. Each verified by reading the cited line.

| # | Referrer (file:line) | Today | New target | Mechanism |
|---|---|---|---|---|
| 1 | `App.tsx:53` (route + nav) | `el: <Lookup/>`, nav tab | `el: <LookupRedirect/>`, `nav:false` | §3.2 |
| 2 | `ResultRegion.tsx:75-83` ("Full analyst view →") | `<a href={`/lookup${lookupHash(indicator)}`}>` | **REMOVED entirely** | The cockpit IS the full view; the card is already the full `EscalationCard`. §6.2 |
| 3 | `Overview.tsx:134-140` (`openFullView`) | SPA-navigates to `/lookup` via `submitLookup` | **REMOVED** (dead once #2 is gone) | §6.2 |
| 4 | `Admin.tsx:107` ("Check reputation →") | `href={`/lookup#q=${encodeURIComponent(r.ioc_value)}`}` | `href={`/#q=${encodeURIComponent(r.ioc_value)}`}` | Plain `<a>`; browser loads `/`, cockpit seeds from hash |
| 5 | `commands.ts:26-33` (`view:lookup` palette command) | row with `href:'/lookup'` | **REMOVED**; fold its `keywords` (`lookup, verdict, escalation, ip, domain, url, hash, cve`) into `view:overview` (`commands.ts:24`) | Preserves palette discoverability without a duplicate `/` destination |
| 6 | `commands.ts:119` (`submitLookup` indicator branch) | `navigate(`/lookup${lookupHash(q)}`)` | `navigate(`/${lookupHash(q)}`)` → `/#q=…` | `navigate` (`commands.ts:127-134`) pushState + synthetic popstate → cockpit's popstate sync (§2.2). **Also** update the stale `submitLookup` jsdoc (`commands.ts:102-110`) that still says "routes to the live `/lookup` surface" to describe the cockpit `/#q=` target. |
| 7 | `PowerShellAnalyzer.tsx:7` (comment) | `// palette/`/lookup`, Lookup.tsx` | comment corrected to reference the cockpit; **no code change** | The analyzer's `#q=` read + IOC pivots are unrelated to `/lookup` (see 0.3) |

Notes:
- **`submitLookup`'s command branch is untouched:** `navigate(`/analyzer${lookupHash(q)}`)` (`commands.ts:114-116`) stays — a pasted command still routes to the standalone analyzer with the command prefilled.
- **`CommandPalette.tsx` callers** (`CommandPalette.tsx:267,296` call `submitLookup`) need **no change** — they inherit the repointed target transitively.
- **The analyzer IOC pivot** (`IocTable.tsx:27-40` → `InlineLookup.tsx`) is an inline expand that hits `/api/enrich` directly (`InlineLookup.tsx:9-13`) — it never used `/lookup`, so it is unaffected.

---

## 5. Idle-state examples gallery placement (`CockpitExamples.tsx`)

**Owner decision (locked):** keep the examples gallery; fold it into the cockpit idle state so a first-time visitor sees what a result looks like.

### 5.1 What it renders
`CockpitExamples` extracts the family-tab logic from `Lookup.tsx:103-141` but renders **one `EscalationCard`** for the selected stub — NOT the retired `CardTriptych` (the copy-card PNG and `AnalystVerdict` console are gone from web):
```tsx
// web/src/components/cockpit/CockpitExamples.tsx (new)
import { useState } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import { EscalationCard, STUBS, type EffectiveTheme } from '@socdesk/shared/verdict-cards'
import { MicroLabel } from '../ui'

export function CockpitExamples({ theme }: { theme?: EffectiveTheme }) {
  const [sel, setSel] = useState(STUBS[0].id)
  const stub = STUBS.find((s) => s.id === sel) ?? STUBS[0]
  // Wrapped in the <details> disclosure of §5.2 (collapsed by default):
  // <summary>See a sample card</summary>
  // ... tablist (role="tablist"/"tab", aria-selected) copied from Lookup.tsx:113-136 ...
  // <EscalationCard data={stub.data} theme={theme} />   // no onCompare, no reportSlot
}
```
Renders **exactly** as the current gallery's card did: `CardTriptych` passed `reportable` defaulting to `false` for stubs, so `EscalationCard` mounted with no `reportSlot` and no `onCompare` (`Lookup.tsx:79-82,138`). Behavior is byte-identical for the card; only the copy-card PNG + analyst-console columns are dropped. **No idle network call:** `CompareIp`'s fetch is gated behind a user open + form submit (`CompareIp.tsx:55-58`, `open` starts `false`) — a static stub card issues nothing.

### 5.2 Where it sits — **collapsed behind a disclosure** (owner decision, 2026-08-23)
Render it as a **collapsed disclosure** below the hero `</section>` and above `<SituationalBoard/>`, gated on idle. `CockpitExamples` owns its own open/closed state and renders as a single quiet **"See a sample card ▾"** trigger by default; expanding it reveals the family tabs + the one `EscalationCard`:
```tsx
// Overview.tsx tail (after the hero </section>, ~line 238):
      </section>
      {!isResult && <CockpitExamples theme={theme} />}
      <SituationalBoard />
```
```tsx
// CockpitExamples.tsx — collapsed by default; a native <details> keeps it
// keyboard-accessible and zero-JS-state. STUBS render only once opened.
export function CockpitExamples({ theme }: { theme?: EffectiveTheme }) {
  return (
    <details className="mx-auto w-full max-w-md">
      <summary className="cursor-pointer select-none font-mono text-xs text-muted">
        See a sample card
      </summary>
      {/* family tablist (role=tablist/tab, aria-selected) + one <EscalationCard/> */}
    </details>
  )
}
```
Rationale (resolves the frontend/UX review, finding 4):
- **Collapsed by default → it never out-ranks the live board.** A one-line disclosure below the hero doesn't compete with `SituationalBoard`'s operational data for a returning visitor; a first-timer curious about "what a result looks like" opens it in one click.
- **The globe hero stays the centerpiece.** The expanded `EscalationCard` (`max-w-md`) only appears on demand, so it never fights the absolutely-positioned globe. Route container is `size: 'wide'` (`App.tsx:44`).
- **It vanishes on first lookup.** `!isResult` hides the whole disclosure the moment anything is submitted (`Overview.tsx:78`) — the docked `ResultRegion` becomes the live equivalent.
- **The "Try" demo chips stay** (`Overview.tsx:222-231`) — they submit a real lookup + fly the globe (the more authentic teach), a different purpose from the static per-family anatomy the gallery previews.

Reading order for a returning visitor: globe hero + omnibox + Try chips → **live** situational board (the product) → (a first-timer may open "See a sample card" for the per-family reference).

---

## 6. Deletions

### 6.1 `AnalystVerdict` — delete the component and its export
`AnalystVerdict` (`shared/verdict-cards/AnalystVerdict.tsx`) is rendered in exactly ONE place: `Lookup.tsx:93`. The `// console + extension` framing in its header (`AnalystVerdict.tsx:1-2`) and the `extension/src/popup/main.tsx:5` comment are **stale** — the extension's `Popup.tsx` imports `EscalationCard` + `CardCanvasPreview`, **not** `AnalystVerdict` (`Popup.tsx:36-41`). Verified: the only non-comment references are the export (`index.ts:11`), the file itself, and the `Lookup.tsx:24,93` use. Therefore:
- Delete `shared/verdict-cards/AnalystVerdict.tsx`.
- Delete the `export { AnalystVerdict } from './AnalystVerdict'` line (`index.ts:11`).
- (Docs `BUILD-JOURNAL.md:26-27` and the stale `main.tsx:5`/`AnalystVerdict.tsx:1` comments are historical/cosmetic — optional cleanup, not load-bearing.)

### 6.2 `ResultRegion` — remove the "Full analyst view →" link
In `ResultRegion.tsx`: delete the `FULL_VIEW_CLS` const (`:10-11`), the `lookupHash` import (`:3`, now unused), the `MouseEvent` type import (`:1`, now unused), the `onFullView` prop (`:44-53`), the `indicator` computation (`:58`), and the entire `{indicator && (<a …>Full analyst view →</a>)}` block (`:75-83`). In `Overview.tsx`: delete `openFullView` (`:134-140`), remove `onFullView={openFullView}` from the `ResultRegion` call (`:217`), remove the now-unused `submitLookup` import (`:10`, only used by `openFullView`), and remove `MouseEvent` from the `react` type import (`:2`, only used by `openFullView`).

### 6.3 `CardCanvasPreview` — drop from web, keep in the extension
Web's only use is `Lookup.tsx:87` (inside the deleted `CardTriptych`). The extension keeps it (`Popup.tsx:37,324`). So `CardCanvasPreview` (and its `CardActions` sibling) **stay exported** from `shared/verdict-cards/index.ts:12` — only the web *use* disappears with `Lookup.tsx`. Verified no other web importer.

### 6.4 `Lookup.tsx` — delete the file
All of it: the route component, `CardTriptych`, `ExamplesGallery` (re-homed as `CockpitExamples`), the `EXAMPLES`/`CHIP_CLS`/`Label` locals. Its imports of `useLookup`, `LookupStatus`, `readLookupQuery`, `ReportButton`, `isEnrichable`, `refang`, `classifyCockpitInput`, `lookupHash`, `navigate` all remain used by other (kept) surfaces — nothing shared is orphaned.

---

## 7. Shared-code safety — what STAYS

Named for `/lookup` in comments, but used by the cockpit and/or the extension too. Verified importers; all unchanged.

| Symbol / file | Kept because | Importer (verified) |
|---|---|---|
| `useLookup` (`components/lookup/useLookup.ts`) | The cockpit's resolver | `useCockpitInput.ts:22` |
| `LookupStatus` / `Notice` (`components/lookup/LookupStates.tsx`) | Cockpit degraded states + Admin/MyReports notices | `ResultRegion.tsx:4`, `Admin.tsx:12`, `MyReports.tsx:8` |
| `useCockpitInput` (`components/cockpit/useCockpitInput.ts`) | The cockpit hook | `Overview.tsx:11` |
| `useEffectiveTheme` (`shared/verdict-cards/useEffectiveTheme.ts`) | Cockpit + extension theme | `Overview.tsx:6`, extension |
| `shared/verdict/client.ts` (`fetchEnrich`/`fetchEnrichRaw`) | Cockpit resolver + extension + inline lookup | `useLookup.ts:26`, `Popup.tsx:34`, `useInlineEnrich` |
| `lookupHash` (`palette/commands.ts:98-100`) | The `#q=` writer for palette/analyzer/admin targets | `commands.ts`, `Admin.tsx` (inline `#q=`) |
| `cveToVerdict` (`routes/lookupModel.ts`) | CVE resolution for the shared resolver | `useLookup.ts:30` |
| `readLookupQuery`/`parseQ` (`routes/lookupModel.ts`) | Deep-link read for analyzer + cockpit | `PowerShellAnalyzer.tsx:3`, `Overview.tsx` (new) |
| `CardCanvasPreview`, `CardActions` (`shared/verdict-cards/CardActions.tsx`) | Extension copy-card | `Popup.tsx:37` |
| `STUBS` (`shared/verdict-cards/stubs.ts`) | Cockpit examples + card tests | `CockpitExamples.tsx` (new), `shared/card/__tests__/*` |

---

## 8. Failure / edge modes

- **Command-shaped `#q=` value** (e.g. `/#q=powershell%20-enc%20…`). `useCockpitInput` classifies it `'command'`; `resolveKind`'s monotonic lock forces `'command'` (`useCockpitInput.ts:54-60`); `resolveCockpitArgs` feeds `useLookup` `''` (`useCockpitInput.ts:40-48`) → **zero `/api/enrich`**; `ResultRegion` renders `AnalyzerResult` inline (`ResultRegion.tsx:88-92`). Strictly better than `/lookup`, which had to redirect to `/analyzer`.
- **Empty / garbage hash** (`/`, `/#`, `/#foo`, malformed percent-encoding). `parseQ` returns `''` (no `q=` match, or the decode `catch`, `lookupModel.ts:20-29`). `submitted = ''` → `isResult` false (`Overview.tsx:78`) → idle cockpit with `CockpitExamples`. No crash.
- **Deep link to a CVE / unsupported / email.** Unchanged resolver behavior via `useLookup` → honest `LookupStatus` in the cockpit's indicator branch (`ResultRegion.tsx:72-74`).
- **Back/forward history.** Palette/admin deep-links use `pushState` (`commands.ts:132`) → back returns to the prior route (as today). In-cockpit Enter adds no history entry (§2.5), matching today's cockpit exactly. The `LookupRedirect` uses `replaceState` → no orphan `/lookup` entry, so back never lands on the dead route.
- **Already on `/` when the palette fires `submitLookup`.** `navigate('/#q=…')` pushState keeps pathname `/`, so `App.tsx`'s pathname-only `useRoute` does not remount Overview; the synthetic `popstate` reaches Overview's sync (§2.2) → `submitted` updates → the composite key remounts only the `ResultRegion` subtree. Correct.
- **StrictMode double effect** on `LookupRedirect` — idempotent (§3.1).

---

## 9. `parseQ` extraction (testability)

`readLookupQuery` reads `window.location.hash` (`lookupModel.ts:21`), so it is not directly unit-testable in the repo's **node-environment** vitest (`web/vitest.config.ts:27`, no jsdom, no `window`). Extract the pure parse:
```ts
// lookupModel.ts
export function parseQ(hash: string): string {
  const h = hash.replace(/^#/, '')
  const m = h.match(/(?:^|&)q=([^&]*)/)
  if (!m) return ''
  try { return decodeURIComponent(m[1]).trim() } catch { return m[1].trim() }
}
export function readLookupQuery(): string { return parseQ(window.location.hash) }
```
Pure, deterministic, no I/O — exactly the kind of helper the repo already unit-tests beside its route (cf. `web/src/routes/adminModel.test.ts`, `myReportsModel.test.ts`). `readLookupQuery`'s public signature is unchanged, so `PowerShellAnalyzer.tsx:3,10,17` and the new `Overview.tsx` seed keep working verbatim.

---

## 10. Testing strategy

The repo runs **vitest in a plain node environment** (`web/vitest.config.ts:26-29`, `include: ['src/**/*.test.ts', '../shared/**/*.test.ts']`) — pure logic only, `.ts` not `.tsx`, **no jsdom/RTL harness** (`useCockpitInput.ts:14-19`). JSX is **build-gated** via `npm --prefix web run build` (`tsc -b && vite build`, `web/package.json`).

**Unit (pure, new):** `web/src/routes/lookupModel.test.ts` for `parseQ`:
- `'#q=1.1.1.1'` → `'1.1.1.1'`; `'#q=powershell%20-enc%20AAA'` → decoded command; `'#q='` → `''`; `''` / `'#'` / `'#foo'` → `''`; `'#a=1&q=8.8.8.8'` → `'8.8.8.8'`; malformed `'#q=%E0%A4%A'` → falls to the `catch`, returns the raw trimmed token (no throw); whitespace trimmed.

**Unit (pure, existing — must stay green):** `shared/intent.test.ts` (`classifyCockpitInput`), `useCockpitInput.test.ts` (`resolveCockpitArgs`/`resolveKind`), the card-model/geo/draw tests over `STUBS`. None of these change; the consolidation must not regress them.

**Build gate (the only gate for JSX):** `npm --prefix web run build` green — proves `Overview.tsx`, `LookupRedirect.tsx`, `CockpitExamples.tsx`, `ResultRegion.tsx` (prop removed), `App.tsx`, `commands.ts`, `Admin.tsx`, and the `index.ts` export removal all typecheck with no unused imports.

**Static assertion:** a grep proving no `/lookup` **navigation target** (`href={`/lookup`, `navigate('/lookup`, route `path` other than the stub) remains outside `LookupRedirect.tsx` — comments and `components/lookup/` import paths in the kept shared files are expressly excluded; and no importer of `AnalystVerdict` remains.

**Manual dogfood (prod build, per the repo's live-checkpoint convention):**
1. `/#q=8.8.8.8` (fresh load) → escalation card docks in the cockpit, globe lands.
2. `/lookup#q=8.8.8.8` (bookmark) → URL becomes `/#q=8.8.8.8`, same card, no `/lookup` flash, no 404.
3. `/#q=` + a pasted `powershell -enc …` → analyzer renders inline; **Network tab shows zero `/api/enrich`**.
4. Palette "Escalation cards" search still finds the cockpit (folded keywords); selecting an indicator lands on `/#q=…`.
5. Admin "Check reputation →" → cockpit card.
6. Idle cockpit shows `CockpitExamples` **collapsed** as a "See a sample card ▾" disclosure below the hero; opening it reveals the family tabs, and picking each swaps the card; the whole disclosure disappears on first lookup.
7. Top nav shows no "Lookup" tab.

---

## 11. Consolidated acceptance criteria

1. Cockpit honors `#q=` on mount, `hashchange`, and `popstate`; `submitted` stays the committed value; no live-typed value reaches `useLookup`.
2. `/lookup#q=x` resolves to the cockpit result via `LookupRedirect` (replaceState, no history orphan, no 404).
3. Every `/lookup` referrer repointed per §4; the only remaining `/lookup` **navigation target** is inside `LookupRedirect.tsx` (comments/import-paths in kept shared files excluded).
4. A command-shaped `#q=` renders the analyzer inline with zero `/api/enrich` calls.
5. `AnalystVerdict.tsx` deleted, export removed, no importer remains; `CardCanvasPreview` still exported and used by the extension only.
6. `CockpitExamples` renders **collapsed** (a "See a sample card" disclosure) below the hero in the idle cockpit, expanding to one `EscalationCard` per family; hidden entirely once a result shows; no idle network call.
7. `lookupModel.ts` (with new pure `parseQ`) survives; `cveToVerdict` + `readLookupQuery` importers unbroken.
8. Top nav shows no "Lookup" tab.
9. `npm --prefix web run build` green; `npx vitest run` (from `web/`) green including the new `parseQ` test and all existing pure tests.
10. No verdict-hue, doctrine, wording, extension, or analyzer-logic change. Attribution: SaltyCarl, zero AI attribution.

---

## 12. Reserved-colour / doctrine / attribution
No new verdict hues; the examples gallery and redirect add none. Chips stay periwinkle; gated characterization stays red/amber; honesty states keep their existing voice (`LookupStates.tsx`). This is a pure composition/routing consolidation. Attribution: **SaltyCarl — no AI attribution anywhere.**
