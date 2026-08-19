# SOCDesk — Polymorphic Cockpit: Design Spec

**Date:** 2026-08-19 · **Status:** design, owner-approved, pre-plan · **Scope target:** `web/` + `shared/` (the live React/TS app).

## 0. Summary

The cockpit (`web/src/routes/Overview.tsx`, route `/`) accepts an indicator, enriches it, and docks an `EscalationCard` beside a 3D globe. The PowerShell analyzer lives on a **separate** `/analyzer` route with its own textarea and result components, unreachable from the cockpit. This spec makes the cockpit **polymorphic**: one input classifies what you pasted and routes it to enrichment **or** the analyzer, rendering either result in the same docked slot — so "paste anything, get the analysis, one screen." The globe yields (steps back, stops rendering) when the result isn't geographic.

The product promise "IOC in, OSINT out" becomes "paste anything — indicator or command — and get the right analysis in place," matching the VirusTotal/urlscan single-box expectation and extending it to a command line as a first-class artifact type.

## 1. Locked decisions (owner-approved 2026-08-19)

- **Unified submit.** One submit gesture (paste + **Enter**, or the omnibox arrow button) for BOTH paths: on submit, classify the input, then run enrichment or analysis. This is consistent and — crucially — avoids re-firing `/api/enrich` on every keystroke (`useLookup` has no debounce of its own; today it is gated only by the explicit-submit UI). The analyzer, though instant/local, is gated the same way for consistency; for a paste (its overwhelming use) live-vs-submit is indistinguishable.
- **Full v1** as scoped in §3. **Deferred to a fast-follow (§9):** the analyzer's "Full analyst view →" deep-link parity (the `/analyzer` route has no `#q=` consumer), and converting `IocTable`'s "Look up →" from a hard route-navigation into an in-place cockpit kind-flip.
- **`/analyzer` route stays** as the deep/standalone view, refactored to share the new `AnalyzerResult` component. The cockpit becomes the primary entry; the standalone route is not deleted.
- **Reserved-colour + honesty doctrine unchanged.** The analyzer result keeps its periwinkle chips + gated red/amber characterization. The cockpit's "unclassified" state uses the existing honest-empty voice.
- **Data boundary is load-bearing (§2.1).** A pasted command must never reach `/api/enrich`.

## 2. The problems this must solve (grounded in recon)

### 2.1 Security/data-boundary fix (not optional)
`detectType` (`shared/indicators.ts:53-64`) classifies by shape, and its **URL regex is prefix-only** (`/^https?:\/\//i`, not end-anchored, `indicators.ts:61`). A pasted script whose first line is a download URL is therefore typed `'url'`, and the **entire raw multi-line blob** is sent as `?q=<full text>` to the third-party `/api/enrich` (`indicators.ts:110-112` → `useLookup.ts:106` → `shared/verdict/client.ts:81-98`). The analyzer's core promise is that a pasted command **never leaves the browser**. The command classifier MUST run and short-circuit **before** `detectType`.

The `domain` regex (`indicators.ts:62`) also matches bare LOLBin filenames (`powershell.exe`, `rundll32.exe`) as domains — a lesser correctness bug the same ordering fixes.

### 2.2 Two drifted classifiers, two submit paths
- Two indicator classifiers exist and have drifted: `shared/indicators.ts::detectType` (`ipv4|ipv6|md5|sha1|sha256|cve|email|url|domain|''`) and `web/src/components/palette/classify.ts::classifyIndicator` (`ip|domain|url|hash|cve|unknown`, `palette/types.ts:9`). The palette one is looser (`s.includes('/')` → `url`, `classify.ts:35`).
- Two submit paths route to lookup: `web/src/components/palette/commands.ts::submitLookup` (`commands.ts:108-113`) and a **direct** `web/src/routes/Lookup.tsx::runLookup` (`Lookup.tsx:152-163`) that writes `location.hash` itself, bypassing `commands.ts`.
Intent detection must be a single source of truth applied at every submit path, or a command pasted into one path leaks (2.1) while another is guarded.

### 2.3 Two structurally-different result pipelines
- `useLookup` (`web/src/components/lookup/useLookup.ts:37-45`): 6-arm union `idle|checking|ok|declined|unavailable|unsupported`, real cancellable network I/O (`fetchEnrichRaw`, 12s timeout, `client.ts:22,83`), result `VerdictData` (`shared/verdict/types.ts:91-114`) → one `EscalationCard` (whose IP branch does its own **second** fetch via `CompareIp`, `EscalationCard.tsx:104-113`).
- `usePsAnalysis` (`web/src/components/analyzer/usePsAnalysis.ts:5-9,13-26`): 4-arm union `idle|analyzing|ok|error` (`error` = a real thrown bug, not an expected outcome), **no network, no AbortController**, only async is `DecompressionStream` in `analyze()` (`shared/analyzer/report.ts:36`), result `AnalysisResult` (`shared/analyzer/types.ts`) → three independently-optional components inlined in the route (`PowerShellAnalyzer.tsx:29-40`).
Both already share the same idioms: keyed on `[input]`, a `live` staleness guard, and an **empty-input short-circuit to `idle`** (`useLookup.ts:52`, `usePsAnalysis.ts:16-17`) — the property that makes a switcher hook cheap.

### 2.4 Cockpit composition + globe
`Overview.tsx` drives everything from `active: string` (`Overview.tsx:123`, `''`=idle), `isResult = active !== ''` (`:126`), `state = useLookup(active)` (`:125`). The intro folds via a CSS `grid-template-rows: 1fr→0fr` toggle (`:205-227`); the omnibox is one persistent single-line `<input>` (`:247-260`); a slot below swaps Try-chips ↔ `LandingResult` (`:73-105,266-274`), keyed `key={active}`. `LandingResult` hard-switches `state.kind==='ok' ? <EscalationCard/> : <LookupStatus/>` (`:89-93`). The **globe** is an absolutely-positioned overlay (`GlobeStage3`, `.sdh-wrap { position:absolute; right:-6% }`, `globe.css:80-88`) — **not layout-load-bearing**. It exposes `GlobeApi { flyToLatLng, flyBack, drawArc, clearArc }` (`useGlobe3.ts:289-299`); non-geo results already call `api.flyBack()` (`Overview.tsx:143-145`). Its visual "yield" today is **CSS-only, gated on `.is-result` + viewport width** (`globe.css:498-524`) — on desktop it stays full-presence beside any result. The rAF/WebGL loop is gated by `IntersectionObserver` (`useGlobe3.ts:1217-1239`), which **does not** see CSS opacity — a CSS dim leaves the globe burning GPU. Hero height is clamped `min-height: clamp(460px,62vh,680px)` (`globe.css:20`), sized for an IOC card.

## 3. v1 scope — the design

### 3.1 Input classifier (`shared/intent.ts`, net-new, pure)
`export function classifyCockpitInput(raw: string): 'indicator' | 'command' | 'unclassified'`
- Returns `'command'` when `raw` looks like a command/script and NOT a bare indicator: contains a newline; OR matches `\b(powershell|pwsh|iex|invoke-expression|invoke-\w+|new-object)\b`; OR `-e(nc|ncodedcommand)?\b`; OR shell/PS punctuation (`;`, `|`, `` ` ``, `$(`) together with ≥2 whitespace-separated tokens. Case-insensitive.
- Else `detectType(refang(raw)) !== ''` → `'indicator'`.
- Else `'unclassified'`.
- **Command wins ties** (a value that is both command-shaped and indicator-shaped is a command) — this is the data-boundary guarantee.
- Deterministic, no I/O. Fully unit-tested (positive + benign-twin per branch; the standout tests: a script whose first line is a URL → `'command'` (NOT `'indicator'`); `powershell.exe` alone → not a bare domain; a bare IP/domain/hash/cve/url → `'indicator'`).

### 3.2 Consolidate the classifiers (§2.2)
Make `classify.ts::classifyIndicator` delegate to (or be replaced by) `detectType` so there is one indicator classifier; map its output to the palette badge enum in one place. No behaviour change to the palette badges beyond removing the `includes('/')`-is-url looseness.

### 3.3 Unified hook (`web/src/components/cockpit/useCockpitInput.ts`, net-new)
```ts
type CockpitResult =
  | { kind: 'indicator'; state: LookupState }
  | { kind: 'command'; state: PsState }
  | { kind: 'unclassified'; state: { kind: 'idle' } }
function useCockpitInput(submitted: string): CockpitResult
```
- `kind = classifyCockpitInput(submitted)`.
- Calls BOTH hooks unconditionally (rules-of-hooks): `useLookup(kind==='indicator' ? submitted : '')` and `usePsAnalysis(kind==='command' ? submitted : '')`. The unselected hook gets `''` → short-circuits to `idle` for free (§2.3), so no wasted fetch/analysis.
- `submitted` is the **committed** value (post-Enter), per the unified-submit decision — so `useLookup` never sees a live-typed value and can't hammer `/api/enrich`.

### 3.4 `AnalyzerResult` component (`web/src/components/analyzer/AnalyzerResult.tsx`, net-new)
Extract the composition currently inlined in `PowerShellAnalyzer.tsx:29-40` (flag chips + `TechniqueTally` + `DecodeLadder` + `IocTable`) into one prop-driven component `AnalyzerResult({ result }: { result: AnalysisResult })`. Refactor the `/analyzer` route to use it (no behaviour change there). The cockpit reuses it verbatim.

### 3.5 `ResultRegion` (`web/src/components/cockpit/ResultRegion.tsx`, net-new) — replaces the `LandingResult` hard switch
Dispatch by `cockpit.kind` first, then each hook's own union:
- `indicator` → today's `state.kind==='ok' ? <EscalationCard/> : <LookupStatus/>`, unchanged.
- `command` → `state.kind==='ok' ? <AnalyzerResult result={state.result}/> : <PsStatus/>` where `PsStatus` renders `analyzing` (a light "Analyzing…" line, reusing the existing pattern) and `error` (an honest failure line). `idle` renders nothing.
- `unclassified` → an honest one-line hint ("Not a recognised indicator or command — paste an IP, domain, hash, URL, CVE, or a PowerShell command"), reusing the existing unrecognised voice (`LookupStates.tsx:119-127`).
- On a `kind` flip the region fully unmounts the previous subtree (via `key={kind}` on the wrapper), so `EscalationCard`'s `CompareIp` second-fetch can't leak across a switch (§2.3 risk).

### 3.6 Cockpit rewiring (`Overview.tsx`)
- Replace the single `active`/`useLookup` wiring with: a committed `submitted` string + `const cockpit = useCockpitInput(submitted)`; `isResult = cockpit.kind !== 'unclassified' || submitted !== ''` (i.e. any committed input shows a result region). Keyed reveal uses `key={submitted}`.
- The submit handler classifies-then-commits (no route navigation for the cockpit itself — it renders in place).
- Thread a new boolean `resultIsGeoless` into the globe/layout reconciliation (see §3.7), split out from the overloaded `.is-result`.

### 3.7 Input morph + mode chip
- The omnibox becomes a control that renders a single-line `<input>` by default and a multi-line `<textarea>` (mono, auto-growing) once the live-typed value is command-shaped or multi-line — one component, adaptive, preserving the typed value across the swap (do not remount).
- A small **mode chip** on the input row shows the live-detected kind (`IP`/`URL`/`CVE`/`Hash`/`Domain`/`PowerShell`/`—`), reusing the palette badge pattern (`CommandPalette.tsx:409-412`). It is **correctable**: clicking it toggles a manual override (indicator ↔ command) that wins over auto-detection for that submit. Command-detection wins auto ties.
- Placeholder/aria-label generalise from "Enrich an IP / domain / hash" to accept a command too.

### 3.8 Globe yield (three layers, per §2.4)
- **Behavioural:** on a `command` (or any geoless) result, `api.flyBack()` — already the primitive.
- **Visual:** add a new modifier class (e.g. `.is-geoless` on `.sdh-hero`, driven by `resultIsGeoless`) with a rule mirroring the existing `<1024px` demotion (dim/reposition/hide the hint) but applied **regardless of viewport width**. Split this concern OUT of `.is-result` (which stays "has a result", driving the intro fold) so the two selectors don't tangle.
- **Loop cost:** add `suspend()`/`resume()` to `GlobeApi` (`useGlobe3.ts`) that call the engine's `stopLoop()`/restart, and have the cockpit call `api.suspend()` when `resultIsGeoless` and `api.resume()` otherwise — so a yielded globe stops rendering rather than burning GPU behind a CSS dim.

### 3.9 Height flex
Relax the hero `min-height` clamp so the taller full-width analyzer stack (`AnalyzerResult`, open-ended length) grows the hero smoothly instead of jump-cutting or fighting the 680px cap. The globe being absolute means this cannot collapse layout; verify the idle/short-result states still hold their intended minimum.

## 4. Data flow

`omnibox (live value) → live classify → mode chip + input morph` (no run). On **submit**: `commit value → useCockpitInput(committed) → classifyCockpitInput → {indicator: useLookup | command: usePsAnalysis} → ResultRegion renders the matching surface; Overview sets resultIsGeoless → globe flyBack/suspend + .is-geoless`. IOC extraction, defang, and the analyzer's internal pipeline are unchanged.

## 5. Files

**Create:** `shared/intent.ts` (+ test), `web/src/components/cockpit/useCockpitInput.ts`, `web/src/components/cockpit/ResultRegion.tsx`, `web/src/components/analyzer/AnalyzerResult.tsx`, a unified omnibox input control (e.g. `web/src/components/cockpit/CockpitOmnibox.tsx`) + a `ModeChip`.
**Modify:** `web/src/routes/Overview.tsx` (rewire to `useCockpitInput` + `ResultRegion` + `resultIsGeoless`), `web/src/routes/PowerShellAnalyzer.tsx` (use `AnalyzerResult`), `web/src/components/palette/classify.ts` (delegate to `detectType`), `web/src/components/palette/commands.ts::submitLookup` + `web/src/routes/Lookup.tsx::runLookup` (apply the command guard — route a command to the cockpit/analyzer, never enrich), `web/src/components/hero/useGlobe3.ts` (+ `GlobeApi` `suspend`/`resume`), `web/src/components/hero/globe.css` (`.is-geoless`, height flex).

## 6. Testing

- **`shared/intent.ts`** (vitest, `shared/**`): positive + benign-twin per classifier branch; the data-boundary tests (URL-first-line script → `command`; `powershell.exe` → not a bare domain enrich); determinism.
- **Classifier consolidation:** a test proving `classifyIndicator` now agrees with `detectType` on the previously-divergent cases (e.g. a lone `/` is no longer `url`).
- **`useCockpitInput`:** the unselected hook stays idle (no fetch/analyze); a `kind` flip resets the region.
- **No `web/` browser-test harness** — UI (input morph, mode chip, ResultRegion, globe yield) gates on `tsc -b` + `npm run build` + a controller dogfood screenshot on the prod build (indicator → card+globe; command → analyzer result + globe yielded; unclassified → honest hint; the URL-first-line script does NOT hit the network — verify no `/api/enrich` request fires).
- **Determinism / no-network for the command path:** assert `classifyCockpitInput` + the analyzer path issue zero network calls.

## 7. Risks (from recon)

- **Misclassification is silent** — a command with no PS tokens and no newline could fall to `detectType` and land on `unsupported` (a quiet dropped-analysis). Mitigate: the correctable mode chip lets the analyst force `command`; keep the command heuristic reasonably inclusive; the `unclassified` hint names both input kinds.
- **Rate-limit regression** if a live value ever reaches `useLookup` — the unified-submit decision (feed only the committed value) is the guard; a test asserts no fetch on live typing.
- **`EscalationCard`/`CompareIp` second fetch** leaking across a kind flip — `key={kind}` unmount is the guard.
- **Globe GPU burn** behind a CSS dim — the `suspend()`/`stopLoop()` path is mandatory, not cosmetic.
- **Height/void** — a hidden globe beside a short analyzer result could leave dead space; the height flex + keeping some globe presence (dim, not `display:none`, on desktop) mitigates.
- **Two submit paths** — both must get the guard or the data-boundary fix is partial.

## 8. Reserved-colour / doctrine

Chips periwinkle; the gated characterization callout red/amber (already shipped). The cockpit adds no new verdict hues. The mode chip is neutral/periwinkle (a fact about the input, not a verdict). Attribution: SaltyCarl, zero AI attribution.

## 9. Deferred (fast-follow, not v1)

- Analyzer **deep-link parity**: give `/analyzer` a `#q=` consumer (mirror `Lookup.tsx:126-150` + `lookupModel.readLookupQuery`) so a cockpit "Full analyst view →" (and a shared command) can land there. Needs hash-encoding the script (or a `sessionStorage` handoff) — a real decision deferred.
- `IocTable` "Look up →" → **in-place kind-flip**: instead of `submitLookup` navigating away (`IocTable.tsx:17` → `commands.ts:108-112`), flip the cockpit's own committed value/kind so the enrichment renders in the same region. (Needs the cockpit to expose a setter; low risk, deferred for focus.)
- Tabs demote to views/history (a later IA pass).
