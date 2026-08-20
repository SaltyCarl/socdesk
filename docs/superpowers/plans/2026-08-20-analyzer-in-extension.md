# Analyzer in the Extension — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an analyst highlight a script in a Defender Attack Story, right-click "Check in SOCDesk", and get the full analyzer in a docked side panel — the analysis running locally in the extension.

**Architecture:** Lift the analyzer UI components from `web/src/components/analyzer/` into a new `shared/analyzer-ui/` (the analysis engine in `shared/analyzer/` is already shared and client-side). Decouple the inline IOC-lookup from the web's heavyweight `useLookup` to a lean `fetchEnrich → EscalationCard` path so `shared/analyzer-ui/` has zero `web/src` dependency. The extension adds a `sidePanel` surface and routes the right-clicked selection with `classifyCockpitInput`: command → side-panel analyzer, enrichable indicator → popup lookup, else → report tab.

**Tech Stack:** TypeScript, React 19, Vite, Tailwind v4, MV3 (`chrome.sidePanel`, `chrome.contextMenus`, `chrome.storage`). Tests: vitest (node env — pure logic only; React components are `tsc`/build-gated, matching the existing repo).

**Spec:** `docs/superpowers/specs/2026-08-20-analyzer-in-extension-design.md`

## Global Constraints

- **Data boundary:** the analyzed script is NEVER sent to `/api/enrich`; it is analyzed locally. Only a clicked IOC enriches. `classifyCockpitInput` (command-wins-ties) is the guard.
- **No `eval` / `new Function`** anywhere in the analyzer path (also MV3-required).
- **No AI attribution** in any commit message, code comment, or doc (public repo, owner rule).
- **`shared/analyzer-ui/` must not import from `web/src`** — that is the whole point of the lift.
- Verification gate per task: `npm --prefix web run build` (tsc -b + vite) clean, `cd web && npx vitest run ../shared src` green, and where the task touches the extension, `npm --prefix extension run build` clean.
- The alias `@socdesk/shared` → `../shared` resolves subpaths to directories with an `index.ts` barrel (web AND extension vite configs). A new `shared/analyzer-ui/index.ts` makes `@socdesk/shared/analyzer-ui` importable from both.
- `fetchEnrich(type, q, opts?)` returns `EnrichOutcome = {status:'ok',data} | {status:'declined',reason} | {status:'unavailable',reason}`; `opts.baseUrl` selects the origin (default same-origin).
- `classifyCockpitInput(raw): 'command' | 'indicator' | 'unclassified'` and `isEnrichable(type): boolean`, `detectType(q): IndicatorType`, `refang(s): string` all live in `@socdesk/shared/indicators` / `@socdesk/shared/intent`.

---

## File Structure

- `shared/verdict-cards/useEffectiveTheme.ts` — MOVED from `web/src/components/lookup/useEffectiveTheme.ts` (the card-theme hook; consumed by the card + analyzer + lookup surfaces).
- `shared/analyzer-ui/useInlineEnrich.ts` — NEW. Lean, injectable-origin resolver for ONE IOC → card-ready state. Pure `inlineInitialState` + the `useInlineEnrich` hook.
- `shared/analyzer-ui/InlineLookupStatus.tsx` — NEW. The non-ok honest renderings (checking / declined / unavailable / unsupported) for the lean state.
- `shared/analyzer-ui/InlineLookup.tsx` — MOVED + rewired to the lean resolver; gains an optional `baseUrl`.
- `shared/analyzer-ui/{AnalyzerResult,DecodeLadder,TechniqueTally,ActionBullets,IocTable}.tsx`, `usePsAnalysis.ts` — MOVED verbatim (imports already `@socdesk/shared/*`); `AnalyzerResult`/`IocTable` gain an optional `baseUrl` passthrough.
- `shared/analyzer-ui/index.ts` — NEW barrel.
- `shared/intent.ts` — ADD `routeSelection(raw)` beside `classifyCockpitInput`.
- `extension/manifest.json` — ADD `sidePanel` permission + `side_panel.default_path`.
- `extension/src/background.ts` — route the click via `routeSelection`; open the side panel for analyze.
- `extension/panel.html`, `extension/src/panel/main.tsx`, `extension/src/panel/Panel.tsx` — NEW panel surface.
- `extension/vite.config.ts` — ADD the `panel` HTML entry.
- Web consumers rewired (imports only): `web/src/routes/PowerShellAnalyzer.tsx`, `web/src/components/cockpit/ResultRegion.tsx`, `web/src/components/cockpit/useCockpitInput.ts`, `web/src/routes/Lookup.tsx`, `web/src/routes/Overview.tsx`.

---

### Task 1: Shared card-theme hook + lean inline-enrich resolver

**Files:**
- Create: `shared/verdict-cards/useEffectiveTheme.ts` (moved), `shared/analyzer-ui/useInlineEnrich.ts`, `shared/analyzer-ui/InlineLookupStatus.tsx`
- Modify: `shared/verdict-cards/index.ts` (export the hook), the 4 web importers of `lookup/useEffectiveTheme`
- Delete: `web/src/components/lookup/useEffectiveTheme.ts`
- Test: `shared/analyzer-ui/__tests__/useInlineEnrich.test.ts`

**Interfaces:**
- Produces: `useEffectiveTheme(): EffectiveTheme` (from `@socdesk/shared/verdict-cards`); `inlineInitialState(raw: string): InlineEnrichState`; `useInlineEnrich(raw: string, baseUrl?: string): InlineEnrichState`; `InlineLookupStatus({state})`; where
  `InlineEnrichState = {kind:'idle'} | {kind:'checking';indicator} | {kind:'ok';indicator;data:VerdictData} | {kind:'declined';indicator;reason} | {kind:'unavailable';indicator;reason} | {kind:'unsupported';indicator}`.

- [ ] **Step 1: Move `useEffectiveTheme` into shared.** `git mv web/src/components/lookup/useEffectiveTheme.ts shared/verdict-cards/useEffectiveTheme.ts`. Its imports (`@socdesk/shared/lib/theme`) are unchanged. Add `export { useEffectiveTheme } from './useEffectiveTheme'` and `export type { EffectiveTheme } from './useEffectiveTheme'` to `shared/verdict-cards/index.ts`.

- [ ] **Step 2: Rewire the 4 web importers.** In `web/src/components/analyzer/InlineLookup.tsx`, `web/src/components/cockpit/ResultRegion.tsx`, `web/src/routes/Lookup.tsx`, `web/src/routes/Overview.tsx`, replace `from '../lookup/useEffectiveTheme'` / `from '../components/lookup/useEffectiveTheme'` with `from '@socdesk/shared/verdict-cards'`. (Grep: `grep -rl "lookup/useEffectiveTheme" web/src`.)

- [ ] **Step 3: Write the failing test** for the pure classifier (`shared/analyzer-ui/__tests__/useInlineEnrich.test.ts`):

```ts
import { describe, expect, it } from 'vitest'
import { inlineInitialState } from '../useInlineEnrich'

describe('inlineInitialState (the analyzer inline-lookup resolver)', () => {
  it('is idle for empty input', () => {
    expect(inlineInitialState('').kind).toBe('idle')
  })
  it('checks an enrichable IP (refanged)', () => {
    expect(inlineInitialState('45[.]9[.]148[.]20')).toEqual({ kind: 'checking', indicator: '45.9.148.20' })
  })
  it('checks an enrichable domain and URL', () => {
    expect(inlineInitialState('evil.test').kind).toBe('checking')
    expect(inlineInitialState('http://evil.test/a').kind).toBe('checking')
  })
  it('is unsupported for a CVE (not inline-enrichable) and for junk', () => {
    expect(inlineInitialState('CVE-2024-1234').kind).toBe('unsupported')
    expect(inlineInitialState('not an indicator ☺').kind).toBe('unsupported')
  })
})
```

- [ ] **Step 4: Run it, expect FAIL** (module missing): `cd web && npx vitest run ../shared/analyzer-ui/__tests__/useInlineEnrich.test.ts` → FAIL "Cannot find module '../useInlineEnrich'".

- [ ] **Step 5: Implement `shared/analyzer-ui/useInlineEnrich.ts`:**

```ts
import { useEffect, useState } from 'react'
import { detectType, isEnrichable, refang } from '@socdesk/shared/indicators'
import { fetchEnrich, type VerdictData } from '@socdesk/shared/verdict'

export type InlineEnrichState =
  | { kind: 'idle' }
  | { kind: 'checking'; indicator: string }
  | { kind: 'ok'; indicator: string; data: VerdictData }
  | { kind: 'declined'; indicator: string; reason: string }
  | { kind: 'unavailable'; indicator: string; reason: string }
  | { kind: 'unsupported'; indicator: string }

/** Pure first state: only an enrichable indicator triggers a fetch; anything
 *  else (empty / CVE / email / unclassifiable) is terminal. Extracted so the
 *  classification is testable without rendering the hook. */
export function inlineInitialState(raw: string): InlineEnrichState {
  const indicator = raw ? refang(raw) : ''
  if (!indicator) return { kind: 'idle' }
  return isEnrichable(detectType(indicator))
    ? { kind: 'checking', indicator }
    : { kind: 'unsupported', indicator }
}

/** Resolve ONE extracted IOC to a card-ready state through the shared enrich
 *  client. `baseUrl` selects the origin (same-origin on the web, the configured
 *  SOCDesk origin in the extension). Only `indicator` — never any surrounding
 *  script — reaches /api/enrich. */
export function useInlineEnrich(raw: string, baseUrl?: string): InlineEnrichState {
  const [state, setState] = useState<InlineEnrichState>(() => inlineInitialState(raw))
  useEffect(() => {
    const first = inlineInitialState(raw)
    setState(first)
    if (first.kind !== 'checking') return
    let live = true
    void fetchEnrich(detectType(first.indicator), first.indicator, baseUrl ? { baseUrl } : undefined).then((o) => {
      if (!live) return
      if (o.status === 'ok') setState({ kind: 'ok', indicator: first.indicator, data: o.data })
      else if (o.status === 'declined') setState({ kind: 'declined', indicator: first.indicator, reason: o.reason })
      else setState({ kind: 'unavailable', indicator: first.indicator, reason: o.reason })
    })
    return () => { live = false }
  }, [raw, baseUrl])
  return state
}
```

- [ ] **Step 6: Implement `shared/analyzer-ui/InlineLookupStatus.tsx`:**

```tsx
import { MicroLabel } from '@socdesk/shared/ui'
import { cx } from '@socdesk/shared/lib/cx'
import type { InlineEnrichState } from './useInlineEnrich'

/** Honest non-ok renderings for the inline IOC lookup (never a fabricated
 *  verdict). `idle`/`ok` return null — the caller renders those. */
export function InlineLookupStatus({ state }: { state: InlineEnrichState }) {
  if (state.kind === 'checking') {
    return (
      <div className="flex items-center gap-3 rounded-lg border border-line bg-panel p-4" role="status" aria-live="polite">
        <span aria-hidden="true" className="size-4 shrink-0 rounded-full border-2 border-line-bright border-t-accent motion-safe:animate-spin" />
        <span className="break-all font-mono text-xs text-muted">Checking {state.indicator}…</span>
      </div>
    )
  }
  if (state.kind === 'declined' || state.kind === 'unavailable' || state.kind === 'unsupported') {
    const amber = state.kind === 'declined'
    const title =
      state.kind === 'declined' ? 'The enrichment endpoint declined this indicator'
      : state.kind === 'unavailable' ? 'Live lookup is unavailable'
      : 'Not a live-enriched indicator'
    const body = state.kind === 'unsupported'
      ? 'Live lookup covers IPs, domains, URLs and file hashes.'
      : `${state.reason}.`
    return (
      <div className={cx('flex flex-col gap-1.5 rounded-lg border bg-panel p-4', amber ? 'border-[var(--edge-gold)]' : 'border-line')} role="status">
        <MicroLabel tone="faint">{state.kind}</MicroLabel>
        <p className={cx('font-display text-sm font-bold leading-snug', amber ? 'text-verdict-amber' : 'text-paper')}>{title}</p>
        <p className="text-xs leading-relaxed text-muted">{body}</p>
      </div>
    )
  }
  return null
}
```

- [ ] **Step 7: Run the test, expect PASS**, then the gate: `cd web && npx vitest run ../shared && npm --prefix web run build` (build clean confirms the useEffectiveTheme move + rewire).

- [ ] **Step 8: Commit** — `git add -A && git commit -m "feat(shared): card-theme hook + lean inline-enrich resolver for the analyzer"`

---

### Task 2: Move the analyzer UI into `shared/analyzer-ui/` (decouple InlineLookup)

**Files:**
- Create: `shared/analyzer-ui/index.ts`
- Move: `web/src/components/analyzer/{AnalyzerResult,DecodeLadder,TechniqueTally,ActionBullets,IocTable,InlineLookup}.tsx` + `usePsAnalysis.ts` → `shared/analyzer-ui/`
- Modify: the moved `InlineLookup.tsx`, `IocTable.tsx`, `AnalyzerResult.tsx` (baseUrl passthrough); `web/src/routes/PowerShellAnalyzer.tsx`, `web/src/components/cockpit/ResultRegion.tsx`, `web/src/components/cockpit/useCockpitInput.ts` (rewire imports)
- Delete: `web/src/components/analyzer/` (now empty) and the stale `web/src/components/lookup/` deps used only by the old InlineLookup, IF nothing else imports them (verify with grep; leave `useLookup.ts`/`LookupStates.tsx` — they still serve `/lookup`).

**Interfaces:**
- Consumes: `useInlineEnrich`, `InlineLookupStatus`, `useEffectiveTheme` (Task 1).
- Produces (from `@socdesk/shared/analyzer-ui`): `AnalyzerResult({result, baseUrl?})`, `usePsAnalysis(input): PsState`, `InlineLookup({raw, baseUrl?})`, plus `DecodeLadder`, `TechniqueTally`, `ActionBullets`, `IocTable({iocs, baseUrl?})`.

- [ ] **Step 1: Move the six straight components + the hook.** `git mv` each of `AnalyzerResult.tsx DecodeLadder.tsx TechniqueTally.tsx ActionBullets.tsx IocTable.tsx InlineLookup.tsx usePsAnalysis.ts` from `web/src/components/analyzer/` to `shared/analyzer-ui/`. Their `@socdesk/shared/*` and `./sibling` imports resolve unchanged in the new directory.

- [ ] **Step 2: Rewrite the moved `shared/analyzer-ui/InlineLookup.tsx`** to the lean resolver + `baseUrl`:

```tsx
import { EscalationCard, useEffectiveTheme } from '@socdesk/shared/verdict-cards'
import { useInlineEnrich } from './useInlineEnrich'
import { InlineLookupStatus } from './InlineLookupStatus'

/** One expanded IOC row's escalation. Resolves `raw` through the lean shared
 *  enrich path (only the clicked IOC reaches /api/enrich; never the analyzed
 *  script). `baseUrl` is same-origin on the web, the configured origin in the
 *  extension. */
export function InlineLookup({ raw, baseUrl }: { raw: string; baseUrl?: string }) {
  const state = useInlineEnrich(raw, baseUrl)
  const theme = useEffectiveTheme()
  if (state.kind === 'idle') return null
  if (state.kind === 'ok') return <EscalationCard data={state.data} theme={theme} baseUrl={baseUrl} />
  return <InlineLookupStatus state={state} />
}
```

- [ ] **Step 3: Thread `baseUrl` through `IocTable` and `AnalyzerResult`.** In `shared/analyzer-ui/IocTable.tsx`: change the signature to `IocTable({ iocs, baseUrl }: { iocs: ExtractedIoc[]; baseUrl?: string })` and pass `<InlineLookup raw={i.raw} baseUrl={baseUrl} />`. In `shared/analyzer-ui/AnalyzerResult.tsx`: change to `AnalyzerResult({ result, baseUrl }: { result: AnalysisResult; baseUrl?: string })` and pass `<IocTable iocs={result.iocs} baseUrl={baseUrl} />`.

- [ ] **Step 4: Create the barrel `shared/analyzer-ui/index.ts`:**

```ts
export { AnalyzerResult } from './AnalyzerResult'
export { usePsAnalysis, type PsState } from './usePsAnalysis'
export { DecodeLadder } from './DecodeLadder'
export { TechniqueTally } from './TechniqueTally'
export { ActionBullets } from './ActionBullets'
export { IocTable } from './IocTable'
export { InlineLookup } from './InlineLookup'
export { useInlineEnrich, inlineInitialState, type InlineEnrichState } from './useInlineEnrich'
export { InlineLookupStatus } from './InlineLookupStatus'
```

- [ ] **Step 5: Rewire the web consumers.** In `web/src/routes/PowerShellAnalyzer.tsx`, `web/src/components/cockpit/ResultRegion.tsx`, `web/src/components/cockpit/useCockpitInput.ts`: replace every `from '../components/analyzer/X'` / `from '../analyzer/X'` / `from './analyzer/X'` with `from '@socdesk/shared/analyzer-ui'`. (Grep: `grep -rl "components/analyzer\|/analyzer/AnalyzerResult\|/analyzer/usePsAnalysis" web/src`.) Delete the now-empty `web/src/components/analyzer/` directory.

- [ ] **Step 6: Verify no `web/src` import survived the lift.** Run `grep -rn "web/src\|\.\./\.\./routes\|views/useStateData\|hero/heroLayers\|routes/lookupModel" shared/analyzer-ui` → expect NO matches. If any appears, the decouple is incomplete — fix before proceeding.

- [ ] **Step 7: Run the gate:** `cd web && npx vitest run ../shared src && npm --prefix web run build`. Build clean + tests green = the `/analyzer` route and cockpit render the moved components unchanged.

- [ ] **Step 8: Commit** — `git add -A && git commit -m "feat(shared): lift the analyzer UI into shared/analyzer-ui, decouple inline lookup"`

---

### Task 3: Extension selection router + background wiring + manifest

**Files:**
- Modify: `shared/intent.ts` (add `routeSelection`), `extension/src/background.ts`, `extension/manifest.json`
- Test: `shared/__tests__/intent.test.ts` (or the existing intent test file — grep `grep -rl "classifyCockpitInput" shared/**/__tests__`)

**Interfaces:**
- Consumes: `classifyCockpitInput`, `isEnrichable`, `detectType`, `refang`.
- Produces: `routeSelection(raw: string): { mode: 'analyze' | 'lookup' | 'report'; q: string }`.

- [ ] **Step 1: Write the failing test** (append to the intent test file):

```ts
import { routeSelection } from '../intent' // adjust path to the test's location

describe('routeSelection (extension selection router — data-boundary guard)', () => {
  it('routes a command/script to the analyzer with the raw text', () => {
    expect(routeSelection('powershell -nop -w hidden -enc AAAA')).toEqual({
      mode: 'analyze', q: 'powershell -nop -w hidden -enc AAAA',
    })
    expect(routeSelection('cmd.exe /c for /f %e in (\'finger x@1.2.3.4\') do %e').mode).toBe('analyze')
  })
  it('routes an enrichable indicator to lookup, refanged', () => {
    expect(routeSelection('45[.]9[.]148[.]20')).toEqual({ mode: 'lookup', q: '45.9.148.20' })
    expect(routeSelection('evil.test').mode).toBe('lookup')
  })
  it('routes a CVE (indicator but not inline-enrichable) to the report tab', () => {
    expect(routeSelection('CVE-2024-1234').mode).toBe('report')
  })
  it('routes empty / unclassifiable to report', () => {
    expect(routeSelection('   ').mode).toBe('report')
  })
})
```

- [ ] **Step 2: Run it, expect FAIL** (`routeSelection` undefined).

- [ ] **Step 3: Implement `routeSelection` in `shared/intent.ts`** (beside `classifyCockpitInput`; import `isEnrichable`/`detectType`/`refang` if not already):

```ts
/** Route a right-clicked selection to an extension surface. `command` → the
 *  side-panel analyzer (with the RAW script — the analyzer preprocesses it, and
 *  it must never be refang-mangled or enriched); an enrichable `indicator` →
 *  the popup lookup (refanged); a non-enrichable indicator (CVE) or anything
 *  unclassifiable → the full report tab. This is the data-boundary decision:
 *  a `command` never becomes a `lookup`, so a script never reaches /api/enrich. */
export function routeSelection(raw: string): { mode: 'analyze' | 'lookup' | 'report'; q: string } {
  const trimmed = (raw || '').trim()
  if (!trimmed) return { mode: 'report', q: '' }
  const kind = classifyCockpitInput(trimmed)
  if (kind === 'command') return { mode: 'analyze', q: trimmed }
  if (kind === 'indicator') {
    const ind = refang(trimmed)
    return isEnrichable(detectType(ind)) ? { mode: 'lookup', q: ind } : { mode: 'report', q: ind }
  }
  return { mode: 'report', q: trimmed }
}
```

- [ ] **Step 4: Run the test, expect PASS:** `cd web && npx vitest run ../shared/**/intent.test.ts`.

- [ ] **Step 5: Add the `sidePanel` permission + entry to `extension/manifest.json`.** Add `"sidePanel"` to the `permissions` array, and a top-level key: `"side_panel": { "default_path": "panel.html" }`.

- [ ] **Step 6: Rewire `extension/src/background.ts`** to route via `routeSelection` and open the side panel on the gesture. Replace the `onClicked` listener body:

```ts
import { routeSelection } from '@socdesk/shared/intent'
// ...existing imports (refang, detectType, isEnrichable, normalizeOrigin, reportUrl, DEFAULT_ORIGIN) stay...

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId !== MENU_ID) return
  const route = routeSelection(info.selectionText || '')
  if (!route.q) return

  // ANALYZE — open the side panel ON THE GESTURE (open() must be called
  // synchronously in the listener; the stash is fire-and-forget and the panel
  // reads it on mount / via storage.onChanged).
  if (route.mode === 'analyze' && tab?.id != null && chrome.sidePanel?.open) {
    void chrome.storage.session.set({ pending: { mode: 'analyze', q: route.q, at: Date.now() } })
    void chrome.sidePanel.open({ tabId: tab.id })
    return
  }

  // LOOKUP / REPORT — the existing async flow (unchanged behaviour).
  void handleLookupOrReport(route)
})

async function handleLookupOrReport(route: { mode: 'lookup' | 'report' | 'analyze'; q: string }): Promise<void> {
  const origin = await getOrigin()
  if (route.mode !== 'lookup') return openReport(origin, route.q)
  try {
    await chrome.storage.session.set({ pending: { mode: 'lookup', q: route.q, type: detectType(route.q), at: Date.now() } })
  } catch { /* fall through */ }
  try {
    if (chrome.action.openPopup) { await chrome.action.openPopup(); return }
  } catch { /* degrade */ }
  openReport(origin, route.q)
}
```

  Keep `installMenu`, `getOrigin`, `openReport` as they are. The stored `pending` now carries a `mode` field (the popup in Task 5 reads it; add `mode?: 'lookup'` tolerance there).

- [ ] **Step 7: Run the gate:** `cd web && npx vitest run ../shared && npm --prefix extension run build` (build compiles the new import + background changes; no dist load yet).

- [ ] **Step 8: Commit** — `git add -A && git commit -m "feat(extension): route right-click selection to analyzer / lookup / report"`

---

### Task 4: Extension side-panel surface

**Files:**
- Create: `extension/panel.html`, `extension/src/panel/main.tsx`, `extension/src/panel/Panel.tsx`
- Modify: `extension/vite.config.ts` (add the `panel` entry); `extension/src/popup/Popup.tsx` (tolerate the `mode` field on `pending`)

**Interfaces:**
- Consumes: `AnalyzerResult`, `usePsAnalysis` (`@socdesk/shared/analyzer-ui`); `EscalationCard`, `detectTheme` (`@socdesk/shared/verdict-cards`); `routeSelection` (for the paste box); `DEFAULT_ORIGIN`, `normalizeOrigin` (`@socdesk/shared/indicators`).

- [ ] **Step 1: Create `extension/panel.html`** (mirror `popup.html`, wider default):

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>SOCDesk — Analyze</title>
</head>
<body>
  <div id="root"></div>
  <script type="module" src="/src/panel/main.tsx"></script>
</body>
</html>
```

- [ ] **Step 2: Create `extension/src/panel/main.tsx`** (mirror the popup entry):

```tsx
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import '../index.css'
import { initTheme } from '@socdesk/shared/lib/theme'
import { Panel } from './Panel'

initTheme()
createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Panel />
  </StrictMode>,
)
```

- [ ] **Step 3: Create `extension/src/panel/Panel.tsx`.** Reads the pending handoff (and `storage.onChanged`, since the panel may mount before the stash lands), resolves the origin, then renders the analyzer for a command or the escalation card for an indicator — a paste box re-routes with `routeSelection`. The analyzed script never leaves the browser; `baseUrl` on the card/IOC path selects the enrich origin.

```tsx
import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { DEFAULT_ORIGIN, detectType, normalizeOrigin, refang } from '@socdesk/shared/indicators'
import { routeSelection } from '@socdesk/shared/intent'
import { AnalyzerResult, usePsAnalysis } from '@socdesk/shared/analyzer-ui'
import { EscalationCard, detectTheme, type CanvasTheme } from '@socdesk/shared/verdict-cards'
import { fetchEnrich, type VerdictData } from '@socdesk/shared/verdict'
import { SdMonogram } from '@socdesk/shared/ui'

type Mode = { kind: 'idle' } | { kind: 'analyze'; script: string } | { kind: 'lookup'; q: string }

export function Panel() {
  const [origin, setOrigin] = useState(DEFAULT_ORIGIN)
  const [input, setInput] = useState('')
  const [mode, setMode] = useState<Mode>({ kind: 'idle' })
  const theme: CanvasTheme = detectTheme()
  const applied = useRef(false)

  const apply = useCallback((raw: string) => {
    const route = routeSelection(raw)
    setInput(raw)
    if (route.mode === 'analyze') setMode({ kind: 'analyze', script: route.q })
    else if (route.mode === 'lookup') setMode({ kind: 'lookup', q: route.q })
    else setMode({ kind: 'idle' })
  }, [])

  useEffect(() => {
    void (async () => {
      try {
        const { origin: stored } = (await chrome.storage.sync.get('origin')) as { origin?: string }
        setOrigin(normalizeOrigin(stored))
      } catch { /* default */ }
      const take = (p?: { mode?: string; q?: string }) => {
        if (applied.current || !p?.q) return
        applied.current = true
        void chrome.storage.session.remove('pending')
        apply(p.q)
      }
      try {
        const { pending } = (await chrome.storage.session.get('pending')) as { pending?: { mode?: string; q?: string } }
        take(pending)
      } catch { /* none */ }
      const onChanged = (changes: Record<string, chrome.storage.StorageChange>, area: string) => {
        if (area === 'session' && changes.pending?.newValue) take(changes.pending.newValue as { mode?: string; q?: string })
      }
      chrome.storage.onChanged.addListener(onChanged)
    })()
  }, [apply])

  const onSubmit = (e: FormEvent) => { e.preventDefault(); apply(input) }

  return (
    <div className="flex min-h-screen flex-col">
      <header className="flex items-center gap-2 border-b border-line px-4 py-3">
        <SdMonogram className="h-5 w-auto text-paper" />
        <span className="font-display text-sm font-bold tracking-tight text-paper">SOCDesk</span>
        <span className="ml-auto font-mono text-micro tracking-label text-faint">TLP:CLEAR</span>
      </header>
      <form onSubmit={onSubmit} className="px-4 pt-3">
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          spellCheck={false}
          rows={3}
          placeholder="Paste a command/script to analyze, or an indicator to look up"
          className="w-full resize-y rounded-md border border-line bg-field px-3 py-2 font-mono text-xs text-paper placeholder:text-faint focus-visible:border-line-bright"
        />
      </form>
      <main className="px-4 py-3">
        {mode.kind === 'idle' && (
          <p className="rounded-md border border-line bg-panel px-3 py-2.5 text-xs text-muted">
            Highlight a command in your console and choose <b className="font-semibold text-paper">Check in SOCDesk</b>, or paste above.
          </p>
        )}
        {mode.kind === 'analyze' && <AnalyzeBody script={mode.script} baseUrl={origin} />}
        {mode.kind === 'lookup' && <LookupBody q={mode.q} baseUrl={origin} theme={theme} />}
      </main>
    </div>
  )
}

function AnalyzeBody({ script, baseUrl }: { script: string; baseUrl: string }) {
  const state = usePsAnalysis(script)
  if (state.kind === 'analyzing' || state.kind === 'idle')
    return <p className="font-mono text-micro text-faint">Analyzing…</p>
  if (state.kind === 'error')
    return <p className="font-mono text-micro text-verdict-amber">Analysis failed: {state.message}</p>
  return <AnalyzerResult result={state.result} baseUrl={baseUrl} />
}

function LookupBody({ q, baseUrl, theme }: { q: string; baseUrl: string; theme: CanvasTheme }) {
  const [data, setData] = useState<VerdictData | null>(null)
  const [err, setErr] = useState<string | null>(null)
  useEffect(() => {
    let live = true
    setData(null); setErr(null)
    void fetchEnrich(detectType(refang(q)), refang(q), { baseUrl }).then((o) => {
      if (!live) return
      if (o.status === 'ok') setData(o.data)
      else setErr(o.reason)
    })
    return () => { live = false }
  }, [q, baseUrl])
  if (err) return <p className="font-mono text-micro text-verdict-amber">Lookup unavailable: {err}</p>
  if (!data) return <p className="font-mono text-micro text-faint">Checking {q}…</p>
  return <EscalationCard data={data} theme={theme} baseUrl={baseUrl} />
}
```

- [ ] **Step 4: Add the `panel` entry to `extension/vite.config.ts`.** In `build.rollupOptions.input`, add `panel: join(here, 'panel.html'),` beside `popup`/`options`/`background`. (The `entryFileNames` rule already hashes non-background entries; the emitted `dist/panel.html` is what `side_panel.default_path` references.)

- [ ] **Step 5: Make `extension/src/popup/Popup.tsx` tolerate the `mode` field.** The `Pending` interface gains `mode?: 'lookup'`; no behaviour change (the popup only ever receives `lookup` handoffs now). Confirm `tsc` accepts the added field.

- [ ] **Step 6: Run the gate:** `npm --prefix extension run build` clean; `cd web && npx vitest run ../shared` green (no shared regression).

- [ ] **Step 7: Commit** — `git add -A && git commit -m "feat(extension): side-panel analyzer surface (analyze + inline lookup)"`

---

### Task 5: Build the extension dist + integration verification

**Files:**
- Modify: `extension/dist/**` (the built artifact — committed), `extension/manifest.json` version bump, `extension/README.md` (document the analyzer + side panel)

- [ ] **Step 1: Bump the manifest version** `0.2.0` → `0.3.0` in `extension/manifest.json` (new user-facing capability).

- [ ] **Step 2: Full integrated gate.** Run, and confirm each is clean/green:
  - `npm --prefix web run build`
  - `cd web && npx vitest run ../shared src`
  - `npm --prefix extension run build`
  - `git status --porcelain` shows the rebuilt `extension/dist` + sources; nothing unexpected.

- [ ] **Step 3: Confirm the dist is a complete loadable MV3 extension.** Verify `extension/dist/manifest.json` contains `"sidePanel"` and `"side_panel": {"default_path": "panel.html"}`, and that `extension/dist/panel.html` exists and references a hashed `assets/panel-*.js`.

```bash
grep -o '"sidePanel"\|"side_panel"\|"default_path": *"panel.html"' extension/dist/manifest.json
test -f extension/dist/panel.html && echo "panel.html present"
```

- [ ] **Step 4: Update `extension/README.md`** — add a short "Analyze a script" section: highlight a command in a console → right-click "Check in SOCDesk" → the side panel analyzes it locally (the script never leaves the browser; only clicked IOCs enrich). Note the Chrome 116+ side-panel requirement and the popup/report-tab fallbacks.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "chore(extension): rebuild dist with the side-panel analyzer (v0.3.0)"`

- [ ] **Step 6: Manual acceptance (owner, documented, not automated).** Load `extension/dist` unpacked in Chrome 116+; on any page select `powershell -nop -w hidden -enc SQBFAF...` → right-click "Check in SOCDesk" → the side panel opens and shows the decode ladder + technique tally + kill-chain bullets + IOCs; select `45.9.148.20` → the popup shows the escalation card. Confirm (DevTools → Network) that no request body ever contains the script text.

---

## Notes for the executor

- **Do not** touch `web/src/components/lookup/useLookup.ts` or `LookupStates.tsx` — they still serve the `/lookup` route and the landing globe. Only the *analyzer's* inline lookup moves to the lean path.
- The shared test env is node (no DOM/React render). Test **pure** functions (`inlineInitialState`, `routeSelection`); React components are gated by `tsc -b` + `npm run build`, matching the repo's existing convention (`splitLead`, `coverageState`, `domainModel` are the precedent).
- `chrome.sidePanel.open()` MUST be called synchronously inside the `onClicked` listener (before any `await`) or Chrome rejects it as lacking a user gesture — see Task 3 Step 6.
