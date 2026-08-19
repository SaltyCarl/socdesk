# Polymorphic Cockpit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the SOCDesk cockpit (`/`, `web/src/routes/Overview.tsx`) polymorphic — classify a pasted indicator or PowerShell command and route it to enrichment or the local analyzer in the same docked result slot, closing the data-boundary leak where a pasted script could reach `/api/enrich`, and have the globe yield (visually and in its render loop) when the current result isn't geographic.

**Architecture:** A new pure classifier (`shared/intent.ts::classifyCockpitInput`) is the single data-boundary gate every submit path must call *before* `detectType` (`shared/indicators.ts`) ever sees the raw text — its un-anchored URL regex would otherwise misclassify a multi-line script whose first line is a download URL as a bare `'url'`. A new `useCockpitInput` hook composes the existing `useLookup` and `usePsAnalysis` hooks unconditionally (feeding the unselected one `''`, which each hook already short-circuits to `idle` for free), and a new `ResultRegion` component dispatches on the resulting `{kind, state}` discriminant to either the existing `EscalationCard`/`LookupStatus` pair or a newly-extracted `AnalyzerResult`/`PsStatus` pair, fully unmounting the previous surface on every kind flip via `key={kind}`. `Overview.tsx` is rewired onto this hook + region with a unified (post-Enter, never live-typed) submit; the omnibox morphs between a single-line `<input>` and an auto-growing `<textarea>` with a correctable mode chip; and the globe engine (`useGlobe3.ts`) gains `suspend()`/`resume()` so a geoless result stops the WebGL render loop instead of merely dimming behind CSS.

**Tech Stack:** React 19 + TypeScript (`web/`), Vite 8 + Tailwind v4, Vitest 3 (Node environment — no jsdom, no React Testing Library), three.js hero globe (`web/src/components/hero`), a framework-free `shared/` library consumed via the `@socdesk/shared/*` path alias (`web/tsconfig.app.json`).

**Spec:** `docs/superpowers/specs/2026-08-19-polymorphic-cockpit-design.md`

## Global Constraints

- **Unified submit.** One submit gesture — paste + **Enter**, or the omnibox arrow button — for BOTH the indicator and command paths. Classify, then run enrichment or analysis. `useLookup` has no debounce of its own, so a live-typed value must never reach it; only the **committed** (post-Enter/post-click) value is ever passed downstream.
- **Data boundary is load-bearing.** A pasted command must **never** reach `/api/enrich`. `classifyCockpitInput` (`shared/intent.ts`) MUST run and short-circuit before `detectType` gets anywhere near the raw text, at **every** submit path — the cockpit, the command palette, and the standalone `/lookup` route.
- **Reserved-colour / honesty doctrine unchanged.** Chips stay periwinkle; the gated characterization callout keeps its shipped red/amber. The cockpit introduces no new verdict hues. The mode chip is neutral/periwinkle — a fact about the input, never a verdict.
- **Attribution.** SaltyCarl, **ZERO AI attribution** on every commit — no `Co-Authored-By`, no Claude/agent reference, plain conventional-commit messages only.
- **§9 deferred items are OUT of scope for this plan.** Do not build: analyzer deep-link parity (`/analyzer#q=` consumer), `IocTable`'s "Look up →" in-place kind-flip, or the tabs-to-views IA pass.
- **Test commands (run from `web/`):**
  - Pure logic under `shared/**`: `npx vitest run ../shared` (or a narrower single-file path, e.g. `npx vitest run ../shared/intent.test.ts`).
  - Pure logic colocated under `web/src/**` (matches vitest's `src/**/*.test.ts` include — no DOM needed): `npx vitest run src/<path>/<file>.test.ts`.
  - Any `.tsx`/UI change: **there is no `web/` unit-test harness** (no jsdom, no React Testing Library configured). The gate is `npx tsc -b` clean, then `npm run build` clean. Each UI task states what the controller should dogfood manually on the built app.

---

### Task 1: `shared/intent.ts` — `classifyCockpitInput` (the data-boundary classifier)

**Files:**
- Create: `shared/intent.ts`
- Test: `shared/intent.test.ts`

**Interfaces:**
- Consumes: `detectType(q: string): IndicatorType` and `refang(s: unknown): string` from `./indicators` (`shared/indicators.ts:53`, `:67`).
- Produces: `export type CockpitInputKind = 'indicator' | 'command' | 'unclassified'` and `export function classifyCockpitInput(raw: string): CockpitInputKind`. Consumed by Task 4 (`useCockpitInput`), Task 7 (`CockpitOmnibox`/`ModeChip` live classification), and Task 9 (guarding both submit paths).

- [ ] **Step 1: Write the failing test file**

Create `shared/intent.test.ts`:

```ts
import { describe, expect, it } from 'vitest'
import { detectType, refang } from './indicators'
import { classifyCockpitInput } from './intent'

describe('classifyCockpitInput — indicator branch', () => {
  it('classifies a bare IPv4 as indicator', () => {
    expect(classifyCockpitInput('185.220.101.34')).toBe('indicator')
  })
  it('classifies a bare domain as indicator', () => {
    expect(classifyCockpitInput('evil-example.com')).toBe('indicator')
  })
  it('classifies a bare URL as indicator', () => {
    expect(classifyCockpitInput('https://example.com/path')).toBe('indicator')
  })
  it('classifies a bare MD5 hash as indicator', () => {
    expect(classifyCockpitInput('d41d8cd98f00b204e9800998ecf8427')).toBe('indicator')
  })
  it('classifies a bare CVE id as indicator', () => {
    expect(classifyCockpitInput('CVE-2024-12345')).toBe('indicator')
  })
})

describe('classifyCockpitInput — command branch', () => {
  it('classifies any multi-line paste as command', () => {
    expect(classifyCockpitInput('8.8.8.8\n1.1.1.1')).toBe('command')
  })
  it('classifies a PowerShell invocation token as command', () => {
    expect(classifyCockpitInput('IEX (New-Object Net.WebClient).DownloadString($u)')).toBe('command')
  })
  it('classifies -enc as command, case-insensitively', () => {
    expect(classifyCockpitInput('POWERSHELL -NOP -W HIDDEN -ENC JABzAGUA')).toBe('command')
  })
  it('classifies shell punctuation with >=2 tokens as command', () => {
    expect(classifyCockpitInput('echo hi; whoami')).toBe('command')
  })
  it('does NOT classify shell punctuation in a single token as command', () => {
    // one token, no whitespace — not a command line, and not indicator-shaped
    // either (no dot+TLD), so it falls through to unclassified.
    expect(classifyCockpitInput('a;b')).toBe('unclassified')
  })
  it('classifies powershell.exe as command, not as a bare domain', () => {
    // detectType's domain regex (indicators.ts:62) would otherwise match this
    // as a domain — the command check must run first and win.
    expect(classifyCockpitInput('powershell.exe')).toBe('command')
    expect(detectType(refang('powershell.exe'))).toBe('domain') // sanity: proves the ordering matters
  })
})

describe('classifyCockpitInput — data boundary (spec §2.1/§6)', () => {
  it('classifies a script whose first line is a download URL as command, never indicator', () => {
    const raw =
      'http://evil.example.com/stage1.ps1\npowershell -nop -w hidden -enc JABzAGUAYwB1AHIAZQBTAHQAcgBpAG4AZwA='
    expect(classifyCockpitInput(raw)).toBe('command')
    // Sanity: detectType alone (the old single-classifier path) misreads this
    // as a bare url, because its regex is prefix-only, not end-anchored —
    // exactly the leak classifyCockpitInput exists to short-circuit before.
    expect(detectType(refang(raw))).toBe('url')
  })
})

describe('classifyCockpitInput — unclassified + determinism', () => {
  it('classifies empty input as unclassified', () => {
    expect(classifyCockpitInput('')).toBe('unclassified')
  })
  it('classifies noise as unclassified', () => {
    expect(classifyCockpitInput('just some plain words')).toBe('unclassified')
  })
  it('is deterministic', () => {
    const raw = 'CVE-2024-12345'
    expect(classifyCockpitInput(raw)).toBe(classifyCockpitInput(raw))
  })
})
```

- [ ] **Step 2: Run the test, confirm it fails**

Run (from `web/`): `npx vitest run ../shared/intent.test.ts`
Expected: FAIL — `Cannot find module './intent'` (or equivalent resolution error; `shared/intent.ts` does not exist yet).

- [ ] **Step 3: Implement `shared/intent.ts`**

```ts
// intent.ts — the cockpit's DATA-BOUNDARY classifier: routes a pasted omnibox
// value to enrichment or the local analyzer before either surface ever sees
// it.
//
// This is the single source of truth every submit path MUST call BEFORE
// detectType (shared/indicators.ts) gets anywhere near the raw value.
// detectType alone is not safe here: its URL regex is prefix-only
// (`/^https?:\/\//i`, not end-anchored — indicators.ts:61), so a pasted
// script whose FIRST LINE is a download URL classifies as `'url'` under
// detectType alone, and the entire multi-line blob would be sent to the
// third-party /api/enrich endpoint as `?q=<full text>` (indicators.ts:110-112
// -> useLookup.ts:106 -> shared/verdict/client.ts:81-98). A pasted command
// must NEVER reach /api/enrich — classifyCockpitInput is the guard that makes
// that true.
//
// Pure, synchronous, no I/O — safe to call on every keystroke as well as on
// submit.

import { detectType, refang } from './indicators'

export type CockpitInputKind = 'indicator' | 'command' | 'unclassified'

/** Command/script tokens that only show up in a PowerShell or shell paste —
 *  never in a bare indicator. `invoke-\w+` covers Invoke-Expression's many
 *  cmdlet siblings (Invoke-WebRequest, Invoke-RestMethod, …) without listing
 *  them one by one. Word-bounded, so `powershell` also fires inside a bare
 *  LOLBin filename like `powershell.exe` (the `.` is a non-word boundary) —
 *  that is intentional: it stops that filename being misread as a domain by
 *  detectType's domain regex (indicators.ts:62). `rundll32.exe` is NOT
 *  covered by this token list (a known, lesser gap the design spec §2.1
 *  calls out and explicitly leaves out of v1 scope). */
const COMMAND_TOKEN_RE = /\b(powershell|pwsh|iex|invoke-expression|invoke-\w+|new-object)\b/i

/** `-e`, `-enc`, or `-encodedcommand` — PowerShell's Base64 payload flag in
 *  every abbreviation the interpreter accepts. */
const ENC_FLAG_RE = /-e(nc|ncodedcommand)?\b/i

/** Shell/PS punctuation that never appears in a bare indicator: statement
 *  separator, pipe, backtick (PowerShell's escape/obfuscation character), and
 *  a command-substitution open. On their own these are too common to trust
 *  (a URL query string can contain `|`) — they only count alongside >=2
 *  whitespace-separated tokens, i.e. something that reads as a command line
 *  rather than a single pasted value. */
const SHELL_PUNCT_RE = /[;|`]|\$\(/

function looksLikeCommand(raw: string): boolean {
  if (raw.includes('\n')) return true
  if (COMMAND_TOKEN_RE.test(raw)) return true
  if (ENC_FLAG_RE.test(raw)) return true
  if (SHELL_PUNCT_RE.test(raw)) {
    const tokenCount = raw.trim().split(/\s+/).filter(Boolean).length
    if (tokenCount >= 2) return true
  }
  return false
}

/**
 * Classify a raw omnibox value. Command wins ties — a value that is BOTH
 * command-shaped and indicator-shaped (e.g. `powershell.exe`, which also
 * satisfies detectType's domain regex) still resolves to `'command'`,
 * because the command check runs first and returns immediately. This
 * ordering is the data-boundary guarantee: detectType only ever sees a
 * value this function has already ruled out as a command.
 */
export function classifyCockpitInput(raw: string): CockpitInputKind {
  if (looksLikeCommand(raw)) return 'command'
  if (detectType(refang(raw)) !== '') return 'indicator'
  return 'unclassified'
}
```

- [ ] **Step 4: Run the test, confirm it passes**

Run (from `web/`): `npx vitest run ../shared/intent.test.ts`
Expected: PASS — all cases green.

- [ ] **Step 5: Commit**

```bash
git add shared/intent.ts shared/intent.test.ts
git commit -m "feat(cockpit): add classifyCockpitInput data-boundary classifier"
```

---

### Task 2: Consolidate `palette/classify.ts` onto `detectType`

**Files:**
- Modify: `web/src/components/palette/classify.ts:1-56` (full rewrite)
- Test: `web/src/components/palette/classify.test.ts` (new)

**Interfaces:**
- Consumes: `detectType(q: string): IndicatorType` from `@socdesk/shared/indicators` (`shared/indicators.ts:53`); `IndicatorType` from `./types` (`palette/types.ts:9`).
- Produces: `classifyIndicator(raw: string): IndicatorType` — **signature unchanged**, still consumed by `CommandPalette.tsx:130,140` and `commands.ts:111`. `INDICATOR_LABEL: Record<IndicatorType, string>` — unchanged, still consumed by `CommandPalette.tsx:411`.

- [ ] **Step 1: Write the failing test file**

Create `web/src/components/palette/classify.test.ts`:

```ts
import { describe, expect, it } from 'vitest'
import { detectType } from '@socdesk/shared/indicators'
import { classifyIndicator } from './classify'

describe('classifyIndicator — delegates to detectType (design spec §3.2)', () => {
  it('agrees with detectType on ipv4/ipv6 -> ip', () => {
    expect(classifyIndicator('185.220.101.34')).toBe('ip')
    expect(classifyIndicator('2001:db8::1')).toBe('ip')
  })
  it('agrees with detectType on hash lengths -> hash', () => {
    expect(classifyIndicator('d41d8cd98f00b204e9800998ecf8427')).toBe('hash') // md5
  })
  it('agrees with detectType on domain/url/cve', () => {
    expect(classifyIndicator('evil-example.com')).toBe('domain')
    expect(classifyIndicator('https://example.com/path')).toBe('url')
    expect(classifyIndicator('CVE-2024-12345')).toBe('cve')
  })
  it('a lone "/" is no longer classified as url (the previously-divergent case)', () => {
    // Old classify.ts: `s.includes('/')` -> 'url'. detectType has no such
    // rule (its url branch requires an http(s):// prefix) — consolidation
    // removes the looseness, so the two classifiers can no longer disagree.
    expect(classifyIndicator('/')).toBe('unknown')
    expect(detectType('/')).toBe('')
  })
  it('empty input is unknown', () => {
    expect(classifyIndicator('')).toBe('unknown')
  })
})
```

- [ ] **Step 2: Run the test, confirm it fails**

Run (from `web/`): `npx vitest run src/components/palette/classify.test.ts`
Expected: FAIL — `classifyIndicator('/')` currently returns `'url'` (the old `s.includes('/')` rule), not `'unknown'`.

- [ ] **Step 3: Rewrite `classify.ts` to delegate to `detectType`**

Replace the full contents of `web/src/components/palette/classify.ts`:

```ts
import type { IndicatorType } from './types'
import { detectType } from '@socdesk/shared/indicators'

/**
 * Lightweight indicator classifier for the palette's live badge. Delegates
 * ALL shape-detection to the shared `detectType` (the same classifier the
 * cockpit's data-boundary check and useLookup use) so the palette can never
 * drift from the rest of the app again (design spec §2.2, §3.2). This
 * function only maps detectType's richer taxonomy onto the palette's badge
 * enum — it adds no detection logic of its own.
 */

const TYPE_MAP: Record<string, IndicatorType> = {
  ipv4: 'ip',
  ipv6: 'ip',
  domain: 'domain',
  url: 'url',
  md5: 'hash',
  sha1: 'hash',
  sha256: 'hash',
  cve: 'cve',
  email: 'unknown', // no palette badge for email — not part of this taxonomy
  '': 'unknown',
}

export function classifyIndicator(raw: string): IndicatorType {
  const s = raw.trim()
  if (!s) return 'unknown'
  return TYPE_MAP[detectType(s)] ?? 'unknown'
}

/** Short uppercase badge shown on indicator rows. */
export const INDICATOR_LABEL: Record<IndicatorType, string> = {
  ip: 'IP',
  domain: 'DOMAIN',
  url: 'URL',
  hash: 'HASH',
  cve: 'CVE',
  unknown: 'IOC',
}
```

- [ ] **Step 4: Run the test, confirm it passes**

Run (from `web/`): `npx vitest run src/components/palette/classify.test.ts`
Expected: PASS.

- [ ] **Step 5: Typecheck the consumers**

Run (from `web/`): `npx tsc -b`
Expected: clean — `CommandPalette.tsx` and `commands.ts` call `classifyIndicator`/`INDICATOR_LABEL` with the same signatures.

- [ ] **Step 6: Commit**

```bash
git add web/src/components/palette/classify.ts web/src/components/palette/classify.test.ts
git commit -m "refactor(palette): consolidate classifyIndicator onto detectType"
```

---

### Task 3: Extract `AnalyzerResult` component (UI — tsc/build gate)

**Files:**
- Create: `web/src/components/analyzer/AnalyzerResult.tsx`
- Modify: `web/src/routes/PowerShellAnalyzer.tsx:1-44` (full rewrite)

**Interfaces:**
- Consumes: `AnalysisResult` (`shared/analyzer/types.ts:62-73`), `Chip` (`@socdesk/shared/ui`), `DecodeLadder({layers})`, `IocTable({iocs})`, `TechniqueTally({signals, characterization})` (existing, unchanged).
- Produces: `AnalyzerResult({ result: AnalysisResult }): JSX.Element` — consumed by Task 5 (`ResultRegion`) and by `PowerShellAnalyzer.tsx`.

- [ ] **Step 1: Create `AnalyzerResult.tsx`**

```tsx
import { Chip } from '@socdesk/shared/ui'
import type { AnalysisResult } from '@socdesk/shared/analyzer'
import { DecodeLadder } from './DecodeLadder'
import { IocTable } from './IocTable'
import { TechniqueTally } from './TechniqueTally'

/** The analyzer's result composition — flag chips + the technique tally +
 *  the decode ladder + the extracted-IOC table. Extracted from
 *  PowerShellAnalyzer.tsx (the `/analyzer` route) so the cockpit's
 *  ResultRegion can render the exact same surface for a `command`-classified
 *  submission (design spec §3.4). Prop-driven, no local state — both callers
 *  own their own `usePsAnalysis` hook and pass down only the resolved
 *  `AnalysisResult`. */
export function AnalyzerResult({ result }: { result: AnalysisResult }) {
  return (
    <div className="flex flex-col gap-4">
      {result.flags.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {result.flags.map((f) => (
            <Chip key={f.flag} variant="neutral">{f.flag}</Chip>
          ))}
        </div>
      )}
      <TechniqueTally signals={result.signals} characterization={result.characterization} />
      <DecodeLadder layers={result.layers} />
      <IocTable iocs={result.iocs} />
    </div>
  )
}
```

- [ ] **Step 2: Refactor `PowerShellAnalyzer.tsx` to use it**

Replace the full contents of `web/src/routes/PowerShellAnalyzer.tsx`:

```tsx
import { useState } from 'react'
import { AnalyzerResult } from '../components/analyzer/AnalyzerResult'
import { usePsAnalysis } from '../components/analyzer/usePsAnalysis'

export function PowerShellAnalyzer() {
  const [input, setInput] = useState('')
  const state = usePsAnalysis(input)
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-1">
        <span className="font-mono text-micro uppercase tracking-label text-faint">PowerShell analyzer</span>
        <h1 className="font-display text-xl font-bold text-paper">Paste a PowerShell command</h1>
        <p className="text-xs text-muted">Deterministic, client-side, never executed. Decodes it and extracts IOCs you can look up.</p>
      </div>
      <textarea
        value={input}
        onChange={(e) => setInput(e.target.value)}
        spellCheck={false}
        placeholder="powershell -nop -w hidden -enc …"
        aria-label="PowerShell command"
        className="min-h-28 w-full rounded-md border border-line bg-field p-3 font-mono text-xs text-paper placeholder:text-faint focus-visible:border-line-bright"
      />
      {state.kind === 'analyzing' && <p className="font-mono text-micro text-faint">Analyzing…</p>}
      {state.kind === 'error' && <p className="font-mono text-xs text-muted">Could not analyze: {state.message}</p>}
      {state.kind === 'ok' && <AnalyzerResult result={state.result} />}
    </div>
  )
}
```

- [ ] **Step 3: Typecheck**

Run (from `web/`): `npx tsc -b`
Expected: clean. (`Chip` is no longer imported by `PowerShellAnalyzer.tsx` — confirm no unused-import error; it moved to `AnalyzerResult.tsx`.)

- [ ] **Step 4: Build**

Run (from `web/`): `npm run build`
Expected: clean production build.

- [ ] **Step 5: Dogfood note (for the controller, on the built app)**

Visit `/analyzer`, paste `powershell -nop -w hidden -enc JABzAGUA`, confirm the result (flags, technique tally, decode ladder, IOC table) renders identically to before the extraction — no visual or behavioural change.

- [ ] **Step 6: Commit**

```bash
git add web/src/components/analyzer/AnalyzerResult.tsx web/src/routes/PowerShellAnalyzer.tsx
git commit -m "refactor(analyzer): extract AnalyzerResult from the PowerShellAnalyzer route"
```

---

### Task 4: `useCockpitInput` hook

**Files:**
- Create: `web/src/components/cockpit/useCockpitInput.ts`
- Test: `web/src/components/cockpit/useCockpitInput.test.ts`

**Interfaces:**
- Consumes: `classifyCockpitInput`, `CockpitInputKind` (`shared/intent.ts`, Task 1); `useLookup(rawIndicator: string): LookupState` (`web/src/components/lookup/useLookup.ts:64`, `LookupState` at `:37-45`); `usePsAnalysis(input: string): PsState` (`web/src/components/analyzer/usePsAnalysis.ts:13`, `PsState` at `:5-9`).
- Produces: `export type CockpitResult = {kind:'indicator';state:LookupState} | {kind:'command';state:PsState} | {kind:'unclassified';state:{kind:'idle'}}`; `export function resolveCockpitArgs(kind: CockpitInputKind, submitted: string): {indicatorArg: string; commandArg: string}`; `export function useCockpitInput(submitted: string, override?: 'indicator' | 'command' | null): CockpitResult`. `CockpitResult` and `useCockpitInput` are consumed by Task 5 (`ResultRegion`) and Task 6/7 (`Overview.tsx`). The `override` parameter exists from the start so Task 7's correctable mode chip does not require a later signature change.

- [ ] **Step 1: Write the failing test file**

Create `web/src/components/cockpit/useCockpitInput.test.ts`:

```ts
import { describe, expect, it } from 'vitest'
import { resolveCockpitArgs } from './useCockpitInput'

describe('resolveCockpitArgs — the unselected hook gets "" (design spec §3.3)', () => {
  it('routes the committed value to useLookup and "" to usePsAnalysis when kind is indicator', () => {
    expect(resolveCockpitArgs('indicator', '185.220.101.34')).toEqual({
      indicatorArg: '185.220.101.34',
      commandArg: '',
    })
  })
  it('routes the committed value to usePsAnalysis and "" to useLookup when kind is command', () => {
    const raw = 'powershell -enc JABzAGUA'
    expect(resolveCockpitArgs('command', raw)).toEqual({
      indicatorArg: '',
      commandArg: raw,
    })
  })
  it('routes "" to both hooks when kind is unclassified — neither hook does work', () => {
    expect(resolveCockpitArgs('unclassified', 'just some plain words')).toEqual({
      indicatorArg: '',
      commandArg: '',
    })
  })
})
```

- [ ] **Step 2: Run the test, confirm it fails**

Run (from `web/`): `npx vitest run src/components/cockpit/useCockpitInput.test.ts`
Expected: FAIL — `Cannot find module './useCockpitInput'`.

- [ ] **Step 3: Implement `useCockpitInput.ts`**

```ts
// useCockpitInput — the ONE hook that turns a committed omnibox value into a
// same-shaped result the cockpit renders, whichever surface it belongs to
// (design spec §3.3). Classifies with `classifyCockpitInput` (shared/intent.ts
// — the data-boundary guard, run BEFORE either downstream hook sees the raw
// value), then calls BOTH `useLookup` and `usePsAnalysis` unconditionally
// (rules-of-hooks) — the unselected one is fed `''`, which both hooks already
// short-circuit to their own `idle` state for free (useLookup.ts:52,
// usePsAnalysis.ts:16-17), so nothing extra is fetched or analyzed.
//
// `submitted` MUST be the COMMITTED (post-Enter) value, never the live-typed
// one — useLookup has no debounce of its own, so feeding it a live value
// would hammer /api/enrich on every keystroke (design spec §1, §7).
//
// `useCockpitInput` itself calls two real React hooks internally and so,
// like `useLookup`/`usePsAnalysis` (neither of which has a dedicated unit
// test in this repo), is not independently unit-tested — there is no
// jsdom/React Testing Library harness here. Its correctness rides on the
// pure `resolveCockpitArgs` routing step below (fully tested) plus the
// tsc/build gate on every task that consumes it.

import { classifyCockpitInput, type CockpitInputKind } from '@socdesk/shared/intent'
import { useLookup, type LookupState } from '../lookup/useLookup'
import { usePsAnalysis, type PsState } from '../analyzer/usePsAnalysis'

export type CockpitResult =
  | { kind: 'indicator'; state: LookupState }
  | { kind: 'command'; state: PsState }
  | { kind: 'unclassified'; state: { kind: 'idle' } }

/** Pure routing step: which committed value (if any) each downstream hook
 *  should receive for a given classified `kind`. Exported and unit-tested on
 *  its own (see useCockpitInput.test.ts). */
export function resolveCockpitArgs(
  kind: CockpitInputKind,
  submitted: string,
): { indicatorArg: string; commandArg: string } {
  return {
    indicatorArg: kind === 'indicator' ? submitted : '',
    commandArg: kind === 'command' ? submitted : '',
  }
}

/**
 * `override`, when set, wins over auto-detection for this submission — the
 * ModeChip's correction (design spec §3.7, Task 7). Defaults to auto-detect.
 */
export function useCockpitInput(
  submitted: string,
  override: 'indicator' | 'command' | null = null,
): CockpitResult {
  const kind: CockpitInputKind = override ?? classifyCockpitInput(submitted)
  const { indicatorArg, commandArg } = resolveCockpitArgs(kind, submitted)
  const lookupState = useLookup(indicatorArg)
  const psState = usePsAnalysis(commandArg)

  if (kind === 'indicator') return { kind, state: lookupState }
  if (kind === 'command') return { kind, state: psState }
  return { kind: 'unclassified', state: { kind: 'idle' } }
}
```

- [ ] **Step 4: Run the test, confirm it passes**

Run (from `web/`): `npx vitest run src/components/cockpit/useCockpitInput.test.ts`
Expected: PASS.

- [ ] **Step 5: Typecheck**

Run (from `web/`): `npx tsc -b`
Expected: clean. `useCockpitInput` is not yet consumed by any component — confirm no unused-export errors (exports are exempt from `noUnusedLocals`).

- [ ] **Step 6: Commit**

```bash
git add web/src/components/cockpit/useCockpitInput.ts web/src/components/cockpit/useCockpitInput.test.ts
git commit -m "feat(cockpit): add useCockpitInput hook"
```

---

### Task 5: `ResultRegion` (UI — tsc/build gate)

**Files:**
- Create: `web/src/components/cockpit/ResultRegion.tsx`

**Interfaces:**
- Consumes: `CockpitResult` (Task 4); `AnalyzerResult({result})` (Task 3); `EscalationCard({data, theme, onCompare})`, `CompareResult` (`shared/verdict-cards/index.ts` → `EscalationCard.tsx`, `CompareIp.tsx:32`); `LookupStatus({state})` (`web/src/components/lookup/LookupStates.tsx:71`); `lookupHash(query): string` (`web/src/components/palette/commands.ts:97`); `EffectiveTheme` (`web/src/components/lookup/useEffectiveTheme.ts`); `PsState` (`usePsAnalysis.ts:5-9`).
- Produces: `ResultRegion({cockpit, theme, onFullView, onCompare}): JSX.Element | null` — consumed by Task 6/7 (`Overview.tsx`).

- [ ] **Step 1: Create `ResultRegion.tsx`**

```tsx
import type { MouseEvent } from 'react'
import { EscalationCard, type CompareResult } from '@socdesk/shared/verdict-cards'
import { lookupHash } from '../palette/commands'
import { LookupStatus } from '../lookup/LookupStates'
import type { EffectiveTheme } from '../lookup/useEffectiveTheme'
import type { PsState } from '../analyzer/usePsAnalysis'
import { AnalyzerResult } from '../analyzer/AnalyzerResult'
import type { CockpitResult } from './useCockpitInput'

const FULL_VIEW_CLS =
  'inline-flex w-fit items-center gap-1 font-mono text-xs font-semibold text-accent underline-offset-2 outline-offset-2 hover:underline focus-visible:outline-2 focus-visible:outline-accent'

/** A light "Analyzing…" line for the command path — the same honest-status
 *  register as LookupStatus's Checking, but for the (synchronous, near-
 *  instant) analyzer. `idle` and `ok` are handled by the caller. */
function PsStatus({ state }: { state: Extract<PsState, { kind: 'analyzing' } | { kind: 'error' }> }) {
  if (state.kind === 'analyzing') {
    return <p className="font-mono text-micro text-faint">Analyzing…</p>
  }
  return <p className="font-mono text-xs text-muted">Could not analyze: {state.message}</p>
}

/**
 * The cockpit's mode-aware result slot (design spec §3.5) — replaces the old
 * hard `LandingResult` switch. Dispatches on `cockpit.kind` FIRST, then on
 * each hook's own state union:
 *
 *   indicator     -> EscalationCard (ok) | LookupStatus (checking/declined/
 *                    unavailable/unsupported), unchanged from the old
 *                    LandingResult, plus the "Full analyst view ->" deep link.
 *   command       -> AnalyzerResult (ok) | PsStatus (analyzing/error).
 *   unclassified  -> an honest one-line hint naming both accepted input kinds.
 *
 * The caller keys its wrapper on `key={cockpit.kind}` (Overview.tsx, Task 6)
 * so a kind flip fully unmounts the previous subtree — this is what stops
 * EscalationCard's CompareIp second-fetch from surviving a switch to the
 * analyzer and firing against stale state (design spec §2.3, §7).
 */
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
  if (cockpit.kind === 'indicator') {
    const { state } = cockpit
    if (state.kind === 'idle') return null
    const indicator = 'indicator' in state ? state.indicator : ''
    return (
      <div className="flex w-full max-w-md flex-col gap-3">
        {state.kind === 'ok' ? (
          <EscalationCard data={state.data} theme={theme} onCompare={onCompare} />
        ) : (
          <LookupStatus state={state} />
        )}
        {indicator && (
          <a
            href={`/lookup${lookupHash(indicator)}`}
            onClick={(e) => onFullView(e, indicator)}
            className={FULL_VIEW_CLS}
          >
            Full analyst view <span aria-hidden="true">→</span>
          </a>
        )}
      </div>
    )
  }

  if (cockpit.kind === 'command') {
    const { state } = cockpit
    if (state.kind === 'idle') return null
    if (state.kind === 'ok') return <AnalyzerResult result={state.result} />
    return <PsStatus state={state} />
  }

  // unclassified — an honest hint, never a fabricated result (reuses the
  // unrecognised voice from LookupStates.tsx:119-127). Only ever mounted
  // once something has been submitted — the caller gates on `isResult`.
  return (
    <p className="font-mono text-xs text-muted">
      Not a recognised indicator or command — paste an IP, domain, hash, URL, CVE, or a PowerShell
      command.
    </p>
  )
}
```

- [ ] **Step 2: Typecheck**

Run (from `web/`): `npx tsc -b`
Expected: clean. `ResultRegion` is not yet consumed by any route — confirm no unused-export errors.

- [ ] **Step 3: Build**

Run (from `web/`): `npm run build`
Expected: clean.

- [ ] **Step 4: Dogfood note (deferred — exercised once Task 6 wires it in)**

Note for the controller: once `Overview.tsx` (Task 6) mounts `ResultRegion` keyed on `cockpit.kind`, verify a kind flip (submit an IP, see the card; then submit a PowerShell command) fully replaces the DOM subtree rather than patching it — inspect via the browser dev tools that the previous card's nodes are gone, not hidden.

- [ ] **Step 5: Commit**

```bash
git add web/src/components/cockpit/ResultRegion.tsx
git commit -m "feat(cockpit): add mode-aware ResultRegion"
```

---

### Task 6: Cockpit rewiring (`Overview.tsx`) — hook + region, unified submit, `resultIsGeoless`

**Files:**
- Modify: `web/src/routes/Overview.tsx:1-303` (full rewrite)

**Interfaces:**
- Consumes: `useCockpitInput`, `CockpitResult` (Task 4); `ResultRegion` (Task 5); `geoPresent(result): boolean` (`web/src/components/hero/heroLayers.ts:295`); `GlobeApi` (`web/src/components/hero/useGlobe3.ts:289-299`, unchanged in this task — only `flyToLatLng`/`flyBack`/`drawArc`/`clearArc` are called here); `submitLookup(query)` (`palette/commands.ts:108`).
- Produces: a module-local `isGeolessResult(cockpit, submitted): boolean` helper and the `resultIsGeoless` boolean it drives — both consumed (extended, not redefined) by Task 8's globe-suspend wiring and by the `.is-geoless` CSS class Task 8 adds.

This task replaces the old `active: string` + `useLookup(active)` wiring and the inlined `LandingResult` function with `submitted` + `useCockpitInput` + `ResultRegion`. The omnibox stays a plain `<input>` for now — Task 7 replaces it with the morphing `CockpitOmnibox`.

- [ ] **Step 1: Rewrite `Overview.tsx`**

Replace the full contents of `web/src/routes/Overview.tsx`:

```tsx
import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import type { FormEvent, KeyboardEvent, MouseEvent, ReactNode } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import { MicroLabel } from '../components/ui'
import { SituationalBoard } from '../components/overview'
import type { CompareResult } from '@socdesk/shared/verdict-cards'
import type { GlobeApi } from '../components/hero/useGlobe3'
import { ENRICH_EVENT } from '../components/hero/enrichFly'
import { geoPresent, type EnrichApiResult } from '../components/hero/heroLayers'
import { submitLookup } from '../components/palette/commands'
import { useEffectiveTheme } from '../components/lookup/useEffectiveTheme'
import { useCockpitInput, type CockpitResult } from '../components/cockpit/useCockpitInput'
import { ResultRegion } from '../components/cockpit/ResultRegion'
// The hero-shell classes (.sdh-hero / .sdh-atmos / .sdh-enter*) must be present
// on FIRST paint — this route is synchronous, so importing the co-located CSS
// here puts them in the main bundle even though the globe canvas itself streams
// in later from the lazy chunk below.
import '../components/hero/globe.css'

/**
 * Overview (`/`) — the POLYMORPHIC cockpit: one omnibox classifies a pasted
 * indicator or PowerShell command and routes it to enrichment or the local
 * analyzer, rendering either result in the same docked slot beside the globe
 * (design spec, full document).
 */

const GlobeStage3 = lazy(() =>
  import('../components/hero/GlobeStage3').then((m) => ({ default: m.GlobeStage3 })),
)

const DEMO_INDICATORS = ['185.220.101.34', '1.1.1.1', '8.8.8.8']

const CHIP_CLS =
  'rounded-md border border-line bg-panel px-2.5 py-1 font-mono text-xs text-muted transition-colors duration-150 ease-brand hover:border-line-bright hover:text-paper focus-visible:outline-2 focus-visible:outline-accent'

// Standard enter used for the card reveal + the compact result brand line.
const REVEAL_CLS =
  'motion-safe:animate-[sd-rise_var(--duration-slow)_var(--ease-brand)_both]'

/** Whether the CURRENT cockpit result has no geography to land on: a command
 *  result, an unclassified submission, or an indicator that has resolved
 *  (past `checking`) without geo. `checking` stays non-geoless so the globe
 *  doesn't flicker dim before the outcome is known (design spec §3.6, §3.8). */
function isGeolessResult(cockpit: CockpitResult, submitted: string): boolean {
  if (cockpit.kind === 'command') return true
  if (cockpit.kind === 'unclassified') return submitted !== ''
  const state = cockpit.state
  if (state.kind === 'idle' || state.kind === 'checking') return false
  if (state.kind === 'ok') return !(state.raw && geoPresent(state.raw))
  return true // declined / unavailable / unsupported — no geo
}

export interface OverviewProps {
  kicker?: string
  title?: ReactNode
  subtitle?: ReactNode
}

export function Overview({
  kicker = 'Live threat surface',
  title,
  subtitle,
}: OverviewProps) {
  const apiRef = useRef<GlobeApi | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  // `submitted` is the COMMITTED (post-Enter) value that drives the result
  // region + the globe — empty string -> Idle. useCockpitInput classifies it
  // and runs the matching hook; the unselected hook is fed '' internally, so
  // only ONE round-trip (or zero, for a command) ever fires per submit.
  const [submitted, setSubmitted] = useState('')
  const theme = useEffectiveTheme()
  const cockpit = useCockpitInput(submitted)
  const isResult = cockpit.kind !== 'unclassified' || submitted !== ''
  const resultIsGeoless = isGeolessResult(cockpit, submitted)

  const brand = title ?? (
    <>
      IOC in. <span className="text-accent">OSINT</span> out.
    </>
  )

  // The globe only ever lands on an INDICATOR result with real geo. A command
  // or unclassified result — and any indicator state that isn't a geo-bearing
  // `ok` — flies the globe home so a stale landing never sits under a
  // mismatched result. `checking` is left alone (mirrors the old behaviour).
  useEffect(() => {
    const api = apiRef.current
    if (cockpit.kind === 'indicator') {
      const state = cockpit.state
      if (state.kind === 'ok' && state.raw && geoPresent(state.raw)) {
        document.dispatchEvent(new CustomEvent<EnrichApiResult>(ENRICH_EVENT, { detail: state.raw }))
      } else if (state.kind !== 'checking') {
        api?.flyBack()
      }
      return
    }
    api?.flyBack()
  }, [cockpit])

  const submit = (value: string) => setSubmitted(value.trim())

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault()
      submit(e.currentTarget.value)
    }
  }
  const onInput = (e: FormEvent<HTMLInputElement>) => {
    // Clearing the field returns the hero to Idle (globe flies home).
    if (e.currentTarget.value.trim() === '') setSubmitted('')
  }
  const flyDemo = (v: string) => {
    setSubmitted(v)
    if (inputRef.current) inputRef.current.value = v
  }

  // The full analyst console lives at /lookup. Left-click SPA-navigates there;
  // modified clicks keep the real href so it right-clicks / opens in a new tab.
  const openFullView = (e: MouseEvent<HTMLAnchorElement>, q: string) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return
    e.preventDefault()
    submitLookup(q)
  }

  const onCompareArc = (c: CompareResult | null) => {
    const api = apiRef.current
    if (!api) return
    if (c && c.first.precise && c.second.precise) {
      api.drawArc({ lat: c.first.lat, lng: c.first.lon }, { lat: c.second.lat, lng: c.second.lon })
    } else {
      api.clearArc()
    }
  }

  return (
    <div className="flex flex-col">
      <section
        className={cx(
          'sdh-hero relative py-16',
          isResult && 'is-result',
          resultIsGeoless && 'is-geoless',
        )}
      >
        <div className="sdh-atmos" aria-hidden="true" />

        <div className="relative z-[2] flex max-w-xl flex-col items-start">
          <MicroLabel tone="accent" tick className="sdh-enter sdh-enter-1">
            {kicker}
          </MicroLabel>

          <div
            className={cx(
              'grid w-full transition-[grid-template-rows] duration-[600ms] ease-brand motion-reduce:transition-none',
              isResult ? 'grid-rows-[0fr]' : 'grid-rows-[1fr]',
            )}
          >
            <div
              className={cx(
                'min-h-0 overflow-hidden transition-opacity duration-150 ease-brand motion-reduce:transition-none',
                isResult ? 'opacity-0' : 'opacity-100',
              )}
            >
              <div className="flex flex-col items-start gap-5 pt-5">
                <h1 className="sdh-enter sdh-enter-2 font-display text-display font-extrabold tracking-display text-paper">
                  {brand}
                </h1>
                <p className="sdh-enter sdh-enter-3 max-w-lg text-md text-muted">
                  {subtitle ??
                    'Reported malicious IPs and ransomware victim-countries, plotted from real sources. Enrich any indicator to get its attributed escalation card inline — and watch it land live on the globe. Drag to spin, scroll to zoom.'}
                </p>
              </div>
            </div>
          </div>

          {isResult && (
            <h2
              className={cx(
                'mt-5 font-display text-lg font-extrabold tracking-tight text-paper',
                REVEAL_CLS,
              )}
            >
              {brand}
            </h2>
          )}

          <div className="sdh-enter sdh-enter-4 mt-5 flex w-full max-w-md flex-col gap-3">
            <input
              ref={inputRef}
              type="text"
              inputMode="text"
              autoComplete="off"
              spellCheck={false}
              aria-label="Look up an indicator — get its escalation card inline and land it on the globe"
              placeholder="Enrich an IP / domain / hash — 185.220.101.34"
              onKeyDown={onKeyDown}
              onInput={onInput}
              className="w-full rounded-md border border-line bg-field px-3 py-2 font-mono text-base text-paper outline-offset-2 placeholder:text-faint focus-visible:outline-2 focus-visible:outline-accent"
            />
          </div>

          {isResult ? (
            <div
              key={submitted}
              role="region"
              aria-label="Cockpit result"
              className={cx('mt-6 w-full', REVEAL_CLS)}
            >
              <ResultRegion cockpit={cockpit} theme={theme} onFullView={openFullView} onCompare={onCompareArc} />
            </div>
          ) : (
            <div className="sdh-enter sdh-enter-4 mt-4 flex w-full max-w-md flex-wrap items-center gap-2">
              <span className="font-mono text-micro uppercase tracking-[0.14em] text-faint">
                Try
              </span>
              {DEMO_INDICATORS.map((v) => (
                <button key={v} type="button" onClick={() => flyDemo(v)} className={CHIP_CLS}>
                  {v}
                </button>
              ))}
            </div>
          )}
        </div>

        <Suspense fallback={null}>
          <GlobeStage3 apiRef={apiRef} />
        </Suspense>
      </section>

      <SituationalBoard />
    </div>
  )
}
```

- [ ] **Step 2: Typecheck**

Run (from `web/`): `npx tsc -b`
Expected: clean.

- [ ] **Step 3: Build**

Run (from `web/`): `npm run build`
Expected: clean.

- [ ] **Step 4: Dogfood note (for the controller, on the built app)**

Visit `/`. Submit `185.220.101.34` (Enter) — the `EscalationCard` renders and the globe lands. Submit `CVE-2026-9198` — the card renders, globe flies back, `.sdh-hero` carries `is-geoless` in dev tools (no visible CSS effect yet — that lands in Task 8). Paste a single-line PowerShell one-liner containing `-enc` and hit Enter — `ResultRegion` renders `AnalyzerResult`, not the escalation card; globe flies back. Clear the field — back to Idle/Try-chips.

- [ ] **Step 5: Commit**

```bash
git add web/src/routes/Overview.tsx
git commit -m "feat(cockpit): rewire Overview onto useCockpitInput and ResultRegion"
```

---

### Task 7: Input morph + mode chip (`CockpitOmnibox` + `ModeChip`)

**Files:**
- Create: `web/src/components/cockpit/ModeChip.tsx`
- Create: `web/src/components/cockpit/CockpitOmnibox.tsx`
- Modify: `web/src/routes/Overview.tsx` (full rewrite — builds on Task 6's version)

**Interfaces:**
- Consumes: `classifyCockpitInput` (Task 1); `classifyIndicator`, `INDICATOR_LABEL` (Task 2); `Chip` (`@socdesk/shared/ui`); `cx` (`@socdesk/shared/lib/cx`); `useCockpitInput` (Task 4, now called with its `override` argument).
- Produces: `ModeChip({value, override, onToggle}): JSX.Element`; `CockpitOmnibox({value, onChange, onSubmit}): JSX.Element` where `onSubmit: (value: string, kindOverride: 'indicator' | 'command' | null) => void` — both consumed only by `Overview.tsx`.

- [ ] **Step 1: Create `ModeChip.tsx`**

```tsx
import { Chip } from '@socdesk/shared/ui'
import { classifyCockpitInput } from '@socdesk/shared/intent'
import { classifyIndicator, INDICATOR_LABEL } from '../palette/classify'

/** The live-detected input kind, shown beside the omnibox — a FACT about the
 *  pasted text, never a verdict (periwinkle/neutral, design spec §8).
 *  Correctable: clicking toggles a manual override that wins over
 *  auto-detection for the next submit (spec §3.7, §7 — the misclassification
 *  mitigation). `override` is null when auto-detection is in force. */
export function ModeChip({
  value,
  override,
  onToggle,
}: {
  value: string
  override: 'indicator' | 'command' | null
  onToggle: () => void
}) {
  const autoKind = classifyCockpitInput(value)
  const kind = override ?? autoKind
  const label =
    kind === 'unclassified'
      ? '—'
      : kind === 'command'
        ? 'PowerShell'
        : INDICATOR_LABEL[classifyIndicator(value)]
  // Only offer the override toggle when there is a real call to correct — not
  // the honest '—' unclassified state.
  const correctable = kind !== 'unclassified'
  return (
    <button
      type="button"
      onClick={correctable ? onToggle : undefined}
      disabled={!correctable}
      aria-label={
        correctable
          ? `Detected as ${label} — click to switch to ${kind === 'command' ? 'indicator' : 'command'}`
          : 'No indicator or command detected yet'
      }
      className="shrink-0 disabled:cursor-default"
    >
      <Chip variant="neutral">{label}</Chip>
    </button>
  )
}
```

- [ ] **Step 2: Create `CockpitOmnibox.tsx`**

```tsx
import { useEffect, useRef, useState } from 'react'
import type { ChangeEvent, KeyboardEvent } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import { classifyCockpitInput } from '@socdesk/shared/intent'
import { ModeChip } from './ModeChip'

const FIELD_CLS =
  'w-full rounded-md border border-line bg-field px-3 py-2 font-mono text-base text-paper outline-offset-2 placeholder:text-faint focus-visible:outline-2 focus-visible:outline-accent'

const SUBMIT_BTN_CLS =
  'shrink-0 rounded-md border border-line bg-panel px-3 py-2 font-mono text-sm text-muted transition-colors duration-150 ease-brand hover:border-line-bright hover:text-paper focus-visible:outline-2 focus-visible:outline-accent'

export interface CockpitOmniboxProps {
  value: string
  onChange: (value: string) => void
  /** Fires on Enter or the arrow button. `kindOverride` carries a corrected
   *  ModeChip toggle (null when auto-detection is in force). */
  onSubmit: (value: string, kindOverride: 'indicator' | 'command' | null) => void
}

/**
 * The cockpit's single input control (design spec §3.7) — a one-line
 * `<input>` by default, morphing to a multi-line, auto-growing, monospace
 * `<textarea>` once the LIVE value is command-shaped (`classifyCockpitInput`
 * === 'command'). Both elements are fully CONTROLLED off the same `value`
 * prop, so the swap never loses what was typed/pasted — only the DOM node
 * identity changes (input and textarea are different element types, so React
 * always remounts the leaf on the swap); the focus effect below re-focuses
 * the textarea immediately after, so a mid-paste morph doesn't strand the
 * caret in the unmounted input.
 */
export function CockpitOmnibox({ value, onChange, onSubmit }: CockpitOmniboxProps) {
  const [override, setOverride] = useState<'indicator' | 'command' | null>(null)
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const isCommandShaped = classifyCockpitInput(value) === 'command'

  useEffect(() => {
    if (isCommandShaped) textareaRef.current?.focus()
  }, [isCommandShaped])

  const fire = () => {
    onSubmit(value, override)
    setOverride(null)
  }
  const onKeyDown = (e: KeyboardEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault()
      fire()
    }
  }
  const onInputChange = (e: ChangeEvent<HTMLInputElement>) => {
    onChange(e.target.value)
    setOverride(null) // a further edit invalidates a stale correction
  }
  const onTextareaChange = (e: ChangeEvent<HTMLTextAreaElement>) => {
    onChange(e.target.value)
    setOverride(null)
    const el = e.target
    el.style.height = 'auto'
    el.style.height = `${el.scrollHeight}px`
  }
  const toggleOverride = () => {
    const autoKind = classifyCockpitInput(value)
    const current = override ?? autoKind
    setOverride(current === 'command' ? 'indicator' : 'command')
  }

  return (
    <div className="flex w-full flex-col gap-2">
      <div className="flex items-start gap-2">
        {isCommandShaped ? (
          <textarea
            ref={textareaRef}
            value={value}
            onChange={onTextareaChange}
            onKeyDown={onKeyDown}
            spellCheck={false}
            rows={3}
            aria-label="Paste an indicator or a PowerShell command — get its escalation card or decode inline"
            placeholder="powershell -nop -w hidden -enc … or 185.220.101.34"
            className={cx(FIELD_CLS, 'min-h-24 resize-none overflow-hidden')}
          />
        ) : (
          <input
            type="text"
            inputMode="text"
            autoComplete="off"
            spellCheck={false}
            value={value}
            onChange={onInputChange}
            onKeyDown={onKeyDown}
            aria-label="Paste an indicator or a PowerShell command — get its escalation card or decode inline"
            placeholder="Enrich an IP / domain / hash, or paste a command — 185.220.101.34"
            className={FIELD_CLS}
          />
        )}
        <button type="button" onClick={fire} aria-label="Submit" className={SUBMIT_BTN_CLS}>
          →
        </button>
      </div>
      <ModeChip value={value} override={override} onToggle={toggleOverride} />
    </div>
  )
}
```

- [ ] **Step 3: Rewire `Overview.tsx` onto `CockpitOmnibox`**

Replace the full contents of `web/src/routes/Overview.tsx`:

```tsx
import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import type { MouseEvent, ReactNode } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import { MicroLabel } from '../components/ui'
import { SituationalBoard } from '../components/overview'
import type { CompareResult } from '@socdesk/shared/verdict-cards'
import type { GlobeApi } from '../components/hero/useGlobe3'
import { ENRICH_EVENT } from '../components/hero/enrichFly'
import { geoPresent, type EnrichApiResult } from '../components/hero/heroLayers'
import { submitLookup } from '../components/palette/commands'
import { useEffectiveTheme } from '../components/lookup/useEffectiveTheme'
import { useCockpitInput, type CockpitResult } from '../components/cockpit/useCockpitInput'
import { ResultRegion } from '../components/cockpit/ResultRegion'
import { CockpitOmnibox } from '../components/cockpit/CockpitOmnibox'
import '../components/hero/globe.css'

const GlobeStage3 = lazy(() =>
  import('../components/hero/GlobeStage3').then((m) => ({ default: m.GlobeStage3 })),
)

const DEMO_INDICATORS = ['185.220.101.34', '1.1.1.1', '8.8.8.8']

const CHIP_CLS =
  'rounded-md border border-line bg-panel px-2.5 py-1 font-mono text-xs text-muted transition-colors duration-150 ease-brand hover:border-line-bright hover:text-paper focus-visible:outline-2 focus-visible:outline-accent'

const REVEAL_CLS =
  'motion-safe:animate-[sd-rise_var(--duration-slow)_var(--ease-brand)_both]'

function isGeolessResult(cockpit: CockpitResult, submitted: string): boolean {
  if (cockpit.kind === 'command') return true
  if (cockpit.kind === 'unclassified') return submitted !== ''
  const state = cockpit.state
  if (state.kind === 'idle' || state.kind === 'checking') return false
  if (state.kind === 'ok') return !(state.raw && geoPresent(state.raw))
  return true
}

export interface OverviewProps {
  kicker?: string
  title?: ReactNode
  subtitle?: ReactNode
}

export function Overview({
  kicker = 'Live threat surface',
  title,
  subtitle,
}: OverviewProps) {
  const apiRef = useRef<GlobeApi | null>(null)
  const [liveValue, setLiveValue] = useState('')
  const [submitted, setSubmitted] = useState('')
  const [submittedOverride, setSubmittedOverride] = useState<'indicator' | 'command' | null>(null)
  const theme = useEffectiveTheme()
  const cockpit = useCockpitInput(submitted, submittedOverride)
  const isResult = cockpit.kind !== 'unclassified' || submitted !== ''
  const resultIsGeoless = isGeolessResult(cockpit, submitted)

  const brand = title ?? (
    <>
      IOC in. <span className="text-accent">OSINT</span> out.
    </>
  )

  useEffect(() => {
    const api = apiRef.current
    if (cockpit.kind === 'indicator') {
      const state = cockpit.state
      if (state.kind === 'ok' && state.raw && geoPresent(state.raw)) {
        document.dispatchEvent(new CustomEvent<EnrichApiResult>(ENRICH_EVENT, { detail: state.raw }))
      } else if (state.kind !== 'checking') {
        api?.flyBack()
      }
      return
    }
    api?.flyBack()
  }, [cockpit])

  const submit = (value: string, kindOverride: 'indicator' | 'command' | null) => {
    const trimmed = value.trim()
    setSubmitted(trimmed)
    setSubmittedOverride(trimmed ? kindOverride : null)
  }

  const onOmniboxChange = (v: string) => {
    setLiveValue(v)
    if (v.trim() === '') {
      setSubmitted('')
      setSubmittedOverride(null)
    }
  }

  const flyDemo = (v: string) => {
    setLiveValue(v)
    submit(v, null)
  }

  const openFullView = (e: MouseEvent<HTMLAnchorElement>, q: string) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return
    e.preventDefault()
    submitLookup(q)
  }

  const onCompareArc = (c: CompareResult | null) => {
    const api = apiRef.current
    if (!api) return
    if (c && c.first.precise && c.second.precise) {
      api.drawArc({ lat: c.first.lat, lng: c.first.lon }, { lat: c.second.lat, lng: c.second.lon })
    } else {
      api.clearArc()
    }
  }

  return (
    <div className="flex flex-col">
      <section
        className={cx(
          'sdh-hero relative py-16',
          isResult && 'is-result',
          resultIsGeoless && 'is-geoless',
        )}
      >
        <div className="sdh-atmos" aria-hidden="true" />

        <div className="relative z-[2] flex max-w-xl flex-col items-start">
          <MicroLabel tone="accent" tick className="sdh-enter sdh-enter-1">
            {kicker}
          </MicroLabel>

          <div
            className={cx(
              'grid w-full transition-[grid-template-rows] duration-[600ms] ease-brand motion-reduce:transition-none',
              isResult ? 'grid-rows-[0fr]' : 'grid-rows-[1fr]',
            )}
          >
            <div
              className={cx(
                'min-h-0 overflow-hidden transition-opacity duration-150 ease-brand motion-reduce:transition-none',
                isResult ? 'opacity-0' : 'opacity-100',
              )}
            >
              <div className="flex flex-col items-start gap-5 pt-5">
                <h1 className="sdh-enter sdh-enter-2 font-display text-display font-extrabold tracking-display text-paper">
                  {brand}
                </h1>
                <p className="sdh-enter sdh-enter-3 max-w-lg text-md text-muted">
                  {subtitle ??
                    'Reported malicious IPs and ransomware victim-countries, plotted from real sources. Enrich any indicator to get its attributed escalation card inline — and watch it land live on the globe. Drag to spin, scroll to zoom.'}
                </p>
              </div>
            </div>
          </div>

          {isResult && (
            <h2
              className={cx(
                'mt-5 font-display text-lg font-extrabold tracking-tight text-paper',
                REVEAL_CLS,
              )}
            >
              {brand}
            </h2>
          )}

          <div className="sdh-enter sdh-enter-4 mt-5 flex w-full max-w-md flex-col gap-3">
            <CockpitOmnibox value={liveValue} onChange={onOmniboxChange} onSubmit={submit} />
          </div>

          {isResult ? (
            <div
              key={submitted}
              role="region"
              aria-label="Cockpit result"
              className={cx('mt-6 w-full', REVEAL_CLS)}
            >
              <ResultRegion cockpit={cockpit} theme={theme} onFullView={openFullView} onCompare={onCompareArc} />
            </div>
          ) : (
            <div className="sdh-enter sdh-enter-4 mt-4 flex w-full max-w-md flex-wrap items-center gap-2">
              <span className="font-mono text-micro uppercase tracking-[0.14em] text-faint">
                Try
              </span>
              {DEMO_INDICATORS.map((v) => (
                <button key={v} type="button" onClick={() => flyDemo(v)} className={CHIP_CLS}>
                  {v}
                </button>
              ))}
            </div>
          )}
        </div>

        <Suspense fallback={null}>
          <GlobeStage3 apiRef={apiRef} />
        </Suspense>
      </section>

      <SituationalBoard />
    </div>
  )
}
```

- [ ] **Step 4: Typecheck**

Run (from `web/`): `npx tsc -b`
Expected: clean.

- [ ] **Step 5: Build**

Run (from `web/`): `npm run build`
Expected: clean.

- [ ] **Step 6: Dogfood note (for the controller, on the built app)**

Type a plain IP — single-line input, mode chip reads `IP`. Paste a 3-line PowerShell block — the box morphs to a textarea, mode chip reads `PowerShell`, the pasted text is intact and the textarea is focused. Click the mode chip before submitting to flip `IP`/`PowerShell` and confirm the override routes correctly on submit (e.g. force `powershell.exe` to be treated as `indicator` and see it hit `/lookup`'s honest-unsupported/checking state rather than the analyzer). Clear the field — back to Idle.

- [ ] **Step 7: Commit**

```bash
git add web/src/components/cockpit/ModeChip.tsx web/src/components/cockpit/CockpitOmnibox.tsx web/src/routes/Overview.tsx
git commit -m "feat(cockpit): add CockpitOmnibox input morph and correctable ModeChip"
```

---

### Task 8: Globe yield — `suspend()`/`resume()`, `.is-geoless` CSS, height flex

**Files:**
- Modify: `web/src/components/hero/useGlobe3.ts:289-299` (`GlobeApi` interface), `:324-335` (`apiHolder`/`apiRefStable` defaults), `:849-853` (near `stopLoop`), `:1037` (`apiHolder.current` assignment)
- Modify: `web/src/components/hero/globe.css:17-21` (`.sdh-hero` transition), `:441-444` (reduced-motion selector list), append new rules at end of file (after line 524)
- Modify: `web/src/routes/Overview.tsx` (small addition on top of Task 7's version)

**Interfaces:**
- Consumes: the mount effect's existing closures `stopLoop(): void`, `startLoop(): void`, `visible: boolean` (`useGlobe3.ts`, all pre-existing, unchanged).
- Produces: `GlobeApi.suspend(): void`, `GlobeApi.resume(): void` — consumed by `Overview.tsx`.

- [ ] **Step 1: Extend the `GlobeApi` interface**

Modify `web/src/components/hero/useGlobe3.ts:289-299`. Before:

```ts
export interface GlobeApi {
  /** Programmatic land on real coordinates (verdict tone optional). */
  flyToLatLng(lat: number, lng: number, opts?: { tier?: Tier; sev?: number }): void
  /** Return home (also fired by Escape). */
  flyBack(): void
  /** Draw the great-circle route between two real coordinates + a marker at B,
   *  and rotate it into view. Used by the landing Compare-IP result. */
  drawArc(a: { lat: number; lng: number }, b: { lat: number; lng: number }): void
  /** Remove the compare arc + marker and resume the idle spin. */
  clearArc(): void
}
```

After:

```ts
export interface GlobeApi {
  /** Programmatic land on real coordinates (verdict tone optional). */
  flyToLatLng(lat: number, lng: number, opts?: { tier?: Tier; sev?: number }): void
  /** Return home (also fired by Escape). */
  flyBack(): void
  /** Draw the great-circle route between two real coordinates + a marker at B,
   *  and rotate it into view. Used by the landing Compare-IP result. */
  drawArc(a: { lat: number; lng: number }, b: { lat: number; lng: number }): void
  /** Remove the compare arc + marker and resume the idle spin. */
  clearArc(): void
  /** Stop the render loop without losing state — used when the current
   *  cockpit result has no geography to show (design spec §3.8). Safe to
   *  call repeatedly. */
  suspend(): void
  /** Restart the render loop, but only if the globe is still on-screen
   *  (mirrors the IntersectionObserver gate the mount effect already uses). */
  resume(): void
}
```

- [ ] **Step 2: Extend the default/forwarding API objects**

Modify `web/src/components/hero/useGlobe3.ts:324-335`. Before:

```ts
  const apiHolder = useRef<GlobeApi>({
    flyToLatLng: () => {},
    flyBack: () => {},
    drawArc: () => {},
    clearArc: () => {},
  })
  const apiRefStable = useRef<GlobeApi>({
    flyToLatLng: (...a) => apiHolder.current.flyToLatLng(...a),
    flyBack: (...a) => apiHolder.current.flyBack(...a),
    drawArc: (...a) => apiHolder.current.drawArc(...a),
    clearArc: (...a) => apiHolder.current.clearArc(...a),
  })
```

After:

```ts
  const apiHolder = useRef<GlobeApi>({
    flyToLatLng: () => {},
    flyBack: () => {},
    drawArc: () => {},
    clearArc: () => {},
    suspend: () => {},
    resume: () => {},
  })
  const apiRefStable = useRef<GlobeApi>({
    flyToLatLng: (...a) => apiHolder.current.flyToLatLng(...a),
    flyBack: (...a) => apiHolder.current.flyBack(...a),
    drawArc: (...a) => apiHolder.current.drawArc(...a),
    clearArc: (...a) => apiHolder.current.clearArc(...a),
    suspend: (...a) => apiHolder.current.suspend(...a),
    resume: (...a) => apiHolder.current.resume(...a),
  })
```

- [ ] **Step 3: Define `suspend`/`resume` beside `stopLoop`, and wire them into `apiHolder.current`**

Modify `web/src/components/hero/useGlobe3.ts` — insert immediately after the `stopLoop` function (`:849-853`):

```ts
    function stopLoop(): void {
      running = false
      if (raf) cancelAnimationFrame(raf)
      raf = 0
    }
    /** Suspend the loop entirely — a geoless cockpit result stops the globe
     *  animating instead of merely dimming it behind CSS (design spec §3.8:
     *  IntersectionObserver-based gating doesn't see a CSS opacity change, so
     *  without this the loop keeps burning GPU behind the .is-geoless dim). */
    function suspend(): void {
      stopLoop()
    }
    /** Resume, but only if the globe is still on-screen — mirrors the
     *  existing onVisibility gate below (`if (document.hidden) stopLoop();
     *  else if (visible) startLoop()`). */
    function resume(): void {
      if (visible) startLoop()
    }
```

Then modify the `apiHolder.current` assignment at `:1037`. Before:

```ts
    apiHolder.current = { flyToLatLng, flyBack, drawArc, clearArc }
```

After:

```ts
    apiHolder.current = { flyToLatLng, flyBack, drawArc, clearArc, suspend, resume }
```

- [ ] **Step 4: Typecheck `useGlobe3.ts` in isolation**

Run (from `web/`): `npx tsc -b`
Expected: clean.

- [ ] **Step 5: Add the `.is-geoless` demotion CSS**

Modify `web/src/components/hero/globe.css`. Append at the end of the file (after the existing `@media (min-width: 1024px) { .sdh-hero.is-result .sdh-wrap { top: min(50%, 44vh) } }` block, so specificity/source-order makes this win when both apply):

```css

/* ==========================================================================
   GEOLESS RESULT (.sdh-hero.is-geoless) — the current result has no
   geography to land on (a command result, an unclassified submission, or a
   resolved indicator without geo — design spec §3.6, §3.8). Demote the globe
   to the same faint, repositioned corner backdrop the narrow layout already
   uses, but REGARDLESS of viewport width — a wide-desktop analyzer result
   gets the demotion too, not just a stacked mobile card. Kept as its OWN
   selector (not folded into `.is-result`, which stays "has a result" and
   only drives the intro fold) so the two concerns never fight over the same
   rule at the same breakpoint. Placed last in the file so it wins the
   specificity tie against the `.is-result` desktop centring rule above.
   ========================================================================== */
.sdh-hero.is-geoless .sdh-wrap {
  top: 8%;
  right: -28%;
  transform: none;
  opacity: 0.16;
  pointer-events: none;
}
.sdh-hero.is-geoless .sdh-hint,
.sdh-hero.is-geoless .sdh-tip {
  display: none;
}
```

- [ ] **Step 6: Relax the hero height clamp for result mode (height flex)**

Modify `web/src/components/hero/globe.css:17-21`. Before:

```css
.sdh-hero {
  position: relative;
  overflow: visible;
  min-height: clamp(460px, 62vh, 680px);
}
```

After:

```css
.sdh-hero {
  position: relative;
  overflow: visible;
  min-height: clamp(460px, 62vh, 680px);
  transition: min-height 0.3s var(--ease-brand);
}
```

Then, in the same file, add the following rule directly after the `.is-geoless` block from Step 5 (still at the end of the file):

```css

/* Result mode may need to grow taller than the idle clamp's 680px ceiling —
   the full-width analyzer stack (flag chips + technique tally + decode
   ladder + IOC table) is open-ended in length. Relax the UPPER bound so a
   tall result grows the hero smoothly instead of straining against a ceiling
   sized for a compact escalation card; the 460px FLOOR is untouched, so an
   idle or short (indicator) result still holds its intended minimum height
   (design spec §3.9). */
.sdh-hero.is-result {
  min-height: max(460px, 62vh);
}
```

Then modify the reduced-motion block at `:441-444`. Before:

```css
  .sdh-stage,
  .sdh-tip {
    transition: none !important;
  }
```

After:

```css
  .sdh-hero,
  .sdh-stage,
  .sdh-tip {
    transition: none !important;
  }
```

- [ ] **Step 7: Wire `suspend`/`resume` into `Overview.tsx`**

Modify `web/src/routes/Overview.tsx` (the version from Task 7) — insert a new effect immediately after the existing fly-back effect (the one keyed on `[cockpit]`):

```tsx
  // Loop cost: a geoless result stops the render loop instead of merely
  // dimming it behind CSS — IntersectionObserver-based gating doesn't see a
  // CSS opacity change, so without this the globe would keep burning GPU
  // behind the .is-geoless dim (design spec §2.4, §3.8).
  useEffect(() => {
    if (resultIsGeoless) apiRef.current?.suspend()
    else apiRef.current?.resume()
  }, [resultIsGeoless])
```

- [ ] **Step 8: Typecheck**

Run (from `web/`): `npx tsc -b`
Expected: clean.

- [ ] **Step 9: Build**

Run (from `web/`): `npm run build`
Expected: clean.

- [ ] **Step 10: Dogfood note (for the controller, on the built app)**

Submit a PowerShell command — confirm the globe visibly dims and slides to the top-right corner (`.is-geoless` applied) AND stops animating (open dev tools, confirm no repeated `requestAnimationFrame` churn — e.g. via the Performance panel or a temporary `console.count` in `frame()`). Submit a geo-bearing IP afterward — confirm the globe un-dims, re-centres, and resumes spinning/landing. Trigger a long `AnalyzerResult` (many IOCs/layers) and confirm the hero grows smoothly without a hard snap at ~680px, while a short CVE/idle state still holds a sensible minimum height.

- [ ] **Step 11: Commit**

```bash
git add web/src/components/hero/useGlobe3.ts web/src/components/hero/globe.css web/src/routes/Overview.tsx
git commit -m "feat(hero): add globe suspend/resume, geoless demotion CSS, and height flex"
```

---

### Task 9: Guard both submit paths — close the data-boundary leak everywhere

**Files:**
- Modify: `web/src/components/palette/commands.ts:1-4` (imports), `:108-113` (`submitLookup` body)
- Modify: `web/src/routes/Lookup.tsx:18-33` (imports), `:152-158` (`runLookup` body)

**Interfaces:**
- Consumes: `classifyCockpitInput` (Task 1); `navigate(href: string): void` (`palette/commands.ts:120-127`, pre-existing — now also imported into `Lookup.tsx`).
- Produces: nothing new. This task is the closing move of the data-boundary fix: `shared/intent.ts` (Task 1) is the classifier, but `commands.ts::submitLookup` (used by the command palette's lookup row, `CommandPalette.tsx:267,296`) and `Lookup.tsx::runLookup` (the standalone `/lookup` route's own search box) are the two remaining places raw text can reach `useLookup`/`detectType` **without ever going through `useCockpitInput`**. Both must apply the guard or the fix is partial (design spec §2.2, §7: "Two submit paths — both must get the guard or the data-boundary fix is partial").

- [ ] **Step 1: Guard `commands.ts::submitLookup`**

Modify `web/src/components/palette/commands.ts:1-4`. Before:

```ts
import type { CommandItem } from './types'
import { classifyIndicator } from './classify'
import { clearRecents, pushRecent } from './recents'
import { applyThemePref, resolveTheme } from '@socdesk/shared/lib/theme'
```

After:

```ts
import type { CommandItem } from './types'
import { classifyIndicator } from './classify'
import { classifyCockpitInput } from '@socdesk/shared/intent'
import { clearRecents, pushRecent } from './recents'
import { applyThemePref, resolveTheme } from '@socdesk/shared/lib/theme'
```

Modify `web/src/components/palette/commands.ts:108-113`. Before:

```ts
export function submitLookup(query: string): void {
  const q = query.trim()
  if (!q) return
  pushRecent(q, classifyIndicator(q))
  navigate(`/lookup${lookupHash(q)}`)
}
```

After:

```ts
/**
 * Submit an indicator lookup. Records it as recent, then routes to the live
 * `/lookup` surface with the indicator on the `#q=` deep link — from ANY
 * route. A command-shaped value NEVER reaches `/lookup` (whose `useLookup`
 * calls `detectType` directly, with no command guard of its own — the exact
 * leak described in design spec §2.1/§2.2): it routes to the standalone
 * `/analyzer` instead. Analyzer deep-link parity (prefilling the pasted
 * command there) is deferred (spec §9) — v1 lands on the bare route.
 */
export function submitLookup(query: string): void {
  const q = query.trim()
  if (!q) return
  if (classifyCockpitInput(q) === 'command') {
    navigate('/analyzer')
    return
  }
  pushRecent(q, classifyIndicator(q))
  navigate(`/lookup${lookupHash(q)}`)
}
```

- [ ] **Step 2: Guard `Lookup.tsx::runLookup`**

Modify `web/src/routes/Lookup.tsx:29` (the `commands` import). Before:

```ts
import { lookupHash } from '../components/palette/commands'
```

After:

```ts
import { lookupHash, navigate } from '../components/palette/commands'
```

Add the classifier import beside the existing `refang` import at `web/src/routes/Lookup.tsx:20`. Before:

```ts
import { refang } from '@socdesk/shared/indicators'
```

After:

```ts
import { refang } from '@socdesk/shared/indicators'
import { classifyCockpitInput } from '@socdesk/shared/intent'
```

Modify `web/src/routes/Lookup.tsx:152-158`. Before:

```ts
  const runLookup = (raw: string) => {
    const q = refang(raw)
    if (!q) return
    // Writing the hash drives the sync effect. An identical resubmit fires no
    // hashchange — but the result already shows it, so that is a harmless no-op.
    window.location.hash = lookupHash(q)
  }
```

After:

```ts
  const runLookup = (raw: string) => {
    const q = refang(raw)
    if (!q) return
    // A command-shaped paste must never drive useLookup (whose detectType
    // call has no command guard of its own) — route it to the standalone
    // analyzer instead of writing the lookup hash (design spec §2.2, §9).
    if (classifyCockpitInput(q) === 'command') {
      navigate('/analyzer')
      return
    }
    // Writing the hash drives the sync effect. An identical resubmit fires no
    // hashchange — but the result already shows it, so that is a harmless no-op.
    window.location.hash = lookupHash(q)
  }
```

- [ ] **Step 3: Typecheck**

Run (from `web/`): `npx tsc -b`
Expected: clean.

- [ ] **Step 4: Build**

Run (from `web/`): `npm run build`
Expected: clean.

- [ ] **Step 5: Dogfood note (for the controller, on the built app) — this closes the leak everywhere**

Open the command palette (its shortcut), type a command-shaped string (e.g. a multi-line paste or `powershell -enc …`), select the resulting "Lookup" row — confirm it lands on `/analyzer`, not `/lookup`, and that no `/api/enrich` request fires (check the network panel). Separately, visit `/lookup` directly and paste the same command-shaped text into its own search box and submit — confirm the SAME redirect to `/analyzer` with no `/api/enrich` call. Together with Task 6/7's cockpit-level guard (which never lets a command-shaped value reach `useLookup` in the first place via `useCockpitInput`), this confirms the data boundary holds at every submit path in the app.

- [ ] **Step 6: Commit**

```bash
git add web/src/components/palette/commands.ts web/src/routes/Lookup.tsx
git commit -m "fix(cockpit): guard submitLookup and runLookup against a command paste"
```

---

## Self-Review

**1. Spec coverage** — every numbered item in spec §3 (the v1 scope) maps to a task:

| Spec item | Task |
|---|---|
| §3.1 `classifyCockpitInput` | Task 1 |
| §3.2 consolidate `classify.ts` onto `detectType` | Task 2 |
| §3.3 `useCockpitInput` (unified hook, unconditional calls, `''` short-circuit) | Task 4 |
| §3.4 `AnalyzerResult` extraction | Task 3 |
| §3.5 `ResultRegion` (mode-aware dispatch, `key={kind}` unmount) | Task 5 |
| §3.6 Cockpit rewiring (`submitted`, `isResult`, `resultIsGeoless`) | Task 6 |
| §3.7 Input morph + correctable mode chip | Task 7 |
| §3.8 Globe yield (behavioural flyBack / visual `.is-geoless` / loop-cost `suspend`/`resume`) | Task 6 (flyBack branch) + Task 8 (CSS + suspend/resume) |
| §3.9 Height flex | Task 8 |
| §2.1/§2.2 data boundary at every submit path | Task 1 (classifier) + Task 6/7 (cockpit's own hook never bypasses it) + Task 9 (`submitLookup` + `runLookup`) |
| §2.3 `CompareIp` second-fetch leak across a kind flip | Task 5 (`key={cockpit.kind}` in `Overview.tsx`) |
| §7 risks: silent misclassification | Task 7 (correctable `ModeChip`) |
| §7 risks: rate-limit regression from live typing | Task 6/7 (`useCockpitInput` only ever receives the committed `submitted` value, never `liveValue`) |
| §7 risks: two submit paths | Task 9 |
| §7 risks: globe GPU burn behind CSS dim | Task 8 (`suspend()`/`stopLoop()`) |
| §7 risks: height/void | Task 8 (height flex; globe stays a dim backdrop, not `display:none`) |
| §8 reserved-colour / doctrine | Enforced throughout — no new verdict-tone class or hue is introduced anywhere in this plan; `ModeChip` uses `Chip variant="neutral"` |
| §9 deferred items | Explicitly excluded — no task builds analyzer deep-link parity, the `IocTable` in-place kind-flip, or the tabs IA pass; `submitLookup`'s command branch (Task 9) intentionally lands on the bare `/analyzer` route, not a prefilled one |

**2. Placeholder scan** — every task shows full, exact code (no `// TODO`, no "similar to Task N", no "write tests for the above"); every `Modify` cites a real `file:line` range read from the actual source during planning; every commit message is a literal `git commit -m` command.

**3. Type-consistency check:**
- `CockpitInputKind` (Task 1: `'indicator' | 'command' | 'unclassified'`) is used identically in Task 4 (`useCockpitInput`'s internal `kind` variable), Task 7 (`ModeChip`/`CockpitOmnibox`'s `autoKind`), and Task 9 (both submit-path guards) — no task redefines it.
- `CockpitResult` (Task 4) is consumed with the exact same shape by Task 5 (`ResultRegion`'s `cockpit` prop) and Task 6/7 (`Overview.tsx`'s `cockpit` local + the `isGeolessResult` helper's parameter type).
- `resolveCockpitArgs(kind, submitted)` and `useCockpitInput(submitted, override?)` signatures are defined once in Task 4 and never redeclared elsewhere.
- The `override`/`kindOverride` type (`'indicator' | 'command' | null`) is identical across Task 4 (`useCockpitInput`'s second parameter), Task 7 (`ModeChip`'s `override` prop, `CockpitOmnibox`'s `onSubmit`'s second argument), matching the `submit`/`submittedOverride` plumbing added to `Overview.tsx` in Task 7.
- `GlobeApi.suspend`/`resume` (Task 8) are added to the interface, the two default-object literals, and the `apiHolder.current` assignment in the same task — no caller (`Overview.tsx`) references them before Task 8 lands.
- `PsStatus`'s prop type in Task 5 (`Extract<PsState, {kind:'analyzing'}|{kind:'error'}>`) matches exactly what `ResultRegion`'s command branch passes to it after its own `idle`/`ok` early returns.

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-19-polymorphic-cockpit.md`. Two execution options:

**1. Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**
