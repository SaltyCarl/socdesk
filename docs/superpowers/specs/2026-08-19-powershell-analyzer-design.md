# SOCDesk — PowerShell Analyzer: Design Spec

**Date:** 2026-08-19 · **Status:** design, pre-implementation · **Scope target:** `web/` + `shared/` (the live React/TS stack per `docs/HANDOFF.md` §0 — *not* the superseded `site/`/Python architecture the root `CLAUDE.md`/`docs/ARCHITECTURE.md` still describe; see §14).

## 0. Summary

A new client-side tool: an analyst pastes a PowerShell command (or `.ps1` / EID-4104 script text) pulled from an EDR/SIEM alert and gets, deterministically and without ever executing it:

1. a decoded/deobfuscated view with a **per-layer completeness ladder**,
2. a concise, execution-ordered **"what did it do" breakdown** (the headline),
3. an auditable, MITRE-mapped **technique-signal tally** (never a synthesized verdict), and
4. every extracted **IOC as a one-click pivot into SOCDesk's existing reputation card**.

The answer to *"what did it do"* is the product; the IOC bridge is what makes it SOCDesk's and not a CyberChef reskin.

## 1. Locked scope (v1) & doctrine

- **Public socdesk.io. 100% client-side, deterministic TypeScript in `shared/analyzer/`. No LLM in v1.** A fenced, Framework-only LLM *narration* layer is a deferred v2 — the fact-object output is designed so it can bolt on later (§13), but v1 ships without it.
- **Never executes the input.** No `eval`/`new Function`/dynamic dispatch of the pasted script. The CSP (`script-src 'self'`, no `unsafe-eval`; `web/public/_headers`) already forbids this structurally — the parser is a pure string→data transform.
- **No synthesized, black-box verdict and no risk score.** The base output is a **technique-signal tally** (count + specificity-weighting, each chip citing its triggering substring) — the "count and attribute, don't pronounce" model. The analyst owns the escalate/close call.
- **Specificity-gated characterization (owner decision 2026-08-19).** When a **near-dispositive** signal fires (a technique with *no legitimate use* — e.g. an AMSI reflection patch, `conhost --headless powershell`, a Nishang reverse shell), the tool DOES assert a **"high-confidence malicious behavior"** characterization — but one **attributed to those named techniques** (each with its "no legitimate use" basis), never a black-box stamp. **Weak/strong-only cases stay the descriptive tally** — benign RMM/installer/GPO tooling shares the weak signals (`-enc`, hidden window, exec-bypass), so a label there would cry wolf. This is the escalation card's own rule applied to behaviours: *authoritative facts assert, ambiguous signals hedge*. A `'suspicious'` tier for strong-only co-occurrence is deliberately deferred (see §6).
- **Honesty is a first-class output.** Silent partial success is the cardinal sin. Every incomplete decode is marked; residual blobs are shown with entropy; "known-pattern not matched ≠ safe."
- **Reserved-colour law** (`shared/ui/Chip.tsx`): technique/LOLBin/switch signals render as periwinkle/neutral chips; red/amber/green stay verdict-severity only.
- **Public sources only** (LOLBAS, public ATT&CK, public MS docs) — no employer/CARL knowledge in this public repo.
- **Data boundary:** a pasted command line can carry internal hostnames — it **never leaves the browser**; the only egress is the analyst-initiated same-origin `/api/enrich` bridge.
- Commits `feat(analyzer): …` as SaltyCarl, **zero AI attribution**.

## 2. Engine architecture

**Chosen approach: a purpose-built lexer + flat token-stream passes** (not a full recursive-descent AST parser; not a naive regex pipeline).

- A single **lexer** walks the input once and emits a token stream that distinguishes barewords from string literals — the minimum grammar needed to guarantee *literal-safety* (a backtick inside a double-quoted string is an escape, not noise; case is significant inside literals). This is the property naive regex pipelines cannot have, and it is the one that prevents confidently-wrong decodes.
- Every higher stage (constant-folder, signature matcher, IOC extractor, bullet deriver) is a **windowed pattern-match pass over the token stream**, never over raw text and never over a full statement/expression AST.
- Deep multi-statement / scoped-reassignment / runtime-computed obfuscation correctly **falls through to the halting boundary** and is marked OPAQUE — the honest outcome, consistent with the ~80–90% realistic ceiling (alert PowerShell is overwhelmingly `-enc` one-liners and `IEX(...)` cradles; the hard tail — DPAPI, reflection, network-gated — is not decodable by any non-executing tool).

Rejected: **full AST parser** (weeks of work, its own mis-slicing bug surface, buys corner cases rare in the alert corpus); **regex+fold with no lexer** (ships the exact literal-safety bug the research named).

### The five stages (data flows forward; stage 2↔3 loop per decoded layer)

1. **Preprocess/normalize** — intake (raw command line / `.ps1` / 4104 text), strip the `powershell.exe … -enc <b64>` cmd-flag wrapper (cmd syntax, a separate concern from PS grammar), capture evasion flags (`-w hidden`, `-nop`, `-ep bypass`, `-enc`, `-noni`, `-sta`) as **facts**. Does not touch string-literal contents.
2. **Tokenize/parse (lexer-aware)** — token stream (`String` with resolved escapes, `Bareword`, `Variable`, `Operator`, `TypeLiteral`, `Comment`, `Number`, `Punctuation`). Also computes obfuscation-likelihood + entropy/token stats.
3. **Deobfuscate/recurse** — decode primitives + bounded constant-folder + single-assignment tracker; depth-capped recursion through `IEX`/`&`/`.Invoke()` sinks (each new layer re-enters stage 2). Stops at the halting boundary; emits the ordered **layer stack** with per-layer transform provenance + completeness state + residual/entropy.
4. **Extract facts/IOCs** — from every decoded layer: URLs/IPs/domains/hashes/paths/regkeys/tasks/mutexes, download cradles, shellcode byte-array + API-name tells, AMSI/ETW markers. Reuses `detectType`/`refang` (`shared/indicators.ts`) + `defang` (`shared/verdict/doctrine.ts`).
5. **Classify/report** — map constructs → MITRE ATT&CK; run the signature rule table (with co-occurrence weighting) → signals; derive the action-bullet breakdown; roll up completeness/confidence; assemble `AnalysisResult` + `copyText`.

## 3. Module design — `shared/analyzer/`

Mirrors the barrel-plus-pure-logic shape of `shared/verdict/` (pure, DOM-free, no I/O, same-input→same-output). Tests auto-run by `web/vitest.config.ts` (already globs `../shared/**/*.test.ts` — no config change).

| File | Responsibility |
|---|---|
| `types.ts` | Pure types only (§4). |
| `lex.ts` | `tokenize(source): Token[]` — quoting/escaping rules only, no statement grammar. |
| `preprocess.ts` | Stage 1: strip the cmd-flag wrapper, capture evasion flags as facts. |
| `fold.ts` | Stage 3, the **one async module** (WebCrypto + Compression Streams): Base64+UTF-16LE, gzip + **raw-DEFLATE** (`DecompressionStream('deflate-raw')`), inline-key AES; bounded literal fold-to-fixed-point (`+`,`-join`,`-f`,`[char]`,`-replace`,array-reversal over literals only); single-assignment `$var=<literal>` tracker; depth-capped `IEX`/`&`/`.Invoke()` recursion (re-tokenises each new layer). |
| `extract.ts` | Stage 4: IOCs + facts per resolved layer (reuses `detectType`/`refang`/`defang`). |
| `lolbins.ts` | Public-sources-only LOLBAS/binary fingerprint data table, separate from rule logic. |
| `techniques.ts` | Stage 5 signature rule table + co-occurrence upgrade pass → `Signal[]`. |
| `bullets.ts` | Fact→action-bullet rule table → execution-ordered, three-tier `ActionBullet[]`. |
| `confidence.ts` | Per-layer `DecodeState`, entropy, roll-up `fractionAccounted`. |
| `report.ts` | `analyze(input): Promise<AnalysisResult>` — the one entry point; also `composeCopyText`. |
| `index.ts` | Barrel. |
| `__tests__/*.test.ts` | Per-module + fixture tests. |

Big data tables (`lolbins.ts`, `techniques.ts`) stay **importable TS chunks**, never `data:` URIs (`build.assetsInlineLimit:0`).

## 4. Data types (`types.ts`)

Deliberately echoes `VerdictData` (`shared/verdict/types.ts`) **minus any band/verdict field** — the locked scope forbids one.

```ts
export type ConfidenceTier = 'resolved' | 'inferred' | 'opaque'
export type DecodeState = 'fully-decoded' | 'partial' | 'opaque' | 'wall'
export type Specificity = 'weak' | 'strong' | 'near-dispositive'

export interface EvasionFlag { flag: string; raw: string; techniqueIds: string[] }

export interface DecodedLayer {
  index: number
  transform: string            // e.g. "Base64 → UTF-16LE", "deflate-raw inflate", "-f fold"
  text: string | null          // decoded text if resolved
  state: DecodeState
  residual?: { bytes: number; entropy: number; note: string }  // when not fully decoded
}

export interface ExtractedIoc {
  raw: string                  // verbatim, pivotable
  defanged: string
  type: IndicatorType          // from shared/indicators
  layerIndex: number           // provenance: which layer it came from
}

export interface Signal {
  id: string                   // rule id
  label: string                // chip text, e.g. "download cradle"
  techniqueIds: string[]       // MITRE, e.g. ["T1059.001","T1105"]
  specificity: Specificity     // after co-occurrence upgrade
  trigger: string              // the exact substring that fired it (audit)
}

export interface Characterization {
  level: 'high-confidence-malicious'  // v1: near-dispositive only; 'suspicious' tier deferred (§6)
  basis: string[]              // ids of the near-dispositive signals that justify it (audit)
  read: string                 // "High-confidence malicious behaviour: AMSI bypass via reflection (no legitimate use) + download cradle → …"
}

export interface ActionBullet {
  order: number                // execution order (statement, then dataflow depth)
  verb: string                 // Downloads / Decodes / Disables / Schedules / …
  text: string                 // the rendered bullet
  confidence: ConfidenceTier
  iocs: string[]               // raw IOCs referenced inline
  techniqueIds: string[]
}

export interface AnalysisResult {
  input: string
  flags: EvasionFlag[]
  layers: DecodedLayer[]
  iocs: ExtractedIoc[]         // deduped across layers
  signals: Signal[]            // the technique tally
  characterization: Characterization | null  // specificity-gated; null unless a near-dispositive signal fires
  bullets: ActionBullet[]      // the "what did it do" breakdown
  confidence: { fractionAccounted: number; state: DecodeState }  // worst-layer roll-up
  copyText: string
  checkedAt: string
}
```

**Data flow:** `preprocess → tokenize → fold (async, recursive, re-tokenises each layer) → extract → {classify(techniques), deriveBullets(bullets)} → deriveConfidence → report assembles AnalysisResult + copyText`.

## 5. Deobfuscation (`fold.ts`) — the safe, non-executing approach

**Decode primitives (reliable):**
- Base64 → **UTF-16LE** for `-enc` (the #1 gotcha — not UTF-8); opportunistically try UTF-8 + Base64-of-Base64 for embedded blobs.
- gzip (magic `1F 8B`) and **raw-DEFLATE** via `DecompressionStream('deflate-raw')` — PowerShell's `DeflateStream` emits raw DEFLATE with no zlib header, so plain `'deflate'` throws. `deflate-raw` is load-bearing.
- inline-key `ConvertTo-SecureString -Key (...)` → AES-CBC via WebCrypto (only when the key is literally present).

**Bounded constant-folder (literal operands only):** `+`, `-join`/`-split`, `-f`, `[char]`/`[char[]]`/`[int][char]`, `-replace`/`.Replace()` (literal find/replace; gate regex-form on .NET-faithful semantics), array reversal. **Refuses to fold** the moment any operand is a function call, cmdlet output, loop result, or unresolved variable — returns the sub-expression untouched, never a guess.

**Single-assignment tracker:** resolve `$a='New'; $b='-Object'` and substitute at use sites, only for variables bound exactly once to a fold-able constant. On reassignment/branch/loop → mark **unknown**, stop tracking that symbol.

**Recursion:** when folding resolves an `IEX`/`&`/`.Invoke()` operand to a literal string, re-enter stage 2 on it. **Depth cap 6** (configurable), dedupe layers by hash (stop `iex $x` ping-pong), record each layer's transform + state.

**The halting boundary (mark, never cross):** runtime-computed dispatch (`iex (gcm *ke-e*)`, `$env:ComSpec[...]`-built commands), DPAPI SecureString (no `-Key`), non-inline crypto keys, reflection/`[Ref].Assembly.GetType(...)`, network-gated stagers. At the first such construct: **stop, show the residual blob with byte-count + Shannon entropy, tag the layer `opaque`/`wall`, and state plainly that a clean partial decode is not a safety verdict and an undecoded blob is to be treated as hostile.**

**Lexer-awareness caveat (correctness-critical):** backtick-strip/case-normalise only in the token stream *outside* string literals; never mutate the bytes inside a `'...'`/`"..."` literal. Order is always **lex → structure-aware normalise → fold**, never regex-blast raw text.

**Completeness state per layer** feeds the UI ladder + the confidence roll-up (worst layer wins the headline).

## 6. Signature catalog (`techniques.ts` + `lolbins.ts`)

A declarative rule table. Each `SignatureRule`:

```ts
interface SignatureRule {
  id: string
  label: string
  techniqueIds: string[]
  baseSpecificity: Specificity
  upgradesWith: string[]        // companion rule ids → co-occurrence upgrade
  test(ctx: RuleContext): { hit: boolean; trigger?: string }
}
```

Rules run over the **decoded** token stream (co-occurrence weighting is the accuracy mechanism — nearly every single token has a benign twin; `-nop` alone is weak, `AmsiUtils`+`amsiInitFailed` reflection is near-dispositive). A post-pass upgrades specificity when `upgradesWith` companions co-fire.

**Families (each with MITRE + FP-disambiguation, priority-ordered for v1):**
- **Download cradles** — `IEX(New-Object Net.WebClient).DownloadString`, `iwr|irm|curl|wget → IEX`, `Start-BitsTransfer`, `DownloadFile/Data`, raw `WebRequest`/`HttpClient`. Discriminator: fetched content going *directly into an interpreter* (malicious) vs into a file/`ConvertFrom-Json` (benign). T1059.001/T1105.
- **ClickFix / paste-and-run** *(high priority, recent)* — hidden-window one-liner (`-w hidden` + `-nop` + fetch + IEX), `mshta https://`/`javascript:`, `conhost --headless powershell`, `nslookup -type=txt`→PS, CAPTCHA/"verify human"/ray-id decoy comments beside a downloader. T1204/T1059.001/T1218.005/T1105.
- **Beaconing / C2** — jittered `Start-Sleep` in `while($true)` + same-host fetch + IEX; hardcoded browser UA; framework launcher fingerprints (Cobalt Strike default `-nop -w hidden -enc`→`DownloadString('http://127.0.0.1:<port>/')`; Empire `-noP -sta -w 1 -enc`; Sliver `-NoExit -OutputFormat text -NonInteractive`; Nishang `Invoke-PowerShellTcp`/raw `Net.Sockets.TCPClient`). T1071.001/T1571/T1573.
- **AMSI/ETW/Defender tampering** — `AmsiUtils`+`amsiInitFailed`/`SetValue($null,$true)` reflection (near-dispositive), `AmsiScanBuffer`+`VirtualProtect` memory patch, ETW `EtwEventWrite`/provider field patch, `Set-MpPreference -Disable*`, `Add-MpPreference -ExclusionPath`. T1562.001/.002/T1112. Disambiguate reflection patches (zero benign use) from `Set/Add-MpPreference` (installer-collision → needs corroboration).
- **Evasion-flag clustering** — count of {`-ep bypass`,`-nop`,`-w hidden`,`-noni`,`-enc`}; discriminator: cluster + `-File local.ps1` (benign automation) vs cluster + `-enc`/inline-fetch (malicious). T1059.001/T1564.003/T1027.
- **Fileless/in-memory loaders** — `[Reflection.Assembly]::Load([byte[]])`, `Add-Type` P/Invoke (`VirtualAlloc`/`CreateThread`/`memset`), shellcode byte arrays. Detectable, not decodable → flag presence + entropy. T1055/T1620.
- **Persistence** — `Register-ScheduledTask`/`schtasks`, WMI event subscription, Run/RunOnce key writes, startup folder, services. T1053.005/T1547.001/T1546.
- **LOLBins** — certutil, bitsadmin, mshta, regsvr32, rundll32, msiexec `/i http`, wmic (from `lolbins.ts`).

**Tally rendering:** count + specificity ("3 high-risk technique signals across 3 ATT&CK techniques"); each chip cites its trigger substring; no bare score.

**Behavioral characterization (specificity-gated pass, in `report.ts`):** after co-occurrence, if **≥1 signal is `near-dispositive`**, emit a `Characterization` (`level: 'high-confidence-malicious'`, `basis` = those signal ids, `read` naming each with its "no legitimate use" note — e.g. "High-confidence malicious behaviour: AMSI bypass via reflection (no legitimate use) + download cradle → `hxxp://…` + logon persistence"). If no signal reaches near-dispositive, `characterization` is **null** and only the tally renders — weak/strong-only patterns (which benign RMM/installer/GPO tooling shares) are never labelled. The characterization is always **enumerated and attributed** — the "malicious" word is earned by named near-dispositive techniques, never a black-box stamp. A **`'suspicious'` tier** for strong-only co-occurrence is deliberately deferred to post-dogfooding: the strong signals (download cradle, Defender-cmdlet tampering, evasion clusters) have real benign twins, so auto-labelling them risks cry-wolf.

## 7. "What did it do" breakdown (`bullets.ts`) — the headline

Execution-ordered plain-English **action bullets**, each from a keyed `ActionRule` that fires **only on facts the parser resolved**:

```ts
interface ActionRule {
  id: string
  requiredFacts: string[]       // fires only when these are resolved
  fires(ctx: RuleContext): Match | null
  render(m: Match): ActionBullet // verb-first; names the RESOLVED object; states consequence
}
```

Rules (representative): `-enc` decode → "Decodes a Base64 `-EncodedCommand` (UTF-16LE) revealing the real script"; WebClient/`iwr` → "Downloads content from **{url}**" (degrade: "from a URL assembled at runtime — not resolved"); download→IEX → "Executes the downloaded content **in memory** (not written to disk)"; Gzip/Deflate → "Decompresses an embedded blob with {algo} in memory"; `Set-MpPreference -DisableRealtimeMonitoring` → "Disables Microsoft Defender real-time monitoring"; `Register-ScheduledTask` → "Creates scheduled task **{name}** running **{action}** at **{trigger}**"; Run-key → "Sets an autostart Run-key **{name}** → **{value}** (persists across reboot)"; `VirtualAlloc`+`CreateThread` → "Allocates executable memory and starts a thread on embedded shellcode (in-memory injection)".

**Discipline:**
- **Verb-first, names the resolved object (never the variable), states the host/network consequence.** One action per bullet; plumbing (stream/reader construction) collapses into the action it serves.
- **Ordered** by `(statementIndex, dataflowDepth desc)` so acquire→decode→execute reads correctly.
- **Never invents intent** — "downloads content", not "downloads malware"; maliciousness lives only in the separate signal layer.
- **Three-tier confidence, visually separated:** `resolved` (●) load-bearing; `inferred` (~, object dynamic) flags the dynamic part; `opaque` (○) quarantined in a separate muted "Could not resolve" block with the raw snippet. An opaque item is **never** promoted into the confident list.

## 8. IOC extraction + the enrich bridge

`extract.ts` harvests IOCs from **every decoded layer** (verbatim + defanged + type + layer provenance), deduped. In the UI, each IOC row's "Look up" button calls **`submitLookup(ioc.raw)`** (`web/src/components/palette/commands.ts:100`) → `navigate('/lookup#q=')` → existing `useLookup`→`fetchEnrichRaw`→`EscalationCard`. Zero new routing; the `/lookup` popstate listener already handles it from any route. IOCs are defanged for display; the raw form is what's handed to `submitLookup` (which refangs).

## 9. UI composition — new `/analyzer` route

A dedicated top-level route (matches `/lookup`'s "input → rich result" shape far better than a `/desk` tab).

- Add one row to `ROUTES` (`web/src/App.tsx:35-55`, nav auto-derives) + one `DEFAULT_VIEWS` entry (`commands.ts`).
- New `web/src/routes/PowerShellAnalyzer.tsx` (sibling to `Lookup.tsx`); local `usePsAnalysis(input)` hook mirrors `useLookup`'s tagged-state shape (`idle|analyzing|ok|error`) but with no network fetch — the only async is `fold.ts`.
- `ToolbeltView.tsx` keeps its blurb; its "decode encoded command lines" card flips from `planned` to a live link to `/analyzer` once shipped (the one existing file that changes).

**Component reuse:**
- `Chip`/`MicroLabel`/`Card`/`Panel` (`shared/ui`) + `CardActions`' copy-text pattern (swap `composeEscalation` for `AnalysisResult.copyText`).
- **One additive edit** to `shared/ui/Chip.tsx`: a new `'technique'` variant (periwinkle/neutral) in the `ChipVariant` union + `VARIANT` map + `DEFAULT_LABEL` — low blast radius.
- **New presentational components** (following `SourceLedger`'s layout grammar — fixed left cell, mono micro-text, zebra rows): `TechniqueTally`, `DecodeLadder`, `IocTable`. Do **not** reuse `TallyHeadline`/`SegGauge` (hard-wired to `VerdictData` doctrine + red/amber/green bands).
- **No canvas/PNG artifact in v1** (`copyCard`/`renderVerdictCanvas` are `VerdictData`-specific; there's no severity band to theme a card around).

**Layout (top→bottom):** paste input → (analyzing skeleton) → evasion-flag chips + technique tally, **led by `characterization.read` when present** (the near-dispositive-gated high-confidence line, styled assertively but rendered from the enumerated `basis`), else the plain count → the "what did it do" action bullets (confident block, then quarantined "could not resolve") → decode ladder (each layer: transform + state, residual+entropy where opaque) → IOC table with one-click enrich → copy-to-ticket button.

## 10. Honesty / completeness UX

- **Decode ladder** renders each `DecodedLayer.state` explicitly: FULLY DECODED / PARTIALLY FOLDED / OPAQUE — execution required / WALL — secret absent. Never a single "decoded!" banner.
- **Residual display** for any halted layer: bytes + entropy + classification ("high-entropy → likely encrypted/compressed/shellcode"; "Base64-shaped but non-decoding → encoded blob, key/format unknown").
- **Analysis-confidence chip** driven by `fractionAccounted` (fraction of tokens consumed by known rules) — high / partial / low. Fully deterministic; the single most important honesty feature.
- **Two axes never blended:** *did we fully decode?* vs *is it malicious?* A clean decode with no signal reads "decoded; no known-bad pattern matched — not a safety verdict"; an undecoded residual reads "could not decode — treat as unknown/hostile."

## 11. Pathological-input guards (v1)

A hostile paste must never hang the tab even though nothing executes. **Hard per-stage caps in v1:** max input length, max token count, max fold iterations (fixed-point loop bound), max recursion depth (6), max total layers, max output size. On exceeding a cap: stop, mark the layer `opaque`, surface honestly. A Web Worker (`worker-src 'self'` already permits it, no CSP change) is deferred to v2 if needed.

## 12. Testing strategy (vitest, `shared/analyzer/__tests__/`)

- **Lexer:** literal-safety fixtures (backtick inside `"…"`, case inside `'…'`) — a "fixed" claim needs a failing-without-fix test.
- **Fold:** `-enc` UTF-16LE fixture; gzip + `deflate-raw` cradle fixtures; a nested-cradle fixture; a **halting-boundary fixture verified to report `opaque`/`wall`, never a guess**; inline-key AES fixture.
- **Extract:** IOC verbatim + defang + layer-provenance fixtures.
- **Signatures:** one positive + one **benign-twin** fixture per rule (the FP-disambiguation requirement); ClickFix prioritised; a co-occurrence-upgrade test.
- **Characterization:** a near-dispositive fixture yields `characterization.level === 'high-confidence-malicious'` with the firing signal ids in `basis`; a **strong-only** and a **benign-twin** fixture both yield `characterization === null` (the anti-cry-wolf guarantee); the `read` string contains only names present in `basis`.
- **Bullets:** execution-ordering test; a **banned-word test** proving bullets never emit "malicious/attacker/likely/C2" unless present as a resolved fact (mirrors how `doctrine.ts` structurally forbids a verdict word); an opaque-quarantine test.
- **Confidence:** `fractionAccounted` roll-up + worst-layer-state test.
- **Determinism:** same input → identical `AnalysisResult` (minus `checkedAt`).

## 13. Phased build sequence

Each phase independently testable and (from Phase 1) shippable.

- **Phase 0 — scaffold.** `types.ts` + barrel + fixture-stub `analyze()`. Gate: `tsc -b` clean, one smoke test.
- **Phase 1 — the 80/20 core.** `preprocess`, `lex`, `fold` (Base64/UTF-16LE + gzip/raw-DEFLATE, depth 1), `extract`. Minimal `/analyzer` route + `IocTable` + the one-click `submitLookup` bridge. **Shippable value on its own: paste → decode → IOCs → enrich.** Gate: `-enc` UTF-16LE fixtures; IOC button lands on `/lookup#q=`.
- **Phase 2 — recursion + folding.** Depth-cap 6, constant-folder, single-assignment tracker, inline-key AES. `DecodeLadder` UI + residual/entropy. Gate: nested-cradle fixtures; halting-boundary fixture reports `opaque`/`wall`.
- **Phase 3 — signature catalog.** `lolbins`, `techniques` + co-occurrence. `TechniqueTally` UI + the `'technique'` Chip variant. Gate: positive + benign-twin per rule; ClickFix prioritised.
- **Phase 4 — action-bullet breakdown + honesty chip.** `bullets`, `confidence`. Three-tier bullet UI (opaque quarantined). Gate: ordering + banned-word tests.
- **Phase 5 — copy-to-ticket + polish.** `composeCopyText` (one-line summary + confident actions + deduped defanged IOCs + MITRE + "could not resolve" footer + "static analysis, NOT executed" provenance line). Flip the `ToolbeltView` link live. Visual QA vs reserved-colour law + CSP.

Each phase = a dogfoodable checkpoint (per the project's dogfood-checkpoint discipline).

## 14. Open questions & deferred

- **v2 — LLM narration (Framework-only, fenced):** structured facts in / validated prose out; post-generation validation that every IOC/cmdlet/technique in the prose exists verbatim in the fact-object; judgment vocabulary banned; decoded payload treated as hostile input (prompt-injection); verdict path bypasses the model; templated prose stays the default. Designed-for, not built in v1.
- **Doc-debt:** root `CLAUDE.md`/`docs/ARCHITECTURE.md` describe the superseded Python/`site/` architecture. This spec scopes against `web/`+`shared/`; those docs should be reconciled separately.
- **`DecompressionStream('deflate-raw')` / WebCrypto browser-support floor** for socdesk.io's audience — confirm before committing to `deflate-raw` as the only raw-DEFLATE path (fallback: a vendored pure-JS inflate).
- **Entropy threshold** for the "opaque ciphertext" classification — a numeric product call to pin during Phase 2.
- **`web/` browser-test harness** existence (the legacy `site-tests/` Playwright targets `site/`, not `web/`) — confirm before citing browser-test gates for the UI phases.
- **Extension reachability** of `shared/analyzer/` — plausible (extension already ships shared card parity) but v1 is web-only; verify the alias before a v1.x extension surface.
- **LOLBAS/ATT&CK table refresh cadence/owner** — `lolbins.ts`/`techniques.ts` are hand-authored, committed, public-sources-only constants (no live fetch).
