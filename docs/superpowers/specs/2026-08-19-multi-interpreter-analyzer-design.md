# SOCDesk — Multi-Interpreter Analyzer: Design Spec

**Date:** 2026-08-19 · **Status:** design, pre-implementation · **Scope target:** `shared/analyzer/` only — no route/UI changes in this increment (the analyzer already has a `/analyzer` surface per `docs/superpowers/specs/2026-08-19-powershell-analyzer-design.md`; this increment extends the deterministic core it reads from, not the UI).

## 0. Summary

The analyzer (`docs/superpowers/specs/2026-08-19-powershell-analyzer-design.md`) is PowerShell-scoped. A live test against a real ClickFix sample proved the gap:

```
cmd /c ... for /f ... in ('finger user@host') do %e ...
```

a `finger`-based download/exec cradle, caret-obfuscated (`^`/`^^`), with a `--Verify... press ENTER` decoy — the analyzer returned only 2 IOCs, **no signals, no characterization**, and mis-typed `cmd.exe` itself as a domain IOC (a false positive). Two root causes:

1. **No interpreter model.** The pipeline assumes the input is PowerShell. A `cmd.exe`/`mshta`/`wscript`/`cscript` command line is never recognized, so its payload is never isolated for lexing, folding, or signature matching.
2. **No cmd.exe grammar awareness.** Even where cmd-launched PowerShell text happens to reach the signature layer, caret obfuscation (`^`) is cmd-specific noise the PowerShell lexer doesn't strip, and cmd's own constructs (`for /f`, `finger`, `%`-variables) have no signature coverage at all.

This increment adds **cmd.exe + mshta + wscript/cscript** as first-class interpreters alongside PowerShell: detection, per-interpreter body/target extraction with recursive nested-interpreter re-entry (a `cmd`/`mshta`/`wscript` wrapper's inner `powershell -enc` payload is re-detected and decoded, §2.1), a dedicated cmd caret deobfuscator, a bounded WSH/HTA numeric-char-code decode fronted by unconditional honesty signalling for its limits (§4), four new MITRE technique IDs' worth of signatures, and an IOC-extraction leak fix. It does **not** add a cmd/VBScript/JScript lexer, string-concat folding for WSH, or eval-recursion — those are named, bounded, explicit follow-ups (§4).

## 1. Interpreter model

`preprocess.ts` gains a detector and the pipeline gains an interpreter tag threaded through the rest of the stages.

```ts
export type Interpreter = 'powershell' | 'cmd' | 'mshta' | 'wscript' | 'cscript' | 'unknown'

export function detectInterpreter(input: string): Interpreter
```

- **Detection basis:** the leading token after stripping a path/quote prefix — the same shape the existing PowerShell-wrapper strip already uses at `preprocess.ts:24`:
  ```ts
  let script = input.replace(/^\s*(?:["']?[^"'\s]*\b)?(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b/i, '')
  ```
  `detectInterpreter` generalizes this match against `cmd(.exe)`, `mshta(.exe)`, `wscript(.exe)`, `cscript(.exe)`, and `powershell(.exe)`/`pwsh(.exe)`, in that order of specificity, falling through to `'unknown'`.
- **`preprocess()`'s return shape gains an `interpreter` field.** Current signature (`preprocess.ts:14`):
  ```ts
  export function preprocess(input: string): { script: string; encoded: string | null; flags: EvasionFlag[] }
  ```
  becomes `{ script, encoded, flags, interpreter }`. Every downstream stage (body extraction, `cmdlex.ts` gating, the numeric-char-code pass, `report.ts`'s layer assembly) branches on `interpreter`.
- **Zero regression on the PowerShell path.** When `detectInterpreter` returns `'powershell'` (or `'unknown'`, which must behave identically to today's un-detected default), every existing stage runs exactly as it does today. This is the hard constraint that keeps the existing 86 PowerShell-analyzer vitest specs green untouched.

## 2. Per-interpreter body extraction

Each interpreter gets its own extraction step feeding the same downstream lex → fold/resolve → extract → classify pipeline that PowerShell already uses (`report.ts`'s `scan`/`corpus` assembly, lines 46–79).

| Interpreter | Extraction |
|---|---|
| **powershell / pwsh** | Unchanged: existing `-Command`/`-EncodedCommand` path (`preprocess.ts:21`, `:25-26`). |
| **cmd** | Extract the `/c` or `/k` body, mirroring the shape of the existing `-Command` extraction at `preprocess.ts:25-26` (`const cmd = script.match(/-c(?:ommand)?\s+(.*)$/is); if (cmd) script = cmd[1]`) — same "match a flag, take the rest of the line" pattern, `/c`/`/k` in place of `-Command`. Run the caret deobfuscator (§3) on the extracted body **before** anything else touches it, then hand the result to the nested-interpreter re-entry step (§2.1) — a cmd body very often wraps a nested `powershell -w hidden -enc <blob>`, which must be re-detected and decoded, not lexed as opaque cmd text. |
| **mshta** | The argument itself IS the payload: a URL (`http(s)://…/x.hta`), a local `.hta` path, or an inline `vbscript:`/`javascript:"…"` scheme. Extract the inline script body when present (feeds lex/signatures directly) or the URL (recorded as an IOC via the existing `extract.ts` path, not specially parsed). Run the existing Base64/gzip fold (`fold.ts`) over any embedded blob found in the extracted body; IOC-extraction and signature-matching then run over the result exactly as for any other layer. |
| **wscript / cscript** | Extract the `.vbs`/`.js` file target (recorded as a path/IOC) or an inline target when present. Recognize `//E:vbscript`, `//E:jscript`, `//B`, `//NoLogo` as evasion/config flags — new WSH-scoped flag rules, structurally the same as the existing `FLAG_RULES` table in `preprocess.ts:5-12` (`{ flag, re, techniqueIds }` entries), but gated to fire only when `interpreter` is `'wscript'`/`'cscript'` so they can never collide with PowerShell's `-w`/`-nop`/etc. |

### 2.1 Nested interpreter re-entry (recursive, depth-capped)

Real-world cmd/mshta/wscript wrappers overwhelmingly exist to launch a *nested* interpreter — the canonical case is `cmd /c powershell -w hidden -enc <blob>`, or `mshta vbscript:CreateObject("WScript.Shell").Run("powershell -enc <blob>")`. So an extracted body is **not** fed straight into stage-2 lexing: it is first looped back through `detectInterpreter` + `preprocess`, so a nested `powershell -enc <blob>` inside a cmd/mshta/wscript wrapper gets its Base64/`-Command` body decoded exactly as a top-level PowerShell input would. Without this, the increment would recognize the wrapper yet miss the actual payload — the very case it exists to catch. The recursion is **depth-capped** with the same discipline `report.ts` already applies to IEX/`&`/`.Invoke()` string-target recursion (a fixed max depth plus an output-size cap), so a hostile wrapper-in-wrapper cannot spin the analyzer. Each interpreter transition is recorded as its own decode-ladder layer (`transform` naming the hop, e.g. `cmd→powershell -enc`), keeping provenance visible to the analyst.

## 3. Caret deobfuscation (`shared/analyzer/cmdlex.ts`, NEW)

A **raw-text→raw-text normalizer**, not a tokenizer — cmd's caret rule has the opposite quote-scoping shape from PowerShell's backtick rule (PS: backtick escapes *inside* nothing special, cmd: caret is suppressed *inside* double quotes), so it cannot be folded into `lex.ts`'s token stream without corrupting PS literal-safety. It is a **separate module**.

**Rule:**
- Track **double-quote parity only.** Single quotes are not tracked at all — cmd does not caret-process inside `"…"`, but it **does** caret-process inside a `for /f`'s `'…'` list (the list delimiter, not a cmd string-literal quote).
- **Outside `"…"`:** `^^` → `^`; a bare `^` is dropped and the next character is kept literally. This mirrors the existing no-op-escape shape the PowerShell lexer already uses for backtick, at `lex.ts:56-57`:
  ```ts
  if (d === '`' && i + 1 < n) { v += source[i + 1]; i += 2; continue } // outside strings: backtick = no-op escape
  ```
  — same "consume the escape char, keep the next char" mechanic, keyed on `^` instead of `` ` ``, with the doubled-caret case handled first.
- **Inside `"…"`:** carets are left untouched (cmd does not process them there).
- **Trailing `^` at end-of-line** is a line-continuation marker, not a per-character escape — it must not consume past EOL into a synthetic next character.

**Non-negotiable interpreter gate:** `cmdlex.ts`'s normalizer is invoked **only when `interpreter === 'cmd'`**. This is the sharpest risk in the whole increment: running caret-stripping on PowerShell text corrupts legitimate regex literals such as `'^https?://'`, silently mangling correct PowerShell analysis to fix a cmd.exe gap. The gate lives at the single call site in `preprocess.ts`'s (or `report.ts`'s) cmd body-extraction branch — it must not be reachable from any other interpreter's path, including `'unknown'`.

## 4. WSH/HTA deobfuscation depth — the YAGNI cut

**In scope this increment:**
- Interpreter detection + body/target extraction + IOC extraction + signature matching for all four new interpreters. Signature matching needs no interpreter-specific plumbing to reach the corpus: `report.ts:78` already builds the classify-context from raw `input` plus every resolved layer —
  ```ts
  const corpus = [input, script, ...scan.map((s) => s.text)].filter(Boolean).join('\n')
  ```
  — so a `mshta`/`wscript`/`cmd` rule added to `techniques.ts`'s `RULES` table matches this corpus the same way every PowerShell rule already does, with no new wiring beyond adding rows to that table.
- A **grammar-light numeric-char-code decode**: `Chr(72)&Chr(105)` (VBScript) and `String.fromCharCode(72,105)` (JScript) → decoded text, implemented as a regex-driven pass over the interpreter-extracted body (conceptually analogous to the PowerShell `[char]` decode named in the PowerShell-analyzer spec's fold design, §5 of `2026-08-19-powershell-analyzer-design.md` — not itself yet built in `shared/analyzer/resolve.ts`, which today only implements string-concat folding (`foldConcat`) and single-assignment substitution (`resolveVars`)). The decode pass is **interpreter-gated to `mshta`/`wscript`/`cscript` only** (Chr()/fromCharCode syntax has no PowerShell meaning), and its output feeds into IOC-extraction and signature-matching exactly like any other resolved layer. The decided design does not pin a filename for this pass; structurally it belongs with the other interpreter-specific grammar handling (`cmdlex.ts`'s precedent of "separate module per distinct interpreter grammar" applies equally here), but the exact module boundary is an implementation-task decision, not a design decision.

- **Honest self-limiting for WSH/HTA (unconditional).** This pass sees `Chr()`/`fromCharCode()` but NOT string-concatenation (`"po" & "wershell"` in VBScript, `"a"+"b"` in JScript) or `Execute`/`eval` — which are at least as common in VBScript/JScript malware — so a thin WSH result must never read as "clean." Two signals, both **independent of `DecodeState`** (that vocabulary describes the fold pipeline's halting boundary, not "we never built the capability to see this class of obfuscation"):
  - an **unconditional** notice whenever `interpreter ∈ {mshta, wscript, cscript}`: *"WSH/HTA support is numeric char-code decode only; string-concatenation and Execute/eval are not resolved — a thin result here is not a clean result."* It renders even on a nominally `fully-decoded` Chr-layer, because that state is a claim about the Chr-pass's completeness, not the sample's.
  - a **cheap presence-detector as an active flagged fact** (no folding required): regex-detect concat-adjacent string literals (`"…" & "…"` / `"…" + "…"`) or `Execute(`/`ExecuteGlobal(`/`eval(` calls in the WSH corpus and surface *"string-concat / eval obfuscation present — not resolved; elevated suspicion warranted,"* converting silent absence into the same explicit "undecoded ⇒ treat as hostile" posture the PowerShell halting-boundary already uses.

**Out of scope this increment (bounded follow-up):**
- A full VBScript/JScript lexer.
- String-**concat** folding for WSH (`"a" & "b"` in VBScript, `"a"+"b"` in JScript) — this needs its own per-grammar lexing/escape rules distinct from PowerShell's, the same reason `cmdlex.ts` is a separate module rather than a `lex.ts` bolt-on.
- Deep eval-recursion: VBScript `Execute`/`ExecuteGlobal`, JScript `eval()`, `document.write` chains.
- **cmd.exe environment-variable substring/reassembly obfuscation** (`%COMSPEC:~10,1%`, `set a=…`/`%a%` reassembly) — at least as common as caret obfuscation in cmd loaders. Named here as an explicit bounded follow-up; a cheap presence-flag could land later, full resolution is deferred.

**Rationale:** commodity WSH/HTA loaders in the wild are overwhelmingly URL cradles plus a `Chr`-encoded blob. Signatures + IOC extraction + the cheap `Chr`/`fromCharCode` decode cover that shape at a fraction of the cost of a full WSH interpreter. Deep eval-recursion is its own deobfuscator with its own ROI case, deferred.

## 5. Signatures + technique IDs

All additions land as new rows in the existing `techniques.ts` `RULES` table (`techniques.ts:70-248`) and the existing `lolbins.ts` `LOLBINS` table (`lolbins.ts:14-24`), using the shapes those tables already define — no new rule-engine mechanics.

- **`finger` LOLBin.** New `LolbinEntry` in `lolbins.ts`, matching the existing `{ bin, context, techniqueIds }` shape (e.g. `lolbins.ts:15`'s `certutil` entry). `finger` must **never fire bare** — it needs a discriminating context token (e.g. a `for /f`/pipe-to-execute co-occurrence), the same "bin AND at least one context discriminator" contract `matchLolbin` (`lolbins.ts:31-42`) already enforces for every other entry. Its `techniqueIds` are pinned to `T1105` (Ingress Tool Transfer) — fetching a payload is finger.exe's only purpose in this context.
- **`cmd-cradle` rule.** New `SignatureRule` in `techniques.ts`, mirroring `download-cradle`'s existing two-part-AND shape (`techniques.ts:70-83`: `fetches && hasIexSink(ctx)`). The cmd-cradle discriminator is `for /f … in (…) do %` co-occurring with a download/exec inner command — `finger`, `curl`, `certutil -urlcache`, `bitsadmin`, or a nested `powershell`/`pwsh` (native `curl.exe`, bundled since Win10 1803, is now among the most common `for /f`-wrapped download vectors and MUST be in the set; a nested `powershell` inner command is the canonical wrapper case, §2.1). Presence of the `for /f` loop construct alone must not fire it, exactly as a bare `iwr`/`curl` alone doesn't fire `download-cradle` without an `IEX` sink. The rule carries `T1059.003` **and** `T1105`, mirroring `download-cradle`'s existing `T1059.001`+`T1105` dual-mapping.
- **Broader ClickFix decoy phrases.** Extend the existing `hasAny` decoy list in the `clickfix` rule (`techniques.ts:177`):
  ```ts
  const decoy = hasAny(ctx, ['verify you are human', 'i am not a robot', 'ray id', 'captcha', 'press win+r'])
  ```
  with additional phrasing observed in cmd-targeted ClickFix lures (e.g. "press enter to verify"/"--Verify"-style prompts from the live test sample). Stays co-occurrence-gated exactly as today — a decoy phrase alone is not sufficient on its own for any rule that isn't already structured that way.
- **mshta rule promotion.** The existing raw-text mshta signal — today only reachable via the generic `lolbin` rule's data-driven match against the `mshta` entry in `lolbins.ts:17` (`{ bin: 'mshta', context: [...], techniqueIds: ['T1218.005'] }`), plus a weaker `hta` sub-check inside `clickfix` (`techniques.ts:176`) — is promoted into its own **interpreter-aware `T1218.005` rule**: fires when `interpreter === 'mshta'`, distinguishing it from a mere LOLBin text mention. This new rule also recognizes `mshta vbscript:`/`mshta javascript:` inline execution as a discriminator, not just a `.hta`/URL target. (Optional: when that inline `vbscript:`/`javascript:` scheme is the discriminator — the script itself is VB/JS, not merely LOLBin proxy execution — the rule may additionally tag `T1059.005`/`T1059.007`; `T1218.005` alone is defensible and matches ATT&CK's primary mshta framing.)
- **wscript/cscript rule.** New `SignatureRule`(s) for executing a `.vbs`/`.js` target from a suspicious path, or a `//E:` inline-eval flag, discriminated the same way as every other rule in the table (never a bare binary-name mention). Maps to `T1059.005` (VBScript) or `T1059.007` (JScript) depending on which script type is being executed.
- **New technique IDs** (absent repo-wide today — confirmed against `techniques.ts`'s full `techniqueIds` usage and `lolbins.ts`'s table): `T1059.003` (cmd), `T1059.005` (VBScript), `T1059.007` (JScript), `T1218.005` (mshta — already used by the `lolbins.ts` mshta entry and the `clickfix` rule's technique list, but not yet backed by an interpreter-aware rule of its own). (`T1105` is NOT new — it is already in the catalog via `download-cradle`; `finger` and `cmd-cradle` reuse it, they do not introduce it.)
- **`start` is a companion discriminator only** — usable inside `cmd-cradle`/`clickfix` as a co-occurrence signal, never registered as a standalone LOLBin entry (too benign alone; `start notepad.exe` is unremarkable).

No new characterization mechanics: the specificity-gated red/amber system in `report.ts` (`deriveCharacterization`, `report.ts:125-151`) is unchanged. New rules get honestly-assigned `baseSpecificity` under the existing three-tier vocabulary (`cmd-cradle` as `strong` — it has a real benign twin in legitimate batch automation; `finger` as `weak`-with-context — `finger` alone is essentially never seen and is a strong tell, but the rule fires only with a discriminator present, so its base tier should reflect "not intrinsically near-dispositive on its own").

## 6. Extract IOC-leak fix (`extract.ts`)

Fixes the false-positive proven by the live test: `cmd.exe` itself (and similar binary-name tokens) getting mis-typed as a domain IOC.

- **New extension denylist**, applied beside the existing PascalCase `.NET`-member guard at `extract.ts:24-26`:
  ```ts
  // .NET member-access tokens (Net.WebClient, IO.MemoryStream, wc.DownloadString)
  // are mis-typed as domains by the shared detectType. They're PascalCase; real
  // domains are conventionally lowercase and URL hosts arrive via the URL branch.
  if (type === 'domain' && /[A-Z]/.test(raw)) continue
  ```
  The PascalCase guard catches `Net.WebClient` but not lowercase filenames like `cmd.exe`, `kernel32.dll`, `amsi.dll` — which the shared TLD-agnostic domain regex in `detectType` happily accepts as a "domain." A denylist on trailing extensions — `.exe`, `.dll`, `.sys`, `.bat`, `.cmd`, `.scr`, `.ocx`, `.cpl`, `.msi`, `.vbs`, `.ps1`, `.js`, `.hta` — added as a second guard clause immediately beside the PascalCase check closes this.
- **Scope: local to `extract.ts`, not `shared/indicators.ts`.** `indicators.ts`'s `detectType` is used far beyond the analyzer (it's the general-purpose type-detector behind `/api/enrich` and the extension-wide indicator UI), so an extension-based exclusion there would change behavior for every consumer, not just the analyzer's IOC harvest. This is the same reasoning that already keeps the PascalCase guard local to `extract.ts` rather than upstreamed into `detectType` — precedent, not a new pattern.
- **Token-scoping the domain regex** (matching only within lexer string-literal tokens, rather than the current whole-text `CANDIDATE_RE` regex scan at `extract.ts:7`) is a recognized, aligned improvement — the recon that fed this design noted `extract.ts` currently violates the project's general "match over tokens, never raw text" doctrine. It is **not** done in this increment; the denylist is the fix that ships. Token-scoping is noted here as an explicit optional follow-up, not silently dropped.

## 7. Unchanged / binding

These hold for every new interpreter exactly as they hold for PowerShell today — no exceptions, no interpreter-specific carve-outs:

- **Characterization mechanics are unchanged.** The specificity-gated red/amber(/suspicious) system in `report.ts` is not touched by this increment. New rules integrate into the existing `baseSpecificity`/co-occurrence machinery; no new characterization tiers or logic are introduced.
- **Reserved-colour law** — technique/LOLBin/signal chips stay periwinkle/neutral; red/amber/green stay verdict-severity only.
- **The data boundary** — a pasted command line never reaches `/api/enrich` on its own; the only egress is an analyst-initiated, same-origin lookup.
- **No `iocs.json`, strict CSP** — unchanged.
- **Zero AI attribution** — unchanged, applies to this increment's commits the same as every prior analyzer commit.
- **Deterministic, client-side, never executes input.** This is the load-bearing invariant this whole increment extends rather than relaxes: `cmdlex.ts` is a string→string normalizer, the numeric-char-code decode is a regex-driven text transform, and body/target extraction for mshta/wscript/cscript is string slicing — none of the four new interpreters' handling involves `eval`, `new Function`, dynamic dispatch, or any other execution of the pasted input, for any interpreter, at any stage.

## 8. Terminology disambiguation

The PowerShell-analyzer spec's stage-1 description (`2026-08-19-powershell-analyzer-design.md` §2, stage 1: "strip the `powershell.exe … -enc <b64>` cmd-flag wrapper (**cmd syntax**, a separate concern from PS grammar)") uses "cmd syntax" to mean **PowerShell's own command-line flag syntax** (`-enc`, `-nop`, `-w hidden`, etc.) — not the cmd.exe interpreter. This increment introduces cmd.exe as an actual interpreter for the first time, creating a real collision risk with that earlier wording.

**This spec, and any code/comments/commit messages it produces, must say "cmd.exe interpreter" or "command-shell interpreter" explicitly** wherever the cmd.exe program is meant, and reserve unqualified "cmd syntax"/"cmd-flag" phrasing for PowerShell's own flag grammar as the prior spec used it. This is a documentation/naming discipline, not a code change.

## 9. Build sequencing

Dependency-ordered:

1. **Extract IOC-leak fix (§6).** Independent of everything else in this increment — lands first, standalone.
2. **`detectInterpreter()` + `preprocess()`'s `interpreter` field (§1–2).** Prerequisite for every other piece; the PS-path regression guard (§1) is verified here before anything else builds on top.
3. **`cmdlex.ts` caret deobfuscation (§3).** Gated on #2 (needs `interpreter` to enforce the non-negotiable `interpreter === 'cmd'` gate).
4. **Numeric-char-code decode pass (§4).** Gated on #2 (needs interpreter-aware invocation, restricted to mshta/wscript/cscript).
5. **Signatures + technique IDs (§5).** Gated on #2; benefits from #3/#4 landing first (a cleaner, deobfuscated corpus makes the new rules easier to write and test), but the rule-table rows themselves have no hard code dependency on #3/#4.

**Parallelizable:** #1 (independent) and the `finger`-LOLBin row within #5 can proceed alongside the #2→#3→#4 chain. #2→#3→#4 is a strict chain; #5 depends on #2 but not on #3/#4 landing first (only benefits from it).

## 10. Testing

Mirrors the existing `shared/analyzer/__tests__/` shape — one `.test.ts` per module plus cross-module `integration.test.ts`/`report.test.ts`-style coverage at the `analyze()` level, `describe`/`it` blocks per rule with an explicit **benign-twin** case per new signature (the pattern already established in `techniques.test.ts` and `lolbins.test.ts` — e.g. `lolbins.test.ts`'s "does NOT hit certutil doing legitimate cert work" case). `web/vitest.config.ts` already globs `../shared/**/*.test.ts` (confirmed at `web/vitest.config.ts:22`) — no config change needed for new test files anywhere under `shared/analyzer/__tests__/`.

- **`preprocess.test.ts` (extended):** `detectInterpreter` fixtures — one positive case per interpreter (`powershell`, `cmd`, `mshta`, `wscript`, `cscript`) plus an `'unknown'` fallback case; a path/quote-prefix fixture (`"C:\Windows\System32\cmd.exe" /c ...`) proving the leading-token detection survives a wrapping path, mirroring the existing PS-wrapper-strip test shape. A regression fixture proving `preprocess()`'s `script`/`encoded`/`flags` output for a plain PowerShell input is byte-identical before/after the `interpreter` field is added.
- **`cmdlex.test.ts` (new):** the load-bearing correctness suite for §3 — `^^`→`^` and bare-`^`-drop outside quotes; carets left untouched inside `"…"`; caret processing correctly applies inside a `for /f 'list'` single-quoted segment; a trailing-`^` line-continuation fixture that does NOT consume into a synthetic next character; and the **non-negotiable gating test**: feeding a PowerShell literal containing `^` (e.g. a regex `'^https?://'`) through the full pipeline with `interpreter !== 'cmd'` and asserting it is byte-for-byte untouched — a "fixed without breaking PS" claim needs this failing-without-the-gate test, per the project's existing testing discipline (`2026-08-19-powershell-analyzer-design.md` §12's "a 'fixed' claim needs a failing-without-fix test").
- **WSH numeric-char-code decode (new, module TBD per §4):** `Chr(72)&Chr(105)` → `"Hi"` (VBScript); `String.fromCharCode(72,105)` → `"Hi"` (JScript); an interpreter-gating test proving the pass does not fire for `interpreter === 'powershell'`/`'cmd'`; a fixture proving it is intentionally NOT applied to a string-concat case (`"a" & "b"`) — the explicit out-of-scope boundary from §4 rendered as a test, not just prose.
- **Extraction (`preprocess.ts`/`report.ts`, extended):** per-interpreter body/target extraction fixtures — cmd `/c`/`/k` body extraction; mshta URL vs. inline `vbscript:`/`javascript:` extraction; wscript/cscript `.vbs`/`.js` target extraction plus the new `//E:`/`//B`/`//NoLogo` WSH flag fixtures (mirroring `preprocess.test.ts`'s existing flag-capture assertions).
- **`extract.test.ts` (extended):** a fixture proving `cmd.exe`/`kernel32.dll`/`amsi.dll`-shaped lowercase filenames are no longer extracted as domain IOCs (the exact false positive the live test surfaced), alongside the existing PascalCase-guard test (`extract.test.ts`'s "does not extract .NET member-access tokens as domains") so both guards are independently verified.
- **`techniques.test.ts` (extended):** one positive + one benign-twin fixture per new rule — `cmd-cradle` positive (`for /f` + `finger`/`certutil` inner command) vs. benign twin (a `for /f` loop with no download/exec inner command); `finger` LOLBin positive (with discriminator) vs. benign twin (bare `finger user@host`, which must NOT fire); broadened ClickFix decoy-phrase fixtures; a co-occurrence-upgrade test involving at least one new rule (e.g. `cmd-cradle` + a broadened ClickFix decoy). Plus a targeted benign-twin: `for /f` parsing `robocopy`/`reg query`/`dir` output with NO download/exec inner command must NOT fire `cmd-cradle` — a real-world FP pressure test, not just an "absent inner command" case.
- **`lolbins.test.ts` (extended):** `finger` entry fixtures following the existing per-entry positive/negative pattern (`lolbins.test.ts:11-37`).
- **mshta/wscript/cscript rule tests:** positive fixture per new rule + a benign twin per rule (e.g. `mshta` launching a local trusted `.hta` with no URL/inline-script discriminator should not fire the new interpreter-aware rule, matching the "bin AND discriminator" contract already enforced elsewhere).
- **WSH honesty signals (new, §4):** the unconditional WSH-limits notice renders for `interpreter ∈ {mshta, wscript, cscript}` EVEN on a `fully-decoded` Chr-layer (the state is a claim about the Chr-pass, not the sample); the concat/eval presence-detector fires on `"po" & "wershell"` (VBScript concat), `"a"+"b"` (JScript concat), and `Execute(…)`/`eval(…)`, surfacing the "not resolved — elevated suspicion" signal rather than silent absence; and a plain-PowerShell input does NOT trigger either signal (interpreter-gated).
- **Nested interpreter re-entry (new, §2.1):** `cmd /c powershell -w hidden -enc <b64>` decodes the inner `-enc` blob — a decode-ladder layer for the `cmd→powershell` transition appears with the Base64 resolved, and the resulting signals/IOCs match what the same PowerShell payload yields top-level; plus a depth-cap fixture proving a pathological wrapper-in-wrapper terminates instead of spinning.
- **`integration.test.ts` (extended):** an end-to-end fixture reproducing the live-test finding — the caret-obfuscated `cmd /c ... for /f ... ('finger user@host') do %e ...` ClickFix sample — asserting it now yields the `cmd-cradle` and/or `finger` signal(s), the decoy-phrase-widened `clickfix` signal, and **no** `cmd.exe`-as-domain IOC, closing the exact gap the increment was scoped against.
- **Determinism:** same input → identical `AnalysisResult` (minus `checkedAt`) for every new interpreter path, matching the existing determinism test pattern in `techniques.test.ts`.
- **Build gate:** `tsc -b` clean (the `Interpreter` union and `preprocess()`'s widened return type must type-check across every existing call site) plus full `vitest` green, the same two-part gate the PowerShell-analyzer spec's phases already use (`2026-08-19-powershell-analyzer-design.md` §13, e.g. "Gate: `tsc -b` clean, one smoke test").
