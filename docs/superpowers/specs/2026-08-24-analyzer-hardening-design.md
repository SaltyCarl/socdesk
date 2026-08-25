# SOCDesk — Analyzer Hardening: Design Spec

**Date:** 2026-08-24 · **Status:** design, pre-implementation · **Author:** SaltyCarl
**Scope target:** `shared/analyzer/*` + `shared/analyzer-ui/*` + `shared/intent.ts` (the live `web/`/`shared/` stack — *not* the superseded `site/`/Python tier). Extends the two prior analyzer specs (`2026-08-19-powershell-analyzer-design.md`, `2026-08-19-multi-interpreter-analyzer-design.md`); their doctrine is inherited, not restated.

---

## 0. Summary

An external critical review (`SOCDesk-Analyzer-Review-2026-08-24.pdf`, 7 live samples + static read) confirmed the analyzer is best-in-class on its happy path but has **two holes that undercut its core "translate for L1/L2" promise** and a backlog of five lesser gaps. Every finding was re-verified against the code this session (file:line in §1). This spec hardens all eight, in four tested phases, keeping every existing doctrine (specificity gating, benign-twin discipline, reserved-colour law, data boundary, no-account read path, deterministic client-side, zero AI attribution).

**The single organizing principle** (the review's own headline recommendation): **never render blank on input the analyzer could not fully process.** A malicious multi-stage stager the decode ladder can't open currently renders *identically* to a benign one-liner — blank — so an L1's mental model ("nothing found = safe") turns a silent false negative into a dangerous one. The fix reuses the honesty vocabulary the tool already applies to its verdict (resolved / inferred / **opaque**) and applies it to decode failure: an unresolvable construct becomes a visible *opaque partial*, not silence.

## 1. Findings (all re-verified this session)

| # | Sev | Finding | Confirmed at |
|---|-----|---------|--------------|
| 2.1 | CRIT | Plain base64 inner stage never decoded; malicious ≡ blank ≡ benign | `report.ts:154-165` (only `inflate()` tried); tests only cover gzip'd inner (`report.test.ts:80-85`) |
| 2.2 | HIGH | Download-to-disk-then-exec cradle yields zero signals | `techniques.ts:111-116` (cradle needs an in-memory sink); `.Invoke()` deferred (`report.ts:279`) |
| 2.3 | HIGH | Fabricated Squiblydoo narrative on benign `regsvr32 /u`, `rundll32 shell32.dll` | `lolbins.ts:18-19` (bare `'/u '`, `shell32.dll` as triggers); `bullets.ts:553-555` (hardcoded text) |
| 2.4 | MED | T1490 shadow-delete missed; ClickFix over-fires | no `vssadmin`/`wbadmin`/`bcdedit`/`shadowcopy` anywhere in `shared/`; ClickFix `hiddenFetchIex` branch `techniques.ts:224` |
| 2.5 | MED | cmd deobfuscation is caret-only (the named "cmd" half) | `cmdlex.ts` (only `^` stripping; no `set`/`%var%`/`%COMSPEC:~%`) |
| 2.6 | MED | No debounce, no size cap, unbounded inflate | `usePsAnalysis.ts:11` claims "debounced-by-caller" but `PowerShellAnalyzer.tsx:34` doesn't; `fold.ts` inflate unbounded (`resolve.ts:92` caps, inflate doesn't) |
| 2.7 | LOW | IOC over-extraction + lone-filename routing leak | `extract.ts:14` denylist misses `.json/.xml/.txt/.log`; `intent.ts` `EXE_NAME_RE` lists only 9 bins → lone `mimikatz.exe` routes to `/api/enrich` |

The review's "well done" section (specificity gating on *base* specificity `report.ts:232-253`, benign-twin discriminators, no decoy-text leak into verdict, data boundary holds) was also verified and is **preserved unchanged** by every fix below.

## 2. Doctrine (inherited — do NOT violate)

- **100% client-side, deterministic TypeScript. No LLM. Never executes input** (CSP `script-src 'self'`, no `unsafe-eval`).
- **Specificity-gated characterization.** Only an *intrinsically* near-dispositive signal (no legitimate use) earns "high-confidence malicious"; a strong signal upgraded by company stays "suspicious — review." New rules declare `baseSpecificity` honestly (`report.ts:232-253` reads base, not upgraded).
- **Benign-twin discipline.** Every risky rule carries a discriminator that its benign twin fails. New rules ship with the twin as a negative test.
- **Honesty is a first-class output.** Silent partial success is the cardinal sin — this spec's spine.
- **Reserved-colour law** (`shared/ui/Chip.tsx`): the partial-decode notice is neutral/periwinkle (an honesty read, gray-means-unknown), never red/amber — those stay earned severity only.
- **Data boundary:** a pasted command never leaves the browser; the only egress is the analyst-clicked same-origin `/api/enrich`. §7 (2.7) *tightens* this, never loosens it.
- Commits `feat(analyzer): …` / `fix(analyzer): …` as SaltyCarl, **zero AI attribution**.

## 3. Approach

**Chosen: opaque-residue detector first, then incremental decoders that shrink the opaque set.** The safety property (no blank on unprocessable input) ships in Phase 1 and is future-proof — any encoding we never handle still renders "opaque, escalate," and each later decoder *converts* an opaque residue into a real layer. Reuses the existing `DecodedLayer{state:'opaque'}` machinery (already used for a malformed `-enc` payload at `report.ts:135-141`).

**Rejected:** *decode-ladder-first* (leaves the malicious≡blank hole open for the whole effort; reopens on every future unknown encoding — the review's central argument is legibility-beats-coverage); *generic PS expression VM* (large surface, hard to bound against ReDoS/decode-bombs, overkill for the enumerated obfuscation set).

## 4. Phase 1 — Failure legibility + honest narratives

### 4.1 Opaque-residue detector — new `shared/analyzer/residue.ts`

Called from `analyze()` after the decode/resolve chain settles (after the layer loop, before the return). Scans the final resolved text (or the preprocessed script when no layers exist) for **encoding constructs that produced no decode layer.** Four rules, each with a benign-twin discriminator:

- **R1 unresolved-base64** — a quoted base64-shaped literal (≥16 chars, passes `looksBase64`) that no layer consumed, co-occurring with a decode-API mention (`FromBase64String`, `[Convert]::`). The API mention is the discriminator; a bare base64-charset word never fires.
- **R2 dynamic-execution-unresolved** — an IEX / `&` / `.Invoke()` sink whose operand the resolve chain could not reduce to a literal, with construction evidence present (`GetString`, variable concat, `[char]`, `-join`, `-f`, `-replace`, reversal, `-bxor`). **Excluded:** a sink whose operand is a network fetch — that is download-cradle's job, nothing local to decode.
- **R3 unresolved-char-assembly** — `[char]`-array / numeric `-join` shapes that produced no layer (same sink-or-decode-API gate).
- **R4 unresolved-cmd-expansion** — cmd interpreter path only: `%VAR:~n,m%`, or `set x=…` + adjacent `%a%%b%` left unresolved. A bare `%PATH%` never fires.

Each finding **appends an opaque `DecodedLayer`** (`text:null`, `state:'opaque'`, `residual:{bytes, entropy, note}`) — the exact shape `report.ts:135-141` already emits. This mechanically flips `confidence.state` to `'partial'` via the existing `fullyDecoded === layers.length` math (`report.ts:207-209`), feeds `DecodeLadder` (already renders opaque layers), and a matching opaque **bullet** lands in `ActionBullets`' existing "Could not resolve" block: *"An embedded &lt;construct&gt; could not be resolved — content unknown; treat as opaque and escalate."* `entropy` = Shannon entropy of the residual substring; `note` names the construct.

### 4.2 Partial-decode UI notice — `shared/analyzer-ui/AnalyzerResult.tsx`

One new element: a `PartialDecodeNotice` band shown when `result.confidence.state === 'partial'`, **neutral/periwinkle** per reserved-colour law. Copy: *"Partially decoded — an inner construct could not be resolved. A thin result here is not a clean result; escalate for manual review."* Because `AnalyzerResult` is the shared surface (`web/` `/analyzer`, cockpit result region, extension), all three get it from one change. No other component changes.

### 4.3 LOLBin truth-gating (2.3)

**Curate `LOLBINS` context tokens to real abuse discriminators** (`lolbins.ts:14-32`):

| bin | drop | keep / add |
|-----|------|-----------|
| regsvr32 | `'/u '` | `/i:http`, `scrobj`, `http://`, `https://` |
| rundll32 | bare `shell32.dll` | `javascript:`, tighten → `url.dll,fileprotocolhandler`, `mshtml,runhtmlapplication` |
| msiexec | `'/q'` | remote-URL forms only |
| installutil | `'/u '`, `'.exe'` | `/logfile=`, `logtoconsole` |

certutil, bitsadmin, mshta, wmic, conhost, finger: already sound, unchanged.

**Variant-aware bullets** (`bullets.ts:544-569`): the regsvr32 / rundll32 bullets stop being hardcoded. Their `fires()` re-tests the in-hand ctx (same pattern as `constructUrlHost`) and renders only what matched — `/i:` + http/scrobj → Squiblydoo text; URL-only → "Executes regsvr32 with a remote target"; nothing else fires post-gating. **Structural rule: "remote"/"script"/"Squiblydoo" appear only when the token proving them matched** — no-invent enforced by construction.

### 4.4 Phase 1 tests (failing-first)

New `shared/analyzer/__tests__/review-samples.test.ts` pins all 7 review inputs as a **ratcheting integration fixture** (later phases upgrade the expected result). Plus: sample 6 → opaque layer + partial state + notice; sample 2 benign → still perfectly silent; `IEX (iwr http://…)` cradle → no residue; resolved `$a='…'; IEX $a` → no residue; sample 7 → zero signals, zero bullets; real Squiblydoo → fires; `rundll32 shell32.dll,Control_RunDLL`, `msiexec /i app.msi /qn`, `installutil /u app.exe` → all silent; canonical installutil abuse → fires.

## 5. Phase 2 — Decode-ladder expansion (2.1, part 2.5)

Five decoders, each converting a Phase-1 opaque residue into a real layer.

**In `report.ts` (layer-producing, beside inflate at 154-165):**
- **Plain base64 → text** (the 2.1 fix). Embedded-literal loop tries inflate first (unchanged), then plain decode: sniff NUL-at-odd-index ratio → UTF-16LE vs UTF-8, gate on existing `isMostlyPrintable ≥ 0.85`. Attempted only when a decode-API mention co-occurs **or** the literal is ≥32 chars (a short base64-shaped bareword never yields a junk layer). Non-printable result → **not** a layer; falls to residue detector ("decodes to non-text — N bytes, entropy X"). Sample 6 flips to a visible `Base64 → text (UTF-8)` layer.

**In `resolve.ts` (constant folds, literal-only, straight-line — module's existing doctrine):**
- **`[char]` / `-join` assembly** — `[char]78`, `[char[]](110,…) -join ''`, literal-array joins.
- **`-f` format operator** — literal format string + literal args, plain `{N}` only; format-specs left unresolved → residue.
- **`-replace` / `.Replace()` chains** — literal subject + args. **ReDoS guard: `-replace` applied only when the pattern is metacharacter-free (plain substitution); anything regex-fancy is skipped → residue.** A hostile paste must never hand our own analyzer a catastrophic regex.
- **String reversal** — `-join $s[-1..-($s.Length)]`, `[array]::Reverse` over a known literal, after variable substitution yields a literal.

Folded text flows through the existing `resolve (fold/substitute)` layer + IEX recursion — no new plumbing. **`-bxor` deferred** (needs key/loop emulation; residue detector names it honestly) → §9 backlog.

**Tests:** per-decoder units in `resolve.test.ts`/`report.test.ts`; sample-6 fixture ratchets opaque→decoded; negatives pin benign `-join ','`, variable-arg `-f`, regex `-replace` as untouched-no-layer-no-false-residue.

## 6. Phase 3 — Detection gaps (2.4, 2.2)

New rules in `techniques.ts`, all benign-twin disciplined:

- **T1490 shadow/recovery-tamper** (`baseSpecificity: near-dispositive` — no admin-legitimate interactive use in a pasted one-liner, the review's #1 pre-ransomware indicator). Fires on destructive verb + object: `vssadmin delete shadows` / `vssadmin resize shadowstorage`, `wmic shadowcopy delete`, `wbadmin delete catalog|systemstatebackup`, `bcdedit … recoveryenabled no` / `bootstatuspolicy ignoreallfailures`. Discriminator: never a bare `vssadmin list`. Bullet: "Deletes volume shadow copies / disables recovery — destroys ransomware rollback." Fixes sample 3.
- **Download-to-disk-then-exec cradle** (extend `download-cradle`, `baseSpecificity: strong` — dropper has a benign-installer twin). Second accepted shape: to-disk fetch (`DownloadFile`, `iwr -OutFile`, `curl -o`, `certutil -urlcache … <path>`, `Start-BitsTransfer -Destination`) **+** local-exec sink (`Start-Process`, `Invoke-Item`, `saps`, `& <path>`, `.exe` in corpus). Bullet: "Downloads a file to disk and executes it." Fixes 2.2.
- **ClickFix trait-gating** (`techniques.ts:214-239`). `hiddenFetchIex` **no longer alone** satisfies ClickFix — it must co-occur with an actual paste-and-run trait (`decoyPhrases`, `--verify` decoy, `conhost --headless`, mshta lure). A plain `-enc` cradle reads as download-cradle only (fixes samples 1 & 4). `hidden -nop -w` alone stays an evasion-cluster contributor, unchanged.
- **Offensive-tool-name rule** (`baseSpecificity: near-dispositive` — no benign twins): `invoke-mimikatz`, `dumpcreds`, `sekurlsa::`, `rubeus`, `-dumpcreds`. So the decoded sample-6 payload also characterizes rather than rendering decoded-but-signal-less. *(Owner veto point at spec review.)*

**Tests:** sample 3 → shadow-delete signal + bullet; `vssadmin list shadows` → silent; `DownloadFile+Start-Process` → dropper; benign `iwr -OutFile update.zip` (no exec) → silent; samples 1/4 → cradle **without** ClickFix; a real fake-CAPTCHA lure → ClickFix still fires.

## 7. Phase 4 — cmd reassembly + robustness + IOC hygiene (2.5, 2.6, 2.7)

**cmd `set`/`%var%` reassembly** — new logic invoked from `preprocess.ts`'s **cmd branch only** (never PS text, per `cmdlex.ts`'s non-negotiable), applied before interpreter re-entry:
- `set VAR=VALUE` (incl. quoted `set "x=y"`) parsed straight-line → substitute `%VAR%` refs. Fixes sample 4's `set x=power && set y=shell && %x%%y%` (caret-strip already ran).
- `%VAR:~n,m%` / `%COMSPEC:~n,m%` substring; `!VAR!` delayed-expansion treated as `%VAR%` when `enabledelayedexpansion` present.
- **Bounded:** single pass, var map ≤64, reference expansion depth-1 (no recursive `%a%`→`%b%`), so a hostile `set` chain can't spin it.
- **`cmd-var-obfuscation` weak signal** fires when reassembly changed the text — even a half-resolved case is surfaced, never silent.

**Robustness (2.6):**
- **Debounce** — `useDebounced` hook in `analyzer-ui/`; `PowerShellAnalyzer.tsx` + cockpit caller debounce ~200ms before `usePsAnalysis`. Makes the hook's existing "debounced-by-caller" comment true.
- **Size cap** — `analyze()` caps input at **64 KB**; past it, analyze the head + emit an opaque "input truncated for analysis — N KB not scanned" notice (reuses Phase-1 partial machinery). Bounds the ≤6×≤12 re-tokenization.
- **Bounded inflate** — `fold.ts` `inflate()` output cap **2 MiB** (mirrors `resolve.ts:92`), reads incrementally, bails past cap → null → honest opaque residue, not a hang.

**IOC hygiene (2.7):**
- `extract.ts:14` — widen `BINARY_EXT_DENYLIST` with `json|xml|txt|log|csv|dat|tmp|ini|cfg`. Add a known-.NET-namespace prefix guard (`system.`, `net.`, `io.`, `text.`, `management.`) so all-lowercase `system.io.memorystream` (which passes the `[A-Z]` guard) stops yielding a bogus domain IOC.
- `intent.ts` — add the same binary-extension denylist to the classifier so a lone `mimikatz.exe`/`kernel32.dll` classifies as `command`/unclassified, **not** `domain` — closing the `routeSelection → /api/enrich?type=domain&q=mimikatz.exe` filename leak. **Data-boundary fix → dedicated test** asserting no enrich route for bare malware filenames.

**Tests:** sample 4 → full cmd re-entry + decoded cradle; `set`-bomb → bounded, no hang; 64KB+1 paste → truncation notice; gzip-bomb literal → null + opaque residue; `-OutFile data.json` → no IOC; lone `mimikatz.exe` → not routed to enrich.

## 8. Acceptance criteria

1. **No blank on unprocessable input.** Sample 6 (and any base64/`[char]`/`-join`/cmd-var construct the ladder can't open) renders an opaque partial + the notice, never blank. Sample 2 (benign) stays perfectly silent.
2. **No fabrication.** Sample 7 → zero signals/bullets; the regsvr32/rundll32 bullets name only what matched.
3. **Decoded coverage.** Samples 4 & 6 fully decode and characterize by end of Phase 3/4.
4. **Detection gaps closed.** Sample 3 flags T1490; a disk-then-exec dropper flags; ClickFix fires only on real ClickFix traits.
5. **Bounded + hygienic.** 64 KB cap, 2 MiB inflate cap, debounced input; no bogus `.json`/filename IOCs; no malware-filename enrich route.
6. **Doctrine intact.** Specificity gating, benign-twin discipline, reserved-colour, data boundary, no-account read path all unchanged. Every "well done" behavior from the review still passes.
7. **QA gate green each phase:** `npm --prefix web run build` (`tsc -b`) + `cd web && npx vitest run ../shared` + `npx vitest run src` all pass; each fix has a test that fails without it.

## 9. Out of scope (logged backlog — YAGNI)

`-bxor` decode; WMI/CIM fileless (`Invoke-CimMethod … Create`); nltest recon; reg-run persistence variants; extra LOLBins (msbuild, cmstp, mavinject, odbcconf, regasm/regsvcs, esentutl, extrac32, expand, forfiles, hh, ieexec, certreq); `certutil -decode/-encode`; the generic-expression-VM engine; a **runtime** banned-word guard (stays test-side — considered, deferred: the no-invent-by-construction rule in §4.3 addresses the one confirmed fabrication path).

## 10. Delivery & QA

| Phase | Ships | Fixes |
|-------|-------|-------|
| 1 | opaque-residue detector + partial-decode notice; LOLBin truth-gating | 2.1/2.2 safe, 2.3 |
| 2 | plain-base64→text, `[char]`/`-join`, `-f`, `-replace`, reversal | 2.1, part 2.5 |
| 3 | T1490, disk-then-exec cradle, ClickFix gating, offensive-tool rule | 2.4, 2.2 |
| 4 | cmd `set`/`%var%`/`%COMSPEC:~%`, debounce/size-cap/bounded-inflate, IOC/intent denylist | 2.5, 2.6, 2.7 |

- **Branch:** fresh off `main` (isolates from in-flight `feat/ransomware-profile-rebuild`).
- **TDD every fix** (failing test first, per house rule "Fixed requires a test that fails without the fix").
- **`nt` note-taker checkpoint after each phase.**
- **Commits** one logical unit each, `feat(analyzer):`/`fix(analyzer):`, SaltyCarl, zero AI attribution.
- Full implementation plan follows via the writing-plans skill after this spec is approved.
