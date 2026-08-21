# SOCDesk — Session Handoff

**Written:** 2026-08-08 · **Updated:** 2026-08-21 (session 8 — escalation-card redesign + OTX/AbuseIPDB/GreyNoise enrich LIVE, analyzer-in-extension MERGED, IOC-reporting Phase 0+1 MERGED + DEPLOYED live, interactive dogfood pending) · **Read §0 first.**

---

## 0. LATEST — 2026-08-21 (session 8 — escalation-card + enrich sources LIVE, analyzer-in-extension MERGED, IOC-reporting Phase 0+1 MERGED + DEPLOYED live)

> Newest block. Two units shipped to `main`/live since session 7 (escalation-card
> redesign + three enrich-source changes; the analyzer lifted into the browser
> extension), plus a third **built but not merged**: the IOC-reporting Phase 0+1
> crowdsourced-abuse write path on branch `feat/ioc-reporting-p01` (12 commits
> ahead of `main`). `main` = `origin/main` = `043601a` (reporting spec/plan/
> research docs only, not the implementation); branch HEAD `23d6a22`.

### 1. Escalation-card redesign + enrich sources (`main`, LIVE)
- GreyNoise honesty: an *observed* source is no longer treated as a no-record
  coverage gap (`eda8ed1`).
- AbuseIPDB attack-category chips on the IP card (`31f053f`, dogfooded live).
- AlienVault OTX added as an enrich source — `kind:context`, **excluded from the
  independent-sources tally** (`133a460`; 9s timeout for its Cloudflare-egress
  throttling `b7f1e84`; backlog marked shipped `2a631ea`).
- `coverageState` terse "show, don't tell" assessment + OTX attention chip
  (`98f7dc4`); redundant source verb dropped + OTX deduped to the chip
  (`41053c2`); `splitLead` evidence-lead-figure highlight + **Context section
  removed** (`0b0c708`). Supporting run: risk-graduated signal chips + declutter
  (`b147fe5`), IP-literal URL hosts as their own IOC (`eb7ffd9`), RDAP reg-age
  honesty + blank-state (`cb1d9e0`), technique-signal trigger labeled an audit
  fact (`52c3d38`), inline-expand IOC lookup (`f794ac4`), `-enc` whitespace
  tolerance (`8cef3e1`), cockpit routes cmd/mshta/wscript/LOLBin to the analyzer
  (`3964b4c`).

### 2. Analyzer lifted into the browser extension (`main`, MERGED + deployed)
- Analyzer now runs in the extension side panel with right-click routing to
  analyze / lookup / report. Built via a 5-task SDD (spec `2151aab`, plan
  `14d75e0`); **7 impl commits**: shared card-theme hook + inline-enrich resolver
  (`1786a60`), analyzer UI lifted into `shared/analyzer-ui` decoupled from inline
  lookup (`aaf3a7c`), right-click selection routing (`a139e3e`), side-panel
  analyzer surface (`fecb48f`), side panel + v0.3.0 bump (`ec8f458`), README
  fallback-gate fix (`0e85a45`), panel-handoff/effect cleanup + type tightening
  (`7d563af`). Whole-branch review clean; merged to `main`.

### 3. IOC-reporting Phase 0+1 — crowdsourced abuse-report write path (branch `feat/ioc-reporting-p01`, 12 commits, NOT merged)
- Foundation + write path for authenticated abuse reporting. Stack: Cloudflare D1
  (`socdesk_reports`, bind `DB`) + hand-rolled GitHub OAuth (write-path only, no
  PII, HMAC-signed session cookie) + `POST /api/report` (guard order:
  session→turnstile→validate→ban→daily-cap→dedupe→queued) + `GET /api/report/mine`
  + web report form + `/reports` view (`nav:false`) + docs reframe (no-account
  READ path, auth-gated WRITE path). Read path / `/api/enrich` / analyzer
  unchanged.
- Commits: HMAC session sign/verify (`96a7310`), validation + daily-cap policy
  (`d2786f6`), D1 schema + parameterized DAL (`a5d5b83`), GitHub OAuth
  start/callback + `requireSession` (`2494b5c`), open-redirect guards (`776309b`,
  `bdb3752`), `POST /api/report` + `/mine` (`f70c184`), report button + form +
  `/reports` + Turnstile CSP (`03cd0ad`), identity reframe (`68b27df`),
  report-button type gate + Turnstile retry/dedup + list error state (`d5ca902`),
  OPERATIONS owner-setup correction (`23d6a22`); plan-test correction (`b816c1a`).
  Branch HEAD `23d6a22`.
- Key files: `lib/reporting/{session,validate,policy,db}.mjs`;
  `functions/_lib/session.mjs`; `functions/api/auth/github/{start,callback}.js` +
  `functions/api/auth/logout.js`; `functions/api/report.js`;
  `functions/api/report/mine.js`; `migrations/0001_init.sql`;
  `web/src/components/report/{useSession,ReportButton,ReportForm}.tsx`;
  `web/src/routes/MyReports.tsx`; `web/src/routes/Lookup.tsx`;
  `web/public/_headers` + `web/index.html` (CSP adds `challenges.cloudflare.com`);
  `docs/OPERATIONS.md`.
- Artifacts already on `main` (`f70b571`, `c47b14e`, `043601a`):
  `docs/superpowers/specs/2026-08-20-ioc-reporting-phase01-design.md`;
  `docs/superpowers/plans/2026-08-21-ioc-reporting-phase01.md`;
  `docs/superpowers/research/2026-08-20-reporting-{storage,auth,integration}.md`;
  `docs/competitive-landscape.md`.

### 4. IOC-reporting Phase 0+1 — MERGED to `main` + DEPLOYED live (supersedes §3's branch/unmerged status)
- **Merged + deployed** (2026-08-21). `feat/ioc-reporting-p01` rebased onto
  `origin/main`, fast-forwarded, pushed — `main` tip `e72760d` (= `origin/main`,
  git-confirmed). Deploy run **32473705287** (collect-and-deploy,
  `workflow_dispatch`) green per invoker: pytest → collectors → Vite build →
  Cloudflare Pages direct-upload.
- **Deploy fix** (`704c51b`, on `main`): `VITE_TURNSTILE_SITEKEY` is a build-time
  Vite inline and the prod build runs in **GitHub Actions** (direct-upload), NOT on
  Cloudflare — so it must be a GitHub **Actions variable** fed into the workflow's
  Vite step (added), not a Cloudflare Pages var. `docs/OPERATIONS.md` corrected.
- **From-here live verification** (per invoker; no account needed): socdesk.io →
  200; `GET /api/auth/github/start` → 302 to github.com/login/oauth/authorize with
  `client_id=Ov23li3sw0imGDGok8Gx`, exact `redirect_uri`
  `/api/auth/github/callback`, empty scope, signed HMAC `state` (⇒ `GITHUB_CLIENT_ID`
  + `SESSION_SECRET` live); `POST /api/report` + `GET /api/report/mine` with no
  session → 401 (Functions deployed, auth guard live); deployed bundle
  `index-CJ63pfQI.js` has the Turnstile sitekey inlined (`0x4AAAAAAE…`) ⇒ build-var
  chain confirmed end-to-end.
- Owner created a **GitHub App** (`Ov23li…`-format client_id), not a classic OAuth
  App — works identically with the standard OAuth web flow.
- **Reporting Open / next:** interactive dogfood is the only remaining acceptance
  gate — GitHub sign-in → submit report → lands `queued` in D1 → shows on
  `/reports`; needs owner GitHub login, not yet run. (Supersedes §-block Open/next
  "merge decision" + "owner Cloudflare setup" — both now done.)

**Verified:** escalation-card + enrich and analyzer-in-extension are on `main`/live
— all cited commits are ancestors of `origin/main` `043601a` (confirmed via
`git merge-base --is-ancestor`); AbuseIPDB chips dogfooded live per invoker.
IOC-reporting branch confirmed **12 commits ahead of `main`** (`git rev-list
--count`); cited key files spot-checked present on disk. Whole-branch review =
APPROVE-WITH-FOLLOW-UPS (all 8 invariants held); final gate green per invoker (web
build + 434 shared/lib/src tests + all Functions `node --check`) — gate not
re-run here. Working tree on branch: only
`docs/superpowers/plans/2026-08-21-ioc-reporting-phase01.md` modified + untracked
`node_modules/`.

**Open / next:**
- Merge decision on `feat/ioc-reporting-p01` (merge-local / push+PR / keep).
- Optional ship-dark gate: hide report button until `VITE_TURNSTILE_SITEKEY` set.
- Owner Cloudflare setup then dogfood-verify (`docs/OPERATIONS.md`): GitHub OAuth
  App; D1 create + bind `DB` + run `migrations/0001_init.sql` (wrangler NOT
  installed → dashboard D1 Console); Turnstile widget; 4 Function secrets
  (`GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `SESSION_SECRET`,
  `TURNSTILE_SECRET`) + build var `VITE_TURNSTILE_SITEKEY`. `OWNER_GITHUB_ID` =
  Phase 2 only.
- Parked branch minors (non-blocking): cap→dedupe→insert TOCTOU; OAuth state has
  no single-use nonce + `SESSION_SECRET` reused for state+session; `readCookie`
  unescaped regex (const-only); no comment-truncation test; banned-check ordering.
- Deferred: abuse-hardening (Turnstile + rate-limit + KV budget on `/api/enrich`),
  own OSINT dataset, ISP/ASN abuse-leaderboard (Phase 4), P1.5c domain→IP hero
  pivot.

---

## 0-RECENT. 2026-08-19 (session 7 — multi-interpreter analyzer, doc-scoping, kill-chain bullets — all SHIPPED LIVE)

> Newest block. Supersedes §0-RECENT (session 6) — three more units shipped
> and verified live since: the analyzer's multi-interpreter increment, a
> documentation-scoping pass, and the kill-chain "EXPLAINED" action-bullets
> (the analyzer's headline output, previously `bullets:[]`). `origin/main` =
> local `main` = `36ce3cb`, working tree clean.

**Three units shipped and verified live since the last checkpoint.**

### 1. Multi-interpreter analyzer increment (`/analyzer`, LIVE)
- cmd.exe, mshta, and wscript/cscript are now first-class interpreters, not
  just PowerShell: `detectInterpreter()` (`fd6389d`) + per-interpreter body
  extraction (`extractCmdBody`/`extractMshtaBody`/`extractWshBody`,
  `6c6d384`) + recursive depth-capped nested re-entry that decodes a
  cmd/mshta wrapper's inner `powershell -enc` payload (`c3d57a0`).
- `shared/analyzer/cmdlex.ts::deobfuscateCaret` — cmd caret deobfuscation,
  cmd-gated (`b3ff7c8`). `shared/analyzer/wsh.ts` — WSH/HTA numeric
  char-code decode + honesty signals (`f0e6353`).
- Interpreter-aware signature rules (`8c8c927`): `cmd-cradle` (`for /f` +
  finger/curl/certutil/bitsadmin/powershell co-occurrence — closes the
  finger-cradle gap flagged at the end of session 6 — T1059.003/T1105),
  `mshta-interpreter` (T1218.005, +T1059.005 when an inline script is
  present), `wsh-script-exec` (T1059.005 for VBS / T1059.007 for JS). Fixed
  the ClickFix `--Verify` decoy false-positive against `gpg --verify`
  (`82e902d`).
- `extract.ts` binary-filename→domain IOC-leak fix (`abde7d9`).
- 8-task SDD (`docs/superpowers/plans/2026-08-19-multi-interpreter-analyzer.md`,
  `.superpowers/sdd/2026-08-19-multi-interpreter-analyzer/`) + whole-branch
  review caught 2 cross-task defects, both fixed in `1db775e`
  (`fix(analyzer): non-anchored nested launcher detection + dedupe evasion
  flags`): the non-anchored nested-launcher fallback was truncating corpus
  text a signal rule depended on (the `for /f`+`finger` cradle), and evasion
  flags could duplicate. End-to-end integration + determinism tests:
  `f6bcffc`. 264/264 `shared/analyzer` tests green post-fix.

### 2. Documentation-scoping pass (`3e049c8`, `aff3063`, `e9740d9`)
- `docs/OPERATIONS.md`: Deploying section rewritten for the real `web/dist`
  Vite build + `wrangler pages deploy` (previously still described `site/`
  uploads).
- `docs/AUTOMATION.md`: scope note; historical markers on the old `site/`
  Definition-of-Done bullets (process doctrine §2-6 unchanged).
- `docs/ARCHITECTURE.md`: reordered so the live `web/` analyzer + cockpit
  land right after "End to end" (not seventh); diagram gets a `web/` node +
  a Tier-3 skip pointer; analyzer section updated for the multi-interpreter
  increment.
- `docs/HANDOFF.md` itself trimmed (847→732 lines per the commit message,
  pre-this-edit) — stale §2/§3/§5/§9/§10 reduced to pointers; `## 0` session
  history untouched.
- `README.md`: capability table split into Live-in-`web/` vs
  Legacy-`site/`-only, correcting stale `site/js/*` paths for the 7
  capabilities rebuilt in `web/`.
- `docs/BUILD-JOURNAL.md` marked deprecated in favor of `docs/HANDOFF.md`
  (the `nt` agent definition already points here, not there).
- New `docs/REPO-MAP.md` — canonical `web/src` + `shared/` module map;
  `CLAUDE.md` and `README.md` now point to it instead of duplicating it.
- `web/src/App.tsx`: Gallery dropped from the public top-nav — routable-only
  internal design ref, matching `/privacy` (`e9740d9`).
- `docs/SOCDesk-Overview.{html,pdf}` regenerated for `web/`-live state
  (analyzer block, `/desk` pillars, real deploy steps).
- `BACKLOG.md` synced: command-line deobfuscator marked SHIPPED, Analyzer
  roadmap section added.

### 3. Kill-chain / "EXPLAINED" action-bullets (`/analyzer`, LIVE)
- The analyzer's headline output (spec §7 `ActionBullet`, previously
  `bullets:[]`): `shared/analyzer/bullets.ts` — 28 execution-ordered
  `ActionRule`s → `ActionBullet[]` (`aa67f20`), wired into `analyze()` and
  `copyText` (`de72496`), rendered by
  `web/src/components/analyzer/ActionBullets.tsx` between the technique
  tally and the decode ladder, plus a copyText "What it did" section
  (`b4e3db2`).
- Verb-first plain-English actions; three-tier honesty (resolved ● /
  inferred ~ / opaque ○ quarantined); never invents intent (machine-guarded
  banned-word sweep, tested in `dfe2cb0`); per-behavior IOC attribution — no
  cross-behavior misattribution (`abdbd4c`; `d53cc8c` scoped the
  beacon-loop host to its own loop body to fix a cross-brace
  misattribution). `4ff4f25`: mshta/WSH entry-vector bullet surfaced,
  raw-socket beacon host named, clearer evasion wording.
- Built via 5-task SDD (`.superpowers/sdd/2026-08-19-analyzer-bullets/`) +
  whole-branch review (4 findings fixed, re-reviewed APPROVED) + a SOC
  output-quality pass on real samples (3 must-fixes, follow-ups logged in
  `BACKLOG.md` by `36ce3cb`). **375 tests green.**

**All three verified live on socdesk.io** — `origin/main` = local `main` =
`36ce3cb`, working tree clean; live bundle `index-CS8J7t-q.js` fetched
directly from socdesk.io matches this build.

### Analyzer roadmap follow-ups (logged in `BACKLOG.md`, not yet built)
- `clickfix` "paste-and-run" label leaks into the top-line characterization
  on the generic hidden+nop+fetch+IEX branch when no decoy text is present
  (the bullets themselves stay correctly silent — it's a `techniques.ts`
  label issue on that branch).
- `EMBEDDED_LAUNCHER_RE` `WScript.Shell` false-match burns depth-cap hops
  (mislabels an `mshta→wscript` decode-layer transition).
- Deep WSH deobfuscation (VBScript/JScript concat-fold + `Execute`/`eval`
  recursion); cmd env-var obfuscation (`%COMSPEC:~x,y%`, `set`/`%a%`
  reassembly).
- Broader gaps: PowerShell deobfusc breadth (`-join`/`-f`/`[char]`/
  `-replace`/`FromBase64String`/`.Invoke()` sink); technique-family
  expansion (credential-access/LSASS, ransomware shadow-delete, UAC bypass,
  lateral, DNS exfil); LOLBin table (9 of ~200 LOLBAS); honesty layer (real
  entropy/`wall`/`fractionAccounted`).

---

## 0-RECENT. 2026-08-19 (session 6 — analyzer Phase 3 + polymorphic cockpit SHIPPED LIVE)

> Newest block. Supersedes §0-RECENT (session 5) on analyzer status — Phase 3
> interpretation now IS built, tested, and live, not just the Phase 1/2a
> decoder. Also ships an entirely new capability, the polymorphic cockpit, not
> covered by any block below. Both verified live on socdesk.io, `origin/main`
> ≈ `a62ac2f`.

**Two features shipped and verified live since the last checkpoint.**

### 1. PowerShell analyzer Phase 3 — signatures + characterization (`/analyzer`, LIVE)
- The Phase 1/2a decoder core (lex → fold → resolve → extract, §0-PRIOR) now
  feeds a **signature catalog**: 12 MITRE-ATT&CK-mapped `SignatureRule`s
  across download cradle, evasion-flag cluster, AMSI reflection/memory-patch,
  ETW tamper, Defender tamper, ClickFix/paste-and-run, beaconing, reverse
  shell, fileless loader, persistence, and LOLBins (certutil/bitsadmin/mshta/
  regsvr32/rundll32/msiexec/wmic/installutil/conhost), with co-occurrence
  upgrade.
- **Specificity-gated characterization** (the analyst payoff Carl asked for):
  `analyze()` emits a **RED** "High-confidence malicious behaviour" callout
  ONLY for intrinsically near-dispositive signals (amsi-reflection,
  amsi-memory-patch, reverse-shell — "no legitimate use"); an **AMBER**
  "Suspicious — review" tier fires when a strong signal is corroborated to
  near-dispositive by co-occurrence (the CS-beacon shape); otherwise just the
  periwinkle technique tally. **Never a synthesized score/verdict.**
- **⚠ RESERVED-COLOUR EVOLUTION (owner-approved):** the ONE gated
  characterization callout carries a verdict-severity hue (red/amber);
  technique CHIPS stay periwinkle facts, tier-tagged, sorted strongest-first.
  This relaxes the old "analyzer is periwinkle-only" rule for the gated read
  only — red/amber/green stay reserved for a real severity read elsewhere,
  never decoration.
- Files: `shared/analyzer/{types,lex,preprocess,fold,extract,resolve,report,index}.ts`,
  `web/src/routes/PowerShellAnalyzer.tsx`,
  `web/src/components/analyzer/{AnalyzerResult,TechniqueTally,DecodeLadder,IocTable}.tsx`.
  `AnalyzerResult` is a shared component, reused by the cockpit (below). Each
  extracted IOC has a one-click "Look up →" into the reputation/enrich card.
  **86 vitest** for `shared/analyzer`.

### 2. Polymorphic cockpit — one omnibox, two paths (`/` = `Overview.tsx`, LIVE)
- `shared/intent.ts::classifyCockpitInput(raw)` classifies a paste as
  `'indicator'|'command'|'unclassified'` and routes it. An **indicator** →
  enrichment (`useLookup` → `/api/enrich`) → `EscalationCard` inline + the 3D
  globe lands the geo pin. A **PowerShell command** → the local analyzer
  (`usePsAnalysis`) → `AnalyzerResult` inline in the SAME docked slot, and the
  globe YIELDS — dims/steps back AND suspends its WebGL render loop
  (`GlobeApi.suspend/resume` + `.is-geoless` CSS). One screen, no tab-switch.
  `/analyzer` stays as the deep/standalone view sharing `AnalyzerResult`.
- Key pieces: `web/src/components/cockpit/{useCockpitInput,ResultRegion,
  CockpitOmnibox,ModeChip}.tsx`. `useCockpitInput(submitted, override)`
  composes both `useLookup` + `usePsAnalysis` (the unselected path fed `''`);
  `ResultRegion` dispatches by kind; `CockpitOmnibox` morphs a single-line
  `<input>` ↔ an auto-growing `<textarea>` for scripts; `ModeChip` shows the
  detected kind (periwinkle catalog), correctable to escalate to command
  (monotonic — see below).
- **⚠ DATA BOUNDARY (load-bearing, verified live):** a pasted command NEVER
  reaches the third-party `/api/enrich`. `classifyCockpitInput` runs before
  `detectType` at EVERY entry point: the cockpit auto-path; the mode-chip
  override (`resolveKind` is MONOTONIC — a detected command can't be
  overridden back to indicator); `palette/commands.ts::submitLookup` +
  `Lookup.tsx::runLookup` (submit); and `Lookup.tsx`'s hash mount /
  `hashchange` / `popstate` reads — a `/lookup#q=<command>` link redirects to
  `/analyzer`, zero enrich calls. Also consolidated the two drifted
  classifiers (`palette/classify.ts` now delegates to `detectType`).
- Submit is unified — only the committed value runs, never live-typed, so no
  per-keystroke `/api/enrich`.

**Both verified live on socdesk.io — `origin/main` ≈ `a62ac2f`.**

### Deferred fast-follows (not yet built)
- `/analyzer#q=` deep-link prefill — a command routed from the palette/
  `/lookup` currently lands on the BARE `/analyzer` (loses the paste). Add a
  `#q=` consumer mirroring `Lookup.tsx`'s hash reader.
- `IocTable` "Look up →" → in-place cockpit kind-flip, instead of navigating
  away.

### Roadmap (owner-set, unbuilt)
1. **cmd-family / multi-interpreter increment** — cmd `^`/`^^` caret
   deobfusc, `finger`/`for /f`/`start` LOLBin+cradle, broader ClickFix decoys,
   HTA/WSH awareness; fix the lowercase-filename→domain IOC leak. Motivated
   by a live test: a ClickFix `cmd /c … for /f … in ('finger user@host') do
   %e` finger download-exec cradle the analyzer under-detected.
2. The **"explained"/kill-chain breakdown** — spec §7 `ActionBullet` /
   `bullets.ts`, currently `bullets:[]` — the numbered, execution-ordered
   plain-English "what did it do" narrative.
3. **PowerShell deobfusc breadth** (`-join`/`-f`/`[char]`/`-replace`/
   `[Convert]::FromBase64String`/`.Invoke()` sink); **technique-family
   expansion** (credential-access, ransomware shadow-delete, UAC bypass,
   lateral, DNS exfil); LOLBin table expansion; **honesty layer** (real
   entropy/`wall`/`fractionAccounted`).

---

## 0-RECENT. 2026-08-19 (session 5 — PowerShell analyzer: decoder core merged, interpretation layer next)

> Newest block. For **analyzer build-state and what to do next**, this
> supersedes the session-4 block below. Everything about the live IOC-lookup
> cockpit in session 4 is unchanged and still current — this block only adds the
> `/analyzer` route's status.

**The `/analyzer` route now has a real deobfuscation core, but it is a DECODER, not yet an ANALYZER.**

### Shipped to LOCAL main (UNPUSHED / NOT live)
- **Phase 1** (merge `6eade54`) + **Phase 2a** (merge `ff8fada`) of the PowerShell
  analyzer are merged to **local `main`**. Local `main` is **~32 commits ahead of
  `origin/main`** and **nothing analyzer is deployed** — the live socdesk.io
  `/analyzer` route does NOT yet have this. Deploy is deliberately held for an
  explicit `deploy` (rebase-guard first: `git pull --rebase origin main`, then
  trigger collect-and-deploy — see `[[socdesk-deploy]]` memory).
- What the core does: lexer + `-enc` Base64→UTF-16LE decode + gzip/raw-DEFLATE
  inflate (U+FFFD-aware plausibility guard) + **string-concat folding** +
  **position-aware single-assignment variable substitution** (fixpoint-capped) +
  **`IEX`/`&`-sink recursion** + IOC extraction across **every** decode layer with
  true `layerIndex` provenance + one-click bridge into the reputation card.
  Deterministic, client-side, **NEVER executes input** (strict CSP, no eval).
- Files: `shared/analyzer/{types,lex,preprocess,fold,extract,resolve,report,index}.ts`,
  `web/src/routes/PowerShellAnalyzer.tsx`, `web/src/components/analyzer/*`. Tests:
  `shared/analyzer/__tests__/*` — **40/40**, `tsc` clean. Run from `web/`:
  `npx vitest run ../shared/analyzer`.

### NEXT: Phase 3 — the interpretation layer (the actual analyst value)
- Phase 1+2a is *decode + IOC extraction*. The payoff Carl asked for —
  the bulleted **"what did it do"** breakdown, **behavioral signatures**
  (beaconing, clickfix, download-cradle, AMSI/ETW tampering, etc.), and the
  **specificity-gated characterization** (near-dispositive signals earn an
  attributed high-confidence read; weak/strong-only stay a descriptive tally) —
  is **Phase 3/4** and is **not built yet**.
- **⚠️ Phase 3 is SAFEGUARD-SENSITIVE:** the signature-catalog content trips the
  API cyber-safeguard. Carl was added to the **Cyber Verification Program**;
  Phase 3 was deferred until he **restarts the session** so verification is
  active. **Before building Phase 3, confirm verification is active** (no
  safeguard blocks on a signature-authoring probe), then brainstorm/plan →
  build via **subagent-driven-development**.
- Design refs (authority): `docs/superpowers/specs/2026-08-19-powershell-analyzer-design.md`
  **§6** (signatures), **§7** (breakdown), **§14** (open questions + the
  specificity-gated characterization decision + Phase-2 carry-forward findings).

### Also queued — Phase 2b (deobfuscation breadth, safe to build anytime, lower value)
`-join` / `-f` format / `[char]` / `-replace` / string-reversal / inline-AES
folding; lexer-token domain extraction (fixes the lowercase `.dll` IOC leak);
full wall/opaque layer states + real `fractionAccounted` (resolve layers are
currently hardcoded `fully-decoded`, so `fractionAccounted` can overstate);
`.Invoke()` sink (needs `.`-member lexer support) + its comment trim;
`preprocess` max-input-length (rest of §11); pure-script decode-ladder
surfacing; `&`-sink recursion test.

---

## 0-PRIOR. 2026-08-18 (session 4 — the modern-stack app is LIVE)

> Newest block. It **supersedes §0-RECENT (session 3) and everything below it**
> for anything about *what is live and shipped.* The historical design/logo
> record below stays for context; where it conflicts with this block on shipped
> state, **this block wins.** Palette + the SD-monogram logo decision are
> unchanged — no re-skin.

**Read this first. SOCDesk is live and the loop works end to end.**

### The AAA modern-stack app is LIVE at socdesk.io ✅
- The production site is now the **`web/` app** — **Vite + React + Tailwind v4 +
  Motion**, under the **strict CSP** — deployed to socdesk.io. The **legacy
  `site/` vanilla app is SUPERSEDED** (kept in-repo for history; no longer the
  deploy target).
- The landing is a lookup **"cockpit":** typing an indicator **folds the
  marketing intro, pins the omnibox, and docks the escalation card beside a 3D
  globe** (the globe lands the geo pin). IOC in → OSINT out, in one screen.
- **Favicon = the SD monogram** (periwinkle `#7C8AFF`), cut from the approved
  master. The logo saga (§0-RECENT / §0-PRIOR) is closed.

### The escalation card — honest by STRUCTURE
- **Source-class labels** on every source: `catalog/identity`, `authoritative`,
  `behavioral/observed`, `reputation-score`, `list-membership`, and an
  `unclassified` fallback. The **evidence ledger** stacks the source name over
  its class chip with **per-source recency** ("as of DATE"). **EPSS is
  attributed to FIRST.org** on CVE cards.
- **Signals are CHIPS, not prose:** dual-use / Tor, grayware, and
  hosting/datacenter render as chips.

### ⚠️ DE-WORDIFY (2026-08-18) — a doctrine change (see `docs/VERDICT-LANGUAGE.md`)
The escalation card **and its copy-out** (the **"Copy card"** PNG + **"Copy
text"**) are now a **CLEAN, FACTUAL artifact** the analyst annotates in the
email body. **Removed** from the card, the PNG, and the copy-text: the
disclaimer **CAVEAT** ("Reflects third-party reputation … not independently
confirmed") and the prose **"Note:"** lines (dual-use, grayware). **Honesty is
now STRUCTURE**, not disclaimer prose — every claim attributed to a named source
+ class, the coverage tally (never a synthesized score), honest empties ("not a
clearance"), geo-as-context. The signals became chips. **The analyst owns the
nuance in the escalation email.** `docs/VERDICT-LANGUAGE.md` §4 is the binding
copy.

### Shipped this session — the loop's reach
- **IPv6 lookups** — detected + enriched (**AbuseIPDB + VirusTotal + ipinfo**;
  **GreyNoise stays IPv4-only** — its community API 400s on v6). Private/reserved
  v6 (`::1`, `fc00::/7`, `fe80::/10`, `ff00::/8`) is rejected.
- **URL workflow** — the urlscan **existing-scan screenshot** renders on-card
  (CSP allows `https://urlscan.io` images) with a **click-to-expand lightbox**,
  plus a **Browserling** safe-view pivot (opens the URL in a disposable remote
  browser). **Existing-scans only — SOCDesk never submits to urlscan.**
- **Domain** — the registration-age hero is populated by a new **keyless RDAP**
  source (`rdap.org`, requires a User-Agent; `kind:"context"` so it is excluded
  from the tally) carrying **Registered / Registrar / Expires**. The urlscan
  domain search uses **`page.domain:`** (a scan *of* the domain, not any scan
  that merely contacted it); domains also show the scanned-page screenshot.
- **Compare-IP / impossible-travel** — after an IP lookup, a collapsed **"Compare
  to a previous IP"** panel takes a second IP + optional minutes → **great-circle
  distance in miles + implied speed in mph** with an honest plausibility read
  (**plausible ≤600 mph / implausible / impossible >2200 mph**) + a copyable
  one-liner. Computed **only from real coordinates** (both IPs `precise`), never
  country centroids; an amber caution chip, **never a red "compromised" verdict.**
  Shows **distance, velocity, and a map arc** (the arc + second pin also draw in
  the copy-card PNG).
- **Browser extension → full-card parity (manifest `v0.2.0`)** — the toolbar
  popup now renders the shared `EscalationCard` (heroes, chips, Compare-IP, copy
  actions), the **same card the web app shows.** It already shares indicator
  detection + the enrich pipeline, so IPv6 / RDAP / URL all flow through.

### Deploy — the rebase guard
- CI (`collect-and-deploy.yml`) **builds `web/dist` and direct-uploads to
  Cloudflare Pages.** The cron commits **"data: refresh snapshots"** constantly,
  so a plain `git push` is **non-fast-forward** — **always
  `git pull --rebase origin main` before pushing.**

### Next / pending
- **Compare-IP globe arc** — the great-circle arc on the 3D globe is **landing
  now** (the shared-card SVG arc + PNG arc are in).
- **Per-source metric / icon visual** — a small per-source metric or icon on each
  evidence line (visual pass, not yet built).
- **Same-origin `/api/shot` proxy** — so the copied PNG can include the urlscan
  screenshot (cross-origin urlscan images currently taint the copy canvas; a
  same-origin proxy fixes it). Not built.

---

## 0-RECENT. 2026-08-12 (session 3 — logo RESOLVED + segmented)

> Second-newest block. **Superseded by §0 for shipped state** (the segmented
> next-session tasks below — wire the logo, ship the rebuild — have since landed
> in the `web/` app). Kept for the logo/palette decision record, which still
> holds. Everything in §0-PRIOR — verdict graphic, palette, the working-tree
> guard — still stands as history.

**The logo saga is over.** The next session was a set of **segmented,
mostly-independent tasks** (only #4 is a sequence). **Palette is unchanged — no
re-skin.**

### LOGO — RESOLVED (locked) ✅
- **Primary mark = "SD Monogram" (brand-sheet Option 1)** — interlocking S/D
  built from clean geometry, with periwinkle **signal-bars.** The **coffee mug is
  demoted to a SECONDARY brand motif** (warmth / community / merch — shift-start,
  daily-brief, physical mug), **NOT** the primary logo. This dissolved the mug's
  16px-favicon problem in one move.
- **Palette UNCHANGED** — the brand sheet sits on our already-shipped
  **warm-espresso / warm-paper + periwinkle** tokens
  (`#15100A / #F2E6D0 / #A6612F / #7C8AFF`). **NO re-skin.**
- **Rejected: the "System Mug" alternative sheet** (VOID `#080C10` +
  electric-blue `#5A78FF` + copper + **paid Aeonik** font). Void = the cold-cyber
  slop we left; copper collides with the reserved **verdict-gold**; Aeonik is a
  paid font (breaks no-paid-tools + CSP self-host). A System-Mug preview was built
  (`design/mockups/brand-systemmug-preview.*`) then **discarded.**
- **Asset — `design/mockups/sd_logo.svg`:** the monogram **traced to clean,
  scalable SVG** from the brand sheet (`suggestions.png`) and recolored to exact
  tokens. **Theme-aware:** monogram `fill="currentColor"` (cream on dark, espresso
  on light); bars `fill="var(--sd-bar,#7C8AFF)"` (`#4A4FD0` on light). Crisp
  200 → 32px; at 16px the **SD holds but the 4 bars compress** → a **2-bar 16px
  favicon cut** is still needed.
- **Preview — `design/mockups/hero-sd-preview.*`:** the warm globe hero with the
  SD monogram in the topbar + an added hero lockup, both themes, verified
  **CSP-clean.**
- **NOT yet wired into `site/`.** The logo lives **only in mockups.**
  `site/favicon.svg` still holds a **non-approved experimental mark** (revert
  pending).
- **Committed design-only at `c4cd6fd`** (`design/` — `sd_logo.svg` +
  hero/brand mockups + `UX-DIRECTION.md` + `REFERENCES.md` + brand explorations).

### Memory rules added/strengthened this session (so the saga can't repeat)
- **`feedback-visual-asset-generation`** — polished raster/brand visuals come
  **ONLY** from an image generator or an approved master; **never** hand-authored
  SVG / raster-recolor / agent-redraw ("it's just a flat icon" is the trap).
  **Converge the instant the user approves one; no variant fan-out.**
- **`framework-local-dev`** — **READ the Stack Bible**
  (`Desktop\Projects\stack-bible\`) **before touching the Framework box;** the
  memory was marked stale (Bible §A is source of truth).
- **`feedback-no-personable-filler`** — task-focused communication only.

### Next-session tasks — SEGMENTED (also logged in the task tracker)
1. **Wire the SD logo into `site/`** — topbar + favicon (+ the **2-bar 16px cut**)
   + hero lockup; theme-aware; **palette unchanged.**
2. **Fix the light-theme globe** — dark-sphere-on-cream → warm-greige instrument
   (isolated tweak; **gates nothing**).
3. **Globe elevations** — depth / rim-light, denser dots, node emphasis, dot
   richness (the **4 palette-independent wins** from the globe review).
4. **Finish the RADAR rebuild → commit + ship** (the one sequence) — verdict
   **Core + companion** into `verdict.js` / `evidence.js` (decide **EPSS% vs
   composite** center number), **globe Phase 3** (self-host **cobe**), then
   **commit the `site/` rebuild** + make the **ship call.**
5. **Revert the experimental `site/favicon.svg`.**
6. **Leg 2 build** (already tracked — see §0-EARLIER; build **only after** the
   rebuild lands, shared files).

### Still-open owner actions (carry forward, unchanged)
- **Upload Extension v1** — Chrome Web Store, **Unlisted**; zip on Carl's Desktop.
- **Tailscale SSH ACL flip** (`check` → `accept`) for headless box automation.
- **Leg-2 source decisions** — ransomware.live license, abuse.ch key.
- **Deferred fix for future asset generation:** local image-gen on the Framework
  box (**ComfyUI + FLUX** via the kyuz0 ROCm toolbox, Stack Bible §D/§H).

### Working tree (standing guard — unchanged)
- `site/` (**12 files, the RADAR rebuild**) remains **uncommitted + incomplete**
  since commit `f029b26`. Keep the standing rule: **no `git add -A` / rebase /
  checkout** — this handoff commits **`docs/` only.**
- `design/` is **now committed** (`c4cd6fd`).

---

## 0-PRIOR. 2026-08-11 (session 2 — brand/logo · logo now RESOLVED in §0)

> This is the **later** of two 2026-08-11 sessions. The **session 1** block (RADAR
> rebuild / extension / copy-card) is directly below, kept for context. Where the
> two conflict, **THIS block wins** — specifically it **supersedes** session 1's
> verdict-graphic pick ("B · Severity Spine") and the "logo-v2, owner picking"
> line.

**Honest framing:** this whole session went to the **logo** and produced **NO
shippable logo** — ~5 hours in failure loops. Recorded plainly so next session
starts from the correct approach, **not the loop.** The real design decisions
that DID get made are below and must not be lost.

### Design decisions LOCKED this session (preserve)
- **Verdict graphic — DECIDED** (this replaces session 1's "Severity Spine" rec):
  **Core radar** — filled polygon + a bold central number on a faceted hex plate
  — for **CVEs**; plus a **range-gate companion** — discrete count "blips," the
  benign source shown **hollow** — for the **enrich consensus tally.** Mockups
  (uncommitted): `design/mockups/verdict-graphic-explore.html`,
  `design/mockups/verdict-graphic-radar-round2.html`. **Build note:** before
  wiring into `verdict.js` / `evidence.js`, decide whether the big center number
  is **EPSS%** (current) or a **labeled composite** (KEV+CVSS+EPSS).
- **Palette — CONFIRMED #1 "warm + periwinkle"** (the current RADAR-rebuild
  scheme) after a 3-way comparison (`design/mockups/palette-explore.html`).
  Graphite-ground and gold-mono were **rejected** — gold collides with the
  reserved **verdict-amber.** Mug/ceramic = caramel **`#C68B5B`**; do **NOT**
  drift to pale-latte tones (a mid-session color error, corrected).
- **Lockup orientation:** mug → **thin vertical rule** (sized to the text block,
  not stretched) → **SOCDESK** (Archivo 800, −0.02em) over **"THREAT
  INTELLIGENCE, FASTER."** (FASTER. in periwinkle), **no wordmark underline.**
  (The topbar "underline" was an accidental `<a>` default; `site/css/base.css`
  already ships `a{text-decoration:none}`, so the live site is fine.)

### LOGO — ⚠️ SUPERSEDED by §0 (session 3): RESOLVED as the SD Monogram
> Historical — kept to show why the mug-as-primary path was abandoned. The logo
> is now the **SD Monogram** (mug demoted to a secondary motif); do **not**
> resume the image-gen-the-mug plan below. See §0.

- **Definitive reference = the ChatGPT brand sheet** (Carl's file
  `chatgptbrandsheet.png`): a **dimensional caramel MUG** with a rounded
  **D-handle**, periwinkle **PIXEL steam**, **no saucer**; tagline "Good intel,
  hot coffee"; palette `#F5F1EB` text / `#C68B5B` mug / `#6B8AFF` steam /
  `#1A150F` bg. **This is the target.**
- **Dead ends — DO NOT resume:** cup-and-saucer silhouette, **wavy** steam,
  pale-latte ceramic, and the flat-geometric "UI icon" register — all detours
  (assistant-led). Steam is **PIXEL** per the sheet, not wavy.
- **Why it failed (root cause):** the mug is **AI-image-generated** — fidelity
  **cannot be hand-authored or recovered from a screenshot.** Two wrong
  approaches were burned: (a) sub-agents hand-coding SVG from *text descriptions*
  of the reference → clipart (the agent can't see the image; telephone game);
  (b) cropping the 928px brand-sheet *screenshot* + background-keying → a lossy
  ~107px raster with a dark handle-eye artifact, not portfolio-grade.
- **Correct path for next session — EITHER:**
  1. **Carl exports the actual full-resolution generated master** from ChatGPT —
     isolated icon, transparent, **1024px+**, the **real file (NOT a
     screenshot)**; OR
  2. **Stand up local image generation on the Framework box** — ComfyUI +
     **FLUX.1-schnell / SDXL** over the tailnet, **reference-conditioned**
     (img2img / IP-Adapter) to match the sheet, driven from Claude Code via
     SSH/HTTP — then **`rembg`** for a clean alpha + **`vtracer`** for an optional
     scalable SVG. Then wire the logo in. (See memory `feedback-logo-asset-generation`.)
- **Tooling installed on Carl's Windows box this session (reuse):** Python
  **Pillow** + **vtracer**. **cairosvg / svglib FAILED** (no native cairo on
  Windows). **Headless-Chrome screenshotting FAILED** (collides with the
  already-open Chrome profile + flag quirks) — next time pass a **fresh
  `--user-data-dir`**, or render on the Framework box.

### ⚠️ Working tree / cleanup (flag prominently)
- **The LIVE `site/favicon.svg` was overwritten** by a failed logo attempt
  (uncommitted) — it currently holds a **non-approved cup/caramel experiment.**
  **Revert or replace it before any deploy.**
- Uncommitted logo explorations: `design/mockups/logo-v2.html`,
  `design/mockups/logo-v3.html`, `design/mockups/favicon-v3.svg` (+ the
  verdict/palette mockups above).
- **The entire RADAR visual rebuild is STILL uncommitted** (`site/index.html`,
  `site/css/*`, `site/js/*`, `sw.js` at **v15**) — **unchanged from session 1.**
  Nothing has been committed since the docs-only commit **`6b68393`** (session
  1's handoff). Keep the standing rule: **do NOT `git add -A` / rebase / checkout
  blindly** — this handoff commits `docs/` only.

### Next-session sequence
1. **Resolve the logo** via image generation (path above) — the first real step.
2. **Wire the locked set into the rebuild in ONE pass:** the logo asset (topbar +
   favicon + lockup), the verdict **Core + range-gate companion** into
   `verdict.js` / `evidence.js` (decide **EPSS vs composite** center number), and
   the **palette #1** tokens.
3. **Revert/replace** the experimental `site/favicon.svg`.
4. **Commit the rebuild;** then the **ship decision** (with-globe vs ship-now);
   then **Leg 2** (build plan + `brief.json` contract still to be persisted from
   the earlier architect log; `summarize-local` / Qwen3-Next-80B verified).

### Still-open owner actions (unchanged)
- **Upload Extension v1** — Chrome Web Store, **Unlisted**; zip on Carl's Desktop.
- **Tailscale SSH ACL flip** (`check` → `accept`) for durable headless automation.
- **Leg-2 source decisions** — ransomware.live license, abuse.ch key.

---

## 0-EARLIER. 2026-08-11 (session 1 — RADAR rebuild built [UNCOMMITTED] · extension v1 ready · copy-card)

Read this whole section. Two things gate the next session: **an uncommitted
working tree** and a **reversed stack decision.** These supersede the stale body
below (especially §5 "Design law" and any "React + shadcn / teal" phrasing).

### ⚠️ CRITICAL — the RADAR visual rebuild is BUILT but UNCOMMITTED

The RADAR rebuild lives in the working tree, **not committed and not deployed.**
Do NOT `git pull --rebase`, do NOT `git checkout`/`reset` these files, and do NOT
let a stray `git add -A` sweep them into an unrelated commit. This docs handoff
commits **`docs/` only** for exactly this reason.

**Decision: EVOLVE the vanilla site — NOT a framework rewrite.** The site was
restyled in place (still vanilla ES modules, no build step):
- Palette **warm-espresso** (dark) / **warm-paper** (light) + **periwinkle**
  accent + the **coffee-mug** mark. **Light / Dark / System** toggle added.
- Compact RADAR header — the old giant "SOC DESK" masthead was **deleted.**
- Search-hero: H1 stacked **"IOC in." / "OSINT out."** ("OSINT" in periwinkle).
- The broken score gauge is **fixed** (value now centered in the ring).
- Feed rows + actor cards brought to the escalation-card visual language.
- Stat band restrained (periwinkle slab removed); hero decluttered — Live-Wire
  ticker + TRY chips cut, disclosure collapsed to one line, "Escalation summary"
  renamed **"Intelligence summary."**
- `site/sw.js` bumped to **v15.**
- Files (all uncommitted): `site/index.html`,
  `site/css/{tokens,base,chrome,panels}.css`,
  `site/js/{verdict,views,app,motion,state}.js`, `site/favicon.svg`,
  `site/sw.js`, `site-tests/specs/*`. Tests **~108–110 green.** Not deployed.

### ⚠️ STALE DECISION REVERSED (it was in the old §0)

The previous §0 said the production rebuild moves to **React + Vite + Tailwind +
shadcn, teal accent, Bricolage/Geist fonts.** **That is reversed.** We evolved
the vanilla site (no framework); accent = **periwinkle** (not teal); fonts =
self-hosted **Archivo + IBM Plex Mono** (Red Hat / Bricolage were only mockup
stand-ins). `ui-ux-pro-max` / Watermelon-UI / React-shadcn are no longer the
plan. Ignore any surviving "React + shadcn" phrasing elsewhere in this doc.

### Committed this session
- **Escalation "Copy card"** — the evidence card is drawn to canvas and copied
  to the clipboard as a **PNG image,** from byte-identical code shared across
  `site/js/evidence.js` and `extension/lib/evidence.js`. The popup now offers
  **Copy card** (image) + **Copy text.** `lib/enrich.mjs` surfaces ipinfo `loc`
  → a city-level pin. Card cleanups: `GEOLOCATION` header; not-consulted/footer
  lines removed; single timestamp; clean/negative sources retained (honest
  "5 of 6"); **no SOCDesk branding in the copied image;** dual-use note promoted
  under the tally; jargon glossed.
- **`docs/VERDICT-LANGUAGE.md` §4** updated to match (no branding in the copied
  artifact, reworded caveat, named sources retained, dual-use promoted,
  plain-text ships alongside the image).
- **Extension v1** finished and ready to ship — final pixel-coffee-mug icons;
  popup/options restyled to the warm/periwinkle brand (self-hosted Archivo +
  IBM Plex Mono); escalation copy-out fixed (button `COPY`, no recommendation
  line, neutral provenance). Submission **zip is on Carl's Desktop**
  (`socdesk-extension-v1.zip`). Store upload (Unlisted, `privacy.html` as the
  policy URL) is **Carl's action.**
- **`BACKLOG.md`** — added the analyst-utility expansion lane (highlight→engine
  dispatcher, ACCURACY-FIRST) and the public-vs-private data boundary. See §9.

### In flight — design explorations (mockups UNCOMMITTED in `design/mockups/`)

> ⚠ The **verdict-graphic** and **logo** items below are **SUPERSEDED by §0
> (session 2)** — the verdict graphic is now decided (**Core radar + range-gate
> companion**, not Severity Spine), and the logo direction changed to an
> **image-generated asset** (ref = `chatgptbrandsheet.png`). Kept for context.

- **RADAR globe hero (Phase 3)** — NOT built. Plan: self-host GSAP + globe.gl
  locally, a local/embedded earth texture (CSP-safe), a self-drawn dot-matrix
  fallback, tighten CSP `script-src` to `'self'`. On hold until the foundation +
  logo + verdict-graphic settle.
- **Verdict graphic** (`design/mockups/verdict-graphic-explore.html`) —
  replacing the VT-donut score ring. Recommended: **B · Severity Spine**
  (segmented bullet meter unifying the CVE score + the N-of-M tally, animated)
  as the primary mark; **A · Threat Radar** (spider-scope, on-brand) as a
  secondary CVE-page view. **Owner picking.**
- **Logo redesign** (`design/mockups/logo-v2.html`, being built) — the pixel mug
  had a tonal mismatch; refining a dimensional coffee mug + periwinkle pixel
  steam (owner-provided reference), glow-free, in our tokens, proven at 16px.
  **Owner picking.**

### Leg 2 (Threat-Intel bulletins) — PLANNED, not built
- The full build plan + the **`brief.json` contract** (`schemas/brief.schema.json`
  + `tests/fixtures/brief/example.json`) were produced **inline** by the
  architect (Write was disabled) and are **NOT yet persisted to disk** — the
  exact content is in this session's task logs. **Next session: persist them
  first,** then dispatch the two lanes. Shape: `pipeline/cluster.py` (dedup) +
  rank (reuse `relevance.py`) + trending (extend `history.py`) + register
  `brief.json` in `validate.py`'s gate + a stubbable local-LLM summarizer
  (`pipeline/llm.py` + `pipeline/summarize.py`) + extend `renderBrief`. CI never
  calls the LLM; the box writes `brief.stories.json`.
- **Summarizer model (empirically verified on the Framework box):** target
  LiteLLM **`summarize-local` (Qwen3-Next-80B-A3B)** — 3–4 s / ~150 tokens,
  grounded. The paper pick "reuse GLM-4.7-Flash" was **rejected** by the box
  test (verbose/slow: 25 s / ~1,300 tokens). Optional: re-probe GLM with
  thinking off; add `Qwen3.6-35B-A3B` (~21 GB, Apache) as `brief-local` for half
  the memory.
- **Sequencing:** build Leg 2 **only AFTER the RADAR rebuild lands** — both touch
  `site/js/views.js` + `index.html`; never run them concurrently.
- **One structural decision pending owner:** trending is pipeline-owned (free,
  every run) and `brief.json` publishes even with empty stories → the Brief tab
  would appear on trending-only (a behavior change). Confirm before building.

### Infra (from the Framework Stack Bible, reviewed)
- LiteLLM live on `framework:4444` (tailnet): `summarize-local` (Qwen3-Next-80B),
  `agent-fast` (GLM-4.7-Flash), gemma; n8n on `:5678`. **SSH `carl@framework`
  works** from Carl's Windows box via Tailscale — **but** Tailscale-SSH
  check-mode needs interactive browser re-approval; flip the ACL
  **`check` → `accept`** (or add a raw key) for durable headless automation.
  No Anthropic key on the box (cloud lane blocked; the local summarizer is
  unaffected).
- Automation: Mode 1 (drive the box via SSH from here) + Mode 2 (delegate to the
  box's local Aider/Claude, plan-then-build). Production brief job = a user
  systemd timer or n8n workflow on the box → `generate_brief.py` → push → deploy.

### Concurrency caution
Background implementation agents edit the working tree. Don't `git pull --rebase`
on a dirty tree; commit only your own files explicitly and let each agent commit
its own.

---

## 1. What this is

**SOCDesk** — a free, public, static threat-intelligence console. An analyst
pastes any indicator (IP, domain, hash, URL, CVE, email) and gets:

1. **A verdict** — authoritative for CVEs (CISA KEV + NVD CVSS + FIRST EPSS);
   for other types an honest "not in corpus" plus type-aware deep links to the
   right public reputation services.
2. **A ticket-ready escalation summary** — the differentiator. No other public
   tool writes the write-up.
3. A ranked threat feed, KEV/EPSS vulnerability triage, ATT&CK actor and
   malware profiles, collection health, source registry, and an analyst
   toolbelt (defang, UTF-16LE Base64 decode, PowerShell parser, IOC extract,
   LOLBin lookup).

Personal project by Carlos Sanchez (SaltyCarl), sibling to his portfolio
**SanchezOnSecurity.com**. Used by his MSSP SOC team; also a portfolio piece.

**North star (owner-set 2026-08-10, governs all prioritization):** 99% of the
analyst workflow is IP/hash → AbuseIPDB/VirusTotal → screenshot the
reputation → paste into the escalation email (URLs: same, via a safe viewer).
SOCDesk exists to make THAT loop painless. Everything else — CVE features
included, for now — is secondary until the loop is excellent. See
`BACKLOG.md` for the loop-to-feature map and the parked list.

**Live:** https://socdesk.io — **DEPLOYED & VERIFIED 2026-08-10.** Cloudflare
Pages project up, custom domain attached (200), deploys green. `/api/enrich`
confirmed live returning real multi-source verdicts (AbuseIPDB, VirusTotal,
ipinfo, MalwareBazaar keyed; GreyNoise keyless by choice). The core Leg-1
lookup loop is in production.
**Repo:** https://github.com/SaltyCarl/socdesk
**Local path:** `C:\Users\Carl\Desktop\Projects\VIGIL\` ⚠️ *folder is still named
VIGIL; the product was renamed to SOCDesk on 2026-08-08. Do not be confused.*
**Domain:** `socdesk.io` — **live** (Cloudflare Pages, custom domain attached,
serving the `web/` app). See §0.

---

## 2. Architecture

See docs/ARCHITECTURE.md — superseded restatement removed 2026-08-19.

---

## 3. Current state

See docs/ARCHITECTURE.md — superseded restatement removed 2026-08-19.

---

## 4. Recently landed (both workstreams are IN, commit `a59a4d9`)

1. **Front-end console rebuild** — `site/index.html`, `site/css/*`,
   `site/js/*`. The editorial scroll-page is now an operational console:
   verdict has its own full-width region under the search (no scroll jump),
   escalation summary renders as a docket instead of raw markdown, hash
   deep-linking (`#q=<indicator>`), topbar nav switches views in place, feed is
   a score-sorted work queue, masthead collapses after the first visit, mobile
   breakpoint added, status dot green.
2. **Relationship index** — `pipeline/relations.py`, `schemas/relations.schema.json`,
   `tests/test_relations.py`, `docs/RELATIONSHIPS.md`. Evidence-backed entity
   edges (ATT&CK actor→technique→software + feed co-occurrence + CVE→vendor/
   product), with the verdict: **no node-link graph**, build the ranked
   "related entities" panel.

**Open item from #2:** `relations.json` is built, schema-gated and deployed
(1.47 MB raw / 101 KB gzipped), but `site/js/data.js` does not fetch it — the
`FILES` array omits `relations`. The RELATED panel does not exist yet, so the
payload currently ships unread. Wiring it is the cheapest remaining win.

---

## 5. Design law — ⚠️ SUPERSEDED (see §0)

See `CLAUDE.md` (binding design law — periwinkle/warm for `web/`) and
`design-system.md` (Chart Room v4 — historical, `site/` only).

---

## 6. Environment gotchas (each of these cost real time)

- **Service worker masks your changes.** The shell is cached cache-first.
  **Bump `VERSION` in `site/sw.js` on every shell change** or you (and every
  returning visitor) will see the old UI. Masked three changes this session.
- **A push to `main` does NOT auto-deploy `site/` changes.** The
  `collect-and-deploy.yml` workflow only redeploys on its cron (`:11`/`:41`), a
  manual `workflow_dispatch`, or a push whose paths match **`data/brief.json`**
  (the `paths:` filter — the Framework's Tier-2 brief pushes, via a deploy key
  that can retrigger). A normal push that changes the shell / JS / CSS / `sw.js`
  just sits on `origin/main` until the next cron tick (≤30 min) or a manual run —
  the edge keeps serving the old shell. **To ship a shell change now:**
  `gh workflow run collect-and-deploy.yml -R SaltyCarl/socdesk`, then
  `gh run watch <id> --exit-status` (the run also runs pytest + collectors before
  the `wrangler pages deploy site` step, ~3 min). **Symptom of the trap:** a new
  asset returning HTTP 200 at a fixed ~16.5 KB is the Cloudflare Pages
  404-fallback page (the file isn't deployed yet), not the real file. Cost ~15 min
  of "broken deploy" diagnosis before the `paths:` filter was spotted.
- **CSP has no `unsafe-inline`** — a single `style=""` attribute or inline
  `<script>` breaks it. `csp.spec.js` catches it. Use classes or
  `el.style.setProperty()` (CSSOM writes are allowed).
- **`<use href="#symbol">` renders into shadow DOM** — outer CSS cannot style
  non-inheritable properties (opacity, animation) there. Inline the SVG if you
  need to animate it.
- **IntersectionObserver `threshold` > 0 never fires on elements taller than
  the viewport.** Use `threshold: 0`. This left 18 elements permanently
  invisible once.
- **Python:** no `python` on PATH. Use `.venv\Scripts\python.exe`.
  (Installed 3.12.10 via winget this session.)
- **Playwright MCP browser lock:** if it errors "browser is already in use",
  kill Chrome processes whose command line contains `ms-playwright-mcp`, then
  retry. `file://` is blocked — serve over HTTP.
- **Local servers:** `:8473` serves `site/`, `:8471` serves the repo root
  (mockups). Node one-liners; restart if a session ends.
- **Domain checks:** Comcast DNS hijacks NXDOMAIN so everything looks
  registered. Use `https://rdap.org/domain/<name>` (404 = available).
- **Agents die** emitting >32k output tokens — instruct chunked Write+Edit
  builds under ~15KB per call, always. Agent transcripts also expire; re-brief
  fresh rather than assuming a resume works.
- **Rebase conflicts on `data/state/*.json`** are generated data — take either
  side and re-run the pipeline.

---

## 7. Verification discipline (non-negotiable)

The cautionary tale: sanitization was committed, declared safe, and shipped
with **two working XSS bypasses** (an unterminated tag borrowing a `>` from
surrounding markup; a scheme-prefix URL check allowing attribute breakout).
Both now have regression tests.

- "Fixed" requires a test that fails without the fix.
- "Renders" requires a screenshot and a clean console.
- "Works" requires pasted command output.
- Never trust an agent's summary — re-run it yourself.
- A green first run of a new test suite is suspicious.

---

## 8. Pending — owner actions & open work

**Owner:**
- ~~Cloudflare Pages~~ **DONE.** ~~Chrome Web Store dev account~~ **DONE**
  (under `carlos@sanchezonsecurity.com`, a Cloudflare-forwarded alias — created
  the Google account via "use existing email"; publisher = SanchezOnSecurity).
- **Ship the RADAR rebuild** (built + uncommitted, see §0) — the **logo is now
  settled,** so the remaining path is the **segmented next-session plan (§0):**
  wire the SD logo, fix the light-theme globe, add the globe elevations, finish
  the verdict graphic + globe Phase 3, then **commit `site/` and make the ship
  call.**
- **Verdict graphic — DECIDED** (session 2, §0): **Core radar** for CVEs + a
  **range-gate companion** for the consensus tally (supersedes the old "Severity
  Spine" rec). Remaining: pick the center number (**EPSS%** vs **KEV+CVSS+EPSS
  composite**) at build time, then wire into `verdict.js` / `evidence.js`.
- **Logo — RESOLVED (session 3, §0).** Locked to the **SD Monogram** (brand-sheet
  Option 1); the mug is demoted to a secondary motif. Asset =
  `design/mockups/sd_logo.svg` (theme-aware, on the **existing tokens — no
  re-skin**), committed design-only at `c4cd6fd`. Remaining code work: **wire it
  into `site/`** (topbar + favicon + **2-bar 16px cut** + hero lockup) and
  **revert the experimental `site/favicon.svg`.**
- **Upload Extension v1** to the Chrome Web Store **Unlisted** — the submission
  zip is on Carl's Desktop (`socdesk-extension-v1.zip`), `socdesk.io/privacy.html`
  as the policy URL.
- **Tailscale SSH ACL flip** (`check` → `accept`) for durable headless box
  automation.
- **Leg 2 green-light:** ransomware.live license call (leans keep, non-commercial),
  abuse.ch free key (add?), and confirm the trending / Brief-tab structural
  decision (§0) before the build starts.
- Optional: employment IP-assignment clause (gates repo-private + Leg-3 sensor).

**Open code work (next):**
- **Commit + deploy the RADAR rebuild** once the owner picks the ship path
  (§0 lists the uncommitted files; bump `sw.js` is already at v15). Not done here
  because this handoff commits `docs/` only.
- **Persist the Leg-2 `brief.json` contract + build plan** — currently only in
  this session's task logs (`schemas/brief.schema.json` +
  `tests/fixtures/brief/example.json`), then dispatch the two lanes. Build Leg 2
  **only after** the RADAR rebuild lands (shared files — see §0).
- **Dogfood** — 2-3 analysts run real alerts through the live tool + extension.

---

## 9. Backlog — superseded by BACKLOG.md (updated 2026-08-11)

See `BACKLOG.md` for the current priorities, lanes, and parked-work map.

---

## 10. Key documents

See the Documentation table in README.md (the single source for the doc map).

**Attribution policy:** all commits are SaltyCarl with **no AI attribution**
anywhere, including automated ones. Non-negotiable.
