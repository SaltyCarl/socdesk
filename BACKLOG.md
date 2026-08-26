# SOCDesk Backlog

> _Refreshed 2026-08-26 (sitewide-critique close-out)._ Shipped 2026-08-25/26 from the two external
> critiques + follow-ups: **CI test gate** (`.github/workflows/ci.yml` — vitest+eslint+tsc+pytest on
> every push/PR; they never ran in CI before) · **auth hardening** (fail-closed session HMAC; OAuth
> state browser-bound via nonce cookie) · **.onion render-guard** (safeUrl rejects .onion hosts —
> closed live leak-site links that contradicted COMPLIANCE.md) · **victim-first leak-claim feed rows**
> (VictimLogo shared, provenance line) · **nav dissolve** (logo=home, Overview tab dropped) ·
> **Intel→Adversaries re-label** · **Health warnings de-dump** (`<details>` collapse) · **KEV
> due-date on Vulns** · **ISP leaderboard bars** · **ATT&CK technique names** (`technique_names.json`
> id→name catalog, 697 entries) · **capture-safe scroll reveal** (transform-only + print guard) ·
> **link-primitive unification** (shared CveLink/ExternalLink; feed CVE rail now a live pivot).
> COMPLIANCE R3 re-rated MED-accepted w/ dated rationale; README no-db/no-accounts clarified.
> **Two owner activation gates remain:** (1) `IPINFO_TOKEN` → GitHub Actions secret (populates the
> ISP leaderboard); (2) bind a `KV` namespace + add the `/api/enrich` WAF Block rule (activates B2 —
> see `docs/OPERATIONS.md`). **Owner-flagged, pending:** a deliberate COMPLIANCE.md reconciliation
> pass (owner: "generally too rigid") against current posture + what's actually built — proposals
> for approval, not casual loosening; the `.onion` never-hyperlink rule stays. Next feature
> candidates: Phase 5 trends · Phase 6 upstream push · enrich B3 own-OSINT dataset · give-back
> honeypot · the critique's remaining design ideas (Desk `Now · Exposure · Actors` re-cut, Adversaries
> directory card enrichment, feed sparklines). Refresh at every close-out.

## North star (owner-set, 2026-08-10 — read before adding ANYTHING)

99% of a T1/T2 analyst's day is: paste an IP or hash into AbuseIPDB /
VirusTotal → read the reputation → screenshot it if escalating → paste into
the email. URLs get the same treatment in a safe viewer (Browserling).
**SOCDesk's job is to make that loop as painless and efficient as possible.**
Everything else — including CVE features, for now — is secondary until that
loop is excellent. Vendors an analyst doesn't open on shift (Shodan, Censys,
Spamhaus, sandbox grids) are fluff here; do not accrete them back
(`site-tests/specs/verdict.spec.js` pins the pivot set).

The loop, mapped to what exists:

| Step | SOCDesk feature | Status |
|---|---|---|
| Paste indicator | Omnibox, type auto-detect, refang (bulk + bookmarklet are legacy `site/` only) | Shipped |
| Get reputation | `/api/enrich` Pages Function → AbuseIPDB + VT + GreyNoise + **ipinfo geo/ASN** (IP), VT + MalwareBazaar (hash), VT + **urlscan verdict** (URL/domain) | **Live** — socdesk.io, keys set 2026-08-18; multi-source verified in prod |
| Screenshot for the email | Evidence card rendered to canvas → copy as PNG | Shipped |
| Paste into email | Copy image / markdown / text / .md download | Shipped |
| URL safe-view | urlscan existing-scan verdict+screenshot (in `/api/enrich`) + Browserling live-view pivot | **Shipped** — on-card screenshot preview + click-to-expand lightbox + Browserling pivot (2026-08-18) |

## P0 — DONE ✅ (2026-08-18)
Cloudflare Pages (`socdesk` project, socdesk.io) is live; enrichment keys set in
the **Production** scope; `/api/enrich` returns multi-source in prod (verified:
AbuseIPDB + VirusTotal + GreyNoise + ipinfo on a live IP). Also shipped since:
the AAA modern-stack rebuild (the `web/` React app, now the deploy target,
superseding the vanilla `site/`), the lookup **cockpit** (escalation card docked
beside the globe), and the live escalation-card loop (IOC in → OSINT out, with
the globe landing the pin). Shipped 2026-08-18 on top of that: **IPv6** lookups;
the **URL** screenshot preview + lightbox + **Browserling** safe-view; keyless
**RDAP** domain-registration; **Compare-IP / impossible-travel**; the browser
**extension full-card parity** (manifest v0.2.0); the **favicon** (SD monogram);
and the **de-wordify** doctrine change (the card + copy-out are now a clean,
factual artifact — see `docs/VERDICT-LANGUAGE.md`). Remaining gap: the
**Preview** env scope still lacks enrich keys (Production-only) — see Polish &
ops below.

**Also shipped 2026-08-19:** the **polymorphic cockpit** (intent-routing omnibox —
indicator→enrich, command→analyzer, one surface); the PowerShell / **multi-interpreter
analyzer** at `/analyzer` (see the Analyzer roadmap below); the `/analyzer#q=` prefill +
in-place IOC pivot; Gallery → internal-only (dropped from the public nav); and a full
**documentation-scoping pass** (docs now `web/`-first, `site/`-as-current traps removed,
`docs/REPO-MAP.md` added, BUILD-JOURNAL deprecated in favour of HANDOFF).

## P1 — hammer the loop (after P0, before anything else)
1. Live dogfood: 2-3 analysts run real alerts through it for a shift; fix
   what they trip on. The acceptance test: indicator → verdict → email
   evidence faster than the bookmark-folder workflow.
2. ✅ **SHIPPED (2026-08-18) — urlscan screenshot preview rendered on-page**,
   with a click-to-expand lightbox; CSP `img-src https://urlscan.io` added to
   both `_headers` and the `<meta>` copy. Wrinkle (b) confirmed real: the
   cross-origin urlscan image taints the evidence-card canvas, so the screenshot
   shows as a plain `<img>` beside the card and is **not** yet composited into
   the **Copy card** PNG. Fixing that is the pending same-origin **`/api/shot`**
   proxy (see Polish & ops).
3. ✅ **SHIPPED (2026-08-18) — Browserling safe-view pivot** (opens the URL in a
   disposable remote browser). Deep-link scheme verified live:
   `browserling.com/browse/win10/chrome/<url>` (a bare domain gets an `https://`
   scheme first).
4. **Analyst reach** (the Recorded Future extension question) — scoped in
   `docs/superpowers/specs/2026-08-10-analyst-reach-scope.md`: R1 bookmarklet
   selection-capture (small, do first), R2 right-click menu (ships with R3),
   R3 MV3 extension (only on real team demand + IT approval). ✅ **R3 SHIPPED
   to full-card parity (manifest v0.2.0)** — the toolbar popup renders the same
   `EscalationCard` as the web app (heroes, chips, Compare-IP, copy actions),
   sharing indicator detection + the enrich pipeline, so IPv6 / RDAP / URL all
   flow through. Chrome Web Store upload (Unlisted) remains an owner action.
5. **Reputation-quality fixes** (from the 2026-08-18 UX + SOC review) — ✅ **DONE (2026-08-24).**
   MalwareBazaar-on-IP-cards was already a no-op (source is `types:["md5","sha1","sha256"]`,
   never queried on an IP lookup — backlog note was stale). domain→IP clickable pivot SHIPPED
   (`364499e`→`85520e3`): VT `last_dns_records` A-record → a quiet "Hosting IP <ip> — check
   reputation" accent link on the domain card, pivots to `/#q=<ip>`. *(Earlier from that review:
   AbuseIPDB categories `31f053f`, GreyNoise honesty `eda8ed1`, honest source-class labels,
   per-source recency, EPSS attribution, dual-use Tor chip, AA contrast.)*
   - Deferred: extension-origin parity for `#q=` card links (pre-existing gap); the dead geo-based
     "Resolves to"/"Hosting" FactCells on domain cards (geoModel never populates for domains).

## Polish & ops (opportunistic, non-blocking)
- **Compare-IP globe arc** — the great-circle arc on the 3D globe (the shared-card
  SVG arc + the copy-card PNG arc are in; the globe-arc render is **landing now**).
- **Same-origin `/api/shot` proxy** — so the copied **Copy card** PNG can include
  the urlscan screenshot (cross-origin urlscan images taint the copy canvas today
  — the residual from P1.2).
- **Per-source metric / icon visual** — a small per-source metric or icon on each
  evidence line (visual pass, not yet built).
- Cockpit P2s: exit-anim symmetry (idle↔result), mobile compact-wordmark.
- Deploy hygiene: `git pull --rebase origin main` before every push (cron diverges
  origin, so a plain push silently no-ops); fix the PS-5.1 `.ps1` false-success
  deploy scripts; add enrich keys to the CF **Preview** env scope (fixes the
  GreyNoise-only preview enrich).
- Verify the privacy-page contact email.
- ~~**CI: Node-20→24 bump**~~ — ✅ DONE (verified 2026-08-25): `collect-and-deploy.yml` is on checkout@v7 / setup-python@v7 / setup-node@v7 (`node-version: "24"`) / wrangler-action@v4.
- ~~**CI: `concurrency:` group on `collect-and-deploy`**~~ — ✅ DONE (verified 2026-08-25): the workflow already declares `concurrency: {group: collect-and-deploy, cancel-in-progress: false}` (lines 11-13), so overlapping cron/dispatch runs serialize instead of racing the `data/state` commit.
- **CVE catalog growth** — `cves.json` is ~8 MB and hovers near the (now per-file
  16 MB) publish cap because it carries the 180-day window PLUS every KEV entry
  forever. Needs a windowing/pruning strategy (cap the KEV-forever accumulation)
  before it re-approaches the cap. Noted in `pipeline/validate.py`.
- **CVE `product` data-artifact** — some CVE rows carry `product: 'pipeline\'`
  (a backslash path fragment from the NVD products extraction); cosmetic, shows
  ugly in the trends/vuln surfaces. Fix the extraction in `collectors/nvd.py`.
- **Reporting deferred minors** (from the Phase-2 / UX-polish ships): "Check reputation"
  deep-link `aria-label` on the `/admin` row pivot; an OPERATIONS callback-logs doc line;
  shared `CATEGORIES` import + guard-test; the 2 Task-8 ReportDialog cosmetics.
- **⚠ OWNER TASTE CALL — rename the "Overview" tab?** The 2026-08-25 copy audit
  (`.superpowers/sdd/copy-audit.md`) flagged "Overview" (`App.tsx` + palette `commands.ts`)
  as a generic label; candidate rename to "Cockpit" / "Surface" (tie to the page's
  "Live threat surface" kicker). Left as-is — renaming the primary tab is the owner's call.
  Otherwise the audit verdict was: site copy is clean, analyst-grade (zero slop-word hits).

### Ransomware / TI-uplift follow-ups (owner-directed 2026-08-24)
_Shipped this lane: **Track A** CVE cheap-wins + hardening → LIVE. **Track B-A′** CISA-sourced ransomware **triage profile** → LIVE. **RANSOMWARE PROFILE REBUILD** (attributed named-victim layer w/ logos via same-origin favicon proxy + the digest-carries-claims coverage fix, re-seed by activity + provenance, associated-malware, staleness guard, 3-lens SOC/Data/UX review) → LIVE 2026-08-25. **HC3 ACTIVE-CREW DEPTH** (HHS HC3 as a 2nd public-domain intel source; Qilin seeded; schema gov-gate `(cisa|hhs).gov`; source-aware render via `intelSource.ts`) → LIVE 2026-08-25. Also LIVE 2026-08-25: **Nav/IA simplification** (Analyzer→omnibar + command chip + expand-link, Profiles→**Threat Intelligence**, retire Desk→Actors, Networks→**ISP Abuse Leaderboard**, drop Toolbelt), **3-lens profile refinements**, **landing** (climbing-CVE→lookup links + ISP Abuse Leaderboard homepage section), **copy audit** (verdict: clean; 4 tweaks). Specs/plans/reviews in `docs/superpowers/` + `.superpowers/sdd/`; spike `docs/research/vendor-sourcing-spike.md`._
- **Ransomware COVERAGE — the long tail (the "still no Nitrogen" gap).** A group is listed only if feed-active OR in ATT&CK OR in the intel seed. Two paths (R3 gates them): (a) a **name-only coverage layer** — list ransomware.live group names as directory entries that LINK OUT (rank curated/active first); (b) **broaden the intel seed beyond CISA**. **Path (b) PARTIALLY DONE via HC3** (2026-08-25): HHS HC3 threat profiles are public-domain (17 U.S.C. §105) AND cover active crews CISA doesn't — Qilin now seeded from its TLP:CLEAR HC3 profile. Path (a) + the vendor-blog remainder below are the open pieces.
- ~~**⚠ OWNER DECISION — vendor-blog Tier-3 depth.**~~ ✅ APPROVED + SHIPPED LIVE 2026-08-25. Owner said yes; built + compliance-reviewed (independent web-verification of every fact vs its cited report; wholesale-list boundary checked against Check Point/MITRE primary pages) + LIVE. 5 vendor-sourced crews added (DragonForce, INC Ransom, The Gentlemen, Kazu, Coinbase Cartel) — atomic facts only, per-source attribution via `sources[]`, NO gov `advisory` (that field stays gov-locked), rendered as a DISTINCT "Vendor-reported" badge + "Reported TTPs" panel ("atomic facts compiled from public vendor threat-reporting — unverified, not a government advisory", sources named+linked; `note_image`/CISA-wording structurally isolated). MetaEncryptor OMITTED (conflicting IOCs across sources → honest). Coinbase Cartel's `shinysp1d3r` dropped (in-dev/never-deployed → not a hunt target). Seed now 16 (11 gov + 5 vendor). Report: `.superpowers/sdd/vendor-tier3-report.md`. **Future:** extend to new active crews as reputable reporting appears (same atomic-facts protocol); consider a micro-caveat if any not-yet-deployed tool is ever added.
- **Seed expansion** — add more groups to `data/ransomware_intel.json` as CISA / FBI / **HHS HC3** publish new public-domain profiles (hand-curated, each field source-traceable; HC3 hhs.gov PDFs 403 to bots → verify via the AHA mirror).
- **Approach C — campaign-report / TI-parity page** — the shareable per-campaign report (CVEs + KEV due-dates + named TTPs + hunting-query links + targeting), rendering on the same group→CVE data layer A′ built. **HARD PREREQUISITE:** the **CARL KQL library must be vetted (strongest model) + QA'd** before any hunting-query links ship (CARL is a separate repo; KQL flagged stale/buggy). Its own phase.

## P2 — next core component (only once the loop is excellent)
CVE / Threat-Intel feed as the second pillar (feed, KEV/EPSS triage — already
built, needs dogfood-driven sharpening rather than new construction). Review
adds: CVE patch/fixed-version + an "overdue" chip when action-due < today; wire
`NVD_API_KEY` into `collectors/nvd.py`. Adjacent enrich/globe candidates:
~~OTX AlienVault as an enrich source~~ **(shipped 2026-08-20 — 8th enrich
source, `kind:context` community pulse attribution, `OTX_API_KEY`; OTX + RDAP are
now NON-BLOCKING — pulled off the verdict path 2026-08-22, so their slow egress no
longer gates the lookup)**;
AbuseIPDB blacklist → ambient reported-IP globe layer. *(The impossible-travel tool — two IPs → great-circle distance/velocity →
plausibility read — **shipped 2026-08-18 as Compare-IP**; the globe-arc render is
landing now, see Polish & ops.)*

## Expansion lane — analyst-utility workflow (owner-directed 2026-08-11)

Broaden the extension's **select → type-detect → focused output** gesture beyond
IOC lookup into an L1/L2 "investigation copilot." A dispatcher recognizes what
was highlighted and routes it to the right engine (the BASTION Tier-0.5 / CARL
engine model, behind the highlight gesture, on any page). One knowledge source,
two views: extension = quick highlight lookup where the analyst already is;
site = the fuller browsable reference. Every output copyable (the COPY pattern).

**Governing rule — ACCURACY FIRST (owner's #1 priority).** These outputs guide
investigation; a wrong table, a broken query, or a mis-decoded command wastes
analyst time and erodes trust worse than shipping nothing. So: deterministic /
curated-vetted content, NOT on-the-fly LLM that can hallucinate table/column/flag
names. Any LLM layer is a clearly-labelled "AI — verify" gloss on top of vetted
facts, never the source of truth. Facts-not-verdicts, same as enrich. Built from
PUBLIC sources only (LOLBAS, public ATT&CK, Microsoft table/schema docs) — never
port proprietary CARL/employer knowledge into this public repo.

**Guardrail:** this is an EXPANSION beyond the north-star loop, not part of it —
additive, accuracy-gated, must not dilute or slow the core paste→enrich→email
loop. Each candidate earns its place only if it removes a real step from the
L1/L2 daily loop.

**Public-vs-private data boundary (HARD RULE — the site is publicly reachable).**
On the PUBLIC surface, user-submitted input is limited to a **bare indicator**
(IP/hash/domain → reputation vendors, never an LLM), and the LLM only ever
processes **public data** (the Leg-2 feed, server-side + scheduled — no user
input reaches it). Therefore engines that ingest analyst-pasted content (command
lines, alerts, logs, emails) must run **deterministically and 100% client-side**
— the data never leaves the browser — which is what makes them safe on the public
tool. This rules out even an LLM "intent gloss" on the public site: a command
line can carry internal hostnames/users. Any **LLM-on-internal-data** assist
(escalation write-up draft, alert/log triage, phishing-email triage) is
**PRIVATE-ONLY** — a private instance (the extension's configurable origin →
tailnet + auth) or the internal toolset (BASTION/CARL), never socdesk.io.
Rationale: internal/client data must not leave the MSSP boundary into a public
tool + the home LLM + its Langfuse traces. Preserves the public-until-employer-IP
and never-leak posture.

Candidate engines (deterministic unless noted), by value:
1. **Command-line deobfuscator** — ✅ **SHIPPED as `/analyzer` + the polymorphic
   cockpit** (2026-08-19): decode `-enc`/Base64/gzip, deobfuscate, extract IOCs
   (each one-click into enrich), a MITRE technique tally + specificity-gated
   characterization, and **multi-interpreter** support (cmd.exe + mshta +
   wscript/cscript, nested re-entry, caret + WSH decode). Client-side,
   deterministic, never executes input. Rebuilt from public sources. **Its
   forward roadmap is the "Analyzer roadmap" block below.**
2. **Universal decoder** — highlight a blob → auto-detect + decode
   Base64/hex/URL/gzip. Client-side.
3. **Event ID + ATT&CK lookup** — highlight `4625` / `T1059.001` → what it is +
   what to check. Deterministic reference (ATT&CK data already in the pipeline).
4. **IOC extraction from a selection** — pull IOCs from a highlighted log/email,
   defanged + one-click enrich. (Owner passed on *paste-a-blob*; this is the
   highlight-driven cousin — confirm it's different enough before building.)
5. **"Explain this" LLM gloss** — local-LLM plain-English layer for messy
   obfuscated chains only; labelled AI + verify; grounded on the deterministic parse.

### Analyzer roadmap (`/analyzer`, active — owner-sequenced)

The command-line deobfuscator (candidate #1) shipped and is the live `/analyzer`
+ cockpit. Next, in order:
- **★ Kill-chain / "EXPLAINED" narrative** — ✅ **SHIPPED LIVE 2026-08-19**
  (`shared/analyzer/bullets.ts` — 28 execution-ordered `ActionRule`s → `ActionBullet[]`,
  rendered by `web/src/components/analyzer/ActionBullets.tsx` between the technique tally
  and the decode ladder + a copyText "What it did" section). Verb-first plain-English
  actions; three-tier honesty (resolved ● / inferred ~ / opaque ○ quarantined); NEVER
  invents intent (machine-guarded banned-word sweep); per-behavior IOC attribution (no
  cross-behavior misattribution). Built via 5-task SDD + whole-branch review (4 findings
  fixed + re-reviewed APPROVED) + a SOC output-quality pass on real samples (3 must-fixes).
  375 tests green.
- **Analyzer follow-ups** (from the kill-chain SOC output-quality pass): the `clickfix`
  "paste-and-run" label leaks into the top-line characterization on the generic
  hidden+nop+fetch+IEX branch when NO decoy text is present (the bullets themselves
  correctly stay silent — it's the `techniques.ts` signal label) → qualify/genericize that
  branch's label. (The `mshta→wscript` decode-layer mislabel is the `EMBEDDED_LAUNCHER_RE`
  `WScript.Shell` false-match already listed under Multi-interpreter follow-ups.)
- **Multi-interpreter follow-ups** (deferred from the 2026-08-19 increment): deep
  WSH deobfuscation (VBScript/JScript concat-fold + `Execute`/`eval` recursion);
  cmd env-var obfuscation (`%COMSPEC:~x,y%`, `set`/`%a%` reassembly); tighten the
  `EMBEDDED_LAUNCHER_RE` `WScript.Shell` false-match (burns depth-cap hops).
- **Broader gaps:** PS deobfusc breadth (`-join`/`-f`/`[char]`/`-replace`/
  `FromBase64String`/`.Invoke()` sink); technique-family expansion (cred-access /
  LSASS, ransomware shadow-delete, UAC bypass, lateral, DNS exfil); LOLBin table
  (9 of ~200 LOLBAS); honesty layer (real entropy / `wall` / `fractionAccounted`).

**Bigger arc — analyst recommendations / relevant SIEM tables + queries (owner
idea 2026-08-11).** Highlight an artifact (event ID, entity, technique) →
recommend the relevant SIEM table(s) + a set of VETTED, copyable queries +
bulleted context. Example: highlight `4625` → recommend `SecurityEvent`, a
starter KQL set (`SecurityEvent | where EventID == 4625 | ...`), and what to
check (logon types, source host, account).
- **Accuracy:** a curated, vetted query LIBRARY keyed to artifact type — NOT
  LLM-generated queries (they hallucinate table/column names). If an LLM ever
  assists, it must be schema-grounded and KQL-syntax-validated.
- **Scope:** start **KQL / Microsoft Sentinel + Defender** (best public docs,
  widest analyst audience, fully public schema). Generalize later to other SIEMs
  (Google SecOps UDM, Splunk SPL) — tag queries by SIEM.
- **Incorporation:** knowledge in one place (bundled client-side data for the
  common set; `/api` for the fuller KB). Extension = quick highlight lookup;
  site = browsable "table / event / technique → queries" reference. Queries
  copyable.
- Largest and most accuracy-sensitive lane; scope as its own phase after the
  smaller deterministic engines prove the dispatcher pattern.

## Sustainability, dataset & community lane (owner-directed 2026-08-20)

- **Enrich non-blocking context — SHIPPED ✅ (2026-08-22).** OTX/RDAP pulled off the
  `/api/enrich` blocking path (4-phase assembler + collect-anchored grace-race, `GRACE_MS=0`;
  `partial` recomputed from the BLOCKING axis = cache-safe; additive `skipped_context` honesty
  field). Cold lookups now **verdict-gated** (~0.8s IP / 1.0s domain live) instead of the old
  ~1.5s stopgap floor — context rides along free when ready, drops without gating when slow.
  Supersedes the OTX/RDAP 9s/7s→1.5s timeout stopgap. `spec 2026-08-22-enrich-nonblocking-context-design.md`.
- **★ Abuse hardening (`/api/enrich`) — B2, PENDING (wanted before a public share).** The public keyed proxy is currently
  protected ONLY by the 15-min edge cache; a script over novel indicators burns
  free-tier quota / risks a key ToS-revocation. Harden with: **Cloudflare
  Turnstile** (free, invisible — UX-transparent, gates the web app; extension
  needs a separate story), **per-IP rate limit** (CF free tier), and a **per-source
  daily budget circuit-breaker in CF KV** that degrades honestly ("quota reached —
  source not consulted") near a source's free quota. Owner: rate-limiting must NOT
  hamper real UX; reasonable added cost acceptable. Needs its own spec.
- **★ Own OSINT dataset (redistributable-only)** — high interest. Pull
  redistributable feeds (abuse.ch URLhaus/ThreatFox/Feodo, Spamhaus DROP/EDROP,
  FireHOL, CINSscore, blocklist.de, Tor exit list, OpenPhish/PhishTank) via the
  existing collector→pipeline→committed-data machinery; **check it FIRST** on
  lookup so keyed APIs become deep-enrichment fallback only (cuts key spend, works
  keyless/offline for covered indicators). Stays "aggregator not mirror" —
  redistributable feeds only, attributed. **Derived analytics it unlocks:** ISP /
  ASN **abuse-leaderboard rankings**, trend views, cross-feed dedup — original,
  publishable content. Bigger architectural direction → own design/spec.
- **Give back to OSINT** — (1) **publish the curated cross-feed dataset** (dedup +
  joined + attributed) as a community resource — YES; (3) **honeypot sensor** —
  YES, employment-IP gate LIFTED; generates real telemetry to report scanners
  (AbuseIPDB/GreyNoise) + submit samples (MalwareBazaar). (2) open-source the
  analyzer engine as a standalone lib — later / well down the line.
- **★ IOC reporting (crowdsourced abuse reporting).** Report an IP/domain/etc., AbuseIPDB/VT-style.
  Resolved the public-model risk with the **narrow contributor-identity account model**: the
  read/lookup path stays 100% no-account; only the *report/write path* is auth-gated (GitHub OAuth
  + Turnstile + per-account daily cap + owner moderation before any publish). Roadmap spec:
  `docs/superpowers/specs/2026-08-20-ioc-reporting-phase01-design.md`.
  - **Phase 0+1** (D1 + OAuth + report write path + my-reports) — ✅ SHIPPED + LIVE + dogfooded (2026-08-21).
  - **Reporting UX polish** (quiet-until-relevant account nav chip, real Report button in the card
    action row, ReportDialog modal + OAuth draft preservation, MyReports redesign, legibility) —
    ✅ SHIPPED (2026-08-22, 12-task SDD).
  - **Phase 2 — owner moderation console (`/admin`)** — ✅ SHIPPED + DOGFOOD-ACCEPTED (2026-08-22):
    owner-gated (numeric `OWNER_GITHUB_ID` secret, set) approve/reject queue; atomic race-safe D1
    write; fail-closed. `spec 2026-08-22-admin-moderation-console-design.md`.
  - **Phase 3 — publish approved reports as a live `SOCDESK_COMMUNITY` context source** — ✅ SHIPPED +
    LIVE + DOGFOOD-VERIFIED (2026-08-24). Option A committed dataset (D1 approved rows → Python export →
    served static JSON, no per-lookup D1); metric = `COUNT(DISTINCT github_id)` "reported by N
    contributor(s)"; `kind:context`, OUT of tally; twice-enforced no-PII fence (verified clean in prod).
    Live dogfood passed end-to-end (report → approve → export → row renders). 8-task SDD.
  - **`/about#community-reports` transparency page** — ✅ SHIPPED (2026-08-24): the verify-link target
    for community rows; dispute contact `abuse@socdesk.io` (Cloudflare Email Routing, inbound-only —
    removal-is-the-response); footer now "About · Privacy" + palette-discoverable.
  - **Phase 4** ISP/ASN abuse-leaderboard → **Phase 5** trends → **Phase 6** optional upstream push — pending
    (the now-populated community dataset is Phase 4's substrate).
- **Deferred / future ambition — broader user account (doctrine change, NOT now).**
  The account is deliberately a **narrow contributor identity** (report → my-reports →
  later reputation / corroboration-vote / contributor-profile) and **never touches the
  read loop**. A broader "user account" unlocking read-side conveniences — **watchlists /
  saved indicators, change-alerts & subscriptions, higher enrich rate-limit tiers** — is a
  genuine future direction but a **reversal of the no-account-read north-star doctrine**.
  Decide it deliberately as its own spec if/when pursued; do not back into it via a UX
  pass. (Owner-noted 2026-08-21.)

## Parked (fluff until further notice)
- Wave-2 collectors (C2IntelFeeds, APTnotes) — *(URLhaus/ThreatFox/PhishTank/Feodo
  now promoted into the dataset lane above)*
- Relationship-index enhancements beyond the shipped RELATED block
- Client-side fuzzy search; CVE corpus sharding
- Phase C Framework brief loop
