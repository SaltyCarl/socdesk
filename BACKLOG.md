# SOCDesk Backlog

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
| Paste indicator | Omnibox, type auto-detect, refang, bulk, bookmarklet | Shipped |
| Get reputation | `/api/enrich` Pages Function → AbuseIPDB + VT + GreyNoise + **ipinfo geo/ASN** (IP), VT + MalwareBazaar (hash), VT + **urlscan verdict** (URL/domain) | **Live** — socdesk.io, keys set 2026-08-18; multi-source verified in prod |
| Screenshot for the email | Evidence card rendered to canvas → copy as PNG | Shipped |
| Paste into email | Copy image / markdown / text / .md download | Shipped |
| URL safe-view | urlscan existing-scan verdict+screenshot (in `/api/enrich`) + Browserling live-view pivot | Verdict shipped; screenshot preview + Browserling pivot = **active build (P1.2/1.3)** |

## P0 — DONE ✅ (2026-08-18)
Cloudflare Pages (`socdesk` project, socdesk.io) is live; enrichment keys set in
the **Production** scope; `/api/enrich` returns multi-source in prod (verified:
AbuseIPDB + VirusTotal + GreyNoise + ipinfo on a live IP). Also shipped since:
the AAA modern-stack rebuild, the lookup **cockpit** (escalation card docked
beside the globe), and the live escalation-card loop (IOC in → OSINT out, with
the globe landing the pin). Remaining gap: the **Preview** env scope still lacks
enrich keys (Production-only) — see Polish & ops below.

## P1 — hammer the loop (after P0, before anything else)
1. Live dogfood: 2-3 analysts run real alerts through it for a shift; fix
   what they trip on. The acceptance test: indicator → verdict → email
   evidence faster than the bookmark-folder workflow.
2. **urlscan screenshot preview rendered on-page** (the `screenshot` URL is
   already returned by the enrich function, urlscan-origin-guarded). Two real
   wrinkles to handle deliberately, not bolt on: (a) CSP is `default-src
   'none'` — showing the image needs `img-src https://urlscan.io` added to
   BOTH `_headers` and the `<meta>` copy (csp.spec.js enforces they match);
   (b) the evidence-card canvas is copied to clipboard as PNG — drawing a
   cross-origin urlscan image onto it taints the canvas and breaks the copy
   unless urlscan sends CORS headers (verify; if not, show the preview as a
   plain `<img>` beside the card, not composited into it).
3. Verify the Browserling deep-link format against their current URL scheme
   at first live use.
4. **Analyst reach** (the Recorded Future extension question) — scoped in
   `docs/superpowers/specs/2026-08-10-analyst-reach-scope.md`: R1 bookmarklet
   selection-capture (small, do first), R2 right-click menu (ships with R3),
   R3 MV3 extension (only on real team demand + IT approval). All gated on
   enrichment being live.
5. **Reputation-quality fixes** (from the 2026-08-18 UX + SOC review — sharpen the
   "get reputation" output the analyst actually reads): drop MalwareBazaar from IP
   cards (it's hash-only and currently mis-leads the lead fact); add AbuseIPDB
   abuse categories to the IP card; add the resolved A-record IP to domain cards
   (enables the domain→IP pivot). *(Already shipped from that review: honest
   source-class labels, ledger alignment, per-source recency on card+PNG, EPSS
   attribution, the dual-use Tor chip, AA contrast.)*

## Polish & ops (opportunistic, non-blocking)
- Cockpit P2s: exit-anim symmetry (idle↔result), mobile compact-wordmark.
- Deploy hygiene: `git pull --rebase origin main` before every push (cron diverges
  origin, so a plain push silently no-ops); fix the PS-5.1 `.ps1` false-success
  deploy scripts; add enrich keys to the CF **Preview** env scope (fixes the
  GreyNoise-only preview enrich).
- Verify the privacy-page contact email.

## P2 — next core component (only once the loop is excellent)
CVE / Threat-Intel feed as the second pillar (feed, KEV/EPSS triage — already
built, needs dogfood-driven sharpening rather than new construction). Review
adds: CVE patch/fixed-version + an "overdue" chip when action-due < today; wire
`NVD_API_KEY` into `collectors/nvd.py`. Adjacent enrich/globe candidates: OTX
AlienVault as an enrich source; AbuseIPDB blacklist → ambient reported-IP globe
layer; impossible-travel tool (two IPs → great-circle distance/velocity → verdict,
reusing the dropped globe-arc geometry).

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
1. **Command-line deobfuscator** (v1.2 top pick) — highlight a PS/cmd line →
   decode `-EncodedCommand`/Base64, expand aliases, flag switches
   (`-nop -w hidden -ep bypass`), name LOLBins, extract embedded URLs/IPs/hashes
   (each one-click into enrich). Client-side, deterministic. Reuses BASTION's
   PS-analyzer technique, rebuilt from public sources.
2. **Universal decoder** — highlight a blob → auto-detect + decode
   Base64/hex/URL/gzip. Client-side.
3. **Event ID + ATT&CK lookup** — highlight `4625` / `T1059.001` → what it is +
   what to check. Deterministic reference (ATT&CK data already in the pipeline).
4. **IOC extraction from a selection** — pull IOCs from a highlighted log/email,
   defanged + one-click enrich. (Owner passed on *paste-a-blob*; this is the
   highlight-driven cousin — confirm it's different enough before building.)
5. **"Explain this" LLM gloss** — local-LLM plain-English layer for messy
   obfuscated chains only; labelled AI + verify; grounded on the deterministic parse.

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

## Parked (fluff until further notice)
- Wave-2 collectors (FeodoTracker, C2IntelFeeds, PhishTank, APTnotes)
- Relationship-index enhancements beyond the shipped RELATED block
- Client-side fuzzy search; CVE corpus sharding
- Phase C Framework brief loop
- Honeypot sensor (also gated on the employment-IP question)
