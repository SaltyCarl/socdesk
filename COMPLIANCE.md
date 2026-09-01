# SOCDESK — Compliance Findings & Gates

Skeptical compliance/legal review, 2026-08-06. This file is a launch gate; do
not deploy publicly until the must-fix items are closed.

## 2026-08-06 scope correction (re-rates the register below)

Owner clarified: **personally owned** (not the company), **primarily a
portfolio/showcase project** shown to the team who *may* reference it — NOT
mandated daily-driver tooling. Core functions: (1) consolidate IOC lookups,
(2) output an IOC into a presentable escalation format, (3) current cyber
news. This lowers several ratings:

- **R1 (team adoption): CRITICAL → MEDIUM.** A personal showcase individuals
  reference is not institutional shadow IT. Residual risk is unchanged by
  ownership or "official" status: it returns the instant anyone pastes a
  **real client-incident IOC** — that's a data-sensitivity fact, not a
  framing fact. Control = "personal project; use PUBLIC indicators only"
  stated plainly on the site + the pivot OPSEC footnote.
- **R7 (CUI): MEDIUM → LOW**, same caveat — fine for public-indicator
  research; document "not for CUI-scoped client-incident indicators."
- **R2 (employer IP): UNCHANGED — HIGH.** Personal ownership is the *intent*,
  but ownership is decided by the employment agreement's IP-assignment
  clause, not by declaring it. "I own it" does not resolve this — reading the
  clause does. Still the top thing to verify.
- **R3/R4 (data redistribution): UNCHANGED** — republication rights don't
  depend on who owns the site or whether use is "official." Still must-fix.
  But they align with the core: see the IOC-model note.

**IOC-model note (serves the #1 core function AND fixes R4):** favor the
*aggregator/pivot* model over the *mirror* model. Analyst pastes an IOC →
SOCDESK detects type → shows a verdict from clearly-redistributable data it
holds (KEV/EPSS/NVD, all CC0/public-domain/FIRST) + a row of deep-links to
external reputation services (VT, GreyNoise, AbuseIPDB, urlscan…). Linking is
not redistributing — this sidesteps the abuse.ch corpus-mirror problem (R4)
and is a *better* one-stop-shop for lookups than holding a stale local IOC
mirror. Keep the local corpus only for the public-domain vuln data.

## The correction that matters most

The architecture's privacy strengths (fully static, no backend, `connect-src
'self'` CSP, localStorage-only analyst state) are real — but they defend
against **data exfiltration**, which is *none of the top four risks*. Several
earlier assurances were wrong:
- "no client names" in case-note templates answers the wrong question — the
  template *shape* is the concern (R6).
- "free/OSS sources only" conflates free-to-access with free-to-redistribute
  (R3, R4).
- "the team can just use it" ignores that unapproved personal tooling in a
  client-incident workflow is itself the critical finding (R1).

## 2026-08-06 RE-REVIEW (aggregator scope) — FINAL register, supersedes below

Verified: KEV = CC0, NVD = US-Gov public domain (embedded CVE text CC0),
EPSS = free to publish **with attribution, no implied endorsement**. So the
local KEV/NVD/EPSS corpus is genuinely clean to hold. abuse.ch, AbuseIPDB,
VirusTotal are NOT open-licensed — but a plain `<a href>` deep-link is not
redistribution and doesn't touch their terms; a background `fetch()` would
(CSP `connect-src 'self'` already blocks that — keep it).

| # | Risk | Final | Note |
|---|------|-------|------|
| R1 | Team adoption / shadow-IT | MEDIUM | Not mandated + no backend/retention shrinks it; colleague-pastes-live-IOC residual remains |
| R2 | **Employer IP** | **HIGH — the gate** | "Personally owned" does NOT defeat a "relates-to-employer's-business" assignment clause; turns on the actual contract + whether any employer time/equipment/confidential-info was used. Unverifiable here. |
| R3 | Ransomware.live / leak-site republication | **MED — accepted with safeguards (re-rated 2026-08-25, see below)** | ⚠ **Behavior CHANGED 2026-08-24:** leak-site CLAIM FACTS (victim org name, domain, sector, country, date, note-filename, exploited CVEs) ARE now republished — attributed to the LEAK SITE (the ultimate source), framed **unverified** ("Unverified claim by \<group\>, per its leak site"). ransomware.live's own editorial `description`/`screenshot` are NOT mirrored; intel panels remain public-domain (CISA/HC3 §105) or attributed-vendor facts. The old "link-out only, nothing mirrored / LOW-resolved" rating is **superseded** — see the dated R3 re-rating below. |
| R4 | abuse.ch redistribution | LOW / resolved | No corpus held; deep-link ≠ redistribution |
| R5 | Public verdicts | LOW-MED | KEV/EPSS = "known-exploited / probability", not "malicious" — smaller surface; keep sourced + timestamped |
| R6 | Escalation template | **RE-OPENED MEDIUM** | Core function (b) revives it — must pass the generic test below |
| R7 | CMMC/CUI handling | MEDIUM | Behavior-driven; **amplified** by one-click fan-out (faster/wider third-party disclosure) |
| R8 | SIEM-query gen | LOW | Vendor-neutral framing |
| R9 | RSS/attribution | LOW-MED | Headline+snippet+link only; attribute feeds |

### R3 re-rating — leak-site victim-claim republication (2026-08-25)

_Documents a deliberate policy change. Prompted by an external site-review that correctly flagged this doc as false about live behavior. This is a documented risk-acceptance position + reasoning, not legal advice; the owner owns the residual-risk acceptance and the operational safeguards below._

**What changed (2026-08-24, `collectors/ransomwarelive.py`):** the collector previously withheld victim names ("victim names are not republished here"). It now republishes, per claim, the **victim organisation name, domain, sector, country, claim date, ransom-note filename, and exploited CVEs** — as the digest's `claims[]` and the profile's claimed-victim ledger. This reverses the earlier "drop victim name" position in the superseded §"Must-fix" list below.

**Why the position is defensible (the considered basis):**
- **Facts, not expression.** The republished values are discrete FACTS (an org name, a domain, a date) — not copyrightable expression. ransomware.live's own editorial `description` and its `screenshot` asset are NOT mirrored (COMPLIANCE R3's original "don't mirror their expression/assets" line is upheld). Intel-panel depth is public-domain (CISA/HHS-HC3, 17 U.S.C. §105) or attributed atomic vendor facts, never mirrored prose.
- **Attributed to the leak site, framed unverified.** Every claim renders "Unverified claim by \<group\>, per its leak site" — SOCDesk asserts only that the criminal group PUBLICLY CLAIMS the victim (a true statement about a public event), never that a breach occurred. This is a claim RECORD, not a SOCDesk verdict.
- **OSINT-liability posture.** The owner's standing posture is to name **publicly-claimed victims WITH attribution** — the leak-site claim is already public; re-surfacing it attributed + unverified is defensible OSINT (consistent with how ransomware.live, and news outlets, report leak-site claims).
- **Not a permanent static mirror of live claims.** The feed is regenerated from live data twice-hourly, so a claim the group removes drops from the live surface on the next collection (a caveat below covers git-history snapshots).

**Safeguards in place:** unverified/attributed framing on every claim; strings inert-cleaned (`clean_text`), domain hostname-charset-guarded; no ransomware.live editorial/screenshot mirrored; org identity + public domain only (no individual PII); `.onion` claim links rendered as plain non-navigable text.

**Name-only group coverage (2026-09-01, `collectors/ransomwarelive_groups.py`):** the directory additionally lists the bare **group names** from ransomware.live's `/v2/groups` — a name is the minimal fact, attributed, rendered as a link-OUT to ransomware.live's own group page; the endpoint's editorial (`description`, `locations`, `ttps`, `tools`) is discarded at collection and never republished. Strictly less per item than the victim facts accepted above; rides the same open gap #4 (API terms) below.

**Rating: MEDIUM — accepted risk with the safeguards above.** (Not "LOW/resolved" — it is a live, legal-adjacent republication under the owner's real name on a public repo. Not "CRITICAL" — the facts-only + attributed + unverified + no-editorial-mirror design materially reduces the surface the original CRITICAL rating assumed.)

**⚠ OPEN operational gaps (owner to decide — my recommendation, not yet built):**
1. **A dispute / takedown / correction path** — a contact + a documented "we remove on a credible dispute" stance. The single most important missing mitigation; a public tool naming orgs as claimed victims needs a way to be told "that's wrong / remove it."
2. **An explicit personal-data stance** in this doc: org identity + public business domain only; never individual names/emails/PII; how a mistakenly-included individual is handled.
3. **Git-history retention:** committed `data/state` snapshots persist a claim even after the group retracts it and the live feed drops it. Decide whether that's acceptable or whether snapshots should be shallow / periodically pruned.
4. **ransomware.live API terms:** facts are attributed to the leak site (the ultimate source), but they are DISCOVERED via ransomware.live's API (personal-use free tier). Confirm that discover-via-their-API-then-republish-the-underlying-leak-site-fact sits inside their terms, or move discovery to a more permissive source (the `ransomwatch` spike is on file).

### Hard design constraints for Phase B (from the re-review)
1. **Aggregator = explicit user-click deep-links ONLY.** No auto-fan-out
   (one click must not spray an indicator to 6 services at once), no
   background fetch of any third-party service. Keep CSP `connect-src 'self'`.
2. **Prominent disclosure banner**, not a footnote: "Clicking a pivot
   discloses this indicator to that third-party service. Use PUBLIC
   indicators only." + urlscan public-scans-are-published caveat.
3. **Escalation output must pass the generic test:** *"Could an analyst at
   ANY company paste this unchanged, and does it reveal nothing about how MY
   employer specifically notifies MY employer's clients?"* Author from
   scratch (indicator, type, public verdict, KEV/EPSS context, neutral
   next-steps). Must NOT reproduce employer ticket/notification template,
   severity taxonomy, SLA language, or client-facing phrasing.
4. **EPSS attribution** + no implied FIRST/NIST/CISA endorsement.

### The two things still being rationalized past (owner must own these)
- **R2 is the real gate and it's on Carl, not the code:** read the actual
  employment IP-assignment agreement; confirm no employer time/equipment/
  confidential info was used. "I personally own the domain" dissolves nothing.
- **R7 didn't vanish, it moved to analyst behavior:** the single most likely
  real use — a colleague pasting a LIVE client IOC to build an escalation — is
  the CUI/DFARS exposure, and the one-click aggregator makes that disclosure
  faster/wider. "Public indicators only" is a real control only if the banner
  is prominent and nothing persists server-side (it doesn't). Treat it as a
  genuine constraint, not launch copy.

---

## (superseded) Must-fix BEFORE public launch

- **R3 — CRITICAL — Ransomware.live victim republication.** _⚠ REVERSED 2026-08-24 → see the dated "R3 re-rating (2026-08-25)" section above, which supersedes this bullet: victim names/domains ARE now republished (attributed, unverified, facts-only). The concerns below were re-weighed there; the operational gaps (dispute path, personal-data stance, git-history retention, API terms) remain open._ Their terms bar
  commercial use and free API is personal-use only; listings are unverified
  criminal claims; a static mirror won't propagate upstream retractions; org
  names can be personal data. ~~**Action: stop republishing named victims** —
  group-level activity/counts only, link out for detail.~~ (Pipeline change:
  `collectors/ransomwarelive.py` — drop victim name from title/summary, or
  gate behind written permission.)
- **R4 — HIGH — abuse.ch redistribution.** Post-Spamhaus terms condition
  copying platform data on express consent; free access is not-for-profit
  only; a for-profit MSSP team consuming a public mirror is in the
  conditioned/prohibited zone. **Action: either get written OK from abuse.ch
  describing the exact use, or drop bulk republication and link out per-IOC.**
  (Affects threatfox/urlhaus/malwarebazaar collectors + iocs.json publish.)
- **R5 — MEDIUM — public MALICIOUS verdicts.** Community-sourced, FP-prone,
  static snapshot persists after retraction; MIT no-warranty covers code not
  published assertions. **Action: per-verdict disclaimer (source + timestamp,
  "not verified; UNKNOWN ≠ benign"), correction contact, `noindex` on the
  site.**
- **R6 — MEDIUM — case-note/client-notification templates.** Ship empty /
  user-authored in localStorage; **remove baked templates from the public
  repo.**
- **R9 — LOW/MED — attribution & content reuse.** RSS = headline + sanitized
  snippet + link only, never full text. MITRE ATT&CK/CVE require the MITRE
  copyright/permission notice (already in README — keep). NVD public domain,
  KEV CC0, EPSS cite FIRST. Verify README covers all.

## Must-fix BEFORE any MSSP-team use

- **R1 — CRITICAL — unapproved team adoption = shadow IT.** Analysts triaging
  client incidents on an employee's personal public site sits outside change
  control / vendor management / client contracts — a reportable SOC2/client
  audit finding. Architecture is irrelevant to this objection. **Action:
  written employer security review + management sign-off before any team use.
  Until then, personal project only; strip all "for my SOC team" framing from
  repo/README/commits going forward.**
- **R2 — HIGH — employer IP / moonlighting.** A SOC analyst publishing a SOC
  tool "related to the employer's business" — many IP-assignment agreements
  reach this. **Action: check the actual employment agreement; get a written
  side-project acknowledgment; keep content strictly generic OSINT.**
- **R7 — MEDIUM — CMMC/CUI scope.** The *data* is not CUI/FCI/ITAR (public
  OSINT). The exposure is behavioral: an unapproved external tool with
  persistent localStorage history of live client-incident indicators on a
  workstation inside a CMMC assessment boundary conflicts with typical
  software-restriction / config-management controls (CM.L2 3.4.8/3.4.9); and
  pivoting a GCC-High incident IOC to VirusTotal discloses investigation
  activity to a third party some DFARS flowdowns restrict. **Action: document
  "not for use on CUI-scoped assets without employer approval"; keep the
  pivot-disclosure warning prominent.**

## Lower / accepted with controls

- **R8 — LOW** SIEM-query generator (KQL/UDM/SPL together) discloses nothing
  if repo framing stays vendor-neutral. Keep all three formats.
- Privacy statement on site + README (the architecture's genuine strength,
  made legible). Clear-analyst-state button. OPSEC footnote on pivots
  (strengthen per R7).

## Parked — do NOT build as public

Shared team state (shared review marks / team watchlist / per-analyst
investigation metadata on a server) still crosses the line and stays parked —
if ever wanted, a SEPARATE deployment behind authentication, never a bolt-on to
the public site.

_Note (2026-08-25): a Worker + D1 path WAS since built — the **community-report**
feature (public Turnstile-gated submissions → a D1 queue → owner-OAuth
moderation at `/admin`; only owner-approved reports are shown, no per-analyst
state). That is a crowdsourced-public-abuse-report queue with an auth-gated
write/moderate path, deliberately NOT the "shared team investigation state" this
section forbids — the earlier blanket "do NOT build Worker+D1 public" is
narrowed to that specific shared-investigation-state case._

Sources: abuse.ch Terms of Use · ThreatFox API terms · Ransomware.live
disclaimer + API terms · MITRE ATT&CK Terms of Use · cisagov/kev-data (CC0) ·
FIRST EPSS · NVD.
