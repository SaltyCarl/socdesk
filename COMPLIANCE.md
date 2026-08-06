# VIGIL — Compliance Findings & Gates

Skeptical compliance/legal review, 2026-08-06. **Verdict: publishable with
changes — NOT as-is, and NOT as an MSSP-team tool without written employer
approval.** This file is a launch gate; do not deploy publicly or promote
internal use until the must-fix items are closed.

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

## Must-fix BEFORE public launch

- **R3 — CRITICAL — Ransomware.live victim republication.** Their terms bar
  commercial use and free API is personal-use only; listings are unverified
  criminal claims; a static mirror won't propagate upstream retractions; org
  names can be personal data. **Action: stop republishing named victims** —
  group-level activity/counts only, link out for detail. (Pipeline change:
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

Shared team state (Worker + D1 / shared review marks / team watchlist) would
put investigation metadata on a server and crosses the line. If ever wanted,
it is a SEPARATE deployment behind authentication (Cloudflare Access), never a
bolt-on to the public site.

Sources: abuse.ch Terms of Use · ThreatFox API terms · Ransomware.live
disclaimer + API terms · MITRE ATT&CK Terms of Use · cisagov/kev-data (CC0) ·
FIRST EPSS · NVD.
