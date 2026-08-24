# Ransomware Profile Rebuild — Design Spec

**Date:** 2026-08-24
**Status:** Approved design (owner walked every decision through chat), pending review → plan → SDD
**Supersedes the presentation/coverage half of:** `2026-08-24-ransomware-triage-profile-design.md` (the CISA-triage panel it shipped stays; this rebuilds around it).

The v1 ransomware profile shipped correct but **shallow and coverage-inverted** (a SOC-analyst + data + UX critique): it enriched 10 famous historical groups (4% of this week's claims), rendered rich data thinly, discarded the victim identity, and left most groups as "name + link-out." This rebuild fixes coverage, surfaces the data we already have, adds an attributed named-victim layer, and gives the surface a real design pass.

---

## 1. Goals

1. **Coverage tracks activity, not fame.** A random ransomware alert this week should land on a group that has *something*. Re-seed by current claim volume (Qilin first) to the 30-40 target.
2. **Surface the data we already hold.** ATT&CK carries rich descriptions/techniques/software; leak-site claims carry victim/domain/sector/country/date. Both render shallowly or are discarded today.
3. **An attributed named-victim layer** (owner-directed): who a group has claimed, with logos, framed as unverified claims attributed to the leak site — a claim *record*, never a SOCDesk verdict.
4. **Presentation to near-parity feel** with ransomware.live, via a proper design pass (not build-to-spec), staying strictly on public-domain / own-aggregated data.
5. **Honesty + freshness:** provenance dates, honest-empty, no synthesized prose, no staleness hidden.

## 2. Compliance & sourcing — the boundary (owner-confirmed 2026-08-24)

**Facts + attribution are fair game; another party's expression/assets are not.**

- **Republish (leak-site claim FACTS, attributed to the LEAK SITE, framed unverified):** victim name, victim domain, sector, country, claim date, ransom-note filename, exploited CVEs. Sourced from the leak-site claim (discovered via the ransomware.live API, but attributed to the leak site — the ultimate source — not to ransomware.live). Justified by the owner's OSINT-liability posture ("name publicly-claimed victims *with attribution*") — a shift from the collector's current withhold-names stance, made deliberately.
- **Public-domain, redistributable — mirror freely:** CISA #StopRansomware + FBI FLASH (incl. their **figures** — the ransom-note screenshots CISA publishes are US-gov works, 17 U.S.C. §105); MITRE ATT&CK (Apache-2.0, already ingested); abuse.ch / ThreatFox (CC0).
- **Do NOT mirror:** ransomware.live's `description` (their editorial prose) or their `screenshot` asset — for note images use CISA's figures instead. COMPLIANCE.md R3 upheld: no ransomware.live editorial/asset mirrored; their `press` field is used only as news **link-outs**.
- **No ransomware.live permission email** this phase (owner). Investigate `ransomwatch` (open-source) as a more permissive claim-data source than the ransomware.live API — spike in the plan.
- **Logos:** the victim domain → a favicon/logo service (e.g. DuckDuckGo `icons.duckduckgo.com/ip3/<domain>.ico`), CSP `img-src` allowed for that host (or a same-origin proxy). Nominative use; degrade to a monogram when no domain. The "claimed / unverified, per <leak site>" framing stays prominent next to any logo.
- **`.onion` claim links: plain, non-navigable text** (owner) — never a hyperlink; matches the existing leak-site-infra treatment.

## 3. Data changes

### 3.1 Collector — stop discarding victim identity (`collectors/ransomwarelive.py`)
Today it emits sector/country only and hashes the victim name into an id. Change it to carry the claim FACTS per victim: `victim`, `domain`, `sector` (activity), `country`, `claim_date` (discovered), `claim_url`. Keep the digest/grouping behavior. Framing stays "unverified claim." (This also feeds the feed's ransomware rows — the "victim names withheld" line in the feed/profile is replaced by the attributed-claim treatment.) Schema-bound every new string; NO other PII beyond the org identity + its public domain.

### 3.2 Seed — re-seed by ACTIVITY + provenance (`data/ransomware_intel.json`)
- **Re-seed to 30-40 groups ranked by current claim volume** (re-run the window first — counts drift with the cron). Qilin first; include crpxo, coinbasecartel, and the other current busiest that have an authoritative public-domain writeup (CISA #StopRansomware **+ FBI FLASH + joint CERT advisories**). Keep the accurate existing entries. A busy group with NO writeup keeps the honest link-out (shrink that set, don't fake it).
- **Per-entry provenance:** add `advisory_date` and `last_reviewed` (ISO date). Rendered as an "as of" on the card.
- **Note figure (public domain):** where the CISA advisory includes a ransom-note screenshot, add its `cisa.gov` figure URL (`note_image`).
- Schema: add `advisory_date`, `last_reviewed`, `note_image` (pattern-locked to `^https://.*cisa\.gov/`), `sources[]` (advisory ids/urls for multi-source groups incl. FBI FLASH). `additionalProperties:false` retained.

### 3.3 abuse.ch malware link (already ingested)
Surface a group's associated malware/C2 from ThreatFox/Feodo where present, as a link into the malware profile / abuse.ch (CC0).

### 3.4 Provenance / staleness CI check
A cheap test/CI check that flags drift: cross-check the seed's CVEs against KEV's ransomware-flagged set, and warn when a seed entry's `last_reviewed` is older than N days — so silent staleness surfaces (the hand-curation risk).

## 4. Fusion (`web/src/components/views/profiles.ts`)
- **Named-victim list** from the collector claims: `{victim, domain, sector, country, claim_date, claim_url}[]`, newest first, per group.
- **Richer activity aggregates:** sectors, countries (fix the digest-drops-country gap where possible), a claim-volume **timeline** (claims/week), victim count.
- **ATT&CK-leaned intel:** render the full description + techniques + software already ingested (presentation, not new ingest).
- **Gate `reportsFor` on the curated dictionary** — kill the "Play"/"Akira" common-word FP on the profile's reporting list, not just the score bonus.
- **`hasIntel` / `hasClaims` surfaced** for the directory marker.
- Pure functions, unit-tested; honest-empty per field.

## 5. Presentation — the design pass (the "AI slop" fix)
**Method (owner-mandated):** use the **`ckm:ui-ux-pro-max`** skill + the design reference libraries (anime.js, motion.dev, kokonutui, reactbits, motion-primitives, swishy.ai, bklit.ui, Vantage CTI, Apple; repo `design/reference/REFERENCES.md`) to design the layout — NOT build-to-spec. Hold the existing brand system ([[feedback_visual_ai_slop_pattern]]: dark, Archivo + IBM Plex Mono, periwinkle #7C8AFF reserved accent; verdict red/amber/green carry meaning only).

Target surface (`ActorProfile.tsx` → the Threat-Intelligence entity page): a considered profile with (a) an identity header (name, aliases, first-seen, RaaS, status-as-facts), (b) the **CISA "Initial access & detection"** panel (kept from v1: CVE→lookup pivots, advisory, tools, signatures, note image), (c) an **activity** panel (claim-volume timeline chart, sectors, countries, victim count), (d) a **claimed-victims** list (logo + org + sector + country + date + plain-text `.onion` + "unverified claim, per <leak site>"), (e) ATT&CK fingerprint (description/techniques/software), (f) related + reporting (link-outs), (g) an "as of <last_reviewed>" provenance line. Every section honest-empty. A chart type from ui-ux-pro-max for the timeline (deterministic, no heavy dep beyond what's approved).

## 6. Coverage / directory
A group is listed if feed-active OR ATT&CK OR seeded; **mark seeded/intel groups** with a directory badge (render `hasIntel`) so the value is findable; curated/active sort first.

## 7. Non-goals / explicitly out
- No ransomware.live editorial or asset mirror; no permission email this phase.
- No synthesized descriptions/verdicts/status; no hosted IOC corpus.
- The IA cut (Desk-Actors→Profiles, TI / ISP Abuse Leaderboard renames + landing section, Toolbelt removal) and the Daily-summary CVE title+link + AI-slop copy sweep are **separate phases** of the program, not this spec.

## 8. Testing & review gates
- Pure-fusion + collector + schema unit tests (assert shape/rules, never live content).
- **Design pass** via `ckm:ui-ux-pro-max` + references (§5).
- **Three-lens final review before close-out (owner-mandated, [[feedback_design_pass_and_review]]):** a **SOC Analyst** pass (triage value on a real alert), a **Data Analytics** pass (aggregations/timeline correct + honestly presented), a **UX Designer** pass (IA, formatting, polish, AI-slop) — in addition to the normal code review.
- **Live dogfood:** re-seeded active group renders full; a claimed-victim shows a logo + attributed framing; `.onion` is plain text; provenance shows.

## 9. Global Constraints
Free-tier / no paid APIs / no accounts; deterministic; honesty doctrine (attributed facts, honest-empty, no synthesized verdict); **COMPLIANCE R3** (facts+attribution yes, ransomware.live expression/assets no); named victims framed as unverified claims attributed to the leak site; schema-bounds every string/array; committed-dataset tests assert shape not content; `github.com/SaltyCarl/*` → NO AI attribution on commits; brand system held.

## 10. Build sequence (for the plan)
1. Collector: emit victim/domain/sector/country/date (+ tests).
2. Seed: re-seed by activity to 30-40 (Qilin first) + provenance + note-image fields + schema (+ tests). Spike `ransomwatch` viability.
3. Fusion: named-victim list + richer aggregates + reportsFor gate + hasIntel (+ tests).
4. abuse.ch malware surface.
5. Presentation design pass (`ckm:ui-ux-pro-max` + references) → the rebuilt profile + directory badge + logos + `.onion` plain + provenance.
6. Provenance/staleness CI check.
7. Deploy + 3-lens review + live dogfood.
