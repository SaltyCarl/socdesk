# SOCDESK — Public CTI Platform Design

**Date:** 2026-07-28
**Status:** Draft for review
**Repo:** `C:\Users\Carl\Desktop\Projects\SOCDESK` (public GitHub repo under SaltyCarl)

## 1. Purpose

A public, zero-cost cyber threat intelligence site that serves as the one-stop
shop for a SOC MSSP team's daily OSINT needs: a live threat feed, vulnerability
triage, IOC lookup, actor profiles, and analyst utilities — reachable at a
public URL with nothing to install.

Origin: a ChatGPT-generated reference site ("Vantage CTI") had the right idea
(daily intelligence, repository, collection health, source registry) but a
broken data layer — all fetches ran client-side and died on CORS. SOCDESK
rebuilds the concept with a real collection pipeline and adds MSSP-practical
workflows plus a locally-inferred daily brief.

The name: SOCDesk is the desk an analyst checks first — the front door for any
indicator, before the six tabs. (Renamed 2026-08-08 from the working title VIGIL.)

## 2. Goals and non-goals

**Goals**
- Public URL the whole team can open at work; no install, no accounts.
- Always-fresh raw intel regardless of any personal hardware being online.
- AI-written daily brief with zero API spend (local inference on the Framework).
- Analyst toolbelt so routine transforms (defang, decode, extract) happen in
  the same tab as the intel.
- Portfolio-grade: public repo, clean pipeline, distinctive design.
- $0 total cost. Free tiers and local compute only.

**Non-goals (v1)**
- Authentication, user accounts, or server-side per-user state.
- Paid enrichment (VirusTotal, Shodan, etc.) — even BYO-key.
- SIEM/SOAR integration.
- Any server runtime component. The deployed artifact is fully static.
- Client-specific data of any kind (see §8 guardrails).

## 3. Architecture — three tiers, independently degradable

```
Tier 1  GitHub Actions (cron ~45min)          Tier 2  Framework loop (cron 2x/day)
  Python collectors                              pull latest JSON + RSS full text
  -> normalized JSON snapshots                   entity clustering (pure Python)
  -> schema validation gate                      local LLM brief via LiteLLM :4444
  -> deploy site + data                          -> commit brief.json (deploy key)
        |                                              |
        +----------------------+-----------------------+
                               v
Tier 3  Static site (Cloudflare Pages, direct upload via wrangler)
  client-side search/filter over JSON, localStorage analyst state
```

Failure behavior:
- Tier 2 offline → site fully works; brief panel shows last-generated
  timestamp. Raw intel freshness is never coupled to the Framework.
- Any single Tier 1 collector failing → its source is marked degraded in
  health data; all other sources publish normally. A collector failure can
  never fail the workflow run or block deploys.
- Upstream outage with no fresh data → site serves last-known-good snapshots
  with visible staleness indicators.

### 3.1 Tier 1 — Collection (GitHub Actions)

Scheduled workflow (~every 45 min; tunable) runs Python collectors:

| Source | What it provides | Access |
|---|---|---|
| CISA KEV | Known-exploited CVE catalog | public JSON |
| NVD | Recent CVE details (CVSS, CPE) | public API, rate-limited |
| FIRST EPSS | Exploitation probability scores | public API |
| abuse.ch ThreatFox | IOCs with malware attribution | public API |
| abuse.ch URLhaus | Malicious URLs | recent/delta endpoint |
| abuse.ch MalwareBazaar | Sample hashes + families | recent endpoint |
| Ransomware.live | Ransomware group activity / victims | public API |
| MITRE ATT&CK | Groups, software, techniques | STIX JSON from GitHub |
| RSS pool | Vendor/researcher reporting (Talos, Unit 42, The DFIR Report, MS Threat Intel, etc.) | feedparser |

Collector requirements:
- Each collector is an isolated module with a common interface: fetch,
  normalize to the item schema (§6), report health. One failing never
  touches the others (per-collector try/except + timeout).
- Respect upstream rate limits; use recent/delta endpoints, never full dumps.
- Deployed JSON is a rolling window (feed items ~30 days, IOC repository
  ~90 days, CVE join table ~180 days) to cap payload size. Target: full data
  payload under ~10 MB gzipped.
- Schema validation gate in CI: malformed collector output fails validation
  and the previous snapshot for that source is retained; the deploy still
  ships.

Deploys are driven from the Action via `wrangler pages deploy` (direct
upload). Rationale: at this cadence, Cloudflare's git-integrated builds would
exhaust the 500-builds/month free cap in ~10 days; direct upload bypasses the
build system. Fallback if direct-upload quotas prove tighter than documented:
GitHub Pages via `actions/deploy-pages` (soft 10 builds/hour, well clear of
our 2/hour), optionally fronted by Cloudflare for the custom domain.

Repo is public: unlimited Actions minutes (private caps at 2,000 min/month,
below our usage) and portfolio value.

### 3.2 Tier 2 — Intelligence loop (Framework Desktop)

Cron job on the Framework, 2x/day aligned to shift starts (tunable):

1. Pull latest collected JSON + full text of top RSS items.
2. **Trending detection** — pure Python: cluster last-48h items by extracted
   entities (threat actors, malware families, vendors, CVE IDs). No LLM.
3. **Brief generation** — local model via existing LiteLLM gateway at :4444
   writes the Daily Brief: top 5-8 stories summarized, one-line
   "why it matters" per story, trending-topic callouts, notable new KEV
   entries. Output is structured JSON, validated before commit.
4. Commit `brief.json` to the repo with a fine-grained deploy key scoped to
   this repo only. The push triggers the same Action deploy path as Tier 1.

Constraints:
- Local inference only; no cloud LLM calls (zero API spend, and brief content
  never depends on external AI services).
- Automated commits use the SaltyCarl identity with no AI attribution
  (§8).
- Brief JSON carries `generated_at`; the site renders staleness honestly.

### 3.3 Tier 3 — Presentation (static site)

Static site deployed to Cloudflare Pages. All interactivity is client-side
over the published JSON. Per-analyst state (read/reviewed marks, "new since
last shift" cursor, personal vendor watchlist) lives in localStorage.

**Layout is intentionally unspecified.** The reference site's four-tab
structure is NOT a constraint. The design phase (§5) owns information
architecture, navigation, and visual structure end-to-end. This spec defines
capabilities only.

## 4. Capability inventory (what the site must let an analyst do)

1. **Daily threat feed** — scan normalized intel items reverse-chron; filter
   by category (ransomware / vulnerability / malware / APT / campaign) and
   source; see severity at a glance; mark items reviewed; see a "new since
   last visit" boundary.
2. **Daily Brief** — read the Framework-generated brief; see when it was
   generated; fall back gracefully when stale.
3. **Vulnerability triage** — sortable CVE table joining KEV membership +
   CVSS + EPSS + vendor/product; default ordering surfaces
   actively-exploited-AND-high-EPSS first; filter by a personal vendor
   watchlist (localStorage).
4. **IOC lookup** — paste one or many IPs / domains / hashes / URLs; search
   the full collected corpus; see source, malware attribution, first/last
   seen; bulk results exportable as CSV, JSON, and defanged plaintext.
5. **Actor & malware profiles** — ATT&CK-derived pages: aliases, techniques,
   associated software; cross-linked to related feed items and IOCs.
6. **Collection health** — per-source status, last successful run, item
   counts, recent errors.
7. **Source registry** — the reference site's 24-source catalog carried over
   as seed data, each entry linking out. Entries are marked either
   collector-backed (the 9 automated sources in §3.1, with enable/disable)
   or reference-only (curated link-outs).
8. **Toolbelt** — client-side utilities ported as snapshots from CARL's
   public-data tables: defang/refang, Base64 decode (UTF-16LE aware),
   PowerShell flag parser, IOC extraction from pasted text, LOLBin lookup
   (34-entry DB). Extraction results pivot directly into IOC lookup (#4).
9. **Shift handoff** — one click renders a markdown digest of items the
   analyst marked notable, copied to clipboard.

Cross-cutting: every IOC and CVE anywhere in the UI offers copy-defanged and
copy-raw; every feed item offers a copy-ready client-notification blurb
(generic wording, no client names).

## 5. Design phase (precedes feature implementation)

Multi-agent design pass using the established 3-layer methodology:

1. **Research sweep** — parallel design-research agents survey modern
   data-dense dashboard patterns from free galleries and OSS design systems
   (Awwwards/Godly-class references, shadcn ecosystem, Tremor/Grafana-style
   layouts). No paid libraries or references.
2. **`design-system.md`** — distilled per-project design system with
   anti-examples. Pre-seeded constraints: dark command-center baseline,
   Inter + JetBrains Mono, single saturated accent, hard ban on
   editorial-serif "AI slop" styling. The research sweep may propose
   evolutions beyond the baseline; the anti-examples are non-negotiable.
3. **Competing mockups** — 2-3 full-page mockups from design agents exploring
   different information architectures (they own tab structure, navigation
   model, density). Carl picks a direction; the Playwright iteration loop
   drives the winner to pixel-final before feature work begins.

## 6. Data contracts

**Feed item (normalized, all collectors):**
```json
{
  "id": "sha1 of source+native_id",
  "source": "threatfox",
  "category": "malware",
  "title": "...",
  "summary": "...",
  "url": "https://...",
  "severity": "high",
  "entities": {"actors": [], "malware": [], "vendors": [], "cves": []},
  "iocs": [{"type": "sha256", "value": "..."}],
  "published_at": "ISO-8601 UTC",
  "collected_at": "ISO-8601 UTC"
}
```

**Published files:** `feed.json` (rolling window), `iocs.json` (indexed by
type for fast lookup), `cves.json` (KEV+CVSS+EPSS join rows), `actors.json`
/ `malware.json` (ATT&CK-derived), `health.json`, `sources.json` (registry),
`brief.json` (Tier 2). All carry a top-level `generated_at` and `schema_version`.

Schema validation (jsonschema) runs in CI on every collector output before
deploy; a failing file is replaced by the previous snapshot, never deployed
malformed.

## 7. Testing

- **Collectors:** pytest with recorded fixture responses per source; tests
  cover normalization, rolling-window pruning, and failure isolation (one
  collector raising must not affect siblings' output).
- **CI gate:** schema validation on all published JSON; workflow fails only
  on pipeline bugs, never on upstream outages.
- **Brief loop:** structure-validation smoke test (prompt → valid brief.json)
  runnable on the Framework; content quality is human-reviewed.
- **UI:** Playwright suite — per established QA-loop checklist — covering
  search/filter/export flows, toolbelt transforms, localStorage state
  transitions, and stale-data rendering.

## 8. Guardrails

- **No client data, ever.** Nothing client-identifying enters the repo,
  the published JSON, the brief prompts, or the site. Watchlists are generic
  vendor/product lists. Client-aware workflows remain in CARL (local).
- **Attribution policy:** all commits — including Tier 1 workflow commits and
  Tier 2 automated commits — use the SaltyCarl identity with no AI
  attribution of any kind.
- **Cost ceiling: $0.** Public repo (free Actions), Cloudflare free plan,
  local inference. Any feature that would require spend is out of scope.
- **CARL boundary:** only public-data utilities are ported (as snapshots, not
  shared modules). CARL's routing engines, playbooks, KQL curation, and
  client profiles stay in CARL.

## 9. Success criteria

- Morning triage of the last 24h of intel takes under 10 minutes.
- A pasted IOC returns a verdict (hit with attribution, or clean-miss)
  in under 5 seconds.
- Raw feed data is never more than ~90 minutes stale while upstreams are up,
  regardless of whether the Framework is on.
- A teammate given only the URL can use every capability with no
  explanation, install, or login.
- Lighthouse-fast static load; full data payload under ~10 MB gzipped.

## 10. Open items (deferred, not blocking)

- Custom domain choice (works fine on `*.pages.dev` until decided).
- Brief cadence/shift alignment — start at 2x/day, tune after dogfooding.
- Wrangler direct-upload deployment quota re-verification during
  implementation (fallback path already defined in §3.1).
- Post-v1 candidates, explicitly parked: shared team state via a single
  Worker + D1, additional free sources (OTX, CIRCL), "copy as UDM search"
  toolbelt action.
