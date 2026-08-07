# VIGIL

A personal, public triage cockpit for open-source threat intelligence: paste
an indicator once and get an authoritative vulnerability verdict, one-click
pivots to every relevant public reputation service, and an escalation-ready
summary — alongside a live cyber-news feed. Static site fed by scheduled
collectors; zero infrastructure, zero cost.

**Aggregator, not mirror.** VIGIL publishes only data it may clearly
redistribute (CISA KEV, NVD, FIRST EPSS, MITRE ATT&CK, headline+link RSS).
Reputation services (VirusTotal, AbuseIPDB, GreyNoise, urlscan, abuse.ch,
Shodan) are reached through user-clicked deep links, never mirrored.

> **Privacy:** there is no backend, no accounts, and no analytics. Anything
> you paste, mark, or save stays in your browser (localStorage) and is never
> transmitted — the site's Content-Security-Policy blocks outbound requests.
> **Clicking a pivot link discloses that indicator to the third-party
> service** (and urlscan publishes public scans). Use public indicators only.

*Personal project by SaltyCarl — not affiliated with or endorsed by any
employer, and not an official tool of any organization.*

## Architecture

- **Collect** — GitHub Actions cron runs Python collectors for 9 public
  sources every 30 min, validates against JSON Schemas, keeps last-known-good
  per file, and commits rolling state snapshots.
- **Enrich** — a local job (separate machine) writes `data/brief.json`
  (AI-written daily brief); its push auto-redeploys the site.
- **Serve** — `site/` deploys to Cloudflare Pages via wrangler direct upload.

## Local development

    python -m venv .venv
    .venv\Scripts\pip install -r requirements.txt
    .venv\Scripts\python -m pytest tests/ -v      # fixture-backed, no network
    .venv\Scripts\python run_pipeline.py          # live run -> site/data/
    .venv\Scripts\python -m http.server 8080 -d site

## One-time setup

1. Create the public GitHub repo and push.
2. Cloudflare: create a Pages project named `vigil`
   (`npx wrangler pages project create vigil`).
3. Repo secrets (Settings → Secrets → Actions):
   - `CLOUDFLARE_API_TOKEN` — API token with Cloudflare Pages > Edit
   - `CLOUDFLARE_ACCOUNT_ID` — from the Cloudflare dashboard
   (No data-source keys are needed — every collector uses keyless public
   endpoints.)
4. Run the workflow once manually (Actions → collect-and-deploy → Run
   workflow) and open the `vigil.pages.dev` URL.

## Data files

`feed.json` (30-day window) · `cves.json` (180-day, KEV+CVSS+EPSS join) ·
`actors.json` / `malware.json` (ATT&CK) · `health.json` · `sources.json` ·
`brief.json` (optional, external writer)

## Data sources, attribution, and terms

All intelligence is aggregated from public sources; every item links back to
its origin, and the Source Registry documents the full set. In particular:

- ATT&CK® content: © 2026 The MITRE Corporation. This work is reproduced and
  distributed with the permission of The MITRE Corporation. ATT&CK is a
  registered trademark of The MITRE Corporation.
- Exploit Prediction Scoring System (EPSS) scores provided by FIRST
  (https://www.first.org/epss/). CISA KEV data is U.S. Government work in the
  public domain. IOC data courtesy of the abuse.ch projects (ThreatFox,
  URLhaus, MalwareBazaar) under their community terms. Ransomware activity
  data via Ransomware.live. Headlines and summaries are excerpted with
  attribution and link to the original publishers.

This is an informational aggregation tool. No warranty is made about the
accuracy or completeness of third-party data; verify independently before
acting on any indicator.
