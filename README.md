# VIGIL

Public CTI console for SOC daily use: live threat feed, KEV+EPSS vulnerability
triage, IOC repository, actor profiles, and analyst utilities. Static site fed
by scheduled collectors; zero infrastructure, zero cost.

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
   - `ABUSECH_AUTH_KEY` — free key from https://auth.abuse.ch (used by
     ThreatFox / URLhaus / MalwareBazaar collectors)
4. Run the workflow once manually (Actions → collect-and-deploy → Run
   workflow) and open the `vigil.pages.dev` URL.

## Data files

`feed.json` (30-day window) · `iocs.json` (90-day) · `cves.json` (180-day,
KEV+CVSS+EPSS join) · `actors.json` / `malware.json` (ATT&CK) ·
`health.json` · `sources.json` · `brief.json` (optional, external writer)
