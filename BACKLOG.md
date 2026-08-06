# VIGIL Backlog

## Wave-2 collectors (post-v0.1; from Awesome-OSINT-List review 2026-08-02)

All free, all fit the existing collector interface; each is one module + one
fixture + one registry row:

1. **abuse.ch FeodoTracker** — botnet C2 IP blocklist (JSON). Covered by the
   same ABUSECH_AUTH_KEY; fills the C2-infrastructure gap in iocs.json.
2. **C2IntelFeeds** (github.com/drb-ra/C2IntelFeeds) — free CSV C2 feeds
   derived from Censys, raw-GitHub fetch, no key.
3. **PhishTank** — community phishing-URL feed (hourly JSON dump). Phishing
   is a coverage gap; verify current registration/key availability at build.
4. **APTnotes** (github.com/aptnotes/data) — APT report metadata (CSV/JSON).
   Not a feed; enrich actor profiles with "recent reporting" links.

## Phase B additions (fold into site build)

- **Type-aware pivot rows** on the verdict report: IP → AbuseIPDB, GreyNoise,
  Spamhaus; domain → Pulsedive, IBM X-Force Exchange; hash → MetaDefender;
  URL → PhishTank; all free lookup pages, links only, no APIs.
- **Email as a detected indicator type** — omnibox recognizes emails; no
  local corpus lookup, verdict renders as pivot-only (HIBP, Hudson Rock
  infostealer check). MSSP-daily-useful, zero backend.
- **Registry additions (reference kind):** APTnotes, ThreatMiner, Pulsedive,
  GreyNoise Visualizer.

## Positioning note

The heavyweight OSS CTI platforms (OpenCTI, MISP, IntelOwl, YETI) all require
servers + databases. VIGIL's niche is deliberately beneath them: zero-infra,
public URL, analyst-speed. Keep that line in the README when publicizing.
