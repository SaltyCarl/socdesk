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

## knock-knock.net review (3-agent team, 2026-08-06)

**Data: DO NOT COLLECT.** No data licence exists (`/terms`,`/license`,`/legal`
all 404; repo MIT covers *code* only; GeoIP fields inherit MaxMind's EULA).
Silence ≠ permission — same rule that removed abuse.ch. Value is also low:
one hobbyist sensor fleet = internet background radiation, the population
GreyNoise exists to *deprioritise*; binary listed/not-listed over 365d on
recycling cloud IPs would mislead as a verdict. Free API caps at 500/day and
there is no human per-IP page.
→ **Ship at most a deep link** `https://api.knock-knock.net/ip/<IPv4>`
(labelled "raw JSON"). Optional: email David Kurlander for an explicit
CC0/CC-BY data licence; only then reconsider.

**Design: adopt 4, reinvent 1, reject the rest** (see also design-system v4.1):
- ADOPT **per-item context/trivia** — static JSON keyed to CVE/actor/TTP so
  every feed row teaches something. Highest ROI; it is VIGIL's editorial
  voice and what makes a *static* site worth reading.
- ADOPT **seconds-since-ingest counter** (`LAST INGEST +00:14:32`, Plex Mono,
  ticking) + **next-pull countdown** — liveness that measures our own clock,
  never faked real-time.
- ADOPT **multi-cue event sync** (2–3 cues only: row insert + count-up +
  vermilion rule that draws and retracts) and **raw-JSON receipts** on
  right-click (prints as a bordered slip).
- ADAPT **deltas as headlines** (`1,284 ▲ +37 since 14:00`) and
  **time-staggered reveal** replaying the real 30-min window on load.
- REINVENT **geography as print cartography**, never a globe: flat Equal
  Earth SVG, ink-on-bone, coastline hairlines, density as *engraved
  crosshatching* (hatch frequency = log volume — a real 19th-c. atlas
  technique), one vermilion stamp on the top origin. More distinctive than a
  globe precisely because nobody does it.
- REJECT: 3D neon globe, event sounds, style toggles, jokes panel.

**Own-honeypot idea: LIGHTER VERSION, later (not v1).**
Verdict: one **Cowrie** sensor (SSH/Telnet, ~100MB RAM, narratively rich
logs) on **Oracle Cloud Always Free** — never from home (residential AUPs
prohibit it; home IP becomes public and correlated; compromised sensor sits
inside the LAN). Tunnels don't work: scanners hit IPs, Cloudflare Tunnel
publishes hostnames. T-Pot rejected (8-16GB + ELK to babysit). Non-negotiable
safety: separate tenancy/identity, **egress default-DENY** (the AUP insurance
policy — receiving attacks is fine, being used to launch them is not),
unprivileged container, admin SSH restricted to Tailscale, honeypot holds no
tokens/keys, monthly rebuild from snapshot, no UDP. Pipeline: Cowrie JSON →
nightly local aggregate → Framework pulls over Tailscale → Framework commits
rolled-up JSON → Pages rebuild. **Publish aggregates only, 24h delayed**;
sanitise sensor IP/hostname/host key, third-party data attackers paste, no
malware binaries (hashes + defanged URLs only). Attacker source IPs are fine.
Cost: ~4–6h build, ~1h/month; Oracle reclaims idle instances, so design for
"sensor offline". Portfolio value: high (the *pipeline and safety
engineering* is the story). Daily-triage value: none (n=1 never intersects
client incidents). **Caveat: original attack data arguably strengthens the
R2 "relates to employer's business" reading — read the IP clause first.**

## Compliance gates (see COMPLIANCE.md — 2026-08-06 skeptical SME review)

Launch is GATED. Must-fix before public deploy: cut Ransomware.live victim
names (R3), resolve abuse.ch redistribution in writing or link-out (R4),
per-verdict disclaimer + noindex (R5), remove case-note templates from repo
(R6). Must-fix before any team use: written employer approval + CUI-scope
exclusion (R1/R2/R7). Shared-team-state idea is now explicitly parked as
public — auth-gated separate deploy only.

## Positioning note

The heavyweight OSS CTI platforms (OpenCTI, MISP, IntelOwl, YETI) all require
servers + databases. VIGIL's niche is deliberately beneath them: zero-infra,
public URL, analyst-speed. Keep that line in the README when publicizing.
