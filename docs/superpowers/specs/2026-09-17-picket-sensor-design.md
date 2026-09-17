# SOCDESK · PICKET — first-party honeypot sensor + "Knock → Block" intelligence layer (design spec)

**Date:** 2026-09-17 · **Status:** design, approved in-session (approaches + sectioned design), pre-implementation · **Author identity:** SaltyCarl (AI-assisted, per the relaxed 2026-08-25 attribution posture in CLAUDE.md).
**Predecessors / precedents this rides on:** collector contract (`collectors/base.py`), the Framework's out-of-repo push precedent (`.github/workflows/collect-and-deploy.yml:7-9,69-71`), the community-reports read path (`lib/enrich.mjs:570-604`, `functions/api/enrich.js:31-40`, `pipeline/community.py`), the ISP abuse leaderboard (`pipeline/asn.py`, spec `2026-08-24-asn-abuse-leaderboard-design.md`), the `/admin` moderation console (`functions/api/admin/moderate.js`, `migrations/0001_init.sql`), the hunt-playbook KQL validation lane (`tools/validate_hunt_kql.py`, Kustainer), the ambient globe layer (`web/src/components/hero/heroLayers.ts:26-49,118-134`).
**Inspiration / quality bar (owner-set):** knock-knock — https://knock-knock.net · https://github.com/djkurlander/knock-knock (MIT, Python/FastAPI/SQLite/Redis, 13 protocol emulators, GeoIP, hourly public blocklist). Owner brief: *"at least this level of quality and novelty … some wow factor … an export for Sentinel or Defender in the form of watchlists or whatever format would be most accessible to importing to block."*
**Compliance:** R2 (employer IP) is RESOLVED (`COMPLIANCE.md`, dated re-rating 2026-09-17). This spec introduces no re-litigation of it.

---

## 0. SCOPE BOUNDARY (anti-drift — strict)

**Goal (one sentence).** Stand up a first-party, internet-facing honeypot sensor whose telemetry flows — bounded, sanitized, keyless — into SOCDesk as (a) a `SOCDESK · PICKET` surface, (b) fusion into the analyst loop (escalation-card context row, ISP leaderboard, globe), (c) a **"Knock → Block" export pack** ready to import into Defender for Endpoint, Microsoft Sentinel, and Entra Password Protection, and (d) an **owner-moderated** upstream give-back to AbuseIPDB — all framed as *what bots try against an unsolicited sensor: context, never a verdict on any network or operator.*

**Owner decisions locked in-session (do not re-ask):**
1. **Hosting:** a cheap, isolated VPS (Hetzner CX or Oracle Always-Free ARM). Not the Framework.
2. **Upstream posture:** **owner-moderated queue** — the sensor proposes, the owner approves in `/admin` before anything is reported. Never automatic.
3. **v1 surfaces:** escalation-card context row + ISP-leaderboard third source + ambient globe layer + a dedicated PICKET panel/route — **all four**.
4. **Approach:** **A** — knock-knock is the sensor engine (reused, MIT); SOCDesk builds the intelligence layer knock-knock structurally lacks.

**In scope (phased — §9).**
- **Tier S — sensor box:** knock-knock via Docker (host networking) on the VPS; hardening posture (§3.1); MaxMind GeoLite2 (free) on-box.
- **Tier X — exporter:** `tools/picket/exporter.py` (versioned in THIS repo, deployed to the box) + a systemd timer; produces a bounded, PII-fenced `export.json` validated against `schemas/picket_export.schema.json`; pushes it to a **separate public, data-only repo** (§3.2).
- **Tier P — pipeline:** `collectors/picket.py` (keyless raw fetch, `clean_text` on every string, bounds), `pipeline/picket.py` (publishes `picket.json`, `picket_lookup.json`, `picket_ips.json`, the export pack, the report-candidate list; folds `"picket"` into `pipeline/asn.py` `SOURCES`), three new JSON schemas, `SCHEMA_FOR` registration, health row.
- **Tier W — web:** `/desk#picket` tab + landing-board teaser; `SOCDESK_PICKET` enrich source (`kind:"context"`); `picket` globe layer; the four export cards with per-product import steps; `/about#picket` transparency section.
- **Tier G — give-back:** D1 migration `0002_picket.sql`; owner-gated Functions `GET/POST /api/admin/picket`; `/admin` Picket tab; AbuseIPDB report POST on approve.
- **Tests:** pytest (collector, pipeline, byte-exact export fixtures, asn fold), schema gate, Kustainer lane for the watchlist KQL pack, vitest (web models + views where the node harness allows), lib tests (`SOCDESK_PICKET` row, D1 helpers), migration test.

**Explicitly OUT of scope (a fence, not a suggestion).**
- **Writing our own protocol emulators.** The sensor is knock-knock; we do not fork or re-implement its honeypots. Extending knock-knock with a new protocol module is a possible *later* contribution upstream, not this spec.
- **Exposing knock-knock's dashboard publicly** (approach C, declined). The box publishes honeypot ports only.
- **Automatic upstream reporting** of any kind (owner decision 2). No "auto with guards."
- **Publishing username:password pairs, per-knock logs, or any per-IP credential attribution.** Aggregates only (§3.6).
- **A live/WebSocket feed inside SOCDesk.** SOCDesk stays on the 30-minute pipeline cadence by architecture (static core, `INFRASTRUCTURE-OPTIONS.md` §5 discipline). "Live" novelty is delivered by the intelligence layer, not by streaming.
- **STIX 2.1 / Sentinel STIX-objects API export** — Phase 4 (§9). The legacy upload API is deprecated-preview and app-registration-gated (Sentinel Contributor), i.e. the *least* accessible path; deferred.
- **Trends over time for PICKET** (week-over-week movement) — Phase 4.
- **Any new GitHub Actions secret, any new Pages binding on the read path, any per-lookup network call for PICKET data.** The read path consults committed static assets only (Option-A invariant, unchanged).
- **Any change to the verdict tally/band.** `SOCDESK_PICKET` is `kind:"context"` — it never votes.
- **The Framework.** Not involved anywhere in this spec.

---

## 1. Doctrine / invariants (binding)

1. **Additive and independently degradable** (`INFRASTRUCTURE-OPTIONS.md` §5). A dead sensor, a vandalized export repo, a failed schema gate, or a missing `picket*.json` must leave every other surface exactly as it is today. Last-known-good on gate failure (`pipeline/validate.py`); "sensor silent" is rendered honestly, never as "0 attacks."
2. **Never trust upstream text — and the sensor is the most attacker-influenced upstream we will ever have.** Every string (usernames, passwords, ISP names, country names) passes `collectors/base.py:clean_text` at collection AND is escaped again at render. Bounds (`maxLength`/`maxItems`/`additionalProperties:false`) on every schema. `safe_url` for any URL. This is the exact case `clean_text`'s docstring was written for.
3. **Aggregator, not mirror** (`COMPLIANCE.md`). We publish *our own* first-party telemetry (redistributable by construction) and only *check membership* against abuse.ch / community data — we never redistribute theirs. MaxMind GeoLite2 requires its attribution line; knock-knock (MIT) is credited in Sources/README.
4. **Context, never a verdict.** Every PICKET surface carries the ASN-leaderboard framing: *reported/observed abuse volume against an unsolicited sensor — not a verdict on the network or its operator.* No red/amber/green anywhere in PICKET; periwinkle volume measures only (colour law, CLAUDE.md).
5. **Keyless pipeline; no new CI secret.** The collector fetches a public raw URL. The exporter's write credential lives on the box and is scoped to a data-only repo that is *not* this one (§3.2).
6. **No-PII, enforced twice, structurally** (§3.6): on-box (exporter filters + knock-knock self-redaction) and in-pipeline (collector filters + schema `additionalProperties:false` + no pair fields exist to leak).
7. **Owner-moderated writes.** The only third-party write (AbuseIPDB report) requires an owner session (`requireSession` + `isOwner`, `moderate.js` precedent) per IP, and persists only on upstream success (§3.9).
8. **Honesty in the "wow."** Lead-time claims are made against "the feeds SOCDesk holds," with the C2-feed caveat stated in the UI (§3.7). Export files carry the caveat and generation time in-band.

---

## 2. Architecture at a glance

```
Internet bots
   │  SSH/Telnet/FTP/RDP/SMB/SIP/HTTP/SMTP (+ optional MQTT/Node-RED/Modbus/S7/SNMP)
   ▼
┌─ Tier S · VPS (isolated) ─────────────────────────────────────────────┐
│ knock-knock (Docker, host net)  → SQLite rollups (ip_intel, *_proto, │
│   user_intel, pass_intel, isp_intel, country_intel, heartbeats)      │
│ tools/picket/exporter.py (systemd timer, :05/:35)                    │
│   reads rollups + GeoLite2-Country → delta ring (state.json, 7d)     │
│   → export.json (schema-validated, PII-fenced, ≤ 512 KB)             │
│   → git push → SaltyCarl/socdesk-picket-export (public, data-only)   │
└──────────────────────────────────────────────────────────────────────┘
   │  raw.githubusercontent.com (keyless GET, ≤ 2 MB cap)
   ▼
┌─ Tier P · GitHub Actions pipeline (cron :11/:41) ─────────────────────┐
│ collectors/picket.py  → clean_text + bounds → CollectorResult.extra  │
│ pipeline/picket.py    → picket.json · picket_lookup.json ·           │
│                         picket_ips.json · exports/* (CSV/TXT) ·      │
│                         report_candidates (dedupe vs D1 decisions)   │
│ pipeline/asn.py       → SOURCES += "picket" (third source)           │
│ validate.py gate      → last-known-good on any failure               │
└──────────────────────────────────────────────────────────────────────┘
   │  data/state/ + web/public/data/state/ (dual-write, unchanged)
   ▼
┌─ Tier W · web/ (static) ──────┐  ┌─ /api/enrich (Pages Function) ────┐
│ /desk#picket tab              │  │ loadPicket() ← picket_lookup.json │
│ landing teaser · globe layer  │  │ SOCDESK_PICKET  kind:"context"    │
│ export cards (import steps)   │  │ (clone of SOCDESK_COMMUNITY)      │
│ /about#picket                 │  └───────────────────────────────────┘
└───────────────────────────────┘
┌─ Tier G · owner-moderated give-back ───────────────────────────────────┐
│ /admin Picket tab ← picket.json.report_candidates + GET /api/admin/   │
│ picket (D1 decisions) → POST /api/admin/picket {ip, action}           │
│   approve → AbuseIPDB /api/v2/report (existing key) → D1 row on 200   │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Key design decisions (each with a recommendation)

### 3.1 Sensor box posture — **RECOMMEND: minimal, disposable, honeypot-ports-only**
- **Host:** Hetzner CX (≈€4/mo) or Oracle Always-Free ARM ($0). Debian/Ubuntu LTS. Nothing else runs on it. Treat as disposable: compromise ⇒ nuke and rebuild from `tools/picket/README.md`.
- **Real `sshd`** moved to a high port, key-only, `AllowUsers` one admin, source allow-list (Tailscale or a fixed IP) via ufw. Do this **before** knock-knock binds :22 (its INSTALL.md warns you lock yourself out otherwise).
- **Firewall:** allow only enabled honeypot ports + the admin SSH port. `WEB_PORT` (default 8080) bound to `127.0.0.1` — **never public** (owner decision: approach C declined). Owner views the live knock-knock dashboard over an SSH tunnel if ever wanted.
- **knock-knock `.env`:** `ENABLED_PROTOCOLS` = the core eight (SSH, TELNET, FTP, RDP, SMB, SIP, HTTP, SMTP) in P1; optional IoT/OT set (MQTT, NRED, MODB, S7, SNMP) is a later owner toggle. `SAVE_KNOCKS` **off** (rollups only — no per-knock store on an internet-facing box; §3.3 gets time series another way). `MAX_KNOCKS`/`BAN_DURATION` defaults. `SOURCE_ID=picket-1`. Self-redaction stays on (it is default behaviour, not a toggle).
- **Updates:** `unattended-upgrades`; knock-knock pinned to a tag, bumped deliberately.
- **Cost of this decision:** none of knock-knock's live dashboard/blocklist pages are public; we re-create the public value inside SOCDesk (the whole point).

### 3.2 Getting telemetry into the pipeline — **RECOMMEND: exporter pushes to a separate public data-only repo; collector fetches it keyless**
Options considered:
- (a) **Write deploy key to this repo + `paths:` retrigger** (the Framework/`brief.json` precedent). Rejected: a deploy key with write access can push *anything*; a compromised internet-facing honeypot must not hold a credential to the product repo. The Framework is a trusted home machine — a different risk class.
- (b) **Box exposes an HTTPS JSON endpoint + a bearer token in CI.** Rejected: a new CI secret (architectural decision per CLAUDE.md) and a public web listener on the honeypot box.
- (c) **Box pushes `export.json` to `SaltyCarl/socdesk-picket-export` (public, data-only); `collectors/picket.py` GETs the raw URL.** **Chosen.** Blast radius of a box compromise = vandalizing a data repo, which the collector's `clean_text` + bounds + schema gate + last-known-good already contain. No CI secret. Keyless collector (CLAUDE.md rule). The export repo has a README stating what it is and that it is machine-written.
- **Cadence:** systemd timer at **:05 and :35**, six minutes ahead of the pipeline cron (`:11/:41`), so each run sees a fresh export. Push only when content changed (idempotent commits; `git commit` no-ops otherwise).
- **Size:** exporter refuses to write an export > 512 KB (schema bounds make this structurally unreachable; belt and braces). Collector caps the fetch at 2 MB and treats a larger body as a failed collection.

### 3.3 Time series without per-knock storage — **RECOMMEND: an on-box delta ring (`state.json`)**
knock-knock's rollups are cumulative all-time counters (`hits`, `first_seen`, `last_seen`) with no per-period buckets, and we keep `SAVE_KNOCKS` off. The exporter therefore keeps its own small state:
- Every run (30 min) it snapshots `SUM(hits)` overall and per protocol, plus per-IP / per-username / per-password / per-country / per-ISP `hits`, and stores **deltas** into a **336-bucket ring** (7 days × 30 min). `state.json` (on-box only, never pushed) holds the ring + the previous snapshot.
- From the ring: `histogram_7d` (published as **168 hourly** sums), `knocks_24h`, `knocks_7d`, per-entity **7-day hits** (sum of that entity's deltas), `unique_ips_7d` (IPs with any positive delta in the window). All-time totals are published separately (`knocks_total`, `since`).
- Restart/reset safety: if a counter goes *down* (knock-knock DB reset/prune), the delta is clamped to 0 and a `ring_reset_at` marker is emitted; the pipeline surfaces "counters reset on <date>" rather than a bogus spike.
- **Alternative rejected:** `SAVE_KNOCKS=true` + on-box pruning — more attacker-influenced data at rest on the exposed box for no additional published value.

### 3.4 Per-IP enrichment on-box — **RECOMMEND: join rollups + GeoLite2-Country lookup in the exporter**
`ip_intel` gives `ip, hits, first_seen, last_seen, lat, lng, asn`; `ip_intel_proto` gives per-protocol hits; `isp_intel` gives `isp` by `asn`. **Country per IP is not in `ip_intel`** — the exporter resolves it from the on-box GeoLite2-Country database (the same MaxMind data knock-knock already uses; `geoip2` reader; no extra account). Protocol ids map to names via knock-knock's registry (`protocols/registry.py` / `PROTOCOL_META`); the exporter asserts the map at startup and fails loudly on an unknown id rather than guessing. `geo_precision` is `"city"` when lat/lng came from the city DB, else `"country"` — carried through to the globe layer honestly (the `ThreatIp` type already has this field).

### 3.5 The published payloads (pipeline outputs)
- **`picket.json`** — the panel payload (§4.2). Bounded top-N lists, histogram, protocol share, lead-time block, give-back block, export manifest, sensor status.
- **`picket_lookup.json`** — `indicators` map keyed exactly like `communityKey` (`"ipv4|<ip>"` / `"ipv6|<ip>"`, `pipeline/community.py:community_key` ↔ `lib/enrich.mjs:communityKey`, parity-tested) → `{hits_7d, hits_total, protocols[], first_seen, last_seen, country, asn, reported_upstream}`. ≤ 5,000 entries. This is what `/api/enrich` loads (§3.8).
- **`picket_ips.json`** — `ThreatIpsPayload` shape (`heroLayers.ts:44-49`) with `source: "picket"`, ≤ 1,000 rows, only rows with finite lat/lng. A **separate file** so `threat_ips.schema.json` is untouched.
- **`exports/`** — the Knock → Block pack (§3.10), listed in `picket.json.exports` with row counts and `generated_at` so the UI never links to a missing file.
- **`asn_leaderboard.json`** — unchanged shape; `pipeline/asn.py` gains `"picket"` in `SOURCES` (`asn.py:10`) and a third branch in `_distinct_abusive_ips` (`asn.py:55-70`) yielding `(ip, "picket", category, False)` where `category` is `"brute-force"` (or `"ssh"` when SSH-only) from the existing category enum. Built **after** picket (run_pipeline ordering, as it is already built after community + threat_ips, `run_pipeline.py:230-240`). This is also the most likely thing to lift the leaderboard past `hasRankableVolume()`'s 20-IP floor.
- **`health.json`** — a `picket` source row via the normal `run_all` health list (`base.py:78-96`).

### 3.6 Credential + identity PII fence — **HARD requirement, enforced twice**
Attackers replay credential-stuffing lists that can contain real people's emails and passwords. Rules (exporter AND collector each apply the full set; the schema forbids any field that could carry a pair):
1. **Aggregate only.** `top_usernames` / `top_passwords` are top-N by 7-day hits; **no `(username, password)` pair exists anywhere in any payload** — the schema has no such field. knock-knock's live feed shows pairs; we deliberately do not.
2. **Floor:** `hits_7d ≥ 3`. A singleton credential could be one real leaked credential replayed once.
3. **Drop** any value that: contains `@`; matches an email, phone, card-number, or SSN-like pattern; is longer than 32 chars; or is empty after `clean_text`.
4. **Sensor self-identifiers** (public IP, hostname, domain) are redacted on-box by knock-knock's `self_redaction` and additionally rejected by the collector (any row whose value contains the sensor's own IP — carried in the export as `sensor.public_ip_sha256`, never plaintext — is dropped).
5. **Attacker IPs are published.** They are the point of the dataset (as the ASN leaderboard already does for abuse.ch/community IPs) — a public IP that brute-forced an unsolicited sensor is a fact about a host, not personal data; framing per §1.4.
6. **Entra banned-password export** (§3.10) additionally filters to 4–16 chars and case-dedupes.

### 3.7 Lead-time intelligence — **RECOMMEND: keyless membership against the committed feeds, with the caveat in-band**
For each `top_ips` row: `known_to.abusech = ip ∈ threat_ips.json` (feodo/threatfox), `known_to.community = ip ∈ community_reports.json`; `lead_days` = `(feed.first_seen − picket.first_seen).days` when Picket saw it first, else omitted. Weekly aggregate `lead_time{sensor_first_7d, new_ips_7d, pct}` → *"X of Y new attacker IPs this week were unknown to the feeds SOCDesk holds when Picket first saw them."*
**Honesty caveat, rendered next to the stat and in the export README:** abuse.ch Feodo/ThreatFox are C2/botnet feeds, not brute-force feeds — most brute-forcers being "unknown to them" is expected. The stat is about *SOCDesk's held feeds*; at lookup time AbuseIPDB/GreyNoise speak for themselves on the card. **No enrich quota is spent** computing this (pipeline-side, committed data only).

### 3.8 The enrich context row — **RECOMMEND: `SOCDESK_PICKET`, a clone of `SOCDESK_COMMUNITY`**
- `lib/enrich.mjs`: new `SOCDESK_PICKET` in `SOURCES` (`:604`): `types: ["ipv4","ipv6"]`, `key: "SOCDESK_PICKET_DATA"`, `optionalKey: true`, `kind: "context"`, `link: "https://socdesk.io/about#picket"`, synchronous `run()` over the injected map; returns `undefined` when absent or no hit (never an error, never clutter). Headline: *"Seen by SOCDesk's own sensor · N attempts (7d) · <protocols> · last <date>"*; facts: Attempts (7d), Attempts (all-time), Protocols, First seen, Last seen, Source = *"SOCDesk Picket honeypot — context, not a verdict"*, plus `Reported upstream: yes/no`.
- `functions/api/enrich.js`: `loadPicket(env, origin)` mirrors `loadCommunity` (`:31-40`): `env.ASSETS.fetch("/data/state/picket_lookup.json")`, memoize **only successful** loads, inject into the derived env as `SOCDESK_PICKET_DATA`. **No D1, no new binding** (Option-A invariant).
- `shared/verdict/map.ts`: `kind:"context"` rows are already excluded from the tally — no change; verify with a lib test.

### 3.9 Owner-moderated give-back — **RECOMMEND: candidates in the payload, decisions in D1, one owner-gated endpoint pair**
- **Candidate rule (pipeline, `pipeline/picket.py`):** an IP is a `report_candidate` iff **all** hold: (a) `hits_7d ≥ 10` on **credential-bearing protocols** (SSH, Telnet, FTP, RDP, SMB; SMTP/HTTP only when knock-knock's module records an auth attempt — *build-time check:* confirm per module that a "knock" is an authentication attempt, not a bare TCP connect, and exclude any protocol where it isn't); (b) **not** in `data/picket/benign_scanners.json` (owner-curated, versioned allow-list of research-scanner ASNs/prefixes — Shodan, Censys, BinaryEdge, GreyNoise, Rapid7 Sonar, ShadowServer, Stretchoid, and the like; seeded in P3, reviewed like `data/entities/`); (c) **not** already on abuse.ch (`known_to.abusech`) — no value in reporting what is already blocklisted; (d) **no D1 decision in the last 30 days** (approve or reject). ≤ 100 candidates, ranked by `hits_7d`.
- **Dedupe source:** `pipeline/picket.py` reads decisions via the **existing read-only D1 REST path** (`CF_D1_READ_TOKEN` + `CLOUDFLARE_D1_DATABASE_ID`, exactly as `pipeline/community.py` does). If unavailable → no dedupe (candidates may reappear; `/admin` still shows "decided" from its own live read) — honest degradation, never a crash. Also yields `give_back{reported_30d}` (a count).
- **D1 migration `migrations/0002_picket.sql`:**
  ```sql
  CREATE TABLE picket_reports (
    ip                  TEXT    NOT NULL,
    decided_at          TEXT    NOT NULL,
    action              TEXT    NOT NULL,   -- 'approved' | 'rejected'
    protocols           TEXT,               -- comma-separated, from the candidate
    hits                INTEGER,
    abuseipdb_report_id TEXT,               -- set only on a 200 from AbuseIPDB
    PRIMARY KEY (ip, decided_at)
  );
  CREATE INDEX idx_picket_reports_ip ON picket_reports(ip, decided_at);
  ```
  No new binding (`DB` exists). No PII by construction (an IP, a timestamp, an action).
- **Functions (owner-gated, `requireSession` + `isOwner`, fail-closed like `moderate.js`):**
  - `GET /api/admin/picket?ips=a,b,c` → `{decisions: {ip: {action, decided_at, abuseipdb_report_id}}}` (≤ 100 ips).
  - `POST /api/admin/picket` `{ip, action: "approve"|"reject", protocols, hits}` → validates the IP is a public IPv4/IPv6 literal (never CIDR), that it appears in the current `picket_lookup.json` (prevents reporting arbitrary IPs through this endpoint), then: **reject** → insert row; **approve** → `POST https://api.abuseipdb.com/api/v2/report` (`Key: ABUSEIPDB_API_KEY`, form `ip`, `categories` from protocols — `18` Brute-Force always, plus `22` SSH / `15` Hacking / `21` Web App Attack / `11` Email Spam / `23` IoT Targeted as applicable — `comment` = *"SOCDesk Picket honeypot: <n> credential-submitting attempts over <protocols>, <first>→<last>. Unsolicited sensor; owner-reviewed."* (PII-free by construction, ≤ 1,024 chars)) → on **200** insert the row with `abuseipdb_report_id`; on any non-200 **persist nothing** and return 502 with AbuseIPDB's message so the owner can retry. *Build-time check:* AbuseIPDB permits one report per IP per account per 15 minutes and has a daily free-tier report quota — surface the quota headers in the 502 body.
  - **Flag (owner-acknowledged):** first *write* use of the existing `ABUSEIPDB_API_KEY`; reports appear under the owner's AbuseIPDB account.
- **`/admin` Picket tab** (`web/src/routes/Admin.tsx` + a `PicketQueue.tsx`): reads candidates from the static `picket.json`, joins decisions from `GET /api/admin/picket`, shows per-candidate provenance (hits, protocols, first/last, country/ASN, known_to), Approve / Reject with the same optimistic-then-confirm pattern as the report queue. Owner-only route as today.

### 3.10 The "Knock → Block" export pack — **RECOMMEND: four static files + import cards, byte-exact fixture-tested**
Generated every run by `pipeline/picket.py` into `data/state/picket/` (dual-written like every payload), each with an in-band header comment carrying attribution, `generated_at`, the honesty caveat, and the row count. All limits below were verified against Microsoft Learn on 2026-09-17.
1. **Defender for Endpoint indicators** — `picket-defender-indicators-<n>.csv`, chunked at **≤ 500 rows per file** (the import batch limit), **≤ 4 files** (cap 2,000 IPs = credential-submitting IPs active in the last 7 days, ranked by hits; a tenant spends ≤ 2,000 of its **15,000-indicator** limit). Exact import columns, in order: `indicatorType,indicatorValue,action,title,description,expirationTime,severity,recommendedActions,rbacGroups,category,mitretechniques,GenerateAlert`. Values: `IpAddress`; the IP (single external IPv4 dotted-quad or full 8-segment IPv6 — **no CIDR**, which is inherently what a honeypot yields); `Block` (network indicators do **not** accept `BlockAndRemediate`); title `SOCDesk Picket: brute-force source (<protocols>)`; description with hits/first/last/ASN/country + caveat; `expirationTime = last_seen + 30d` as `YYYY-MM-DDTHH:MM:SS.0Z`; `severity` `Medium` (< 100 hits/7d) or `High`; `recommendedActions` a one-liner; `rbacGroups` empty; `category` `CredentialAccess`; `mitretechniques` `T1110`; `GenerateAlert` `True`. The import card states the tenant prerequisites verbatim from Learn: *Custom network indicators* enabled, Network Protection in block mode, enforcement typically < 2 h (up to 48 h).
2. **Sentinel watchlist** — `picket-sentinel-watchlist.csv`, header `IPAddress,Hits7d,HitsTotal,Protocols,FirstSeen,LastSeen,Country,ASN,ISP,KnownToAbuseCh,LeadDays`; the card says *"SearchKey = IPAddress · alias `SOCDeskPicket`"* (alias 3–64 chars, alphanumeric ends — satisfied). ≤ 2,000 rows (far under the 3.8 MB local-upload limit). **Plus a KQL pack** (`picket-sentinel-hunts.kql`, also rendered as copyable steps): *"did any Picket attacker touch your tenant?"* — `SigninLogs | where IPAddress in ((_GetWatchlist('SOCDeskPicket') | project SearchKey))`, `DeviceNetworkEvents | where RemoteIP in (...)`, and (only where committed DDL exists — *build-time check*) `DeviceLogonEvents`, `CommonSecurityLog`. Validated in the existing Kustainer lane with a **stub `_GetWatchlist` function** bound in the emulator (Sentinel-only function) so the queries compile against real DDL.
3. **Entra Password Protection** — `picket-entra-banned-passwords.txt`: top passwords by 7-day hits filtered to **4–16 chars**, case-insensitively deduped, **≤ 1,000 lines**, one per line, paste-ready for the custom banned-password list (Entra ID P1; substitution-aware matching means `p@ssw0rd`-style variants are covered by the base term). Card copy is honest: *Microsoft's global list already covers many of these; this adds the sensor's current view* (Learn: the custom list "is not designed for blocking large lists").
4. **Plain blocklist** — `picket-blocklist.txt` (IP per line, same 2,000-IP set) + recipes (nftables/ipset/pfSense/CrowdSec) rendered in the panel — knock-knock parity.
- **Tests:** each generator has a **byte-exact fixture** (`tests/fixtures/picket/*.expected.*`) so a header drift or a quoting bug fails CI, plus property tests: no CIDR ever, no empty required MDE column, chunk ≤ 500, Entra 4–16 chars.
- **Phase 4 (out of scope here):** `picket-stix.json` (STIX 2.1 bundle, `[ipv4-addr:value = '…']`, `valid_until` = expiration) for the Sentinel STIX-objects API / any TIP.

### 3.11 The PICKET web surface — **RECOMMEND: a Desk tab + a landing teaser, in the periwinkle/warm register**
- **Route:** `/desk#picket` — new tab `{ key: 'picket', label: 'Picket' }` in `DataDeskRoute.tsx:36-40`; `PicketRoute.tsx` + `PicketView.tsx` mirroring `AsnLeaderboardRoute/View`. Brand: `SOCDESK · PICKET`, first-use subtitle *"telemetry from my own sensor"* (`design/brand.md:309-311`). No emoji, no jokes, no serifs.
- **Tab content:** sensor status strip (live/stale/silent, uptime, protocols enabled, last knock, export age); 7-day hourly histogram (Sparkline idiom, `overview/Sparkline.tsx`); protocol share bars (periwinkle volume, `barWidthClass`); top attackers table (rank + bar — volume here is thousands, so `hasRankableVolume`-style gating is not needed, but reuse the same "volume, not verdict" caption); usernames and passwords side-by-side (hits only, no pairs); countries; ISPs; the **lead-time stat with its caveat**; the four **export cards** with product-specific import steps; give-back status (*"N IPs reported upstream in 30 days — owner-moderated"*). Empty/silent states are explicit copy, never blank.
- **Landing teaser:** a `BoardPanel` like `NetworkAbuseLeaderboard.tsx` — knocks/24h, 7-day sparkline, top country, "sensor-first" %, `DeskLink tab="picket"`. Honest empty when the payload is absent or silent.
- **Globe:** `picket_ips.json` rendered as its own ambient layer beside the feodo/threatfox layer (`heroLayers.ts` builder is payload-generic); periwinkle, possibly a lighter tint to distinguish provenance — **never a verdict tone** (colour law). `geo_precision:"country"` rows are drawn at centroid like today's data.
- **`/about#picket`:** what the sensor is, that credentials are aggregated and fenced, that upstream reports are owner-moderated, the dispute contact (`abuse@socdesk.io`, removal-is-the-response), MaxMind + knock-knock attribution.

---

## 4. Schemas (all `additionalProperties:false`, every string bounded)

### 4.1 `schemas/picket_export.schema.json` — the RAW box→repo contract (validated on-box before push AND by the collector after fetch)
```json
{ "type":"object", "additionalProperties":false,
  "required":["schema_version","exported_at","sensor","totals","ring","top_ips","top_usernames","top_passwords","top_countries","top_isps","by_protocol"],
  "properties":{
    "schema_version":{"type":"integer"},
    "exported_at":{"type":"string","pattern":"^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$"},
    "sensor":{"type":"object","additionalProperties":false,
      "required":["id","public_ip_sha256","protocols","uptime_minutes","knockknock_version"],
      "properties":{"id":{"type":"string","maxLength":32},"public_ip_sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"},
        "country":{"type":"string","maxLength":2},"protocols":{"type":"array","maxItems":16,"items":{"type":"string","maxLength":8}},
        "uptime_minutes":{"type":"integer","minimum":0},"knockknock_version":{"type":"string","maxLength":32},
        "ring_reset_at":{"type":"string","maxLength":20}}},
    "totals":{"type":"object","additionalProperties":false,"required":["knocks_total","since"],
      "properties":{"knocks_total":{"type":"integer","minimum":0},"since":{"type":"string","maxLength":20}}},
    "ring":{"type":"object","additionalProperties":false,"required":["bucket_minutes","buckets"],
      "properties":{"bucket_minutes":{"const":30},"buckets":{"type":"array","minItems":336,"maxItems":336,"items":{"type":"integer","minimum":0}}}},
    "by_protocol":{"type":"array","maxItems":16,"items":{"type":"object","additionalProperties":false,
      "required":["proto","hits_7d","hits_total"],"properties":{"proto":{"type":"string","maxLength":8},"hits_7d":{"type":"integer","minimum":0},"hits_total":{"type":"integer","minimum":0}}}},
    "top_ips":{"type":"array","maxItems":2000,"items":{"type":"object","additionalProperties":false,
      "required":["ip","hits_7d","hits_total","first_seen","last_seen","protocols"],
      "properties":{"ip":{"type":"string","maxLength":45},"hits_7d":{"type":"integer","minimum":0},"hits_total":{"type":"integer","minimum":0},
        "first_seen":{"type":"string","maxLength":20},"last_seen":{"type":"string","maxLength":20},
        "protocols":{"type":"array","maxItems":16,"items":{"type":"object","additionalProperties":false,"required":["proto","hits_7d"],
          "properties":{"proto":{"type":"string","maxLength":8},"hits_7d":{"type":"integer","minimum":0}}}},
        "country":{"type":"string","maxLength":2},"asn":{"type":"integer","minimum":0},"isp":{"type":"string","maxLength":120},
        "lat":{"type":"number"},"lng":{"type":"number"},"geo_precision":{"enum":["city","country"]}}}},
    "top_usernames":{"$ref":"#/$defs/credlist"},
    "top_passwords":{"$ref":"#/$defs/credlist"},
    "top_countries":{"type":"array","maxItems":50,"items":{"type":"object","additionalProperties":false,"required":["iso","hits_7d"],
      "properties":{"iso":{"type":"string","maxLength":2},"name":{"type":"string","maxLength":64},"hits_7d":{"type":"integer","minimum":0},"hits_total":{"type":"integer","minimum":0}}}},
    "top_isps":{"type":"array","maxItems":50,"items":{"type":"object","additionalProperties":false,"required":["isp","hits_7d"],
      "properties":{"isp":{"type":"string","maxLength":120},"asn":{"type":"integer","minimum":0},"hits_7d":{"type":"integer","minimum":0},"hits_total":{"type":"integer","minimum":0}}}}
  },
  "$defs":{"credlist":{"type":"array","maxItems":50,"items":{"type":"object","additionalProperties":false,"required":["value","hits_7d"],
    "properties":{"value":{"type":"string","minLength":1,"maxLength":32},"hits_7d":{"type":"integer","minimum":3},"hits_total":{"type":"integer","minimum":0}}}}}
}
```
Note the **absence** of any field that could hold a username+password pair, per-knock rows, or the sensor's plaintext IP. `hits_7d` minimum 3 on credentials encodes the floor structurally.

### 4.2 `schemas/picket.schema.json` — the published panel payload
Envelope (`generated_at`, `schema_version`, `attribution` ≤ 1,000 incl. the MaxMind line), `sensor{id,country,uptime_days,protocols,status:"live"|"stale"|"silent",export_age_minutes,ring_reset_at?}`, `totals{knocks_total,since,knocks_24h,knocks_7d,unique_ips_7d}`, `histogram_7d[168]`, `by_protocol[≤16]{proto,hits_7d,share_pct}`, `top_ips[≤100]{…as export + known_to{abusech,community}, lead_days?, reported_upstream}`, `top_usernames/top_passwords[≤50]`, `top_countries/top_isps[≤50]`, `lead_time{sensor_first_7d,new_ips_7d,pct,caveat}`, `report_candidates[≤100]{ip,hits_7d,protocols,first_seen,last_seen,country,asn,reason}`, `give_back{reported_30d,moderated:true}`, `exports{defender:[{path,rows}]≤4, sentinel_watchlist{path,rows}, sentinel_hunts{path}, entra_banned{path,rows}, blocklist{path,rows}, generated_at}`.

### 4.3 `schemas/picket_lookup.schema.json`
`{generated_at, schema_version, attribution, count, indicators: {maxProperties:5000, additionalProperties:{type,value,hits_7d,hits_total,protocols[≤16],first_seen,last_seen,country?,asn?,reported_upstream}}}` — keys `"ipv4|<ip>"` / `"ipv6|<ip>"`.

### 4.4 `picket_ips.json`
Validated against `threat_ips.schema.json`'s row shape via a **new** `picket_ips.schema.json` (copy of the row schema with `source: {const:"picket"}`, ≤ 1,000 rows) — kept separate so the existing threat-IPs schema is not loosened.

All four registered in `pipeline/validate.py:SCHEMA_FOR`; the gate falls back to last-known-good per file, as today.

---

## 5. Failure modes / honest degradation

| Failure | Behaviour |
|---|---|
| Box down / export repo unreachable / fetch > 2 MB | Collector `ok:false`; pipeline keeps last-known-good `picket*.json`, re-stamps `generated_at`; `sensor.status` computed from `exported_at` age → `stale` (90 min–24 h) / `silent` (> 24 h); panel + teaser render the state in words. health.json shows the error. Everything else unaffected. |
| Export fails its own schema on-box | Exporter does **not** push; previous export stands; a local log line. |
| Export passes on-box but fails the collector's re-validation / bounds | Treated as a failed collection (above). Vandalism containment. |
| knock-knock DB reset | Deltas clamp to 0; `ring_reset_at` set; panel notes "counters reset <date>". |
| `picket_lookup.json` missing in the Function | `loadPicket` returns null (not memoized); `SOCDESK_PICKET` omits itself; the card is byte-identical to today. |
| D1 read-only path unavailable in CI | Candidates published without the 30-day dedupe; `/admin` still shows decisions from its own read. |
| AbuseIPDB non-200 on approve | Nothing persisted; 502 with the upstream message + quota headers; owner retries. |
| MaxMind DB missing on-box | Per-IP `country` omitted (optional field); country/lat/lng from knock-knock's own GeoIP still present. |

---

## 6. Testing

- **`tests/test_picket_collector.py`** — hostile fixtures (`<img src=x onerror=…>` usernames, entity-encoded markup, unterminated tags, emails, phone/card-like passwords, 33+ char values, the sensor's own IP smuggled into an ISP name); asserts every string is inert, every fenced value dropped, bounds enforced, oversize body rejected, `ok:false` on network failure without raising.
- **`tests/test_picket_pipeline.py`** — ring→histogram/24h/7d math (incl. reset clamp); `known_to`/`lead_days`; candidate rule (each clause independently flips inclusion; benign-scanner allow-list; 30-day D1 dedupe with and without D1); `picket_lookup` key parity with `communityKey` (extend `key_parity.json`); `picket_ips` only finite coords.
- **`tests/test_picket_exports.py`** — **byte-exact** expected files for the MDE CSV (header, quoting, chunking at 500, expiration format, `Block` never `BlockAndRemediate`, no CIDR), Sentinel watchlist CSV, Entra list (4–16 chars, ≤ 1,000, case-dedupe), blocklist; property tests over random inputs.
- **`tests/test_asn_leaderboard.py`** — extend: `"picket"` source folds, categories map, mixed-source network sums.
- **Schema gate** — fixtures for all four new schemas; a deliberately-broken export fails the gate and last-known-good survives.
- **Kustainer lane** (`tools/validate_hunt_kql.py`) — the watchlist KQL pack compiles with the stub `_GetWatchlist`; a negative control (misspelled column) fails the lane.
- **`lib/__tests__/enrich.test.mjs` / `community.test.mjs` pattern** — `SOCDESK_PICKET` row present on a hit, omitted on miss/absent dataset, never in the tally; `loadPicket` memoizes success only.
- **`lib/reporting/__tests__/`** — `picket` endpoint validation (IP literal, must exist in lookup, owner gate fail-closed), persist-only-on-200 (mocked AbuseIPDB 200/429/500).
- **Migration test** — `0002_picket.sql` applies on a fresh D1 (existing migration harness).
- **vitest** — `PicketView` model helpers (status thresholds, share %, export manifest → cards), teaser empty/silent states via `renderToStaticMarkup` (the harness the repo has).
- **Live dogfood (the real gate):** box up → :22 sees knocks within minutes → first export → pipeline → tab, teaser, globe pins, enrich row on a Picket IP, leaderboard fold; import the MDE CSV into a test tenant's Indicators page and the watchlist CSV into a Sentinel workspace (owner has both); approve one candidate → AbuseIPDB shows the report → D1 row → panel says "reported."

---

## 7. Acceptance criteria

1. `SAVE_KNOCKS` off, dashboard port not public, only honeypot ports + admin SSH exposed (nmap from outside proves it).
2. An export lands in `socdesk-picket-export` every 30 min; a deliberately malformed export is refused on-box; a hand-vandalized export in the repo is refused by the collector and the site is unchanged.
3. `/desk#picket` renders all §3.11 blocks with live data; every string on it survived `clean_text`; zero red/amber/green.
4. An IP that hit the sensor shows a `SOCDesk Picket` context row on `/lookup` that does not change the tally; an IP that didn't shows nothing extra.
5. `asn_leaderboard.json` lists `picket` in `sources` for at least one network.
6. The four export files download from the panel; the MDE CSV imports without error into Defender (≤ 500 rows/file), the watchlist CSV creates `SOCDeskPicket` in Sentinel and `_GetWatchlist('SOCDeskPicket') | take 10` returns rows, the Entra file pastes into the custom banned list.
7. Approving a candidate in `/admin` produces an AbuseIPDB report id persisted in D1; rejecting persists a rejection; neither IP is re-proposed for 30 days; an AbuseIPDB failure persists nothing.
8. Kill the exporter timer: within 90 minutes the panel says "stale," after 24 h "silent"; nothing else on the site changes.
9. All pytest/vitest/lib suites and the Kustainer lane green; schema gate fixtures pass; `npm run build` clean.

---

## 8. Anti-drift guardrails (for the implementer)

- If a task wants to fork/patch knock-knock's honeypots, **STOP** — out of scope (§0).
- If a task wants to put a write credential for THIS repo on the box, **STOP** — §3.2 decided against it.
- If a task wants to publish any username:password pair, per-knock row, or singleton credential, **STOP** — §3.6.
- If a task wants to auto-report to AbuseIPDB (or anywhere) without an owner session per IP, **STOP** — owner decision 2.
- If a task adds a Pages binding or a per-lookup fetch to the read path for PICKET, **STOP** — Option-A invariant.
- If a task adds a colour that implies a verdict to any PICKET element, **STOP** — colour law.
- If a task wants to loosen a schema to make a live export pass, **STOP** — fix the exporter; the gate falling back is the system working.
- If a task starts STIX or trends-over-time, **STOP** — Phase 4.
- If a task re-opens R2, **STOP** — resolved.

---

## 9. Phasing and owner one-time setup

**P1 — collect-only (foundation).** VPS + hardening (§3.1); knock-knock; `tools/picket/exporter.py` + timer + on-box schema check; export repo; `collectors/picket.py`; `pipeline/picket.py` producing `picket.json` (+ `picket_ips.json`); schemas + gate; `/desk#picket` tab + landing teaser; `/about#picket`; tests. **Exit:** acceptance 1–3, 8, 9.
**P2 — fusion + exports.** `picket_lookup.json` + `SOCDESK_PICKET` + `loadPicket`; `asn.py` third source; globe layer; lead-time block; the Knock → Block pack + import cards + Kustainer-validated KQL. **Exit:** 4, 5, 6.
**P3 — moderated give-back.** `0002_picket.sql`; `GET/POST /api/admin/picket`; `/admin` Picket tab; `benign_scanners.json` seed; candidate dedupe via D1 read path. **Exit:** 7.
**P4 (separate spec later).** STIX 2.1 bundle; week-over-week trends; optional IoT/OT protocol set; a knock-knock protocol contribution upstream.

**Owner one-time setup (documented in `docs/OPERATIONS.md` as a new section; nothing here is a repository secret):**
1. VPS account + one small instance (or Oracle Always-Free ARM); DNS not required.
2. Free MaxMind GeoLite2 account → `MAXMIND_ACCOUNT_ID` / `MAXMIND_LICENSE_KEY` in the box's `.env` only.
3. Create the public repo `SaltyCarl/socdesk-picket-export`; add the box's SSH key as a **deploy key with write access to that repo only**.
4. Move real `sshd` to a high port, then run `tools/picket/README.md` (install script: ufw, Docker, knock-knock pinned tag, exporter + timer).
5. **P3:** apply `migrations/0002_picket.sql` (`wrangler d1 migrations apply socdesk_reports --remote`, as for `0001`). Confirm `ABUSEIPDB_API_KEY` is set in the Pages **Production** scope (it already is for lookups). Curate `data/picket/benign_scanners.json`.
6. Dogfood checklist (§6, last bullet) before announcing the surface.

**Costs:** ≈€4/mo or $0; no new SaaS; no new CI secret; one new D1 table on the existing binding.

---

## 10. Documentation deliverables (owner requirement — binding)

Owner, 2026-09-17, on approving this spec: *"this design will need to be extensively documented for review and reference."* Documentation is therefore a **phase exit criterion**, shipped in the same commit series as the code it describes. A phase is not done until every item below that it touches exists and is current.

| Document | Purpose / audience | Owned by phase |
|---|---|---|
| **`docs/PICKET.md`** (new) | **The reference.** Architecture (the §2 diagram, kept current), every payload and schema explained field-by-field with example rows, the PII-fence rules and their rationale, the delta-ring method, the lead-time methodology **and its caveat**, the candidate rule, the export-pack formats with each Microsoft limit and its Learn citation, the freshness state machine, the failure-mode table, the threat model of the box. Written for a reviewer who has not read this spec. | P1 (created), P2/P3 (extended) |
| **`tools/picket/README.md`** (new) | **The box runbook.** Provision → harden (exact `sshd`/ufw steps, in order — the lock-out warning first) → install knock-knock (pinned tag, `.env` template) → install exporter + timer → verify (external `nmap`, first export, deploy-key push) → **rebuild-from-scratch** → **incident response** (compromise: destroy the box, rotate the export-repo deploy key, review the export repo history). | P1 |
| **`docs/OPERATIONS.md`** | New section *"Owner one-time setup — PICKET"* (§9 steps) + the dogfood acceptance checklist, mirroring the B2 section's style. | P1, P3 |
| **`docs/DATA-SOURCES.md`** | A `picket` entry: what it is, first-party redistribution posture, knock-knock MIT + MaxMind GeoLite2 attribution lines. | P1 |
| **`docs/REPO-MAP.md`** | Every new module, route, component, schema, migration, Function (CLAUDE.md requires this on any structural change). | each phase |
| **`docs/ANALYST-GUIDE.md`** | How to read the PICKET tab; what the `SOCDesk Picket` context row means and does not mean; **how to import each export** (per-product steps + the tenant prerequisites quoted from Learn). | P1, P2 |
| **`README.md`** | Documentation-table rows for `PICKET.md` and the runbook; a feature blurb in the product register. | P1 |
| **`web/src/routes/About.tsx` `#picket`** | Public transparency: what the sensor is, that credentials are aggregated and fenced, that upstream reports are owner-moderated, dispute contact, attributions. | P1 |
| **`COMPLIANCE.md`** | A dated PICKET entry: first-party telemetry posture, why attacker IPs are published, the credential fence, moderated give-back, attribution obligations. | P1, P3 |
| **`schemas/*.schema.json`** | Each new schema carries a `description` on every property (the schema *is* documentation). | P1, P2 |
| **Module docstrings** | Every new module states the invariant it enforces (house style — see `pipeline/community.py`, `collectors/base.py`). | each phase |
| **`BACKLOG.md` + `docs/HANDOFF.md`** | Status at each phase close-out (existing convention); the dated §0 HANDOFF block names what shipped, what was verified, and what the next phase needs. | each phase |
| **Plan review record** | Each phase plan is adversarially vetted before build (existing practice); findings and their resolutions are folded into the plan document itself so the reasoning is reviewable later. | each phase |

Optional, on request: a standalone review packet (HTML/PDF, like `docs/SOCDesk-Overview.pdf`) rendered from `PICKET.md` at a phase close-out.

## 11. Self-review (folded in)

- **Placeholders:** none — every limit cites a verified source (Microsoft Learn pages fetched 2026-09-17; knock-knock `monitor.py`, `.env.example`, `self_redaction.py`, `INSTALL.md` read from the repo at its 2026-09-16 HEAD). Two items are explicitly marked **build-time checks** rather than assumed: (i) which knock-knock protocols log a knock only on an authentication attempt (gates candidacy, §3.9a); (ii) which Sentinel/Defender tables have committed DDL for the KQL pack (§3.10.2). Both are cheap to verify in P1/P2 and change nothing structural.
- **Consistency:** the same 2,000-IP, credential-submitting, last-7-days set feeds the MDE CSV, the watchlist, and the blocklist; `top_ips` in the panel is a ≤ 100 view of it; `picket_lookup` is the ≤ 5,000 superset for enrich. Candidates (§3.9) are a stricter subset (≥ 10 hits, not on abuse.ch, not benign, not recently decided). No surface derives a number a different way.
- **Scope:** three implementation phases, each independently shippable and each ending in a dogfood gate; STIX/trends explicitly deferred. Large but not decomposable further without splitting the sensor from the surface that justifies it.
- **Ambiguity resolved:** "live" (SOCDesk cadence vs. knock-knock streaming) — decided: no streaming in SOCDesk, dashboard not public. "Report automatically" — decided: never. "Which SIEM format" — decided: Defender indicators CSV (blocks), Sentinel watchlist + KQL (detects/hunts), Entra banned list (hardens), plain blocklist (parity); STIX later.
- **Doctrine check:** keyless CI ✓ · no new binding on read path ✓ · no-PII twice ✓ · context-never-verdict ✓ · additive/degradable ✓ · aggregator-not-mirror ✓ · owner-moderated writes ✓ · colour law ✓ · attribution (MaxMind, knock-knock) ✓.
