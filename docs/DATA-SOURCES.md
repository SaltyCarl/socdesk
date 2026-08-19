# SOCDesk — Data Sources

Every source this project touches, what it provides, on what terms, and why it
is either republished here or reachable only as a link you click.

This document is the operational view. The legal reasoning, the risk register,
and the launch gates live in [COMPLIANCE.md](../COMPLIANCE.md) and are
referenced below by finding number (R1–R9) rather than restated. **Read
COMPLIANCE.md before adding any source to this list.**

## The rule that decides which list a source lands on

> Publish only what we may clearly redistribute. Everything else is a link the
> analyst clicks.

A plain `<a href>` deep link is not redistribution and does not engage a
service's data-reuse terms; a background `fetch()` would. The site is
structurally incapable of the latter — the Content-Security-Policy sets
`connect-src 'self'`, so the page cannot call a third-party host at all. That
is the R4 resolution in mechanical form, and it is why there is no `iocs.json`
in this repo and never will be under the current architecture.

The practical consequence for an analyst: a CVE gets a real verdict from data
we hold; every other indicator type gets an honest "not in corpus" plus the
right pivots. See [ANALYST-GUIDE.md](ANALYST-GUIDE.md).

---

## Collected and republished

These feed the pipeline. All are public endpoints and **the repository holds no
secrets** — the one credential in play (the abuse.ch Auth-Key used by ThreatFox)
is a GitHub Actions secret injected at run time, never committed.

### CISA Known Exploited Vulnerabilities (KEV)

| | |
|---|---|
| Provides | The authoritative catalogue of CVEs confirmed exploited in the wild, with `dateAdded`, vendor/product, and a known-ransomware-use flag |
| Endpoint | `collectors/kev.py:6` — the published JSON feed |
| Terms | U.S. Government work, in the public domain; the catalogue data is CC0. Clean to hold and republish |
| Cadence | Every pipeline run (`:11` and `:41`) |
| Published as | The `kev`, `kev_date_added` and `kev_ransomware` fields on every row of `cves.json`, plus feed items for entries added in the last 30 days (`ITEM_WINDOW_DAYS`) |
| Finding | R5 (LOW-MED) — a KEV listing means "known exploited", not "malicious"; keep it sourced and timestamped wherever it is displayed |

KEV is the spine of the product. It is the one input that turns a lookup into a
defensible statement rather than an opinion.

### NVD (NIST National Vulnerability Database)

| | |
|---|---|
| Provides | CVE descriptions, CVSS base scores and severities, and affected vendor/product from CPE configurations |
| Endpoint | `collectors/nvd.py:6` — CVE API 2.0 |
| Terms | U.S. Government work; NVD analysis is public domain and the embedded CVE® records are CC0. Clean to hold |
| Cadence | Every pipeline run, **two queries**: everything modified in the last 2 days, plus the entire KEV catalogue via `hasKev` |
| Published as | `title`, `cvss`, `cvss_severity`, `vendors`, `products`, `published_at`, `last_modified` on `cves.json` rows |
| Finding | Covered by the same public-domain reasoning as KEV |

The second query is not an optimisation — it is the difference between a real
join and a fake one. KEV spans 2014 onward while the modified window is two
days, so without it almost every KEV row renders with an unknown CVSS. Paging
is capped at `MAX_PAGES = 5` × 2000 results to stay inside the keyless rate
limit, and a failure of the KEV-detail query is swallowed rather than failing
the collector (`collectors/nvd.py:79`) because it is an enrichment.

### FIRST EPSS

| | |
|---|---|
| Provides | Exploit Prediction Scoring System — probability of exploitation in the next 30 days, plus percentile |
| Endpoint | `pipeline/cves.py:6`, batched 100 CVEs per request |
| Terms | Free to use and publish **with attribution and no implied endorsement**. Both obligations are met: the site footer and this repository credit FIRST, and no endorsement is claimed anywhere |
| Cadence | Every pipeline run, for every CVE in the table |
| Published as | `epss` and `epss_percentile` on `cves.json` rows; also the basis of the EPSS-movers panel in `trends.json` |
| Finding | Attribution requirement is called out explicitly in the R-review's hard design constraints |

EPSS is an enrichment step rather than a collector module, which is why
`health.json` carries an `epss` row that has no corresponding file in
`collectors/`.

### MITRE ATT&CK

| | |
|---|---|
| Provides | Intrusion-set profiles (aliases, description, techniques used, associated software) and malware/tool profiles |
| Endpoint | `collectors/attack.py:4` — the `attack-stix-data` enterprise bundle |
| Terms | Reproduction and distribution permitted **with the MITRE copyright and permission notice**. That notice is carried in the README and in the site footer. ATT&CK® is a registered trademark of The MITRE Corporation |
| Cadence | **Cached — fetched only when local state is older than 7 days** (`CACHE_DAYS`). The bundle is large and moves on a quarterly cadence |
| Published as | `actors.json` and `malware.json`; also the alias-resolution and structural backbone of `relations.json` |
| Finding | R9 (attribution). The notice is mandatory, not decorative |

Revoked and deprecated objects are filtered out at collection
(`collectors/attack.py:21`), so a retired group never appears as a live profile.

### Ransomware.live

| | |
|---|---|
| Provides | Recent ransomware victim postings — group name, sector, country, discovery time, claim URL |
| Endpoint | `collectors/ransomwarelive.py:4` |
| Terms | Restrictive. Their terms bar commercial use and the free API is personal-use only; the listings are unverified criminal claims |
| Cadence | Every pipeline run |
| Published as | Feed items at **group level only** — `"<group> posted a new victim claim"` with sector and country. Victim organisation names are **not** republished; the claim link carries the detail |
| Finding | **R3** — resolved to LOW by exactly this restriction |

Three reasons the victim name is withheld, all in the collector's docstring: the
postings are unverified criminal claims, an upstream retraction would never
propagate to a static mirror, and an organisation name can be personal data.
The name is still hashed into the item id so deduplication stays stable across
runs — a SHA-1 discloses nothing.

Four or more claims from the same group collapse into a single digest row
(`pipeline/relevance.py:98`); without that, victim-claim stubs dominate the
feed.

### abuse.ch Feodo Tracker + ThreatFox (C2 / blocklist IPs)

| | |
|---|---|
| Provides | Botnet C2 and payload-delivery IPs. Feodo Tracker: `ip_address`, `port`, `country` (ISO-2), `malware`, `first_seen`, `last_online`. ThreatFox `ip:port` IOCs: ip, port, `malware`/`malware_printable`, `confidence_level`, `first_seen`, tags |
| Endpoint | `collectors/feodotracker.py` (keyless JSON blocklist) and `collectors/threatfox.py` (POST `get_iocs`, needs the free Auth-Key in `ABUSECH_API_KEY`) |
| Terms | These are **indicators published expressly to be blocked** — the opposite posture to the MalwareBazaar/ThreatFox *corpus* reuse withheld under R4. Feodo Tracker's blocklist exists to be loaded into firewalls; the IP is the redistributable datum. SOCDesk is non-commercial, satisfying abuse.ch's not-for-profit free-access condition. abuse.ch is attributed in the payload, the README, and the footer |
| Cadence | Every pipeline run. ThreatFox skips gracefully when `ABUSECH_API_KEY` is absent (local dev), so the pipeline still produces Feodo-only output |
| Published as | `threat_ips.json` — `{generated_at, schema_version, attribution, ips[]}` where each row is `{ip, country, lat, lng, source, malware, port, first_seen, last_seen, geo_precision}`. De-duplicated by IP (sources merged), ranked most-recent-first, capped at 300 for the globe. Assembled in `pipeline/threat_ips.py`; bounded by `schemas/threat_ips.schema.json` |
| Geolocation | `pipeline/geo.py` — **IPinfo** (`IPINFO_TOKEN`) resolves each IP to city-level lat/lng/country (`geo_precision: "city"`); results are written to a persistent per-IP cache (`data/state/geo_cache.json`) so only IPs new since the last run cost a lookup and the twice-hourly pipeline stays inside IPinfo's free tier. When the token is absent or a lookup fails, it falls back to the country centroid (`data/geo/country_centroids.json`, public domain) plus a **deterministic per-IP jitter** seeded from the IP (`geo_precision: "country"`), so shared-country IPs scatter and coordinates stay stable across runs. IP geolocation is approximate and reflects hosting/registrar, **not** operator location |
| Finding | Distinct from R4: R4 governs the reputation *corpus* (hashes, lookups). A curated block list of C2 IPs is redistribution-intended intel. An IP that cannot be placed (no IPinfo result and no source country) is **dropped**, never given a fabricated coordinate |

The geo cache is committed alongside the state snapshots and pruned each run to
the IPs currently on a list, so it stays bounded. ThreatFox returns no
geolocation of its own; with a token it is placed by IPinfo like any other IP,
and without one its rows fall into `dropped_no_geo` while Feodo Tracker (which
carries `country`) still populates the globe via the centroid fallback.
IPinfo's free tier requires attribution, carried in the payload `attribution`
string, the README, and the site footer.

### Vendor and researcher RSS pool

| | |
|---|---|
| Provides | Threat research and security news headlines |
| Feeds | Nine, listed in `collectors/rss.py:10` — Cisco Talos, Unit 42, The DFIR Report, Microsoft Threat Intelligence, Google Threat Intelligence, SANS ISC, BleepingComputer, The Hacker News, Securelist |
| Terms | Publisher-specific. Treated conservatively: **headline plus a sanitised snippet plus the link, never full text** |
| Cadence | Every pipeline run, up to 20 entries per feed |
| Published as | Feed items with entity extraction (actors, malware, vendors, CVEs) and a derived category |
| Finding | **R9** (LOW-MED) — attribute the feed, excerpt only, always link out |

The publisher name is prefixed into every title, so attribution travels with
the item wherever it is copied. Summaries are capped at 500 characters by the
item builder and by the schema. One dead feed does not kill the pool; the
collector raises only if every feed fails.

---

## Reached by link only — never mirrored

None of the following is fetched, cached, or stored. They appear as pivot
buttons on a verdict, and nothing happens until the analyst clicks. Clicking is
a disclosure of that indicator to that service — the site says so prominently
above the pivot row, and repeats it in [ANALYST-GUIDE.md](ANALYST-GUIDE.md).

Targets are built in `pivotsFor()` (`site/js/verdict.js:24`) and are
type-aware.

| Service | Offered for | Why link-only |
|---|---|---|
| VirusTotal | all types except email | Not open-licensed; terms restrict reuse of results |
| AbuseIPDB | IPv4 | Not open-licensed |
| GreyNoise | IPv4 | Not open-licensed |
| Shodan | IPv4 | Not open-licensed |
| Censys | IPv4, domain | Not open-licensed |
| Spamhaus | IPv4 | Not open-licensed |
| urlscan.io | IPv4, domain, URL | Not open-licensed. Note: **urlscan publishes public scans** — a submission is itself a disclosure |
| Pulsedive | domain, URL | Not open-licensed |
| IBM X-Force Exchange | domain | Not open-licensed |
| abuse.ch — MalwareBazaar | hashes | **R4.** Post-Spamhaus terms condition copying platform data on express consent; free access is not-for-profit only. Deep-linking sidesteps this entirely |
| abuse.ch — ThreatFox, URLhaus | registry entries | Same as above. Listed in the source registry as reference sources; no corpus is held |
| MetaDefender, Hybrid Analysis | hashes | Not open-licensed |
| Tria.ge, ANY.RUN, Joe Sandbox | hashes, URLs | Sandboxes. The URL-type links are marked with a warning glyph because submitting a URL detonates it and is a far larger disclosure than reading an existing scan |
| PhishTank | URL | Community phishing corpus; link only |
| Have I Been Pwned | email | Credential-exposure lookup |
| Hudson Rock | email | Infostealer exposure lookup |

Two deliberate design rules from the compliance re-review govern this whole
table, and both are load-bearing:

1. **User-clicked links only.** No auto fan-out — one click must never spray an
   indicator to six services at once. The "Lookup all" control in the toolbelt
   feeds indicators into the *local* bulk table, not into third parties.
2. **Existing scans before new submissions.** For URLs the pivot list leads
   with urlscan *search*, because inspecting someone else's completed scan
   discloses nothing new.

---

## Queried live by the enrichment function — never stored

The lookup cockpit calls a single **same-origin** Cloudflare Pages Function,
`/api/enrich` (`lib/enrich.mjs`), which queries public reputation services
server-side for the one indicator the analyst pasted and returns the
consensus-tally escalation card (see
[VERDICT-LANGUAGE.md](VERDICT-LANGUAGE.md)). The browser only ever calls its own
origin — `connect-src 'self'` still holds — and **nothing fetched here is
mirrored, cached to the repo, or published as a payload;** every response is
per-request. The reputation sources' redistribution posture is unchanged (there
is still no `iocs.json`); their terms are the same ones tracked in
[COMPLIANCE.md](../COMPLIANCE.md) and the source-license review. Two behaviours
are worth recording here:

- **IPv6 is supported for the IP sources.** AbuseIPDB, VirusTotal and ipinfo are
  queried for both IPv4 and IPv6; **GreyNoise is IPv4-only** (its community API
  returns 400 on a v6 address). Private/reserved v6 (`::1`, `fc00::/7`,
  `fe80::/10`, `ff00::/8`) is rejected before any lookup.
- **urlscan uses `page.domain:` for domains** — a scan *of* the domain, not any
  scan that merely contacted it — and surfaces the **existing scan's** verdict and
  screenshot. SOCDesk reads existing scans only; it **never submits** to urlscan.

### RDAP (domain registration)

| | |
|---|---|
| Provides | Registration data for a domain — Registered / Registrar / Expires / Last-changed — via the Registration Data Access Protocol |
| Endpoint | `rdap.org` (`lib/enrich.mjs`), which bootstraps to the authoritative registry RDAP server. **Keyless**, but requires a `User-Agent` (rdap.org 403s a request that sends none) |
| Terms | Public registry protocol; no key, no ToS gate. Queried per-request, never stored |
| Role | **Context, not a verdict** (`kind:"context"`) — it populates the domain card's registration-age hero and is **excluded from the N-of-M tally.** A 404 means "no record / not registered", a finding rather than an outage |

---

## Reviewed and rejected

**knock-knock.net** (assessed 2026-08-06, detail in [BACKLOG.md](../BACKLOG.md)).
Not collected. No data licence exists — `/terms`, `/license` and `/legal` all
404, the repository's MIT licence covers code only, and the GeoIP fields
inherit MaxMind's EULA. Silence is not permission, which is the same rule that
removed the abuse.ch corpus. The value was also low: a single hobbyist sensor
fleet measures internet background radiation, and a binary listed/not-listed
verdict over recycled cloud IPs would mislead. A deep link is the most it will
ever get.

abuse.ch Feodo Tracker (and ThreatFox `ip:port` IOCs) have now landed as the
geolocated `threat_ips.json` surface — see the subsection above. Three sources
remain queued but not built — C2IntelFeeds, PhishTank, and APTnotes. Each is one
collector module, one fixture, and one registry row; each needs its own terms
review first. See [BACKLOG.md](../BACKLOG.md).

---

## The source registry

`data/sources.json` is copied into the published payloads with a fresh
timestamp and rendered as the **Sources** view. Rows carry `kind: "collector"`
(published here) or `kind: "reference"` (pivot link only), and the site counts
each kind in the section header.

Two known inaccuracies in that file, worth fixing rather than documenting
around:

- The nine publishers inside the RSS pool also appear as individual
  `reference` rows, so they read as "never mirrored" while their headlines are
  in fact republished. Genuinely reference-only entries — KrebsOnSecurity,
  CrowdStrike, Trend Micro, Sophos X-Ops, Ransomlook, CISA Advisories — are
  correctly labelled.
- The "Vendor & researcher RSS pool" row has `"url": "https://github.com"`,
  which is what its OPEN link on the site points at.

## Adding a source

1. Read [COMPLIANCE.md](../COMPLIANCE.md). Establish the licence **in writing**
   before writing any code. Free to access is not free to redistribute — that
   conflation is the origin of findings R3 and R4.
2. Decide which list it belongs on. If the terms are silent, it is a link, not
   a collector. Silence is not permission.
3. If it is collectable: one module in `collectors/` exposing `SOURCE` and
   `collect(fetch, now)`, one fixture-backed test, one row in
   `data/sources.json`, and registration in `collectors/__init__.py`.
4. If a new payload shape is involved, add a bounded schema in `schemas/` and
   register it in `pipeline/validate.py`. Unbounded schemas are how one giant
   upstream string blows up a build.
5. Add the attribution to the README and the site footer if the licence
   requires it.
