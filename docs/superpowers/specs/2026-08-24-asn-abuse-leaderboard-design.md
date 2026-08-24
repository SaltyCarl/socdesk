# IOC Reporting — Phase 4: ISP/ASN abuse-leaderboard (design spec)

**Date:** 2026-08-24 · **Status:** design, pre-implementation · **Author identity:** SaltyCarl (no AI attribution anywhere).
**Predecessors:** Phase 0+1 reporting (`docs/superpowers/specs/2026-08-20-ioc-reporting-phase01-design.md`), Phase 2 moderation console (`…/2026-08-22-admin-moderation-console-design.md`), Phase 3 community-reports publish (`…/2026-08-22-community-reports-publish-design.md`). Phase 3's `community_reports.json` is now **LIVE and populated** — it is Phase 4's substrate.

---

## 0. SCOPE BOUNDARY (anti-drift — strict)

**Goal (one sentence).** Aggregate the already-published abusive indicators by network (ASN + ISP name) into a small, committed/served `asn_leaderboard.json`, rendered as a read-only "which networks host the most reported abuse" leaderboard — framed as *reported/blocklisted abuse volume, never a verdict on the network*.

**In scope.**
- A **new pipeline step** `pipeline/asn.py` that resolves an **ASN + ISP name per distinct abusive IP** (via IPinfo's `org` field — the crux, §3) and aggregates by network.
- The **committed dataset** `data/state/asn_leaderboard.json` + its schema, riding the existing `gate() → dual-write → deploy` machinery (run_pipeline.py:99-114, validate.py:36-51).
- A committed **per-IP ASN cache** `data/state/asn_cache.json` (quota discipline — mirrors `geo_cache.json`, run_pipeline.py:71,118-121).
- A **read-only web surface** — a new **"Networks" tab** in the Data Desk (DataDeskRoute.tsx:26-33) rendering the committed dataset, mirroring `SourcesView.tsx`.
- `SCHEMA_FOR` registration (validate.py:8-19); a Python unit-test module `tests/test_asn_leaderboard.py`; a `web/src/routes/AsnLeaderboardRoute.tsx` + `web/src/components/views/AsnLeaderboardView.tsx` + a type in `types.ts`.

**Explicitly OUT of scope (named so the boundary is a fence, not a suggestion).**
- **Phase 5** trends/analytics over the leaderboard (movement, week-over-week ASN deltas). **Phase 6** upstream push (AbuseIPDB etc.). Neither ships here.
- **ANY change to the read model / verdict doctrine.** The leaderboard is a standalone *data view* over committed JSON. It touches **nothing** in `lib/enrich.mjs`, `functions/api/enrich.js`, `map.ts`, or the verdict tally. No new enrich source, no `SOCDESK_COMMUNITY_DATA`-style injection.
- **ANY change to the community-reports write path** (`/api/report`, OAuth, D1 schema, `lib/reporting/*`, `migrations/`) **or** the Phase-3 read path. Phase 4 only *consumes* `community_reports.json` (and `threat_ips.json`) as already-published inputs.
- **ANY per-lookup D1 / API on the web surface.** The view is a static asset read via `useStateData` (useStateData.ts:23,32), no-account — the Option-A invariant, unchanged.
- **Reporter identities, at any granularity.** HARD no-PII: aggregate network stats only. `pipeline/asn.py` never touches D1 or `github_id` — it reads the *already-PII-stripped* `community_reports.json` (community.py:103-110) and the identity-free `threat_ips.json`.
- **No new owner secret.** Reuses the existing `IPINFO_TOKEN` (collect-and-deploy.yml:42). If unset → every IP is `unattributed`, the view degrades honestly.

**Files this track OWNS.**
- *Create:*
  - `pipeline/asn.py` — IPinfo `org` → (ASN, ISP) resolution + aggregation → the `asn_leaderboard.json` payload.
  - `schemas/asn_leaderboard.schema.json` — dataset schema; `additionalProperties:false` at both levels is the machine-checked **no-PII fence**.
  - `data/state/asn_leaderboard.json` — the committed dataset (first commit = empty envelope).
  - `data/state/asn_cache.json` — the committed per-IP `{asn, isp, country}` cache (first commit = `{}`).
  - `tests/test_asn_leaderboard.py` — pure `parse_org` + aggregation + no-PII + degradation tests (mock fetch, no network).
  - `tests/fixtures/asn/org_parity.json` — shared `org`→`{asn,isp}` fixture (mirrors the JS regex; parity-tested, like `tests/fixtures/community/key_parity.json`).
  - `web/src/routes/AsnLeaderboardRoute.tsx` + `web/src/components/views/AsnLeaderboardView.tsx`.
- *Modify:*
  - `pipeline/validate.py` — register `SCHEMA_FOR["asn_leaderboard.json"]`.
  - `run_pipeline.py` — call `build_asn_leaderboard(...)`, thread `asn_cache`, add the payload before `gate()`, persist the cache (mirrors the community + geo_cache blocks, run_pipeline.py:92-97,118-121).
  - `web/src/routes/DataDeskRoute.tsx` — add `{ key: 'networks', label: 'Networks' }` to `TABS` (line 26) and mount the route (line 101-106).
  - `web/src/components/views/types.ts` — add `AsnLeaderboardPayload` / `AsnNetwork`.
  - `README.md` — one line: the abuse-by-network leaderboard is built from committed datasets; still no-account, no per-lookup D1.

**Interfaces / dependencies.** IPinfo `/{ip}/json` `org` field (geo.py:19,68; proven present at enrich.mjs:366); the existing `gate()` + last-known-good + triple dual-write (validate.py:36-51, run_pipeline.py:99-121); the two input payloads `community_reports.json` (community.py:112-119) and `threat_ips.json` (threat_ips.py:90-98); the `useStateData` static-asset fetch (useStateData.ts:23) + `AsyncGate`/`ViewHeader`/`EmptyState` view vocab (states.tsx:78,115, ViewFrame.tsx:9).

**Acceptance criteria.** See §8. **Anti-drift guardrails.** See §9.

---

## 1. Doctrine / invariants (binding)

1. **Read model untouched.** No enrich source, no verdict, no tally change, no D1 on any request path. The leaderboard is a data view over a committed file — the same class as `feed.json`/`sources.json`, reached through `useStateData` (useStateData.ts:32).
2. **Reported volume, NOT a verdict on the network.** Every headline, column, and the envelope `attribution` say "reported / blocklisted abuse volume." Naming an ISP/ASN in an aggregate, attributed abuse leaderboard is explicitly OK (OSINT-liability posture); accusing the *operator* is not. Copy inherits the Phase-3 framing ("a report is an allegation reviewed before publication, not a verdict" — community.py:21-25).
3. **HARD no-PII fence.** The dataset carries ONLY aggregate network stats: ASN, ISP name, country, distinct-abusive-IP count, community distinct-report count, category set, provenance, example IPs. **Never** a reporter, `github_id`, `evidence`, `comment`, or per-report row. `pipeline/asn.py` structurally *cannot* leak these — it never reads D1; its inputs are already PII-stripped (community.py:103-110). The schema's `additionalProperties:false` is the second, machine-checked fence.
4. **Free-tier only.** ASN comes from the IPinfo `org` field already present in the response the pipeline *already fetches* for geolocation (geo.py:68) — no new endpoint, no paid ASN database. A committed per-IP cache means only IPs new since the last run cost a call (mirrors geo_cache, workflow:36-38). Distinct abusive IPs are few (§3.2), so the cost is negligible and bounded.
5. **Honest degradation.** IPinfo/token missing → IPs are `unattributed` (counted honestly, never a fabricated ASN). A build failure returns `None` → `gate()` keeps last-known-good (validate.py:46-48). The view states its empty/error reason (states.tsx:78-107), never a blank screen.
6. **Attributed + honest provenance.** Each network row records which source(s) contributed its IPs (`community`, `abuse.ch`), so a reader can tell an owner-moderated *allegation* from an abuse.ch *published blocklist C2* — the two are never silently merged into an undifferentiated "abuse" number.

---

## 2. Architecture at a glance

```
                 already-published committed datasets (Phase 3 + threat surface)
                 ├─ data/state/community_reports.json   (indicators map, PII-stripped — community.py:112)
                 └─ data/state/threat_ips.json          (abuse.ch C2/blocklist IPs — threat_ips.py:90)
                              │  (twice-hourly, GitHub Actions — Python; run_pipeline.py)
                              ▼
        pipeline/asn.py ── distinct abusive IPs (ipv4/ipv6) ──► resolve ASN+ISP per IP
                              │        via IPinfo `org` (geo.py:68 fetch already carries it)
                              │        cache-first: data/state/asn_cache.json (only NEW IPs call)
                              ▼
                       aggregate by ASN  (ip_count, report_count, categories[], sources[], examples[], country)
                              │
        run_pipeline → gate() (schema + last-known-good) → triple dual-write (run_pipeline.py:109-114)
                              │
             ├─ data/state/asn_leaderboard.json            (committed to git)
             └─ web/public/data/state/asn_leaderboard.json (→ Vite copy → web/dist/… → deployed asset)
                              │
                              ▼  served static at /data/state/asn_leaderboard.json
        web/src/routes/AsnLeaderboardRoute.tsx ── useStateData('asn_leaderboard') ──► AsnLeaderboardView
                              ▼
              Data Desk "Networks" tab (DataDeskRoute.tsx) — read-only, no-account, no D1/API
```

The whole loop reuses machinery that already exists for `community_reports.json` and `threat_ips.json` (publish.py:83-92, run_pipeline.py:92-121). Phase 4 adds **one builder, one payload, one cache file, and one desk tab** to that same conveyor — and, unlike Phase 3, adds **nothing** to the enrich read path.

---

## 3. Key design decisions (each with a recommendation)

### 3.1 ASN/ISP sourcing — the crux — **RECOMMEND: resolve per distinct IP via IPinfo's `org` field, cache-first**

**The problem, precisely.** The reported indicators have no ASN attached. `community_reports.json` entries carry `type/value/reporters/categories/first_reported/latest_reported` and nothing else (community.py:103-110, schema `additionalProperties:false`). `threat_ips.json` rows carry `ip/country/lat/lng/source/malware/port/first_seen/last_seen/geo_precision` — a **country but no ASN** (threat_ips.schema.json:20-32). Neither the D1 `reports` table (migrations/0001_init.sql:8-18) nor either published dataset holds an ASN. So the ASN→network mapping must be *derived* at build time.

**Candidates weighed:**
- **(a) Capture ASN at report time.** Rejected: it would require a write-path change (`/api/report`, D1 schema, `lib/reporting/*`, a migration) — all explicitly out of scope (§0), and it would only cover *future* community reports, never the abuse.ch feed IPs.
- **(b) Build from a dataset that already carries ASN.** There is none — confirmed by grep: no `asn`/ASN field in any `data/state/*.json`, schema, or collector. Rejected as counterfactual.
- **(c) A downloadable free ASN database (IPinfo Lite / MaxMind GeoLite ASN).** Viable but heavier: a multi-MB DB committed to the repo or fetched each run, plus a CIDR longest-prefix-match implementation and a licence/attribution obligation. Rejected as over-built for tens–hundreds of distinct IPs.
- **(d) Resolve each distinct abusive IP via IPinfo's `org` field, cache-first.** **← RECOMMENDED.** The pipeline **already** calls `https://ipinfo.io/{ip}/json?token=…` for geolocation (geo.py:19,68). That exact response **already carries `org`** = `"AS60729 Stiftung Erneuerbare Freiheit"` — **proven** by the live read path, which parses it with `org.match(/^(AS\d+)\s+(.*)$/)` into an ASN + Organisation (enrich.mjs:366-380). geo.py simply **discards** `org` today (it reads only `loc`/`country`/`city`, geo.py:73-86). So the ASN + ISP name are **already available, on the free tier, from a call SOCDesk already makes** — the only new work is to *read the field we're throwing away*.

**Mechanism (d), concrete.**

`pipeline/asn.py`:
```python
import re
from collectors.base import iso

IPINFO_URL = "https://ipinfo.io/{ip}/json?token={token}"
_ORG_RE = re.compile(r"^(AS\d+)\s+(.*)$")   # byte-mirror of enrich.mjs:367

def parse_org(org):
    """'AS60729 Stiftung Erneuerbare Freiheit' -> ('AS60729', 'Stiftung …').
    Returns (None, None) when the string has no leading AS number (some IPinfo
    orgs are name-only or empty) — the IP is then UNATTRIBUTED, never faked."""
    m = _ORG_RE.match(str(org or "").strip())
    return (m.group(1), m.group(2).strip()) if m else (None, None)

def resolve_asn(ip, cache, fetch, token):
    """Cache-first ASN lookup. Returns {'asn','isp','country'} or None.
    (1) cache hit -> no call; (2) IPinfo when fetch+token present, cached on
    success; (3) None (UNATTRIBUTED). Never raises for upstream reasons."""
    hit = cache.get(ip)
    if isinstance(hit, dict) and hit.get("asn"):
        return hit
    if fetch is None or not token:
        return None
    try:
        data = fetch(IPINFO_URL.format(ip=ip, token=token))
    except Exception:                          # network/HTTP -> unattributed
        return None
    if not isinstance(data, dict):
        return None
    asn, isp = parse_org(data.get("org"))
    if not asn:
        return None
    rec = {"asn": asn, "isp": isp or asn,
           "country": (data.get("country") or "").strip().upper()[:2]}
    cache[ip] = rec                            # persisted for next run
    return rec
```
- **Same endpoint, same token, same cache discipline** as geolocation — this is deliberately a copy of the geo.py:61-119 shape (cache-first, only-new-IPs-call, never-fatal) so it inherits a reviewed pattern rather than inventing one.
- **`fetch` is `pipeline.http.http_fetch`** (http.py:6), threaded from `run_pipeline.run()` exactly as it is to the collectors and the geo path.
- **Unresolved IPs** (no token, network error, name-only/empty `org`, private/bogon) return `None` and are tallied into the envelope's `unattributed_ips` — a network leaderboard shows only IPs it can honestly place on a network.

**Quota / cost bound.** Distinct abusive IPs = the IPv4/IPv6 entries in `community_reports.json` (currently 3, all IPv4) **∪** the rows in `threat_ips.json` (capped at 300 — threat_ips.py:3). Worst case, a *cold* first run resolves ≤ ~300 + ε IPs = ~300 calls; every run after that only calls for IPs new since the last (the committed `asn_cache.json` carries the rest). IPinfo's free tier is 50k lookups/month; the twice-hourly cron (workflow:5) does ~1,440 runs/month but each reuses the cache, so steady-state is a handful of calls/run. Comfortably free, matching the "only IPs new since the last run are looked up" discipline already documented for geo (workflow:36-38).

**Companion optimization (optional, low-risk).** Extend `geo._ipinfo` (geo.py:84-86) to *also* stash `org`'s parsed `asn`/`isp` in the shared `geo_cache.json` record — since that call already happens for every threat IP, `asn.py` could seed from it and skip even the first-run threat-IP calls. **Not required** (the cold cost is already trivially free) and it entangles `asn.py` with geo's cache-pruning (threat_ips.py:79-82 prunes `geo_cache` to threat IPs only, which would evict community IPs). **Recommendation: keep `asn.py` self-contained with its own `asn_cache.json`** (own pruning, no cross-concern coupling); revisit the geo-seed only if quota ever tightens.

### 3.2 Data-source scope — **RECOMMEND: community reports ∪ abuse.ch threat feed, per-source attributed — but FLAG to owner**

Community reports alone are, today, **3 IPs** (community_reports.json) — too thin to read as a "leaderboard." `threat_ips.json` already holds up to 300 abuse.ch Feodo/ThreatFox C2/blocklist IPs (threat_ips.py:4,90) that are, by definition, "abusive IPs grouped by nothing yet" — an ideal, already-in-pipeline substrate. **Recommend the union of distinct abusive IPs from both**, with each network row recording per-source provenance and counts so honesty holds:
- `ip_count` — total distinct abusive IPs on the ASN (the rank key).
- `report_count` — distinct community *reports* contributed (from `reporters`, community.py:106) — **community only**, 0 when the ASN's IPs came only from the feed.
- `sources` — `["community"]`, `["abuse.ch"]`, or both — so an owner-moderated *allegation* is never silently pooled with an abuse.ch *published C2* under one undifferentiated number.

Envelope `attribution` states the mix openly and reuses the two upstreams' own wording (community.py:21-25, threat_ips.py:6-12).

**This is a genuine owner decision — FLAGGED (§10).** Community-only keeps the leaderboard purely "what our contributors reported" (cleanest provenance story, but sparse and slow to fill); the union makes it immediately useful and richer but blends two evidence classes (mitigated by `sources`/`report_count`). The spec builds the union with an easy switch to community-only (a single `SOURCES` list in `asn.py`); **owner picks before build.**

### 3.3 The committed dataset — **`data/state/asn_leaderboard.json`**

Envelope + a `networks` array sorted by `ip_count` desc (a leaderboard is ordered; the site ships ranked, it does not re-sort in the browser — mirroring feed/threat_ips ordering, publish.py:59, threat_ips.py:86):
```json
{
  "generated_at": "2026-08-24T14:41:00Z",
  "schema_version": 1,
  "attribution": "Networks (ASN / ISP) ranked by the volume of abusive IPs reported to SOCDesk (community, owner-moderated) and published on the abuse.ch Feodo Tracker / ThreatFox blocklists. A count of reported/blocklisted IPs hosted on a network — NOT a verdict on the network or its operator. ASN/ISP mapping by IPinfo (https://ipinfo.io); a report is an allegation reviewed before publication, not a confirmation.",
  "count": 2,
  "total_abusive_ips": 41,
  "unattributed_ips": 3,
  "cap": 200,
  "truncated": false,
  "networks": [
    {
      "asn": "AS60729",
      "isp": "Stiftung Erneuerbare Freiheit",
      "country": "DE",
      "ip_count": 12,
      "report_count": 2,
      "categories": ["phishing", "scanner"],
      "sources": ["abuse.ch", "community"],
      "examples": ["185.220.101.34", "185.220.101.42"]
    },
    {
      "asn": "AS14061", "isp": "DigitalOcean, LLC", "country": "US",
      "ip_count": 9, "report_count": 0, "categories": ["malware-c2"],
      "sources": ["abuse.ch"], "examples": ["162.243.103.246"]
    }
  ]
}
```
Field notes:
- **`networks` is an array** (not an object map like community) — the view iterates a ranked list; no O(1) lookup is needed (no read-path consumer).
- **`ip_count`** = distinct abusive IPs on the ASN — the rank key. **`report_count`** = distinct community reports (0 for feed-only ASNs). **`categories`** = sorted union across the ASN's IPs (community categories + abuse.ch malware-family is *not* a category enum, so feed IPs contribute to `ip_count` but only community IPs contribute categories — kept honest). **`sources`** = sorted provenance enum. **`country`** = the modal country across the ASN's placed IPs (an ASN can span countries; surfaced as approximate, mirroring threat_ips' "reflects hosting, not operator" caveat, threat_ips.py:10-12).
- **`examples`** = up to `EXAMPLE_CAP` (e.g. 3) IP strings — these are **already-public abusive indicators** (threat_ips publishes full IPs; community values are the reported indicators themselves), so listing them exposes nothing new and gives an analyst a concrete pivot. **Never** a reporter, comment, or evidence string.
- **Envelope counters** (`total_abusive_ips`, `unattributed_ips`, `cap`, `truncated`) mirror the threat_ips envelope's honest-degradation counters (threat_ips.py:90-98) — a reader sees how many IPs couldn't be placed on a network.

**Schema** `schemas/asn_leaderboard.schema.json` (modeled on threat_ips.schema.json; `additionalProperties:false` at **both** levels is the no-PII fence):
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["generated_at", "schema_version", "attribution", "count", "networks"],
  "properties": {
    "generated_at": {"type": "string"},
    "schema_version": {"type": "integer"},
    "attribution": {"type": "string", "maxLength": 1000},
    "count": {"type": "integer", "minimum": 0},
    "total_abusive_ips": {"type": "integer", "minimum": 0},
    "unattributed_ips": {"type": "integer", "minimum": 0},
    "cap": {"type": "integer", "minimum": 0},
    "truncated": {"type": "boolean"},
    "networks": {
      "type": "array",
      "maxItems": 1000,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["asn", "isp", "ip_count", "report_count", "categories", "sources", "examples"],
        "properties": {
          "asn": {"type": "string", "pattern": "^AS\\d+$", "maxLength": 16},
          "isp": {"type": "string", "minLength": 1, "maxLength": 128},
          "country": {"type": "string", "minLength": 2, "maxLength": 2},
          "ip_count": {"type": "integer", "minimum": 1},
          "report_count": {"type": "integer", "minimum": 0},
          "categories": {
            "type": "array", "maxItems": 10,
            "items": {"enum": ["brute-force","ssh","port-scan","web-app-attack","phishing","malware-c2","scanner","spam","exploited-host","other"]}
          },
          "sources": {
            "type": "array", "minItems": 1, "maxItems": 2,
            "items": {"enum": ["community", "abuse.ch"]}
          },
          "examples": {
            "type": "array", "maxItems": 5,
            "items": {"type": "string", "minLength": 3, "maxLength": 45}
          }
        }
      }
    }
  }
}
```
The `categories` enum is `lib/reporting/validate.mjs` `CATEGORIES` verbatim (validate.mjs:4-7) — same lockstep discipline as the community schema (community_reports.schema.json:25). Register: `SCHEMA_FOR["asn_leaderboard.json"] = "asn_leaderboard.schema.json"` (validate.py:8-19).

### 3.4 Aggregation logic — `build_asn_leaderboard(...)`

Pure over its inputs (the two committed payloads + the mutable cache); the only I/O is the cache-first IPinfo call inside `resolve_asn`:
```python
CAP = 200            # networks published (ranked); backstop below the schema's 1000
EXAMPLE_CAP = 3
SOURCES = ("community", "abuse.ch")   # switch to ("community",) for community-only (§3.2)

def _distinct_abusive_ips(community, threat_ips):
    """Yield (ip, source, category_or_None, is_report) for every ipv4/ipv6
    abusive indicator. Domains/urls/hashes have no ASN -> skipped (NOT counted
    as unattributed; they are simply not network-scoped)."""
    if "community" in SOURCES:
        for entry in (community or {}).get("indicators", {}).values():
            if entry["type"] in ("ipv4", "ipv6"):
                for cat in entry.get("categories", []):
                    yield entry["value"], "community", cat, True
                if not entry.get("categories"):
                    yield entry["value"], "community", None, True
    if "abuse.ch" in SOURCES:
        for row in (threat_ips or {}).get("ips", []):
            yield row["ip"], "abuse.ch", None, False   # malware family != category enum

def build_asn_leaderboard(community, threat_ips, cache, fetch, now, token):
    # 1. fold indicators -> per-IP {sources, categories, is_report}
    # 2. resolve_asn(ip) per DISTINCT ip (cache-first); None -> unattributed++
    # 3. group placed IPs by asn -> {isp, country(modal), ip_count(distinct),
    #    report_count(distinct report-IPs), categories(sorted union),
    #    sources(sorted), examples(<=EXAMPLE_CAP)}
    # 4. sort by (ip_count desc, asn) ; cap at CAP ; prune cache to IPs seen
    # 5. return the full envelope, or None on a structural failure (last-known-good)
```
Determinism: sort tie-break on `asn` (as threat_ips ties on `ip`, threat_ips.py:87); `examples` taken in sorted order; `categories`/`sources` sorted — so the committed file is byte-stable across runs with the same inputs (clean git diffs). Cache pruned to IPs seen this run (threat_ips.py:79-82 pattern) so `asn_cache.json` stays bounded. **`report_count` counts distinct report-bearing IPs on the ASN, not summed `reporters`** — a network stat, and it structurally cannot exceed `ip_count`.

### 3.5 The web surface — **RECOMMEND: a "Networks" tab in the Data Desk** (FLAG the label)

**Recommend a desk tab, not a top-level route.** The five existing data surfaces already live behind `DataDeskRoute`'s in-content tab bar (DataDeskRoute.tsx:26-33, 101-106), deep-linkable as `/desk#feed` etc. Adding `{ key: 'networks', label: 'Networks' }` there keeps `App.tsx`'s route table (App.tsx:39-63) **untouched**, gives a `/desk#networks` deep link for free, and reads as one system with the other data views. (A top-level `/leaderboard` route is the alternative — more prominent, but a new nav entry and route-table change for a surface that is a peer of Sources/Health. Prefer the tab.)

`web/src/routes/AsnLeaderboardRoute.tsx` mirrors `FeedRoute.tsx:16-45` exactly:
```tsx
export function AsnLeaderboardRoute() {
  const { status, data, error } = useStateData<AsnLeaderboardPayload>('asn_leaderboard')
  const networks = data?.networks ?? []
  return (
    <div className="flex flex-col gap-6">
      <ViewHeader
        eyebrow="Abuse by network"
        title="Networks"
        intro="Autonomous systems ranked by the volume of abusive IPs reported to SOCDesk and published on the abuse.ch blocklists. Reported volume hosted on a network — not a verdict on the network or its operator."
        aside={status === 'ready' && data ? (
          <MicroLabel tone="faint">
            <CountUp value={networks.length} /> networks · updated {rel(data.generated_at)}
          </MicroLabel>
        ) : null}
      />
      <AsyncGate status={status} label="the leaderboard" detail={error}
                 skeleton={<SkeletonRows rows={8} />}>
        <AsnLeaderboardView payload={data} />
      </AsyncGate>
    </div>
  )
}
```
`AsnLeaderboardView.tsx` is a ranked table cloned from `SourcesView.tsx:29-111` — columns **# · ASN · ISP · Country · Abusive IPs · Reported for (category chips) · Source(s) · Examples**. It renders its own `EmptyState` (states.tsx:78) on `networks.length === 0` ("No networks to rank yet — the pipeline may not have placed any reported IP on an ASN"), stating the reason honestly, never a blank screen. `ip_count` is the visual weight (right-aligned, `num()` formatted, format.ts:27); the `NOT a verdict` framing sits in the `ViewHeader` intro and a one-line footnote. **No verdict hues** — the count is neutral ink; red/amber stay reserved for the verdict/severity axis (format.ts:49-53). Types (`AsnLeaderboardPayload`, `AsnNetwork`) added to `types.ts` alongside the other data-view payloads, every field optional-tolerant (types.ts:6-8 rule).

### 3.6 Freshness / degradation

Rides the existing pipeline cadence and gate, identical to community (run_pipeline.py:92-97):
```python
asn_cache = state.get("asn_cache.json", {})
if not isinstance(asn_cache, dict):
    asn_cache = {}
leaderboard = build_asn_leaderboard(
    payloads.get("community_reports.json") or state.get("community_reports.json"),
    payloads.get("threat_ips.json") or state.get("threat_ips.json"),
    asn_cache, fetch, now, token=os.environ.get("IPINFO_TOKEN"))
if leaderboard is not None:
    payloads["asn_leaderboard.json"] = leaderboard
elif "asn_leaderboard.json" in state:
    payloads["asn_leaderboard.json"] = dict(
        state["asn_leaderboard.json"], generated_at=iso(now))
# ... persist asn_cache.json next to geo_cache.json (run_pipeline.py:118-121 pattern)
```
- **Built AFTER** community + threat_ips are assembled (it consumes their fresh payloads, falling back to the committed prior in `state` if a given input failed its own gate that run). Placed **before** `gate()` (run_pipeline.py:99), so it gets schema validation + last-known-good + triple dual-write for free — like every other payload.

| Failure | Behaviour |
|---|---|
| `IPINFO_TOKEN` missing | Every IP → `unattributed`; `networks: []`, `unattributed_ips = total`. The view shows an honest empty state naming that no network mapping was available. Build still succeeds (an empty leaderboard is valid). |
| IPinfo 5xx / timeout on some IPs | Those IPs → `unattributed` (counted); the rest rank normally. Never fatal (`resolve_asn` swallows, geo.py:69 pattern). |
| A distinct-IP call fails mid-run | Cache holds prior successes; only the failing IP is unattributed this run, retried next run. |
| `community_reports.json` unavailable | Leaderboard still builds from `threat_ips.json` alone (and vice-versa); `sources` reflects what was present. |
| Builder hits a structural error | Returns `None` → `gate()` keeps the **last committed** `asn_leaderboard.json` (the empty-envelope seed guarantees a prior exists from run 1). CI stays green (run_pipeline.py exits 0, line 146). |
| Payload violates schema (leak/oversize) | `gate()` drops it, keeps last-known-good, records a `pipeline_warnings` entry (run_pipeline.py:100-103). Fails **closed** — stale but safe, never leaks. |
| Asset missing at read time | `useStateData` resolves `error`; `AsyncGate` renders the standard honest error (states.tsx:93-107). Rest of the desk still works. |

### 3.7 No-PII (design requirement) — enforced twice, structurally

**Publish exactly:** ASN, ISP name, country, `ip_count`, `report_count`, `categories`, `sources`, `examples` (public IPs) + the envelope counters.
**Never publish (structurally impossible here):** any reporter, `github_id`, `evidence`, `comment`, per-report id or row. Two independent enforcers:
1. **`pipeline/asn.py` never touches identity.** It reads `community_reports.json` — which is *already* PII-stripped by the Phase-3 whitelist projection (community.py:103-110) and never contained a reporter field — and `threat_ips.json`, which has no identity column. It issues **no D1 query** and never sees `github_id`. There is no code path by which a reporter identity could reach the leaderboard.
2. **The schema's `additionalProperties:false`** (both levels, §3.3) makes any stray field fail `validate_payload`, so `gate()` refuses the payload and keeps last-known-good (validate.py:29-30, 46-48). A regression **fails closed**. A test string-searches the serialized payload for forbidden tokens (§7), mirroring `test_community.py:124-141`.

---

## 4. Testing

Repo split: pure logic Python-unit-tested; JSX build-gated (the view is presentational, the logic lives in the builder). `tests/test_asn_leaderboard.py`, mock `fetch`, no network — mirrors `tests/test_community.py`:
- **`parse_org` parity:** `"AS60729 Stiftung Erneuerbare Freiheit"` → `("AS60729", "Stiftung …")`; name-only/empty/`""` → `(None, None)`. A committed fixture `tests/fixtures/asn/org_parity.json` of `org → {asn,isp}` pairs asserts the Python regex agrees with the JS one at `enrich.mjs:367` (same guard style as the `communityKey` parity fixture, test_community.py:118-121).
- **Aggregation:** two IPs on the same ASN → one network row, `ip_count:2`; categories deduped + sorted union; `sources` sorted; `examples` ≤ `EXAMPLE_CAP`; ranked by `ip_count` desc with `asn` tie-break; `count`/`total_abusive_ips`/`unattributed_ips` correct.
- **`report_count` honesty:** an ASN whose IPs came only from `threat_ips` → `report_count:0`, `sources:["abuse.ch"]`; a community IP → `report_count ≥ 1`, and `report_count ≤ ip_count` always.
- **Cache-first / quota:** an IP already in `asn_cache` triggers **no** `fetch` call (assert the stub isn't invoked for cached IPs); a new IP is looked up once and written to the cache; the cache is pruned to IPs seen this run.
- **Unattributed:** a `None` from `resolve_asn` (name-only org / no token / network error) increments `unattributed_ips` and places the IP on **no** fabricated ASN.
- **No-PII fence:** a defensively-mocked community input carrying stray `evidence`/`github_id`/`comment` yields a payload whose serialized JSON contains none of those tokens; an injected extra field fails `validate_payload` (proves the schema fence).
- **Scope switch:** `SOURCES=("community",)` builds a community-only leaderboard with no abuse.ch rows (guards the owner-decision toggle, §3.2/§10).
- **Degradation:** missing token → all-unattributed empty-but-valid payload; a `fetch` raising on every IP → still returns a valid (empty) payload, not a crash; a structural error → `None` (→ last-known-good).
- **Schema round-trip:** a built payload validates against `asn_leaderboard.schema.json`; `SCHEMA_FOR["asn_leaderboard.json"]` is registered (mirrors test_community.py:25-34).
- **Build gates (unchanged, must stay green):** `python -m pytest tests/ -q`; `npm --prefix web ci && npm --prefix web run build` (tsc + Vite — the JSX gate, workflow:86-88); `cd web && npx vitest run …` (the view has no logic branch worth a runtime test; the model is Python-tested).
- **Manual acceptance (owner, on a preview deploy):** run `workflow_dispatch` → confirm `data/state/asn_leaderboard.json` populates (networks ranked, no PII, `unattributed_ips` sane) and `asn_cache.json` grows → open `/desk#networks` on the preview → the leaderboard renders, ordered, with the "not a verdict" framing → unset `IPINFO_TOKEN` locally → confirm the view degrades to the honest empty state.

---

## 5. Acceptance criteria

1. After one pipeline run with `IPINFO_TOKEN` set, `data/state/asn_leaderboard.json` ranks networks by distinct abusive IP count, each row carrying ASN, ISP, `ip_count`, `report_count`, `categories`, `sources`, `examples` — and nothing else (schema `additionalProperties:false`).
2. The dataset contains **no** reporter identity, `github_id`, `evidence`, `comment`, or per-report row — verified by a test and structurally (the builder never reads D1 or identity; its inputs are PII-stripped).
3. ASN/ISP is sourced free from IPinfo's `org` field, cache-first via `asn_cache.json`; only IPs new since the last run cost a call; unresolved IPs are counted in `unattributed_ips`, never given a fabricated ASN.
4. The `/desk#networks` tab renders the committed dataset read-only, no-account, with **no** D1/API call on any request; it states its empty/error reason honestly and frames the ranking as reported volume, not a network verdict.
5. A missing token / IPinfo outage / input-dataset gap degrades to an honest (possibly empty) leaderboard and keeps CI green; a build failure keeps the last committed dataset (`gate()` last-known-good).
6. No change to `lib/enrich.mjs`, `functions/api/enrich.js`, the verdict tally, the community-reports write path, `migrations/`, or `App.tsx`'s route table; no new owner secret.

---

## 6. Anti-drift guardrails

- **If a task wants to add a leaderboard source to `lib/enrich.mjs` / `functions/api/enrich.js`, STOP** — Phase 4 is a *data view*, not a read-path change. It touches no enrich code, no verdict, no tally.
- **If a task wants to query D1 (for ASN, reporters, or anything) from `asn.py` or the web view, STOP** — `asn.py` consumes the already-published, PII-stripped `community_reports.json`/`threat_ips.json`; the view reads a static asset. No D1 anywhere in Phase 4.
- **If a task wants to fabricate an ASN for an unresolved IP, STOP** — unresolved IPs are counted in `unattributed_ips`, never placed on a made-up network (mirrors geo's "drop, never fabricate a coordinate", geo.py:41-45).
- **If a task frames a network as "malicious"/"bad"/a verdict, STOP** — copy is "reported/blocklisted abuse volume hosted on this network," never an accusation against the operator.
- **If a task adds a paid ASN database or a new IPinfo plan, STOP** — the free `org` field on the call we already make is the sourcing mechanism (enrich.mjs:366, geo.py:68).
- **If a task publishes reporter counts per contributor, example evidence, or any per-report detail "for richness", STOP** — HARD no-PII; aggregate network stats only, fenced by the schema.
- **If a task starts Phase 5 (trends over the leaderboard) or Phase 6 (upstream push), STOP** — out of scope; this dataset is only their substrate.
- **Keep the `categories` enum identical to `lib/reporting/validate.mjs` `CATEGORIES`** — drift silently freezes the dataset to last-known-good on the next new-category (same failure mode the community schema guards, community-reports spec §8).

---

## 7. Open owner decisions (flagged — do not guess)

1. **[SCOPE — the one real decision] Leaderboard source scope (§3.2).** Community-only (purest provenance, but currently 3 IPs — a sparse "leaderboard") **vs** community ∪ abuse.ch feed (immediately useful and ranked, per-source attributed via `sources`/`report_count`, but blends allegation with published-blocklist evidence). **Spec recommends the union** with a one-line `SOURCES` switch to fall back to community-only. Owner picks before build.
2. **[MINOR — label] Web surface placement/label (§3.5).** Spec recommends a Data Desk **"Networks"** tab (`/desk#networks`), not a top-level `/leaderboard` route. Label ("Networks" vs "Abuse by network" vs "ASN leaderboard") and tab-vs-route are an owner nicety; the tab is the low-surface-area default.
3. **[MINOR — caps] Publish/example caps.** `CAP=200` networks, `EXAMPLE_CAP=3` example IPs/row — tunable; both sit below the schema's structural `maxItems` backstops.

---

## 8. Self-review (folded in)

A single-pass architectural self-review against the real files; issues found were fixed **inline above** before finalizing. Record:

- **[FIXED] Cache-pruning collision.** An initial sketch shared `geo_cache.json` between geo and ASN; but `build_threat_ips` prunes `geo_cache` to threat IPs only (threat_ips.py:79-82), which would evict community-only IPs every run. Resolved by giving `asn.py` its **own** `asn_cache.json` with its own pruning (§3.1 companion-optimization note, §3.4).
- **[FIXED] Input-freshness ordering.** The builder must consume the *fresh* community/threat payloads when they built this run, else the committed prior — so §3.6 reads `payloads.get(...) or state.get(...)`, and the step is placed after both are assembled but before `gate()`.
- **[FIXED] `report_count` semantics.** Clarified it counts distinct *report-bearing IPs* on the ASN (a network stat, ≤ `ip_count`), **not** a sum of `reporters` — summing per-indicator contributor counts would be a meaningless, potentially inflated figure (§3.4). Kept it envelope-honest like Phase-3's distinct-contributor discipline (community-reports spec §10.1).
- **[FIXED] Category honesty for feed IPs.** abuse.ch rows carry a malware family, not a `category` enum value (threat_ips.py:72); they must not be coerced into the enum. Fixed: feed IPs contribute to `ip_count` but only community IPs contribute `categories` (§3.3, §3.4).
- **[FIXED] `unattributed` vs non-IP indicators.** Domains/URLs/hashes have no ASN by nature; counting them as "unattributed" would be misleading. Fixed: only ipv4/ipv6 enter the resolver; other types are simply out of network scope, not unattributed (§3.4 `_distinct_abusive_ips`).
- **[VERIFIED] Free-tier `org` availability.** The load-bearing claim — that IPinfo returns `org` (ASN + name) on the free tier from `/{ip}/json` — is confirmed by the live read path already parsing it (enrich.mjs:358,366-380), not an assumption; the pipeline already makes this exact call (geo.py:19,68) and merely discards the field.
- **[VERIFIED] Read-path untouched.** Unlike Phase 3, nothing here injects into `enrich()` or adds an enrich source; the surface is a `useStateData` static-asset view (useStateData.ts:23,32), so the Option-A / no-account / no-D1 invariants hold by construction.
- **[VERIFIED] Conveyor fit.** Registering `SCHEMA_FOR` (validate.py:8-19) + adding the payload before `gate()` is exactly how `threat_ips.json` and `community_reports.json` ride the pipeline (run_pipeline.py:92-114); the triple dual-write reaches `web/public/data/state` → Vite → `web/dist` → served asset (workflow:72-88), and `git add data/state` commits both the dataset and the cache (workflow:57).
- **[NOTED — owner] Scope + label** left as explicit owner decisions (§7) rather than guessed.
