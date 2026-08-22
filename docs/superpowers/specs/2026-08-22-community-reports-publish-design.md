# IOC Reporting — Phase 3: Publish approved reports as `SOCDESK_COMMUNITY` (design spec)

**Date:** 2026-08-22 · **Status:** design, pre-implementation · **Author identity:** SaltyCarl (no AI attribution anywhere).
**Predecessors:** Phase 0+1 (`docs/superpowers/specs/2026-08-20-ioc-reporting-phase01-design.md`), Phase 2 moderation console (`docs/superpowers/specs/2026-08-22-admin-moderation-console-design.md`), non-blocking context assembler (`docs/superpowers/specs/2026-08-22-enrich-nonblocking-context-design.md`).

---

## 0. SCOPE BOUNDARY (anti-drift — strict)

**Goal (one sentence).** Publish D1 reports with `status='approved'` as a small, committed/served JSON dataset that the enrich read path consults with a synchronous in-memory lookup, emitting one attributed `kind:"context"` `SOCDESK_COMMUNITY` row (out of the verdict tally) when the looked-up indicator matches.

**In scope.**
- A **D1 → committed-JSON export** step in the existing pipeline (approved rows only, aggregated by indicator).
- The **committed dataset** `data/state/community_reports.json` + its schema, riding the existing gate → dual-write → deploy machinery.
- A **`SOCDESK_COMMUNITY` source** in `lib/enrich.mjs` (`kind:"context"`, no network, no D1) that reads the injected dataset and emits a context row on a match.
- **Loading + injecting** that dataset into `enrich()` from `functions/api/enrich.js` (via the static-asset store, memoized) — no per-lookup D1.
- **Card rendering / attribution / copy** for the community context row (it already routes through the existing context-row path).
- Docs: note the community layer is served from committed JSON; the read path still touches no D1.

**Explicitly OUT of scope (named so the boundary is a fence, not a suggestion).**
- **Phase 4** ISP/ASN abuse-leaderboard (this dataset is the substrate Phase 4 will reuse, but no leaderboard, no ASN aggregation ships here).
- **Phase 5** trends/analytics. **Phase 6** upstream push (AbuseIPDB etc.).
- **Any change to the Phase-2 moderation console** or to the report **write path** (`/api/report`, OAuth, D1 schema, `lib/reporting/*`). Phase 3 is read-only against D1.
- **ANY per-lookup D1 read on the read path.** `/api/enrich` gains **no** `DB` binding. This is the OWNER-DECIDED Option A invariant and is not re-opened.
- **Changing the verdict tally.** Community is `kind:"context"` → excluded from `consulted`/`flagged`/`band` (enrich.mjs:559-570, map.ts:127-131). It NEVER contributes a verdict word.
- **A broader user account / any new sign-in.** The read path stays 100% no-account.
- **No new migration.** The `reports` table and its `idx_reports_ioc` index (migrations/0001_init.sql:8-21) already serve this.

**Files this track OWNS.**
- *Create:*
  - `pipeline/community.py` — D1 REST query + aggregation → the `community_reports.json` payload.
  - `schemas/community_reports.schema.json` — dataset schema; its `additionalProperties:false` is the machine-checked **privacy fence**.
  - `data/state/community_reports.json` — the committed dataset (first commit = empty envelope).
  - `tests/test_community.py` — Python export/aggregation + privacy tests (mock fetch, no network).
  - `lib/__tests__/community.test.mjs` (or additions to `lib/__tests__/enrich.test.mjs`) — the source's match/no-match/copy/normalization behaviour (mock env, no network).
- *Modify:*
  - `lib/enrich.mjs` — add `SOCDESK_COMMUNITY` to `SOURCES`; add the shared `communityKey()` normalizer.
  - `functions/api/enrich.js` — load `community_reports.json` from the asset store (memoized per isolate) and inject it into the enrich env; **no D1 binding added**.
  - `run_pipeline.py` — call `build_community_reports(...)`, add its payload before `gate()`, thread the D1 env.
  - `pipeline/validate.py` — register `SCHEMA_FOR["community_reports.json"]`.
  - `.github/workflows/collect-and-deploy.yml` — add the D1 secrets to the `run_pipeline.py` step env.
  - `README.md` / `CLAUDE.md` — one-line note: community layer served from committed JSON; read path still no-D1.

**Interfaces / dependencies.** Cloudflare **D1 REST query API** (read-only); the existing `gate()` schema-validate + last-known-good fallback + dual-write (pipeline/validate.py:35-50, run_pipeline.py:83-98); the shared `validate()` indicator normalizer (enrich.mjs:76-95); the context-row routing in map.ts:128 and `contextLine` in doctrine.ts:311; the Pages Functions **static-asset (`ASSETS`) binding**.

**Acceptance criteria.** See §7. **Anti-drift guardrails.** See §8.

---

## 1. Doctrine / invariants (binding)

1. **Read path stays no-account and no-D1.** `/api/enrich` reads a static, committed JSON — never D1, never a login. (enrich.js:26-47 gains only a static-asset read.)
2. **Community is CONTEXT, never a verdict.** The row is `kind:"context"` → excluded from the tally and the band, exactly like ipinfo/RDAP/OTX today. SOCDesk emits no verdict word; it states an attributed count. (docs/VERDICT-LANGUAGE — the "count what sources reported, never synthesize" rule.)
3. **Attributed + contributor-count language.** Copy says "Reported by N contributor(s) (owner-moderated) · <categories> · latest <date>" — a **distinct-contributor** count (`COUNT(DISTINCT github_id)`), never "this is malicious", and never a raw report `COUNT(*)` that one re-reporting accuser could inflate. Inherits the Phase-1 evidence-required + Phase-2 moderation controls; only `status='approved'` rows publish.
4. **HARD privacy fence.** The published dataset carries **only** indicator, type, category set, distinct-contributor count, first/latest dates. **Never** `id`, `github_id`, `evidence`, or `comment` (nor `login`, which isn't a `reports` column). Enforced twice: the export SELECT names no id column and reads `github_id` only inside `COUNT(DISTINCT …)` (no value projected), and the schema's `additionalProperties:false` makes any leak fail `gate()`.
5. **Free-tier only.** D1 REST reads are free; no paid dependency. No new site surface that itself reads D1.
6. **Honest degradation.** A D1 outage or missing token never blanks the layer or fails CI — `gate()` keeps last-known-good; a missing dataset at read time simply omits the row (never an error, never `partial`).

---

## 2. Architecture at a glance

```
D1 (reports, status='approved')
      │  (twice-hourly, GitHub Actions — Python)
      ▼
pipeline/community.py  ──D1 REST query──►  aggregate by indicator
      │                                     (distinct reporters, categories[], first/latest date)
      ▼
run_pipeline → gate() (schema + last-known-good) → dual-write
      │
      ├─ data/state/community_reports.json           (committed to git)
      └─ web/public/data/state/community_reports.json (→ Vite → web/dist/... → deployed asset)
                                                              │
                                                              ▼  served at /data/state/community_reports.json
functions/api/enrich.js  ──env.ASSETS.fetch (memoized per isolate)──►  parsed map
      │  injected as env.SOCDESK_COMMUNITY_DATA
      ▼
lib/enrich.mjs  SOCDESK_COMMUNITY source  ──synchronous map lookup──►  kind:"context" row (on match)
      ▼
map.ts mapContext → ContextRow → escalation card "CONTEXT (not a verdict)"
```

The whole loop reuses machinery that already exists for `threat_ips.json` (the one other reputation-adjacent committed dataset, publish.py:83-92, threat_ips.py, threat_ips.schema.json). Phase 3 adds one more payload to that same conveyor.

---

## 3. Key design decisions (each with a recommendation)

### 3.1 The D1 → committed-JSON export mechanism (the crux) — **RECOMMEND (a): a Python step in the pipeline that queries the D1 REST API**

The pipeline is Python-in-GitHub-Actions (run_pipeline.py); the write substrate is Cloudflare D1. Three candidates:

- **(a) Pipeline queries D1 REST directly.** A new `pipeline/community.py` issues one `POST` to the D1 query endpoint using the CI secrets already present for deploy, and returns the aggregated payload. **← RECOMMENDED.**
- **(b) A dedicated Pages Function export endpoint that reads D1, fetched by the pipeline.** Rejected: it re-introduces a D1-reading HTTP surface (public → leaks aggregate shape and invites scraping; owner-gated → the pipeline must carry a session), plus a per-fetch edge D1 read and a new Function to test/secure. More moving parts for no gain.
- **(c) `wrangler d1 export`/CLI in a Node step.** Rejected: dumps the whole table (including `evidence`/`comment`/`github_id`) into the runner before we filter — the PII would transit CI logs/artifacts. Direct REST with a projecting SELECT never materializes PII.

**Mechanism (a), concrete.**

D1 REST query endpoint:
```
POST https://api.cloudflare.com/client/v4/accounts/{CLOUDFLARE_ACCOUNT_ID}/d1/database/{CLOUDFLARE_D1_DATABASE_ID}/query
Authorization: Bearer {CF_D1_READ_TOKEN}
Content-Type: application/json

{ "sql": "SELECT ioc_type, ioc_value,
                 COUNT(DISTINCT github_id) AS reporters,
                 GROUP_CONCAT(DISTINCT category) AS categories,
                 MIN(created_at) AS first_at, MAX(created_at) AS latest_at
          FROM reports
          WHERE status = 'approved'
          GROUP BY ioc_type, ioc_value" }
```
The SELECT aggregates at the **indicator level** (not per-category), so the reporter count is a true per-indicator distinct: `COUNT(DISTINCT github_id)` — **the row surfaces distinct contributors, never a raw `COUNT(*)` that a T1 would misread as N independent corroborations** (owner-approved amendment, §10.1). `github_id` is read **only inside `COUNT(DISTINCT …)`** — no id VALUE is ever projected, so it cannot leave D1; the privacy fence holds (§3.6.1). `GROUP_CONCAT(DISTINCT category)` (SQLite/D1, comma-separated) yields the distinct category set in the same grouped query — category enum values contain no commas, so the split is unambiguous. `evidence`, `comment`, `id`, and the raw `github_id` value are never named. `pipeline/community.py` then, per indicator: splits `categories` (dedupe + sort), takes `reporters` directly (no cross-category fold needed — the count is already indicator-level), slices the dates to `YYYY-MM-DD`, and canonicalizes the key (§3.5).

**Auth / owner-config.** Reuse `CLOUDFLARE_ACCOUNT_ID` (already a secret) — but it is currently referenced **only in the deploy step** (collect-and-deploy.yml:95), so the build task must **add it to the "Run collectors" step env too** (collect-and-deploy.yml:40-43), or `build_community_reports` can't construct the D1 URL. Add **two** new secrets:
- `CLOUDFLARE_D1_DATABASE_ID` — the database id.
- `CF_D1_READ_TOKEN` — a **dedicated least-privilege token scoped to D1 → Read only**. *Recommended over widening the existing `CLOUDFLARE_API_TOKEN`* so the deploy token stays single-purpose (a leaked deploy token can't read the DB, and vice-versa) — matching the least-privilege discipline already in the repo. If the owner prefers one token, widening `CLOUDFLARE_API_TOKEN` to include D1:Read also works; the spec's code reads `CF_D1_READ_TOKEN` with a fallback to `CLOUDFLARE_API_TOKEN`.

**Where it runs.** Add the **three** env vars (`CLOUDFLARE_ACCOUNT_ID` + the two new secrets) to the existing **"Run collectors"** step (collect-and-deploy.yml:40-43, alongside `IPINFO_TOKEN`). `run_pipeline.run()` calls `build_community_reports(fetch=http_fetch, now=now, env=os.environ)`; on success it sets `payloads["community_reports.json"]` **before** `gate()` (run_pipeline.py:83), so the payload gets schema validation, the last-known-good fallback, and the triple dual-write (out_dir / state_dir / web_dir) for free — identical to every other payload (run_pipeline.py:93-98). **Net-new plumbing (not a one-liner):** `run_pipeline.py` today imports no `os` and `run()` takes no env arg (run_pipeline.py:1-13, 51, 126-129) — the build task adds `import os` and threads `env=os.environ` into the new call. CI ordering already holds: collectors/export (dual-writes `web/public`) runs before the Vite build (copies `web/public`→`web/dist`), so the fresh JSON is deployed as an asset.

**JSON shape (keyed by normalized indicator for O(1) lookup).**
```json
{
  "generated_at": "2026-08-22T14:41:00Z",
  "schema_version": 1,
  "attribution": "Community-submitted abuse reports from SOCDesk contributors, owner-moderated. Counts of reports, not independent confirmations; a report is an allegation reviewed before publication, not a verdict.",
  "count": 2,
  "report_count": 5,
  "indicators": {
    "ipv4|203.0.113.4": {
      "type": "ipv4",
      "value": "203.0.113.4",
      "reporters": 2,
      "categories": ["brute-force", "ssh"],
      "first_reported": "2026-08-10",
      "latest_reported": "2026-08-20"
    },
    "domain|evil.example": {
      "type": "domain", "value": "evil.example", "reporters": 1,
      "categories": ["phishing"], "first_reported": "2026-08-18", "latest_reported": "2026-08-19"
    }
  }
}
```
- `indicators` is an **object map** (not an array like threat_ips) because the read path needs O(1) lookup by the looked-up indicator; the envelope (`generated_at`/`schema_version`/`attribution`/`count`) follows the existing convention (publish.py:13, threat_ips.py:90-98).
- **`reporters`** = `COUNT(DISTINCT github_id)` — the number of **distinct contributors** who reported this indicator (owner-approved amendment §10.1). It is the honest metric: at `1` it reads "reported by 1 contributor" (a single source, not implied corroboration). The raw `COUNT(*)` report count is **deliberately NOT** carried per-indicator — surfacing it would let one re-reporting accuser read as many, since write-path dedup only fires on still-`queued` same-author rows (db.mjs:24-28) and there is no `(github_id, ioc_value)` unique constraint.
- `categories` is the **distinct union** across that indicator's approved reports, sorted for stable diffs. Dates are `YYYY-MM-DD` (sliced from `created_at`).
- `report_count` (envelope only) = total approved reports across all indicators (a bare integer, no PII) — an aggregate volume figure, never rendered on a card.

**Scale.** Crowdsourced + human-moderated + single owner → tens to low-thousands of indicators for a long time. The schema caps `indicators` at `maxProperties: 5000` and the pipeline's existing `MAX_PAYLOAD_BYTES = 8_000_000` gate (validate.py:32) is the backstop. Each entry is ~6 short fields, so 5000 entries ≈ well under 1 MB. If the cap is ever approached, Phase 4's aggregation supersedes the raw map.

### 3.2 How `SOCDESK_COMMUNITY` slots into the enrich assembler — **RECOMMEND: a `SOURCES` entry, `kind:"context"`, BLOCKING, dataset injected via a spread env**

It rides the same plan → dispatch → collect → assemble path every source uses (enrich.mjs:581-709). The source definition:
```js
const SOCDESK_COMMUNITY = {
  name: "SOCDesk Community",
  types: ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"],
  key: "SOCDESK_COMMUNITY_DATA",   // env slot carries the injected parsed map, not a secret
  optionalKey: true,               // usable even when absent → then it no-ops
  kind: "context",                 // excluded from the tally + band (enrich.mjs:560, map.ts:127)
  // BLOCKING (default): a synchronous in-memory lookup resolves in the dispatch
  // tick, so it adds ZERO fan-out latency and — unlike a non-blocking source —
  // is never subjected to the grace-race drop. It has no network and no failure
  // mode, so it can never set `partial`.
  link: "https://socdesk.io/about#community-reports",
  async run(_fetchImpl, ind, data) {
    const map = data && data.indicators;           // injected dataset (see §3.3)
    if (!map) return undefined;                    // dataset absent → omit, never an error
    const hit = map[communityKey(ind.type, ind.value)];
    if (!hit) return undefined;                    // no report for this indicator → omit
    const cats = (hit.categories ?? []).join(", ");
    const n = hit.reporters ?? 0;
    return {
      name: SOCDESK_COMMUNITY.name,
      kind: "context",
      verdict: "unknown",                          // context — never votes
      headline:
        `Reported by ${n} contributor${n === 1 ? "" : "s"} ` +
        `(owner-moderated)` + (cats ? ` · ${cats}` : "") +
        (hit.latest_reported ? ` · latest ${hit.latest_reported}` : ""),
      facts: [
        ["Contributors", String(n)],
        ["Reported for", cats || "—"],
        ["First reported", hit.first_reported ?? "—"],
        ["Latest reported", hit.latest_reported ?? "—"],
        ["Source", "SOCDesk contributors · owner-moderated"],
      ],
      url: SOCDESK_COMMUNITY.link,
    };
  },
};
```
Appended to the `SOURCES` array (enrich.mjs:539). Because `run()` **returns `undefined` on no-match**, the assembler's `slots.filter(Boolean)` (enrich.mjs:685) drops it for the ~all indicators with no community report — the card is never cluttered with "no community reports on this". Third `run` arg is `env[s.key]` = `env.SOCDESK_COMMUNITY_DATA` (dispatchSources, enrich.mjs:628), so the dataset arrives through the existing injection channel with **no signature change** to any other source.

*Rejected alternative:* appending the row directly in `assemble()`. It would bypass the uniform source contract (types-applicability, ordering, skip/error accounting) that every other source rides; keeping it a `SOURCES` entry means it obeys the same rules and tests as ipinfo/OTX.

### 3.3 Loading + injecting the dataset (the Function wrapper) — **RECOMMEND: `env.ASSETS.fetch`, memoized per isolate, spread into a derived env**

`functions/api/enrich.js` loads the committed dataset from the deployment's **static-asset store** and injects it, WITHOUT touching D1:
```js
let _communityCache;   // module scope = per-isolate memo; caches ONLY successful loads
async function loadCommunity(env, origin) {
  if (_communityCache !== undefined) return _communityCache;   // success previously memoized
  try {
    const req = new Request(`${origin}/data/state/community_reports.json`);
    const res = env.ASSETS ? await env.ASSETS.fetch(req) : await fetch(req);
    if (res.ok) { _communityCache = await res.json(); return _communityCache; }
  } catch { /* fall through */ }
  return null;                                                 // transient miss → NOT memoized; retried next request
}
// ... in onRequestGet, before enrich():
const community = await loadCommunity(env, url.origin);
const result = await enrich(fetch, type, q, { ...env, SOCDESK_COMMUNITY_DATA: community });
```
- **`env.ASSETS.fetch`** reads from the local deployment asset store (no external network), with a same-origin `fetch` fallback if `ASSETS` is unbound. **Only a successful parse is memoized** — a transient failure returns `null` **without** poisoning the module-scope cache, so the next request retries rather than omitting community rows for the isolate's whole life (Infra review). A warm isolate that has loaded once does the read **once**, not per request.
- The dataset is spread into a **derived env** (`{ ...env, ... }`) — the real secrets object is never mutated. `SOCDESK_COMMUNITY_DATA` is the parsed object (or `null`); the source no-ops on `null`.
- **`enrich.js` gains no `DB` binding** — confirming the Option-A invariant. The only new capability the Function needs is the (default) `ASSETS` binding.

**Latency answer (design Q2).** The dataset LOAD is one cheap, memoized, local asset read in the Function wrapper — outside the source fan-out, so it never interacts with the blocking/grace machinery. The SOURCE itself is a pure synchronous map lookup that resolves in the dispatch tick as a BLOCKING source, adding **zero** measurable latency. Net effect on the card's latency floor: negligible.

*Considered alternative:* `import communityData from "../../data/state/community_reports.json"` bundled into the Function at deploy. It would also refresh each deploy, but couples read-path code to the data file, bloats every isolate's code with a growing JSON, and complicates the Node test harness. `ASSETS.fetch` keeps `lib/enrich.mjs` pure (data injected like `fetchImpl`/`env`) and lets the data refresh with the asset. **Prefer `ASSETS.fetch`.**

### 3.4 What the community row shows (copy + labelling)

Rendered through the **existing context path** — `map.ts` `mapContext` (line 111-118) keeps `name`/`finding`/`facts`/`url`; it appears in the card's **"CONTEXT (not a verdict)"** section and in the escalation copy-out via `contextLine` → `• SOCDesk Community — <finding>` (doctrine.ts:311, 341). No new card component required; it renders like ipinfo/RDAP today.

- **name:** `SOCDesk Community`.
- **finding/headline:** `Reported by 2 contributors (owner-moderated) · brute-force, ssh · latest 2026-08-20`.
- **facts:** Contributors / Reported for / First reported / Latest reported / Source (as above).
- **url:** a **public transparency page** `https://socdesk.io/about#community-reports` explaining what the community dataset is, that every entry is owner-moderated, the count-**not**-verdict framing, **and a dispute/removal contact** (an un-approve drops the entry at the next ~30-min export via `WHERE status='approved'` — the page names how to request it). It deliberately does **not** deep-link to any per-report page — that would expose reporters (privacy fence). This satisfies enrich's "verify link always present" rule (enrich.mjs:20-21) by pointing at the dataset's provenance + methodology + redress path.
- **Source-class label:** none. Context rows carry no `SourceClass` (mapContext assigns none; `sourceClassFor` is never called for context — doctrine.ts:39). If the row were ever mis-rendered as a scored source, `sourceClassFor("SOCDesk Community")` would fall to `unclassified` (never `score`) — but `kind:"context"` keeps it out of that path entirely.

### 3.5 Indicator normalization / matching — **shared `communityKey()` on BOTH sides**

The export key and the enrich lookup must be byte-identical. Both derive from the **same `validate()` normalization** the write path already applied (enrich.mjs:76-95): domain/ipv6 lowercased, URL via `new URL().href`, ipv4 unchanged. The one gap: `validate()` does **not** lowercase hashes (enrich.mjs:94), so `AAAA…`/`aaaa…` are distinct in D1 and would miss on lookup. `communityKey()` closes it on both sides:
```js
// lib/enrich.mjs (exported for reuse + tests)
const HASH_TYPES = new Set(["md5", "sha1", "sha256"]);
export function communityKey(type, value) {
  const v = HASH_TYPES.has(type) ? String(value).toLowerCase() : String(value);
  return `${type}|${v}`;
}
```
- **Python export** builds the same key from D1's stored `(ioc_type, ioc_value)` — which is `validate()`-normalized on write — additionally lowercasing hashes. (A one-line Python mirror of `communityKey`; the two are unit-tested to agree on a shared fixture set of type/value pairs.)
- **JS lookup** calls `communityKey(ind.type, ind.value)` where `ind.value` is already `validate()`-normalized (enrich.mjs:724).
Handled consistently: **ipv4** exact; **ipv6/domain** lowercased (validate); **url** `URL.href`-normalized (validate); **md5/sha1/sha256** lowercased by `communityKey`. This normalization equivalence is a named acceptance test (§7).

### 3.6 Freshness / propagation (design Q4) — **acceptable; messaged via recency + envelope**

Timeline of an approval reaching the card:
1. Owner approves in the Phase-2 console → D1 row flips to `approved`.
2. Next pipeline run (cron `11,41 * * * *`, twice hourly — collect-and-deploy.yml:5) exports it, commits `data/state`, builds, deploys the asset.
3. `/api/enrich` for that indicator reflects it after the response **edge cache** (`public, max-age=900` — 15 min, enrich.js:20) expires for that key, plus the warm-isolate memo (`_communityCache`) lifetime.

**Worst case ≈ 30 min (pipeline) + up to 15 min (enrich cache) ≈ 45 min** from approval to appearing on an already-cached indicator; a first-time lookup after deploy sees it immediately. This is **acceptable**: approval is already a deliberate human gate, not a real-time event, and every other enrich datum carries the same 15-min cache staleness. **Messaged** by (a) the per-row `Latest reported` date (recency), and (b) the dataset envelope's `generated_at` (the card can surface "community data as of …"). No "live" claim is made anywhere. *(Isolate-memo caveat: `_communityCache` persists for the isolate's life; because the whole deployment — Functions + assets — is replaced on each deploy, a redeploy starts fresh isolates, so the memo never serves data older than the current deployment.)*

### 3.6.1 Privacy (design Q6) — **HARD requirement, enforced twice**

**Publish exactly:** indicator `value`, `type`, distinct `categories`, `reporters` (distinct-contributor count), `first_reported`, `latest_reported` (+ envelope `generated_at`/`schema_version`/`attribution`/`count`/`report_count`).
**Never publish:** `id` (the per-report UUID PK), `github_id`, `evidence`, `comment`, or any reporter-identifying field or raw per-report row. (`login` is not even a `reports` column — it lives on `accounts`, reachable only via a `JOIN accounts` on `github_id` the SELECT never performs.)

Two independent enforcers, so a single mistake cannot leak:
1. **The export SELECT projects only aggregate columns** (§3.1) — `id`/`evidence`/`comment` are never named. `github_id` appears **only** inside `COUNT(DISTINCT github_id)`: the aggregate reads the column to count distinct values but projects **no id value** into the result set, so no reporter identity leaves D1 — the one carve-out to "the SELECT never reads those columns" (it counts `github_id`, never emits it).
2. **The schema's `additionalProperties:false`** on each indicator entry (and on the envelope) makes any stray field fail `validate_payload`, so `gate()` refuses the payload and keeps last-known-good (validate.py:35-50). A privacy regression therefore **fails closed** (stale-but-safe), never leaks.
`evidence` in particular can contain internal IPs/hostnames/log excerpts (the Phase-1 "don't paste sensitive data" hint acknowledges this) — it must never approach the published file. A test asserts the payload's JSON contains none of the forbidden keys (§7).

---

## 4. Schema (`schemas/community_reports.schema.json`)

Modeled on `threat_ips.schema.json`, with `indicators` as a constrained object map:
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["generated_at", "schema_version", "attribution", "count", "indicators"],
  "properties": {
    "generated_at": {"type": "string"},
    "schema_version": {"type": "integer"},
    "attribution": {"type": "string", "maxLength": 1000},
    "count": {"type": "integer", "minimum": 0},
    "report_count": {"type": "integer", "minimum": 0},
    "indicators": {
      "type": "object",
      "maxProperties": 5000,
      "additionalProperties": {
        "type": "object",
        "additionalProperties": false,
        "required": ["type", "value", "reporters", "categories", "first_reported", "latest_reported"],
        "properties": {
          "type": {"enum": ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"]},
          "value": {"type": "string", "minLength": 1, "maxLength": 2048},
          "reporters": {"type": "integer", "minimum": 1},
          "categories": {
            "type": "array", "minItems": 1, "maxItems": 10,
            "items": {"enum": ["brute-force","ssh","port-scan","web-app-attack","phishing","malware-c2","scanner","spam","exploited-host","other"]}
          },
          "first_reported": {"type": "string", "pattern": "^\\d{4}-\\d{2}-\\d{2}$"},
          "latest_reported": {"type": "string", "pattern": "^\\d{4}-\\d{2}-\\d{2}$"}
        }
      }
    }
  }
}
```
The `categories` enum is `lib/reporting/validate.mjs`'s `CATEGORIES` (validate.mjs:4-7) verbatim — kept in lockstep so a new category doesn't silently fail the gate. `additionalProperties:false` at both levels is the privacy fence.

Register it: `SCHEMA_FOR["community_reports.json"] = "community_reports.schema.json"` (validate.py:8-18).

---

## 5. Failure modes / honest degradation

| Failure | Behaviour |
|---|---|
| D1 REST unreachable / 5xx / token missing | `build_community_reports` returns `None`; run_pipeline does not set the payload; `gate()` keeps the **last committed** `community_reports.json` (prior snapshot). CI never fails (run_pipeline exits 0 — line 130). |
| First run ever, D1 unreachable | The **committed seed** `data/state/community_reports.json` (an empty envelope, `indicators: {}`, committed with the first PR — §0 owned-files) IS the last-known-good, so `gate()` always has a prior to keep from run 1. *(This is the mechanism — `build_community_reports` returning `None` with no committed prior would write nothing; the seed guarantees there is always a prior. The builder must never publish the empty seed by *overwriting* a good snapshot — it only returns `None`, letting `gate()` retain whatever is committed.)* |
| Payload violates schema (e.g. a leaked field, oversize) | `gate()` drops it, keeps last-known-good, records a `pipeline_warnings` entry in health.json (run_pipeline.py:84-86). Fails **closed**. |
| Asset missing / unparseable at read time | `loadCommunity` returns `null`; the source no-ops; enrich returns normally with no community row. Never an error, never `partial`. |
| No community report for the indicator | `run()` returns `undefined` → row omitted. The 99.99% case. |

Community is never a blocking-failure source (no network, no key requirement), so it can never poison the enrich edge cache via `partial`.

---

## 6. Testing

Following the repo split (pure logic unit-tested; infra integration/manual):
- **Python (`tests/test_community.py`, vitest-equivalent pytest, mock fetch):**
  - Aggregation: a D1 result grouped by indicator yields one entry per indicator; `reporters` = the `COUNT(DISTINCT github_id)` the query returned (taken directly, **not** summed across categories); `categories` = the `GROUP_CONCAT(DISTINCT category)` string split, deduped, sorted; dates sliced to `YYYY-MM-DD` from the `MIN`/`MAX` `created_at`.
  - **Distinct-contributor honesty:** two approved rows for the same indicator from the **same** `github_id` (e.g. a re-report after approval) yield `reporters: 1`, not 2 — proving the metric can't be inflated by one re-reporting accuser.
  - Key canonicalization: mixed-case hashes collapse to one lowercased key; domain/ipv6 lowercased; ipv4 unchanged; url via href.
  - **Privacy:** given D1 rows carrying `evidence`/`comment`/`github_id`/`id`, the serialized payload contains **none** of those keys/values (string-search the JSON).
  - **Schema-enum parity:** the schema's `categories` enum equals `lib/reporting/validate.mjs` `CATEGORIES` exactly (a committed shared fixture both suites read) — a drift would silently freeze the whole dataset to last-known-good when a new category is approved.
  - Degradation: a fetch raising / non-200 yields `None` (→ last-known-good), not a crash.
  - Schema round-trip: a built payload validates against `community_reports.schema.json`; a payload with an injected extra field **fails** (proves the fence).
- **JS (`lib/__tests__/community.test.mjs`, mock env, no network):**
  - Match → one `kind:"context"` row with `verdict:"unknown"`, headline `Reported by N contributor(s) …` (singular/plural correct), facts led by `Contributors: N`, url = the transparency page; the tally (`consulted`/`flagged`/`band`) is **unchanged** vs. the same lookup without community data (proves out-of-tally).
  - No-match / absent dataset → **no** community row, no error, `partial` unchanged.
  - `communityKey` parity: JS and the Python mirror agree on a shared fixture of `[type, value] → key` pairs (a committed fixture both suites read).
  - Instant/blocking: the row is present in the awaited (blocking) result deterministically (never grace-dropped).
- **Build gates (unchanged, must stay green):** `python -m pytest tests/ -q`; `npm --prefix web run build`; `cd web && npx vitest run ../shared src ../lib`.
- **Manual acceptance (owner, on a preview deploy):** approve a report in Phase-2 → run `workflow_dispatch` → confirm `data/state/community_reports.json` gains the entry (no PII) → look the indicator up on the preview → the community context row renders, out of the tally; look up an unreported indicator → no community row; confirm `/api/enrich` still works with **no D1 binding** on the Function.

---

## 7. Acceptance criteria

1. A report with `status='approved'` in D1 appears in `data/state/community_reports.json` after one pipeline run, aggregated by indicator, carrying **only** type/value/categories/`reporters`(distinct-contributor count)/dates; two approved rows from the same `github_id` yield `reporters:1`.
2. The published dataset contains **no** `id`, `github_id`, `evidence`, or `comment` (and no `login`) — verified by a test and by the schema's `additionalProperties:false`.
3. Looking up a reported indicator via `/api/enrich` returns a `SOCDESK_COMMUNITY` row with `kind:"context"`; `consulted`/`flagged`/`band` are **identical** to the pre-Phase-3 result (out of tally).
4. Looking up an unreported indicator returns **no** community row and no error.
5. `/api/enrich`'s Function has **no `DB` binding**; a D1 outage during a pipeline run leaves the previous community dataset served and CI green.
6. Indicator matching is normalization-correct across ipv4/ipv6/domain/url and mixed-case hashes (shared `communityKey`).
7. The community row renders in the card's context section and in the escalation copy-out as an attributed, owner-moderated **distinct-contributor count** ("Reported by N contributor(s)"), never a verdict; its verify link points at the public transparency page (with a dispute/removal contact), not a per-report page.
8. All existing build/test gates stay green; no new migration; no change to the write path or moderation console.

---

## 8. Anti-drift guardrails

- **If a task wants to read D1 from `/api/enrich`, STOP** — that is the rejected per-lookup path; Option A is a committed static dataset. The Function reads an asset, never D1.
- **If a task wants community to affect the tally/band/verdict, STOP** — it is `kind:"context"`, out of the tally, forever. No verdict word.
- **If a task wants to publish evidence/comment/reporter fields "for richness", STOP** — the privacy fence is a hard requirement enforced by the SELECT and the schema.
- **If a task starts building the ASN/ISP leaderboard, trends, or upstream push, STOP** — Phases 4/5/6, out of scope. This dataset is only their substrate.
- **If a task adds a new sign-in or account surface, STOP** — the read path stays no-account.
- **If a task edits `lib/reporting/*`, the moderation console, or `migrations/`, STOP** — Phase 3 is read-only against D1 and adds no migration.
- **Keep `communityKey` identical in Python and JS** — a divergence silently breaks matching; the parity fixture test guards it.
- **Keep the schema `categories` enum identical to `lib/reporting/validate.mjs` `CATEGORIES`** — a drift silently freezes the *entire* dataset to last-known-good the moment a report with the new category is approved (fail-closed but total); the enum-parity test guards it.
- **If a task wants to surface a raw `COUNT(*)` report count on the card, STOP** — the rendered metric is `COUNT(DISTINCT github_id)` ("N contributors"); raw report volume lives only in the non-rendered envelope. Showing raw count lets one re-reporting accuser read as many (owner ruling §10.1).

---

## 9. Open owner-config (inert until set — same posture as the enrich keys)

- `CLOUDFLARE_D1_DATABASE_ID` (Actions secret) — the reports DB id.
- `CF_D1_READ_TOKEN` (Actions secret) — a D1 **Read-only** API token (recommended), or widen `CLOUDFLARE_API_TOKEN` to include D1:Read.
- **Wire `CLOUDFLARE_ACCOUNT_ID` into the "Run collectors" step env** (it exists as a secret but is currently only in the deploy step) — required for the D1 REST URL. No new secret; a workflow-file change the build task makes.
- Confirm the **`ASSETS` binding** resolves on a preview deploy (mirrors the Phase-0 "confirm the D1 binding on preview" caveat) — a bad/absent binding falls back to same-origin `fetch`, but validate before trusting.
- Publish the `/about#community-reports` transparency section (the verify link target) — a short static page: what the dataset is, that every entry is owner-moderated, the count-**not**-verdict framing, and a **dispute/removal contact** (how to request an entry be un-approved → dropped at the next export).

Until these exist, `build_community_reports` no-ops to last-known-good/empty and the read path simply shows no community rows — the site behaves exactly as it does today.

---

## 10. Panel review amendments (APPROVED 2026-08-22)

Three-specialist panel (SOC Analyst · Infrastructure · Data-pipeline), each verifying against real file:line. Infra + Data returned SHIP-TO-BUILD; SOC returned REVISE-THEN-BUILD on one major. All changes below are folded into §§1–9 above; this section is the authoritative change record.

### 10.1 [MAJOR, owner-approved] Rendered metric = distinct contributors, not raw report count
The row surfaces **`COUNT(DISTINCT github_id)`** ("Reported by N contributor(s)"), **not** `COUNT(*)`. A raw report count is a foreseeable corroboration-mislead: a T1 reads "3 reports" as 3 independent sources, but write-path dedup only fires on still-`queued` same-author rows (db.mjs:24-28) and there is no `(github_id, ioc_value)` unique constraint (migrations/0001_init.sql), so one re-reporting accuser can inflate `COUNT(*)`. Distinct-contributor count is the honest metric — at `1` it reads as a single source. **Owner decision:** adopt distinct contributors, no minimum-reporter threshold (a solo legitimate report still surfaces, honestly labeled). Raw volume survives only as the non-rendered envelope `report_count`. The aggregate reads `github_id` only inside `COUNT(DISTINCT …)`, so no reporter id is projected — privacy fence intact (§3.6.1 carve-out). SQL moved to indicator-level `GROUP BY ioc_type, ioc_value` with `GROUP_CONCAT(DISTINCT category)` for the category set (§3.1).

### 10.2 Minors folded in
- **[Data]** `id` (per-report UUID PK) added to the never-publish list (§1.4, §3.6.1, §7.2) — already mechanically fenced, now named.
- **[Data]** `login` clarified as an `accounts` column, not `reports` — the SELECT reaches it via no join (§3.1, §3.6.1).
- **[Data]** First-run empty-envelope guaranteed by the **committed seed**, not builder logic (§5) — builder returns `None`, never overwrites a good snapshot.
- **[Data]** Schema date fields gain `"pattern":"^\\d{4}-\\d{2}-\\d{2}$"` (§4).
- **[SOC+Data]** Schema `categories` enum ↔ `validate.mjs` `CATEGORIES` **parity test** added (§6, §8) — a drift silently freezes the whole dataset to last-known-good on the next new-category approval.
- **[SOC]** `/about#community-reports` transparency page must carry a **dispute/removal contact** (§3.4, §9).
- **[Infra]** `functions/api/enrich.js` memoizes **successful loads only** — a transient first-request blip returns `null` without poisoning the isolate cache (§3.3).
- **[Infra]** `CLOUDFLARE_ACCOUNT_ID` must be added to the **"Run collectors" step env** (currently deploy-step only) for the D1 REST URL (§3.1, §9).
- **[Infra+Data]** `run_pipeline.py` env-threading is **net-new plumbing** (`import os`, `run()` gains an env arg) — not a one-liner (§3.1).

### 10.3 Verified sound by the panel (no change needed)
- **No-clutter self-omission** (the seeded top risk): `optionalKey:true` + no `blocking:false` → the source is **dispatched, not skipped** (enrich.mjs:583-586, 628), `run()` returns `undefined` on absent/no-match, `slots.filter(Boolean)` drops it (enrich.mjs:685) — no "not configured" row on the 99.99% clean lookups.
- **Out-of-tally:** `kind:"context"` excluded from `consensus`/`band` server-side (enrich.mjs:560) and client-side (map.ts:127-131, the authoritative path); copy-out via doctrine.ts:311/341.
- **Render path:** the existing `ContextList` renders a standalone context source generically (ui.tsx:227-255) — no new component.
- **`env.ASSETS` + asset landing:** default Pages-Functions binding; `data/state/*.json` reaches `web/dist` via Vite's default `publicDir` copy (dual-write to `web/public/data/state`), served static; cache can't be poisoned (community never sets `partial`).
- **Migration truths:** `category` single-valued `TEXT NOT NULL`; `created_at` ISO-8601 TEXT (sortable, `[0:10]`-sliceable); `gate()` needs only the mandatory `SCHEMA_FOR` registration.
- **Normalization:** the only residual gap is hash-lowercasing (`communityKey`'s job); ipv6 `::`-compression is a pre-existing `validate()` property, consistent on both sides — no regression.
