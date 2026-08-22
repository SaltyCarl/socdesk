# Community Reports Publish (IOC-Reporting Phase 3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish D1 reports with `status='approved'` as a small committed/served JSON dataset that the enrich read path consults with a synchronous in-memory lookup, emitting one attributed `kind:"context"` `SOCDESK_COMMUNITY` row (out of the verdict tally) when the looked-up indicator matches.

**Architecture:** A new Python pipeline step (`pipeline/community.py`) queries the Cloudflare D1 REST **query** API read-only with a projecting, indicator-level aggregating SELECT, and returns a committed `data/state/community_reports.json` payload that rides the existing `gate()` → dual-write → deploy conveyor (identical to `threat_ips.json`). At read time, `functions/api/enrich.js` loads that committed static asset (memoized per isolate, **no `DB` binding**) and injects it into `enrich()`, where a new `SOCDESK_COMMUNITY` source does a synchronous map lookup and returns a `kind:"context"` row on a match. No per-lookup D1, no new migration, no change to the write path or moderation console.

**Tech Stack:** Python 3.12 + `httpx` (pipeline, via the injected `http_fetch`); `jsonschema` Draft 2020-12 (the `gate()`); pure-ESM `lib/enrich.mjs` (Node/Workers, no bindings); Cloudflare Pages Functions (`ASSETS` binding) + D1 REST query API; GitHub Actions (`collect-and-deploy.yml`, twice-hourly). Tests: `pytest` (Python) + `vitest` (JS pure logic) + `vite build` (Functions/JSX build gate).

**Spec:** `docs/superpowers/specs/2026-08-22-community-reports-publish-design.md` (its **§10 "Panel review amendments (APPROVED)" is binding and overrides any earlier body text it amends**, especially §10.1).

## Global Constraints

Every task's requirements implicitly include this section. Values copied verbatim from the spec.

1. **Option A invariant** — `/api/enrich` gains **NO** `DB` binding, reads a committed static asset, never per-lookup D1.
2. **Rendered metric = `COUNT(DISTINCT github_id)`** "Reported by N contributor(s)"; raw count only in the non-rendered envelope `report_count`.
3. **HARD no-PII** — published dataset carries only type/value/categories/reporters/dates; never `id`/`github_id`/`evidence`/`comment`/`login`; enforced by the projecting SELECT (`github_id` only inside `COUNT(DISTINCT …)`) + schema `additionalProperties:false`.
4. **`kind:"context"`**, OUT of the tally/band, never a verdict word.
5. **No new migration**, no change to the write path / `lib/reporting/*` / moderation console.
6. **Parameterized/projecting SQL only.**
7. **Free-tier only.**
8. **NO AI attribution on any commit** — this is a github.com/SaltyCarl repo: no `Co-Authored-By`, no Claude/Anthropic mentions anywhere in commit messages or code.
9. **Keep `communityKey` (Python ↔ JS) and the schema `categories` enum ↔ `validate.mjs CATEGORIES` in lockstep**, each guarded by a parity test.

> **All commands below run from the repo root `C:\Users\Carl\Desktop\Projects\VIGIL` unless a `cd` is shown.** Windows shell is PowerShell; the `git`/`python`/`npx` invocations are identical across shells.

---

## File Structure (spec §0 owned files)

**Create**
- `pipeline/community.py` — D1 REST query + indicator-level aggregation → the `community_reports.json` payload; owns the Python `community_key()` mirror. Returns the full payload dict or `None` (never raises for upstream reasons; never overwrites a good snapshot).
- `schemas/community_reports.schema.json` — dataset schema; its `additionalProperties:false` (both levels) is the machine-checked **privacy fence**. Its `categories` enum is `lib/reporting/validate.mjs` `CATEGORIES` verbatim.
- `data/state/community_reports.json` — the committed dataset; first commit = empty envelope (`indicators: {}`), which is the last-known-good from run 1.
- `tests/fixtures/community/key_parity.json` — shared `[type,value]→key` fixture, read by both suites (JS `communityKey` and Python `community_key`).
- `tests/fixtures/community/categories.json` — shared canonical category list, read by both suites (JS asserts `CATEGORIES`==fixture==schema enum; Python asserts schema enum==fixture).
- `tests/test_community.py` — Python schema-registration/enum-parity/seed tests (Task 2) + export/aggregation/privacy/degradation tests (Task 3), mock fetch, no network.
- `lib/__tests__/community.test.mjs` — `communityKey` + key-parity (Task 1), enum-parity (Task 2), and `SOCDESK_COMMUNITY` source match/no-match/copy/out-of-tally tests (Task 5), mock env, no network.
- `lib/__tests__/community_loader.test.mjs` — `loadCommunity` memoize-successes-only test (Task 6).

**Modify**
- `lib/enrich.mjs` — add the shared `communityKey()` normalizer (Task 1); add the `SOCDESK_COMMUNITY` source + append it to `SOURCES` (Task 5).
- `pipeline/validate.py` — register `SCHEMA_FOR["community_reports.json"]` (Task 2).
- `run_pipeline.py` — `import os`, `from pipeline.community import build_community_reports`, thread an `env` arg through `run()`, call the builder and set `payloads["community_reports.json"]` **before** `gate()`, with last-known-good fallback on `None` (Task 4).
- `.github/workflows/collect-and-deploy.yml` — add `CLOUDFLARE_ACCOUNT_ID` (currently deploy-step only) + the two new secrets to the **"Run collectors"** step env (Task 4).
- `functions/api/enrich.js` — add `loadCommunity()` (memoize successful loads only) + inject the parsed dataset into a derived env as `SOCDESK_COMMUNITY_DATA`; **no `DB` binding added** (Task 6).
- `README.md` / `CLAUDE.md` — one-line note: community layer served from committed JSON; read path still no-D1 (Task 7).

**Owner-config (NOT a code task in this repo — see Task 7)**
- The `/about#community-reports` transparency page (the source-row verify link target). There is **no `/about` route in `web/src`** today (only `web/src/routes/Privacy.tsx`, a routable-but-hidden disclosure page). Publishing this page is open owner-config (spec §9); Task 7 records it as such (and notes `Privacy.tsx` as the clone pattern if the owner later wants an in-app route). The link resolves to an owner-published page and does not block Phase 3.

---

## Verified codebase facts (each cited, current as of writing)

- `lib/enrich.mjs`: `validate()` at 76-95 (does **not** lowercase hashes, line 94); `SOURCES` array at 539; `planSources` at 581-589 (`usable = optionalKey || env[s.key]`); `dispatchSources` at 627-631 (3rd `run` arg = `env[s.key]`); `consensus` excludes `kind:"context"` at 560; `slots.filter(Boolean)` drops `undefined` rows at 685; `_internals` export at 731-734. Sources use `export function` (e.g. `isPrivateIp`), so a new `export function communityKey` fits the module's style.
- `functions/api/enrich.js`: `onRequestGet` at 26-47; edge cache gate `if (!result.partial) await cache.put(...)` at 45; the single call `enrich(fetch, type, q, env)` at 39; `caches.default`/`Request`/`Response` are referenced only **inside** `onRequestGet`, so the module is import-safe under Node/vitest.
- `run_pipeline.py`: imports `json, shutil, sys, datetime, pathlib` only — **no `os`** (lines 1-5); `from collectors.base import iso` already present (line 6); `run(...)` signature at 51 takes **no env arg**; `gate(payloads, state, schemas_dir)` at 83; `state = _load_state(state_dir)` at 54 (loads committed `data/state/*.json`, so a committed `community_reports.json` seed is available as `state["community_reports.json"]`); dual-write to out/state/web at 93-98; `__main__` at 124-130 passes `web_dir="web/public/data/state"`.
- `pipeline/validate.py`: `SCHEMA_FOR` dict at 8-18; `validate_payload(filename, payload, schemas_dir)` at 27-29 (raises `KeyError` for an unregistered filename); `gate()` keeps `prior[filename]` only on **validation failure** at 35-50 (an *absent* candidate is simply not published — hence the Task 4 last-known-good re-stamp).
- `pipeline/http.py`: `http_fetch(url, *, method="GET", json=None, headers=None, text=False)` — POSTs `json=` and merges `headers=`, calls `raise_for_status()`, returns `resp.json()`. A non-2xx or network error **raises** (caught by the builder's `except`).
- `pipeline/threat_ips.py` + `pipeline/publish.py`: the pattern to mirror — `build_site_data` always sets `payloads["threat_ips.json"]` (fresh, else `dict(prior, generated_at=iso(now))`); `_envelope(now, **body)` adds `generated_at`+`schema_version`. (Community's builder returns the **full envelope itself** per spec §3.1, so `run_pipeline` sets the payload directly — no `_envelope` wrap.)
- `schemas/threat_ips.schema.json`: the schema style to mirror (`additionalProperties:false`, `enum`, `maxItems`).
- `migrations/0001_init.sql`: `reports(id, github_id, ioc_type, ioc_value, category, evidence, comment, status, created_at)`; `idx_reports_ioc ON reports(ioc_type, ioc_value)` at 19. `login` lives on `accounts`, not `reports`. **Not modified by this plan.**
- `lib/reporting/validate.mjs`: `CATEGORIES` at 4-7 = `['brute-force','ssh','port-scan','web-app-attack','phishing','malware-c2','scanner','spam','exploited-host','other']`. **Not modified.**
- `.github/workflows/collect-and-deploy.yml`: pytest at 31; **"Run collectors"** step env at 40-43 (`ABUSECH_API_KEY`, `IPINFO_TOKEN`); `CLOUDFLARE_ACCOUNT_ID` currently only at the deploy step (line 95).
- `web/vitest.config.ts`: `test.include = ['src/**/*.test.ts', '../shared/**/*.test.ts', '../lib/**/*.test.mjs']`, `environment: 'node'`. There is **no** `test` npm script; vitest is invoked directly. `web/package.json` `build` = `tsc -b && vite build` (compiles `web/src` only; `functions/` is deployed as-is, not built).
- Test harness fixtures: `tests/conftest.py` provides `FIXED_NOW = datetime(2026,7,28,12,0,0,tzinfo=utc)`, `FIXTURES = tests/fixtures`, and `fake_fetch({url: payload})` (raises on unmapped URLs). `tests/test_pipeline.py::test_end_to_end_with_one_source_down` shows the `run()` integration harness; because it passes **no** `env`, community stays inert there (builder returns `None` on missing config) and that test **stays green**.

## Test harness commands (repo's real invocations)

- **Python (all):** `python -m pytest tests/ -q` — from repo root. Single file: `python -m pytest tests/test_community.py -q`.
- **JS pure logic (lib):** `cd web && npx vitest run ../lib` — the config `include` globs `../lib/**/*.test.mjs`. Single file: `cd web && npx vitest run ../lib/__tests__/community.test.mjs`.
- **JS full suite:** `cd web && npx vitest run ../shared src ../lib`.
- **Build gate (Functions/JSX):** `npm --prefix web run build` (must stay green; `functions/` is not compiled but the import contract must hold).

---

## Task 1: Shared `communityKey()` normalizer + parity fixture

**Files:**
- Modify: `lib/enrich.mjs` (add after `validate()`, i.e. after line 95)
- Create: `tests/fixtures/community/key_parity.json`
- Create: `lib/__tests__/community.test.mjs`

**Interfaces:**
- Consumes: nothing (first task).
- Produces:
  - `communityKey(type: string, value: string) -> string` — exported from `lib/enrich.mjs`. Returns `` `${type}|${v}` `` where `v` is `value.toLowerCase()` for `md5|sha1|sha256`, else `value` unchanged. **Assumes `value` is already `validate()`-normalized** (domain/ipv6 lowercased, url via `URL.href`, ipv4 unchanged); its only added job is hash-lowercasing (the `validate()` gap at enrich.mjs:94).
  - `tests/fixtures/community/key_parity.json` — a JSON array of `{ "type", "value", "key" }` rows read by BOTH suites. `value` is the already-normalized input each side passes; hash rows use UPPERCASE input to prove the lowercasing.

- [ ] **Step 1: Write the shared parity fixture**

Create `tests/fixtures/community/key_parity.json`:

```json
[
  { "type": "ipv4",   "value": "203.0.113.4", "key": "ipv4|203.0.113.4" },
  { "type": "ipv6",   "value": "2001:db8::1", "key": "ipv6|2001:db8::1" },
  { "type": "domain", "value": "evil.example", "key": "domain|evil.example" },
  { "type": "url",    "value": "https://evil.example/a", "key": "url|https://evil.example/a" },
  { "type": "md5",    "value": "D41D8CD98F00B204E9800998ECF8427E", "key": "md5|d41d8cd98f00b204e9800998ecf8427e" },
  { "type": "sha1",   "value": "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", "key": "sha1|da39a3ee5e6b4b0d3255bfef95601890afd80709" },
  { "type": "sha256", "value": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", "key": "sha256|e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" }
]
```

- [ ] **Step 2: Write the failing test**

Create `lib/__tests__/community.test.mjs`:

```js
// lib/__tests__/community.test.mjs
// Phase 3 community layer: the shared communityKey normalizer + its parity
// fixture (this task), the category-enum parity (Task 2), and the
// SOCDESK_COMMUNITY source behaviour (Task 5). No network — pure logic.
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { communityKey } from '../enrich.mjs'

const keyParity = JSON.parse(readFileSync(
  fileURLToPath(new URL('../../tests/fixtures/community/key_parity.json', import.meta.url)),
  'utf8'))

describe('communityKey', () => {
  it('lowercases hashes and leaves already-normalized values untouched', () => {
    expect(communityKey('md5', 'D41D8CD98F00B204E9800998ECF8427E'))
      .toBe('md5|d41d8cd98f00b204e9800998ecf8427e')
    expect(communityKey('ipv4', '203.0.113.4')).toBe('ipv4|203.0.113.4')
    expect(communityKey('domain', 'evil.example')).toBe('domain|evil.example')
  })

  it('agrees with the shared parity fixture (the Python mirror reads the same file)', () => {
    for (const row of keyParity) {
      expect(communityKey(row.type, row.value)).toBe(row.key)
    }
  })
})
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd web && npx vitest run ../lib/__tests__/community.test.mjs`
Expected: FAIL — `communityKey` is not exported from `../enrich.mjs` (import resolves to `undefined`, call throws).

- [ ] **Step 4: Write the minimal implementation**

In `lib/enrich.mjs`, immediately after the `validate()` function (after line 95), add:

```js
/* ---------- community-report key (shared with the Python export) ---------
 * The export key and the enrich lookup MUST be byte-identical, so this is the
 * one normalizer both sides call. `validate()` already lowercases domain/ipv6
 * and canonicalizes URLs, but does NOT lowercase hashes (line 94) — so a hash
 * reported as AAAA… and looked up as aaaa… would miss. Close that gap here.
 * `value` is assumed already validate()-normalized on both sides. */
const HASH_TYPES = new Set(["md5", "sha1", "sha256"]);
export function communityKey(type, value) {
  const v = HASH_TYPES.has(type) ? String(value).toLowerCase() : String(value);
  return `${type}|${v}`;
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd web && npx vitest run ../lib/__tests__/community.test.mjs`
Expected: PASS (2 tests).

- [ ] **Step 6: Commit** (no AI attribution — SaltyCarl repo)

```bash
git add lib/enrich.mjs lib/__tests__/community.test.mjs tests/fixtures/community/key_parity.json
git commit -m "feat(community): shared communityKey normalizer + parity fixture"
```

---

## Task 2: Schema + `SCHEMA_FOR` registration + committed empty seed + enum parity

**Files:**
- Create: `schemas/community_reports.schema.json`
- Create: `data/state/community_reports.json`
- Create: `tests/fixtures/community/categories.json`
- Modify: `pipeline/validate.py:8-18` (`SCHEMA_FOR`)
- Create: `tests/test_community.py`
- Modify: `lib/__tests__/community.test.mjs` (append the enum-parity block)

**Interfaces:**
- Consumes: `lib/__tests__/community.test.mjs` (Task 1, appended to); `validate_payload(filename, payload, schemas_dir) -> list[str]` and `SCHEMA_FOR` (existing, `pipeline/validate.py`); `CATEGORIES` (existing, `lib/reporting/validate.mjs`).
- Produces:
  - `schemas/community_reports.schema.json` — validated via `validate_payload("community_reports.json", payload, "schemas")`.
  - `data/state/community_reports.json` — committed empty envelope (last-known-good from run 1).
  - `tests/fixtures/community/categories.json` — canonical category list (array), read by both suites.
  - `SCHEMA_FOR["community_reports.json"] == "community_reports.schema.json"`.

- [ ] **Step 1: Write the schema**

Create `schemas/community_reports.schema.json` (from spec §4 verbatim; `categories` enum == `lib/reporting/validate.mjs` `CATEGORIES`):

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

- [ ] **Step 2: Write the committed empty seed**

Create `data/state/community_reports.json` (single line, matching the pipeline's compact `separators=(",",":")` style; must validate against the schema — `count:0`, empty `indicators`):

```json
{"generated_at":"2026-08-22T00:00:00Z","schema_version":1,"attribution":"Community-submitted abuse reports from SOCDesk contributors, owner-moderated. Counts of reports, not independent confirmations; a report is an allegation reviewed before publication, not a verdict.","count":0,"report_count":0,"indicators":{}}
```

- [ ] **Step 3: Write the shared categories fixture**

Create `tests/fixtures/community/categories.json` (exact order of `lib/reporting/validate.mjs` `CATEGORIES`):

```json
["brute-force","ssh","port-scan","web-app-attack","phishing","malware-c2","scanner","spam","exploited-host","other"]
```

- [ ] **Step 4: Write the failing Python tests**

Create `tests/test_community.py`:

```python
import json
from pathlib import Path

from pipeline.validate import SCHEMA_FOR, validate_payload

FIXTURES = Path(__file__).parent / "fixtures" / "community"
SCHEMA = json.loads(Path("schemas/community_reports.schema.json").read_text(encoding="utf-8"))
SEED = json.loads(Path("data/state/community_reports.json").read_text(encoding="utf-8"))
CATEGORIES = json.loads((FIXTURES / "categories.json").read_text(encoding="utf-8"))


def _schema_category_enum():
    return (SCHEMA["properties"]["indicators"]["additionalProperties"]
            ["properties"]["categories"]["items"]["enum"])


def test_schema_is_registered():
    assert SCHEMA_FOR["community_reports.json"] == "community_reports.schema.json"


def test_committed_seed_validates_and_is_empty():
    assert validate_payload("community_reports.json", SEED, "schemas") == []
    assert SEED["indicators"] == {} and SEED["count"] == 0


def test_schema_category_enum_matches_shared_fixture():
    # Drift here silently freezes the WHOLE dataset to last-known-good on the
    # next new-category approval (fail-closed but total). The JS side asserts
    # CATEGORIES (validate.mjs) == this same fixture, so schema == validate.mjs
    # transitively.
    assert _schema_category_enum() == CATEGORIES


def test_extra_indicator_field_fails_the_privacy_fence():
    bad = dict(SEED, indicators={"ipv4|203.0.113.4": {
        "type": "ipv4", "value": "203.0.113.4", "reporters": 1,
        "categories": ["ssh"], "first_reported": "2026-08-10",
        "latest_reported": "2026-08-10", "github_id": 42}})
    assert validate_payload("community_reports.json", bad, "schemas") != []
```

- [ ] **Step 5: Run to verify it fails**

Run: `python -m pytest tests/test_community.py -q`
Expected: FAIL — `test_schema_is_registered` raises `KeyError`/asserts false, and `test_committed_seed_validates_and_is_empty` raises `KeyError: 'community_reports.json'` inside `validate_payload` (filename not yet in `SCHEMA_FOR`).

- [ ] **Step 6: Register the schema**

In `pipeline/validate.py`, add the entry to `SCHEMA_FOR` (after line 17, the `threat_ips.json` entry):

```python
    "threat_ips.json": "threat_ips.schema.json",
    "community_reports.json": "community_reports.schema.json",
}
```

- [ ] **Step 7: Run to verify Python passes**

Run: `python -m pytest tests/test_community.py -q`
Expected: PASS (4 tests).

- [ ] **Step 8: Append the failing JS enum-parity test**

Append to `lib/__tests__/community.test.mjs` (the `readFileSync`/`fileURLToPath` imports are already present from Task 1):

```js
import { CATEGORIES } from '../reporting/validate.mjs'

const categoriesFixture = JSON.parse(readFileSync(
  fileURLToPath(new URL('../../tests/fixtures/community/categories.json', import.meta.url)), 'utf8'))
const communitySchema = JSON.parse(readFileSync(
  fileURLToPath(new URL('../../schemas/community_reports.schema.json', import.meta.url)), 'utf8'))
const schemaCategoryEnum =
  communitySchema.properties.indicators.additionalProperties.properties.categories.items.enum

describe('category enum parity', () => {
  it('validate.mjs CATEGORIES === shared fixture === schema enum', () => {
    expect(CATEGORIES).toEqual(categoriesFixture)
    expect(schemaCategoryEnum).toEqual(categoriesFixture)
  })
})
```

- [ ] **Step 9: Run to verify JS passes**

Run: `cd web && npx vitest run ../lib/__tests__/community.test.mjs`
Expected: PASS (3 tests total — Task 1's two + this one).

- [ ] **Step 10: Commit**

```bash
git add schemas/community_reports.schema.json data/state/community_reports.json tests/fixtures/community/categories.json pipeline/validate.py tests/test_community.py lib/__tests__/community.test.mjs
git commit -m "feat(community): schema + gate registration + committed seed + enum-parity tests"
```

---

## Task 3: `pipeline/community.py` — D1 export + aggregation

**Files:**
- Create: `pipeline/community.py`
- Modify: `tests/test_community.py` (append builder tests)

**Interfaces:**
- Consumes: `tests/fixtures/community/key_parity.json` (Task 1); `schemas/community_reports.schema.json` + registration (Task 2); `validate_payload` (existing); `iso(now) -> str` from `collectors.base` (existing); a `fetch` callable with the `http_fetch(url, *, method, json, headers, text)` shape.
- Produces:
  - `build_community_reports(fetch, now, env) -> dict | None` — full committed payload (`generated_at`/`schema_version`/`attribution`/`count`/`report_count`/`indicators`), or `None` on missing config or any D1 failure. Never raises for upstream reasons. Each indicator entry has EXACTLY `{type, value, reporters, categories, first_reported, latest_reported}`.
  - `community_key(ioc_type, ioc_value) -> str` — the Python mirror of JS `communityKey` (hash-lowercasing only).

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_community.py`:

```python
from collectors.base import iso
from tests.conftest import FIXED_NOW
from pipeline.community import build_community_reports, community_key

ENV = {"CLOUDFLARE_ACCOUNT_ID": "acct", "CLOUDFLARE_D1_DATABASE_ID": "db",
       "CF_D1_READ_TOKEN": "tok"}


def _d1(rows):
    """A fetch stub returning a D1 REST query response wrapping `rows`. Asserts
    the builder POSTs to the D1 query endpoint (no accidental GET/other host)."""
    def fetch(url, *, method="GET", json=None, headers=None, text=False):
        assert method == "POST" and "d1/database" in url and url.endswith("/query")
        assert headers and headers.get("Authorization") == "Bearer tok"
        return {"result": [{"results": rows, "success": True}], "success": True}
    return fetch


def test_aggregates_one_entry_per_indicator():
    rows = [
        {"ioc_type": "ipv4", "ioc_value": "203.0.113.4", "reporters": 2,
         "n_reports": 3, "categories": "ssh,brute-force,ssh",
         "first_at": "2026-08-10T09:00:00Z", "latest_at": "2026-08-20T22:00:00Z"},
        {"ioc_type": "domain", "ioc_value": "evil.example", "reporters": 1,
         "n_reports": 1, "categories": "phishing",
         "first_at": "2026-08-18T00:00:00Z", "latest_at": "2026-08-19T00:00:00Z"},
    ]
    body = build_community_reports(_d1(rows), FIXED_NOW, ENV)
    assert body["count"] == 2 and body["report_count"] == 4
    ip = body["indicators"]["ipv4|203.0.113.4"]
    assert ip["reporters"] == 2
    assert ip["categories"] == ["brute-force", "ssh"]      # deduped + sorted
    assert ip["first_reported"] == "2026-08-10"            # sliced YYYY-MM-DD
    assert ip["latest_reported"] == "2026-08-20"
    assert body["generated_at"] == iso(FIXED_NOW)
    assert body["schema_version"] == 1 and "SOCDesk" in body["attribution"]


def test_distinct_contributor_count_is_not_inflated():
    # Same github_id re-reporting after approval: n_reports=2 but the query's
    # COUNT(DISTINCT github_id)=1. The builder takes `reporters` directly and
    # never uses n_reports per-indicator (owner ruling spec 10.1).
    rows = [{"ioc_type": "ipv4", "ioc_value": "198.51.100.7", "reporters": 1,
             "n_reports": 2, "categories": "scanner",
             "first_at": "2026-08-01T00:00:00Z", "latest_at": "2026-08-02T00:00:00Z"}]
    body = build_community_reports(_d1(rows), FIXED_NOW, ENV)
    assert body["indicators"]["ipv4|198.51.100.7"]["reporters"] == 1
    assert body["report_count"] == 2                       # raw volume, envelope only


def test_hash_key_is_lowercased():
    rows = [{"ioc_type": "sha256",
             "ioc_value": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
             "reporters": 1, "n_reports": 1, "categories": "malware-c2",
             "first_at": "2026-08-01T00:00:00Z", "latest_at": "2026-08-01T00:00:00Z"}]
    body = build_community_reports(_d1(rows), FIXED_NOW, ENV)
    (key,) = body["indicators"].keys()
    assert key == "sha256|e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_key_parity_fixture_matches_js_mirror():
    parity = json.loads((FIXTURES / "key_parity.json").read_text(encoding="utf-8"))
    for row in parity:
        assert community_key(row["type"], row["value"]) == row["key"]


def test_privacy_fence_drops_forbidden_fields():
    # A DEFENSIVE mock: even if a D1 row carried these, the builder's whitelist
    # projection must not let them survive into the payload.
    rows = [{"ioc_type": "ipv4", "ioc_value": "203.0.113.9", "reporters": 1,
             "n_reports": 1, "categories": "ssh",
             "first_at": "2026-08-10T00:00:00Z", "latest_at": "2026-08-10T00:00:00Z",
             "id": "8f3c-report-uuid", "github_id": 4242,
             "evidence": "internal 10.0.0.5 log excerpt",
             "comment": "reporter side note", "login": "octocat"}]
    body = build_community_reports(_d1(rows), FIXED_NOW, ENV)
    entry = body["indicators"]["ipv4|203.0.113.9"]
    assert set(entry) == {"type", "value", "reporters", "categories",
                          "first_reported", "latest_reported"}
    blob = json.dumps(body)
    for forbidden in ("github_id", "evidence", "comment", "login",
                      "8f3c-report-uuid", "internal 10.0.0.5",
                      "reporter side note", "octocat"):
        assert forbidden not in blob


def test_missing_config_returns_none():
    assert build_community_reports(_d1([]), FIXED_NOW, {}) is None


def test_d1_network_failure_returns_none_not_crash():
    def boom(url, **kw):
        raise RuntimeError("D1 500")
    assert build_community_reports(boom, FIXED_NOW, ENV) is None


def test_bad_response_shape_returns_none():
    def bad(url, **kw):
        return {"success": False, "errors": [{"message": "nope"}]}
    assert build_community_reports(bad, FIXED_NOW, ENV) is None


def test_empty_but_successful_query_publishes_empty_map():
    body = build_community_reports(_d1([]), FIXED_NOW, ENV)
    assert body is not None and body["indicators"] == {} and body["count"] == 0


def test_built_payload_validates_against_schema():
    rows = [{"ioc_type": "ipv4", "ioc_value": "203.0.113.4", "reporters": 2,
             "n_reports": 3, "categories": "ssh,brute-force",
             "first_at": "2026-08-10T00:00:00Z", "latest_at": "2026-08-20T00:00:00Z"}]
    body = build_community_reports(_d1(rows), FIXED_NOW, ENV)
    assert validate_payload("community_reports.json", body, "schemas") == []
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/test_community.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'pipeline.community'` (import error at collection).

- [ ] **Step 3: Write the implementation**

Create `pipeline/community.py`:

```python
"""Phase-3 community-reports export: D1 (status='approved') -> committed JSON.

Read-only against D1 via the REST *query* API. The projecting, indicator-level
SELECT names no `id`/`evidence`/`comment` and reads `github_id` ONLY inside
COUNT(DISTINCT ...), so no reporter identity is ever materialized (privacy
fence, spec 3.6.1). The schema's additionalProperties:false is the second,
machine-checked fence.

build_community_reports returns the FULL committed payload (envelope +
indicators map) or None on any D1 failure / missing config. On None the caller
keeps last-known-good (spec 5). It NEVER raises for upstream reasons and NEVER
overwrites a good snapshot with an empty one.

NO per-lookup path and NO D1 binding on /api/enrich touch this — the read path
consults the committed JSON only (Option A invariant).
"""
from collectors.base import iso

SCHEMA_VERSION = 1

ATTRIBUTION = (
    "Community-submitted abuse reports from SOCDesk contributors, owner-"
    "moderated. Counts of reports, not independent confirmations; a report is "
    "an allegation reviewed before publication, not a verdict."
)

# Indicator-level aggregation (spec 3.1 + owner ruling 10.1). `reporters` is a
# true distinct-contributor count; `n_reports` (COUNT(*)) is a bare volume
# integer summed into the envelope's report_count only — never per-indicator,
# never rendered. github_id is read ONLY inside COUNT(DISTINCT ...): the column
# is counted, never projected, so no id value leaves D1. `evidence`/`comment`/
# `id` are never named.
SQL = (
    "SELECT ioc_type, ioc_value, "
    "COUNT(DISTINCT github_id) AS reporters, "
    "COUNT(*) AS n_reports, "
    "GROUP_CONCAT(DISTINCT category) AS categories, "
    "MIN(created_at) AS first_at, MAX(created_at) AS latest_at "
    "FROM reports WHERE status = 'approved' "
    "GROUP BY ioc_type, ioc_value"
)

_HASH_TYPES = {"md5", "sha1", "sha256"}


def community_key(ioc_type, ioc_value):
    """Byte-identical mirror of lib/enrich.mjs communityKey (guarded by the
    shared key_parity.json fixture). Only hashes are lowercased; every other
    type is already validate()-normalized on the write path."""
    v = str(ioc_value).lower() if ioc_type in _HASH_TYPES else str(ioc_value)
    return f"{ioc_type}|{v}"


def _split_categories(group_concat):
    """GROUP_CONCAT(DISTINCT category) -> deduped, sorted list. Category enum
    values contain no commas, so the split is unambiguous."""
    parts = [c.strip() for c in str(group_concat or "").split(",") if c.strip()]
    return sorted(set(parts))


def _rows_from_d1(resp):
    """Pull the row list out of a D1 REST query response, or None if the shape
    is wrong (treated as a failure -> last-known-good)."""
    try:
        rows = resp["result"][0]["results"]
    except (KeyError, IndexError, TypeError):
        return None
    return rows if isinstance(rows, list) else None


def build_community_reports(fetch, now, env):
    """Query D1 for approved reports and assemble the committed payload.

    Returns the full payload dict, or None on missing config / any D1 failure
    (caller keeps last-known-good). Never raises for upstream reasons.
    """
    account = env.get("CLOUDFLARE_ACCOUNT_ID")
    database = env.get("CLOUDFLARE_D1_DATABASE_ID")
    token = env.get("CF_D1_READ_TOKEN") or env.get("CLOUDFLARE_API_TOKEN")
    if not (account and database and token):
        return None                          # inert until owner-config (spec 9)

    url = (f"https://api.cloudflare.com/client/v4/accounts/{account}"
           f"/d1/database/{database}/query")
    try:
        resp = fetch(url, method="POST", json={"sql": SQL},
                     headers={"Authorization": f"Bearer {token}"})
    except Exception:
        return None                          # D1 unreachable -> last-known-good

    rows = _rows_from_d1(resp)
    if rows is None:
        return None

    indicators = {}
    report_count = 0
    for r in rows:
        ioc_type = r["ioc_type"]
        ioc_value = r["ioc_value"]
        report_count += int(r.get("n_reports") or 0)
        # Whitelist projection: ONLY these six keys. Any stray field on the row
        # (evidence/comment/github_id/id/login) is dropped here (privacy fence).
        indicators[community_key(ioc_type, ioc_value)] = {
            "type": ioc_type,
            "value": ioc_value,
            "reporters": int(r["reporters"]),          # distinct contributors, taken directly
            "categories": _split_categories(r.get("categories")),
            "first_reported": str(r.get("first_at") or "")[:10],
            "latest_reported": str(r.get("latest_at") or "")[:10],
        }

    return {
        "generated_at": iso(now),
        "schema_version": SCHEMA_VERSION,
        "attribution": ATTRIBUTION,
        "count": len(indicators),
        "report_count": report_count,
        "indicators": indicators,
    }
```

- [ ] **Step 4: Run to verify it passes**

Run: `python -m pytest tests/test_community.py -q`
Expected: PASS (Task 2's 4 tests + these 11 = 15).

- [ ] **Step 5: Commit**

```bash
git add pipeline/community.py tests/test_community.py
git commit -m "feat(community): D1 export builder with indicator-level distinct-contributor aggregation"
```

---

## Task 4: `run_pipeline.py` wiring + workflow env

**Files:**
- Modify: `run_pipeline.py` (imports at 1-7; `run()` signature at 51; before `gate()` at 83; `__main__` at 124-130)
- Modify: `.github/workflows/collect-and-deploy.yml` ("Run collectors" step env, lines 40-43)
- Modify: `tests/test_pipeline.py` (append two wiring tests)

**Interfaces:**
- Consumes: `build_community_reports(fetch, now, env) -> dict|None` (Task 3); `iso` (existing, already imported at run_pipeline.py:6); `gate`/`_load_state`/dual-write (existing).
- Produces: `run(..., env=None)` — when the builder returns a payload it is set into `payloads["community_reports.json"]` **before** `gate()` (so it gets schema validation + last-known-good + triple dual-write); when the builder returns `None`, the prior committed snapshot is re-published re-stamped, so the served asset is never blanked.

> **Design note (spec ambiguity resolved):** `gate()` keeps a prior only when a *candidate is present and fails validation* — an **absent** candidate is simply not written, which would blank the deployed asset on a `None` run. `threat_ips` avoids this by always re-publishing `dict(prior, generated_at=iso(now))`. Community mirrors that pattern: on `None`, re-stamp `state["community_reports.json"]`. The committed seed (Task 2) guarantees a prior exists from run 1. This realizes spec §5's promise ("the previous community dataset served, CI green") without relying on `gate()` to keep an absent payload.

- [ ] **Step 1: Write the failing wiring tests**

Append to `tests/test_pipeline.py` (`run`, `FIXED_NOW`, `FIXTURES` are already imported at the top of that file; `json` too):

```python
def _pipeline_fetch(fake_fetch):
    """The collector mapping test_end_to_end uses, as a reusable fetch (so the
    community wiring tests exercise a REAL run() without re-listing sources)."""
    from collectors import attack, kev, nvd, rss
    rss_xml = (FIXTURES / "rss/talos.xml").read_text(encoding="utf-8")
    mapping = {kev.URL: "kev/feed.json", nvd.build_url(FIXED_NOW): "nvd/recent.json",
               attack.URL: "attack/enterprise.json"}
    for f in rss.FEEDS:
        mapping[f["url"]] = rss_xml if f is rss.FEEDS[0] else ""
    inner = fake_fetch(mapping)

    def fetch(url, **kw):
        if url.startswith("https://api.first.org"):
            return json.loads((FIXTURES / "epss/scores.json").read_text(encoding="utf-8"))
        return inner(url, **kw)
    return fetch


def test_community_payload_published_and_env_threaded(fake_fetch, tmp_path, monkeypatch):
    import run_pipeline
    payload = {"generated_at": "seed", "schema_version": 1, "attribution": "a",
               "count": 1, "report_count": 1,
               "indicators": {"ipv4|203.0.113.4": {
                   "type": "ipv4", "value": "203.0.113.4", "reporters": 1,
                   "categories": ["ssh"], "first_reported": "2026-08-10",
                   "latest_reported": "2026-08-10"}}}
    seen = {}

    def fake_build(fetch, now, env):
        seen["env"] = env
        return payload
    monkeypatch.setattr(run_pipeline, "build_community_reports", fake_build)

    out, state = tmp_path / "o", tmp_path / "s"
    run(fetch=_pipeline_fetch(fake_fetch), now=FIXED_NOW, out_dir=out, state_dir=state,
        schemas_dir="schemas", sources_path="data/sources.json",
        env={"CLOUDFLARE_ACCOUNT_ID": "acct"})

    assert seen["env"] == {"CLOUDFLARE_ACCOUNT_ID": "acct"}   # env threaded through
    written = json.loads((state / "community_reports.json").read_text(encoding="utf-8"))
    assert written["indicators"]["ipv4|203.0.113.4"]["reporters"] == 1


def test_community_keeps_last_known_good_on_none(fake_fetch, tmp_path, monkeypatch):
    import run_pipeline
    monkeypatch.setattr(run_pipeline, "build_community_reports",
                        lambda fetch, now, env: None)
    out, state = tmp_path / "o", tmp_path / "s"
    state.mkdir(parents=True)
    prior = {"generated_at": "2020-01-01T00:00:00Z", "schema_version": 1,
             "attribution": "a", "count": 0, "report_count": 0, "indicators": {}}
    (state / "community_reports.json").write_text(json.dumps(prior), encoding="utf-8")

    run(fetch=_pipeline_fetch(fake_fetch), now=FIXED_NOW, out_dir=out, state_dir=state,
        schemas_dir="schemas", sources_path="data/sources.json", env={})

    kept = json.loads((out / "community_reports.json").read_text(encoding="utf-8"))
    assert kept["indicators"] == {}                          # prior retained (not blanked)
    assert kept["generated_at"] != prior["generated_at"]     # re-stamped this run
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/test_pipeline.py -q`
Expected: FAIL — `run()` has no `env` keyword (`TypeError: run() got an unexpected keyword argument 'env'`).

- [ ] **Step 3: Add the import and thread `env` into `run()`**

In `run_pipeline.py`, add `import os` (top block) and the builder import (with the other `pipeline` imports):

```python
import json
import os
import shutil
import sys
```

```python
from pipeline.publish import build_site_data
from pipeline.community import build_community_reports
from pipeline.validate import gate
```

Change the `run()` signature (line 51) to accept `env`:

```python
def run(fetch, now, out_dir, state_dir, schemas_dir, sources_path, web_dir=None,
        env=None):
```

- [ ] **Step 4: Build + set the payload before `gate()`**

In `run_pipeline.py`, immediately **before** the `published, problems = gate(...)` line (line 83), add:

```python
    # Community reports (Phase 3): D1 approved rows -> committed JSON, consulted
    # by the enrich read path as a kind:"context" source. On any D1 failure the
    # builder returns None and we re-publish the prior snapshot (the committed
    # seed guarantees one exists from run 1), so the layer degrades to
    # last-known-good and the served asset is never blanked. NO D1 read path,
    # NO DB binding on /api/enrich (Option A invariant).
    community = build_community_reports(fetch=fetch, now=now, env=env or {})
    if community is not None:
        payloads["community_reports.json"] = community
    elif "community_reports.json" in state:
        payloads["community_reports.json"] = dict(
            state["community_reports.json"], generated_at=iso(now))
```

In `__main__` (lines 126-129), pass `env=os.environ`:

```python
    _, problems = run(fetch=http_fetch, now=datetime.now(timezone.utc),
                      out_dir="site/data", state_dir="data/state",
                      schemas_dir="schemas", sources_path="data/sources.json",
                      web_dir="web/public/data/state", env=os.environ)
```

- [ ] **Step 5: Run to verify Python passes**

Run: `python -m pytest tests/ -q`
Expected: PASS — the two new wiring tests pass; `test_end_to_end_with_one_source_down` (which passes no `env`) still passes because `build_community_reports(..., env={})` returns `None` on missing config and the state dir has no prior `community_reports.json`, so nothing is added there.

- [ ] **Step 6: Wire the D1 env into the "Run collectors" workflow step**

In `.github/workflows/collect-and-deploy.yml`, extend the `env:` block of the **"Run collectors"** step (currently lines 40-43) so it reads:

```yaml
        env:
          ABUSECH_API_KEY: ${{ secrets.ABUSECH_API_KEY }}
          IPINFO_TOKEN: ${{ secrets.IPINFO_TOKEN }}
          # Phase 3 community export: D1 REST *query* (read-only). ACCOUNT_ID
          # already exists as a secret but was previously referenced only in the
          # deploy step, so it must be added here for the D1 URL. The DB id and a
          # dedicated D1-Read-only token are new secrets; absent, the builder
          # no-ops to last-known-good (the site behaves exactly as today).
          CLOUDFLARE_ACCOUNT_ID: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}
          CLOUDFLARE_D1_DATABASE_ID: ${{ secrets.CLOUDFLARE_D1_DATABASE_ID }}
          CF_D1_READ_TOKEN: ${{ secrets.CF_D1_READ_TOKEN }}
        run: python run_pipeline.py
```

- [ ] **Step 7: Verify the workflow edit**

Run: `git diff .github/workflows/collect-and-deploy.yml`
Expected: the three env keys appear under the **"Run collectors"** step only (not the deploy step), indentation matches the surrounding `env:` entries. Re-run `python -m pytest tests/ -q` — Expected: still PASS (no regression). (CI validates the YAML on push; the builder returns `None` until the two new secrets are set, so this change is inert until owner-config.)

- [ ] **Step 8: Commit**

```bash
git add run_pipeline.py .github/workflows/collect-and-deploy.yml tests/test_pipeline.py
git commit -m "feat(community): wire D1 export into run_pipeline + collectors workflow env"
```

---

## Task 5: `SOCDESK_COMMUNITY` source in `lib/enrich.mjs`

**Files:**
- Modify: `lib/enrich.mjs` (add the source before `const SOURCES = [...]` at line 539; append it to the `SOURCES` array on line 539)
- Modify: `lib/__tests__/community.test.mjs` (append source-behaviour tests)

**Interfaces:**
- Consumes: `communityKey(type, value) -> string` (Task 1); `enrich(fetchImpl, type, q, env, now?) -> result` (existing); the injection channel `env["SOCDESK_COMMUNITY_DATA"]` (the parsed dataset object or `null`, supplied by Task 6). The source's `run(_fetchImpl, ind, data)` receives `data = env["SOCDESK_COMMUNITY_DATA"]` (per `dispatchSources`, enrich.mjs:628).
- Produces: a `SOURCES` entry named `"SOCDesk Community"`, `kind:"context"`, `optionalKey:true`, that returns `undefined` on absent-dataset / no-match and a `kind:"context"` row (`verdict:"unknown"`, headline `Reported by N contributor(s) …`, `url` = `https://socdesk.io/about#community-reports`) on a match.

- [ ] **Step 1: Write the failing tests**

Append to `lib/__tests__/community.test.mjs`:

```js
import { enrich } from '../enrich.mjs'

/** Every upstream 404s so the other sources return cleanly; the community row
 *  rides on the injected dataset only (no network). */
const miss = async () => ({ status: 404, ok: false, json: async () => ({}) })

const DATASET = {
  generated_at: '2026-08-22T14:41:00Z',
  indicators: {
    'ipv4|203.0.113.4': {
      type: 'ipv4', value: '203.0.113.4', reporters: 2,
      categories: ['brute-force', 'ssh'],
      first_reported: '2026-08-10', latest_reported: '2026-08-20',
    },
    'ipv4|198.51.100.7': {
      type: 'ipv4', value: '198.51.100.7', reporters: 1,
      categories: ['phishing'], first_reported: '2026-08-18', latest_reported: '2026-08-19',
    },
  },
}

describe('SOCDESK_COMMUNITY source', () => {
  it('emits a kind:"context" row with a distinct-contributor count on a match', async () => {
    const out = await enrich(miss, 'ipv4', '203.0.113.4', { SOCDESK_COMMUNITY_DATA: DATASET })
    const row = out.sources.find((s) => s.name === 'SOCDesk Community')
    expect(row).toBeTruthy()
    expect(row.kind).toBe('context')
    expect(row.verdict).toBe('unknown')
    expect(row.headline).toBe(
      'Reported by 2 contributors (owner-moderated) · brute-force, ssh · latest 2026-08-20')
    expect(Object.fromEntries(row.facts).Contributors).toBe('2')
    expect(row.url).toContain('/about#community-reports')
  })

  it('says "1 contributor" (singular) for a single-reporter indicator', async () => {
    const out = await enrich(miss, 'ipv4', '198.51.100.7', { SOCDESK_COMMUNITY_DATA: DATASET })
    const row = out.sources.find((s) => s.name === 'SOCDesk Community')
    expect(row.headline).toContain('Reported by 1 contributor (owner-moderated)')
    expect(row.headline).not.toContain('1 contributors')
  })

  it('stays OUT of the verdict tally (consulted/flagged/tone unchanged vs. no dataset)', async () => {
    const withData = await enrich(miss, 'ipv4', '203.0.113.4', { SOCDESK_COMMUNITY_DATA: DATASET })
    const without = await enrich(miss, 'ipv4', '203.0.113.4', {})
    expect(withData.consulted).toBe(without.consulted)
    expect(withData.flagged).toBe(without.flagged)
    expect(withData.tone).toBe(without.tone)
  })

  it('omits the row on a no-match, with no error and partial unchanged', async () => {
    const out = await enrich(miss, 'ipv4', '8.8.8.8', { SOCDESK_COMMUNITY_DATA: DATASET })
    expect(out.sources.find((s) => s.name === 'SOCDesk Community')).toBeUndefined()
    expect(out.errors.some((e) => /SOCDesk Community/.test(e.source))).toBe(false)
    expect(out.partial).toBe(false)
  })

  it('no-ops when the dataset is absent (null injected) — no row, no error', async () => {
    const out = await enrich(miss, 'ipv4', '203.0.113.4', { SOCDESK_COMMUNITY_DATA: null })
    expect(out.sources.find((s) => s.name === 'SOCDesk Community')).toBeUndefined()
    expect(out.errors.some((e) => /SOCDesk Community/.test(e.source))).toBe(false)
  })

  it('lowercases a hash indicator to match the dataset key', async () => {
    const lower = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    const dataset = { indicators: { [`sha256|${lower}`]: {
      type: 'sha256', value: lower, reporters: 1, categories: ['malware-c2'],
      first_reported: '2026-08-01', latest_reported: '2026-08-01' } } }
    const out = await enrich(miss, 'sha256', lower.toUpperCase(), { SOCDESK_COMMUNITY_DATA: dataset })
    expect(out.sources.find((s) => s.name === 'SOCDesk Community')).toBeTruthy()
  })
})
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd web && npx vitest run ../lib/__tests__/community.test.mjs`
Expected: FAIL — no `SOCDesk Community` row is ever found (the source does not exist yet); the match/singular/hash tests fail.

- [ ] **Step 3: Add the source and append it to `SOURCES`**

In `lib/enrich.mjs`, add the source definition immediately before the `const SOURCES = [...]` declaration (line 539):

```js
/* SOCDesk Community — owner-moderated crowdsourced abuse reports, published as
 * a committed dataset (Phase 3). CONTEXT, never a verdict: it states an
 * attributed distinct-CONTRIBUTOR count, out of the tally/band. No network, no
 * D1 — a synchronous lookup in the injected map. `key` names the env slot the
 * Function fills with the parsed dataset (not a secret); `optionalKey` keeps it
 * dispatched even when absent, and run() returns undefined so slots.filter
 * drops it on the ~all clean lookups (no "not configured" clutter). BLOCKING
 * (default) but pure-synchronous, so it adds zero fan-out latency. */
const SOCDESK_COMMUNITY = {
  name: "SOCDesk Community",
  types: ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"],
  key: "SOCDESK_COMMUNITY_DATA",   // env slot carries the injected parsed map, not a secret
  optionalKey: true,               // usable even when absent → then it no-ops
  kind: "context",                 // excluded from the tally + band (enrich.mjs:560, map.ts:127)
  link: "https://socdesk.io/about#community-reports",
  async run(_fetchImpl, ind, data) {
    const map = data && data.indicators;           // injected dataset (Task 6)
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
        `Reported by ${n} contributor${n === 1 ? "" : "s"} (owner-moderated)` +
        (cats ? ` · ${cats}` : "") +
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

Then append it to the `SOURCES` array (line 539):

```js
const SOURCES = [ABUSEIPDB, VIRUSTOTAL, GREYNOISE, MALWAREBAZAAR, IPINFO, URLSCAN, RDAP, OTX, SOCDESK_COMMUNITY];
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd web && npx vitest run ../lib/__tests__/community.test.mjs`
Expected: PASS (all blocks: communityKey, key-parity, enum-parity, and the 6 source tests).

Also run the neighbouring suite to confirm no regression in the existing enrich tests:
Run: `cd web && npx vitest run ../lib`
Expected: PASS (existing `enrich.test.mjs` + new `community.test.mjs`).

- [ ] **Step 5: Commit**

```bash
git add lib/enrich.mjs lib/__tests__/community.test.mjs
git commit -m "feat(community): SOCDESK_COMMUNITY context source (out of tally, distinct-contributor copy)"
```

---

## Task 6: `functions/api/enrich.js` — load + inject the dataset (no D1 binding)

**Files:**
- Modify: `functions/api/enrich.js` (add `loadCommunity` after the import at line 11; inject in `onRequestGet`, replacing line 39)
- Create: `lib/__tests__/community_loader.test.mjs`

**Interfaces:**
- Consumes: the `SOCDESK_COMMUNITY` source reading `env.SOCDESK_COMMUNITY_DATA` (Task 5); the deployed static asset `/data/state/community_reports.json` (Task 4 produces it); the Pages-Functions `ASSETS` binding (default), same-origin `fetch` fallback.
- Produces: `loadCommunity(env, origin) -> Promise<object|null>` — reads the committed dataset from the asset store, memoizes **successful loads only** in a module-scope cache; a transient miss returns `null` without poisoning the cache. `onRequestGet` injects the result into a **derived** env (`{ ...env, SOCDESK_COMMUNITY_DATA: community }`) — the real secrets object is never mutated, and **no `DB` binding is added**.

- [ ] **Step 1: Write the failing test**

Create `lib/__tests__/community_loader.test.mjs`:

```js
// lib/__tests__/community_loader.test.mjs
// The Function-side dataset loader: reads the committed static asset, memoizes
// SUCCESSFUL loads only (a transient miss must NOT poison the per-isolate
// cache). Importing functions/api/enrich.js is safe under Node/vitest — it only
// references caches.default/Request/Response inside onRequestGet, not at load.
import { describe, expect, it } from 'vitest'
import { loadCommunity } from '../../functions/api/enrich.js'

/** An env whose ASSETS.fetch yields the next scripted step per call:
 *  'miss' -> a non-ok Response, 'throw' -> an exception, else -> ok+json(step). */
function scriptedAssets(steps) {
  let i = 0
  return { ASSETS: { fetch: async () => {
    const step = steps[Math.min(i++, steps.length - 1)]
    if (step === 'throw') throw new Error('asset store down')
    if (step === 'miss') return { ok: false, json: async () => ({}) }
    return { ok: true, json: async () => step }
  } } }
}

describe('loadCommunity (functions/api/enrich.js)', () => {
  it('memoizes successful loads only; a transient miss is retried, not cached', async () => {
    const data = { indicators: { 'ipv4|1.2.3.4': { type: 'ipv4' } } }
    const env = scriptedAssets(['miss', data, 'throw'])
    const origin = 'https://socdesk.io'
    // 1) transient miss -> null, NOT memoized
    expect(await loadCommunity(env, origin)).toBe(null)
    // 2) next call succeeds -> data returned + memoized
    expect(await loadCommunity(env, origin)).toEqual(data)
    // 3) even though the store now throws, the memoized success is served
    expect(await loadCommunity(env, origin)).toEqual(data)
  })
})
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd web && npx vitest run ../lib/__tests__/community_loader.test.mjs`
Expected: FAIL — `loadCommunity` is not exported from `functions/api/enrich.js` (import is `undefined`).

- [ ] **Step 3: Add `loadCommunity` and inject into a derived env**

In `functions/api/enrich.js`, add after the `import { enrich } ...` line (line 11):

```js
// Per-isolate memo of the committed community dataset. Caches ONLY successful
// loads — a transient miss returns null WITHOUT poisoning the cache, so the
// next request retries instead of omitting community rows for the isolate's
// whole life (Infra review). No D1: this reads a static asset (Option A
// invariant — /api/enrich gains no DB binding).
let _communityCache;
export async function loadCommunity(env, origin) {
  if (_communityCache !== undefined) return _communityCache;   // success previously memoized
  try {
    const req = new Request(`${origin}/data/state/community_reports.json`);
    const res = env.ASSETS ? await env.ASSETS.fetch(req) : await fetch(req);
    if (res.ok) { _communityCache = await res.json(); return _communityCache; }
  } catch { /* fall through — transient miss, not memoized */ }
  return null;                                                  // retried next request
}
```

Then, in `onRequestGet`, replace the single enrich call (line 39):

```js
  const community = await loadCommunity(env, url.origin);
  const result = await enrich(fetch, type, q, { ...env, SOCDESK_COMMUNITY_DATA: community });
```

- [ ] **Step 4: Run to verify the loader test passes**

Run: `cd web && npx vitest run ../lib/__tests__/community_loader.test.mjs`
Expected: PASS (1 test).

- [ ] **Step 5: Confirm the build gate stays green**

Run: `npm --prefix web run build`
Expected: PASS — `functions/api/enrich.js` is plain JS (not compiled by `tsc`/Vite); the change is import-safe and `web/src` is untouched, so the build is unaffected. (The `onRequestGet` wiring itself runs only on Cloudflare; it is covered by the manual preview acceptance below, per spec §6.)

- [ ] **Step 6: Commit**

```bash
git add functions/api/enrich.js lib/__tests__/community_loader.test.mjs
git commit -m "feat(community): load committed dataset in enrich Function, inject via derived env (no D1)"
```

**Manual acceptance (owner, on a preview deploy — spec §6/§9, not a code step):** confirm `env.ASSETS` resolves on preview; approve a report in the Phase-2 console → `workflow_dispatch` → confirm `data/state/community_reports.json` gains the entry (no PII); look the indicator up on the preview → the community context row renders, out of the tally; look up an unreported indicator → no community row; confirm `/api/enrich` still works with **no `DB` binding** on the Function.

---

## Task 7: Docs note + transparency-page owner-config record

**Files:**
- Modify: `README.md` (near the pipeline/directory-map description — anchor on the existing `data/state/` line, ~205-208)
- Modify: `CLAUDE.md` (the no-account/D1 paragraph — anchor on lines 117-124)

**Interfaces:**
- Consumes: nothing (documentation).
- Produces: a one-line note in each doc that the community layer is served from committed JSON and the read path still touches no D1; a recorded owner-config item for the `/about#community-reports` transparency page.

- [ ] **Step 1: Add the README note**

In `README.md`, find the pipeline/data description (grep for `data/state/` — the directory-map line "`data/state/     committed last-known-good payloads + daily history snapshots`"). Immediately after that block, add:

```markdown
Phase-3 community layer: `run_pipeline.py` exports approved crowdsourced abuse
reports from D1 (read-only REST query) to the committed `data/state/community_reports.json`,
which the enrich read path consults as a `kind:"context"` `SOCDESK_COMMUNITY`
row. The read path serves that committed JSON as a static asset — `/api/enrich`
gains no D1 binding and never reads D1 per lookup.
```

- [ ] **Step 2: Add the CLAUDE.md note**

In `CLAUDE.md`, at the end of the no-account/D1 paragraph (the block around lines 117-124 that already explains IOC reporting is D1/OAuth-backed and does not touch the no-account read path), append:

```markdown
Phase 3 (community reports) publishes approved D1 rows to a committed
`data/state/community_reports.json` that the enrich read path consults with an
in-memory lookup (a `kind:"context"` row, out of the verdict tally); the read
path gains NO D1 binding — it reads the committed static asset only.
```

- [ ] **Step 3: Record the transparency-page owner-config**

There is **no `/about` route in `web/src`** (only `web/src/routes/Privacy.tsx`, a routable-but-hidden disclosure page). The `/about#community-reports` verify-link target is therefore **owner-authored content**, not a code task in this repo (spec §9). Add this bullet to the CLAUDE.md note (or the repo's handoff doc) so it is not lost:

```markdown
Owner-config (Phase 3, inert until set): publish the `/about#community-reports`
transparency page (what the dataset is, that every entry is owner-moderated,
count-not-verdict framing, and a dispute/removal contact). If an in-app route is
preferred over an owner-hosted page, clone `web/src/routes/Privacy.tsx` (a
`nav:false` routable disclosure page) and register it in `web/src/App.tsx` —
that would be a separate, out-of-Phase-3-scope change. Also set the Actions
secrets `CLOUDFLARE_D1_DATABASE_ID` and `CF_D1_READ_TOKEN` (a D1 Read-only
token), and confirm `CLOUDFLARE_ACCOUNT_ID` reaches the "Run collectors" step.
```

- [ ] **Step 4: Verify the notes landed**

Run: `git diff README.md CLAUDE.md`
Expected: each file gains the note; no other lines changed. Confirm the strings are present:
Run: `git grep -n "no D1 binding\|committed static asset\|community_reports.json" README.md CLAUDE.md`
Expected: at least one hit per file.

- [ ] **Step 5: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "docs(community): note committed-JSON community layer + no-D1 read path + owner-config"
```

---

## Self-Review

**1. Spec coverage** — every spec section maps to a task:

| Spec section | Task |
|---|---|
| §0 owned-files (create/modify) | File Structure + Tasks 1-7 |
| §1.1 read path no-account/no-D1 | Task 6 (asset read, derived env, no `DB`) + Global Constraint 1 |
| §1.2 / §3.2 context, out of tally | Task 5 (`kind:"context"`) + tally-unchanged test |
| §1.3 / §10.1 distinct-contributor copy | Task 3 (`COUNT(DISTINCT github_id)` taken directly) + Task 5 copy tests + Global Constraint 2 |
| §1.4 / §3.6.1 privacy fence (twice) | Task 3 whitelist projection + Task 2 `additionalProperties:false` + privacy test |
| §1.6 / §5 honest degradation | Task 3 `None` on failure + Task 4 last-known-good re-stamp + Task 6 `null` no-op |
| §3.1 D1 REST mechanism + SQL + JSON shape | Task 3 |
| §3.1 `CLOUDFLARE_ACCOUNT_ID` into collectors step + 2 new secrets + env threading | Task 4 |
| §3.3 `ASSETS.fetch`, memoize successes only, derived env | Task 6 |
| §3.4 copy/labelling/verify link | Task 5 (headline/facts/url) |
| §3.5 shared `communityKey` both sides | Task 1 (JS) + Task 3 (Python mirror) + parity fixture |
| §4 schema + `SCHEMA_FOR` registration | Task 2 |
| §5 first-run committed seed | Task 2 (seed) + Task 4 (re-stamp) |
| §6 test matrix + real commands | every task's test steps + "Test harness commands" |
| §7 acceptance criteria 1-8 | Tasks 3/5/6 tests + Task 6 manual acceptance |
| §8 anti-drift guardrails | Global Constraints 1-9 + per-task design notes |
| §9 open owner-config | Task 4 (secrets/workflow) + Task 7 (transparency page) |
| §10.2 minors (id in never-list, date pattern, enum parity, dispute contact, memoize-successes, env-threading) | Task 2 (date pattern, enum parity), Task 3 (`id` fenced), Task 4 (env-threading), Task 6 (memoize), Task 7 (dispute contact) |

No gaps found.

**2. Placeholder scan** — no "TBD/TODO/handle edge cases/similar to Task N"; every code and test step carries actual content. The only non-code steps (workflow YAML, docs, manual acceptance) carry exact text or explicit verification commands.

**3. Type consistency** — verified names/signatures agree across tasks: `communityKey(type, value)` (Task 1) is called by the JS source (Task 5) and mirrored by `community_key(ioc_type, ioc_value)` (Task 3), all reconciled by `key_parity.json`. `build_community_reports(fetch, now, env) -> dict|None` (Task 3) is called with those exact kwargs by `run_pipeline.run(..., env=...)` (Task 4) and stubbed with the same signature in the Task 4 tests. `loadCommunity(env, origin) -> object|null` (Task 6) injects `SOCDESK_COMMUNITY_DATA`, the exact `key` the Task 5 source reads. `validate_payload("community_reports.json", …)` depends on the `SCHEMA_FOR` registration (Task 2) and is used in Tasks 2/3. The category list has one spelling everywhere: `["brute-force","ssh","port-scan","web-app-attack","phishing","malware-c2","scanner","spam","exploited-host","other"]`.

---

## Execution options

**Plan complete. Two execution options:**

1. **Subagent-Driven (recommended)** — dispatch a fresh subagent per task with a two-stage review between tasks (superpowers:subagent-driven-development). Task order is strict: 1 → 2 → 3 → 4 → 5 → 6 → 7 (each task's Consumes are Produced by an earlier one).
2. **Inline Execution** — execute in-session with checkpoints (superpowers:executing-plans).
