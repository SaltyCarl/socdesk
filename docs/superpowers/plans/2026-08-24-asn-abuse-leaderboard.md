# ISP/ASN Abuse-Leaderboard (IOC-Reporting Phase 4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Aggregate already-published abusive indicators by network (ASN + ISP) into a committed/served `asn_leaderboard.json`, rendered as a read-only "which networks host the most reported abuse" leaderboard in a new Data Desk "Networks" tab — framed as reported/blocklisted abuse volume, never a verdict on the operator.

**Architecture:** One new pipeline builder (`pipeline/asn.py`) resolves ASN+ISP per distinct abusive IP from IPinfo's `org` field (the call the pipeline already makes for geolocation — the field is currently discarded), cache-first via a committed `asn_cache.json`, and folds the two already-published, PII-stripped inputs (`community_reports.json` ∪ `threat_ips.json`) into a ranked `networks` array. The payload rides the existing `gate() → last-known-good → triple dual-write → deploy` conveyor untouched. The web surface is a static `useStateData` read of the committed JSON — no D1, no API, no account — reached through a new `/desk#networks` tab; the read/verdict model is not touched.

**Tech Stack:** Python 3.12 (stdlib `re`/`json` + `jsonschema` gate), pytest (venv interpreter). Vite + React + TypeScript + Tailwind for the desk tab; ESLint + `tsc`/Vite build as the JSX gate; Vitest for the existing JS suite (regression only). GitHub Actions cron pipeline; git is the datastore (committed JSON).

**Spec:** `docs/superpowers/specs/2026-08-24-asn-abuse-leaderboard-design.md` (reviewed SHIP-TO-PLAN; owner decisions locked — see Global Constraints).

## Global Constraints

Every task's requirements implicitly include this section. Values copied from the spec.

1. **Free-tier only.** ASN comes from the IPinfo `org` field already present in the geolocation response the pipeline already fetches (`geo.py:19,68`); no new endpoint, no paid ASN DB. Cache-first via a committed `data/state/asn_cache.json`; only IPs new since the last run cost a call (mirrors `geo_cache.json`).
2. **HARD no-PII.** Aggregate network stats only. `pipeline/asn.py` never touches D1 or `github_id`; its inputs are already PII-stripped (`community.py:103-110`, `threat_ips.json` is identity-free). The schema's `additionalProperties:false` at BOTH the envelope and row levels fails closed (modeled on `community_reports.schema.json:4,17`).
3. **Committed-static-dataset.** The web view is a `useStateData` static fetch (`useStateData.ts:23,32`) — no D1/API/account on any request path. The read model is UNTOUCHED: `lib/enrich.mjs`, `functions/api/enrich.js`, `map.ts`, the verdict tally, and `App.tsx`'s route table are not modified.
4. **Attributed + "reported/blocklisted abuse volume, NOT a verdict on the operator."** Every headline/column/envelope says reported volume. Per-network `sources[]` keeps a community allegation distinguishable from an abuse.ch published blocklist C2 — the two are never silently merged.
5. **Honest degradation.** Missing token / unresolvable `org` → the IP is `unattributed`, never a fabricated ASN. Builder returns `None` on a structural error → `gate()` keeps last-known-good (`validate.py:46-48`). The view states its empty/error reason, never a blank screen.
6. **NO AI attribution.** SaltyCarl repo: no `Co-Authored-By`, no Claude references in commits, code, or comments.

**Owner decisions LOCKED (do not re-litigate):**
- Source scope = **UNION** (`community_reports` ∪ `threat_ips`/abuse.ch); keep the one-line `SOURCES` switch in `asn.py` for community-only fallback.
- Web surface = a **"Networks" tab in the Data Desk** (`/desk#networks`), NOT a top-level route.
- Caps: **`CAP = 200`** networks, **`EXAMPLE_CAP = 3`** example IPs/row.

**Gates (run from the repo root `C:\Users\Carl\Desktop\Projects\VIGIL`):**
- Python (this module): `./.venv/Scripts/python.exe -m pytest tests/test_asn_leaderboard.py -q` — ⚠ local pytest needs the **venv** interpreter; bare `python`/`py` lack `jsonschema`/`httpx`.
- Python (full suite, must stay green): `./.venv/Scripts/python.exe -m pytest tests/ -q`
- JSX build gate: `npm --prefix web run build` (runs `tsc` + Vite) and `cd web && npx eslint .`
- JS suite (regression only — no NEW JS test is added, see Task 1): `cd web && npx vitest run`

---

## File Structure

**Create:**
- `pipeline/asn.py` — `parse_org`, `resolve_asn`, `_distinct_abusive_ips`, `build_asn_leaderboard` (the ONLY logic file).
- `schemas/asn_leaderboard.schema.json` — dataset schema; the machine-checked no-PII fence.
- `data/state/asn_leaderboard.json` — committed dataset (first commit = empty envelope; guarantees a last-known-good exists from run 1).
- `data/state/asn_cache.json` — committed per-IP cache (first commit = `{}`).
- `tests/test_asn_leaderboard.py` — pure `parse_org`/`resolve_asn`/aggregation + no-PII + degradation + schema tests.
- `tests/fixtures/asn/org_parity.json` — shared `org → {asn,isp}` fixture (mirrors the JS regex; parity-tested like `tests/fixtures/community/key_parity.json`).
- `web/src/components/views/AsnLeaderboardView.tsx` — ranked table (cloned from `SourcesView.tsx`).
- `web/src/routes/AsnLeaderboardRoute.tsx` — `useStateData` route wrapper (cloned from `FeedRoute.tsx`/`SourcesRoute.tsx`).

**Modify:**
- `pipeline/validate.py` — register `SCHEMA_FOR["asn_leaderboard.json"]` (line 8-19 map).
- `run_pipeline.py` — load `asn_cache`, call `build_asn_leaderboard(...)`, add the payload before `gate()` (line 99), persist `asn_cache.json` next to `geo_cache.json` (line 118-121 pattern).
- `web/src/components/views/types.ts` — add `AsnLeaderboardPayload` / `AsnNetwork` (optional-tolerant, per the rule at `types.ts:6-8`).
- `web/src/routes/DataDeskRoute.tsx` — add `{ key: 'networks', label: 'Networks' }` to `TABS` (line 26-33) and mount `{tab === 'networks' && <AsnLeaderboardRoute />}` (line 100-107).
- `README.md` — one line after the Phase-3 paragraph (line 227).

**No workflow change:** `.github/workflows/collect-and-deploy.yml` already exposes `IPINFO_TOKEN` in the collectors step env (line 42) and commits `git add data/state` (line 57), which captures both the new dataset and the cache. Task 5 only *confirms* this.

---

### Task 1: `parse_org` + the shared parity fixture (pure regex)

**Files:**
- Create: `pipeline/asn.py`
- Create: `tests/fixtures/asn/org_parity.json`
- Test: `tests/test_asn_leaderboard.py`

**Interfaces:**
- Consumes: nothing (pure).
- Produces: `parse_org(org) -> (asn:str, isp:str) | (None, None)`; module constants `IPINFO_URL`, `_ORG_RE`, `CAP=200`, `EXAMPLE_CAP=3`, `SOURCES=("community","abuse.ch")`, `ATTRIBUTION`.

**Parity note — why no JS test.** The JS regex lives inline in `IPINFO.run` at `lib/enrich.mjs:367` (`const m = org.match(/^(AS\d+)\s+(.*)$/)`) and is **not exported**. Adding a JS parity test would require either (a) modifying `enrich.mjs` to export it — forbidden by the anti-drift fence (Phase 4 touches nothing in the read path, Constraint 3), or (b) duplicating the regex in a test, which would test a copy rather than the source (meaningless parity). So `org_parity.json` is the single source of truth: it encodes the canonical `org → {asn,isp}` mapping that the JS regex (verified by reading `enrich.mjs:367`, left unchanged) and the Python `parse_org` both produce, and the **Python** test asserts `parse_org` against it. The existing Vitest suite still runs as a regression gate; no new JS file is added.

- [ ] **Step 1: Write the parity fixture**

Create `tests/fixtures/asn/org_parity.json` (the `null` entries model IPinfo `org` strings with no leading ASN — name-only or empty — which must resolve to `(None, None)`, never a faked ASN):

```json
[
  { "org": "AS60729 Zwiebelfreunde e.V.", "asn": "AS60729", "isp": "Zwiebelfreunde e.V." },
  { "org": "AS14061 DigitalOcean, LLC", "asn": "AS14061", "isp": "DigitalOcean, LLC" },
  { "org": "AS13335 Cloudflare, Inc.", "asn": "AS13335", "isp": "Cloudflare, Inc." },
  { "org": "AS60729  Extra Spaces Inc", "asn": "AS60729", "isp": "Extra Spaces Inc" },
  { "org": "Cloudflare, Inc.", "asn": null, "isp": null },
  { "org": "", "asn": null, "isp": null }
]
```

- [ ] **Step 2: Write the failing tests**

Create `tests/test_asn_leaderboard.py` with the imports and the parse tests:

```python
import json
from pathlib import Path

from pipeline import asn
from pipeline.validate import SCHEMA_FOR, validate_payload
from tests.conftest import FIXED_NOW

FIXTURES = Path(__file__).parent / "fixtures" / "asn"


def test_parse_org_parity_fixture():
    parity = json.loads((FIXTURES / "org_parity.json").read_text(encoding="utf-8"))
    for row in parity:
        assert asn.parse_org(row["org"]) == (row["asn"], row["isp"])


def test_parse_org_name_only_and_empty_are_none():
    assert asn.parse_org("Cloudflare, Inc.") == (None, None)
    assert asn.parse_org("") == (None, None)
    assert asn.parse_org(None) == (None, None)
    assert asn.parse_org("   ") == (None, None)
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_asn_leaderboard.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'pipeline.asn'` (or `AttributeError: parse_org`).

- [ ] **Step 4: Write the minimal implementation**

Create `pipeline/asn.py` (constants + `parse_org` only for now):

```python
import re

from collectors.base import iso

IPINFO_URL = "https://ipinfo.io/{ip}/json?token={token}"
_ORG_RE = re.compile(r"^(AS\d+)\s+(.*)$")   # byte-mirror of lib/enrich.mjs:367

CAP = 200            # networks published (ranked); backstop below the schema's 1000
EXAMPLE_CAP = 3
SOURCES = ("community", "abuse.ch")   # switch to ("community",) for community-only

ATTRIBUTION = (
    "Networks (ASN / ISP) ranked by the volume of abusive IPs reported to "
    "SOCDesk (community, owner-moderated) and published on the abuse.ch Feodo "
    "Tracker / ThreatFox blocklists. A count of reported/blocklisted IPs hosted "
    "on a network — NOT a verdict on the network or its operator. ASN/ISP "
    "mapping by IPinfo (https://ipinfo.io); a report is an allegation reviewed "
    "before publication, not a confirmation."
)


def parse_org(org):
    """'AS60729 Zwiebelfreunde e.V.' -> ('AS60729', 'Zwiebelfreunde e.V.').
    Returns (None, None) when the string has no leading AS number (some IPinfo
    orgs are name-only or empty) — the IP is then UNATTRIBUTED, never faked."""
    m = _ORG_RE.match(str(org or "").strip())
    return (m.group(1), m.group(2).strip()) if m else (None, None)
```

(`iso` is imported now so later steps in this module need no new import.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_asn_leaderboard.py -q`
Expected: PASS (2 tests).

- [ ] **Step 6: Commit**

```bash
git add pipeline/asn.py tests/test_asn_leaderboard.py tests/fixtures/asn/org_parity.json
git commit -m "feat(asn): parse_org ASN/ISP splitter + shared parity fixture"
```

---

### Task 2: `resolve_asn` — cache-first IPinfo resolution

**Files:**
- Modify: `pipeline/asn.py`
- Test: `tests/test_asn_leaderboard.py`

**Interfaces:**
- Consumes: `parse_org` (Task 1); a `fetch(url)` callable matching `pipeline.http.http_fetch` (`http.py:6`).
- Produces: `resolve_asn(ip, cache, fetch, token) -> {"asn","isp","country"} | None`. Cache-first (a hit costs no call), writes successful lookups back into `cache`, swallows all upstream failures. Deliberately a copy of the `geo.resolve`/`geo._ipinfo` shape (`geo.py:61-113`).

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_asn_leaderboard.py` a fetch stub helper and the resolver tests:

```python
def _ipinfo_fetch(orgs, calls=None):
    """fetch(url) mapping IP -> {'org','country'} from `orgs`; records every
    looked-up IP into `calls` (to assert cache-first skips the call)."""
    def fetch(url, *, method="GET", json=None, headers=None, text=False):
        assert url.startswith("https://ipinfo.io/") and "/json?token=" in url
        ip = url[len("https://ipinfo.io/"):].split("/json", 1)[0]
        if calls is not None:
            calls.append(ip)
        return orgs.get(ip, {})       # missing -> empty body -> unattributed
    return fetch


def test_resolve_cache_hit_makes_no_call():
    cache = {"9.9.9.9": {"asn": "AS19281", "isp": "Quad9", "country": "CH"}}
    calls = []
    got = asn.resolve_asn("9.9.9.9", cache, _ipinfo_fetch({}, calls), "tok")
    assert got == {"asn": "AS19281", "isp": "Quad9", "country": "CH"}
    assert calls == []                # a hit never touches the network


def test_resolve_new_ip_is_fetched_once_and_cached():
    orgs = {"1.2.3.4": {"org": "AS64500 Example ISP", "country": "us"}}
    cache, calls = {}, []
    got = asn.resolve_asn("1.2.3.4", cache, _ipinfo_fetch(orgs, calls), "tok")
    assert got == {"asn": "AS64500", "isp": "Example ISP", "country": "US"}
    assert calls == ["1.2.3.4"] and cache["1.2.3.4"]["asn"] == "AS64500"


def test_resolve_no_token_returns_none_without_calling():
    calls = []
    assert asn.resolve_asn("1.2.3.4", {}, _ipinfo_fetch({}, calls), None) is None
    assert calls == []


def test_resolve_name_only_org_is_unattributed():
    orgs = {"1.2.3.4": {"org": "Some ISP Without ASN", "country": "US"}}
    assert asn.resolve_asn("1.2.3.4", {}, _ipinfo_fetch(orgs), "tok") is None


def test_resolve_network_error_returns_none():
    def boom(url, **kw):
        raise RuntimeError("ipinfo 503")
    assert asn.resolve_asn("1.2.3.4", {}, boom, "tok") is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_asn_leaderboard.py -q`
Expected: FAIL — `AttributeError: module 'pipeline.asn' has no attribute 'resolve_asn'`.

- [ ] **Step 3: Write the minimal implementation**

Append to `pipeline/asn.py` (after `parse_org`):

```python
def resolve_asn(ip, cache, fetch, token):
    """Cache-first ASN lookup. Returns {'asn','isp','country'} or None.
    (1) cache hit -> no call; (2) IPinfo when fetch+token present, cached on
    success; (3) None (UNATTRIBUTED). Never raises for upstream reasons —
    copies the geo.resolve discipline (geo.py:89-113)."""
    hit = cache.get(ip)
    if isinstance(hit, dict) and hit.get("asn"):
        return hit
    if fetch is None or not token:
        return None
    try:
        data = fetch(IPINFO_URL.format(ip=ip, token=token))
    except Exception:                          # noqa: BLE001 — network/HTTP, never fatal
        return None
    if not isinstance(data, dict):
        return None
    asn_num, isp = parse_org(data.get("org"))
    if not asn_num:
        return None
    rec = {"asn": asn_num, "isp": isp or asn_num,
           "country": (data.get("country") or "").strip().upper()[:2]}
    cache[ip] = rec                            # persisted for next run
    return rec
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_asn_leaderboard.py -q`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add pipeline/asn.py tests/test_asn_leaderboard.py
git commit -m "feat(asn): cache-first IPinfo ASN resolver with honest degradation"
```

---

### Task 3: `_distinct_abusive_ips` + `build_asn_leaderboard` aggregation

**Files:**
- Modify: `pipeline/asn.py`
- Test: `tests/test_asn_leaderboard.py`

**Interfaces:**
- Consumes: `resolve_asn` (Task 2), `iso` (Task 1 import), `SOURCES`/`CAP`/`EXAMPLE_CAP`/`ATTRIBUTION` (Task 1). Inputs mirror the two committed payloads: `community` = `{"indicators": {key: {"type","value","categories",...}}}` (`community.py:112-119`); `threat_ips` = `{"ips": [{"ip", ...}]}` (`threat_ips.py:90-98`).
- Produces:
  - `_distinct_abusive_ips(community, threat_ips)` — generator of `(ip, source, category_or_None, is_report)` for every ipv4/ipv6 indicator; domains/urls/hashes are skipped (no ASN — NOT counted as unattributed).
  - `build_asn_leaderboard(community, threat_ips, cache, fetch, now, token) -> dict | None`. Full envelope `{generated_at, schema_version, attribution, count, total_abusive_ips, unattributed_ips, cap, truncated, networks[]}`; each row `{asn, isp, country?, ip_count, report_count, categories[], sources[], examples[]}`. Returns `None` on a structural error (last-known-good). Prunes `cache` to IPs seen this run.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_asn_leaderboard.py` the input builders and aggregation tests:

```python
def _community(*entries):
    """entries: (value, [categories]) -> a community_reports-shaped payload."""
    return {"indicators": {
        f"ipv4|{v}": {"type": "ipv4", "value": v, "reporters": 1,
                      "categories": list(cats)} for v, cats in entries}}


def _threat(*ips):
    return {"ips": [{"ip": ip, "source": "feodotracker"} for ip in ips]}


def _orgs_for(*pairs):
    return {ip: {"org": org, "country": cc} for ip, org, cc in pairs}


def test_aggregates_ips_on_one_asn_ranked():
    orgs = _orgs_for(
        ("185.220.101.34", "AS60729 Zwiebelfreunde e.V.", "DE"),
        ("185.220.101.42", "AS60729 Zwiebelfreunde e.V.", "DE"),
        ("162.243.103.246", "AS14061 DigitalOcean, LLC", "US"))
    community = _community(("185.220.101.34", ["phishing"]),
                          ("185.220.101.42", ["scanner", "phishing"]))
    board = asn.build_asn_leaderboard(
        community, _threat("162.243.103.246"), {},
        _ipinfo_fetch(orgs), FIXED_NOW, token="tok")
    assert board["count"] == 2
    assert board["total_abusive_ips"] == 3 and board["unattributed_ips"] == 0
    assert board["cap"] == 200 and board["truncated"] is False
    assert [n["asn"] for n in board["networks"]] == ["AS60729", "AS14061"]  # ip_count desc
    top = board["networks"][0]
    assert top["asn"] == "AS60729" and top["isp"] == "Zwiebelfreunde e.V."
    assert top["ip_count"] == 2 and top["report_count"] == 2
    assert top["categories"] == ["phishing", "scanner"]   # deduped + sorted union
    assert top["sources"] == ["community"] and top["country"] == "DE"
    assert len(top["examples"]) <= asn.EXAMPLE_CAP
    assert top["examples"] == sorted(top["examples"])


def test_rank_tie_breaks_on_asn():
    orgs = _orgs_for(("1.1.1.1", "AS200 B Net", "US"),
                     ("2.2.2.2", "AS100 A Net", "US"))
    board = asn.build_asn_leaderboard(
        _community(("1.1.1.1", ["ssh"]), ("2.2.2.2", ["ssh"])), {},
        {}, _ipinfo_fetch(orgs), FIXED_NOW, token="tok")
    assert [n["asn"] for n in board["networks"]] == ["AS100", "AS200"]  # equal count -> asn asc


def test_feed_only_asn_has_zero_report_count():
    orgs = _orgs_for(("162.243.103.246", "AS14061 DigitalOcean, LLC", "US"))
    board = asn.build_asn_leaderboard(
        {}, _threat("162.243.103.246"), {}, _ipinfo_fetch(orgs), FIXED_NOW, token="tok")
    (row,) = board["networks"]
    assert row["report_count"] == 0 and row["sources"] == ["abuse.ch"]
    assert row["categories"] == []                 # abuse.ch malware family != category enum
    assert row["report_count"] <= row["ip_count"]


def test_both_sources_merge_on_one_asn():
    orgs = _orgs_for(("1.1.1.1", "AS100 Shared Net", "US"),
                     ("2.2.2.2", "AS100 Shared Net", "US"))
    board = asn.build_asn_leaderboard(
        _community(("1.1.1.1", ["ssh"])), _threat("2.2.2.2"),
        {}, _ipinfo_fetch(orgs), FIXED_NOW, token="tok")
    (row,) = board["networks"]
    assert row["ip_count"] == 2 and row["report_count"] == 1
    assert row["sources"] == ["abuse.ch", "community"]   # sorted union


def test_unattributed_ip_gets_no_fabricated_asn():
    orgs = _orgs_for(("1.2.3.4", "Some ISP Without ASN", "US"))
    board = asn.build_asn_leaderboard(
        _community(("1.2.3.4", ["ssh"])), {}, {}, _ipinfo_fetch(orgs), FIXED_NOW, token="tok")
    assert board["networks"] == []
    assert board["unattributed_ips"] == 1 and board["total_abusive_ips"] == 1


def test_non_ip_indicators_are_not_unattributed():
    community = {"indicators": {"domain|evil.example": {
        "type": "domain", "value": "evil.example", "reporters": 1,
        "categories": ["phishing"]}}}
    board = asn.build_asn_leaderboard(community, {}, {}, _ipinfo_fetch({}), FIXED_NOW, token="tok")
    assert board["total_abusive_ips"] == 0 and board["unattributed_ips"] == 0


def test_cache_pruned_to_ips_seen_this_run():
    orgs = _orgs_for(("1.2.3.4", "AS64500 Example ISP", "US"))
    cache = {"5.5.5.5": {"asn": "AS1", "isp": "old", "country": "US"}}
    asn.build_asn_leaderboard(
        _community(("1.2.3.4", ["ssh"])), {}, cache, _ipinfo_fetch(orgs), FIXED_NOW, token="tok")
    assert "5.5.5.5" not in cache and "1.2.3.4" in cache


def test_cached_ip_is_not_refetched_by_builder():
    cache = {"9.9.9.9": {"asn": "AS19281", "isp": "Quad9", "country": "CH"}}
    calls = []
    asn.build_asn_leaderboard(
        _community(("9.9.9.9", ["scanner"])), {}, cache,
        _ipinfo_fetch({}, calls), FIXED_NOW, token="tok")
    assert calls == []                             # cache-first: quota discipline


def test_sources_switch_to_community_only(monkeypatch):
    monkeypatch.setattr(asn, "SOURCES", ("community",))
    orgs = _orgs_for(("1.1.1.1", "AS100 Community Net", "US"))
    board = asn.build_asn_leaderboard(
        _community(("1.1.1.1", ["ssh"])), _threat("162.243.103.246"),
        {}, _ipinfo_fetch(orgs), FIXED_NOW, token="tok")
    assert {s for n in board["networks"] for s in n["sources"]} == {"community"}
    assert board["total_abusive_ips"] == 1         # abuse.ch IP excluded entirely


def test_missing_token_all_unattributed_but_valid():
    board = asn.build_asn_leaderboard(
        _community(("1.2.3.4", ["ssh"])), _threat("5.6.7.8"),
        {}, _ipinfo_fetch({}), FIXED_NOW, token=None)
    assert board is not None and board["networks"] == []
    assert board["unattributed_ips"] == 2 and board["total_abusive_ips"] == 2
    assert board["generated_at"] == asn.iso(FIXED_NOW)


def test_fetch_raising_on_every_ip_still_valid():
    def boom(url, **kw):
        raise RuntimeError("ipinfo 503")
    board = asn.build_asn_leaderboard(
        _community(("1.2.3.4", ["ssh"])), {}, {}, boom, FIXED_NOW, token="tok")
    assert board is not None and board["networks"] == [] and board["unattributed_ips"] == 1


def test_structural_error_returns_none():
    bad = {"indicators": {"ipv4|x": {"type": "ipv4"}}}   # no "value" -> KeyError inside build
    assert asn.build_asn_leaderboard(bad, {}, {}, _ipinfo_fetch({}), FIXED_NOW, token="tok") is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_asn_leaderboard.py -q`
Expected: FAIL — `AttributeError: ... has no attribute 'build_asn_leaderboard'`.

- [ ] **Step 3: Write the minimal implementation**

Append to `pipeline/asn.py`:

```python
def _distinct_abusive_ips(community, threat_ips):
    """Yield (ip, source, category_or_None, is_report) for every ipv4/ipv6
    abusive indicator. Domains/urls/hashes have no ASN -> skipped (NOT counted
    as unattributed; they are simply not network-scoped)."""
    if "community" in SOURCES:
        for entry in (community or {}).get("indicators", {}).values():
            if entry.get("type") in ("ipv4", "ipv6"):
                cats = entry.get("categories") or []
                if cats:
                    for cat in cats:
                        yield entry["value"], "community", cat, True
                else:
                    yield entry["value"], "community", None, True
    if "abuse.ch" in SOURCES:
        for row in (threat_ips or {}).get("ips", []):
            yield row["ip"], "abuse.ch", None, False   # malware family != category enum


def build_asn_leaderboard(community, threat_ips, cache, fetch, now, token):
    """Fold the two committed inputs into a ranked, capped network leaderboard.
    Pure over its inputs except the cache-first IPinfo call in resolve_asn.
    Returns the full envelope, or None on a structural failure (the caller then
    keeps last-known-good)."""
    try:
        # 1. fold indicators -> per-IP {sources, categories, is_report}
        per_ip = {}
        for ip, source, category, is_report in _distinct_abusive_ips(community, threat_ips):
            rec = per_ip.setdefault(ip, {"sources": set(), "categories": set(),
                                         "is_report": False})
            rec["sources"].add(source)
            if category:
                rec["categories"].add(category)
            rec["is_report"] = rec["is_report"] or is_report

        # 2. resolve ASN per DISTINCT ip (cache-first); None -> unattributed
        networks = {}
        unattributed = 0
        seen = set()
        for ip, rec in per_ip.items():
            seen.add(ip)
            placed = resolve_asn(ip, cache, fetch, token)
            if placed is None:
                unattributed += 1
                continue
            net = networks.setdefault(placed["asn"], {
                "asn": placed["asn"], "isp": placed["isp"], "countries": {},
                "ips": set(), "report_ips": set(), "categories": set(), "sources": set()})
            net["ips"].add(ip)
            if rec["is_report"]:
                net["report_ips"].add(ip)
            net["categories"] |= rec["categories"]
            net["sources"] |= rec["sources"]
            cc = placed.get("country")
            if cc:
                net["countries"][cc] = net["countries"].get(cc, 0) + 1

        # 3. finalize rows (modal country: highest count, then alpha; deterministic)
        rows = []
        for net in networks.values():
            row = {
                "asn": net["asn"],
                "isp": net["isp"],
                "ip_count": len(net["ips"]),
                "report_count": len(net["report_ips"]),
                "categories": sorted(net["categories"]),
                "sources": sorted(net["sources"]),
                "examples": sorted(net["ips"])[:EXAMPLE_CAP],
            }
            if net["countries"]:
                row["country"] = sorted(net["countries"].items(),
                                        key=lambda kv: (-kv[1], kv[0]))[0][0]
            rows.append(row)

        # 4. rank by ip_count desc, asn tie-break; cap
        rows.sort(key=lambda r: (-r["ip_count"], r["asn"]))
        capped = rows[:CAP]

        # 5. prune cache to IPs seen this run (threat_ips.py:79-82 pattern)
        for ip in list(cache):
            if ip not in seen:
                del cache[ip]

        return {
            "generated_at": iso(now),
            "schema_version": 1,
            "attribution": ATTRIBUTION,
            "count": len(capped),
            "total_abusive_ips": len(per_ip),
            "unattributed_ips": unattributed,
            "cap": CAP,
            "truncated": len(rows) > CAP,
            "networks": capped,
        }
    except Exception:                              # noqa: BLE001 — structural -> last-known-good
        return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_asn_leaderboard.py -q`
Expected: PASS (all Task 1-3 tests).

- [ ] **Step 5: Commit**

```bash
git add pipeline/asn.py tests/test_asn_leaderboard.py
git commit -m "feat(asn): fold community + abuse.ch IPs into ranked network leaderboard"
```

---

### Task 4: Schema + `SCHEMA_FOR` registration + committed seeds + no-PII fence

**Files:**
- Create: `schemas/asn_leaderboard.schema.json`
- Create: `data/state/asn_leaderboard.json`
- Create: `data/state/asn_cache.json`
- Modify: `pipeline/validate.py:8-19` (the `SCHEMA_FOR` map)
- Test: `tests/test_asn_leaderboard.py`

**Interfaces:**
- Consumes: `build_asn_leaderboard` (Task 3), `SCHEMA_FOR`/`validate_payload` (`validate.py`).
- Produces: `SCHEMA_FOR["asn_leaderboard.json"] == "asn_leaderboard.schema.json"`; the schema's `additionalProperties:false` at BOTH envelope and row levels (the no-PII fence, modeled on `community_reports.schema.json:4,17`); the committed empty seed (guarantees a last-known-good exists from run 1).

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_asn_leaderboard.py`:

```python
def test_schema_is_registered():
    assert SCHEMA_FOR["asn_leaderboard.json"] == "asn_leaderboard.schema.json"


def test_built_payload_validates_against_schema():
    orgs = _orgs_for(("185.220.101.34", "AS60729 Zwiebelfreunde e.V.", "DE"),
                     ("162.243.103.246", "AS14061 DigitalOcean, LLC", "US"))
    board = asn.build_asn_leaderboard(
        _community(("185.220.101.34", ["phishing"])), _threat("162.243.103.246"),
        {}, _ipinfo_fetch(orgs), FIXED_NOW, token="tok")
    assert validate_payload("asn_leaderboard.json", board, "schemas") == []


def test_committed_empty_seed_is_valid():
    seed = json.loads(Path("data/state/asn_leaderboard.json").read_text(encoding="utf-8"))
    assert validate_payload("asn_leaderboard.json", seed, "schemas") == []
    assert seed["networks"] == [] and seed["count"] == 0


def test_no_pii_tokens_in_serialized_payload():
    # DEFENSIVE mock: even if a community indicator carried identity fields, the
    # builder never projects them (it reads only type/value/categories).
    community = {"indicators": {"ipv4|1.2.3.4": {
        "type": "ipv4", "value": "1.2.3.4", "reporters": 1, "categories": ["ssh"],
        "github_id": 4242, "evidence": "internal 10.0.0.5 log", "comment": "side note"}}}
    orgs = _orgs_for(("1.2.3.4", "AS64500 Example ISP", "US"))
    board = asn.build_asn_leaderboard(community, {}, {}, _ipinfo_fetch(orgs), FIXED_NOW, token="tok")
    blob = json.dumps(board)
    for forbidden in ("github_id", "evidence", "comment", "4242",
                      "internal 10.0.0.5", "side note"):
        assert forbidden not in blob


def test_injected_extra_field_fails_the_schema_fence():
    orgs = _orgs_for(("1.2.3.4", "AS64500 Example ISP", "US"))
    board = asn.build_asn_leaderboard(
        _community(("1.2.3.4", ["ssh"])), {}, {}, _ipinfo_fetch(orgs), FIXED_NOW, token="tok")
    board["networks"][0]["reporter"] = "octocat"   # stray row-level field
    assert validate_payload("asn_leaderboard.json", board, "schemas") != []
    bad_envelope = dict(board, leaked="x")          # stray envelope-level field
    board["networks"][0].pop("reporter")
    assert validate_payload("asn_leaderboard.json", bad_envelope, "schemas") != []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_asn_leaderboard.py -q`
Expected: FAIL — `test_schema_is_registered` (KeyError/assert) and the others error on the missing schema file / missing seed.

- [ ] **Step 3: Create the schema**

Create `schemas/asn_leaderboard.schema.json` (the `categories` enum is `lib/reporting/validate.mjs` `CATEGORIES` verbatim — lines 4-7; keep in lockstep):

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

- [ ] **Step 4: Create the committed seeds**

Create `data/state/asn_leaderboard.json` (empty envelope — must validate):

```json
{"generated_at":"2026-08-24T00:00:00Z","schema_version":1,"attribution":"Networks (ASN / ISP) ranked by the volume of abusive IPs reported to SOCDesk and published on the abuse.ch blocklists. Reported/blocklisted abuse volume hosted on a network — NOT a verdict on the network or its operator. ASN/ISP mapping by IPinfo (https://ipinfo.io).","count":0,"total_abusive_ips":0,"unattributed_ips":0,"cap":200,"truncated":false,"networks":[]}
```

Create `data/state/asn_cache.json`:

```json
{}
```

- [ ] **Step 5: Register the schema**

In `pipeline/validate.py`, add the entry to the `SCHEMA_FOR` dict (after the `community_reports.json` line, line 18):

```python
    "community_reports.json": "community_reports.schema.json",
    "asn_leaderboard.json": "asn_leaderboard.schema.json",
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_asn_leaderboard.py -q`
Expected: PASS (all tests).

- [ ] **Step 7: Commit**

```bash
git add schemas/asn_leaderboard.schema.json data/state/asn_leaderboard.json data/state/asn_cache.json pipeline/validate.py tests/test_asn_leaderboard.py
git commit -m "feat(asn): leaderboard schema (two-level no-PII fence) + empty seeds + registration"
```

---

### Task 5: Wire `build_asn_leaderboard` into `run_pipeline.py`

**Files:**
- Modify: `run_pipeline.py` (constant near line 18; `asn_cache` load near line 71-73; build block after the community block at line 92-97 and before `gate()` at line 99; persist block after line 118-121)
- Verify (no change): `.github/workflows/collect-and-deploy.yml`
- Test: `tests/test_pipeline.py`

**Interfaces:**
- Consumes: `build_asn_leaderboard` (Task 3), the assembled `payloads["community_reports.json"]`/`payloads["threat_ips.json"]` (falling back to `state`), the loaded `asn_cache`, `iso` (already imported, `run_pipeline.py:9`), `env` (`run()` param, line 54).
- Produces: `payloads["asn_leaderboard.json"]` added before `gate()` (so it inherits schema validation + last-known-good + triple dual-write for free); `data/state/asn_cache.json` persisted alongside `geo_cache.json`.

**Token-threading decision (stated per reviewer minor):** thread `IPINFO_TOKEN` via **`run()`'s `env`** — `token=(env or {}).get("IPINFO_TOKEN")`. This matches the community precedent (`run_pipeline.py:92` passes `env` to `build_community_reports`; `__main__` passes `env=os.environ`, line 145) and is directly testable without monkeypatching `os.environ` (the geo path instead reads `os.environ.get` inline at `publish.py:87`; we deliberately pick the more testable `env` route here). Note (no action): at the ~300-IP ceiling, geo and asn each fetching IPinfo for a threat IP on a cold start is an immaterial double-fetch; not worth coupling their caches.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_pipeline.py` (reusing the existing `_pipeline_fetch` helper at lines 49-64 and the `monkeypatch` pattern of `test_community_payload_published_and_env_threaded` at 67-89):

```python
def test_asn_leaderboard_published_and_token_threaded(fake_fetch, tmp_path, monkeypatch):
    import run_pipeline
    payload = {"generated_at": "seed", "schema_version": 1, "attribution": "a",
               "count": 1, "total_abusive_ips": 1, "unattributed_ips": 0,
               "cap": 200, "truncated": False,
               "networks": [{"asn": "AS64500", "isp": "Example", "country": "US",
                             "ip_count": 1, "report_count": 1,
                             "categories": ["ssh"], "sources": ["community"],
                             "examples": ["1.2.3.4"]}]}
    seen = {}

    def fake_build(community, threat_ips, cache, fetch, now, token):
        seen["token"] = token
        cache["1.2.3.4"] = {"asn": "AS64500", "isp": "Example", "country": "US"}
        return payload
    monkeypatch.setattr(run_pipeline, "build_asn_leaderboard", fake_build)

    out, state = tmp_path / "o", tmp_path / "s"
    run(fetch=_pipeline_fetch(fake_fetch), now=FIXED_NOW, out_dir=out, state_dir=state,
        schemas_dir="schemas", sources_path="data/sources.json",
        env={"IPINFO_TOKEN": "tok"})

    assert seen["token"] == "tok"                     # threaded via run()'s env
    written = json.loads((out / "asn_leaderboard.json").read_text(encoding="utf-8"))
    assert written["networks"][0]["asn"] == "AS64500"
    cache = json.loads((state / "asn_cache.json").read_text(encoding="utf-8"))
    assert cache["1.2.3.4"]["asn"] == "AS64500"        # cache persisted


def test_asn_leaderboard_keeps_last_known_good_on_none(fake_fetch, tmp_path, monkeypatch):
    import run_pipeline
    monkeypatch.setattr(run_pipeline, "build_asn_leaderboard",
                        lambda community, threat_ips, cache, fetch, now, token: None)
    out, state = tmp_path / "o", tmp_path / "s"
    state.mkdir(parents=True)
    prior = {"generated_at": "2020-01-01T00:00:00Z", "schema_version": 1,
             "attribution": "a", "count": 0, "total_abusive_ips": 0,
             "unattributed_ips": 0, "cap": 200, "truncated": False, "networks": []}
    (state / "asn_leaderboard.json").write_text(json.dumps(prior), encoding="utf-8")

    run(fetch=_pipeline_fetch(fake_fetch), now=FIXED_NOW, out_dir=out, state_dir=state,
        schemas_dir="schemas", sources_path="data/sources.json", env={})

    kept = json.loads((out / "asn_leaderboard.json").read_text(encoding="utf-8"))
    assert kept["networks"] == []                      # prior retained (not blanked)
    assert kept["generated_at"] != prior["generated_at"]   # re-stamped this run
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_pipeline.py -q`
Expected: FAIL — `AttributeError: module 'run_pipeline' has no attribute 'build_asn_leaderboard'` (import not yet added), or `asn_leaderboard.json` / `asn_cache.json` not written.

- [ ] **Step 3: Add the import and the cache-name constant**

In `run_pipeline.py`, add the import beside the community import (after line 10) and a cache-name constant beside `GEO_CACHE_NAME` (after line 18):

```python
from pipeline.asn import build_asn_leaderboard
from pipeline.community import build_community_reports
```

```python
GEO_CACHE_NAME = "geo_cache.json"    # IP -> {lat,lng,country,city,precision}
ASN_CACHE_NAME = "asn_cache.json"    # IP -> {asn,isp,country}
```

- [ ] **Step 4: Load the ASN cache, build the leaderboard, and persist the cache**

In `run_pipeline.run()`, after the community block (line 92-97) and before `gate()` (line 99), add:

```python
    # ASN abuse-leaderboard (Phase 4): aggregate the already-published,
    # PII-stripped community + abuse.ch IPs by network via IPinfo's `org` field
    # (cache-first, only new IPs cost a call). Built AFTER community + threat_ips
    # so it consumes their fresh payloads (falling back to the committed prior).
    # Placed before gate() so it inherits schema validation + last-known-good +
    # triple dual-write. NO D1, NO identity — inputs are already PII-stripped.
    asn_cache = state.get(ASN_CACHE_NAME, {})
    if not isinstance(asn_cache, dict):
        asn_cache = {}
    leaderboard = build_asn_leaderboard(
        payloads.get("community_reports.json") or state.get("community_reports.json"),
        payloads.get("threat_ips.json") or state.get("threat_ips.json"),
        asn_cache, fetch, now, token=(env or {}).get("IPINFO_TOKEN"))
    if leaderboard is not None:
        payloads["asn_leaderboard.json"] = leaderboard
    elif "asn_leaderboard.json" in state:
        payloads["asn_leaderboard.json"] = dict(
            state["asn_leaderboard.json"], generated_at=iso(now))
```

Then, after the geo-cache persist block (line 118-121), add the ASN-cache persist:

```python
    (state_dir / ASN_CACHE_NAME).write_text(
        json.dumps(asn_cache, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":")),
        encoding="utf-8")
```

- [ ] **Step 5: Run the wiring tests, then the full suite**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_pipeline.py -q`
Expected: PASS (both new tests + the existing end-to-end/community tests).

Run: `./.venv/Scripts/python.exe -m pytest tests/ -q`
Expected: PASS (whole Python suite green — confirms `test_end_to_end_with_one_source_down` still passes now that `asn_leaderboard.json` is also published; its assertions use subset `<=`, and with no token every IP is unattributed so the payload is a valid empty leaderboard).

- [ ] **Step 6: Confirm the workflow needs no change**

Open `.github/workflows/collect-and-deploy.yml`. Confirm `IPINFO_TOKEN: ${{ secrets.IPINFO_TOKEN }}` is present in the "Run collectors" step env (line 42) and that the "Commit state snapshots" step runs `git add data/state` (line 57) — this already commits the new `asn_leaderboard.json` and `asn_cache.json`. No edit required.

- [ ] **Step 7: Commit**

```bash
git add run_pipeline.py tests/test_pipeline.py
git commit -m "feat(asn): wire leaderboard build + cache persist into the pipeline"
```

---

### Task 6: The "Networks" Data Desk tab (types + view + route + tab wiring)

**Files:**
- Modify: `web/src/components/views/types.ts`
- Create: `web/src/components/views/AsnLeaderboardView.tsx`
- Create: `web/src/routes/AsnLeaderboardRoute.tsx`
- Modify: `web/src/routes/DataDeskRoute.tsx:26-33,100-107`

**Interfaces:**
- Consumes: `useStateData<T>` (`useStateData.ts:32`), `ViewHeader` (`ViewFrame.tsx`), `AsyncGate`/`SkeletonRows`/`EmptyState` (`states.tsx`), `MicroLabel` (`components/ui`), `CountUp` (`views/CountUp.tsx`), `rel`/`num` (`views/format.ts`), `cx` (`@socdesk/shared/lib/cx`).
- Produces: `AsnLeaderboardPayload`/`AsnNetwork` types; `<AsnLeaderboardView payload={...} />`; `<AsnLeaderboardRoute />`; the `networks` tab in the desk. This is the JSX gate (`tsc` + Vite + ESLint) — the model is Python-tested, the view is presentational, so no runtime JS test is added (matching the desk's other views).

- [ ] **Step 1: Add the payload types**

Append to `web/src/components/views/types.ts` (every field optional-tolerant, per the rule at `types.ts:6-8`):

```typescript
/* ---------------- networks (ASN abuse leaderboard) ---------------- */

/** One network (ASN) row. Reported/blocklisted abuse volume hosted on the
 *  network — NOT a verdict on the operator. `report_count` (distinct
 *  report-bearing IPs) is always <= `ip_count`; `sources` distinguishes a
 *  community allegation from an abuse.ch published blocklist entry. */
export interface AsnNetwork {
  asn?: string
  isp?: string
  country?: string
  ip_count?: number
  report_count?: number
  categories?: string[]
  sources?: string[]
  examples?: string[]
}

export interface AsnLeaderboardPayload {
  generated_at?: string
  schema_version?: number
  attribution?: string
  count?: number
  total_abusive_ips?: number
  unattributed_ips?: number
  cap?: number
  truncated?: boolean
  networks: AsnNetwork[]
}
```

- [ ] **Step 2: Create the view (cloned from `SourcesView.tsx:29-111`)**

Create `web/src/components/views/AsnLeaderboardView.tsx`:

```tsx
import { cx } from '@socdesk/shared/lib/cx'
import type { AsnLeaderboardPayload, AsnNetwork } from './types'
import { num } from './format'
import { EmptyState } from './states'

/**
 * The abuse-by-network leaderboard — autonomous systems ranked by the volume of
 * abusive IPs reported to SOCDesk and published on the abuse.ch blocklists.
 * Reported/blocklisted volume hosted on a network, NOT a verdict on the
 * operator: the count is neutral ink, and `sources` keeps a community
 * allegation distinct from an abuse.ch published C2. Ranking is done in the
 * pipeline; this view does not re-sort.
 */

function Chip({ label, accent = false }: { label: string; accent?: boolean }) {
  return (
    <span
      className={cx(
        'inline-flex items-center rounded-sm border px-2 py-0.5 font-mono text-micro font-semibold uppercase tracking-label',
        accent
          ? 'border-[var(--edge-accent)] bg-[var(--tint-accent)] text-accent'
          : 'border-line bg-panel-soft text-muted',
      )}
    >
      {label}
    </span>
  )
}

const HEADERS = ['#', 'ASN', 'ISP', 'Country', 'Abusive IPs', 'Reported for', 'Source(s)', 'Examples'] as const

export function AsnLeaderboardView({ payload }: { payload: AsnLeaderboardPayload | null }) {
  const networks: AsnNetwork[] = payload?.networks ?? []

  if (!networks.length) {
    return (
      <EmptyState title="No networks to rank yet">
        The pipeline has not placed any reported IP on an ASN — an IPinfo token
        is needed to map IPs to networks, or there are no abusive IPs to rank.
        Everything else on this page still works.
      </EmptyState>
    )
  }

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap gap-x-6 gap-y-1 font-mono text-micro uppercase tracking-label text-faint">
        <span>
          <b className="text-accent">{num(payload?.total_abusive_ips)}</b> abusive IPs
        </span>
        <span>
          <b className="text-paper">{num(payload?.unattributed_ips)}</b> unattributed
        </span>
      </div>

      <div className="overflow-x-auto rounded-lg border border-line">
        <table className="w-full min-w-[860px] border-collapse text-left">
          <thead>
            <tr>
              {HEADERS.map((h, i) => (
                <th
                  key={h}
                  scope="col"
                  className={cx(
                    'border-b border-line bg-panel px-3 py-2.5 font-mono text-micro font-semibold uppercase tracking-label text-faint',
                    i === 4 && 'text-right',
                  )}
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {networks.map((n, i) => (
              <tr
                key={n.asn ?? i}
                className="border-b border-line align-top last:border-0 transition-colors duration-150 ease-brand hover:bg-panel-soft"
              >
                <td className="px-3 py-2.5 font-mono text-micro text-faint">{i + 1}</td>
                <td className="px-3 py-2.5 font-mono text-xs font-semibold text-paper">{n.asn ?? '—'}</td>
                <td className="px-3 py-2.5 text-xs text-paper">{n.isp ?? '—'}</td>
                <td className="px-3 py-2.5 font-mono text-micro text-muted">{n.country ?? '—'}</td>
                <td className="whitespace-nowrap px-3 py-2.5 text-right font-mono text-sm tabular-nums text-paper">
                  {num(n.ip_count)}
                  {n.report_count ? (
                    <span className="ml-1 text-micro text-faint">({num(n.report_count)} reported)</span>
                  ) : null}
                </td>
                <td className="px-3 py-2.5">
                  <div className="flex flex-wrap gap-1">
                    {(n.categories ?? []).length ? (
                      (n.categories ?? []).map((c) => <Chip key={c} label={c} />)
                    ) : (
                      <span className="font-mono text-micro text-faint">—</span>
                    )}
                  </div>
                </td>
                <td className="px-3 py-2.5">
                  <div className="flex flex-wrap gap-1">
                    {(n.sources ?? []).map((s) => (
                      <Chip key={s} label={s} accent={s === 'community'} />
                    ))}
                  </div>
                </td>
                <td className="px-3 py-2.5 font-mono text-micro text-muted">
                  {(n.examples ?? []).join(', ') || '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <p className="max-w-2xl text-micro text-faint">
        Reported/blocklisted abuse volume hosted on a network — not a verdict on
        the network or its operator. ASN/ISP mapping by IPinfo.
      </p>
    </div>
  )
}
```

- [ ] **Step 3: Create the route (cloned from `FeedRoute.tsx`/`SourcesRoute.tsx`)**

Create `web/src/routes/AsnLeaderboardRoute.tsx`:

```tsx
import { MicroLabel } from '../components/ui'
import { ViewHeader } from '../components/views/ViewFrame'
import { AsyncGate, SkeletonRows } from '../components/views/states'
import { AsnLeaderboardView } from '../components/views/AsnLeaderboardView'
import { useStateData } from '../components/views/useStateData'
import { rel } from '../components/views/format'
import { CountUp } from '../components/views/CountUp'
import type { AsnLeaderboardPayload } from '../components/views/types'

/**
 * /desk#networks — the abuse-by-network leaderboard. Reads the committed
 * asn_leaderboard.json snapshot (no D1, no API, no account) and hands it to
 * AsnLeaderboardView, gating on loading/error with an honest skeleton +
 * fallback.
 */
export function AsnLeaderboardRoute() {
  const { status, data, error } = useStateData<AsnLeaderboardPayload>('asn_leaderboard')
  const networks = data?.networks ?? []

  return (
    <div className="flex flex-col gap-6">
      <ViewHeader
        eyebrow="Abuse by network"
        title="Networks"
        intro="Autonomous systems ranked by the volume of abusive IPs reported to SOCDesk and published on the abuse.ch blocklists. Reported volume hosted on a network — not a verdict on the network or its operator."
        aside={
          status === 'ready' && data ? (
            <MicroLabel tone="faint">
              <CountUp value={networks.length} /> networks · updated {rel(data.generated_at)}
            </MicroLabel>
          ) : null
        }
      />
      <AsyncGate
        status={status}
        label="the leaderboard"
        detail={error}
        skeleton={<SkeletonRows rows={8} />}
      >
        <AsnLeaderboardView payload={data} />
      </AsyncGate>
    </div>
  )
}
```

- [ ] **Step 4: Wire the tab into the Data Desk**

In `web/src/routes/DataDeskRoute.tsx`:

Add the import (after the `SourcesRoute` import, line 8):

```tsx
import { SourcesRoute } from './SourcesRoute'
import { AsnLeaderboardRoute } from './AsnLeaderboardRoute'
import { ToolbeltRoute } from './ToolbeltRoute'
```

Add the tab to `TABS` (line 26-33), after `sources` and before `toolbelt`:

```tsx
  { key: 'sources', label: 'Sources' },
  { key: 'networks', label: 'Networks' },
  { key: 'toolbelt', label: 'Toolbelt' },
] as const
```

Mount it in the tab body (line 100-107), after the `sources` line:

```tsx
        {tab === 'sources' && <SourcesRoute />}
        {tab === 'networks' && <AsnLeaderboardRoute />}
        {tab === 'toolbelt' && <ToolbeltRoute />}
```

- [ ] **Step 5: Run the JSX gate**

Run: `npm --prefix web run build`
Expected: PASS — `tsc` type-checks the new types/view/route and Vite builds. (No new data file is needed to build; the view renders its honest empty/error state when the asset is absent in local dev.)

Run: `cd web && npx eslint .`
Expected: PASS — no lint errors (no `any`, no unused imports, no inline styles).

Run: `cd web && npx vitest run`
Expected: PASS — the existing JS suite stays green (regression check; no new JS test added).

- [ ] **Step 6: Commit**

```bash
git add web/src/components/views/types.ts web/src/components/views/AsnLeaderboardView.tsx web/src/routes/AsnLeaderboardRoute.tsx web/src/routes/DataDeskRoute.tsx
git commit -m "feat(asn): Networks tab in the Data Desk (read-only committed dataset)"
```

---

### Task 7: README note + full-suite verification

**Files:**
- Modify: `README.md:227`
- Verify: whole Python suite, web build, ESLint, Vitest

**Interfaces:**
- Consumes: everything from Tasks 1-6.
- Produces: the documentation line; the final green-gate evidence.

- [ ] **Step 1: Add the README note**

In `README.md`, immediately after the Phase-3 paragraph (which ends at line 227 with "…never reads D1 per lookup."), add a new paragraph:

```markdown
Phase-4 abuse-by-network leaderboard: `run_pipeline.py` aggregates the already-
published, PII-stripped `community_reports.json` and `threat_ips.json` by network
(ASN + ISP) into the committed `data/state/asn_leaderboard.json`, resolving each
distinct abusive IP via IPinfo's `org` field (cache-first, `data/state/asn_cache.json`).
It is rendered read-only in the Data Desk "Networks" tab (`/desk#networks`) as a
static-asset view — still no account, no per-lookup D1, and no change to the
enrich read path. Reported/blocklisted abuse volume hosted on a network, not a
verdict on the operator.
```

- [ ] **Step 2: Run the full verification gate**

Run each and confirm green:

```bash
./.venv/Scripts/python.exe -m pytest tests/ -q
npm --prefix web run build
cd web && npx eslint .
cd web && npx vitest run
```

Expected: all PASS. This is the acceptance evidence for §5 of the spec (except the manual preview-deploy acceptance, which the owner runs — see below).

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: register the Phase-4 abuse-by-network leaderboard"
```

- [ ] **Step 4: Owner manual acceptance (not automatable — hand off)**

On a preview deploy, the owner should: run `workflow_dispatch` → confirm `data/state/asn_leaderboard.json` populates (networks ranked, no PII, `unattributed_ips` sane) and `asn_cache.json` grows → open `/desk#networks` on the preview → the leaderboard renders, ordered, with the "not a verdict" framing → unset `IPINFO_TOKEN` locally → confirm the view degrades to the honest empty state (spec §4 manual acceptance).

---

## Self-Review

**1. Spec coverage** (each spec section → task):
- §0 files-owned (create/modify list) → Tasks 1-7 cover every named file. ✓
- §1.1 read model untouched → Constraint 3 + Task 6 uses only `useStateData`; no enrich/verdict/route-table edits. ✓
- §1.2 reported-volume-not-verdict copy → Task 6 view footnote + route intro + envelope `ATTRIBUTION` (Task 1). ✓
- §1.3 / §3.7 no-PII (both fences) → Task 4 schema (both-level `additionalProperties:false`) + no-PII/injected-field tests. ✓
- §1.4 free-tier `org`, cache-first → Tasks 2-3 (`resolve_asn`, cache-first, prune) + Task 5 (persist). ✓
- §1.5 honest degradation → Tasks 2-3 (None-not-fabricate, empty-but-valid, structural→None) + Task 5 (last-known-good). ✓
- §1.6 attributed provenance → Task 3 `sources[]` sorted union + `report_count`. ✓
- §3.1 sourcing mechanism (`parse_org`, `resolve_asn`) → Tasks 1-2. ✓
- §3.2 UNION scope + `SOURCES` switch → Task 1 constant + Task 3 scope-switch test. ✓
- §3.3 dataset + schema → Tasks 3-4. ✓
- §3.4 aggregation determinism → Task 3 (sort, tie-break, sorted examples/categories/sources, `report_count ≤ ip_count`). ✓
- §3.5 Networks desk tab → Task 6. ✓
- §3.6 freshness/degradation wiring → Task 5 (build after community+threat, before gate, `payloads.get() or state.get()`). ✓
- §4 testing (parity, aggregation, report_count honesty, cache-first, unattributed, no-PII, scope-switch, degradation, round-trip) → Tasks 1-4 tests. ✓
- §5 acceptance → Task 7 gate + owner manual step. ✓
- §6 anti-drift → encoded in Global Constraints + inline comments. ✓
- §7 owner decisions → resolved (UNION, Networks tab, CAP=200/EXAMPLE_CAP=3) in Global Constraints. ✓

**2. Placeholder scan:** No `TBD`/`TODO`/"add error handling"/"similar to Task N"/"write tests for the above". Every code and test step shows real, runnable content. The only forward-references are to symbols defined in an earlier task (declared in each task's Interfaces block). ✓

**3. Type consistency:** `build_asn_leaderboard(community, threat_ips, cache, fetch, now, token)` — identical signature in Task 3 (def), Task 5 (call + both monkeypatch stubs), Task 5 test. `resolve_asn(ip, cache, fetch, token)` consistent across Tasks 2-3. `parse_org(org) -> (asn, isp)|(None,None)` consistent Tasks 1-2. Envelope keys (`generated_at, schema_version, attribution, count, total_abusive_ips, unattributed_ips, cap, truncated, networks`) and row keys (`asn, isp, country?, ip_count, report_count, categories, sources, examples`) match across the builder (Task 3), schema (Task 4), seed (Task 4), TS types (Task 6), and view (Task 6). `SCHEMA_FOR["asn_leaderboard.json"]` string matches the created schema filename. `ASN_CACHE_NAME = "asn_cache.json"` matches the seed and the persist path. ✓

**Issues found & fixed inline:** two-level fence cited to `community_reports.schema.json` (not `threat_ips.schema.json`, which fences only the item level); token threaded via `run()`'s `env` (stated, with the geo-precedent alternative noted); JS parity resolved as Python-asserts-shared-fixture (no enrich.mjs edit); `iso` imported in `asn.py` at Task 1 so no later import churn.
