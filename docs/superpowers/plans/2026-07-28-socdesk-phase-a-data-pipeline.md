# SOCDESK Phase A — Data Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build SOCDESK's Tier 1 — Python collectors for 9 public CTI sources, normalized JSON with a schema gate, and a GitHub Actions pipeline that deploys data + a placeholder page to Cloudflare Pages on a 30-minute cron.

**Architecture:** Each collector is an isolated module with a common `collect(fetch, now)` interface and injected HTTP fetch (tests use fixture-backed fakes, no HTTP mocking library). A publish stage merges collector output with prior state under rolling windows, a jsonschema gate falls back to last-known-good per file, and the workflow commits state with `GITHUB_TOKEN` (which cannot recursively retrigger workflows) while the Framework's future `data/brief.json` pushes via deploy key *do* retrigger the deploy — that asymmetry is deliberate.

**Tech Stack:** Python 3.12, httpx, feedparser, jsonschema, pytest, GitHub Actions, wrangler (Cloudflare Pages direct upload).

**Scope:** Plan 1 of 3. Phase B (design phase + site) and Phase C (Framework brief loop) get their own plans at their phase boundaries. This plan ends with a live public URL serving real data.

---

## File structure

```
SOCDESK/
  .gitignore
  requirements.txt
  README.md                      # setup + secrets (T15)
  run_pipeline.py                # entrypoint (T13)
  collectors/
    __init__.py                  # COLLECTORS registry list
    base.py                      # CollectorResult, make_item, iso, run_all
    kev.py  nvd.py  threatfox.py  urlhaus.py  malwarebazaar.py
    ransomwarelive.py  rss.py  attack.py
  pipeline/
    __init__.py
    http.py                      # real fetch (httpx)
    entities.py                  # dictionary-based entity extraction
    cves.py                      # CVE join (NVD+KEV) + EPSS enrichment
    publish.py                   # rolling windows + site payload builder
    validate.py                  # jsonschema gate + last-known-good fallback
  schemas/
    feed.schema.json  iocs.schema.json  cves.schema.json
    health.schema.json  sources.schema.json  actors.schema.json
  data/
    sources.json                 # 24-source registry seed
    entities/actors.json  entities/malware.json  entities/vendors.json
    state/                       # last-known-good payloads (committed by CI)
  site/
    index.html                   # Phase A placeholder status page (replaced in Phase B)
    data/                        # build output (gitignored)
  tests/
    conftest.py                  # FIXED_NOW, fake_fetch factory
    fixtures/<source>/*.json
    test_validate.py test_base.py test_kev.py test_nvd.py test_cves.py
    test_threatfox.py test_abusech.py test_ransomwarelive.py
    test_rss.py test_attack.py test_publish.py test_pipeline.py
  .github/workflows/collect-and-deploy.yml
```

Interface contracts used throughout (defined in T3, repeated here for reference):

```python
@dataclass
class CollectorResult:
    source: str
    items: list = field(default_factory=list)   # feed items (spec §6)
    extra: dict = field(default_factory=dict)   # source-specific rows (kev/iocs/actors/...)
    ok: bool = True
    error: str = ""

def collect(fetch, now) -> CollectorResult     # every collector module; module also has SOURCE = "<slug>"
fetch(url, *, method="GET", json=None, headers=None, text=False)  # returns parsed JSON, or str if text=True
```

Category enum: `ransomware | vulnerability | malware | apt | campaign | report`.
Severity enum: `critical | high | medium | low | info`.
IOC type enum: `ipv4 | domain | url | md5 | sha256`.
Design refinement over spec §6 (analyst-reality call): ThreatFox / URLhaus / MalwareBazaar feed the IOC repository only (`extra["iocs"]`), not the scrolling feed — the feed stays human-readable (RSS, ransomware activity, new KEV entries).

---

### Task 1: Scaffolding

**Files:**
- Create: `.gitignore`, `requirements.txt`, `collectors/__init__.py`, `pipeline/__init__.py`, `tests/conftest.py`

- [ ] **Step 1: Write scaffolding files**

`.gitignore`:
```
__pycache__/
*.pyc
.venv/
site/data/
.pytest_cache/
```

`requirements.txt`:
```
httpx==0.27.*
feedparser==6.0.*
jsonschema==4.*
pytest==8.*
```

`collectors/__init__.py` and `pipeline/__init__.py`: empty for now.

`tests/conftest.py`:
```python
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
FIXED_NOW = datetime(2026, 7, 28, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def now():
    return FIXED_NOW


@pytest.fixture
def fake_fetch():
    """fake_fetch({"https://url": payload_or_fixture_relpath}) -> fetch callable."""
    def _make(mapping):
        def fetch(url, *, method="GET", json=None, headers=None, text=False):
            if url not in mapping:
                raise RuntimeError(f"unexpected URL in test: {url}")
            val = mapping[url]
            if isinstance(val, str) and val.endswith(".json"):
                raw = (FIXTURES / val).read_text(encoding="utf-8")
                return raw if text else __import__("json").loads(raw)
            if isinstance(val, str):
                return val  # raw text (RSS xml)
            return val
        return fetch
    return _make
```

- [ ] **Step 2: Set up venv and verify pytest runs**

Run: `python -m venv .venv; .venv\Scripts\pip install -r requirements.txt; .venv\Scripts\python -m pytest tests/ -v`
Expected: `no tests ran` (exit 5) — clean environment, no import errors.

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "chore: project scaffolding"
```

---

### Task 2: Schemas + validation gate

**Files:**
- Create: `schemas/feed.schema.json`, `schemas/iocs.schema.json`, `schemas/cves.schema.json`, `schemas/health.schema.json`, `schemas/sources.schema.json`, `schemas/actors.schema.json`, `pipeline/validate.py`
- Test: `tests/test_validate.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_validate.py
from pipeline.validate import validate_payload, gate

GOOD_FEED = {
    "generated_at": "2026-07-28T12:00:00Z", "schema_version": 1,
    "items": [{
        "id": "a" * 40, "source": "rss", "category": "report",
        "title": "t", "summary": "s", "url": "https://x.test/a",
        "severity": "info",
        "entities": {"actors": [], "malware": [], "vendors": [], "cves": []},
        "iocs": [], "published_at": "2026-07-28T10:00:00Z",
        "collected_at": "2026-07-28T12:00:00Z",
    }],
}
BAD_FEED = {"generated_at": "2026-07-28T12:00:00Z", "schema_version": 1,
            "items": [{"id": "x"}]}


def test_valid_payload_passes():
    assert validate_payload("feed.json", GOOD_FEED, "schemas") == []


def test_invalid_payload_reports_errors():
    assert validate_payload("feed.json", BAD_FEED, "schemas") != []


def test_gate_falls_back_to_prior_on_invalid():
    published, problems = gate(
        {"feed.json": BAD_FEED}, {"feed.json": GOOD_FEED}, "schemas")
    assert published["feed.json"] == GOOD_FEED
    assert problems and "feed.json" in problems[0]


def test_gate_skips_invalid_with_no_prior():
    published, problems = gate({"feed.json": BAD_FEED}, {}, "schemas")
    assert "feed.json" not in published
    assert problems
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv\Scripts\python -m pytest tests/test_validate.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'pipeline.validate'`

- [ ] **Step 3: Write schemas and validate.py**

`schemas/feed.schema.json`:
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["generated_at", "schema_version", "items"],
  "properties": {
    "generated_at": {"type": "string"},
    "schema_version": {"type": "integer"},
    "items": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["id", "source", "category", "title", "summary", "url",
                     "severity", "entities", "iocs", "published_at", "collected_at"],
        "properties": {
          "id": {"type": "string", "minLength": 40, "maxLength": 40},
          "source": {"type": "string"},
          "category": {"enum": ["ransomware", "vulnerability", "malware",
                                 "apt", "campaign", "report"]},
          "title": {"type": "string", "minLength": 1},
          "summary": {"type": "string"},
          "url": {"type": "string"},
          "severity": {"enum": ["critical", "high", "medium", "low", "info"]},
          "entities": {
            "type": "object",
            "required": ["actors", "malware", "vendors", "cves"],
            "properties": {
              "actors": {"type": "array", "items": {"type": "string"}},
              "malware": {"type": "array", "items": {"type": "string"}},
              "vendors": {"type": "array", "items": {"type": "string"}},
              "cves": {"type": "array", "items": {"type": "string"}}
            }
          },
          "iocs": {"type": "array", "items": {
            "type": "object",
            "required": ["type", "value"],
            "properties": {
              "type": {"enum": ["ipv4", "domain", "url", "md5", "sha256"]},
              "value": {"type": "string"}
            }
          }},
          "published_at": {"type": "string"},
          "collected_at": {"type": "string"}
        }
      }
    }
  }
}
```

`schemas/iocs.schema.json`:
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["generated_at", "schema_version", "iocs"],
  "properties": {
    "generated_at": {"type": "string"},
    "schema_version": {"type": "integer"},
    "iocs": {
      "type": "object",
      "properties": {
        "ipv4": {"$ref": "#/$defs/entries"}, "domain": {"$ref": "#/$defs/entries"},
        "url": {"$ref": "#/$defs/entries"}, "md5": {"$ref": "#/$defs/entries"},
        "sha256": {"$ref": "#/$defs/entries"}
      }
    }
  },
  "$defs": {
    "entries": {"type": "array", "items": {
      "type": "object",
      "required": ["value", "source", "first_seen", "last_seen"],
      "properties": {
        "value": {"type": "string"}, "source": {"type": "string"},
        "malware": {"type": "string"}, "confidence": {"type": "integer"},
        "first_seen": {"type": "string"}, "last_seen": {"type": "string"}
      }
    }}
  }
}
```

`schemas/cves.schema.json`:
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["generated_at", "schema_version", "cves"],
  "properties": {
    "generated_at": {"type": "string"},
    "schema_version": {"type": "integer"},
    "cves": {"type": "array", "items": {
      "type": "object",
      "required": ["cve", "kev", "last_modified"],
      "properties": {
        "cve": {"type": "string", "pattern": "^CVE-\\d{4}-\\d{4,7}$"},
        "title": {"type": "string"},
        "cvss": {"type": ["number", "null"]},
        "cvss_severity": {"type": ["string", "null"]},
        "epss": {"type": ["number", "null"]},
        "epss_percentile": {"type": ["number", "null"]},
        "kev": {"type": "boolean"},
        "kev_date_added": {"type": "string"},
        "kev_ransomware": {"type": "boolean"},
        "vendors": {"type": "array", "items": {"type": "string"}},
        "products": {"type": "array", "items": {"type": "string"}},
        "published_at": {"type": "string"},
        "last_modified": {"type": "string"}
      }
    }}
  }
}
```

`schemas/health.schema.json`:
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["generated_at", "schema_version", "sources"],
  "properties": {
    "generated_at": {"type": "string"},
    "schema_version": {"type": "integer"},
    "pipeline_warnings": {"type": "array", "items": {"type": "string"}},
    "sources": {"type": "array", "items": {
      "type": "object",
      "required": ["source", "ok", "items", "last_success_at"],
      "properties": {
        "source": {"type": "string"}, "ok": {"type": "boolean"},
        "error": {"type": "string"}, "items": {"type": "integer"},
        "last_success_at": {"type": "string"}
      }
    }}
  }
}
```

`schemas/sources.schema.json`:
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["generated_at", "schema_version", "sources"],
  "properties": {
    "generated_at": {"type": "string"},
    "schema_version": {"type": "integer"},
    "sources": {"type": "array", "items": {
      "type": "object",
      "required": ["name", "kind", "url", "coverage"],
      "properties": {
        "name": {"type": "string"},
        "kind": {"enum": ["collector", "reference"]},
        "slug": {"type": "string"},
        "url": {"type": "string"},
        "coverage": {"type": "string"},
        "enabled": {"type": "boolean"}
      }
    }}
  }
}
```

`schemas/actors.schema.json` (used for both `actors.json` and `malware.json`):
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["generated_at", "schema_version", "profiles"],
  "properties": {
    "generated_at": {"type": "string"},
    "schema_version": {"type": "integer"},
    "profiles": {"type": "array", "items": {
      "type": "object",
      "required": ["name", "attack_id"],
      "properties": {
        "name": {"type": "string"}, "attack_id": {"type": "string"},
        "aliases": {"type": "array", "items": {"type": "string"}},
        "description": {"type": "string"},
        "techniques": {"type": "array", "items": {"type": "string"}},
        "software": {"type": "array", "items": {"type": "string"}}
      }
    }}
  }
}
```

`pipeline/validate.py`:
```python
import json
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft202012Validator

# published filename -> schema filename
SCHEMA_FOR = {
    "feed.json": "feed.schema.json",
    "iocs.json": "iocs.schema.json",
    "cves.json": "cves.schema.json",
    "health.json": "health.schema.json",
    "sources.json": "sources.schema.json",
    "actors.json": "actors.schema.json",
    "malware.json": "actors.schema.json",
}


@lru_cache(maxsize=None)
def _validator(schemas_dir, schema_name):
    schema = json.loads((Path(schemas_dir) / schema_name).read_text(encoding="utf-8"))
    return Draft202012Validator(schema)


def validate_payload(filename, payload, schemas_dir):
    v = _validator(schemas_dir, SCHEMA_FOR[filename])
    return [f"{e.json_path}: {e.message}" for e in v.iter_errors(payload)][:20]


def gate(candidate, prior, schemas_dir):
    """Validate each candidate payload; fall back to prior snapshot on failure."""
    published, problems = {}, []
    for filename, payload in candidate.items():
        errors = validate_payload(filename, payload, schemas_dir)
        if not errors:
            published[filename] = payload
        elif filename in prior:
            published[filename] = prior[filename]
            problems.append(f"{filename}: invalid, kept last-known-good ({errors[0]})")
        else:
            problems.append(f"{filename}: invalid, no prior snapshot, skipped ({errors[0]})")
    return published, problems
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_validate.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add schemas pipeline/validate.py tests/test_validate.py
git commit -m "feat: published-payload schemas and validation gate with last-known-good fallback"
```

---

### Task 3: Collector base — result type, item builder, fault-isolated runner

**Files:**
- Create: `collectors/base.py`
- Test: `tests/test_base.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_base.py
from collectors.base import CollectorResult, iso, make_item, run_all
from tests.conftest import FIXED_NOW


def test_make_item_shape():
    item = make_item("rss", "native-1", "report", "Title", "Summary",
                     "https://x.test/a", "info", "2026-07-28T10:00:00Z", FIXED_NOW)
    assert len(item["id"]) == 40
    assert item["collected_at"] == "2026-07-28T12:00:00Z"
    assert item["entities"] == {"actors": [], "malware": [], "vendors": [], "cves": []}
    assert item["iocs"] == []


def test_make_item_id_is_stable():
    a = make_item("rss", "native-1", "report", "T", "S", "u", "info", "p", FIXED_NOW)
    b = make_item("rss", "native-1", "report", "T2", "S2", "u2", "low", "p2", FIXED_NOW)
    assert a["id"] == b["id"]


class _Good:
    SOURCE = "good"
    @staticmethod
    def collect(fetch, now):
        return CollectorResult(source="good", items=[{"x": 1}], extra={"iocs": [1, 2]})


class _Boom:
    SOURCE = "boom"
    @staticmethod
    def collect(fetch, now):
        raise RuntimeError("upstream 500")


def test_run_all_isolates_failures():
    results, health = run_all([_Good, _Boom], fetch=None, now=FIXED_NOW)
    by_source = {r.source: r for r in results}
    assert by_source["good"].ok and not by_source["boom"].ok
    assert "upstream 500" in by_source["boom"].error
    h = {e["source"]: e for e in health}
    assert h["good"]["items"] == 3          # 1 item + 2 extra rows
    assert h["good"]["last_success_at"] == iso(FIXED_NOW)
    assert h["boom"]["ok"] is False and h["boom"]["last_success_at"] == ""
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv\Scripts\python -m pytest tests/test_base.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'collectors.base'`

- [ ] **Step 3: Write collectors/base.py**

```python
import hashlib
from dataclasses import dataclass, field


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class CollectorResult:
    source: str
    items: list = field(default_factory=list)
    extra: dict = field(default_factory=dict)
    ok: bool = True
    error: str = ""


def make_item(source, native_id, category, title, summary, url, severity,
              published_at, now, entities=None, iocs=None):
    return {
        "id": hashlib.sha1(f"{source}:{native_id}".encode("utf-8")).hexdigest(),
        "source": source,
        "category": category,
        "title": title.strip()[:300],
        "summary": (summary or "").strip()[:500],
        "url": url,
        "severity": severity,
        "entities": entities or {"actors": [], "malware": [], "vendors": [], "cves": []},
        "iocs": iocs or [],
        "published_at": published_at,
        "collected_at": iso(now),
    }


def run_all(collector_modules, fetch, now):
    """Run every collector; one raising never affects the others."""
    results, health = [], []
    for mod in collector_modules:
        try:
            r = mod.collect(fetch, now)
        except Exception as e:  # noqa: BLE001 — fault isolation is the point
            r = CollectorResult(source=mod.SOURCE, ok=False, error=str(e)[:300])
        results.append(r)
        count = len(r.items) + sum(
            len(v) for v in r.extra.values() if isinstance(v, list))
        health.append({
            "source": r.source,
            "ok": r.ok,
            "error": r.error,
            "items": count,
            "last_success_at": iso(now) if r.ok else "",
        })
    return results, health
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_base.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add collectors/base.py tests/test_base.py
git commit -m "feat: collector base with fault-isolated runner and normalized item builder"
```

---

### Task 4: CISA KEV collector

**Files:**
- Create: `collectors/kev.py`, `tests/fixtures/kev/feed.json`
- Test: `tests/test_kev.py`

- [ ] **Step 1: Write fixture and failing test**

`tests/fixtures/kev/feed.json`:
```json
{
  "vulnerabilities": [
    {"cveID": "CVE-2026-1111", "vendorProject": "Fortinet", "product": "FortiOS",
     "vulnerabilityName": "FortiOS Auth Bypass", "dateAdded": "2026-07-25",
     "shortDescription": "Auth bypass in FortiOS.",
     "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2020-9999", "vendorProject": "OldCo", "product": "Legacy",
     "vulnerabilityName": "Old Bug", "dateAdded": "2020-01-01",
     "shortDescription": "Ancient.", "knownRansomwareCampaignUse": "Unknown"}
  ]
}
```

```python
# tests/test_kev.py
from collectors import kev
from tests.conftest import FIXED_NOW


def _result(fake_fetch):
    fetch = fake_fetch({kev.URL: "kev/feed.json"})
    return kev.collect(fetch, FIXED_NOW)


def test_kev_rows(fake_fetch):
    r = _result(fake_fetch)
    assert r.ok
    rows = {row["cve"]: row for row in r.extra["kev"]}
    assert rows["CVE-2026-1111"]["kev_ransomware"] is True
    assert rows["CVE-2026-1111"]["vendor"] == "Fortinet"
    assert len(rows) == 2


def test_recent_kev_additions_become_feed_items(fake_fetch):
    r = _result(fake_fetch)
    assert len(r.items) == 1                      # only the 2026 addition
    item = r.items[0]
    assert item["category"] == "vulnerability"
    assert item["severity"] == "critical"         # ransomware-linked KEV
    assert "CVE-2026-1111" in item["entities"]["cves"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python -m pytest tests/test_kev.py -v`
Expected: FAIL — no module `collectors.kev`

- [ ] **Step 3: Write collectors/kev.py**

```python
from datetime import timedelta

from collectors.base import CollectorResult, make_item

SOURCE = "kev"
URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
ITEM_WINDOW_DAYS = 30


def collect(fetch, now):
    data = fetch(URL)
    rows, items = [], []
    cutoff = (now - timedelta(days=ITEM_WINDOW_DAYS)).strftime("%Y-%m-%d")
    for v in data.get("vulnerabilities", []):
        ransomware = v.get("knownRansomwareCampaignUse", "").lower() == "known"
        rows.append({
            "cve": v["cveID"],
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "name": v.get("vulnerabilityName", ""),
            "kev_date_added": v.get("dateAdded", ""),
            "kev_ransomware": ransomware,
        })
        if v.get("dateAdded", "") >= cutoff:
            items.append(make_item(
                SOURCE, v["cveID"], "vulnerability",
                f"KEV: {v['cveID']} — {v.get('vulnerabilityName', '')}",
                v.get("shortDescription", ""),
                "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "critical" if ransomware else "high",
                v.get("dateAdded", "") + "T00:00:00Z", now,
                entities={"actors": [], "malware": [],
                          "vendors": [v.get("vendorProject", "")],
                          "cves": [v["cveID"]]},
            ))
    return CollectorResult(source=SOURCE, items=items, extra={"kev": rows})
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_kev.py -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add collectors/kev.py tests/fixtures/kev tests/test_kev.py
git commit -m "feat: CISA KEV collector"
```

---

### Task 5: NVD collector

**Files:**
- Create: `collectors/nvd.py`, `tests/fixtures/nvd/recent.json`
- Test: `tests/test_nvd.py`

- [ ] **Step 1: Write fixture and failing test**

`tests/fixtures/nvd/recent.json` (NVD API 2.0 shape, trimmed):
```json
{
  "totalResults": 1,
  "vulnerabilities": [
    {"cve": {
      "id": "CVE-2026-2222",
      "published": "2026-07-27T09:00:00.000",
      "lastModified": "2026-07-27T10:00:00.000",
      "descriptions": [{"lang": "en", "value": "RCE in ExampleServer."}],
      "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
      "configurations": [{"nodes": [{"cpeMatch": [
        {"criteria": "cpe:2.3:a:examplecorp:exampleserver:1.0:*:*:*:*:*:*:*"}
      ]}]}]
    }}
  ]
}
```

```python
# tests/test_nvd.py
from collectors import nvd
from tests.conftest import FIXED_NOW


def test_nvd_rows(fake_fetch):
    url = nvd.build_url(FIXED_NOW)
    fetch = fake_fetch({url: "nvd/recent.json"})
    r = nvd.collect(fetch, FIXED_NOW)
    assert r.ok
    row = r.extra["nvd"][0]
    assert row["cve"] == "CVE-2026-2222"
    assert row["cvss"] == 9.8
    assert row["cvss_severity"] == "CRITICAL"
    assert row["vendors"] == ["examplecorp"]
    assert row["products"] == ["exampleserver"]
    assert row["last_modified"] == "2026-07-27T10:00:00.000"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python -m pytest tests/test_nvd.py -v`
Expected: FAIL — no module `collectors.nvd`

- [ ] **Step 3: Write collectors/nvd.py**

```python
from datetime import timedelta

from collectors.base import CollectorResult

SOURCE = "nvd"
BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
LOOKBACK_DAYS = 2


def build_url(now):
    start = (now - timedelta(days=LOOKBACK_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.000")
    end = now.strftime("%Y-%m-%dT%H:%M:%S.000")
    return (f"{BASE}?lastModStartDate={start}&lastModEndDate={end}"
            f"&resultsPerPage=2000")


def _cpe_vendors_products(cve):
    vendors, products = [], []
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parts = m.get("criteria", "").split(":")
                if len(parts) > 4:
                    if parts[3] not in vendors:
                        vendors.append(parts[3])
                    if parts[4] not in products:
                        products.append(parts[4])
    return vendors[:5], products[:5]


def _cvss(cve):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = cve.get("metrics", {}).get(key)
        if metrics:
            d = metrics[0]["cvssData"]
            return d.get("baseScore"), d.get("baseSeverity", "")
    return None, None


def collect(fetch, now):
    data = fetch(build_url(now))
    rows = []
    for entry in data.get("vulnerabilities", []):
        cve = entry["cve"]
        score, sev = _cvss(cve)
        vendors, products = _cpe_vendors_products(cve)
        desc = next((d["value"] for d in cve.get("descriptions", [])
                     if d.get("lang") == "en"), "")
        rows.append({
            "cve": cve["id"],
            "title": desc[:200],
            "cvss": score,
            "cvss_severity": sev,
            "vendors": vendors,
            "products": products,
            "published_at": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
        })
    return CollectorResult(source=SOURCE, extra={"nvd": rows})
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_nvd.py -v`
Expected: 1 passed

- [ ] **Step 5: Commit**

```bash
git add collectors/nvd.py tests/fixtures/nvd tests/test_nvd.py
git commit -m "feat: NVD recent-CVE collector"
```

---

### Task 6: CVE join + EPSS enrichment

**Files:**
- Create: `pipeline/cves.py`, `tests/fixtures/epss/scores.json`
- Test: `tests/test_cves.py`

- [ ] **Step 1: Write fixture and failing tests**

`tests/fixtures/epss/scores.json`:
```json
{"data": [
  {"cve": "CVE-2026-1111", "epss": "0.92311", "percentile": "0.99871"},
  {"cve": "CVE-2026-2222", "epss": "0.00421", "percentile": "0.61022"}
]}
```

```python
# tests/test_cves.py
from collectors.base import CollectorResult
from pipeline import cves
from tests.conftest import FIXED_NOW

KEV_RESULT = CollectorResult(source="kev", extra={"kev": [
    {"cve": "CVE-2026-1111", "vendor": "Fortinet", "product": "FortiOS",
     "name": "FortiOS Auth Bypass", "kev_date_added": "2026-07-25",
     "kev_ransomware": True}]})
NVD_RESULT = CollectorResult(source="nvd", extra={"nvd": [
    {"cve": "CVE-2026-2222", "title": "RCE in ExampleServer.", "cvss": 9.8,
     "cvss_severity": "CRITICAL", "vendors": ["examplecorp"],
     "products": ["exampleserver"], "published_at": "2026-07-27T09:00:00.000",
     "last_modified": "2026-07-27T10:00:00.000"}]})


def test_join_merges_kev_and_nvd():
    rows = cves.build_cve_rows([KEV_RESULT, NVD_RESULT], prior_rows=[], now=FIXED_NOW)
    by_cve = {r["cve"]: r for r in rows}
    assert by_cve["CVE-2026-1111"]["kev"] is True
    assert by_cve["CVE-2026-1111"]["kev_ransomware"] is True
    assert by_cve["CVE-2026-2222"]["kev"] is False
    assert by_cve["CVE-2026-2222"]["cvss"] == 9.8


def test_join_keeps_prior_rows_within_window():
    prior = [{"cve": "CVE-2026-0001", "kev": False, "kev_date_added": "",
              "kev_ransomware": False, "cvss": 5.0, "cvss_severity": "MEDIUM",
              "title": "old", "vendors": [], "products": [], "epss": None,
              "epss_percentile": None, "published_at": "2026-06-01T00:00:00.000",
              "last_modified": "2026-06-01T00:00:00.000"}]
    rows = cves.build_cve_rows([KEV_RESULT], prior_rows=prior, now=FIXED_NOW)
    assert any(r["cve"] == "CVE-2026-0001" for r in rows)


def test_epss_enrichment(fake_fetch):
    rows = cves.build_cve_rows([KEV_RESULT, NVD_RESULT], prior_rows=[], now=FIXED_NOW)
    url = cves.epss_url(["CVE-2026-1111", "CVE-2026-2222"])
    health = cves.enrich_epss(fake_fetch({url: "epss/scores.json"}), rows, FIXED_NOW)
    by_cve = {r["cve"]: r for r in rows}
    assert by_cve["CVE-2026-1111"]["epss"] == 0.92311
    assert health["ok"] is True and health["source"] == "epss"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv\Scripts\python -m pytest tests/test_cves.py -v`
Expected: FAIL — no module `pipeline.cves`

- [ ] **Step 3: Write pipeline/cves.py**

```python
from datetime import timedelta

from collectors.base import iso

WINDOW_DAYS = 180
EPSS_BASE = "https://api.first.org/data/v1/epss"
BATCH = 100

_EMPTY = {"cve": "", "title": "", "cvss": None, "cvss_severity": None,
          "epss": None, "epss_percentile": None, "kev": False,
          "kev_date_added": "", "kev_ransomware": False, "vendors": [],
          "products": [], "published_at": "", "last_modified": ""}


def _get_results(results, source, key):
    for r in results:
        if r.source == source and r.ok:
            return r.extra.get(key, [])
    return []


def build_cve_rows(results, prior_rows, now):
    cutoff = iso(now - timedelta(days=WINDOW_DAYS))
    merged = {}
    for row in prior_rows:
        if row.get("last_modified", "") >= cutoff or row.get("kev"):
            merged[row["cve"]] = dict(row)

    for n in _get_results(results, "nvd", "nvd"):
        row = merged.setdefault(n["cve"], dict(_EMPTY, cve=n["cve"]))
        row.update({k: n[k] for k in ("title", "cvss", "cvss_severity",
                                      "vendors", "products", "published_at",
                                      "last_modified")})

    for k in _get_results(results, "kev", "kev"):
        row = merged.setdefault(k["cve"], dict(_EMPTY, cve=k["cve"]))
        row["kev"] = True
        row["kev_date_added"] = k["kev_date_added"]
        row["kev_ransomware"] = k["kev_ransomware"]
        if not row["title"]:
            row["title"] = k["name"]
        if k["vendor"] and k["vendor"] not in row["vendors"]:
            row["vendors"] = row["vendors"] + [k["vendor"]]
        if not row["last_modified"]:
            row["last_modified"] = k["kev_date_added"] + "T00:00:00.000"
    return sorted(merged.values(), key=lambda r: r["cve"], reverse=True)


def epss_url(cve_ids):
    return f"{EPSS_BASE}?cve={','.join(cve_ids)}"


def enrich_epss(fetch, rows, now):
    """Mutates rows in place; returns a health entry for the epss enrichment."""
    try:
        scores = {}
        ids = [r["cve"] for r in rows]
        for i in range(0, len(ids), BATCH):
            data = fetch(epss_url(ids[i:i + BATCH]))
            for d in data.get("data", []):
                scores[d["cve"]] = (float(d["epss"]), float(d["percentile"]))
        for r in rows:
            if r["cve"] in scores:
                r["epss"], r["epss_percentile"] = scores[r["cve"]]
        return {"source": "epss", "ok": True, "error": "",
                "items": len(scores), "last_success_at": iso(now)}
    except Exception as e:  # noqa: BLE001
        return {"source": "epss", "ok": False, "error": str(e)[:300],
                "items": 0, "last_success_at": ""}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_cves.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add pipeline/cves.py tests/fixtures/epss tests/test_cves.py
git commit -m "feat: KEV+NVD CVE join with EPSS enrichment"
```

---

### Task 7: ThreatFox collector

**Files:**
- Create: `collectors/threatfox.py`, `tests/fixtures/threatfox/recent.json`
- Test: `tests/test_threatfox.py`

- [ ] **Step 1: Write fixture and failing test**

`tests/fixtures/threatfox/recent.json`:
```json
{"query_status": "ok", "data": [
  {"ioc": "45.61.136.9:443", "ioc_type": "ip:port", "threat_type": "botnet_cc",
   "malware_printable": "Cobalt Strike", "confidence_level": 90,
   "first_seen": "2026-07-27 14:00:00 UTC", "last_seen": null},
  {"ioc": "evil-updates.example", "ioc_type": "domain", "threat_type": "payload_delivery",
   "malware_printable": "Lumma Stealer", "confidence_level": 75,
   "first_seen": "2026-07-28 01:00:00 UTC", "last_seen": "2026-07-28 03:00:00 UTC"},
  {"ioc": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
   "ioc_type": "sha256_hash", "threat_type": "payload",
   "malware_printable": "AgentTesla", "confidence_level": 100,
   "first_seen": "2026-07-28 02:00:00 UTC", "last_seen": null}
]}
```

```python
# tests/test_threatfox.py
from collectors import threatfox
from tests.conftest import FIXED_NOW


def test_threatfox_ioc_normalization(fake_fetch, monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "test-key")
    fetch = fake_fetch({threatfox.URL: "threatfox/recent.json"})
    r = threatfox.collect(fetch, FIXED_NOW)
    assert r.ok and r.items == []            # IOC-repository source: no feed items
    iocs = r.extra["iocs"]
    by_value = {i["value"]: i for i in iocs}
    assert by_value["45.61.136.9"]["type"] == "ipv4"       # port stripped
    assert by_value["evil-updates.example"]["type"] == "domain"
    assert by_value["evil-updates.example"]["malware"] == "Lumma Stealer"
    assert by_value["evil-updates.example"]["last_seen"] == "2026-07-28T03:00:00Z"
    sha = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
    assert by_value[sha]["type"] == "sha256"
    assert all(i["source"] == "threatfox" for i in iocs)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python -m pytest tests/test_threatfox.py -v`
Expected: FAIL — no module `collectors.threatfox`

- [ ] **Step 3: Write collectors/threatfox.py**

```python
import os

from collectors.base import CollectorResult, iso

SOURCE = "threatfox"
URL = "https://threatfox-api.abuse.ch/api/v1/"

TYPE_MAP = {"ip:port": "ipv4", "domain": "domain", "url": "url",
            "md5_hash": "md5", "sha256_hash": "sha256"}


def _ts(value, fallback):
    # "2026-07-27 14:00:00 UTC" -> "2026-07-27T14:00:00Z"
    if not value:
        return fallback
    return value.replace(" UTC", "").replace(" ", "T") + "Z"


def collect(fetch, now):
    data = fetch(URL, method="POST", json={"query": "get_iocs", "days": 1},
                 headers={"Auth-Key": os.environ.get("ABUSECH_AUTH_KEY", "")})
    if data.get("query_status") != "ok":
        raise RuntimeError(f"threatfox query_status={data.get('query_status')}")
    iocs = []
    for d in data.get("data", []):
        ioc_type = TYPE_MAP.get(d.get("ioc_type", ""))
        if not ioc_type:
            continue
        value = d["ioc"].split(":")[0] if d["ioc_type"] == "ip:port" else d["ioc"]
        first = _ts(d.get("first_seen"), iso(now))
        iocs.append({
            "type": ioc_type, "value": value, "source": SOURCE,
            "malware": d.get("malware_printable") or "",
            "confidence": int(d.get("confidence_level") or 0),
            "first_seen": first,
            "last_seen": _ts(d.get("last_seen"), first),
        })
    return CollectorResult(source=SOURCE, extra={"iocs": iocs})
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_threatfox.py -v`
Expected: 1 passed

- [ ] **Step 5: Commit**

```bash
git add collectors/threatfox.py tests/fixtures/threatfox tests/test_threatfox.py
git commit -m "feat: ThreatFox IOC collector"
```

---

### Task 8: URLhaus + MalwareBazaar collectors

**Files:**
- Create: `collectors/urlhaus.py`, `collectors/malwarebazaar.py`, `tests/fixtures/urlhaus/recent.json`, `tests/fixtures/malwarebazaar/recent.json`
- Test: `tests/test_abusech.py`

- [ ] **Step 1: Write fixtures and failing tests**

`tests/fixtures/urlhaus/recent.json`:
```json
{"query_status": "ok", "urls": [
  {"url": "http://bad.example/payload.exe", "url_status": "online",
   "threat": "malware_download", "tags": ["exe", "Amadey"],
   "date_added": "2026-07-28 04:00:00 UTC"}
]}
```

`tests/fixtures/malwarebazaar/recent.json`:
```json
{"query_status": "ok", "data": [
  {"sha256_hash": "ffe2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8fff",
   "signature": "RedLineStealer", "first_seen": "2026-07-28 05:00:00 UTC"}
]}
```

```python
# tests/test_abusech.py
from collectors import malwarebazaar, urlhaus
from tests.conftest import FIXED_NOW


def test_urlhaus(fake_fetch, monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "test-key")
    r = urlhaus.collect(fake_fetch({urlhaus.URL: "urlhaus/recent.json"}), FIXED_NOW)
    assert r.ok and r.items == []
    ioc = r.extra["iocs"][0]
    assert ioc == {"type": "url", "value": "http://bad.example/payload.exe",
                   "source": "urlhaus", "malware": "Amadey", "confidence": 50,
                   "first_seen": "2026-07-28T04:00:00Z",
                   "last_seen": "2026-07-28T04:00:00Z"}


def test_malwarebazaar(fake_fetch, monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "test-key")
    r = malwarebazaar.collect(
        fake_fetch({malwarebazaar.URL: "malwarebazaar/recent.json"}), FIXED_NOW)
    assert r.ok and r.items == []
    ioc = r.extra["iocs"][0]
    assert ioc["type"] == "sha256" and ioc["malware"] == "RedLineStealer"
    assert ioc["source"] == "malwarebazaar"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv\Scripts\python -m pytest tests/test_abusech.py -v`
Expected: FAIL — missing modules

- [ ] **Step 3: Write both collectors**

`collectors/urlhaus.py`:
```python
import os

from collectors.base import CollectorResult, iso

SOURCE = "urlhaus"
URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

_MALWARE_TAG_SKIP = {"exe", "dll", "zip", "elf", "apk", "js", "vbs", "doc", "xll"}


def _ts(value, now):
    if not value:
        return iso(now)
    return value.replace(" UTC", "").replace(" ", "T") + "Z"


def collect(fetch, now):
    data = fetch(URL, method="POST", json={"limit": 1000},
                 headers={"Auth-Key": os.environ.get("ABUSECH_AUTH_KEY", "")})
    if data.get("query_status") != "ok":
        raise RuntimeError(f"urlhaus query_status={data.get('query_status')}")
    iocs = []
    for u in data.get("urls", []):
        tags = u.get("tags") or []
        malware = next((t for t in tags if t.lower() not in _MALWARE_TAG_SKIP), "")
        added = _ts(u.get("date_added"), now)
        iocs.append({
            "type": "url", "value": u["url"], "source": SOURCE,
            "malware": malware, "confidence": 50,
            "first_seen": added, "last_seen": added,
        })
    return CollectorResult(source=SOURCE, extra={"iocs": iocs})
```

`collectors/malwarebazaar.py`:
```python
import os

from collectors.base import CollectorResult, iso

SOURCE = "malwarebazaar"
URL = "https://mb-api.abuse.ch/api/v1/"


def _ts(value, now):
    if not value:
        return iso(now)
    return value.replace(" UTC", "").replace(" ", "T") + "Z"


def collect(fetch, now):
    data = fetch(URL, method="POST", json={"query": "get_recent", "selector": "time"},
                 headers={"Auth-Key": os.environ.get("ABUSECH_AUTH_KEY", "")})
    if data.get("query_status") != "ok":
        raise RuntimeError(f"malwarebazaar query_status={data.get('query_status')}")
    iocs = []
    for d in data.get("data", []):
        seen = _ts(d.get("first_seen"), now)
        iocs.append({
            "type": "sha256", "value": d["sha256_hash"], "source": SOURCE,
            "malware": d.get("signature") or "", "confidence": 80,
            "first_seen": seen, "last_seen": seen,
        })
    return CollectorResult(source=SOURCE, extra={"iocs": iocs})
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_abusech.py -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add collectors/urlhaus.py collectors/malwarebazaar.py tests/fixtures/urlhaus tests/fixtures/malwarebazaar tests/test_abusech.py
git commit -m "feat: URLhaus and MalwareBazaar IOC collectors"
```

---

### Task 9: Ransomware.live collector

**Files:**
- Create: `collectors/ransomwarelive.py`, `tests/fixtures/ransomwarelive/recent.json`
- Test: `tests/test_ransomwarelive.py`

- [ ] **Step 1: Write fixture and failing test**

`tests/fixtures/ransomwarelive/recent.json`:
```json
[
  {"victim": "Example Manufacturing", "group": "akira",
   "discovered": "2026-07-28 02:15:00", "country": "US",
   "activity": "Manufacturing", "claim_url": "https://ransomware.live/id/x1"},
  {"victim": "Beispiel GmbH", "group": "play",
   "discovered": "2026-07-27 22:00:00", "country": "DE",
   "activity": "Logistics", "claim_url": "https://ransomware.live/id/x2"}
]
```

```python
# tests/test_ransomwarelive.py
from collectors import ransomwarelive
from tests.conftest import FIXED_NOW


def test_victims_become_feed_items(fake_fetch):
    fetch = fake_fetch({ransomwarelive.URL: "ransomwarelive/recent.json"})
    r = ransomwarelive.collect(fetch, FIXED_NOW)
    assert r.ok and len(r.items) == 2
    item = r.items[0]
    assert item["category"] == "ransomware"
    assert item["severity"] == "high"
    assert item["entities"]["actors"] == ["akira"]
    assert "Example Manufacturing" in item["title"]
    assert item["published_at"] == "2026-07-28T02:15:00Z"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python -m pytest tests/test_ransomwarelive.py -v`
Expected: FAIL — no module

- [ ] **Step 3: Write collectors/ransomwarelive.py**

```python
from collectors.base import CollectorResult, iso, make_item

SOURCE = "ransomwarelive"
URL = "https://api.ransomware.live/v2/recentvictims"


def collect(fetch, now):
    data = fetch(URL)
    items = []
    for v in data:
        group = (v.get("group") or "unknown").strip()
        victim = (v.get("victim") or "unnamed victim").strip()
        published = (v.get("discovered") or "").replace(" ", "T")
        items.append(make_item(
            SOURCE, f"{group}:{victim}:{v.get('discovered', '')}", "ransomware",
            f"{group} claims {victim}",
            f"Sector: {v.get('activity', 'unknown')} — Country: {v.get('country', '?')}",
            v.get("claim_url") or "https://ransomware.live",
            "high",
            published + "Z" if published else iso(now), now,
            entities={"actors": [group], "malware": [], "vendors": [], "cves": []},
        ))
    return CollectorResult(source=SOURCE, items=items)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_ransomwarelive.py -v`
Expected: 1 passed

- [ ] **Step 5: Commit**

```bash
git add collectors/ransomwarelive.py tests/fixtures/ransomwarelive tests/test_ransomwarelive.py
git commit -m "feat: Ransomware.live activity collector"
```

---

### Task 10: Entity extraction + RSS pool collector

**Files:**
- Create: `pipeline/entities.py`, `data/entities/actors.json`, `data/entities/malware.json`, `data/entities/vendors.json`, `collectors/rss.py`, `tests/fixtures/rss/talos.xml`
- Test: `tests/test_rss.py`

- [ ] **Step 1: Write entity dictionaries**

`data/entities/actors.json` (seed list — grow over time):
```json
["Scattered Spider", "ALPHV", "BlackCat", "LockBit", "Akira", "Play", "Cl0p",
 "Lazarus", "APT28", "APT29", "Midnight Blizzard", "Volt Typhoon",
 "Salt Typhoon", "FIN7", "Sandworm", "Kimsuky", "MuddyWater", "Turla",
 "Black Basta", "RansomHub", "Medusa", "Rhysida", "Qilin", "8Base",
 "Storm-0558", "TA505", "Wizard Spider", "Evil Corp", "Conti", "Royal"]
```

`data/entities/malware.json`:
```json
["Cobalt Strike", "Lumma Stealer", "AgentTesla", "RedLine", "Amadey",
 "QakBot", "IcedID", "Emotet", "TrickBot", "AsyncRAT", "NanoCore", "Remcos",
 "Raspberry Robin", "SocGholish", "Gootloader", "BumbleBee", "Sliver",
 "Brute Ratel", "Mimikatz", "PlugX", "ShadowPad", "XWorm", "DarkGate",
 "Vidar", "StealC", "Rhadamanthys", "SystemBC", "Pikabot", "Latrodectus",
 "Bashlite", "Mirai", "njRAT", "FormBook", "Snake Keylogger", "WarmCookie"]
```

`data/entities/vendors.json`:
```json
["Microsoft", "Cisco", "Fortinet", "Palo Alto", "Ivanti", "Citrix", "VMware",
 "SonicWall", "SAP", "Oracle", "Adobe", "Apple", "Google", "Atlassian",
 "GitLab", "Jenkins", "MOVEit", "ConnectWise", "ScreenConnect", "Veeam",
 "Zimbra", "Exchange", "SharePoint", "Chrome", "Firefox", "Windows", "Linux",
 "Android", "iOS", "Juniper", "F5", "Check Point", "Sophos", "Trend Micro",
 "CrowdStrike", "Okta", "Cloudflare", "AWS", "Azure", "Kubernetes", "Docker",
 "OpenSSH", "OpenSSL", "WordPress", "Zoom", "Slack", "Salesforce", "Zyxel",
 "QNAP", "Synology"]
```

- [ ] **Step 2: Write failing tests for extraction and RSS**

`tests/fixtures/rss/talos.xml`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
  <title>Example Vendor Blog</title>
  <item>
    <title>Akira ransomware exploiting CVE-2026-1111 in Fortinet devices</title>
    <link>https://blog.example/akira-fortinet</link>
    <description>Akira affiliates deploy Cobalt Strike after exploiting FortiOS.</description>
    <pubDate>Mon, 27 Jul 2026 15:00:00 GMT</pubDate>
  </item>
  <item>
    <title>Quarterly trends report</title>
    <link>https://blog.example/trends</link>
    <description>General overview of the quarter.</description>
    <pubDate>Mon, 20 Jul 2026 09:00:00 GMT</pubDate>
  </item>
</channel></rss>
```

```python
# tests/test_rss.py
from collectors import rss
from pipeline.entities import classify_category, extract_entities
from tests.conftest import FIXED_NOW


def test_extract_entities():
    e = extract_entities(
        "Akira ransomware exploiting CVE-2026-1111 in Fortinet devices "
        "with Cobalt Strike", "data/entities")
    assert "Akira" in e["actors"]
    assert "Cobalt Strike" in e["malware"]
    assert "Fortinet" in e["vendors"]
    assert e["cves"] == ["CVE-2026-1111"]


def test_classify_category():
    assert classify_category("Akira ransomware hits org", {"actors": ["Akira"], "malware": [], "vendors": [], "cves": []}) == "ransomware"
    assert classify_category("Patch now", {"actors": [], "malware": [], "vendors": [], "cves": ["CVE-2026-1"]}) == "vulnerability"
    assert classify_category("New infostealer wave observed", {"actors": [], "malware": ["Vidar"], "vendors": [], "cves": []}) == "malware"
    assert classify_category("Capture the flag recap", {"actors": [], "malware": [], "vendors": [], "cves": []}) == "report"  # 'apt' must not substring-match
    assert classify_category("Quarterly trends", {"actors": [], "malware": [], "vendors": [], "cves": []}) == "report"


def test_rss_collector(fake_fetch):
    from tests.conftest import FIXTURES
    mapping = {f["url"]: "" for f in rss.FEEDS}          # unmapped feeds: empty
    mapping[rss.FEEDS[0]["url"]] = (FIXTURES / "rss/talos.xml").read_text(encoding="utf-8")
    r = rss.collect(fake_fetch(mapping), FIXED_NOW)
    assert r.ok
    hits = [i for i in r.items if "Akira" in i["title"]]
    assert hits and hits[0]["category"] == "ransomware"
    assert hits[0]["severity"] == "medium"               # entity-bearing report
    assert hits[0]["entities"]["cves"] == ["CVE-2026-1111"]
```

Every feed URL must be mapped: the fixture goes to the first feed, the rest return `""`, which feedparser treats as an empty feed.

- [ ] **Step 3: Run tests to verify they fail**

Run: `.venv\Scripts\python -m pytest tests/test_rss.py -v`
Expected: FAIL — missing modules

- [ ] **Step 4: Write pipeline/entities.py and collectors/rss.py**

`pipeline/entities.py`:
```python
import json
import re
from functools import lru_cache
from pathlib import Path

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


@lru_cache(maxsize=None)
def _dictionaries(entities_dir):
    d = Path(entities_dir)
    return {
        "actors": json.loads((d / "actors.json").read_text(encoding="utf-8")),
        "malware": json.loads((d / "malware.json").read_text(encoding="utf-8")),
        "vendors": json.loads((d / "vendors.json").read_text(encoding="utf-8")),
    }


def extract_entities(text, entities_dir="data/entities"):
    dicts = _dictionaries(entities_dir)
    lower = text.lower()
    found = {"actors": [], "malware": [], "vendors": [], "cves": []}
    for kind in ("actors", "malware", "vendors"):
        for name in dicts[kind]:
            if re.search(rf"\b{re.escape(name.lower())}\b", lower):
                found[kind].append(name)
    found["cves"] = sorted({m.upper() for m in CVE_RE.findall(text)})
    return found


RANSOM_ACTORS = {"akira", "lockbit", "alphv", "blackcat", "play", "cl0p",
                 "black basta", "ransomhub", "medusa", "rhysida", "qilin",
                 "8base", "conti", "royal"}


def classify_category(title, entities):
    tl = title.lower()
    if "ransom" in tl or any(a.lower() in RANSOM_ACTORS for a in entities["actors"]):
        return "ransomware"
    if entities["cves"] or "vulnerab" in tl or "patch" in tl or "zero-day" in tl:
        return "vulnerability"
    if re.search(r"\bapt\d*\b", tl) or (entities["actors"] and not entities["malware"]):
        return "apt"
    if "campaign" in tl or "phishing" in tl:
        return "campaign"
    if entities["malware"]:
        return "malware"
    return "report"
```

`collectors/rss.py`:
```python
import calendar

import feedparser

from collectors.base import CollectorResult, iso, make_item
from pipeline.entities import classify_category, extract_entities

SOURCE = "rss"

FEEDS = [
    {"name": "Cisco Talos", "url": "https://blog.talosintelligence.com/rss/"},
    {"name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/"},
    {"name": "The DFIR Report", "url": "https://thedfirreport.com/feed/"},
    {"name": "Microsoft Threat Intelligence", "url": "https://www.microsoft.com/en-us/security/blog/feed/"},
    {"name": "Google Threat Intelligence", "url": "https://cloud.google.com/blog/topics/threat-intelligence/rss/"},
    {"name": "SANS ISC", "url": "https://isc.sans.edu/rssfeed.xml"},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "Securelist", "url": "https://securelist.com/feed/"},
]


def _published(entry, now):
    parsed = entry.get("published_parsed") or entry.get("updated_parsed")
    if not parsed:
        return iso(now)
    from datetime import datetime, timezone
    return iso(datetime.fromtimestamp(calendar.timegm(parsed), tz=timezone.utc))


def collect(fetch, now):
    items, errors = [], []
    for feed in FEEDS:
        try:
            raw = fetch(feed["url"], text=True)
            parsed = feedparser.parse(raw)
            for entry in parsed.entries[:20]:
                title = entry.get("title", "").strip()
                if not title:
                    continue
                summary = entry.get("summary", "")
                entities = extract_entities(f"{title} {summary}")
                category = classify_category(title, entities)
                has_entities = any(entities.values())
                items.append(make_item(
                    SOURCE, entry.get("link", title), category,
                    f"[{feed['name']}] {title}", summary,
                    entry.get("link", ""),
                    "medium" if has_entities else "info",
                    _published(entry, now), now, entities=entities))
        except Exception as e:  # noqa: BLE001 — one dead feed must not kill the pool
            errors.append(f"{feed['name']}: {str(e)[:100]}")
    if errors and len(errors) == len(FEEDS):
        raise RuntimeError("; ".join(errors))
    return CollectorResult(source=SOURCE, items=items,
                           error="; ".join(errors)[:300])
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_rss.py -v`
Expected: 3 passed

- [ ] **Step 6: Commit**

```bash
git add pipeline/entities.py data/entities collectors/rss.py tests/fixtures/rss tests/test_rss.py
git commit -m "feat: entity extraction and RSS pool collector"
```

---

### Task 11: MITRE ATT&CK collector (7-day cached)

**Files:**
- Create: `collectors/attack.py`, `tests/fixtures/attack/enterprise.json`
- Test: `tests/test_attack.py`

- [ ] **Step 1: Write fixture and failing test**

`tests/fixtures/attack/enterprise.json` (minimal STIX bundle):
```json
{"type": "bundle", "objects": [
  {"type": "intrusion-set", "id": "intrusion-set--aaa", "name": "APT9999",
   "aliases": ["APT9999", "Test Panda"], "description": "Test actor.",
   "external_references": [{"source_name": "mitre-attack", "external_id": "G9999"}]},
  {"type": "malware", "id": "malware--bbb", "name": "TestRAT",
   "description": "Test malware.",
   "external_references": [{"source_name": "mitre-attack", "external_id": "S9999"}]},
  {"type": "attack-pattern", "id": "attack-pattern--ccc", "name": "Phishing",
   "external_references": [{"source_name": "mitre-attack", "external_id": "T1566"}]},
  {"type": "relationship", "relationship_type": "uses",
   "source_ref": "intrusion-set--aaa", "target_ref": "attack-pattern--ccc"},
  {"type": "relationship", "relationship_type": "uses",
   "source_ref": "intrusion-set--aaa", "target_ref": "malware--bbb"},
  {"type": "intrusion-set", "id": "intrusion-set--ddd", "name": "Deprecated Actor",
   "revoked": true,
   "external_references": [{"source_name": "mitre-attack", "external_id": "G0000"}]}
]}
```

```python
# tests/test_attack.py
from collectors import attack
from tests.conftest import FIXED_NOW


def test_attack_profiles(fake_fetch):
    r = attack.collect(fake_fetch({attack.URL: "attack/enterprise.json"}), FIXED_NOW)
    assert r.ok
    actors = r.extra["actors"]
    assert len(actors) == 1                      # revoked object dropped
    a = actors[0]
    assert a["name"] == "APT9999" and a["attack_id"] == "G9999"
    assert a["techniques"] == ["T1566"]
    assert a["software"] == ["TestRAT"]
    malware = r.extra["malware"]
    assert malware[0]["attack_id"] == "S9999"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python -m pytest tests/test_attack.py -v`
Expected: FAIL — no module

- [ ] **Step 3: Write collectors/attack.py**

```python
from collectors.base import CollectorResult

SOURCE = "attack"
URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
       "master/enterprise-attack/enterprise-attack.json")
CACHE_DAYS = 7  # pipeline skips this collector when state is fresher than this


def _attack_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def collect(fetch, now):
    bundle = fetch(URL)
    objs = bundle.get("objects", [])
    by_id, rels = {}, []
    for o in objs:
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        if o["type"] in ("intrusion-set", "malware", "tool", "attack-pattern"):
            by_id[o["id"]] = o
        elif o["type"] == "relationship" and o.get("relationship_type") == "uses":
            rels.append(o)

    uses = {}
    for r in rels:
        uses.setdefault(r["source_ref"], []).append(r["target_ref"])

    actors, malware = [], []
    for o in by_id.values():
        if o["type"] == "intrusion-set":
            techniques, software = [], []
            for tgt in uses.get(o["id"], []):
                t = by_id.get(tgt)
                if not t:
                    continue
                if t["type"] == "attack-pattern":
                    techniques.append(_attack_id(t))
                elif t["type"] in ("malware", "tool"):
                    software.append(t["name"])
            actors.append({
                "name": o["name"], "attack_id": _attack_id(o),
                "aliases": o.get("aliases", []),
                "description": (o.get("description") or "")[:800],
                "techniques": sorted(t for t in techniques if t),
                "software": sorted(software),
            })
        elif o["type"] in ("malware", "tool"):
            malware.append({
                "name": o["name"], "attack_id": _attack_id(o),
                "aliases": o.get("x_mitre_aliases", []),
                "description": (o.get("description") or "")[:800],
                "techniques": [], "software": [],
            })
    actors.sort(key=lambda a: a["attack_id"])
    malware.sort(key=lambda m: m["attack_id"])
    return CollectorResult(source=SOURCE, extra={"actors": actors, "malware": malware})
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_attack.py -v`
Expected: 1 passed

- [ ] **Step 5: Commit**

```bash
git add collectors/attack.py tests/fixtures/attack tests/test_attack.py
git commit -m "feat: MITRE ATT&CK actor/software collector"
```

---

### Task 12: Rolling windows + site payload builder

**Files:**
- Create: `pipeline/publish.py`
- Test: `tests/test_publish.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_publish.py
from collectors.base import CollectorResult, iso, make_item
from pipeline.publish import build_site_data, merge_feed, merge_iocs
from tests.conftest import FIXED_NOW

NEW_ITEM = make_item("rss", "n1", "report", "Fresh", "s", "https://x/1",
                     "info", "2026-07-28T01:00:00Z", FIXED_NOW)
RECENT_OLD = dict(NEW_ITEM, id="b" * 40, published_at="2026-07-10T00:00:00Z")
ANCIENT = dict(NEW_ITEM, id="c" * 40, published_at="2026-01-01T00:00:00Z")


def test_merge_feed_window_and_dedup():
    merged = merge_feed([RECENT_OLD, ANCIENT, dict(NEW_ITEM)], [NEW_ITEM],
                        days=30, now=FIXED_NOW)
    ids = [i["id"] for i in merged]
    assert NEW_ITEM["id"] in ids and RECENT_OLD["id"] in ids
    assert ANCIENT["id"] not in ids
    assert len(ids) == len(set(ids))
    assert merged[0]["published_at"] >= merged[-1]["published_at"]  # newest first


def test_merge_iocs_updates_last_seen():
    prior = [{"type": "ipv4", "value": "1.2.3.4", "source": "threatfox",
              "malware": "X", "confidence": 50,
              "first_seen": "2026-07-01T00:00:00Z", "last_seen": "2026-07-01T00:00:00Z"}]
    fresh = [dict(prior[0], last_seen="2026-07-28T00:00:00Z", confidence=90)]
    merged = merge_iocs(prior, fresh, days=90, now=FIXED_NOW)
    assert len(merged["ipv4"]) == 1
    entry = merged["ipv4"][0]
    assert entry["first_seen"] == "2026-07-01T00:00:00Z"   # preserved
    assert entry["last_seen"] == "2026-07-28T00:00:00Z"    # updated
    assert entry["confidence"] == 90


def test_build_site_data_shapes():
    results = [
        CollectorResult(source="rss", items=[NEW_ITEM]),
        CollectorResult(source="threatfox", extra={"iocs": [
            {"type": "domain", "value": "evil.example", "source": "threatfox",
             "malware": "", "confidence": 10,
             "first_seen": iso(FIXED_NOW), "last_seen": iso(FIXED_NOW)}]}),
        CollectorResult(source="attack", extra={
            "actors": [{"name": "A", "attack_id": "G1", "aliases": [],
                        "description": "", "techniques": [], "software": []}],
            "malware": []}),
    ]
    health = [{"source": "rss", "ok": True, "error": "", "items": 1,
               "last_success_at": iso(FIXED_NOW)}]
    payloads = build_site_data(results, cve_rows=[], health=health,
                               prior={}, now=FIXED_NOW)
    assert set(payloads) >= {"feed.json", "iocs.json", "cves.json",
                             "health.json", "actors.json", "malware.json"}
    for p in payloads.values():
        assert p["generated_at"] == iso(FIXED_NOW) and p["schema_version"] == 1


def test_health_carries_forward_last_success():
    prior_health = {"health.json": {
        "generated_at": "x", "schema_version": 1, "sources": [
            {"source": "rss", "ok": True, "error": "", "items": 5,
             "last_success_at": "2026-07-27T00:00:00Z"}]}}
    health = [{"source": "rss", "ok": False, "error": "boom", "items": 0,
               "last_success_at": ""}]
    payloads = build_site_data([], cve_rows=[], health=health,
                               prior=prior_health, now=FIXED_NOW)
    entry = payloads["health.json"]["sources"][0]
    assert entry["last_success_at"] == "2026-07-27T00:00:00Z"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv\Scripts\python -m pytest tests/test_publish.py -v`
Expected: FAIL — no module `pipeline.publish`

- [ ] **Step 3: Write pipeline/publish.py**

```python
from datetime import timedelta

from collectors.base import iso

FEED_DAYS = 30
IOC_DAYS = 90
SCHEMA_VERSION = 1
IOC_TYPES = ("ipv4", "domain", "url", "md5", "sha256")


def _envelope(now, **body):
    return {"generated_at": iso(now), "schema_version": SCHEMA_VERSION, **body}


def merge_feed(prior_items, new_items, days, now):
    cutoff = iso(now - timedelta(days=days))
    merged = {i["id"]: i for i in prior_items}
    merged.update({i["id"]: i for i in new_items})     # fresh wins
    kept = [i for i in merged.values() if i["published_at"] >= cutoff]
    return sorted(kept, key=lambda i: i["published_at"], reverse=True)


def merge_iocs(prior_entries, new_entries, days, now):
    cutoff = iso(now - timedelta(days=days))
    merged = {}
    for e in list(prior_entries) + list(new_entries):
        key = (e["type"], e["value"], e["source"])
        if key in merged:
            old = merged[key]
            e = dict(e, first_seen=min(old["first_seen"], e["first_seen"]),
                     last_seen=max(old["last_seen"], e["last_seen"]))
        merged[key] = e
    by_type = {t: [] for t in IOC_TYPES}
    for e in merged.values():
        if e["last_seen"] >= cutoff:
            by_type[e["type"]].append(
                {k: v for k, v in e.items() if k != "type"})
    for t in by_type:
        by_type[t].sort(key=lambda e: e["last_seen"], reverse=True)
    return by_type


def _flatten_prior_iocs(prior_iocs_payload):
    out = []
    for t, entries in prior_iocs_payload.get("iocs", {}).items():
        out.extend(dict(e, type=t) for e in entries)
    return out


def build_site_data(results, cve_rows, health, prior, now):
    ok = {r.source: r for r in results if r.ok}

    new_feed = [i for r in ok.values() for i in r.items]
    prior_feed = prior.get("feed.json", {}).get("items", [])
    feed = merge_feed(prior_feed, new_feed, FEED_DAYS, now)

    new_iocs = [i for r in ok.values() for i in r.extra.get("iocs", [])]
    iocs = merge_iocs(_flatten_prior_iocs(prior.get("iocs.json", {})),
                      new_iocs, IOC_DAYS, now)

    prior_success = {e["source"]: e["last_success_at"]
                     for e in prior.get("health.json", {}).get("sources", [])}
    health_out = [dict(e, last_success_at=e["last_success_at"]
                       or prior_success.get(e["source"], ""))
                  for e in health]

    payloads = {
        "feed.json": _envelope(now, items=feed),
        "iocs.json": _envelope(now, iocs=iocs),
        "cves.json": _envelope(now, cves=cve_rows),
        "health.json": _envelope(now, sources=health_out),
    }

    if "attack" in ok:
        payloads["actors.json"] = _envelope(now, profiles=ok["attack"].extra["actors"])
        payloads["malware.json"] = _envelope(now, profiles=ok["attack"].extra["malware"])
    else:
        for name in ("actors.json", "malware.json"):
            if name in prior:
                payloads[name] = dict(prior[name], generated_at=iso(now))
    return payloads
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_publish.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add pipeline/publish.py tests/test_publish.py
git commit -m "feat: rolling-window merge and site payload builder"
```

---

### Task 13: Source registry seed + pipeline entrypoint

**Files:**
- Create: `data/sources.json`, `pipeline/http.py`, `run_pipeline.py`, `collectors/__init__.py` (modify)
- Test: `tests/test_pipeline.py`

- [ ] **Step 1: Write data/sources.json (24-entry registry seed)**

The 9 collector-backed sources (`kind: "collector"`, slugs matching `SOURCE` constants — `rss` covers the 9-feed pool as one registry group per feed):

```json
{"generated_at": "2026-07-28T00:00:00Z", "schema_version": 1, "sources": [
  {"name": "CISA KEV", "kind": "collector", "slug": "kev", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "coverage": "Actively exploited CVE catalog", "enabled": true},
  {"name": "NVD", "kind": "collector", "slug": "nvd", "url": "https://nvd.nist.gov", "coverage": "CVE details, CVSS, affected products", "enabled": true},
  {"name": "FIRST EPSS", "kind": "collector", "slug": "epss", "url": "https://www.first.org/epss/", "coverage": "Exploitation probability scoring", "enabled": true},
  {"name": "ThreatFox", "kind": "collector", "slug": "threatfox", "url": "https://threatfox.abuse.ch", "coverage": "IOCs with malware attribution", "enabled": true},
  {"name": "URLhaus", "kind": "collector", "slug": "urlhaus", "url": "https://urlhaus.abuse.ch", "coverage": "Malicious URL tracking", "enabled": true},
  {"name": "MalwareBazaar", "kind": "collector", "slug": "malwarebazaar", "url": "https://bazaar.abuse.ch", "coverage": "Malware sample hashes and families", "enabled": true},
  {"name": "Ransomware.live", "kind": "collector", "slug": "ransomwarelive", "url": "https://ransomware.live", "coverage": "Ransomware group activity and victims", "enabled": true},
  {"name": "MITRE ATT&CK", "kind": "collector", "slug": "attack", "url": "https://attack.mitre.org", "coverage": "Adversary groups, software, techniques", "enabled": true},
  {"name": "Vendor & researcher RSS pool", "kind": "collector", "slug": "rss", "url": "https://github.com", "coverage": "Talos, Unit 42, DFIR Report, MSTIC, GTIG, SANS ISC, BleepingComputer, THN, Securelist", "enabled": true},
  {"name": "CISA Advisories", "kind": "reference", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories", "coverage": "US government advisories and alerts"},
  {"name": "Cisco Talos", "kind": "reference", "url": "https://blog.talosintelligence.com", "coverage": "Threat research and reversing"},
  {"name": "Palo Alto Unit 42", "kind": "reference", "url": "https://unit42.paloaltonetworks.com", "coverage": "Threat research, actor tracking"},
  {"name": "The DFIR Report", "kind": "reference", "url": "https://thedfirreport.com", "coverage": "Full intrusion breakdowns"},
  {"name": "Microsoft Threat Intelligence", "kind": "reference", "url": "https://www.microsoft.com/en-us/security/blog/", "coverage": "Nation-state and crimeware tracking"},
  {"name": "Google Threat Intelligence Group", "kind": "reference", "url": "https://cloud.google.com/blog/topics/threat-intelligence", "coverage": "Mandiant lineage threat research"},
  {"name": "CrowdStrike Blog", "kind": "reference", "url": "https://www.crowdstrike.com/blog/", "coverage": "Adversary-focused research"},
  {"name": "SANS Internet Storm Center", "kind": "reference", "url": "https://isc.sans.edu", "coverage": "Daily handler diaries, port trends"},
  {"name": "BleepingComputer", "kind": "reference", "url": "https://www.bleepingcomputer.com", "coverage": "Breaking security news"},
  {"name": "The Hacker News", "kind": "reference", "url": "https://thehackernews.com", "coverage": "Broad security news coverage"},
  {"name": "KrebsOnSecurity", "kind": "reference", "url": "https://krebsonsecurity.com", "coverage": "Cybercrime investigative reporting"},
  {"name": "Securelist (Kaspersky)", "kind": "reference", "url": "https://securelist.com", "coverage": "APT and crimeware research"},
  {"name": "Trend Micro Research", "kind": "reference", "url": "https://www.trendmicro.com/en_us/research.html", "coverage": "Vulnerability and threat research"},
  {"name": "Sophos X-Ops", "kind": "reference", "url": "https://news.sophos.com/en-us/category/threat-research/", "coverage": "Threat research and incident writeups"},
  {"name": "Ransomlook", "kind": "reference", "url": "https://www.ransomlook.io", "coverage": "Ransomware leak-site monitoring (secondary)"}
]}
```

- [ ] **Step 2: Write failing end-to-end test**

```python
# tests/test_pipeline.py
import json
from pathlib import Path

from run_pipeline import run
from tests.conftest import FIXED_NOW, FIXTURES


def test_end_to_end_with_one_source_down(fake_fetch, tmp_path, monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "test-key")
    from collectors import (attack, kev, malwarebazaar, nvd, ransomwarelive,
                            rss, threatfox, urlhaus)
    rss_xml = (FIXTURES / "rss/talos.xml").read_text(encoding="utf-8")
    mapping = {
        kev.URL: "kev/feed.json",
        nvd.build_url(FIXED_NOW): "nvd/recent.json",
        threatfox.URL: "threatfox/recent.json",
        urlhaus.URL: "urlhaus/recent.json",
        malwarebazaar.URL: "malwarebazaar/recent.json",
        attack.URL: "attack/enterprise.json",
        # ransomwarelive.URL deliberately unmapped -> collector fails
    }
    for f in rss.FEEDS:
        mapping[f["url"]] = rss_xml if f is rss.FEEDS[0] else ""
    # EPSS URLs vary by CVE set; route any api.first.org URL to the fixture
    fetch_inner = fake_fetch(mapping)

    def fetch(url, **kw):
        if url.startswith("https://api.first.org"):
            return json.loads((FIXTURES / "epss/scores.json").read_text(encoding="utf-8"))
        return fetch_inner(url, **kw)

    out = tmp_path / "site_data"
    state = tmp_path / "state"
    run(fetch=fetch, now=FIXED_NOW, out_dir=out, state_dir=state,
        schemas_dir="schemas", sources_path="data/sources.json")

    published = {p.name for p in out.iterdir()}
    assert {"feed.json", "iocs.json", "cves.json", "health.json",
            "sources.json", "actors.json", "malware.json"} <= published

    health = json.loads((out / "health.json").read_text(encoding="utf-8"))
    by_source = {s["source"]: s for s in health["sources"]}
    assert by_source["ransomwarelive"]["ok"] is False     # isolated failure
    assert by_source["kev"]["ok"] is True

    # state mirrors published payloads for next run's last-known-good
    assert (state / "feed.json").exists()

    # second run consumes state without error (idempotent)
    run(fetch=fetch, now=FIXED_NOW, out_dir=out, state_dir=state,
        schemas_dir="schemas", sources_path="data/sources.json")
```

- [ ] **Step 3: Run test to verify it fails**

Run: `.venv\Scripts\python -m pytest tests/test_pipeline.py -v`
Expected: FAIL — no module `run_pipeline`

- [ ] **Step 4: Write pipeline/http.py, collectors/__init__.py, run_pipeline.py**

`pipeline/http.py`:
```python
import httpx

HEADERS = {"User-Agent": "SOCDESK-collector/0.1 (+https://github.com/SaltyCarl)"}


def http_fetch(url, *, method="GET", json=None, headers=None, text=False):
    merged = dict(HEADERS, **(headers or {}))
    with httpx.Client(timeout=30, follow_redirects=True) as client:
        resp = client.request(method, url, json=json, headers=merged)
        resp.raise_for_status()
        return resp.text if text else resp.json()
```

`collectors/__init__.py`:
```python
from collectors import (attack, kev, malwarebazaar, nvd, ransomwarelive, rss,
                        threatfox, urlhaus)

COLLECTORS = [kev, nvd, threatfox, urlhaus, malwarebazaar, ransomwarelive, rss]
CACHED_COLLECTORS = [attack]   # run only when state is stale (attack.CACHE_DAYS)
```

`run_pipeline.py`:
```python
import json
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from collectors import CACHED_COLLECTORS, COLLECTORS, attack
from collectors.base import iso, run_all
from pipeline.cves import build_cve_rows, enrich_epss
from pipeline.publish import build_site_data
from pipeline.validate import gate

BRIEF_SRC = Path("data/brief.json")


def _load_state(state_dir):
    state = {}
    if state_dir.exists():
        for p in state_dir.glob("*.json"):
            try:
                state[p.name] = json.loads(p.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
    return state


def _attack_is_fresh(state, now):
    gen = state.get("actors.json", {}).get("generated_at", "")
    return gen >= iso(now - timedelta(days=attack.CACHE_DAYS))


def run(fetch, now, out_dir, state_dir, schemas_dir, sources_path):
    out_dir, state_dir = Path(out_dir), Path(state_dir)
    state = _load_state(state_dir)

    modules = list(COLLECTORS)
    if not _attack_is_fresh(state, now):
        modules += CACHED_COLLECTORS
    results, health = run_all(modules, fetch, now)

    prior_cves = state.get("cves.json", {}).get("cves", [])
    cve_rows = build_cve_rows(results, prior_cves, now)
    health.append(enrich_epss(fetch, cve_rows, now))

    payloads = build_site_data(results, cve_rows, health, state, now)
    sources = json.loads(Path(sources_path).read_text(encoding="utf-8"))
    payloads["sources.json"] = dict(sources, generated_at=iso(now))

    published, problems = gate(payloads, state, schemas_dir)
    if problems:
        published["health.json"] = dict(
            published.get("health.json", payloads["health.json"]),
            pipeline_warnings=problems)

    out_dir.mkdir(parents=True, exist_ok=True)
    state_dir.mkdir(parents=True, exist_ok=True)
    for name, payload in published.items():
        blob = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        (out_dir / name).write_text(blob, encoding="utf-8")
        (state_dir / name).write_text(blob, encoding="utf-8")

    if BRIEF_SRC.exists():                     # Tier 2 output, pass through
        shutil.copy(BRIEF_SRC, out_dir / "brief.json")

    print(f"published {sorted(published)}; problems={problems}")
    return published, problems


if __name__ == "__main__":
    from pipeline.http import http_fetch
    _, problems = run(fetch=http_fetch, now=datetime.now(timezone.utc),
                      out_dir="site/data", state_dir="data/state",
                      schemas_dir="schemas", sources_path="data/sources.json")
    sys.exit(0)   # upstream problems are health data, never a CI failure
```

- [ ] **Step 5: Run full suite**

Run: `.venv\Scripts\python -m pytest tests/ -v`
Expected: all tests pass (16 by this point)

- [ ] **Step 6: Commit**

```bash
git add data/sources.json pipeline/http.py collectors/__init__.py run_pipeline.py tests/test_pipeline.py
git commit -m "feat: source registry seed and end-to-end pipeline entrypoint"
```

---

### Task 14: Placeholder status page

**Files:**
- Create: `site/index.html`

This page is **throwaway** — Phase B's design phase replaces it entirely. Its only job is proving the deploy loop with something human-readable: source health table + latest feed items + counts. Keep it under ~150 lines, dark background, system fonts, zero dependencies. No design effort here (the design phase owns all visual decisions).

- [ ] **Step 1: Write site/index.html**

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SOCDESK — pipeline status</title>
<style>
  body { background:#0d1117; color:#c9d1d9; font-family:system-ui, sans-serif;
         max-width:900px; margin:2rem auto; padding:0 1rem; }
  h1 { font-size:1.2rem; letter-spacing:.2em; }
  .note { color:#8b949e; font-size:.85rem; }
  table { border-collapse:collapse; width:100%; margin:1rem 0; }
  td, th { border-bottom:1px solid #21262d; padding:.4rem .6rem;
           text-align:left; font-size:.9rem; }
  .ok { color:#3fb950; } .fail { color:#f85149; }
  li { margin:.35rem 0; font-size:.9rem; }
</style>
</head>
<body>
<h1>SOCDESK</h1>
<p class="note">Phase A pipeline status page — replaced by the real interface in Phase B.</p>
<div id="app">loading…</div>
<script>
(async () => {
  const app = document.getElementById("app");
  try {
    const [health, feed] = await Promise.all([
      fetch("data/health.json").then(r => r.json()),
      fetch("data/feed.json").then(r => r.json()),
    ]);
    const rows = health.sources.map(s =>
      `<tr><td>${s.source}</td>
           <td class="${s.ok ? "ok" : "fail"}">${s.ok ? "OK" : "FAIL"}</td>
           <td>${s.items}</td><td>${s.last_success_at || "—"}</td>
           <td>${s.error || ""}</td></tr>`).join("");
    const items = feed.items.slice(0, 10).map(i =>
      `<li>[${i.severity}] <a href="${i.url}" style="color:#58a6ff">${i.title}</a></li>`).join("");
    app.innerHTML = `
      <p class="note">data generated ${health.generated_at} —
         ${feed.items.length} feed items in window</p>
      <table><tr><th>source</th><th>status</th><th>items</th>
             <th>last success</th><th>error</th></tr>${rows}</table>
      <h2 style="font-size:1rem">latest items</h2><ul>${items}</ul>`;
  } catch (e) { app.textContent = "no data yet — pipeline has not run: " + e; }
})();
</script>
</body>
</html>
```

- [ ] **Step 2: Verify locally against real pipeline output**

Run: `.venv\Scripts\python run_pipeline.py` (live fetch), then `.venv\Scripts\python -m http.server 8080 -d site` and open `http://localhost:8080`.
Expected: health table shows all sources OK (or specific failures), latest items render. This is the first live-API touch — note any upstream shape surprises and fix collectors + fixtures now.

- [ ] **Step 3: Commit**

```bash
git add site/index.html
git commit -m "feat: placeholder pipeline status page"
```

---

### Task 15: GitHub Actions workflow + README

**Files:**
- Create: `.github/workflows/collect-and-deploy.yml`, `README.md`

- [ ] **Step 1: Write the workflow**

```yaml
name: collect-and-deploy

on:
  schedule:
    - cron: "11,41 * * * *"        # twice hourly, offset from top-of-hour load
  workflow_dispatch: {}
  push:
    branches: [main]
    paths: ["data/brief.json"]     # Tier 2 (Framework) pushes redeploy the site

concurrency:
  group: collect-and-deploy
  cancel-in-progress: false

permissions:
  contents: write

jobs:
  collect-and-deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip

      - run: pip install -r requirements.txt

      - run: python -m pytest tests/ -q

      - name: Run collectors
        env:
          ABUSECH_AUTH_KEY: ${{ secrets.ABUSECH_AUTH_KEY }}
        run: python run_pipeline.py

      - name: Commit state snapshots
        run: |
          git config user.name "SaltyCarl"
          git config user.email "CarlosSanchez1994@live.com"
          git add data/state
          git diff --cached --quiet || git commit -m "data: refresh snapshots"
          git pull --rebase origin main
          git push
        # GITHUB_TOKEN pushes cannot retrigger workflows -> no cron/push loop.
        # The Framework's brief.json pushes use a deploy key, so they DO
        # trigger this workflow. That asymmetry is intentional.

      - name: Deploy to Cloudflare Pages
        uses: cloudflare/wrangler-action@v3
        with:
          apiToken: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          accountId: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}
          command: pages deploy site --project-name=socdesk
```

- [ ] **Step 2: Write README.md**

```markdown
# SOCDESK

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
2. Cloudflare: create a Pages project named `socdesk`
   (`npx wrangler pages project create socdesk`).
3. Repo secrets (Settings → Secrets → Actions):
   - `CLOUDFLARE_API_TOKEN` — API token with Cloudflare Pages > Edit
   - `CLOUDFLARE_ACCOUNT_ID` — from the Cloudflare dashboard
   - `ABUSECH_AUTH_KEY` — free key from https://auth.abuse.ch (used by
     ThreatFox / URLhaus / MalwareBazaar collectors)
4. Run the workflow once manually (Actions → collect-and-deploy → Run
   workflow) and open the `socdesk.pages.dev` URL.

## Data files

`feed.json` (30-day window) · `iocs.json` (90-day) · `cves.json` (180-day,
KEV+CVSS+EPSS join) · `actors.json` / `malware.json` (ATT&CK) ·
`health.json` · `sources.json` · `brief.json` (optional, external writer)
```

- [ ] **Step 3: Commit**

```bash
git add .github README.md
git commit -m "feat: scheduled collect-and-deploy workflow"
```

---

### Task 16: Live dogfood + phase close-out (REQUIRED before tag)

Mocked fixtures ≠ real API behavior. This checkpoint is mandatory before the phase tag.

- [ ] **Step 1: Register for the free abuse.ch Auth-Key** at https://auth.abuse.ch (Carl action). Set locally: `$env:ABUSECH_AUTH_KEY = "<key>"`.

- [ ] **Step 2: Full live local run**

Run: `.venv\Scripts\python run_pipeline.py`
Expected: `published [...]` listing all 7+ files, `problems=[]`. Inspect `site/data/health.json` — every source `ok: true`. For each source that fails or returns a surprising shape: fix the collector, update the fixture to the real shape, re-run tests, commit the fix individually.

- [ ] **Step 3: Verify payload sizes**

Run: `Get-ChildItem site/data | Select-Object Name, Length`
Expected: total well under 10 MB (spec §9). If `cves.json` or `iocs.json` blow past it, tighten windows in `pipeline/publish.py` / `pipeline/cves.py` and commit.

- [ ] **Step 4: Create GitHub repo, push, configure secrets** (README §One-time setup, Carl action for the Cloudflare token + account id).

- [ ] **Step 5: Manual workflow dispatch on GitHub**

Actions → collect-and-deploy → Run workflow. Expected: green run; `data/state` commit appears authored by SaltyCarl with no AI attribution; `https://socdesk.pages.dev` serves the status page with live data.

- [ ] **Step 6: Verify the cron loop** — after the next scheduled run (:11 or :41), confirm a fresh `generated_at` on the live URL and exactly one new state commit.

- [ ] **Step 7: Tag**

```bash
git tag v0.1.0-phase-a
git push --tags
```

---

## Self-review notes (completed)

- **Spec coverage (Phase A scope):** §3.1 collectors — T4–T11; fault isolation — T3 + T13 e2e test; schema gate + last-known-good — T2; rolling windows / payload caps — T12 + T16.3; deploy via wrangler direct upload + retrigger asymmetry — T15; registry seed with collector/reference split — T13; health with last-success carry-forward — T12. Deliberately out of scope here: all §4 site capabilities and §5 design phase (Phase B plan), §3.2 brief loop (Phase C plan — but its integration point, `data/brief.json` passthrough + push trigger, is already wired in T13/T15 so Phase C needs zero pipeline changes).
- **Spec refinement recorded:** abuse.ch trio feeds the IOC repository only, not the human feed (rationale in File structure section).
- **Known risk accepted:** fixture shapes for Ransomware.live/ThreatFox may drift from live APIs — T14.2 and T16.2 are the explicit correction points.
```
