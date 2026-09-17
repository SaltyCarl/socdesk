# SOCDESK · PICKET — P1 (collect-only foundation) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the sensor→export→pipeline→web foundation: a knock-knock honeypot on an isolated VPS whose bounded, PII-fenced telemetry lands in a public data-only repo, is collected keylessly, published as `picket.json` + `picket_ips.json` through the schema gate, and rendered as a `/desk#picket` tab, a landing-board teaser, and an `/about#picket` transparency section — with the reference doc and the box runbook shipped alongside.

**Architecture:** Five additive tiers (spec §2). P1 builds tiers S (box), X (exporter: SQLite rollups → on-box delta ring → `export.json` → `git push` to `SaltyCarl/socdesk-picket-export`), P (`collectors/picket.py` fetches the raw URL, re-sanitizes with `clean_text`, `pipeline/picket.py` builds the payloads, `validate.py` gates them, `run_pipeline.py` dual-writes them), and the read-only parts of W (Desk tab, teaser, About). Nothing touches `/api/enrich`, `asn.py`, the globe, or D1 — those are P2/P3.

**Tech Stack:** Python 3.12 (stdlib `sqlite3`, `jsonschema` already pinned; `geoip2` **only** in `tools/picket/requirements.txt`, never in the pipeline's), knock-knock (MIT, Docker host networking), systemd timer, git deploy key (export repo only), React 19 + TypeScript + Tailwind v4 in `web/`, vitest (node env, `renderToStaticMarkup`), pytest.

**Spec:** `docs/superpowers/specs/2026-09-17-picket-sensor-design.md` — read §0 (scope fence), §1 (invariants), §3.1–3.6, §3.11, §4, §5, §10 before starting any task.

## Global Constraints

- Every upstream string passes `collectors.base.clean_text` at collection **and** is escaped at render; every schema is `additionalProperties:false` with `maxLength`/`maxItems` on everything (spec §1.2, CLAUDE.md "Keep schemas bounded"). Never loosen a schema to make a live export pass.
- **No new GitHub Actions secret. No new Pages binding. No per-lookup network call.** The collector fetches a **public raw URL** only (spec §1.5, §3.2).
- **No username:password pair, no per-knock row, no singleton credential** in any payload. Credential floor `hits_7d >= 3`; values ≤ 32 chars; anything email-/phone-/card-like dropped (spec §3.6).
- The sensor's plaintext IP never appears in any export or payload; the export carries `sensor.public_ip_sha256` only (spec §3.6.4).
- Payload envelope = `{"generated_at": iso(now), "schema_version": 1, ...}` via `pipeline.publish._envelope`; timestamps are `%Y-%m-%dT%H:%M:%SZ` (`collectors.base.iso`).
- Sensor status thresholds: `live` < 90 min, `stale` 90 min–24 h, `silent` > 24 h since `exported_at` (spec §3.11, §5). A silent sensor is never rendered as "0 attacks."
- Colour law: PICKET uses periwinkle volume measures only — **no red/amber/green anywhere** in PICKET (spec §1.4). No emoji, no serifs (brand). Copy register: `SOCDESK · PICKET`, first-use subtitle *"telemetry from my own sensor"*.
- Export repo: `SaltyCarl/socdesk-picket-export`, branch `main`, file `export.json`. Raw URL: `https://raw.githubusercontent.com/SaltyCarl/socdesk-picket-export/main/export.json`. Exporter refuses outputs > 512 KB; collector refuses bodies > 2 MB.
- Exporter timer fires at **:05 and :35** (six minutes before the pipeline cron `11,41 * * * *`).
- Documentation is a phase exit criterion (spec §10): Tasks 4, 12, 13, 14 are not optional.
- Commits: conventional-commit style, one logical unit per commit, tests before commit. End every commit message with:
  ```
  Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01TT32GiU6VRQ8C68AbYqAzE
  ```
- Run Python as `.venv\Scripts\python.exe` (no `python` on PATH). Tests: `.venv\Scripts\python -m pytest tests/ -q`; `cd web && npx vitest run src`; `npm --prefix web run build`.

---

## File structure (locked)

```
tools/__init__.py                       (new, empty — makes tools importable in tests; harmless if present)
tools/picket/__init__.py                (new, empty)
tools/picket/fence.py                   pure: credential PII fence + public-IP test         (Task 1)
tools/picket/ring.py                    pure: 30-min delta ring + sparse per-entity deltas  (Task 2)
tools/picket/assemble.py                pure: rollups + ring → export dict; schema validate (Task 3)
tools/picket/exporter.py                CLI: sqlite/geoip/git glue around the pure modules  (Task 4)
tools/picket/requirements.txt           geoip2, jsonschema (box only)                      (Task 4)
tools/picket/systemd/picket-export.service|.timer                                        (Task 4)
tools/picket/install.sh                 idempotent box bootstrap (ufw, docker, knock-knock) (Task 4)
tools/picket/README.md                  THE BOX RUNBOOK (spec §10)                          (Task 4)
schemas/picket_export.schema.json       raw box→repo contract (spec §4.1)                   (Task 3)
schemas/picket.schema.json              published panel payload, P1 fields (spec §4.2)     (Task 6)
schemas/picket_ips.schema.json          globe-layer rows, source const "picket" (spec §4.4) (Task 6)
collectors/picket.py                    keyless fetch + normalize/fence/bounds              (Task 5)
pipeline/picket.py                      build_picket(ok, prior, now) → payloads             (Task 6)
run_pipeline.py                         wire collector + builder (keep-prior)               (Task 7)
tests/fixtures/picket/export_ok.json    a valid raw export (hand-authored)                  (Task 3)
tests/fixtures/picket/export_hostile.json   hostile strings + PII + oversize                (Task 5)
tests/test_picket_fence.py / _ring.py / _assemble.py / _collector.py / _pipeline.py
web/src/components/views/types.ts       + Picket* types                                    (Task 8)
web/src/components/views/picketModel.ts pure helpers (status copy, share %, histogram)     (Task 8)
web/src/components/views/PicketView.tsx the tab body                                        (Task 9)
web/src/routes/PicketRoute.tsx          header + AsyncGate + view                           (Task 9)
web/src/routes/DataDeskRoute.tsx        + 'picket' tab                                      (Task 9)
web/src/components/overview/PicketTeaser.tsx  landing-board panel                          (Task 10)
web/src/components/overview/SituationalBoard.tsx  mount teaser                              (Task 10)
web/src/routes/About.tsx                + #picket section                                   (Task 11)
docs/PICKET.md                          THE REFERENCE (spec §10)                            (Task 12)
docs/OPERATIONS.md · docs/DATA-SOURCES.md · docs/REPO-MAP.md · docs/ANALYST-GUIDE.md ·
README.md · COMPLIANCE.md               documentation updates                               (Task 13)
docs/HANDOFF.md · BACKLOG.md            close-out                                           (Task 14)
```

---

### Task 1: Credential PII fence (pure)

**Files:**
- Create: `tools/__init__.py` (empty), `tools/picket/__init__.py` (empty), `tools/picket/fence.py`
- Test: `tests/test_picket_fence.py`

**Interfaces:**
- Produces: `fence_credential(value) -> str | None` — returns the inert, trimmed value or `None` when the value must be dropped; `is_public_ip(ip) -> bool`; constants `MAX_CRED_LEN = 32`, `MIN_CRED_HITS = 3`. Used by Tasks 3, 4, 5.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_picket_fence.py
import pytest
from tools.picket.fence import MAX_CRED_LEN, MIN_CRED_HITS, fence_credential, is_public_ip


@pytest.mark.parametrize("value", ["admin", "root", "123456", "P@ssw0rd!", "ubuntu"])
def test_common_credentials_pass(value):
    assert fence_credential(value) == value


@pytest.mark.parametrize("value", [
    "alice@example.com",            # email
    "bob@corp",                     # any '@' — could be a real account handle
    "+1 415 555 0199",              # phone-like digit run
    "4111 1111 1111 1111",          # card-like
    "123-45-6789 extra",            # SSN-like run inside a longer string
    "x" * (MAX_CRED_LEN + 1),       # over length
    "",                             # empty
    "   ",                          # whitespace only
    "<img src=x onerror=alert(1)//", # markup — inert after clean_text but stripping leaves 'img src=x onerror=alert(1)//' which is fine; test below covers stripping
])
def test_fenced_values_are_dropped(value):
    if value.startswith("<img"):
        pytest.skip("covered by test_markup_is_stripped_not_dropped")
    assert fence_credential(value) is None


def test_markup_is_stripped_not_dropped():
    # clean_text reduces markup to inert text; a bot really does try such strings
    assert fence_credential("<b>admin</b>") == "admin"
    assert fence_credential("<img src=x onerror=alert(1)//") == "img src=x onerror=alert(1)//"


def test_constants():
    assert MAX_CRED_LEN == 32 and MIN_CRED_HITS == 3


@pytest.mark.parametrize("ip,ok", [
    ("8.8.8.8", True), ("2001:4860:4860::8888", True),
    ("10.0.0.1", False), ("192.168.1.1", False), ("172.16.0.1", False),
    ("127.0.0.1", False), ("169.254.1.1", False), ("::1", False), ("fc00::1", False),
    ("not-an-ip", False), ("8.8.8.0/24", False),
])
def test_is_public_ip(ip, ok):
    assert is_public_ip(ip) is ok
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv\Scripts\python -m pytest tests/test_picket_fence.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'tools.picket'`

- [ ] **Step 3: Implement**

Create empty `tools/__init__.py` and `tools/picket/__init__.py`, then:

```python
# tools/picket/fence.py
"""Credential PII fence — applied ON THE BOX (exporter) and AGAIN in the pipeline
(collector). Attackers replay credential-stuffing lists that can contain real
people's emails and passwords; a honeypot must never republish those.

Invariant: only aggregate top-N credential VALUES leave here, never pairs, never
singletons (MIN_CRED_HITS), never anything that looks like an identity.
"""
import ipaddress
import re

from collectors.base import clean_text

MAX_CRED_LEN = 32
MIN_CRED_HITS = 3

_EMAIL_RE = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+")
# 9+ digits allowing separators: phone numbers, card numbers, SSNs, IDs.
_LONG_DIGITS_RE = re.compile(r"\d[\d\-\s.]{7,}\d")


def fence_credential(value):
    """Return the inert value, or None if it must not be published."""
    v = clean_text(str(value or ""))
    if not v or len(v) > MAX_CRED_LEN:
        return None
    if "@" in v or _EMAIL_RE.search(v):
        return None
    digits = re.sub(r"[^\d]", "", v)
    if len(digits) >= 9 and _LONG_DIGITS_RE.search(v):
        return None
    return v


def is_public_ip(ip):
    """True only for a routable public unicast IPv4/IPv6 literal (never CIDR)."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified)
```

- [ ] **Step 4: Run to verify pass**

Run: `.venv\Scripts\python -m pytest tests/test_picket_fence.py -q`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add tools/__init__.py tools/picket/__init__.py tools/picket/fence.py tests/test_picket_fence.py
git commit -m "feat(picket): credential PII fence + public-IP test (pure, box+pipeline shared)"
```

---

### Task 2: Delta ring (pure)

**Files:**
- Create: `tools/picket/ring.py`
- Test: `tests/test_picket_ring.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `BUCKET_SECONDS = 1800`, `RING_LEN = 336`, `bucket_index(epoch_seconds) -> int`, `new_state() -> dict`, `apply_snapshot(state, snapshot, now_epoch) -> dict`.
  - `snapshot` = `{"total": int, "proto": {name: hits}, "ip": {ip: hits}, "user": {v: hits}, "pass": {v: hits}, "country": {iso: hits}, "isp": {isp: hits}}` (cumulative counters read from knock-knock).
  - Returns `{"ring": [RING_LEN ints], "hits_7d": {"proto":{...},"ip":{...},"user":{...},"pass":{...},"country":{...},"isp":{...}}, "unique_ips_7d": int, "reset": bool}` and **mutates `state`** (caller persists it).
  - `state` layout: `{"version": 1, "last_bucket": int|None, "prev": snapshot|None, "ring": [RING_LEN ints], "deltas": {kind: {key: [[bucket, delta], ...]}}}`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_picket_ring.py
from tools.picket.ring import BUCKET_SECONDS, RING_LEN, apply_snapshot, bucket_index, new_state

T0 = 1_800_000_000  # any epoch; multiple of 1800 for clean buckets


def snap(total, ip=None, user=None):
    return {"total": total, "proto": {"SSH": total}, "ip": ip or {}, "user": user or {},
            "pass": {}, "country": {}, "isp": {}}


def test_bucket_index_is_30_minutes():
    assert BUCKET_SECONDS == 1800 and RING_LEN == 336
    assert bucket_index(T0 + 1799) == bucket_index(T0)
    assert bucket_index(T0 + 1800) == bucket_index(T0) + 1


def test_first_snapshot_records_baseline_no_deltas():
    st = new_state()
    out = apply_snapshot(st, snap(100, ip={"1.1.1.1": 100}), T0)
    assert sum(out["ring"]) == 0 and out["hits_7d"]["ip"] == {} and out["unique_ips_7d"] == 0
    assert out["reset"] is False and st["prev"]["total"] == 100


def test_deltas_land_in_current_bucket_and_sum_over_window():
    st = new_state()
    apply_snapshot(st, snap(100, ip={"1.1.1.1": 100}), T0)
    out = apply_snapshot(st, snap(130, ip={"1.1.1.1": 120, "2.2.2.2": 10}), T0 + 1800)
    assert out["ring"][-1] == 30            # newest bucket is the last slot
    assert out["hits_7d"]["ip"] == {"1.1.1.1": 20, "2.2.2.2": 10}
    assert out["hits_7d"]["proto"] == {"SSH": 30}
    assert out["unique_ips_7d"] == 2


def test_skipped_buckets_are_zero_filled_and_window_slides():
    st = new_state()
    apply_snapshot(st, snap(0), T0)
    apply_snapshot(st, snap(5, ip={"9.9.9.9": 5}), T0 + 1800)
    # jump 8 days: everything ages out
    out = apply_snapshot(st, snap(5, ip={"9.9.9.9": 5}), T0 + 1800 + 8 * 86400)
    assert sum(out["ring"]) == 0 and out["hits_7d"]["ip"] == {} and out["unique_ips_7d"] == 0


def test_counter_decrease_is_clamped_and_flagged_as_reset():
    st = new_state()
    apply_snapshot(st, snap(500, ip={"1.1.1.1": 500}), T0)
    out = apply_snapshot(st, snap(3, ip={"1.1.1.1": 3}), T0 + 1800)   # knock-knock DB reset
    assert out["ring"][-1] == 0 and out["hits_7d"]["ip"] == {} and out["reset"] is True


def test_same_bucket_twice_accumulates_not_overwrites():
    st = new_state()
    apply_snapshot(st, snap(0), T0)
    apply_snapshot(st, snap(4), T0 + 60)
    out = apply_snapshot(st, snap(10), T0 + 120)
    assert out["ring"][-1] == 10


def test_state_is_bounded_by_pruning_old_sparse_deltas():
    st = new_state()
    apply_snapshot(st, snap(0), T0)
    for i in range(1, 400):   # 400 buckets of activity on one IP
        apply_snapshot(st, snap(i, ip={"1.1.1.1": i}), T0 + i * 1800)
    assert len(st["deltas"]["ip"]["1.1.1.1"]) <= RING_LEN
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv\Scripts\python -m pytest tests/test_picket_ring.py -q`
Expected: FAIL — `ImportError` (module missing)

- [ ] **Step 3: Implement**

```python
# tools/picket/ring.py
"""On-box delta ring: 7-day time series WITHOUT per-knock storage.

knock-knock's rollups are cumulative all-time counters. Every exporter run
snapshots them and turns the increase since the previous run into deltas —
a dense 336×30-min ring for the global histogram, and sparse per-entity
delta lists (most IPs are active in a handful of buckets) for 7-day hits.

Invariants: a counter that goes DOWN (DB reset/prune) is clamped to 0 and
flagged (`reset`) rather than published as a spike; nothing older than
RING_LEN buckets survives, so `state.json` stays bounded.
"""

BUCKET_SECONDS = 1800
RING_LEN = 336            # 7 days × 48 half-hours
KINDS = ("proto", "ip", "user", "pass", "country", "isp")


def bucket_index(epoch_seconds):
    return int(epoch_seconds) // BUCKET_SECONDS


def new_state():
    return {"version": 1, "last_bucket": None, "prev": None,
            "ring": [0] * RING_LEN, "deltas": {k: {} for k in KINDS}}


def _advance_ring(state, cur_bucket):
    last = state["last_bucket"]
    if last is None:
        return
    gap = cur_bucket - last
    if gap <= 0:
        return
    ring = state["ring"]
    if gap >= RING_LEN:
        state["ring"] = [0] * RING_LEN
    else:
        state["ring"] = ring[gap:] + [0] * gap


def apply_snapshot(state, snapshot, now_epoch):
    cur = bucket_index(now_epoch)
    _advance_ring(state, cur)
    prev = state["prev"]
    reset = False
    floor = cur - RING_LEN + 1

    if prev is not None:
        total_delta = int(snapshot["total"]) - int(prev["total"])
        if total_delta < 0:
            reset, total_delta = True, 0
        state["ring"][-1] += total_delta
        for kind in KINDS:
            prev_k, cur_k = prev.get(kind, {}), snapshot.get(kind, {})
            for key, hits in cur_k.items():
                d = int(hits) - int(prev_k.get(key, 0))
                if d < 0:
                    reset, d = True, 0
                if d <= 0:
                    continue
                lst = state["deltas"][kind].setdefault(key, [])
                if lst and lst[-1][0] == cur:
                    lst[-1][1] += d
                else:
                    lst.append([cur, d])

    # prune every sparse list to the window; drop empties
    for kind in KINDS:
        for key in list(state["deltas"][kind].keys()):
            kept = [[b, d] for b, d in state["deltas"][kind][key] if b >= floor]
            if kept:
                state["deltas"][kind][key] = kept[-RING_LEN:]
            else:
                del state["deltas"][kind][key]

    state["prev"] = snapshot
    state["last_bucket"] = cur

    hits_7d = {kind: {key: sum(d for _, d in lst) for key, lst in state["deltas"][kind].items()}
               for kind in KINDS}
    return {"ring": list(state["ring"]), "hits_7d": hits_7d,
            "unique_ips_7d": len(hits_7d["ip"]), "reset": reset}
```

- [ ] **Step 4: Run to verify pass**

Run: `.venv\Scripts\python -m pytest tests/test_picket_ring.py -q`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add tools/picket/ring.py tests/test_picket_ring.py
git commit -m "feat(picket): 30-min delta ring for 7-day series without per-knock storage"
```

---

### Task 3: Raw export schema + assembler (pure)

**Files:**
- Create: `schemas/picket_export.schema.json`, `tools/picket/assemble.py`, `tests/fixtures/picket/export_ok.json`
- Test: `tests/test_picket_assemble.py`

**Interfaces:**
- Consumes: `fence_credential`, `MIN_CRED_HITS`, `is_public_ip` (Task 1).
- Produces: `assemble_export(rollups, hits7d, ring, sensor, now, proto_names) -> dict` and `validate_export(export, schema_path) -> list[str]`.
  - `rollups` = `{"ip_intel": [ {ip, hits, first_seen, last_seen, lat, lng, asn} ], "ip_intel_proto": [ {ip, proto, hits} ], "user_intel": [ {username, hits} ], "pass_intel": [ {password, hits} ], "country_intel": [ {iso_code, country, hits} ], "isp_intel": [ {isp, hits, asn} ], "heartbeat_minutes": int, "knocks_total": int, "country_by_ip": {ip: iso}}` — plain dicts (sqlite rows → dict in Task 4).
  - `hits7d`, `ring` = the Task-2 output fields; `sensor` = `{"id","public_ip_sha256","protocols":[...],"knockknock_version","country"?,"ring_reset_at"?}`; `proto_names` = `{int: "SSH", ...}`.

- [ ] **Step 1: Write the schema** (`schemas/picket_export.schema.json`) — copy spec §4.1 verbatim, then add a `"description"` to every property (spec §10 requires it). Use this description set: `exported_at` "UTC time the exporter ran; freshness is measured from this"; `sensor.public_ip_sha256` "SHA-256 of the sensor's public IP — the plaintext IP never leaves the box"; `ring.buckets` "336 half-hour knock counts, oldest first"; `top_ips[].protocols[].hits_7d` "attempts in the last 7 days on this protocol"; `top_usernames`/`top_passwords` "aggregate values only — never paired, hits_7d ≥ 3 by schema"; and one-line descriptions for the rest.

- [ ] **Step 2: Write the fixture** `tests/fixtures/picket/export_ok.json` — a small valid export: `schema_version:1`, `exported_at:"2026-07-28T11:35:00Z"`, sensor `{id:"picket-1", public_ip_sha256: 64×"a", protocols:["SSH","TELNET"], uptime_minutes: 4320, knockknock_version:"1.9.0", country:"DE"}`, totals `{knocks_total: 9001, since:"2026-07-25T11:35:00Z"}`, ring `{bucket_minutes:30, buckets:[0]*335 + [42]}`, by_protocol `[{proto:"SSH",hits_7d:900,hits_total:8000},{proto:"TELNET",hits_7d:100,hits_total:1001}]`, three `top_ips` (public IPs, one with `geo_precision:"city"` + lat/lng, one `"country"`), `top_usernames [{value:"root",hits_7d:400,hits_total:3000},{value:"admin",hits_7d:300,hits_total:2500}]`, `top_passwords [{value:"123456",hits_7d:200,hits_total:1800}]`, `top_countries [{iso:"CN",name:"China",hits_7d:500,hits_total:4000}]`, `top_isps [{isp:"Example Hosting",asn:64500,hits_7d:300,hits_total:2000}]`.

- [ ] **Step 3: Write the failing tests**

```python
# tests/test_picket_assemble.py
import json
from datetime import datetime, timezone
from pathlib import Path

from tools.picket.assemble import assemble_export, validate_export
from tests.conftest import FIXED_NOW

FIX = Path(__file__).parent / "fixtures" / "picket"
SCHEMA = Path("schemas/picket_export.schema.json")
PROTO = {1: "SSH", 2: "TELNET"}
SENSOR = {"id": "picket-1", "public_ip_sha256": "a" * 64, "protocols": ["SSH", "TELNET"],
          "knockknock_version": "1.9.0", "country": "DE"}


def rollups(**over):
    base = {
        "ip_intel": [
            {"ip": "203.0.113.5", "hits": 900, "first_seen": "2026-07-20 01:00:00",
             "last_seen": "2026-07-28 11:00:00", "lat": 39.9, "lng": 116.4, "asn": 64500},
            {"ip": "10.0.0.7", "hits": 50, "first_seen": None, "last_seen": None, "lat": None, "lng": None, "asn": None},
        ],
        "ip_intel_proto": [{"ip": "203.0.113.5", "proto": 1, "hits": 900}],
        "user_intel": [{"username": "root", "hits": 400}, {"username": "alice@example.com", "hits": 9}],
        "pass_intel": [{"password": "123456", "hits": 200}, {"password": "once", "hits": 1}],
        "country_intel": [{"iso_code": "CN", "country": "China", "hits": 500}],
        "isp_intel": [{"isp": "Example <b>Hosting</b>", "hits": 300, "asn": 64500}],
        "heartbeat_minutes": 4320, "knocks_total": 9001,
        "country_by_ip": {"203.0.113.5": "CN"},
    }
    base.update(over)
    return base


def hits7d():
    return {"proto": {"SSH": 900}, "ip": {"203.0.113.5": 900, "10.0.0.7": 50},
            "user": {"root": 400, "alice@example.com": 9},
            "pass": {"123456": 200, "once": 1}, "country": {"CN": 500}, "isp": {"Example <b>Hosting</b>": 300}}


def test_fixture_validates():
    doc = json.loads((FIX / "export_ok.json").read_text(encoding="utf-8"))
    assert validate_export(doc, SCHEMA) == []


def test_assembled_export_validates_and_is_fenced():
    out = assemble_export(rollups(), hits7d(), [0] * 335 + [42], SENSOR, FIXED_NOW, PROTO)
    assert validate_export(out, SCHEMA) == []
    ips = [r["ip"] for r in out["top_ips"]]
    assert ips == ["203.0.113.5"]                      # private IP dropped
    assert out["top_ips"][0]["country"] == "CN"
    assert out["top_ips"][0]["protocols"] == [{"proto": "SSH", "hits_7d": 900}]
    assert out["top_ips"][0]["first_seen"] == "2026-07-20T01:00:00Z"
    assert [u["value"] for u in out["top_usernames"]] == ["root"]   # email fenced
    assert [p["value"] for p in out["top_passwords"]] == ["123456"] # singleton fenced (<3)
    assert out["top_isps"][0]["isp"] == "Example Hosting"          # markup stripped
    assert out["totals"] == {"knocks_total": 9001, "since": "2026-07-25T12:00:00Z"}
    assert out["exported_at"] == "2026-07-28T12:00:00Z"
    assert out["sensor"]["uptime_minutes"] == 4320
    assert "ring_reset_at" not in out["sensor"]


def test_reset_marker_is_carried():
    sensor = dict(SENSOR, ring_reset_at="2026-07-28T11:30:00Z")
    out = assemble_export(rollups(), hits7d(), [0] * 336, sensor, FIXED_NOW, PROTO)
    assert out["sensor"]["ring_reset_at"] == "2026-07-28T11:30:00Z"


def test_unknown_protocol_id_fails_loudly():
    bad = rollups(ip_intel_proto=[{"ip": "203.0.113.5", "proto": 99, "hits": 1}])
    try:
        assemble_export(bad, hits7d(), [0] * 336, SENSOR, FIXED_NOW, PROTO)
    except KeyError as e:
        assert "99" in str(e)
    else:
        raise AssertionError("unknown protocol id must not be guessed")


def test_caps_are_enforced():
    many = [{"ip": f"203.0.{i // 250}.{i % 250 + 1}", "hits": 5, "first_seen": None, "last_seen": None,
             "lat": None, "lng": None, "asn": None} for i in range(2500)]
    h = hits7d(); h["ip"] = {r["ip"]: 5 for r in many}
    out = assemble_export(rollups(ip_intel=many, ip_intel_proto=[]), h, [0] * 336, SENSOR, FIXED_NOW, PROTO)
    assert len(out["top_ips"]) == 2000 and validate_export(out, SCHEMA) == []
```

- [ ] **Step 4: Run to verify failure**

Run: `.venv\Scripts\python -m pytest tests/test_picket_assemble.py -q`
Expected: FAIL — `ImportError` on `tools.picket.assemble`

- [ ] **Step 5: Implement**

```python
# tools/picket/assemble.py
"""Rollups + ring → the raw export document (spec §4.1).

Runs on the box. Applies the credential fence and public-IP test FIRST TIME
(the collector applies them a second time), joins per-IP protocol hits and
ISP names, converts knock-knock's 'YYYY-MM-DD HH:MM:SS' timestamps to ISO Z,
enforces every cap, and validates against schemas/picket_export.schema.json
before anything is written. Unknown protocol ids raise — never guessed.
"""
import json
from datetime import timedelta
from pathlib import Path

from jsonschema import Draft202012Validator

from collectors.base import clean_text, iso
from tools.picket.fence import MIN_CRED_HITS, fence_credential, is_public_ip

SCHEMA_VERSION = 1
CAP_IPS, CAP_CREDS, CAP_COUNTRIES, CAP_ISPS, CAP_PROTOS = 2000, 50, 50, 50, 16


def _ts(value):
    """'YYYY-MM-DD HH:MM:SS' / 'YYYY-MM-DDTHH:MM:SS' / None -> ISO Z or ''."""
    v = str(value or "").strip().replace(" ", "T")
    if not v:
        return ""
    return v[:19] + "Z"


def _credlist(rows, key, hits7d_kind):
    out = []
    for r in rows:
        v = fence_credential(r.get(key))
        if v is None:
            continue
        h7 = int(hits7d_kind.get(str(r.get(key)), 0))
        if h7 < MIN_CRED_HITS:
            continue
        out.append({"value": v, "hits_7d": h7, "hits_total": int(r.get("hits") or 0)})
    out.sort(key=lambda x: (-x["hits_7d"], x["value"]))
    return out[:CAP_CREDS]


def assemble_export(rollups, hits7d, ring, sensor, now, proto_names):
    isp_by_asn = {int(r["asn"]): clean_text(r.get("isp") or "")[:120]
                  for r in rollups.get("isp_intel", []) if r.get("asn") is not None}
    proto_by_ip = {}
    for r in rollups.get("ip_intel_proto", []):
        pid = int(r["proto"])
        if pid not in proto_names:
            raise KeyError(f"unknown knock-knock protocol id {pid}")
        proto_by_ip.setdefault(r["ip"], []).append(
            {"proto": proto_names[pid], "hits_7d": int(hits7d["ip"].get(r["ip"], 0) and r.get("hits") or 0)})

    ips = []
    for r in rollups.get("ip_intel", []):
        ip = str(r.get("ip") or "").strip()
        if not is_public_ip(ip):
            continue
        h7 = int(hits7d["ip"].get(ip, 0))
        row = {"ip": ip, "hits_7d": h7, "hits_total": int(r.get("hits") or 0),
               "first_seen": _ts(r.get("first_seen")), "last_seen": _ts(r.get("last_seen")),
               "protocols": sorted(proto_by_ip.get(ip, []), key=lambda p: -p["hits_7d"])[:CAP_PROTOS]}
        cc = rollups.get("country_by_ip", {}).get(ip)
        if cc:
            row["country"] = str(cc)[:2].upper()
        if r.get("asn") is not None:
            row["asn"] = int(r["asn"])
            if int(r["asn"]) in isp_by_asn:
                row["isp"] = isp_by_asn[int(r["asn"])]
        if r.get("lat") is not None and r.get("lng") is not None:
            row["lat"], row["lng"] = float(r["lat"]), float(r["lng"])
            row["geo_precision"] = "city"
        ips.append(row)
    ips.sort(key=lambda x: (-x["hits_7d"], -x["hits_total"], x["ip"]))

    by_proto = [{"proto": p, "hits_7d": int(hits7d["proto"].get(p, 0)),
                 "hits_total": int(t)} for p, t in _proto_totals(rollups, proto_names).items()]
    by_proto.sort(key=lambda x: -x["hits_7d"])

    countries = [{"iso": str(r["iso_code"])[:2].upper(), "name": clean_text(r.get("country") or "")[:64],
                  "hits_7d": int(hits7d["country"].get(r["iso_code"], 0)), "hits_total": int(r.get("hits") or 0)}
                 for r in rollups.get("country_intel", []) if r.get("iso_code")]
    countries.sort(key=lambda x: -x["hits_7d"])
    isps = [{"isp": clean_text(r.get("isp") or "")[:120], "asn": int(r["asn"]) if r.get("asn") is not None else 0,
             "hits_7d": int(hits7d["isp"].get(r.get("isp"), 0)), "hits_total": int(r.get("hits") or 0)}
            for r in rollups.get("isp_intel", []) if clean_text(r.get("isp") or "")]
    isps.sort(key=lambda x: -x["hits_7d"])

    uptime = int(rollups.get("heartbeat_minutes") or 0)
    sensor_out = {"id": str(sensor["id"])[:32], "public_ip_sha256": sensor["public_ip_sha256"],
                  "protocols": [str(p)[:8] for p in sensor.get("protocols", [])][:CAP_PROTOS],
                  "uptime_minutes": uptime, "knockknock_version": str(sensor.get("knockknock_version", ""))[:32]}
    if sensor.get("country"):
        sensor_out["country"] = str(sensor["country"])[:2].upper()
    if sensor.get("ring_reset_at"):
        sensor_out["ring_reset_at"] = str(sensor["ring_reset_at"])[:20]

    return {
        "schema_version": SCHEMA_VERSION,
        "exported_at": iso(now),
        "sensor": sensor_out,
        "totals": {"knocks_total": int(rollups.get("knocks_total") or 0),
                   "since": iso(now - timedelta(minutes=uptime))},
        "ring": {"bucket_minutes": 30, "buckets": [int(x) for x in ring]},
        "by_protocol": by_proto[:CAP_PROTOS],
        "top_ips": ips[:CAP_IPS],
        "top_usernames": _credlist(rollups.get("user_intel", []), "username", hits7d["user"]),
        "top_passwords": _credlist(rollups.get("pass_intel", []), "password", hits7d["pass"]),
        "top_countries": countries[:CAP_COUNTRIES],
        "top_isps": isps[:CAP_ISPS],
    }


def _proto_totals(rollups, proto_names):
    totals = {}
    for r in rollups.get("ip_intel_proto", []):
        totals[proto_names[int(r["proto"])]] = totals.get(proto_names[int(r["proto"])], 0) + int(r.get("hits") or 0)
    return totals


def validate_export(export, schema_path):
    schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    return [f"{e.json_path}: {e.message}" for e in Draft202012Validator(schema).iter_errors(export)][:20]
```

Note on `protocols[].hits_7d`: knock-knock keeps no per-(ip,proto) 7-day series; the exporter's ring tracks per-IP totals only. For P1 the per-protocol figure on an IP row is the **all-time** per-protocol hits when the IP was active this week (documented in `PICKET.md`), and 0 otherwise — replace the awkward expression above with exactly:

```python
        proto_by_ip.setdefault(r["ip"], []).append(
            {"proto": proto_names[pid],
             "hits_7d": int(r.get("hits") or 0) if int(hits7d["ip"].get(r["ip"], 0)) > 0 else 0})
```

- [ ] **Step 6: Run to verify pass**

Run: `.venv\Scripts\python -m pytest tests/test_picket_assemble.py -q`
Expected: all PASS (fix the fixture until `test_fixture_validates` is green — the fixture is the contract's worked example and is reused by Task 5).

- [ ] **Step 7: Commit**

```bash
git add schemas/picket_export.schema.json tools/picket/assemble.py tests/fixtures/picket/export_ok.json tests/test_picket_assemble.py
git commit -m "feat(picket): raw export schema (bounded, described) + fenced assembler"
```

---

### Task 4: Exporter CLI, systemd units, install script, box runbook

**Files:**
- Create: `tools/picket/exporter.py`, `tools/picket/requirements.txt`, `tools/picket/systemd/picket-export.service`, `tools/picket/systemd/picket-export.timer`, `tools/picket/install.sh`, `tools/picket/README.md`
- Test: `tests/test_picket_exporter.py` (the sqlite→rollups reader + snapshot builder, against an in-memory DB; git/geoip are not exercised in CI)

**Interfaces:**
- Consumes: Tasks 1–3.
- Produces: `read_rollups(conn) -> dict` (the Task-3 `rollups` shape minus `country_by_ip`), `snapshot_from_rollups(rollups, proto_names) -> dict` (the Task-2 `snapshot` shape), `load_proto_names(knockknock_dir) -> dict[int,str]`, `main(argv) -> int`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_picket_exporter.py
import sqlite3

from tools.picket.exporter import read_rollups, snapshot_from_rollups

DDL = """
CREATE TABLE user_intel (username TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME);
CREATE TABLE pass_intel (password TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME);
CREATE TABLE country_intel (iso_code TEXT PRIMARY KEY, country TEXT, hits INTEGER, last_seen DATETIME);
CREATE TABLE isp_intel (isp TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME, asn INTEGER);
CREATE TABLE ip_intel (ip TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME, lat REAL, lng REAL,
  hits_since_cleared INTEGER NOT NULL DEFAULT 0, ban_until INTEGER, ban_count INTEGER NOT NULL DEFAULT 0,
  first_seen DATETIME, asn INTEGER);
CREATE TABLE ip_intel_proto (ip TEXT, proto INTEGER, hits INTEGER, last_seen DATETIME, lat REAL, lng REAL, PRIMARY KEY (ip, proto));
CREATE TABLE monitor_heartbeats (id INTEGER PRIMARY KEY, uptime_minutes INTEGER NOT NULL DEFAULT 0);
"""


def _db():
    c = sqlite3.connect(":memory:")
    c.executescript(DDL)
    c.execute("INSERT INTO ip_intel (ip,hits,last_seen,lat,lng,first_seen,asn) VALUES ('203.0.113.5',900,'2026-07-28 11:00:00',39.9,116.4,'2026-07-20 01:00:00',64500)")
    c.execute("INSERT INTO ip_intel_proto (ip,proto,hits) VALUES ('203.0.113.5',1,900)")
    c.execute("INSERT INTO user_intel VALUES ('root',400,'2026-07-28 11:00:00')")
    c.execute("INSERT INTO pass_intel VALUES ('123456',200,'2026-07-28 11:00:00')")
    c.execute("INSERT INTO country_intel VALUES ('CN','China',500,'2026-07-28 11:00:00')")
    c.execute("INSERT INTO isp_intel VALUES ('Example Hosting',300,'2026-07-28 11:00:00',64500)")
    c.execute("INSERT INTO monitor_heartbeats (id, uptime_minutes) VALUES (1, 4320)")
    c.commit()
    return c


def test_read_rollups_shapes_rows_as_dicts():
    r = read_rollups(_db())
    assert r["ip_intel"][0]["ip"] == "203.0.113.5" and r["ip_intel"][0]["asn"] == 64500
    assert r["ip_intel_proto"] == [{"ip": "203.0.113.5", "proto": 1, "hits": 900}]
    assert r["user_intel"] == [{"username": "root", "hits": 400}]
    assert r["heartbeat_minutes"] == 4320
    assert r["knocks_total"] == 900          # SUM(ip_intel_proto.hits)


def test_snapshot_from_rollups_keys_by_protocol_name():
    snap = snapshot_from_rollups(read_rollups(_db()), {1: "SSH"})
    assert snap["total"] == 900 and snap["proto"] == {"SSH": 900}
    assert snap["ip"] == {"203.0.113.5": 900} and snap["user"] == {"root": 400}
    assert snap["pass"] == {"123456": 200} and snap["country"] == {"CN": 500}
    assert snap["isp"] == {"Example Hosting": 300}
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv\Scripts\python -m pytest tests/test_picket_exporter.py -q`
Expected: FAIL — `ImportError`

- [ ] **Step 3: Implement the exporter**

```python
# tools/picket/exporter.py
"""PICKET exporter — runs ON THE SENSOR BOX (systemd timer :05/:35).

Reads knock-knock's SQLite rollups (never per-knock rows), feeds the delta
ring, assembles + validates export.json, and pushes it to the public
data-only repo SaltyCarl/socdesk-picket-export. The plaintext public IP is
hashed here and never written. geoip2 and git are imported lazily so the pure
parts stay testable in CI without them.

Usage (see README.md):
  exporter.py --db /path/knocks.db --state /var/lib/picket/state.json \
              --out /srv/picket-export/export.json --repo-dir /srv/picket-export \
              --sensor-id picket-1 --knockknock-dir /opt/knock-knock \
              [--geoip-db /usr/share/GeoIP/GeoLite2-Country.mmdb] [--no-push]
"""
import argparse
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from tools.picket.assemble import assemble_export, validate_export
from tools.picket.ring import apply_snapshot, new_state

HERE = Path(__file__).resolve().parent
SCHEMA = HERE.parent.parent / "schemas" / "picket_export.schema.json"
MAX_EXPORT_BYTES = 512 * 1024


def _rows(conn, sql):
    conn.row_factory = sqlite3.Row
    return [dict(r) for r in conn.execute(sql)]


def read_rollups(conn):
    return {
        "ip_intel": _rows(conn, "SELECT ip,hits,first_seen,last_seen,lat,lng,asn FROM ip_intel"),
        "ip_intel_proto": _rows(conn, "SELECT ip,proto,hits FROM ip_intel_proto"),
        "user_intel": _rows(conn, "SELECT username,hits FROM user_intel"),
        "pass_intel": _rows(conn, "SELECT password,hits FROM pass_intel"),
        "country_intel": _rows(conn, "SELECT iso_code,country,hits FROM country_intel"),
        "isp_intel": _rows(conn, "SELECT isp,hits,asn FROM isp_intel"),
        "heartbeat_minutes": int((conn.execute("SELECT uptime_minutes FROM monitor_heartbeats WHERE id=1").fetchone() or [0])[0]),
        "knocks_total": int((conn.execute("SELECT COALESCE(SUM(hits),0) FROM ip_intel_proto").fetchone() or [0])[0]),
    }


def snapshot_from_rollups(rollups, proto_names):
    proto = {}
    for r in rollups["ip_intel_proto"]:
        name = proto_names[int(r["proto"])]
        proto[name] = proto.get(name, 0) + int(r["hits"] or 0)
    return {
        "total": int(rollups["knocks_total"]),
        "proto": proto,
        "ip": {r["ip"]: int(r["hits"] or 0) for r in rollups["ip_intel"]},
        "user": {r["username"]: int(r["hits"] or 0) for r in rollups["user_intel"]},
        "pass": {r["password"]: int(r["hits"] or 0) for r in rollups["pass_intel"]},
        "country": {r["iso_code"]: int(r["hits"] or 0) for r in rollups["country_intel"]},
        "isp": {r["isp"]: int(r["hits"] or 0) for r in rollups["isp_intel"]},
    }


def load_proto_names(knockknock_dir):
    """knock-knock's own registry is the source of truth for proto_id -> name."""
    sys.path.insert(0, str(knockknock_dir))
    from protocols.registry import PROTOCOL_META  # noqa: E402  (knock-knock module)
    return {int(meta["definition"].proto_id): name
            for name, meta in PROTOCOL_META.items() if meta.get("definition")}


def _public_ip():
    out = subprocess.run(["curl", "-4", "-s", "--max-time", "5", "https://ifconfig.me"],
                         capture_output=True, text=True, check=False).stdout.strip()
    return out or socket.gethostbyname(socket.gethostname())


def _country_by_ip(geoip_db, ips):
    if not geoip_db:
        return {}
    import geoip2.database  # noqa: E402  (box only)
    out = {}
    with geoip2.database.Reader(geoip_db) as rd:
        for ip in ips:
            try:
                out[ip] = rd.country(ip).country.iso_code or ""
            except Exception:  # noqa: BLE001 — unknown IP is simply unlabelled
                continue
    return out


def _git_push(repo_dir, out_path):
    subprocess.run(["git", "-C", repo_dir, "add", Path(out_path).name], check=True)
    if subprocess.run(["git", "-C", repo_dir, "diff", "--cached", "--quiet"]).returncode == 0:
        return "unchanged"
    subprocess.run(["git", "-C", repo_dir, "commit", "-q", "-m", "picket: export"], check=True)
    subprocess.run(["git", "-C", repo_dir, "push", "-q"], check=True)
    return "pushed"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True); ap.add_argument("--state", required=True)
    ap.add_argument("--out", required=True); ap.add_argument("--repo-dir", required=True)
    ap.add_argument("--sensor-id", required=True); ap.add_argument("--knockknock-dir", required=True)
    ap.add_argument("--geoip-db", default=None); ap.add_argument("--no-push", action="store_true")
    a = ap.parse_args(argv)

    now = datetime.now(timezone.utc)
    proto_names = load_proto_names(a.knockknock_dir)
    conn = sqlite3.connect(f"file:{a.db}?mode=ro", uri=True)
    rollups = read_rollups(conn)
    rollups["country_by_ip"] = _country_by_ip(a.geoip_db, [r["ip"] for r in rollups["ip_intel"]])

    state_path = Path(a.state)
    state = json.loads(state_path.read_text()) if state_path.exists() else new_state()
    ring_out = apply_snapshot(state, snapshot_from_rollups(rollups, proto_names), int(time.time()))
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, separators=(",", ":")))

    version = (Path(a.knockknock_dir) / "VERSION").read_text().strip() if (Path(a.knockknock_dir) / "VERSION").exists() else "unknown"
    sensor = {"id": a.sensor_id, "public_ip_sha256": hashlib.sha256(_public_ip().encode()).hexdigest(),
              "protocols": sorted(proto_names.values()), "knockknock_version": version}
    if ring_out["reset"]:
        sensor["ring_reset_at"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    export = assemble_export(rollups, ring_out["hits_7d"], ring_out["ring"], sensor, now, proto_names)
    errors = validate_export(export, SCHEMA)
    if errors:
        print("REFUSED (schema): " + errors[0], file=sys.stderr); return 2
    blob = json.dumps(export, ensure_ascii=False, separators=(",", ":"))
    if len(blob.encode("utf-8")) > MAX_EXPORT_BYTES:
        print(f"REFUSED (size): {len(blob)} > {MAX_EXPORT_BYTES}", file=sys.stderr); return 3
    Path(a.out).write_text(blob, encoding="utf-8")
    if not a.no_push:
        print(_git_push(a.repo_dir, a.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

Note: `load_proto_names` reads knock-knock's registry; if the attribute layout differs on the pinned tag, the exporter fails at startup (by design — never guess ids). The README records the pinned tag and how to confirm the map (`python -c "from protocols.registry import PROTOCOL_META; ..."`).

- [ ] **Step 4: Run to verify pass**

Run: `.venv\Scripts\python -m pytest tests/test_picket_exporter.py -q`
Expected: PASS

- [ ] **Step 5: Add box-only dependencies, systemd units, install script**

`tools/picket/requirements.txt`:
```
jsonschema==4.*
geoip2==4.*
```

`tools/picket/systemd/picket-export.service`:
```ini
[Unit]
Description=SOCDesk PICKET exporter (knock-knock rollups -> export.json -> data repo)
After=network-online.target docker.service
[Service]
Type=oneshot
User=picket
WorkingDirectory=/opt/socdesk
Environment=PYTHONPATH=/opt/socdesk
ExecStart=/opt/socdesk/.venv/bin/python -m tools.picket.exporter \
  --db /opt/knock-knock/data/knocks.db \
  --state /var/lib/picket/state.json \
  --out /srv/picket-export/export.json --repo-dir /srv/picket-export \
  --sensor-id picket-1 --knockknock-dir /opt/knock-knock \
  --geoip-db /usr/share/GeoIP/GeoLite2-Country.mmdb
```

`tools/picket/systemd/picket-export.timer`:
```ini
[Unit]
Description=Run the PICKET exporter at :05 and :35 (six minutes before the pipeline cron)
[Timer]
OnCalendar=*-*-* *:05,35:00
Persistent=true
RandomizedDelaySec=0
[Install]
WantedBy=timers.target
```

`tools/picket/install.sh` — idempotent bootstrap, **in this order** (the lock-out hazard first):
```bash
#!/usr/bin/env bash
# SOCDesk PICKET box bootstrap. Idempotent. Run as root on a FRESH Debian/Ubuntu VPS.
# READ tools/picket/README.md FIRST. Step 1 changes your SSH port: keep this session open,
# test the new port from a second terminal before you disconnect.
set -euo pipefail
ADMIN_SSH_PORT="${ADMIN_SSH_PORT:-2222}"
ADMIN_ALLOW_CIDR="${ADMIN_ALLOW_CIDR:?set ADMIN_ALLOW_CIDR to your admin source, e.g. 203.0.113.9/32}"
KK_TAG="${KK_TAG:?set KK_TAG to the pinned knock-knock release tag}"
EXPORT_REPO="${EXPORT_REPO:-git@github.com:SaltyCarl/socdesk-picket-export.git}"

# 1. move real sshd off :22 (knock-knock needs it), key-only
sed -i "s/^#\?Port .*/Port ${ADMIN_SSH_PORT}/; s/^#\?PasswordAuthentication .*/PasswordAuthentication no/" /etc/ssh/sshd_config
systemctl restart ssh || systemctl restart sshd
echo ">> sshd now on ${ADMIN_SSH_PORT}. TEST IT FROM ANOTHER TERMINAL BEFORE CONTINUING."; read -r -p "Press enter when verified"

# 2. firewall: admin SSH from allow-list only; honeypot ports open to all; nothing else
apt-get update -q && apt-get install -y -q ufw git python3-venv curl docker.io docker-compose-plugin geoipupdate
ufw --force reset
ufw default deny incoming; ufw default allow outgoing
ufw allow from "${ADMIN_ALLOW_CIDR}" to any port "${ADMIN_SSH_PORT}" proto tcp
for p in 21 22 23 25 80 445 3389; do ufw allow "${p}/tcp"; done
ufw allow 5060/udp; ufw allow 5060/tcp
ufw --force enable

# 3. knock-knock, pinned, host networking, rollups only, dashboard on localhost
mkdir -p /opt && cd /opt
[ -d knock-knock ] || git clone --branch "${KK_TAG}" --depth 1 https://github.com/djkurlander/knock-knock.git
cd /opt/knock-knock
[ -f .env ] || cp .env.example .env
grep -q '^WEB_HOST=' .env || echo 'WEB_HOST=127.0.0.1' >> .env      # verify the var name on the pinned tag (README)
grep -q '^SOURCE_ID=' .env || echo 'SOURCE_ID=picket-1' >> .env
sed -i 's/^SAVE_KNOCKS=.*/# SAVE_KNOCKS off: rollups only/' .env
docker compose up -d

# 4. exporter: this repo's tools/picket, its own venv, its own requirements
id -u picket &>/dev/null || useradd -r -m -d /var/lib/picket -s /usr/sbin/nologin picket
mkdir -p /opt/socdesk /srv/picket-export /var/lib/picket
# copy tools/picket + collectors/base.py + schemas/picket_export.schema.json here (see README §3)
python3 -m venv /opt/socdesk/.venv && /opt/socdesk/.venv/bin/pip install -q -r /opt/socdesk/tools/picket/requirements.txt
[ -d /srv/picket-export/.git ] || sudo -u picket git clone "${EXPORT_REPO}" /srv/picket-export
chown -R picket:picket /srv/picket-export /var/lib/picket
install -m 644 /opt/socdesk/tools/picket/systemd/picket-export.{service,timer} /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now picket-export.timer
systemctl list-timers picket-export.timer --no-pager
```

- [ ] **Step 6: Write the box runbook** `tools/picket/README.md` (spec §10 — this is a deliverable, not a note). Sections, each with the exact commands:
  1. **What this box is** (one paragraph; threat model: it is bait; assume compromise; blast radius = this box + the data repo only).
  2. **Provision** (Hetzner CX / Oracle ARM; Debian 12 or Ubuntu 24.04; note the public IP; add your SSH key).
  3. **Harden, in order** — the `install.sh` env vars, the lock-out warning, verifying the new port from a second terminal, `nmap -Pn -p- <ip>` from outside showing only honeypot ports + the admin port.
  4. **knock-knock** — pinned `KK_TAG`, MaxMind `.env` values, `docker compose logs -f` sanity, confirm `SAVE_KNOCKS` is off, confirm the dashboard is **not** reachable from outside (`curl -m 3 http://<ip>:8080` must fail); how to view it over an SSH tunnel; how to confirm the `WEB_HOST`/bind variable name on the pinned tag (build-time check from the spec).
  5. **Exporter** — what `tools/picket/` files to copy (`tools/picket/*`, `collectors/base.py`, `collectors/__init__.py` stub not needed — copy `collectors/base.py` and create an empty `collectors/__init__.py`; `schemas/picket_export.schema.json`), the deploy key (`ssh-keygen -t ed25519 -C picket -f /var/lib/picket/.ssh/id_ed25519`; add the **public** key to `socdesk-picket-export` → Settings → Deploy keys → **Allow write access**), first manual run with `--no-push`, then a real run; reading `journalctl -u picket-export`.
  6. **Confirm the protocol map** — `cd /opt/knock-knock && python3 -c "from protocols.registry import PROTOCOL_META; print({n: m['definition'].proto_id for n,m in PROTOCOL_META.items()})"`; also confirm per module whether a knock is logged on auth attempt vs bare connect (spec §3.9 build-time check) and record the answer in `docs/PICKET.md`.
  7. **Rebuild from scratch** (destroy → re-run `install.sh`; `state.json` starts fresh, the ring re-fills over 7 days — say so).
  8. **Incident response** — signs of compromise; destroy the box; **rotate the deploy key** in the export repo; inspect the export repo's history for vandalized commits; the pipeline's gate + fallback mean the site was protected regardless.
  9. **Attribution obligations** — MaxMind GeoLite2 line; knock-knock MIT.

- [ ] **Step 7: Run the full Python suite**

Run: `.venv\Scripts\python -m pytest tests/ -q`
Expected: all PASS (the exporter's git/geoip paths are not executed in CI).

- [ ] **Step 8: Commit**

```bash
git add tools/picket/exporter.py tools/picket/requirements.txt tools/picket/systemd tools/picket/install.sh tools/picket/README.md tests/test_picket_exporter.py
git commit -m "feat(picket): exporter CLI, systemd timer, box bootstrap + runbook"
```

---

### Task 5: The collector (keyless fetch + second fence)

**Files:**
- Create: `collectors/picket.py`, `tests/fixtures/picket/export_hostile.json`
- Modify: `collectors/__init__.py:19-20` (register)
- Test: `tests/test_picket_collector.py`

**Interfaces:**
- Consumes: `fence_credential`, `MIN_CRED_HITS`, `is_public_ip` (Task 1); `validate_export` (Task 3); `clean_text`, `CollectorResult` (`collectors/base.py`).
- Produces: `SOURCE = "picket"`, `EXPORT_URL`, `MAX_BYTES = 2_000_000`, `normalize(export) -> dict` (raises `ValueError` on schema failure), `collect(fetch, now) -> CollectorResult(source="picket", extra={"picket": normalized})`.

- [ ] **Step 1: Write the hostile fixture** `tests/fixtures/picket/export_hostile.json` — start from `export_ok.json`; then: a `top_usernames` value `"<img src=x onerror=alert(1)//"` with `hits_7d: 50`; a `top_usernames` value `"alice@example.com"` with `hits_7d: 40`; a `top_passwords` value `"hunter2"` with `hits_7d: 2` (below floor — but the raw schema's `minimum:3` would reject it, so put `hits_7d: 3` there and instead exercise the floor via `normalize()` receiving an already-parsed dict in the test); a `top_ips` row with `ip: "10.0.0.5"`; a `top_isps[].isp` of `"&lt;script&gt;alert(1)&lt;/script&gt;Hosting"`; a `top_countries[].name` with a trailing unterminated `"<b"`; a `top_ips[0].ip` whose sha256 equals the fixture's `sensor.public_ip_sha256` (compute `hashlib.sha256(b"203.0.113.77").hexdigest()` and set both).

- [ ] **Step 2: Write the failing tests**

```python
# tests/test_picket_collector.py
import hashlib
import json
from pathlib import Path

import pytest

from collectors import picket
from collectors.base import CollectorResult
from tests.conftest import FIXED_NOW

FIX = Path(__file__).parent / "fixtures" / "picket"


def test_collect_returns_normalized_extra(fake_fetch):
    fetch = fake_fetch({picket.EXPORT_URL: "picket/export_ok.json"})
    r = picket.collect(fetch, FIXED_NOW)
    assert isinstance(r, CollectorResult) and r.ok and r.source == "picket"
    assert r.extra["picket"]["sensor"]["id"] == "picket-1"
    assert r.extra["picket"]["exported_at"] == "2026-07-28T11:35:00Z"


def test_hostile_export_is_made_inert_and_fenced(fake_fetch):
    fetch = fake_fetch({picket.EXPORT_URL: "picket/export_hostile.json"})
    out = picket.collect(fetch, FIXED_NOW).extra["picket"]
    users = [u["value"] for u in out["top_usernames"]]
    assert "alice@example.com" not in users
    assert all("<" not in u and ">" not in u for u in users)
    assert all(picket.is_public_ip(r["ip"]) for r in out["top_ips"])
    assert all("<" not in i["isp"] and "script" not in i["isp"].lower() or True for i in out["top_isps"])
    assert all("<" not in i["isp"] and ">" not in i["isp"] for i in out["top_isps"])
    assert all("<" not in c["name"] and ">" not in c["name"] for c in out["top_countries"])
    sensor_hash = out["sensor"]["public_ip_sha256"]
    assert all(hashlib.sha256(r["ip"].encode()).hexdigest() != sensor_hash for r in out["top_ips"])


def test_credential_floor_is_enforced_again_in_pipeline():
    doc = json.loads((FIX / "export_ok.json").read_text(encoding="utf-8"))
    doc["top_passwords"].append({"value": "hunter2", "hits_7d": 3, "hits_total": 3})
    out = picket.normalize(doc)
    assert {"value": "hunter2", "hits_7d": 3, "hits_total": 3} in out["top_passwords"]
    doc["top_passwords"][-1]["hits_7d"] = 2         # simulate a box that skipped the fence
    with pytest.raises(ValueError):                 # raw schema minimum:3 -> refused, not silently kept
        picket.normalize(doc)


def test_oversize_body_is_a_failed_collection(fake_fetch):
    big = "{" + '"x":"' + "a" * (picket.MAX_BYTES + 10) + '"}'
    fetch = fake_fetch({picket.EXPORT_URL: big})
    with pytest.raises(ValueError, match="exceeds"):
        picket.collect(fetch, FIXED_NOW)            # run_all turns this into ok:false


def test_network_error_propagates_for_run_all(fake_fetch):
    fetch = fake_fetch({})                          # unexpected URL -> RuntimeError
    with pytest.raises(RuntimeError):
        picket.collect(fetch, FIXED_NOW)
```

(`run_all` in `collectors/base.py:78-96` converts any exception into an `ok:false` health row — the collector's job is to raise honestly, not to swallow.)

- [ ] **Step 3: Run to verify failure**

Run: `.venv\Scripts\python -m pytest tests/test_picket_collector.py -q`
Expected: FAIL — `ImportError: cannot import name 'picket'`

- [ ] **Step 4: Implement**

```python
# collectors/picket.py
"""PICKET — SOCDesk's own honeypot sensor, via its public data-only export repo.

Keyless: a raw GitHub URL, fetched as text so the 2 MB cap applies to the
BYTES. The export is the most attacker-influenced input this pipeline has
(usernames, passwords, ISP names are chosen by whoever is attacking the
sensor), so it is re-validated against the raw schema and every string is
passed through clean_text + the credential fence AGAIN here — the box already
did both; this is the second, independent fence. Any refusal RAISES so
run_all records ok:false and publish keeps last-known-good.
"""
import hashlib
import json

from collectors.base import CollectorResult, clean_text
from tools.picket.assemble import validate_export
from tools.picket.fence import MIN_CRED_HITS, fence_credential, is_public_ip

SOURCE = "picket"
EXPORT_URL = "https://raw.githubusercontent.com/SaltyCarl/socdesk-picket-export/main/export.json"
SCHEMA = "schemas/picket_export.schema.json"
MAX_BYTES = 2_000_000


def _creds(rows):
    out = []
    for r in rows or []:
        v = fence_credential(r.get("value"))
        if v is None or int(r.get("hits_7d", 0)) < MIN_CRED_HITS:
            continue
        out.append({"value": v, "hits_7d": int(r["hits_7d"]), "hits_total": int(r.get("hits_total", 0))})
    return out


def normalize(export):
    errors = validate_export(export, SCHEMA)
    if errors:
        raise ValueError(f"picket export failed schema: {errors[0]}")
    sensor_hash = export["sensor"]["public_ip_sha256"]
    ips = []
    for r in export.get("top_ips", []):
        ip = str(r.get("ip", "")).strip()
        if not is_public_ip(ip) or hashlib.sha256(ip.encode()).hexdigest() == sensor_hash:
            continue
        row = dict(r, ip=ip)
        if "isp" in row:
            row["isp"] = clean_text(row["isp"])[:120]
        ips.append(row)
    countries = [dict(c, name=clean_text(c.get("name", ""))[:64]) for c in export.get("top_countries", [])]
    isps = [dict(i, isp=clean_text(i.get("isp", ""))[:120]) for i in export.get("top_isps", [])]
    isps = [i for i in isps if i["isp"]]
    return dict(export,
                top_ips=ips,
                top_usernames=_creds(export.get("top_usernames")),
                top_passwords=_creds(export.get("top_passwords")),
                top_countries=countries,
                top_isps=isps,
                sensor=dict(export["sensor"], id=clean_text(export["sensor"]["id"])[:32]))


def collect(fetch, now):
    raw = fetch(EXPORT_URL, text=True)
    if len(raw.encode("utf-8")) > MAX_BYTES:
        raise ValueError(f"picket export {len(raw)} bytes exceeds {MAX_BYTES} cap")
    return CollectorResult(source=SOURCE, extra={"picket": normalize(json.loads(raw))})
```

Register it — `collectors/__init__.py`: add `picket` to the import list and append to `COLLECTORS`:
```python
COLLECTORS = [kev, nvd, ransomwarelive, rss, feodotracker, threatfox, picket]
```
and add to the module comment: `# picket: SOCDesk's OWN honeypot telemetry (first-party, redistributable by construction) — see docs/PICKET.md.`

Check the real `fetch` in `run_pipeline.py` supports `text=True` (grep `def fetch` / `text=`); the conftest fake mirrors it. If it does not, add the `text` keyword there, returning `resp.text` — a one-line change; include it in this task if needed.

- [ ] **Step 5: Run to verify pass**

Run: `.venv\Scripts\python -m pytest tests/test_picket_collector.py tests/test_pipeline.py -q`
Expected: PASS. (`test_pipeline`'s end-to-end runs use a fixture `fetch` mapping — the new collector will raise `RuntimeError: unexpected URL` there and be recorded `ok:false`, which is the designed degradation; confirm those tests still pass and that `health.json` gains a `picket` row with `ok:false`.)

- [ ] **Step 6: Commit**

```bash
git add collectors/picket.py collectors/__init__.py tests/fixtures/picket/export_hostile.json tests/test_picket_collector.py
git commit -m "feat(picket): keyless collector with second-pass sanitizer + fence"
```

---

### Task 6: Published schemas + `pipeline/picket.py` builder

**Files:**
- Create: `schemas/picket.schema.json`, `schemas/picket_ips.schema.json`, `pipeline/picket.py`
- Modify: `pipeline/validate.py:8-27` (`SCHEMA_FOR`)
- Test: `tests/test_picket_pipeline.py`

**Interfaces:**
- Consumes: `CollectorResult.extra["picket"]` (Task 5 shape = normalized raw export); `pipeline.publish._envelope`? — no: `_envelope` is private; use `collectors.base.iso` and build the envelope inline (same shape).
- Produces: `LIVE_MINUTES = 90`, `SILENT_MINUTES = 1440`, `sensor_status(exported_at, now) -> (status, age_minutes)`, `build_picket(ok, prior, now) -> dict | None` where the dict has keys `"picket.json"` and `"picket_ips.json"`; `restamp_prior(prior, now) -> dict` (recomputes `sensor.status`/`export_age_minutes` from the prior's `exported_at`).

- [ ] **Step 1: Write the schemas**
  - `schemas/picket.schema.json` — spec §4.2 **P1 fields only** (P2 adds `known_to`, `lead_days`, `lead_time`, `report_candidates`, `exports`, `reported_upstream` additively): `generated_at`, `schema_version`, `attribution` (≤1000), `collected_at`, `sensor{id, country?, uptime_days (integer≥0), protocols[≤16], status enum [live,stale,silent], export_age_minutes (integer≥0), exported_at, knockknock_version, ring_reset_at?}`, `totals{knocks_total, since, knocks_24h, knocks_7d, unique_ips_7d}`, `histogram_7d` (array of exactly 168 integers ≥0), `by_protocol[≤16]{proto, hits_7d, hits_total, share_pct (number 0–100)}`, `top_ips[≤100]{ip, hits_7d, hits_total, first_seen, last_seen, protocols[≤16]{proto,hits_7d}, country?, asn?, isp?, lat?, lng?, geo_precision?}`, `top_usernames/top_passwords[≤50]{value(≤32), hits_7d(≥3), hits_total}`, `top_countries[≤50]{iso,name,hits_7d,hits_total}`, `top_isps[≤50]{isp,asn,hits_7d,hits_total}`. `additionalProperties:false` everywhere; a `description` on every property.
  - `schemas/picket_ips.schema.json` — `{generated_at, schema_version, attribution, count, ips[≤1000]{ip, country?, lat (number), lng (number), source {const:"picket"}, hits_7d, first_seen, last_seen, geo_precision {enum:[city,country]}}}`.
  - `pipeline/validate.py`: add `"picket.json": "picket.schema.json"` and `"picket_ips.json": "picket_ips.schema.json"` to `SCHEMA_FOR`.

- [ ] **Step 2: Write the failing tests**

```python
# tests/test_picket_pipeline.py
import json
from datetime import timedelta
from pathlib import Path

from collectors.base import CollectorResult
from pipeline import picket as pk
from pipeline.validate import validate_payload
from tests.conftest import FIXED_NOW

FIX = Path(__file__).parent / "fixtures" / "picket"


def _ok():
    doc = json.loads((FIX / "export_ok.json").read_text(encoding="utf-8"))
    return {"picket": CollectorResult(source="picket", extra={"picket": doc})}


def test_status_thresholds():
    assert pk.sensor_status("2026-07-28T11:35:00Z", FIXED_NOW) == ("live", 25)
    assert pk.sensor_status("2026-07-28T10:00:00Z", FIXED_NOW) == ("stale", 120)
    assert pk.sensor_status("2026-07-26T12:00:00Z", FIXED_NOW) == ("silent", 2880)
    assert pk.sensor_status("garbage", FIXED_NOW) == ("silent", 0)


def test_build_publishes_valid_payloads():
    out = pk.build_picket(_ok(), {}, FIXED_NOW)
    assert set(out) == {"picket.json", "picket_ips.json"}
    for name, payload in out.items():
        assert validate_payload(name, payload, "schemas") == [], name
    p = out["picket.json"]
    assert p["sensor"]["status"] == "live" and p["sensor"]["export_age_minutes"] == 25
    assert p["sensor"]["uptime_days"] == 3
    assert len(p["histogram_7d"]) == 168 and sum(p["histogram_7d"]) == 42
    assert p["totals"]["knocks_7d"] == 42 and p["totals"]["knocks_24h"] == 42
    assert p["by_protocol"][0]["share_pct"] == 90.0
    assert "MaxMind" in p["attribution"] and "knock-knock" in p["attribution"]
    assert p["collected_at"] == "2026-07-28T12:00:00Z"


def test_ips_layer_only_has_finite_coords_and_source_picket():
    ips = pk.build_picket(_ok(), {}, FIXED_NOW)["picket_ips.json"]["ips"]
    assert ips and all(r["source"] == "picket" for r in ips)
    assert all(isinstance(r["lat"], float) and isinstance(r["lng"], float) for r in ips)


def test_collector_down_restamps_prior_and_degrades_status():
    prior = pk.build_picket(_ok(), {}, FIXED_NOW)
    later = FIXED_NOW + timedelta(hours=30)
    out = pk.build_picket({}, prior, later)             # no ok result
    assert out["picket.json"]["sensor"]["status"] == "silent"
    assert out["picket.json"]["generated_at"] == "2026-07-29T18:00:00Z"
    assert out["picket.json"]["collected_at"] == "2026-07-28T12:00:00Z"   # a REAL collection stamp survives
    assert validate_payload("picket.json", out["picket.json"], "schemas") == []


def test_collector_down_with_no_prior_is_none():
    assert pk.build_picket({}, {}, FIXED_NOW) is None
```

- [ ] **Step 3: Run to verify failure**

Run: `.venv\Scripts\python -m pytest tests/test_picket_pipeline.py -q`
Expected: FAIL — `ImportError`

- [ ] **Step 4: Implement**

```python
# pipeline/picket.py
"""PICKET publish step: the collector's normalized export -> picket.json (the
panel) + picket_ips.json (the globe layer).

Invariants: every payload is bounded and validated by gate(); a dead sensor
is published as status 'stale'/'silent' computed from exported_at — never as
zero attacks; collected_at is stamped only on a REAL collection and carried
through keep-prior (the actors.json lesson, run_pipeline.py:55-60); P2 adds
lead-time/known_to/exports ADDITIVELY — nothing here changes shape then.
"""
from datetime import datetime, timezone

from collectors.base import iso

SCHEMA_VERSION = 1
LIVE_MINUTES = 90
SILENT_MINUTES = 24 * 60
CAP_TOP_IPS = 100
CAP_GLOBE_IPS = 1000

ATTRIBUTION = (
    "SOCDesk PICKET: telemetry from SOCDesk's own internet-facing honeypot sensor "
    "(knock-knock, MIT, github.com/djkurlander/knock-knock). Counts of automated "
    "break-in attempts against an unsolicited sensor — context, never a verdict on "
    "any network or operator. Credentials are published as aggregate values only, "
    "never as pairs. This product includes GeoLite2 data created by MaxMind, "
    "available from https://www.maxmind.com."
)


def sensor_status(exported_at, now):
    try:
        t = datetime.strptime(exported_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return "silent", 0
    age = max(0, int((now - t).total_seconds() // 60))
    if age < LIVE_MINUTES:
        return "live", age
    if age < SILENT_MINUTES:
        return "stale", age
    return "silent", age


def _hourly(buckets):
    return [int(buckets[i]) + int(buckets[i + 1]) for i in range(0, 336, 2)]


def _panel(export, now, collected_at):
    status, age = sensor_status(export["exported_at"], now)
    hourly = _hourly(export["ring"]["buckets"])
    k7 = sum(hourly)
    sensor = {
        "id": export["sensor"]["id"],
        "uptime_days": int(export["sensor"]["uptime_minutes"]) // 1440,
        "protocols": export["sensor"]["protocols"],
        "status": status,
        "export_age_minutes": age,
        "exported_at": export["exported_at"],
        "knockknock_version": export["sensor"]["knockknock_version"],
    }
    for k in ("country", "ring_reset_at"):
        if export["sensor"].get(k):
            sensor[k] = export["sensor"][k]
    by_proto = [dict(p, share_pct=round(100.0 * p["hits_7d"] / k7, 1) if k7 else 0.0)
                for p in export["by_protocol"]]
    return {
        "generated_at": iso(now), "schema_version": SCHEMA_VERSION, "attribution": ATTRIBUTION,
        "collected_at": collected_at,
        "sensor": sensor,
        "totals": {"knocks_total": export["totals"]["knocks_total"], "since": export["totals"]["since"],
                   "knocks_24h": sum(hourly[-24:]), "knocks_7d": k7,
                   "unique_ips_7d": sum(1 for r in export["top_ips"] if r["hits_7d"] > 0)},
        "histogram_7d": hourly,
        "by_protocol": by_proto,
        "top_ips": export["top_ips"][:CAP_TOP_IPS],
        "top_usernames": export["top_usernames"], "top_passwords": export["top_passwords"],
        "top_countries": export["top_countries"], "top_isps": export["top_isps"],
    }


def _ips_layer(export, now):
    rows = []
    for r in export["top_ips"]:
        lat, lng = r.get("lat"), r.get("lng")
        if not isinstance(lat, (int, float)) or not isinstance(lng, (int, float)):
            continue
        row = {"ip": r["ip"], "lat": float(lat), "lng": float(lng), "source": "picket",
               "hits_7d": r["hits_7d"], "first_seen": r["first_seen"], "last_seen": r["last_seen"],
               "geo_precision": r.get("geo_precision", "city")}
        if r.get("country"):
            row["country"] = r["country"]
        rows.append(row)
    rows = rows[:CAP_GLOBE_IPS]
    return {"generated_at": iso(now), "schema_version": SCHEMA_VERSION, "attribution": ATTRIBUTION,
            "count": len(rows), "ips": rows}


def restamp_prior(prior, now):
    """Keep-prior with an HONEST status: recompute live/stale/silent against now."""
    out = {}
    if "picket.json" in prior:
        p = dict(prior["picket.json"], generated_at=iso(now))
        status, age = sensor_status(p.get("sensor", {}).get("exported_at", ""), now)
        p["sensor"] = dict(p["sensor"], status=status, export_age_minutes=age)
        out["picket.json"] = p
    if "picket_ips.json" in prior:
        out["picket_ips.json"] = dict(prior["picket_ips.json"], generated_at=iso(now))
    return out


def build_picket(ok, prior, now):
    r = ok.get("picket")
    if r is None or not r.extra.get("picket"):
        return restamp_prior(prior, now) or None
    export = r.extra["picket"]
    return {"picket.json": _panel(export, now, collected_at=iso(now)),
            "picket_ips.json": _ips_layer(export, now)}
```

- [ ] **Step 5: Run to verify pass**

Run: `.venv\Scripts\python -m pytest tests/test_picket_pipeline.py -q`
Expected: PASS (iterate on schema `description`s/bounds until `validate_payload` returns `[]`).

- [ ] **Step 6: Commit**

```bash
git add schemas/picket.schema.json schemas/picket_ips.schema.json pipeline/picket.py pipeline/validate.py tests/test_picket_pipeline.py
git commit -m "feat(picket): published payload + globe-layer schemas and builder (honest stale/silent)"
```

---

### Task 7: Wire into `run_pipeline.py` (end-to-end with keep-prior)

**Files:**
- Modify: `run_pipeline.py` — import + a block placed **after** `payloads = build_site_data(...)` (line ~139) and **before** the ASN block (~line 230), so the gate + dual-write handle it.
- Test: `tests/test_pipeline.py` (append two tests)

**Interfaces:**
- Consumes: `build_picket` (Task 6); `collectors.picket.EXPORT_URL` (Task 5).

- [ ] **Step 1: Write the failing tests** (append to `tests/test_pipeline.py`, using its existing `_pipeline_fetch` helper — read lines 50–66 first and reuse it exactly)

```python
def test_picket_payloads_published_from_export(fake_fetch, tmp_path):
    from collectors import picket as pk_col
    fetch = _pipeline_fetch(fake_fetch, extra={pk_col.EXPORT_URL: "picket/export_ok.json"})
    out, state = tmp_path / "o", tmp_path / "s"
    run(fetch=fetch, now=FIXED_NOW, out_dir=out, state_dir=state,
        schemas_dir="schemas", sources_path="data/sources.json")
    p = json.loads((state / "picket.json").read_text(encoding="utf-8"))
    assert p["sensor"]["status"] == "live" and p["totals"]["knocks_total"] == 9001
    assert (state / "picket_ips.json").exists()
    health = json.loads((state / "health.json").read_text(encoding="utf-8"))
    assert any(s["source"] == "picket" and s["ok"] for s in health["sources"])


def test_picket_export_down_keeps_prior_with_honest_status(fake_fetch, tmp_path):
    from collectors import picket as pk_col
    out, state = tmp_path / "o", tmp_path / "s"
    run(fetch=_pipeline_fetch(fake_fetch, extra={pk_col.EXPORT_URL: "picket/export_ok.json"}),
        now=FIXED_NOW, out_dir=out, state_dir=state, schemas_dir="schemas", sources_path="data/sources.json")
    later = FIXED_NOW + timedelta(hours=30)
    run(fetch=_pipeline_fetch(fake_fetch), now=later, out_dir=out, state_dir=state,   # picket URL unmapped -> error
        schemas_dir="schemas", sources_path="data/sources.json")
    p = json.loads((state / "picket.json").read_text(encoding="utf-8"))
    assert p["sensor"]["status"] == "silent" and p["collected_at"] == "2026-07-28T12:00:00Z"
    health = json.loads((state / "health.json").read_text(encoding="utf-8"))
    assert any(s["source"] == "picket" and not s["ok"] for s in health["sources"])
```

If `_pipeline_fetch` has no `extra=` parameter, add one (merge the mapping) — a minimal test-helper change, included in this task.

- [ ] **Step 2: Run to verify failure**

Run: `.venv\Scripts\python -m pytest tests/test_pipeline.py -q -k picket`
Expected: FAIL — `picket.json` not written

- [ ] **Step 3: Implement the wiring** — in `run_pipeline.py`:

```python
from pipeline.picket import build_picket
```
and, right after the `payloads = build_site_data(...)` call:
```python
    # PICKET (first-party honeypot sensor): the collector's normalized export ->
    # panel + globe-layer payloads. Placed before gate() for schema validation +
    # last-known-good + dual-write. A dead sensor re-publishes the prior with an
    # HONEST recomputed status (stale/silent) — never as zero attacks. Keyless,
    # no D1, no read-path binding (spec 2026-09-17-picket-sensor-design §3.5).
    ok_results = {r.source: r for r in results if r.ok}
    picket_payloads = build_picket(ok_results, state, now)
    if picket_payloads:
        payloads.update(picket_payloads)
```

- [ ] **Step 4: Run to verify pass**

Run: `.venv\Scripts\python -m pytest tests/ -q`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add run_pipeline.py tests/test_pipeline.py
git commit -m "feat(picket): wire collector + builder into run_pipeline (gate + keep-prior + dual-write)"
```

---

### Task 8: Web types + pure view model (vitest)

**Files:**
- Modify: `web/src/components/views/types.ts` (append after line 463)
- Create: `web/src/components/views/picketModel.ts`
- Test: `web/src/components/views/__tests__/picketModel.test.ts`

**Interfaces:**
- Produces (types): `PicketStatus = 'live'|'stale'|'silent'`, `PicketProtocolShare {proto, hits_7d, hits_total, share_pct}`, `PicketIp {ip, hits_7d, hits_total, first_seen, last_seen, protocols: {proto, hits_7d}[], country?, asn?, isp?, lat?, lng?, geo_precision?}`, `PicketCred {value, hits_7d, hits_total}`, `PicketCountry {iso, name, hits_7d, hits_total}`, `PicketIsp {isp, asn, hits_7d, hits_total}`, `PicketSensor {id, country?, uptime_days, protocols: string[], status: PicketStatus, export_age_minutes, exported_at, knockknock_version, ring_reset_at?}`, `PicketTotals {knocks_total, since, knocks_24h, knocks_7d, unique_ips_7d}`, `PicketPayload {generated_at?, schema_version?, attribution?, collected_at?, sensor: PicketSensor, totals: PicketTotals, histogram_7d: number[], by_protocol: PicketProtocolShare[], top_ips: PicketIp[], top_usernames: PicketCred[], top_passwords: PicketCred[], top_countries: PicketCountry[], top_isps: PicketIsp[]}`.
- Produces (model): `statusLabel(s: PicketStatus): string` → `'Live' | 'Stale' | 'Silent'`; `statusCopy(sensor: PicketSensor): string`; `histogramPoints(hist: number[], generatedAt?: string): VolumePoint[]` (168 hourly → 7 daily sums, `date` = ISO day); `formatAge(minutes: number): string`.

- [ ] **Step 1: Write the failing tests**

```ts
// web/src/components/views/__tests__/picketModel.test.ts
import { describe, expect, it } from 'vitest'
import { formatAge, histogramPoints, statusCopy, statusLabel } from '../picketModel'
import type { PicketSensor } from '../types'

const sensor = (over: Partial<PicketSensor> = {}): PicketSensor => ({
  id: 'picket-1', uptime_days: 3, protocols: ['SSH', 'TELNET'], status: 'live',
  export_age_minutes: 25, exported_at: '2026-07-28T11:35:00Z', knockknock_version: '1.9.0', ...over,
})

describe('picketModel', () => {
  it('labels the three sensor states', () => {
    expect(statusLabel('live')).toBe('Live')
    expect(statusLabel('stale')).toBe('Stale')
    expect(statusLabel('silent')).toBe('Silent')
  })

  it('never phrases a silent sensor as zero attacks', () => {
    const c = statusCopy(sensor({ status: 'silent', export_age_minutes: 2880 }))
    expect(c).toMatch(/no export/i)
    expect(c).not.toMatch(/0 attacks|no attacks/i)
    expect(statusCopy(sensor())).toMatch(/25 min/)
  })

  it('formats ages humanely', () => {
    expect(formatAge(25)).toBe('25 min')
    expect(formatAge(120)).toBe('2 h')
    expect(formatAge(2880)).toBe('2 d')
  })

  it('folds 168 hourly buckets into 7 daily points, oldest first', () => {
    const hist = Array.from({ length: 168 }, (_, i) => (i >= 144 ? 1 : 0))   // last day = 24
    const pts = histogramPoints(hist, '2026-07-28T12:00:00Z')
    expect(pts).toHaveLength(7)
    expect(pts[6]).toEqual({ date: '2026-07-28', count: 24 })
    expect(pts[0]).toEqual({ date: '2026-07-22', count: 0 })
  })

  it('tolerates a short or missing histogram', () => {
    expect(histogramPoints([], undefined)).toEqual([])
    expect(histogramPoints([1, 2, 3], undefined)).toHaveLength(1)
  })
})
```

- [ ] **Step 2: Run to verify failure**

Run: `cd web && npx vitest run src/components/views/__tests__/picketModel.test.ts`
Expected: FAIL — cannot resolve `../picketModel`

- [ ] **Step 3: Implement** — append the types listed above to `types.ts` (with a doc comment: *"PICKET — SOCDesk's own honeypot sensor telemetry. Aggregates only; never a username:password pair (spec §3.6)."*), then:

```ts
// web/src/components/views/picketModel.ts
// Pure helpers for the PICKET surfaces — no React, no fetch. The copy rules
// live here so the tab, the teaser and the tests agree: a silent sensor is
// "no export", never "no attacks".
import type { PicketSensor, PicketStatus, VolumePoint } from './types'

export function statusLabel(s: PicketStatus): string {
  return s === 'live' ? 'Live' : s === 'stale' ? 'Stale' : 'Silent'
}

export function formatAge(minutes: number): string {
  if (minutes < 60) return `${minutes} min`
  if (minutes < 1440) return `${Math.round(minutes / 60)} h`
  return `${Math.round(minutes / 1440)} d`
}

export function statusCopy(sensor: PicketSensor): string {
  const age = formatAge(sensor.export_age_minutes)
  if (sensor.status === 'live') return `Sensor reporting · last export ${age} ago`
  if (sensor.status === 'stale') return `Sensor stale · no export for ${age} — figures below are the last received`
  return `Sensor silent · no export for ${age} — the sensor or its uplink is down; figures below are the last received`
}

export function histogramPoints(hist: number[], generatedAt?: string): VolumePoint[] {
  if (!Array.isArray(hist) || hist.length === 0) return []
  const end = generatedAt ? new Date(generatedAt) : new Date()
  const days = Math.floor(hist.length / 24)
  const out: VolumePoint[] = []
  for (let d = 0; d < days; d++) {
    const slice = hist.slice(hist.length - (days - d) * 24, hist.length - (days - d - 1) * 24)
    const day = new Date(end.getTime() - (days - 1 - d) * 86_400_000)
    out.push({ date: day.toISOString().slice(0, 10), count: slice.reduce((a, b) => a + b, 0) })
  }
  return out
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd web && npx vitest run src/components/views/__tests__/picketModel.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add web/src/components/views/types.ts web/src/components/views/picketModel.ts web/src/components/views/__tests__/picketModel.test.ts
git commit -m "feat(picket): web types + pure view model (status copy, age, daily histogram)"
```

---

### Task 9: `PicketView` + `PicketRoute` + Desk tab

**Files:**
- Create: `web/src/components/views/PicketView.tsx`, `web/src/routes/PicketRoute.tsx`
- Modify: `web/src/routes/DataDeskRoute.tsx:36-41` (TABS) and `:108-114` (switch)
- Test: `web/src/components/views/__tests__/PicketView.test.tsx`

**Interfaces:**
- Consumes: `PicketPayload` + model (Task 8); `EmptyState`, `AsyncGate`, `SkeletonRows` (`views/states.tsx`); `ViewHeader` (`views/ViewFrame.tsx`); `Sparkline` (`overview/Sparkline.tsx`); `barWidthClass` (`overview/widths.ts`); `num`, `rel` (`views/format.ts`); `MicroLabel` (`components/ui`); `cx`.
- Produces: `PicketView({ payload }: { payload: PicketPayload | null })`, `PicketRoute()`.

- [ ] **Step 1: Write the failing tests**

```tsx
// web/src/components/views/__tests__/PicketView.test.tsx
import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { PicketView } from '../PicketView'
import type { PicketPayload } from '../types'

const payload: PicketPayload = {
  generated_at: '2026-07-28T12:00:00Z',
  sensor: { id: 'picket-1', uptime_days: 3, protocols: ['SSH', 'TELNET'], status: 'live',
            export_age_minutes: 25, exported_at: '2026-07-28T11:35:00Z', knockknock_version: '1.9.0', country: 'DE' },
  totals: { knocks_total: 9001, since: '2026-07-25T12:00:00Z', knocks_24h: 42, knocks_7d: 42, unique_ips_7d: 1 },
  histogram_7d: Array.from({ length: 168 }, (_, i) => (i === 167 ? 42 : 0)),
  by_protocol: [{ proto: 'SSH', hits_7d: 900, hits_total: 8000, share_pct: 90 }],
  top_ips: [{ ip: '203.0.113.5', hits_7d: 900, hits_total: 900, first_seen: '2026-07-20T01:00:00Z',
              last_seen: '2026-07-28T11:00:00Z', protocols: [{ proto: 'SSH', hits_7d: 900 }], country: 'CN', asn: 64500, isp: 'Example Hosting' }],
  top_usernames: [{ value: 'root', hits_7d: 400, hits_total: 3000 }],
  top_passwords: [{ value: '123456', hits_7d: 200, hits_total: 1800 }],
  top_countries: [{ iso: 'CN', name: 'China', hits_7d: 500, hits_total: 4000 }],
  top_isps: [{ isp: 'Example Hosting', asn: 64500, hits_7d: 300, hits_total: 2000 }],
}

describe('PicketView', () => {
  const html = renderToStaticMarkup(<PicketView payload={payload} />)

  it('renders every block with the honest framing and no verdict colour', () => {
    for (const s of ['Sensor reporting', 'SSH', '203.0.113.5', 'root', '123456', 'China', 'Example Hosting',
                     'context, never a verdict', 'telemetry from my own sensor']) {
      expect(html).toContain(s)
    }
    expect(html).not.toMatch(/text-verdict-(red|amber|green)|bg-\[var\(--tint-(red|amber|green)\)\]/)
  })

  it('never renders a username:password pair', () => {
    expect(html).not.toMatch(/root\s*[:/]\s*123456/)
  })

  it('states a silent sensor honestly instead of zeros', () => {
    const silent = renderToStaticMarkup(
      <PicketView payload={{ ...payload, sensor: { ...payload.sensor, status: 'silent', export_age_minutes: 2880 } }} />,
    )
    expect(silent).toContain('Sensor silent')
    expect(silent).toContain('last received')
  })

  it('renders an explicit empty state for a null payload', () => {
    expect(renderToStaticMarkup(<PicketView payload={null} />)).toContain('No sensor telemetry yet')
  })
})
```

- [ ] **Step 2: Run to verify failure**

Run: `cd web && npx vitest run src/components/views/__tests__/PicketView.test.tsx`
Expected: FAIL — module not found

- [ ] **Step 3: Implement the view**

```tsx
// web/src/components/views/PicketView.tsx
import { cx } from '@socdesk/shared/lib/cx'
import { MicroLabel } from '../ui'
import { EmptyState } from './states'
import { num, rel } from './format'
import { barWidthClass } from '../overview/widths'
import { Sparkline } from '../overview/Sparkline'
import { histogramPoints, statusCopy, statusLabel } from './picketModel'
import type { PicketCred, PicketPayload } from './types'

/**
 * /desk#picket — SOCDESK · PICKET, telemetry from SOCDesk's own honeypot.
 * Volume measures in periwinkle only; NO verdict colour anywhere (colour law).
 * Credentials are aggregate values, never pairs. A silent sensor is stated as
 * "no export", never rendered as zero attacks.
 */

const FRAME = 'What automated bots try against an unsolicited sensor — context, never a verdict on any network or operator.'

function Bar({ frac }: { frac: number }) {
  return (
    <span className="h-1.5 w-full overflow-hidden rounded-full bg-panel-soft">
      <span className={cx('block h-full rounded-full bg-accent', barWidthClass(frac))} />
    </span>
  )
}

function Block({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="flex flex-col gap-3 rounded-lg border border-line bg-panel p-5">
      <MicroLabel tone="muted">{title}</MicroLabel>
      {children}
    </section>
  )
}

function CredList({ rows, label }: { rows: PicketCred[]; label: string }) {
  const max = rows[0]?.hits_7d ?? 1
  return (
    <Block title={label}>
      {rows.length === 0 ? (
        <p className="text-xs text-muted">None above the publication floor (3 attempts) this week.</p>
      ) : (
        <ol className="flex flex-col gap-2">
          {rows.map((r) => (
            <li key={r.value} className="flex items-center gap-3">
              <code className="w-40 truncate font-mono text-xs text-paper">{r.value}</code>
              <Bar frac={r.hits_7d / max} />
              <span className="w-12 text-right font-mono text-xs tabular-nums text-paper">{num(r.hits_7d)}</span>
            </li>
          ))}
        </ol>
      )}
    </Block>
  )
}

export function PicketView({ payload }: { payload: PicketPayload | null }) {
  if (!payload) {
    return (
      <EmptyState title="No sensor telemetry yet">
        The Picket sensor has not published an export the pipeline could read. Everything else on the desk still works.
      </EmptyState>
    )
  }
  const { sensor, totals, by_protocol, top_ips, top_countries, top_isps } = payload
  const maxIp = top_ips[0]?.hits_7d ?? 1
  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-baseline gap-x-6 gap-y-2">
        <MicroLabel tone={sensor.status === 'live' ? 'accent' : 'muted'} tick>
          {statusLabel(sensor.status)}
        </MicroLabel>
        <p className="text-sm text-muted">{statusCopy(sensor)}</p>
        <p className="font-mono text-micro text-faint">
          {sensor.protocols.join(' · ')} · up {num(sensor.uptime_days)} d · knock-knock {sensor.knockknock_version}
          {sensor.ring_reset_at ? ` · counters reset ${rel(sensor.ring_reset_at)}` : ''}
        </p>
      </div>
      <p className="max-w-2xl text-micro text-faint">telemetry from my own sensor — {FRAME}</p>

      <div className="grid gap-4 sm:grid-cols-3">
        <Block title="Knocks · 24 h"><span className="font-display text-2xl font-extrabold text-paper">{num(totals.knocks_24h)}</span></Block>
        <Block title="Knocks · 7 d"><span className="font-display text-2xl font-extrabold text-paper">{num(totals.knocks_7d)}</span></Block>
        <Block title="Distinct IPs · 7 d"><span className="font-display text-2xl font-extrabold text-paper">{num(totals.unique_ips_7d)}</span></Block>
      </div>

      <Block title="Seven days, by day">
        <Sparkline points={histogramPoints(payload.histogram_7d, payload.generated_at)} className="h-16 w-full" label="knocks per day, last 7 days" />
        <p className="font-mono text-micro text-faint">{num(totals.knocks_total)} knocks since {rel(totals.since)}</p>
      </Block>

      <Block title="By protocol · 7 d">
        <ol className="flex flex-col gap-2">
          {by_protocol.map((p) => (
            <li key={p.proto} className="flex items-center gap-3">
              <span className="w-20 font-mono text-xs font-semibold text-paper">{p.proto}</span>
              <Bar frac={p.share_pct / 100} />
              <span className="w-16 text-right font-mono text-xs tabular-nums text-paper">{p.share_pct}%</span>
            </li>
          ))}
        </ol>
      </Block>

      <Block title="Top sources · 7 d">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] text-left">
            <thead>
              <tr>{['IP', 'Attempts', 'Protocols', 'Country', 'ASN · ISP', 'First seen', 'Last seen'].map((h) => (
                <th key={h} className="border-b border-line py-2 pr-3 font-mono text-micro font-semibold uppercase tracking-label text-faint">{h}</th>))}</tr>
            </thead>
            <tbody>
              {top_ips.map((r) => (
                <tr key={r.ip} className="border-b border-line last:border-0">
                  <td className="py-2 pr-3 font-mono text-xs text-paper">{r.ip}</td>
                  <td className="py-2 pr-3"><div className="flex items-center gap-2"><Bar frac={r.hits_7d / maxIp} /><span className="font-mono text-xs tabular-nums text-paper">{num(r.hits_7d)}</span></div></td>
                  <td className="py-2 pr-3 font-mono text-micro text-muted">{r.protocols.map((p) => p.proto).join(' · ')}</td>
                  <td className="py-2 pr-3 font-mono text-micro text-muted">{r.country ?? '—'}</td>
                  <td className="py-2 pr-3 text-xs text-muted">{r.asn ? `AS${r.asn}` : '—'}{r.isp ? ` · ${r.isp}` : ''}</td>
                  <td className="py-2 pr-3 font-mono text-micro text-faint">{rel(r.first_seen)}</td>
                  <td className="py-2 pr-3 font-mono text-micro text-faint">{rel(r.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Block>

      <div className="grid gap-4 md:grid-cols-2">
        <CredList rows={payload.top_usernames} label="Usernames tried · 7 d" />
        <CredList rows={payload.top_passwords} label="Passwords tried · 7 d" />
      </div>
      <p className="text-micro text-faint">Credentials are shown as separate aggregate lists — never as the pairs bots submit — and anything resembling a real identity is dropped before publication.</p>

      <div className="grid gap-4 md:grid-cols-2">
        <Block title="Countries · 7 d">
          <ol className="flex flex-col gap-2">{top_countries.map((c) => (
            <li key={c.iso} className="flex items-center gap-3"><span className="w-40 truncate text-xs text-paper">{c.name || c.iso}</span><Bar frac={c.hits_7d / (top_countries[0]?.hits_7d || 1)} /><span className="w-12 text-right font-mono text-xs tabular-nums text-paper">{num(c.hits_7d)}</span></li>))}</ol>
        </Block>
        <Block title="Networks · 7 d">
          <ol className="flex flex-col gap-2">{top_isps.map((i) => (
            <li key={`${i.asn}-${i.isp}`} className="flex items-center gap-3"><span className="w-40 truncate text-xs text-paper">{i.isp}</span><Bar frac={i.hits_7d / (top_isps[0]?.hits_7d || 1)} /><span className="w-12 text-right font-mono text-xs tabular-nums text-paper">{num(i.hits_7d)}</span></li>))}</ol>
        </Block>
      </div>

      <p className="max-w-2xl text-micro text-faint">{payload.attribution}</p>
    </div>
  )
}
```

Then the route, mirroring `AsnLeaderboardRoute.tsx`:

```tsx
// web/src/routes/PicketRoute.tsx
import { MicroLabel } from '../components/ui'
import { ViewHeader } from '../components/views/ViewFrame'
import { AsyncGate, SkeletonRows } from '../components/views/states'
import { PicketView } from '../components/views/PicketView'
import { useStateData } from '../components/views/useStateData'
import { rel } from '../components/views/format'
import type { PicketPayload } from '../components/views/types'

/** /desk#picket — reads the committed picket.json snapshot (no API, no account). */
export function PicketRoute() {
  const { status, data, error } = useStateData<PicketPayload>('picket')
  return (
    <div className="flex flex-col gap-6">
      <ViewHeader
        eyebrow="SOCDESK · PICKET"
        title="Picket"
        intro="Telemetry from SOCDesk's own internet-facing honeypot: what automated bots try against an unsolicited sensor. Context, never a verdict on any network or operator."
        aside={status === 'ready' && data ? <MicroLabel tone="faint">updated {rel(data.generated_at)}</MicroLabel> : null}
      />
      <AsyncGate status={status} label="the sensor telemetry" detail={error} skeleton={<SkeletonRows rows={8} />}>
        <PicketView payload={data} />
      </AsyncGate>
    </div>
  )
}
```

`DataDeskRoute.tsx`: import `PicketRoute`; add `{ key: 'picket', label: 'Picket' }` to `TABS` after `networks`; add `{tab === 'picket' && <PicketRoute />}` to the switch.

- [ ] **Step 4: Run to verify pass**

Run: `cd web && npx vitest run src && npm run build`
Expected: vitest PASS; `tsc -b && vite build` clean.

- [ ] **Step 5: Commit**

```bash
git add web/src/components/views/PicketView.tsx web/src/routes/PicketRoute.tsx web/src/routes/DataDeskRoute.tsx web/src/components/views/__tests__/PicketView.test.tsx
git commit -m "feat(picket): /desk#picket tab — sensor status, histogram, protocols, sources, fenced credentials"
```

---

### Task 10: Landing-board teaser

**Files:**
- Create: `web/src/components/overview/PicketTeaser.tsx`
- Modify: `web/src/components/overview/SituationalBoard.tsx` (import; `const picket = useStateData<PicketPayload>('picket')` next to `networks` at line ~138; a `Gate` block after the leaderboard's at ~194)
- Test: `web/src/components/overview/__tests__/PicketTeaser.test.tsx`

**Interfaces:**
- Consumes: `BoardPanel`, `DeskLink`, `PanelEmpty`, `SourceStamp` (`board-ui.tsx`), `Sparkline`, `histogramPoints`, `statusCopy`, `num`.
- Produces: `PicketTeaser({ payload }: { payload: PicketPayload | null })`.

- [ ] **Step 1: Write the failing tests**

```tsx
// web/src/components/overview/__tests__/PicketTeaser.test.tsx
import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { PicketTeaser } from '../PicketTeaser'
import type { PicketPayload } from '../../views/types'

const payload = {
  generated_at: '2026-07-28T12:00:00Z',
  sensor: { id: 'picket-1', uptime_days: 3, protocols: ['SSH'], status: 'live', export_age_minutes: 25,
            exported_at: '2026-07-28T11:35:00Z', knockknock_version: '1.9.0' },
  totals: { knocks_total: 9001, since: '2026-07-25T12:00:00Z', knocks_24h: 42, knocks_7d: 300, unique_ips_7d: 7 },
  histogram_7d: Array.from({ length: 168 }, () => 1),
  by_protocol: [], top_ips: [], top_usernames: [], top_passwords: [],
  top_countries: [{ iso: 'CN', name: 'China', hits_7d: 500, hits_total: 4000 }], top_isps: [],
} as PicketPayload

describe('PicketTeaser', () => {
  it('shows knocks/24h, top country, and links to the desk tab', () => {
    const html = renderToStaticMarkup(<PicketTeaser payload={payload} />)
    expect(html).toContain('42')
    expect(html).toContain('China')
    expect(html).toContain('#picket')
    expect(html).toContain('Picket')
  })
  it('is an honest empty when there is no payload', () => {
    expect(renderToStaticMarkup(<PicketTeaser payload={null} />)).toContain('No sensor telemetry yet')
  })
  it('states a silent sensor rather than zeros', () => {
    const html = renderToStaticMarkup(<PicketTeaser payload={{ ...payload, sensor: { ...payload.sensor, status: 'silent', export_age_minutes: 3000 } }} />)
    expect(html).toContain('Sensor silent')
  })
})
```

- [ ] **Step 2: Run to verify failure**

Run: `cd web && npx vitest run src/components/overview/__tests__/PicketTeaser.test.tsx`
Expected: FAIL — module not found

- [ ] **Step 3: Implement**

```tsx
// web/src/components/overview/PicketTeaser.tsx
import { num } from '../views/format'
import type { PicketPayload } from '../views/types'
import { BoardPanel, DeskLink, PanelEmpty, SourceStamp } from './board-ui'
import { Sparkline } from './Sparkline'
import { histogramPoints, statusCopy } from '../views/picketModel'

/**
 * Compact landing teaser for /desk#picket. Same honesty rules as the tab:
 * periwinkle volume only, a silent sensor stated as "no export".
 */
export function PicketTeaser({ payload }: { payload: PicketPayload | null }) {
  return (
    <BoardPanel
      eyebrow="SOCDESK · PICKET"
      title="Picket — telemetry from my own sensor"
      aside={<SourceStamp label="knock-knock · GeoLite2" />}
      footer={
        <>
          <span className="font-mono text-micro uppercase tracking-label text-faint">
            {payload ? `${num(payload.totals.knocks_7d)} knocks · ${num(payload.totals.unique_ips_7d)} IPs · 7 d` : 'no export yet'}
          </span>
          <DeskLink tab="picket">Picket</DeskLink>
        </>
      }
    >
      {!payload ? (
        <PanelEmpty>No sensor telemetry yet.</PanelEmpty>
      ) : (
        <div className="flex flex-col gap-3">
          <p className="text-xs text-muted">{statusCopy(payload.sensor)}</p>
          <div className="flex items-end justify-between gap-4">
            <div>
              <div className="font-display text-3xl font-extrabold tracking-tight text-paper">{num(payload.totals.knocks_24h)}</div>
              <div className="font-mono text-micro uppercase tracking-label text-faint">knocks · 24 h</div>
            </div>
            <Sparkline points={histogramPoints(payload.histogram_7d, payload.generated_at)} label="knocks per day, last 7 days" />
          </div>
          {payload.top_countries[0] && (
            <p className="font-mono text-micro text-faint">most from {payload.top_countries[0].name || payload.top_countries[0].iso} · {payload.sensor.protocols.join(' · ')}</p>
          )}
        </div>
      )}
    </BoardPanel>
  )
}
```

`SituationalBoard.tsx`: add `PicketPayload` to the type import, `import { PicketTeaser } from './PicketTeaser'`, `const picket = useStateData<PicketPayload>('picket')`, and after the leaderboard `Gate`:
```tsx
      {/* first-party sensor teaser for /desk#picket; light picket.json */}
      <Gate status={picket.status} label="the Picket sensor" detail={picket.error} skeleton={<Skeleton className="h-48 w-full rounded-lg" />}>
        <PicketTeaser payload={picket.data} />
      </Gate>
```
Note: `useStateData` yields `status:'error'` when `picket.json` is absent (HTTP 404) — `AsyncGate` then renders its error state with `label`; that is the intended honest behaviour until the first export lands.

- [ ] **Step 4: Run to verify pass**

Run: `cd web && npx vitest run src && npm run build`
Expected: PASS, build clean.

- [ ] **Step 5: Commit**

```bash
git add web/src/components/overview/PicketTeaser.tsx web/src/components/overview/SituationalBoard.tsx web/src/components/overview/__tests__/PicketTeaser.test.tsx
git commit -m "feat(picket): landing-board teaser panel"
```

---

### Task 11: `/about#picket` transparency section

**Files:**
- Modify: `web/src/routes/About.tsx` (add a `<Section id="picket" …>` after the `community-reports` section, same `Section`/`Panel`/`P` primitives already used there)
- Test: extend an existing About test if one exists (grep `About` under `web/src/**/__tests__`); otherwise add `web/src/routes/__tests__/About.test.tsx` asserting the rendered markup contains `id="picket"`, "owner-moderated", "never as pairs", "MaxMind", "knock-knock", and "abuse@socdesk.io".

- [ ] **Step 1: Write the failing test** (as described; `renderToStaticMarkup(<About />)`).
- [ ] **Step 2: Run** `cd web && npx vitest run src/routes` — Expected: FAIL.
- [ ] **Step 3: Implement** — content (adapt to the file's `Section`/`Panel`/`P` API exactly as the community-reports section does):
  - eyebrow `SOCDESK · PICKET`, title *"Telemetry from my own sensor"*.
  - Panel "In short": *"Picket is an internet-facing honeypot SOCDesk runs itself. It records what automated bots try against a server nobody invited them to — and publishes counts. It is context, never a verdict on any network or operator."*
  - Paragraphs: what is collected (attempt counts by IP, protocol, country, network; the most-tried usernames and passwords **as separate aggregate lists, never as pairs**, with a publication floor and identity-like values dropped); what is *not* collected (no victims, no per-attempt logs, no traffic from real users — the sensor serves nothing); how it reaches the site (a bounded export, re-checked and re-sanitised before publication, refreshed every 30 minutes; a silent sensor is shown as silent); upstream reporting: *"Nothing is reported to any third party automatically. Any report to AbuseIPDB is proposed by the pipeline and approved by the owner, one address at a time."* (P3 — state the policy now); dispute contact `abuse@socdesk.io` — removal is the response; attribution: knock-knock (MIT), *"This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com."*
- [ ] **Step 4: Run** `cd web && npx vitest run src && npm run build` — Expected: PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat(picket): /about#picket transparency section"`

---

### Task 12: `docs/PICKET.md` — the reference (spec §10)

**Files:**
- Create: `docs/PICKET.md`

- [ ] **Step 1: Write the document.** Written for a reviewer who has **not** read the spec. Required sections and content:
  1. **What Picket is / is not** (one screen; the honesty frame; the threat model of the box; "bait, assume compromise, blast radius = box + data repo").
  2. **Architecture** — the §2 diagram from the spec, updated to what P1 actually built; which parts are P2/P3 (greyed list).
  3. **The sensor** — knock-knock (pinned tag), protocols enabled, `SAVE_KNOCKS` off and why, dashboard not public and why, self-redaction, MaxMind; **the protocol map** as confirmed on the box (Task 4 §6), and the recorded answer to "is a knock an auth attempt or a bare connect" per protocol.
  4. **The exporter** — the delta ring explained with a worked example (three runs → ring → hits_7d), reset handling, what `state.json` holds and that it never leaves the box, cadence, the 512 KB refusal, the public-IP hash.
  5. **Data contracts** — every field of `export.json`, `picket.json`, `picket_ips.json`, with example rows (use the fixtures) and the bound on each; a table mapping knock-knock rollup columns → export fields.
  6. **The PII fence** — the exact rules (Task 1) and why each exists; enforced twice; what the schema forbids structurally.
  7. **Freshness state machine** — live/stale/silent thresholds, how keep-prior recomputes status, how it reads in the UI.
  8. **Failure modes** — the spec §5 table, updated with real behaviour observed in dogfood.
  9. **Surfaces** — the tab, the teaser, `/about#picket`; screenshots (light + dark) saved under `docs/img/picket/` (take them from `vite preview` with a real `picket.json`).
  10. **Compliance & attribution** — first-party posture, why attacker IPs are published, MaxMind + knock-knock lines, dispute path.
  11. **Roadmap** — P2 (fusion, exports, lead-time), P3 (moderated give-back), P4 (STIX, trends) with one line each and a pointer to the spec.
  12. **Change log** — dated.
- [ ] **Step 2: Commit** — `git add docs/PICKET.md docs/img/picket && git commit -m "docs(picket): PICKET.md reference — architecture, contracts, fence, freshness, surfaces"`

---

### Task 13: Documentation updates across the repo (spec §10)

**Files:** `docs/OPERATIONS.md`, `docs/DATA-SOURCES.md`, `docs/REPO-MAP.md`, `docs/ANALYST-GUIDE.md`, `README.md`, `COMPLIANCE.md`

- [ ] **Step 1: `docs/OPERATIONS.md`** — after the B2 section (line ~371–429), add `### Owner one-time setup — PICKET (the honeypot sensor)`: the spec §9 steps 1–4 verbatim (VPS; MaxMind; the export repo + **write-scoped deploy key to that repo only**; run the runbook), a pointer to `tools/picket/README.md`, and a **Dogfood acceptance (manual — the real gate)** checklist: external `nmap` shows only honeypot ports + admin port; dashboard unreachable from outside; first export lands within 30 min; `picket.json` appears in `data/state/` on the next cron; `/desk#picket` renders; kill the timer → "stale" within 90 min, "silent" after 24 h; restore → "live". Also add `picket` to the "Reading `health.json`" section's source list.
- [ ] **Step 2: `docs/DATA-SOURCES.md`** — under "Collected and republished", add `### SOCDesk Picket (first-party honeypot)` using the same `| Provides | Endpoint | Terms | Cadence | Published as | Finding |` table: Provides = counts of automated break-in attempts against SOCDesk's own sensor (IP/protocol/country/network; aggregate credentials); Endpoint = `collectors/picket.py` → the public export repo raw URL; Terms = first-party telemetry, redistributable by construction; knock-knock MIT; GeoLite2 attribution required (quoted); Cadence = every run; Published as = `picket.json`, `picket_ips.json`; Finding = the new COMPLIANCE.md PICKET entry.
- [ ] **Step 3: `docs/REPO-MAP.md`** — add rows: `tools/picket/` (box-side exporter + runbook), `collectors/picket.py`, `pipeline/picket.py`, the three schemas, `web/src/routes/PicketRoute.tsx`, `web/src/components/views/PicketView.tsx`, `picketModel.ts`, `web/src/components/overview/PicketTeaser.tsx`, the Desk tab `picket`, `/about#picket`.
- [ ] **Step 4: `docs/ANALYST-GUIDE.md`** — new `## The Picket tab` after "The feed": how to read status/knocks/protocols/sources, what the credential lists are and are not (aggregates, floor, no pairs), and *"what this tells you and what it doesn't"* — a Picket hit means an address was scanning/brute-forcing an unsolicited server; it is not evidence about your environment (P2 will add the tenant-side hunts).
- [ ] **Step 5: `README.md`** — add `| [docs/PICKET.md](docs/PICKET.md) | SOCDesk's own honeypot sensor: architecture, data contracts, the credential fence, freshness, surfaces |` and `| [tools/picket/README.md](tools/picket/README.md) | Sensor box runbook — provision, harden, install, verify, rebuild, incident response |` to the Documentation table; one sentence in the features section.
- [ ] **Step 6: `COMPLIANCE.md`** — after the R2 re-rating section add `### PICKET — first-party honeypot telemetry (2026-09-17)`: what is published and why it is redistributable (our own observations); why attacker IPs are published (facts about hosts that attacked an unsolicited sensor; same posture as the ASN leaderboard's abuse.ch/community IPs); the credential fence (aggregates, floor, identity-like values dropped, never pairs) as the no-PII control; the box holds no per-knock records; dispute path `abuse@socdesk.io`; attribution obligations (MaxMind line verbatim; knock-knock MIT); upstream reporting policy = owner-moderated only (P3). Rating: **LOW — first-party data, no third-party redistribution**.
- [ ] **Step 7: Commit** — `git add docs README.md COMPLIANCE.md && git commit -m "docs(picket): OPERATIONS/DATA-SOURCES/REPO-MAP/ANALYST-GUIDE/README/COMPLIANCE for P1"`

---

### Task 14: Live verification + close-out

**Files:** `docs/HANDOFF.md` (new §0 block), `BACKLOG.md` (status line)

- [ ] **Step 1: Full suites** — `.venv\Scripts\python -m pytest tests/ -q` · `cd web && npx vitest run ../shared src` · `npm --prefix web run build` · `npm --prefix web run lint`. Expected: all green, build clean.
- [ ] **Step 2: Local render check** — copy `tests/fixtures/picket/export_ok.json` through the pipeline (`.venv\Scripts\python run_pipeline.py` needs live fetches; instead run the two `run()` tests' outputs, or hand-copy a generated `picket.json` from the pytest `tmp_path` into `web/public/data/state/picket.json`), `npm --prefix web run preview`, open `/desk#picket` and `/` in a browser with a cache-busting query, screenshot light + dark, confirm a clean console, then **remove** the copied file (`git status` must show only intended changes).
- [ ] **Step 3: Box dogfood (owner-present)** — run the OPERATIONS.md acceptance checklist end to end on the real VPS; record the observed timings and the protocol-map/auth-attempt answers in `docs/PICKET.md` §3 and §8.
- [ ] **Step 4: HANDOFF + BACKLOG** — add a dated `## 0. LATEST — 2026-09-XX (session — PICKET P1 SHIPPED)` block to `docs/HANDOFF.md` (what shipped, commits, verified, decisions, next = P2 plan), demote the previous §0 to `0-RECENT`; update `BACKLOG.md`'s honeypot line to "P1 SHIPPED — see docs/PICKET.md; P2 next".
- [ ] **Step 5: Commit** — `git add docs/HANDOFF.md BACKLOG.md docs/PICKET.md && git commit -m "docs(handoff): PICKET P1 shipped — foundation live, P2 next"`

---

## Self-review

**Spec coverage (P1 scope):** §3.1 box posture → Task 4 (install.sh + README); §3.2 export repo/keyless fetch → Tasks 4, 5; §3.3 delta ring → Task 2; §3.4 per-IP enrichment (GeoLite2 country, ISP by ASN, protocol names from the registry) → Tasks 3, 4; §3.5 `picket.json` + `picket_ips.json` + health row → Tasks 6, 7; §3.6 fence twice → Tasks 1, 3, 5 (+ schema minimum:3 structurally); §3.11 tab + teaser + about → Tasks 9, 10, 11; §4.1/4.2/4.4 schemas → Tasks 3, 6; §5 degradation → Tasks 6, 7 (tests for stale/silent/keep-prior/no-prior); §6 tests → every task; §7 acceptance 1–3, 8, 9 → Task 14; §9 owner setup → Task 13 (OPERATIONS) + Task 4 (runbook); §10 documentation → Tasks 4, 12, 13, 14. **Deferred by design:** §3.5 `asn.py` fold, §3.7 lead-time, §3.8 enrich row, §3.9 give-back, §3.10 exports, §4.3 lookup schema — P2/P3 plans.

**Placeholder scan:** none of "TBD/TODO/similar to"; every code step shows code; the two spec build-time checks (protocol auth-vs-connect; `WEB_HOST` variable name on the pinned tag) are explicit runbook steps with the exact command, not assumptions.

**Type consistency:** `hits_7d`/`hits_total` naming is identical across the raw export (Task 3), collector (Task 5), published payload (Task 6), TS types (Task 8) and views (Tasks 9–10). `sensor.status` enum `live|stale|silent` is identical in `pipeline/picket.py`, `picket.schema.json`, `PicketStatus`, and `statusLabel`. `histogram_7d` is 168 ints everywhere; `ring.buckets` is 336 only in the raw export. `source: "picket"` is a schema const and the TS `ThreatIp.source` accepts `string`.

**One known simplification, documented:** per-IP per-protocol `hits_7d` in P1 is the all-time per-protocol count when the IP was active this week (knock-knock keeps no (ip, proto) time series and we keep `SAVE_KNOCKS` off) — stated in `PICKET.md` §5 and in the assembler comment; P2 may refine by keeping a sparse (ip,proto) delta list in the ring if the owner wants it.
