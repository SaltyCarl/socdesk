# Hunt Playbooks — Plan 1: Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `playbooks.json` — a committed, schema-gated, Kustainer-validated catalog of alert→KQL hunt playbooks — headless (no UI). Plan 2 (client) consumes it.

**Architecture:** Hand-authored `data/hunt/playbooks/*.yaml` are re-read every pipeline run by a new `load_playbooks` (sibling of `load_authored_rules`), composed FRESH into `playbooks.json` (no keep-prior), gated by a new schema, and every step's KQL (with a canonical sample IOC substituted) is validated against the Kustainer emulator in CI.

**Tech Stack:** Python 3.12 (stdlib + PyYAML), JSON Schema (draft 2020-12), the existing Kustainer validation harness (`tools/validate_hunt_kql.py`).

**Spec:** `docs/superpowers/specs/2026-09-03-hunt-playbooks-design.md`

## Global Constraints
- **v1 dialect is `log_analytics` ONLY** (Sentinel). Every step `dialect: log_analytics`. AH is v2.
- **Publish FRESH every run — no keep-prior.** Empty/deleted `playbooks/` → `playbooks:[]` (authored-local, like authored rules; keep-prior would resurrect deleted playbooks).
- **Clean-room provenance:** public frameworks only (Sentinel community / SigmaHQ / MS docs / MITRE), attributed `SOCDesk · MIT`, `source.url` = the file's own GitHub blob. `rationale` is human-only, STRIPPED from the payload.
- **Every step's sample-substituted KQL must pass Kustainer** against committed DDL in `data/hunt/kusto_ddl/log_analytics/` (SigninLogs, OfficeActivity, AuditLogs, IdentityLogonEvents all present).
- **Placeholder syntax:** `{{ip}}`, `{{upn}}` (double-brace, param name). CI substitutes canonical samples: `ip → 203.0.113.7`, `upn → user@example.com`.
- Free-tier; committed-dataset tests assert SHAPE on fixtures, never live-file content; a malformed YAML is skipped+warned, never guessed.

---

### Task 1: Playbook schema + SCHEMA_FOR wiring

**Files:**
- Create: `schemas/hunt_playbooks.schema.json`
- Modify: `pipeline/validate.py:8-25` (add `"playbooks.json"` to `SCHEMA_FOR`)
- Test: `tests/test_playbooks.py` (new)

**Interfaces:**
- Produces: schema key `"playbooks.json" → "hunt_playbooks.schema.json"`; the published envelope shape `{generated_at, schema_version, playbooks:[…]}`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_playbooks.py
from pipeline.validate import validate_payload

VALID = {
    "generated_at": "2026-09-04T00:00:00Z", "schema_version": 1,
    "playbooks": [{
        "id": "unfamiliar-signin-properties", "title": "Unfamiliar sign-in properties",
        "alert_sources": ["Entra ID Protection"], "ioc_types": ["ipv4", "ipv6"],
        "techniques": ["T1078.004"], "tested": "2026-09-04",
        "source": {"kind": "socdesk", "url": "https://x/y.yaml", "license": "MIT", "author": "SOCDesk"},
        "steps": [{
            "id": "signins-from-ip", "title": "Every sign-in from this IP",
            "kind": "pivot", "param": "ip", "dialect": "log_analytics",
            "tables": ["SigninLogs"], "kql": 'SigninLogs | where IPAddress == "{{ip}}"'}]}]}

def test_valid_playbook_payload_passes():
    assert validate_payload("playbooks.json", VALID, "schemas") == []

def test_step_rejects_unknown_property():
    bad = {**VALID, "playbooks": [{**VALID["playbooks"][0],
        "steps": [{**VALID["playbooks"][0]["steps"][0], "surprise": 1}]}]}
    assert validate_payload("playbooks.json", bad, "schemas") != []

def test_step_rejects_non_log_analytics_dialect():
    bad = {**VALID, "playbooks": [{**VALID["playbooks"][0],
        "steps": [{**VALID["playbooks"][0]["steps"][0], "dialect": "advanced_hunting"}]}]}
    assert validate_payload("playbooks.json", bad, "schemas") != []
```

- [ ] **Step 2: Run to verify it fails** — `python -m pytest tests/test_playbooks.py -q` → FAIL (KeyError on SCHEMA_FOR / schema file missing).

- [ ] **Step 3: Create the schema** — `schemas/hunt_playbooks.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["generated_at", "schema_version", "playbooks"],
  "additionalProperties": false,
  "properties": {
    "generated_at": {"type": "string", "maxLength": 40},
    "schema_version": {"type": "integer"},
    "playbooks": {
      "type": "array", "maxItems": 128,
      "items": {
        "type": "object",
        "required": ["id", "title", "ioc_types", "techniques", "source", "steps"],
        "additionalProperties": false,
        "properties": {
          "id": {"type": "string", "minLength": 1, "maxLength": 120},
          "title": {"type": "string", "minLength": 1, "maxLength": 200},
          "alert_sources": {"type": "array", "maxItems": 8, "items": {"type": "string", "maxLength": 80}},
          "ioc_types": {"type": "array", "minItems": 1, "maxItems": 8,
            "items": {"enum": ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email"]}},
          "techniques": {"type": "array", "maxItems": 16,
            "items": {"type": "string", "pattern": "^T[0-9]{4}(\\.[0-9]{3})?$"}},
          "tested": {"type": "string", "maxLength": 10},
          "source": {
            "type": "object", "required": ["kind", "url", "license"], "additionalProperties": false,
            "properties": {
              "kind": {"enum": ["socdesk"]},
              "url": {"type": "string", "maxLength": 500},
              "license": {"type": "string", "maxLength": 40},
              "author": {"type": "string", "maxLength": 120}
            }
          },
          "steps": {
            "type": "array", "minItems": 1, "maxItems": 12,
            "items": {
              "type": "object",
              "required": ["id", "title", "kind", "param", "dialect", "kql"],
              "additionalProperties": false,
              "properties": {
                "id": {"type": "string", "minLength": 1, "maxLength": 120},
                "title": {"type": "string", "minLength": 1, "maxLength": 200},
                "kind": {"enum": ["pivot", "scenario"]},
                "param": {"enum": ["ip", "upn", "domain", "url", "md5", "sha1", "sha256"]},
                "dialect": {"enum": ["log_analytics"]},
                "tables": {"type": "array", "maxItems": 16, "items": {"type": "string", "maxLength": 60}},
                "kql": {"type": "string", "minLength": 1, "maxLength": 16384}
              }
            }
          }
        }
      }
    }
  }
}
```

- [ ] **Step 4: Add to SCHEMA_FOR** — in `pipeline/validate.py`, inside the `SCHEMA_FOR` dict (after the `"hunt_packs.json"` line), add:

```python
    "playbooks.json": "hunt_playbooks.schema.json",
```

- [ ] **Step 5: Run to verify pass** — `python -m pytest tests/test_playbooks.py -q` → 3 passed.

- [ ] **Step 6: Commit** — `git add schemas/hunt_playbooks.schema.json pipeline/validate.py tests/test_playbooks.py && git commit -m "feat(playbooks): schema + SCHEMA_FOR wiring"`

---

### Task 2: `load_playbooks` loader

**Files:**
- Modify: `pipeline/hunt.py` (add `load_playbooks` beside `load_authored_rules`)
- Test: `tests/test_playbooks.py`

**Interfaces:**
- Consumes: `data/hunt/playbooks/*.yaml`.
- Produces: `load_playbooks(dir) -> (playbooks: list[dict], warnings: list[str])`. Each playbook dict is schema-shaped: `id, title, alert_sources, ioc_types, techniques, tested, source{kind:socdesk,url,license:MIT,author:SOCDesk}, steps[]`; `rationale` STRIPPED. Empty/missing dir → `([], [])`; a malformed file is skipped + a warning appended.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_playbooks.py
from pathlib import Path
from pipeline.hunt import load_playbooks

GOOD = """\
id: unfamiliar-signin-properties
title: Unfamiliar sign-in properties
alert_sources: [Entra ID Protection]
ioc_types: [ipv4, ipv6]
techniques: [T1078.004]
tested: "2026-09-04"
rationale: human-only note, must be stripped
steps:
  - id: signins-from-ip
    title: Every sign-in from this IP
    kind: pivot
    param: ip
    dialect: log_analytics
    tables: [SigninLogs]
    kql: |
      SigninLogs
      | where IPAddress == "{{ip}}"
"""

def test_load_playbooks_composes_schema_valid_shape(tmp_path):
    (tmp_path / "unfamiliar.yaml").write_text(GOOD, encoding="utf-8")
    (tmp_path / "broken.yaml").write_text("id: x\ntitle: no steps\n", encoding="utf-8")
    playbooks, warnings = load_playbooks(tmp_path)
    assert len(playbooks) == 1 and len(warnings) == 1
    pb = playbooks[0]
    assert pb["source"] == {
        "kind": "socdesk",
        "url": "https://github.com/SaltyCarl/socdesk/blob/main/data/hunt/playbooks/unfamiliar.yaml",
        "license": "MIT", "author": "SOCDesk"}
    assert "rationale" not in pb
    assert pb["steps"][0]["kind"] == "pivot" and pb["steps"][0]["param"] == "ip"
    # the composed envelope gate-validates
    payload = {"generated_at": "x", "schema_version": 1, "playbooks": playbooks}
    assert validate_payload("playbooks.json", payload, "schemas") == []

def test_load_playbooks_missing_dir_is_empty():
    assert load_playbooks("no/such/dir") == ([], [])
```

- [ ] **Step 2: Run to verify fail** — `python -m pytest tests/test_playbooks.py -q` → FAIL (ImportError: load_playbooks).

- [ ] **Step 3: Implement** — in `pipeline/hunt.py`, after `load_authored_rules`, add:

```python
PLAYBOOKS_BLOB_BASE = "https://github.com/SaltyCarl/socdesk/blob/main/data/hunt/playbooks"
PLAYBOOK_REQUIRED = ("id", "title", "ioc_types", "techniques", "steps")
STEP_REQUIRED = ("id", "title", "kind", "param", "dialect", "kql")


def load_playbooks(playbooks_dir):
    """Returns (playbooks, warnings). Authored-local alert→KQL playbooks, re-read
    every run (like load_authored_rules). Composes the schema-valid published
    shape (source.url = the file's own GitHub blob) and STRIPS `rationale`.
    A malformed file is skipped + reported, never guessed."""
    d = Path(playbooks_dir)
    if not d.is_dir():
        return [], []
    playbooks, warnings = [], []
    for f in sorted(d.glob("*.yaml")):
        try:
            doc = yaml.safe_load(f.read_text(encoding="utf-8"))
            missing = [k for k in PLAYBOOK_REQUIRED if not doc.get(k)]
            if missing:
                raise ValueError(f"missing {','.join(missing)}")
            steps = []
            for s in doc["steps"]:
                smiss = [k for k in STEP_REQUIRED if not s.get(k)]
                if smiss:
                    raise ValueError(f"step {s.get('id', '?')} missing {','.join(smiss)}")
                steps.append({
                    "id": str(s["id"]), "title": str(s["title"])[:200],
                    "kind": str(s["kind"]), "param": str(s["param"]),
                    "dialect": str(s["dialect"]),
                    "tables": [str(t) for t in s.get("tables", [])],
                    "kql": str(s["kql"]).strip(),
                })
            playbooks.append({
                "id": str(doc["id"]), "title": str(doc["title"])[:200],
                "alert_sources": [str(a) for a in doc.get("alert_sources", [])],
                "ioc_types": [str(t) for t in doc["ioc_types"]],
                "techniques": [str(t) for t in doc["techniques"]],
                "tested": str(doc.get("tested", ""))[:10],
                "source": {
                    "kind": "socdesk",
                    "url": f"{PLAYBOOKS_BLOB_BASE}/{f.name}",
                    "license": "MIT", "author": "SOCDesk",
                },
                "steps": steps,
            })
        except Exception as exc:  # noqa: BLE001 — skip + report, never guess
            warnings.append(f"playbook {f.name}: {exc}")
    return playbooks, warnings
```

- [ ] **Step 4: Run to verify pass** — `python -m pytest tests/test_playbooks.py -q` → all passed.

- [ ] **Step 5: Commit** — `git add pipeline/hunt.py tests/test_playbooks.py && git commit -m "feat(playbooks): load_playbooks loader"`

---

### Task 3: Publish `playbooks.json` fresh in the pipeline

**Files:**
- Modify: `run_pipeline.py:160-166` (add the playbooks compose immediately after the authored-rules merge)
- Test: covered by Task 2's envelope-gate test + the real-YAML gate in Task 5 (run() is integration; the composed shape is the unit under test, already asserted).

**Interfaces:**
- Consumes: `load_playbooks` (Task 2), `hunt_dir`, `iso(now)` (both already in scope at run_pipeline.py:160).
- Produces: `payloads["playbooks.json"]` — fresh every run.

- [ ] **Step 1: Add the import** — in `run_pipeline.py:14`, change `from pipeline.hunt import load_authored_rules, merge_authored` to also import `load_playbooks`:

```python
from pipeline.hunt import load_authored_rules, load_playbooks, merge_authored
```

- [ ] **Step 2: Compose the payload** — in `run_pipeline.py`, immediately AFTER the `if merged_hp is not None: payloads["hunt_packs.json"] = merged_hp` block (line ~165), add:

```python
    # Alert→KQL hunt playbooks (authored-local, spec Hunt-Playbooks): re-read
    # every run, published FRESH (no keep-prior — an emptied dir means the
    # author deleted them; playbooks:[] is the honest publish).
    playbooks, playbook_warnings = load_playbooks(hunt_dir / "playbooks")
    payloads["playbooks.json"] = {
        "generated_at": iso(now), "schema_version": 1, "playbooks": playbooks}
```

- [ ] **Step 3: Surface warnings the same way authored_warnings are** — find where `authored_warnings` is logged/collected below (grep `authored_warnings` in run_pipeline.py) and append `playbook_warnings` into the same sink (e.g. `warnings.extend(playbook_warnings)` or the same `print`/log call). Match the existing pattern exactly.

- [ ] **Step 4: Verify the pipeline still imports + a smoke run composes the key** — `python -c "import run_pipeline"` (no ImportError), and the full `python -m pytest tests/ -q` stays green.

- [ ] **Step 5: Commit** — `git add run_pipeline.py && git commit -m "feat(playbooks): publish playbooks.json fresh each run"`

---

### Task 4: Kustainer CI validation lane + workflow trigger

**Files:**
- Modify: `tools/validate_hunt_kql.py` (add sample-substitution + fold playbook steps into the validated ruleset)
- Modify: `.github/workflows/hunt-kql.yml:22-36` (add the new schema to `paths:`)
- Test: `tests/test_playbooks.py` (unit-test the pure substitution helper)

**Interfaces:**
- Consumes: `load_playbooks` (Task 2), the existing `rules_from_allowlist` / `by_dialect` / `validate_rules` path.
- Produces: `substitute_samples(kql) -> str`; playbook steps appear in the validated ruleset as pseudo-rules `{id, dialect, kql}`.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_playbooks.py
def test_substitute_samples_fills_every_placeholder():
    import sys; sys.path.insert(0, "tools")
    from validate_hunt_kql import substitute_samples
    out = substitute_samples('SigninLogs | where IPAddress == "{{ip}}" or UserPrincipalName == "{{upn}}"')
    assert "{{" not in out
    assert "203.0.113.7" in out and "user@example.com" in out
```

- [ ] **Step 2: Run to verify fail** — `python -m pytest tests/test_playbooks.py::test_substitute_samples_fills_every_placeholder -q` → FAIL (ImportError).

- [ ] **Step 3: Implement the substitution + the playbook lane** — in `tools/validate_hunt_kql.py`:

Add near the top (after `wrap`):

```python
_SAMPLES = {"ip": "203.0.113.7", "upn": "user@example.com", "domain": "example.com",
            "url": "https://example.com/a", "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}


def substitute_samples(kql):
    """Replace every {{param}} placeholder with a canonical sample so a
    parameterized playbook step becomes a bindable query for the emulator."""
    for param, sample in _SAMPLES.items():
        kql = kql.replace("{{" + param + "}}", sample)
    return kql
```

In `rules_from_allowlist`, after the authored rules are appended (`return rules + authored` at the end), fold in the playbook steps as pseudo-rules. Change the tail of `rules_from_allowlist` to:

```python
    from pipeline.hunt import load_authored_rules, load_playbooks
    authored, warnings = load_authored_rules(hunt_dir / "authored")
    for w in warnings:
        print(f"authored warning: {w}")
    playbooks, pb_warnings = load_playbooks(hunt_dir / "playbooks")
    for w in pb_warnings:
        print(f"playbook warning: {w}")
    step_rules = [
        {"id": f"{pb['id']}::{s['id']}", "dialect": s["dialect"],
         "kql": substitute_samples(s["kql"])}
        for pb in playbooks for s in pb["steps"]]
    return rules + authored + step_rules
```

(The existing `load_authored_rules` import line at the top of `rules_from_allowlist` becomes the combined import above; remove the now-duplicate single import.)

- [ ] **Step 4: Run to verify pass** — `python -m pytest tests/test_playbooks.py -q` → all passed.

- [ ] **Step 5: Add the schema to the workflow trigger** — in `.github/workflows/hunt-kql.yml`, in BOTH the `push:` and `pull_request:` `paths:` lists, add the playbook schema next to the existing `schemas/hunt_packs.schema.json` line:

```yaml
      - 'schemas/hunt_playbooks.schema.json'
      - 'data/hunt/playbooks/**'
```

(Confirm `data/hunt/**` already covers `playbooks/**`; if it does, add only the schema line. Match the file's exact indentation.)

- [ ] **Step 6: Commit** — `git add tools/validate_hunt_kql.py .github/workflows/hunt-kql.yml tests/test_playbooks.py && git commit -m "feat(playbooks): Kustainer validation lane + workflow trigger"`

---

### Task 5: Author the two exemplar playbooks (end-to-end proof)

**Files:**
- Create: `data/hunt/playbooks/socdesk-unfamiliar-signin-properties.yaml`
- Create: `data/hunt/playbooks/socdesk-password-spray.yaml`
- Test: `tests/test_playbooks.py` (the real files load + gate-validate) + local Kustainer run.

**Interfaces:**
- Consumes: `load_playbooks` (Task 2), the schema (Task 1), the `substitute_samples` lane (Task 4).
- Produces: `data/hunt/playbooks/*.yaml` — two SigninLogs playbooks whose sample-substituted steps pass Kustainer against `data/hunt/kusto_ddl/log_analytics/SigninLogs.kql`.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_playbooks.py
def test_committed_playbooks_load_and_validate():
    playbooks, warnings = load_playbooks("data/hunt/playbooks")
    assert warnings == []            # every committed file is well-formed
    assert len(playbooks) >= 2
    ids = {p["id"] for p in playbooks}
    assert "unfamiliar-signin-properties" in ids and "password-spray" in ids
    payload = {"generated_at": "x", "schema_version": 1, "playbooks": playbooks}
    assert validate_payload("playbooks.json", payload, "schemas") == []
    # every step opens the ladder honestly: step 1 is the IP pivot
    for p in playbooks:
        assert p["steps"][0]["kind"] == "pivot" and p["steps"][0]["param"] == "ip"
```

- [ ] **Step 2: Run to verify fail** — `python -m pytest tests/test_playbooks.py::test_committed_playbooks_load_and_validate -q` → FAIL (0 playbooks).

- [ ] **Step 3: Author `socdesk-unfamiliar-signin-properties.yaml`** — step 1 is the general IP pivot; step 2 adapts the existing `socdesk-signin-unfamiliar-baseline.yaml` scoped by `{{upn}}`:

```yaml
id: unfamiliar-signin-properties
title: Unfamiliar sign-in properties
alert_sources: [Entra ID Protection]
ioc_types: [ipv4, ipv6]
techniques: [T1078.004, T1621]
tested: "2026-09-04"
rationale: >
  Public-framework motion: scope the IP to surface the accounts, then run the
  trust-reduced novelty hunt (adapted from socdesk-signin-unfamiliar-baseline,
  MIT) for one of them. Validated against the Kusto emulator.
steps:
  - id: signins-from-ip
    title: Every sign-in from this IP (surfaces the accounts to pivot on)
    kind: pivot
    param: ip
    dialect: log_analytics
    tables: [SigninLogs]
    kql: |
      SigninLogs
      | where TimeGenerated > ago(7d)
      | where IPAddress == "{{ip}}"
      | summarize Signins = count(),
                  Results = make_set(ResultType),
                  Apps = make_set(AppDisplayName),
                  Countries = make_set(tostring(LocationDetails.countryOrRegion))
        by UserPrincipalName
      | order by Signins desc
  - id: novelty-baseline
    title: Trust-reduced novelty for an account this IP touched (replace <upn>)
    kind: scenario
    param: upn
    dialect: log_analytics
    tables: [SigninLogs]
    kql: |
      let lookback = 14d;
      let recent = 1d;
      let baseline = SigninLogs
      | where TimeGenerated between (ago(lookback) .. ago(recent))
      | where UserPrincipalName == "{{upn}}"
      | where ResultType == "0"
      | summarize KnownCountries = make_set(tostring(LocationDetails.countryOrRegion)),
                  KnownASNs = make_set(AutonomousSystemNumber),
                  KnownOS = make_set(tostring(DeviceDetail.operatingSystem))
        by UserPrincipalName;
      SigninLogs
      | where TimeGenerated > ago(recent)
      | where UserPrincipalName == "{{upn}}"
      | where ResultType == "0"
      | extend Country = tostring(LocationDetails.countryOrRegion),
               OS = tostring(DeviceDetail.operatingSystem),
               Managed = tobool(DeviceDetail.isManaged)
      | join kind=inner baseline on UserPrincipalName
      | extend Score =
          toint(not(set_has_element(KnownCountries, Country))) * 3
        + toint(not(set_has_element(KnownASNs, AutonomousSystemNumber))) * 3
        + toint(not(set_has_element(KnownOS, OS))) * 1
        - toint(Managed == true) * 2
      | where Score >= 4
      | project TimeGenerated, UserPrincipalName, IPAddress, Country, OS, Managed, Score, AppDisplayName
      | order by Score desc
```

- [ ] **Step 4: Author `socdesk-password-spray.yaml`** — the IP pivot + a spray hunt (many accounts, one IP, failed-then-succeeded), adapted from `socdesk-signin-correct-password-blocked.yaml` (MIT):

```yaml
id: password-spray
title: Password spray from this IP
alert_sources: [Entra ID Protection, Microsoft Defender XDR]
ioc_types: [ipv4, ipv6]
techniques: [T1110.003]
tested: "2026-09-04"
rationale: >
  One IP against many accounts with a low per-account attempt count is the
  spray signature; the "correct password but blocked" (50126/50053/53003)
  follow-up flags a spray that landed. Adapted from
  socdesk-signin-correct-password-blocked (MIT). Validated against the emulator.
steps:
  - id: signins-from-ip
    title: Every sign-in from this IP (surfaces the sprayed accounts)
    kind: pivot
    param: ip
    dialect: log_analytics
    tables: [SigninLogs]
    kql: |
      SigninLogs
      | where TimeGenerated > ago(7d)
      | where IPAddress == "{{ip}}"
      | summarize Attempts = count(),
                  Accounts = dcount(UserPrincipalName),
                  Failures = countif(ResultType != "0"),
                  Successes = countif(ResultType == "0")
        by bin(TimeGenerated, 1h)
      | order by Accounts desc
  - id: spray-fanout
    title: Spray fan-out — one IP, many accounts, low per-account attempts
    kind: scenario
    param: ip
    dialect: log_analytics
    tables: [SigninLogs]
    kql: |
      SigninLogs
      | where TimeGenerated > ago(7d)
      | where IPAddress == "{{ip}}"
      | summarize AttemptsPerAccount = count(),
                  AnySuccess = countif(ResultType == "0")
        by UserPrincipalName
      | summarize SprayedAccounts = count(),
                  MedianAttempts = percentile(AttemptsPerAccount, 50),
                  AccountsThatSucceeded = countif(AnySuccess > 0)
      | where SprayedAccounts >= 10 and MedianAttempts <= 5
```

- [ ] **Step 5: Run the shape test to verify pass** — `python -m pytest tests/test_playbooks.py -q` → all passed.

- [ ] **Step 6: Kustainer-validate locally** — boot the emulator and run the lane, confirming every step (sample-substituted) binds:

```bash
docker run -d -m 4G -e ACCEPT_EULA=Y -p 8091:8080 mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
KUSTO_URL=http://localhost:8091 python tools/validate_hunt_kql.py --from-allowlist
```
Expected: the `unfamiliar-signin-properties::*` and `password-spray::*` step ids appear in the `[log_analytics]` batch and PASS. Fix any bind error (unknown column/function) in the YAML and re-run before committing.

- [ ] **Step 7: Commit** — `git add data/hunt/playbooks/ tests/test_playbooks.py && git commit -m "feat(playbooks): two exemplar identity playbooks (Kustainer-validated)"`

---

## Deferred within Plan 1 (fast-follow, data-only)
The remaining four v1 scenarios (impossible travel, MFA-fatigue, malicious inbox rule, risky OAuth consent) are pure authoring in the SAME shape — no new code — and can land after the machinery proves out. Each: IP-pivot step 1 (SigninLogs) + a `{{upn}}`-scoped scenario step on its table (SigninLogs / AuditLogs / OfficeActivity, all with committed DDL), adapting the matching authored rule; each must pass the Kustainer lane before commit.

## Self-Review
- **Spec coverage:** §1 data model → Task 1 (schema) + Task 2 (loader); §2 CI substitution → Task 4; §4 pipeline → Task 3 + Task 4; §5 scenarios → Task 5 (2 exemplars) + the deferred note (4 more); §7 tests → Tasks 1/2/4/5. Client (§3) is Plan 2. No backend gap.
- **Placeholder scan:** every code step carries real code; the "deferred" note is explicitly data-only follow-on, not a task with hidden work.
- **Type consistency:** `load_playbooks(dir)->(playbooks,warnings)` used identically in Task 3 + Task 4; step shape `{id,title,kind,param,dialect,tables,kql}` matches the schema (Task 1) and the loader (Task 2); `substitute_samples` param set matches the schema's `param` enum + `ioc_types`.
