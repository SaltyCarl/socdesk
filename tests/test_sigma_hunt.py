import json

import pytest

from collectors import sigma_hunt
from pipeline.hunt import load_authored_rules, merge_authored
from tests.conftest import FIXED_NOW

SHA = "8375f87fc85224a96ec133266ea934a3338246aa"
PATH = "rules/windows/process_creation/proc_creation_win_test.yml"
URL = f"{sigma_hunt.RAW_BASE}/{SHA}/{PATH}"

# A minimal real-shaped Sigma rule — converted by the REAL pysigma toolchain
# (installed via requirements), so this test also pins that the backend keeps
# producing one plain-operator query for this shape.
SIGMA_DOC = """\
title: Test Ransom Note Dropper
id: 99999999-8888-7777-6666-555555555555
status: test
author: testauthor
date: 2024-01-01
modified: 2025-06-01
tags:
  - attack.impact
  - attack.t1486
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: 'YOUR_FILES_ARE_ENCRYPTED'
  condition: selection
level: high
"""


def _allowlist(tmp_path, entries):
    p = tmp_path / "sigma_allowlist.json"
    p.write_text(json.dumps({"rules": entries}), encoding="utf-8")
    return p


ENTRY = {"id": "sigma-test-ransom-note-dropper", "path": PATH, "sha": SHA}


def test_sigma_collect_converts_and_attributes(tmp_path, fake_fetch):
    al = _allowlist(tmp_path, [ENTRY])
    r = sigma_hunt.collect(fake_fetch({URL: SIGMA_DOC}), FIXED_NOW, allowlist_path=al)
    assert r.ok and r.error == ""
    [rule] = r.extra["rules"]
    assert rule["dialect"] == "advanced_hunting"
    assert "DeviceProcessEvents" in rule["kql"]          # xdr pipeline output
    assert "YOUR_FILES_ARE_ENCRYPTED" in rule["kql"]
    assert rule["techniques"] == ["T1486"]               # lowercase tag uppercased
    # DRL clause 1: author attribution rides into the published shape
    assert rule["source"] == {
        "kind": "sigma", "url": f"{sigma_hunt.BLOB_BASE}/{SHA}/{PATH}",
        "license": "DRL", "author": "testauthor",
        "rule_id": "99999999-8888-7777-6666-555555555555",
        "modified": "2025-06-01"}                        # date obj str()'d


def test_sigma_collect_skips_unconvertible(tmp_path, fake_fetch):
    bad = "title: nope\nlogsource:\n  product: windows\n  service: nosuchservice77\ndetection:\n  sel:\n    Field: x\n  condition: sel\n"
    e2 = dict(ENTRY, id="bad", path="rules/windows/x.yml")
    al = _allowlist(tmp_path, [ENTRY, e2])
    mapping = {URL: SIGMA_DOC, f"{sigma_hunt.RAW_BASE}/{SHA}/{e2['path']}": bad}
    r = sigma_hunt.collect(fake_fetch(mapping), FIXED_NOW, allowlist_path=al)
    assert len(r.extra["rules"]) == 1
    assert "bad" in r.error


def test_sigma_all_failed_raises(tmp_path, fake_fetch):
    al = _allowlist(tmp_path, [dict(ENTRY, path="rules/windows/missing.yml")])
    with pytest.raises(RuntimeError):
        sigma_hunt.collect(fake_fetch({}), FIXED_NOW, allowlist_path=al)


AUTHORED = """\
id: socdesk-test-rule
title: Test identity rule
dialect: log_analytics
techniques: [T1078.004]
tables: [SigninLogs]
tested: "2026-09-02"
rationale: public citation only
kql: |
  SigninLogs
  | where ResultType == "50126"
"""


def test_authored_loader_composes_schema_valid_shape(tmp_path):
    d = tmp_path / "authored"
    d.mkdir()
    (d / "socdesk-test-rule.yaml").write_text(AUTHORED, encoding="utf-8")
    (d / "broken.yaml").write_text("id: x\ntitle: no kql\n", encoding="utf-8")
    rules, warnings = load_authored_rules(d)
    assert len(rules) == 1 and len(warnings) == 1
    r = rules[0]
    # schema-required source fields composed; rationale STRIPPED from payload
    assert r["source"] == {
        "kind": "socdesk",
        "url": "https://github.com/SaltyCarl/socdesk/blob/main/data/hunt/authored/socdesk-test-rule.yaml",
        "license": "MIT", "author": "SOCDesk"}
    assert "rationale" not in r
    assert r["tested"] == "2026-09-02"
    from pipeline.validate import validate_payload
    payload = {"generated_at": "x", "schema_version": 1, "rules": rules}
    assert validate_payload("hunt_packs.json", payload, "schemas") == []


def test_authored_loader_missing_dir_is_empty():
    rules, warnings = load_authored_rules("no/such/dir")
    assert rules == [] and warnings == []


def test_merge_authored_replaces_socdesk_and_creates_envelope():
    sen = {"id": "s1", "source": {"kind": "sentinel"}}
    old = {"id": "socdesk-old", "source": {"kind": "socdesk"}}
    new = {"id": "socdesk-new", "source": {"kind": "socdesk"}}
    hp = {"generated_at": "x", "schema_version": 1, "rules": [sen, old]}
    merged = merge_authored(hp, [new], {"generated_at": "x", "schema_version": 1})
    assert [r["id"] for r in merged["rules"]] == ["s1", "socdesk-new"]
    assert hp["rules"] == [sen, old]  # never mutated (keep-prior aliases state)
    # no payload at all + authored -> authored-only envelope (no shas -> stale)
    created = merge_authored(None, [new], {"generated_at": "x", "schema_version": 1})
    assert created["rules"] == [new] and "allowlist_sha1" not in created
    assert merge_authored(None, [], {"generated_at": "x"}) is None