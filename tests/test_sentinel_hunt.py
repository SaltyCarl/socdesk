import json

import pytest

from collectors import sentinel_hunt
from pipeline.validate import validate_payload
from tests.conftest import FIXED_NOW

SHA = "6af3c9d0000000000000000000000000000000aa"
PATH = "Solutions/Example/Hunting Queries/Ransom Note Writes.yaml"
URL = f"{sentinel_hunt.RAW_BASE}/{SHA}/{PATH}"

DOC = """\
id: 11111111-2222-3333-4444-555555555555
name: Ransom note file writes
description: Looks for mass creation of ransom-note-like files.
query: |
  DeviceFileEvents
  | where FileName endswith ".readme.txt"
  | summarize count() by DeviceName
"""


def _allowlist(tmp_path, entries):
    p = tmp_path / "sentinel_allowlist.json"
    p.write_text(json.dumps({"rules": entries}), encoding="utf-8")
    return p


ENTRY = {"id": "sentinel-ransom-note-writes", "path": PATH, "sha": SHA,
         "techniques": ["T1486"], "dialect": "advanced_hunting",
         "modified": "2026-06-01", "upstream_id": "11111111-2222-3333-4444-555555555555"}


def test_collect_extracts_rule_with_authoritative_metadata(tmp_path, fake_fetch):
    al = _allowlist(tmp_path, [ENTRY])
    r = sentinel_hunt.collect(fake_fetch({URL: DOC}), FIXED_NOW, allowlist_path=al)
    assert r.ok and r.error == ""
    [rule] = r.extra["rules"]
    assert rule["id"] == "sentinel-ransom-note-writes"
    assert rule["title"] == "Ransom note file writes"
    assert rule["techniques"] == ["T1486"]          # allowlist wins
    assert rule["dialect"] == "advanced_hunting"
    assert rule["tables"] == ["DeviceFileEvents"]   # known-tables extraction
    assert rule["source"] == {
        "kind": "sentinel",
        "url": f"{sentinel_hunt.BLOB_BASE}/{SHA}/{PATH}",
        "license": "MIT", "modified": "2026-06-01"}
    assert len(r.extra["allowlist_sha1"]) == 40


def test_collect_isolates_per_entry_failures(tmp_path, fake_fetch):
    bad = dict(ENTRY, id="bad-entry", path="Solutions/Nope/Hunting Queries/x.yaml")
    al = _allowlist(tmp_path, [ENTRY, bad])
    # fake_fetch raises on the unmapped URL — the good entry must survive
    r = sentinel_hunt.collect(fake_fetch({URL: DOC}), FIXED_NOW, allowlist_path=al)
    assert r.ok
    assert len(r.extra["rules"]) == 1
    assert "bad-entry" in r.error


def test_collect_all_failed_raises(tmp_path, fake_fetch):
    bad = dict(ENTRY, path="Solutions/Nope/Hunting Queries/x.yaml")
    al = _allowlist(tmp_path, [bad])
    with pytest.raises(RuntimeError):
        sentinel_hunt.collect(fake_fetch({}), FIXED_NOW, allowlist_path=al)


def test_collect_skips_oversized_and_queryless_docs(tmp_path, fake_fetch):
    huge = "query: |\n  " + "DeviceFileEvents | where x == 1\n  " * 2000
    noq = "id: x\nname: no query here\n"
    e1 = dict(ENTRY, id="huge", path="Solutions/A/Hunting Queries/huge.yaml")
    e2 = dict(ENTRY, id="noq", path="Solutions/A/Hunting Queries/noq.yaml")
    al = _allowlist(tmp_path, [e1, e2, ENTRY])
    mapping = {
        f"{sentinel_hunt.RAW_BASE}/{SHA}/{e1['path']}": huge,
        f"{sentinel_hunt.RAW_BASE}/{SHA}/{e2['path']}": noq,
        URL: DOC,
    }
    r = sentinel_hunt.collect(fake_fetch(mapping), FIXED_NOW, allowlist_path=al)
    assert [x["id"] for x in r.extra["rules"]] == ["sentinel-ransom-note-writes"]
    assert "huge" in r.error and "noq" in r.error


def test_hunt_packs_schema_accepts_and_rejects():
    good = {"generated_at": "x", "schema_version": 1, "collected_at": "x",
            "allowlist_sha1": "a" * 40, "rules": [{
                "id": "r1", "title": "t", "kql": "DeviceFileEvents | take 1",
                "techniques": ["T1486"], "tables": ["DeviceFileEvents"],
                "dialect": "advanced_hunting",
                "source": {"kind": "sentinel", "url": "https://x", "license": "MIT"}}]}
    assert validate_payload("hunt_packs.json", good, "schemas") == []
    empty = {"generated_at": "x", "schema_version": 1, "rules": []}
    assert validate_payload("hunt_packs.json", empty, "schemas") == []
    bad_dialect = json.loads(json.dumps(good))
    bad_dialect["rules"][0]["dialect"] = "spl"
    assert validate_payload("hunt_packs.json", bad_dialect, "schemas") != []
    bad_kind = json.loads(json.dumps(good))
    bad_kind["rules"][0]["source"]["kind"] = "elastic"
    assert validate_payload("hunt_packs.json", bad_kind, "schemas") != []
    bad_tech = json.loads(json.dumps(good))
    bad_tech["rules"][0]["techniques"] = ["NOTID"]
    assert validate_payload("hunt_packs.json", bad_tech, "schemas") != []


def test_validate_tool_wrap_handles_the_three_trap_shapes():
    import importlib.util
    from pathlib import Path as P
    spec = importlib.util.spec_from_file_location(
        "vhk", P("tools/validate_hunt_kql.py"))
    vhk = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vhk)
    # trailing // comment must not swallow the appended operator
    assert vhk.wrap("T | where x == 1 // note").endswith("\n| take 0")
    # trailing semicolon breaks the pipe — stripped
    assert ";" not in vhk.wrap("T | count;").split("\n")[0][-3:]
    assert vhk.wrap("T | count;").endswith("| take 0")
    # `| render` must be the last operator in real Kusto — stripped
    w = vhk.wrap("T | summarize count() by x | render columnchart")
    assert "render" not in w and w.endswith("| take 0")


def test_hunt_freshness_is_content_keyed_per_file(tmp_path):
    from run_pipeline import _hunt_is_fresh
    import hashlib
    sen = _allowlist(tmp_path, [ENTRY])
    sig = tmp_path / "sigma_allowlist.json"
    sig.write_text('{"rules": []}', encoding="utf-8")
    sha_sen = hashlib.sha1(sen.read_bytes()).hexdigest()
    sha_sig = hashlib.sha1(sig.read_bytes()).hexdigest()
    fresh = {"hunt_packs.json": {"allowlist_sha1": sha_sen,
                                 "sigma_allowlist_sha1": sha_sig}}
    assert _hunt_is_fresh(fresh, sen, sig) is True
    # EITHER file's edit flips stale — one collector's success must not mask
    # the other's failure (the partial-failure self-retry contract)
    stale_sigma = {"hunt_packs.json": {"allowlist_sha1": sha_sen,
                                       "sigma_allowlist_sha1": "old"}}
    assert _hunt_is_fresh(stale_sigma, sen, sig) is False
    stale_sen = {"hunt_packs.json": {"allowlist_sha1": "old",
                                     "sigma_allowlist_sha1": sha_sig}}
    assert _hunt_is_fresh(stale_sen, sen, sig) is False
    assert _hunt_is_fresh({}, sen, sig) is False
    # missing files contribute nothing -> nothing to collect -> fresh
    assert _hunt_is_fresh({}, tmp_path / "no1.json", tmp_path / "no2.json") is True
