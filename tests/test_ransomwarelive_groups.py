from collectors import ransomwarelive_groups as rg
from tests.conftest import FIXED_NOW

# Real /v2/groups entry shape: name + editorial fields the collector must DROP.
GROUPS = [
    {"name": "nitrogen", "description": "EDITORIAL-PROSE", "locations": ["x.onion"],
     "ttps": ["T1486"], "tools": ["rclone"], "url": "nitrogen"},
    {"name": "Black X", "description": "MORE-EDITORIAL", "url": "blackx"},
    {"name": "black x"},                       # case-dupe of the above
    {"name": "unknown", "description": "catch-all"},   # upstream sentinel — excluded
    {"name": ""},                              # nameless — skipped
    {"no_name_key": True},                     # malformed — skipped
    "not-a-dict",                              # malformed — skipped
    {"name": "<b>Alpha</b> Crew"},             # markup — inert-cleaned
]


def test_collect_names_only_no_editorial(fake_fetch):
    r = rg.collect(fake_fetch({rg.URL: GROUPS}), FIXED_NOW)
    assert r.ok
    names = r.extra["group_names"]
    # names only, sorted case-insensitively, dupes/sentinel/malformed dropped
    assert names == ["Alpha Crew", "Black X", "nitrogen"]
    # R3: no editorial field survives anywhere in the result
    blob = str(r.extra)
    assert "EDITORIAL" not in blob and "T1486" not in blob and "rclone" not in blob
    assert "x.onion" not in blob


def test_collect_caps_and_tolerates_non_list(fake_fetch):
    many = [{"name": f"group-{n:04d}"} for n in range(rg.MAX_GROUPS + 50)]
    r = rg.collect(fake_fetch({rg.URL: many}), FIXED_NOW)
    assert len(r.extra["group_names"]) == rg.MAX_GROUPS
    r2 = rg.collect(fake_fetch({rg.URL: {"unexpected": "shape"}}), FIXED_NOW)
    assert r2.extra["group_names"] == []
