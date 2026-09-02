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
    # malware's own uses-rels fill its techniques (was hardcoded [])
    assert malware[0]["techniques"] == ["T1566"]
    assert malware[0]["software"] == []
    # id -> name catalog for the frontend to label the bare technique ids
    assert r.extra["technique_names"] == {
        "T1566": "Phishing", "T1486": "Data Encrypted for Impact"}


def test_attack_technique_tactics(fake_fetch):
    r = attack.collect(fake_fetch({attack.URL: "attack/enterprise.json"}), FIXED_NOW)
    tt = r.extra["technique_tactics"]
    # mitre-attack phases only — the "other-chain" entry is filtered out
    assert tt["tactics"] == {
        "T1566": ["initial-access"],
        "T1486": ["defense-impairment", "impact"],
    }
    # order comes from x-mitre-matrix.tactic_refs, NOT bundle object order
    # (the fixture deliberately lists x-mitre-tactic--t3 after the matrix)
    assert tt["order"] == [
        {"slug": "initial-access", "name": "Initial Access"},
        {"slug": "defense-impairment", "name": "Defense Impairment"},
        {"slug": "impact", "name": "Impact"},
    ]


def test_clip_cuts_at_word_boundary_never_mid_token():
    long = ("word " * 200).strip()          # 999 chars of clean words
    out = attack._clip(long, cap=800)
    assert len(out) <= 800
    assert not out.endswith(" ") and out.endswith("word")  # whole final word
    # short text passes through untouched
    assert attack._clip("short text.", cap=800) == "short text."
    # a single 900-char token can't word-cut — falls back to the hard cap
    assert len(attack._clip("x" * 900, cap=800)) == 800
